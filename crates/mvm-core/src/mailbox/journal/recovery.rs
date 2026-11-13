//! Reconstruct the authenticated journal, reconcile only intact suffixes, and
//! never infer a new genesis from a missing anchored generation.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    DELIVERY_ACK_SIGNATURE_DOMAIN, DeliveryOutcome, MailboxAddress,
};
use zeroize::Zeroizing;

use super::super::{canonical_bytes, frame};
use super::{
    AcceptanceTier, DOMAIN, JournalError, JournalEvent, JournalKey, JournalLimits, JournalTip,
    LeaseState, MAX_JOURNAL_BYTES, MAX_LEASE_RETRIES, MAX_RECORDS, MailboxJournal, Record, Seen,
    acceptance_intent_bytes, checkpoint_path, expiry_intent_bytes, read_record, record_path,
    verify_recovered_lease,
};
use crate::crypto::aead;
use crate::private_fs;
use crate::util::atomic_io::{FileLock, sync_dir};

impl MailboxJournal {
    pub(super) fn open_with_recovery(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: JournalKey,
        limits: JournalLimits,
        expected: JournalTip,
        mut reconcile: impl FnMut(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Self, JournalError> {
        if limits.max_records == 0
            || limits.max_records > MAX_RECORDS
            || limits.max_bytes == 0
            || limits.max_bytes > MAX_JOURNAL_BYTES
        {
            return Err(JournalError::InvalidLimits);
        }
        if expected.cursor == 0 && expected != JournalTip::genesis() {
            return Err(JournalError::Rollback);
        }
        private_fs::ensure_private_dir(root)?;
        sync_dir(root.parent().ok_or(JournalError::Corrupt)?)
            .map_err(|e| JournalError::Storage(std::io::Error::other(e.to_string())))?;
        let lock = FileLock::try_acquire(&root.join("journal"))
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or(JournalError::Busy)?;
        let mut journal = Self {
            root: root.to_owned(),
            address,
            authority,
            key: key.bytes,
            history_key: key.reference,
            tier: key.tier,
            retention: key.retention,
            limits,
            tip: JournalTip::genesis(),
            bytes: 0,
            records: 0,
            seen: BTreeMap::new(),
            order: Vec::new(),
            used_challenges: BTreeMap::new(),
            poisoned: false,
            _lock: lock,
        };
        let mut paths = Vec::new();
        let mut checkpoints = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() == "journal.lock" {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_str().ok_or(JournalError::Corrupt)?;
            if let Some(raw) = name.strip_prefix("checkpoint-") {
                let cursor = raw
                    .strip_suffix(".bin")
                    .and_then(|raw| raw.parse::<u64>().ok())
                    .ok_or(JournalError::Corrupt)?;
                if path != checkpoint_path(root, cursor) {
                    return Err(JournalError::Corrupt);
                }
                checkpoints.push((cursor, path));
            } else if let Some(raw) = name.strip_prefix("entry-") {
                let cursor = raw
                    .strip_suffix(".bin")
                    .and_then(|raw| raw.parse::<u64>().ok())
                    .ok_or(JournalError::Corrupt)?;
                if path != record_path(root, cursor) {
                    return Err(JournalError::Corrupt);
                }
                paths.push((cursor, path));
            } else {
                return Err(JournalError::Corrupt);
            }
            if paths.len() > limits.max_records || checkpoints.len() > 2 {
                return Err(JournalError::Full);
            }
        }
        checkpoints.sort();
        if !checkpoints.is_empty() && journal.tier != AcceptanceTier::Local {
            return Err(JournalError::Corrupt);
        }
        if let Some((cursor, path)) = checkpoints
            .iter()
            .rev()
            .find(|(cursor, _)| *cursor <= expected.cursor)
        {
            journal.restore_checkpoint(path, *cursor)?;
            if *cursor == expected.cursor && journal.tip != expected {
                return Err(JournalError::Rollback);
            }
        }
        let start = journal.tip.cursor;
        let (mut paths, obsolete): (Vec<_>, Vec<_>) =
            paths.into_iter().partition(|(cursor, _)| *cursor > start);
        paths.sort();
        let mut suffix_synced = false;
        for (_, path) in paths {
            let cursor = journal
                .tip
                .cursor
                .checked_add(1)
                .ok_or(JournalError::Full)?;
            if path != record_path(root, cursor) {
                return Err(JournalError::Corrupt);
            }
            let bytes = read_record(&path)?;
            journal.bytes = journal
                .bytes
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= limits.max_bytes)
                .ok_or(JournalError::Full)?;
            journal.records += 1;
            let (tag, ciphertext) = bytes.split_at_checked(32).ok_or(JournalError::Corrupt)?;
            let expected_tag = journal.mac(ciphertext);
            if tag != expected_tag {
                return Err(JournalError::Corrupt);
            }
            let plaintext = Zeroizing::new(
                aead::open(
                    &journal.record_key(),
                    ciphertext,
                    &[DOMAIN, &journal.tip.head].concat(),
                )
                .map_err(|_| JournalError::Corrupt)?,
            );
            let record: Record =
                serde_json::from_slice(&plaintext).map_err(|_| JournalError::Corrupt)?;
            let expected_version = if journal.history_key.is_some() { 3 } else { 2 };
            if record.version != expected_version
                || record.cursor != cursor
                || record.previous != journal.tip.head
                || record.address != address
            {
                return Err(JournalError::Corrupt);
            }
            if let Some(reference) = &record.history_key {
                reference.validate().map_err(|_| JournalError::Corrupt)?;
            }
            if record.history_key != journal.history_key {
                return Err(JournalError::HistoryKeyMismatch);
            }
            match record.event {
                JournalEvent::Accepted {
                    identity,
                    frame: encoded_frame,
                    receipt,
                    authorization_signature,
                } => {
                    let expected_outcome = match journal.tier {
                        AcceptanceTier::Independent => DeliveryOutcome::AcceptedDurable,
                        AcceptanceTier::Local => DeliveryOutcome::AcceptedLocalDurable,
                    };
                    if receipt.address != address
                        || receipt.outcome != expected_outcome
                        || receipt.message_id != identity.message_id
                        || receipt.execution_epoch != identity.execution_epoch
                        || receipt.validate_versioned_outcome().is_err()
                    {
                        return Err(JournalError::Corrupt);
                    }
                    let signature: [u8; 64] = authorization_signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| JournalError::Corrupt)?;
                    authority
                        .verify(
                            &acceptance_intent_bytes(
                                identity,
                                &encoded_frame,
                                &receipt,
                                journal.history_key.as_ref(),
                            )?,
                            &Signature::from_bytes(&signature),
                        )
                        .map_err(|_| JournalError::Corrupt)?;
                    let raw = STANDARD_NO_PAD
                        .decode(&encoded_frame)
                        .map_err(|_| JournalError::Corrupt)?;
                    let (capability, envelope) =
                        frame::decode_frame(&raw).map_err(|_| JournalError::Corrupt)?;
                    if receipt.delivery_id != envelope.routing.delivery_id
                        || receipt.ciphertext_commitment != envelope.ciphertext_commitment
                        || journal.retention.is_some_and(|policy| {
                            policy
                                .retained_until(envelope.routing.expires_at_unix_ms)
                                .is_err()
                        })
                        || journal
                            .seen
                            .insert(
                                identity,
                                Seen {
                                    envelope,
                                    capability,
                                    accepted_receipt: *receipt,
                                    acknowledged: false,
                                    expired_at_unix_ms: None,
                                    lease: None,
                                    signed_ack: None,
                                },
                            )
                            .is_some()
                    {
                        return Err(JournalError::Corrupt);
                    }
                    journal.order.push(identity);
                }
                JournalEvent::Acknowledged {
                    identity,
                    acknowledged_at_unix_ms,
                } => {
                    let Some(entry) = journal.seen.get_mut(&identity) else {
                        return Err(JournalError::Corrupt);
                    };
                    if entry.acknowledged
                        || entry.expired_at_unix_ms.is_some()
                        || entry.lease.is_some()
                        || acknowledged_at_unix_ms < 0
                    {
                        return Err(JournalError::Corrupt);
                    }
                    entry.acknowledged = true;
                }
                JournalEvent::Leased {
                    identity,
                    challenge,
                    lease,
                    enrollment,
                    receive_capability,
                } => {
                    let entry = journal
                        .seen
                        .get_mut(&identity)
                        .ok_or(JournalError::Corrupt)?;
                    if entry.acknowledged
                        || entry.expired_at_unix_ms.is_some()
                        || lease.encode().is_err()
                        || enrollment.encode().is_err()
                        || lease.lease.address != address
                        || lease.lease.delivery_id != entry.envelope.routing.delivery_id
                        || lease.lease.message_id != identity.message_id
                        || lease.lease.execution_epoch != identity.execution_epoch
                        || lease.lease.ciphertext_commitment != entry.envelope.ciphertext_commitment
                        || lease.lease.consumer_session != enrollment.enrollment.consumer_session
                        || lease.lease.receive_capability_id
                            != receive_capability.grant.capability_id
                        || challenge == [0; 32]
                    {
                        return Err(JournalError::Corrupt);
                    }
                    verify_recovered_lease(
                        entry,
                        identity,
                        &lease,
                        &enrollment,
                        &receive_capability,
                        &authority,
                        lease.lease.issued_at_unix_ms,
                    )?;
                    entry.lease = Some(LeaseState {
                        retry_count: 0,
                        signed: *lease,
                        enrollment: *enrollment,
                        receive_capability: *receive_capability,
                    });
                    if journal
                        .used_challenges
                        .insert(challenge, identity)
                        .is_some()
                    {
                        return Err(JournalError::Corrupt);
                    }
                }
                JournalEvent::LeasedRetry {
                    identity,
                    challenge,
                } => {
                    let active = journal
                        .seen
                        .get_mut(&identity)
                        .filter(|entry| !entry.acknowledged && entry.expired_at_unix_ms.is_none())
                        .and_then(|entry| entry.lease.as_mut())
                        .ok_or(JournalError::Corrupt)?;
                    active.retry_count = active
                        .retry_count
                        .checked_add(1)
                        .filter(|count| *count <= MAX_LEASE_RETRIES)
                        .ok_or(JournalError::Corrupt)?;
                    if challenge == [0; 32]
                        || journal
                            .used_challenges
                            .insert(challenge, identity)
                            .is_some()
                    {
                        return Err(JournalError::Corrupt);
                    }
                }
                JournalEvent::AcknowledgedSigned { identity, ack } => {
                    let entry = journal
                        .seen
                        .get_mut(&identity)
                        .ok_or(JournalError::Corrupt)?;
                    let active = entry.lease.as_ref().ok_or(JournalError::Corrupt)?;
                    if entry.acknowledged
                        || entry.expired_at_unix_ms.is_some()
                        || ack.encode().is_err()
                        || ack.ack.lease != active.signed
                    {
                        return Err(JournalError::Corrupt);
                    }
                    let guest_key = verify_recovered_lease(
                        entry,
                        identity,
                        &active.signed,
                        &active.enrollment,
                        &active.receive_capability,
                        &authority,
                        ack.ack.acknowledged_at_unix_ms,
                    )?;
                    let signature: [u8; 64] = ack
                        .signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| JournalError::Corrupt)?;
                    guest_key
                        .verify(
                            &canonical_bytes(DELIVERY_ACK_SIGNATURE_DOMAIN, &ack.ack)
                                .map_err(|_| JournalError::Corrupt)?,
                            &Signature::from_bytes(&signature),
                        )
                        .map_err(|_| JournalError::Corrupt)?;
                    entry.acknowledged = true;
                    entry.signed_ack = Some(*ack);
                }
                JournalEvent::Expired {
                    identity,
                    expired_at_unix_ms,
                    authorization_signature,
                } => {
                    let entry = journal
                        .seen
                        .get_mut(&identity)
                        .ok_or(JournalError::Corrupt)?;
                    if entry.acknowledged
                        || entry.expired_at_unix_ms.is_some()
                        || expired_at_unix_ms < entry.envelope.routing.expires_at_unix_ms
                    {
                        return Err(JournalError::Corrupt);
                    }
                    let signature: [u8; 64] = authorization_signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| JournalError::Corrupt)?;
                    authority
                        .verify(
                            &expiry_intent_bytes(address, identity, entry, expired_at_unix_ms)?,
                            &Signature::from_bytes(&signature),
                        )
                        .map_err(|_| JournalError::Corrupt)?;
                    entry.expired_at_unix_ms = Some(expired_at_unix_ms);
                }
                JournalEvent::Checkpoint { .. } => return Err(JournalError::Corrupt),
            }
            let next = JournalTip {
                cursor,
                head: expected_tag,
            };
            if cursor == expected.cursor && next != expected {
                return Err(JournalError::Rollback);
            }
            if cursor > expected.cursor {
                if !suffix_synced {
                    // A predecessor could crash after publishing a record but
                    // before syncing its directory entry. Recovery must not
                    // advance an independent anchor ahead of that entry.
                    sync_dir(root)
                        .map_err(|error| JournalError::Storage(std::io::Error::other(error)))?;
                    suffix_synced = true;
                }
                reconcile(next)?;
            }
            journal.tip = next;
        }
        if journal.tip.cursor < expected.cursor {
            return Err(JournalError::Rollback);
        }
        if start != 0 {
            for (_, path) in obsolete {
                fs::remove_file(path)?;
            }
        }
        for (cursor, path) in checkpoints {
            if cursor > expected.cursor || cursor < start {
                // Pre-anchor or superseded generations are removed only after
                // the committed prefix has been verified against the anchor.
                fs::remove_file(&path)?;
            }
        }
        sync_dir(root).map_err(|error| JournalError::Storage(std::io::Error::other(error)))?;
        Ok(journal)
    }
}
