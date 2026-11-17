//! Signed local generations and crash-safe prefix replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use mvm_contract::protocol::mailbox::{
    DELIVERY_ACK_SIGNATURE_DOMAIN, DeliveryOutcome, MailboxAddress, MailboxRetentionPolicy,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    AcceptanceTier, DOMAIN, FileJournalAnchor, HistoryKeyRef, JournalError, JournalEvent,
    JournalTip, MAX_LEASE_RETRIES, MAX_RECORD_BYTES, MailboxJournal, Record, ReplayIdentity, Seen,
    aead, atomic_write_new, canonical_bytes, read_record, sync_dir, verify_recovered_lease,
};

const CHECKPOINT_DOMAIN: &[u8] = b"mvm.mailbox.local-checkpoint.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointEntry {
    pub(super) identity: ReplayIdentity,
    pub(super) seen: Seen,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointState {
    pub(super) source: JournalTip,
    pub(super) address: MailboxAddress,
    pub(super) history_key: HistoryKeyRef,
    pub(super) retention: MailboxRetentionPolicy,
    pub(super) created_at_unix_ms: i64,
    pub(super) entries: Vec<CheckpointEntry>,
    pub(super) used_challenges: Vec<([u8; 32], ReplayIdentity)>,
}

pub(super) fn checkpoint_path(root: &Path, cursor: u64) -> PathBuf {
    root.join(format!("checkpoint-{cursor:020}.bin"))
}

impl MailboxJournal {
    pub(super) fn checkpoint_state(
        &self,
        now_unix_ms: i64,
    ) -> Result<CheckpointState, JournalError> {
        Ok(CheckpointState {
            source: self.tip,
            address: self.address,
            history_key: self
                .history_key
                .ok_or(JournalError::HistoryKeyUnavailable)?,
            retention: self.retention.ok_or(JournalError::InvalidLimits)?,
            created_at_unix_ms: now_unix_ms,
            entries: self
                .order
                .iter()
                .map(|identity| {
                    self.seen
                        .get(identity)
                        .cloned()
                        .map(|seen| CheckpointEntry {
                            identity: *identity,
                            seen,
                        })
                        .ok_or(JournalError::Corrupt)
                })
                .collect::<Result<_, _>>()?,
            used_challenges: self.used_challenges.iter().map(|(a, b)| (*a, *b)).collect(),
        })
    }

    pub(super) fn restore_checkpoint(
        &mut self,
        path: &Path,
        cursor: u64,
    ) -> Result<(), JournalError> {
        let bytes = read_record(path)?;
        if bytes.len() as u64 > self.limits.max_bytes {
            return Err(JournalError::Full);
        }
        let (previous, sealed) = bytes.split_at_checked(32).ok_or(JournalError::Corrupt)?;
        let (tag, ciphertext) = sealed.split_at_checked(32).ok_or(JournalError::Corrupt)?;
        let previous: [u8; 32] = previous.try_into().map_err(|_| JournalError::Corrupt)?;
        let expected_tag = self.mac_after(previous, ciphertext);
        if self.tier != AcceptanceTier::Local || tag != expected_tag {
            return Err(JournalError::Corrupt);
        }
        let plaintext = Zeroizing::new(
            aead::open(
                &self.record_key(),
                ciphertext,
                &[DOMAIN, &previous].concat(),
            )
            .map_err(|_| JournalError::Corrupt)?,
        );
        let record: Record =
            serde_json::from_slice(&plaintext).map_err(|_| JournalError::Corrupt)?;
        if !matches!(record.version, 3 | 4)
            || record.version < self.format_version
            || record.cursor != cursor
            || record.previous != previous
            || record.address != self.address
            || record.history_key != self.history_key
        {
            return Err(JournalError::Corrupt);
        }
        let JournalEvent::Checkpoint {
            state,
            authorization_signature,
        } = record.event
        else {
            return Err(JournalError::Corrupt);
        };
        if state.source.cursor.checked_add(1) != Some(cursor)
            || state.source.head != previous
            || state.address != self.address
            || Some(state.history_key) != self.history_key
            || Some(state.retention) != self.retention
            || state.created_at_unix_ms < 0
        {
            return Err(JournalError::Corrupt);
        }
        let signature: [u8; 64] = authorization_signature
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        self.authority
            .verify(
                &canonical_bytes(CHECKPOINT_DOMAIN, &state).map_err(|_| JournalError::Corrupt)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| JournalError::Corrupt)?;
        let mut seen = BTreeMap::new();
        let mut order = Vec::new();
        for CheckpointEntry {
            identity,
            seen: entry,
        } in state.entries
        {
            if record.version == 3 && entry.receipt_completion.is_some() {
                return Err(JournalError::Corrupt);
            }
            let receipt = &entry.accepted_receipt;
            if receipt.address != self.address
                || receipt.outcome != DeliveryOutcome::AcceptedLocalDurable
                || receipt.message_id != identity.message_id
                || receipt.execution_epoch != identity.execution_epoch
                || receipt.delivery_id != entry.envelope.routing.delivery_id
                || receipt.ciphertext_commitment != entry.envelope.ciphertext_commitment
                || receipt.validate_versioned_outcome().is_err()
                || state
                    .retention
                    .retained_until(entry.envelope.routing.expires_at_unix_ms)
                    .is_err()
                || entry
                    .expired_at_unix_ms
                    .is_some_and(|time| time < entry.envelope.routing.expires_at_unix_ms)
                || (entry.acknowledged && entry.expired_at_unix_ms.is_some())
                || (entry.signed_ack.is_some() && !entry.acknowledged)
            {
                return Err(JournalError::Corrupt);
            }
            if let Some(lease) = &entry.lease {
                if lease.retry_count > MAX_LEASE_RETRIES {
                    return Err(JournalError::Corrupt);
                }
                let at = entry
                    .signed_ack
                    .as_ref()
                    .map_or(lease.signed.lease.issued_at_unix_ms, |ack| {
                        ack.ack.acknowledged_at_unix_ms
                    });
                let guest_key = verify_recovered_lease(
                    &entry,
                    identity,
                    &lease.signed,
                    &lease.enrollment,
                    &lease.receive_capability,
                    &self.authority,
                    at,
                )?;
                if let Some(ack) = &entry.signed_ack {
                    if ack.ack.lease != lease.signed || ack.encode().is_err() {
                        return Err(JournalError::Corrupt);
                    }
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
                } else if entry.acknowledged {
                    return Err(JournalError::Corrupt);
                }
            } else if entry.signed_ack.is_some() {
                return Err(JournalError::Corrupt);
            }
            match &entry.receipt_completion {
                Some(super::ReceiptCompletion::Pending { reserved_bytes }) => {
                    if self.pending_receipt(identity, &entry.accepted_receipt)?
                        != (super::ReceiptCompletion::Pending {
                            reserved_bytes: *reserved_bytes,
                        })
                    {
                        return Err(JournalError::Corrupt);
                    }
                }
                Some(super::ReceiptCompletion::Retained { encoded_receipt }) => {
                    self.decode_retained_receipt(identity, &entry, encoded_receipt)?;
                }
                None => {}
            }
            if seen.insert(identity, entry).is_some() {
                return Err(JournalError::Corrupt);
            }
            order.push(identity);
        }
        let mut used_challenges = BTreeMap::new();
        for (challenge, identity) in state.used_challenges {
            if challenge == [0; 32]
                || !seen.contains_key(&identity)
                || used_challenges.insert(challenge, identity).is_some()
            {
                return Err(JournalError::Corrupt);
            }
        }
        self.seen = seen;
        self.order = order;
        self.used_challenges = used_challenges;
        self.tip = JournalTip {
            cursor,
            head: expected_tag,
        };
        self.bytes = bytes.len() as u64;
        self.records = 1;
        self.format_version = record.version;
        Ok(())
    }

    /// Whether local maintenance should checkpoint before quota exhaustion or
    /// retire terminal replay evidence past its signed retention horizon.
    pub fn local_compaction_due(&self, now_unix_ms: i64) -> Result<bool, JournalError> {
        let retention = self.retention.ok_or(JournalError::InvalidLimits)?;
        if now_unix_ms < 0 || self.tier != AcceptanceTier::Local {
            return Err(JournalError::InvalidLimits);
        }
        if self.records >= self.limits.max_records.saturating_sub(8).max(1)
            || (self.records > 1 && self.bytes >= self.limits.max_bytes / 2)
        {
            return Ok(true);
        }
        for entry in self.seen.values() {
            if (entry.acknowledged || entry.expired_at_unix_ms.is_some())
                && now_unix_ms
                    > retention
                        .retained_until(entry.envelope.routing.expires_at_unix_ms)
                        .map_err(|_| JournalError::Corrupt)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Commit a signed local snapshot before pruning the superseded prefix.
    ///
    /// A quota refusal leaves the old history untouched; uncertain I/O poisons
    /// this handle until recovery has verified the committed anchor. The caller
    /// must provide trusted UNIX time for terminal-state retention.
    pub fn compact_local(
        &mut self,
        now_unix_ms: i64,
        signer: &SigningKey,
        anchor: &FileJournalAnchor,
    ) -> Result<JournalTip, JournalError> {
        self.local_ready(anchor, &signer.verifying_key())?;
        let retention = self.retention.ok_or(JournalError::InvalidLimits)?;
        if now_unix_ms < 0 {
            return Err(JournalError::InvalidLimits);
        }
        let mut retired = BTreeSet::new();
        for (identity, entry) in &self.seen {
            // A terminal obligation includes a pending receipt, but neither
            // extends the signed replay-retention horizon.
            if (entry.acknowledged || entry.expired_at_unix_ms.is_some())
                && now_unix_ms
                    > retention
                        .retained_until(entry.envelope.routing.expires_at_unix_ms)
                        .map_err(|_| JournalError::Corrupt)?
            {
                retired.insert(*identity);
            }
        }
        let mut state = self.checkpoint_state(now_unix_ms)?;
        state
            .entries
            .retain(|entry| !retired.contains(&entry.identity));
        state
            .used_challenges
            .retain(|(_, identity)| !retired.contains(identity));
        let signature = signer
            .sign(&canonical_bytes(CHECKPOINT_DOMAIN, &state)?)
            .to_bytes()
            .to_vec();
        let cursor = self.tip.cursor.checked_add(1).ok_or(JournalError::Full)?;
        let record = Record {
            version: 4,
            cursor,
            previous: self.tip.head,
            address: self.address,
            history_key: self.history_key,
            event: JournalEvent::Checkpoint {
                state: Box::new(state),
                authorization_signature: signature,
            },
        };
        let body = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| JournalError::Corrupt)?);
        if body.len() + 64 + aead::NONCE_SIZE + aead::TAG_SIZE > MAX_RECORD_BYTES {
            return Err(JournalError::Full);
        }
        let ciphertext = aead::seal(
            &self.record_key(),
            &body,
            &[DOMAIN, &self.tip.head].concat(),
        );
        let size = (ciphertext.len() + 64) as u64;
        let JournalEvent::Checkpoint { state, .. } = &record.event else {
            return Err(JournalError::Corrupt);
        };
        self.check_checkpoint_capacity(state, size)?;
        let tag = self.mac(&ciphertext);
        let mut bytes = self.tip.head.to_vec();
        bytes.extend_from_slice(&tag);
        bytes.extend_from_slice(&ciphertext);
        let path = checkpoint_path(&self.root, cursor);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(JournalError::Corrupt),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if let Err(error) = atomic_write_new(&path, &bytes).and_then(|()| sync_dir(&self.root)) {
            self.poisoned = true;
            return Err(JournalError::Storage(std::io::Error::other(error)));
        }
        let next = JournalTip { cursor, head: tag };
        if let Err(error) = anchor.advance(next) {
            self.poisoned = true;
            return Err(error);
        }
        self.tip = next;
        self.poisoned = true;
        for entry in fs::read_dir(&self.root)? {
            let old = entry?.path();
            if old != path && old != self.root.join("journal.lock") {
                fs::remove_file(old)?;
            }
        }
        sync_dir(&self.root)
            .map_err(|error| JournalError::Storage(std::io::Error::other(error)))?;
        self.order.retain(|identity| !retired.contains(identity));
        self.seen.retain(|identity, _| !retired.contains(identity));
        self.used_challenges
            .retain(|_, identity| !retired.contains(identity));
        self.bytes = size;
        self.records = 1;
        self.format_version = 4;
        self.poisoned = false;
        Ok(next)
    }
}
