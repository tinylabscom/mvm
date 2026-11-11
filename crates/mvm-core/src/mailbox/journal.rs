//! Destination-owned, bounded ciphertext admission journal.
//!
//! Each immutable entry is published with a no-clobber rename and a directory
//! sync. The signed acceptance receipt and dedup identity live in the same
//! authenticated record as the canonical envelope. A caller must retain the
//! returned tip in an independent trusted anchor to detect whole-journal
//! rollback; a hash chain alone cannot detect deletion of its suffix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac, digest::KeyInit};
use mvm_contract::protocol::mailbox::{
    ContentType, DeliveryLeaseNonce, DeliveryOutcome, DestinationReceipt, MailboxAddress,
    MailboxDeliveryLease, MailboxEnvelope, MailboxGrant, MailboxGuestReaderScope, MailboxOperation,
    ProtocolVersion, SignatureAlgorithm, SignedDestinationReceipt, SignedMailboxCapability,
    SignedMailboxDeliveryAck, SignedMailboxDeliveryLease, SignedMailboxGuestReaderEnrollment,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::reader::{
    ReaderDeliveryContext, sign_delivery_lease, verify_delivery_ack, verify_delivery_lease,
    verify_guest_reader_enrollment, verify_reader_possession,
};
use super::{
    MailboxError, OpenContext, ReplayIdentity, ReplayProtector, authorize_receive, frame,
    open_authenticated_envelope, sign_receipt, verify_receipt,
};
use crate::crypto::aead::{self, Key};
use crate::private_fs;
use crate::util::atomic_io::{FileLock, atomic_write_durable, atomic_write_new, sync_dir};

const DOMAIN: &[u8] = b"mvm.mailbox.journal.v1\0";
const ENCRYPTION_DOMAIN: &[u8] = b"mvm.mailbox.journal.encryption.v1\0";
const ANCHOR_DOMAIN: &[u8] = b"mvm.mailbox.anchor.v1\0";
const MAX_ANCHOR_BYTES: u64 = 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LEASE_RETRIES: u8 = 3;

/// Limits are checked both before admission and while reconstructing state.
#[derive(Debug, Clone, Copy)]
pub struct JournalLimits {
    pub max_records: usize,
    pub max_bytes: u64,
}

/// Trusted external high-water mark. Persist this outside the journal's
/// rollback domain before exposing the receipt to the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalTip {
    pub cursor: u64,
    pub head: [u8; 32],
}

impl JournalTip {
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            cursor: 0,
            head: [0; 32],
        }
    }
}

/// Fail-closed admission and recovery failures; no plaintext is included.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("invalid journal limits")]
    InvalidLimits,
    #[error("journal writer is already active")]
    Busy,
    #[error("journal quota exhausted")]
    Full,
    #[error("journal record or chain is invalid")]
    Corrupt,
    #[error("journal high-water mark does not match its trusted anchor")]
    Rollback,
    #[error("journal address or destination authority does not match")]
    WrongAuthority,
    #[error("a message identity was reused with different bytes")]
    ConflictingRetry,
    #[error("mailbox message does not exist")]
    UnknownMessage,
    #[error("mailbox message has no active delivery lease")]
    NoActiveLease,
    #[error("journal cannot be used after an uncertain write")]
    Uncertain,
    #[error("mailbox authorization refused: {0}")]
    Mailbox(#[from] MailboxError),
    #[error("journal storage is unavailable: {0}")]
    Storage(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    cursor: u64,
    previous: [u8; 32],
    address: MailboxAddress,
    event: JournalEvent,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalEvent {
    Accepted {
        identity: ReplayIdentity,
        frame: String,
        receipt: Box<SignedDestinationReceipt>,
    },
    Acknowledged {
        identity: ReplayIdentity,
        acknowledged_at_unix_ms: i64,
    },
    Leased {
        identity: ReplayIdentity,
        challenge: [u8; 32],
        lease: Box<SignedMailboxDeliveryLease>,
        enrollment: Box<SignedMailboxGuestReaderEnrollment>,
        receive_capability: Box<SignedMailboxCapability>,
    },
    LeasedRetry {
        identity: ReplayIdentity,
        challenge: [u8; 32],
    },
    AcknowledgedSigned {
        identity: ReplayIdentity,
        ack: Box<SignedMailboxDeliveryAck>,
    },
}

struct LeaseState {
    retry_count: u8,
    signed: SignedMailboxDeliveryLease,
    enrollment: SignedMailboxGuestReaderEnrollment,
    receive_capability: SignedMailboxCapability,
}

struct Seen {
    envelope: MailboxEnvelope,
    capability: SignedMailboxCapability,
    acknowledged: bool,
    lease: Option<LeaseState>,
    signed_ack: Option<SignedMailboxDeliveryAck>,
}

#[derive(Default)]
struct Probe(Option<ReplayIdentity>);

impl ReplayProtector for Probe {
    fn check_and_record(&mut self, identity: ReplayIdentity) -> bool {
        self.0 = Some(identity);
        true // Only the durable journal records it after the fsync.
    }
}

/// An exclusive writer. Records contain only canonical ciphertext, capability
/// and signed metadata; plaintext never enters the journal.
pub struct MailboxJournal {
    root: PathBuf,
    address: MailboxAddress,
    authority: VerifyingKey,
    key: Zeroizing<[u8; 32]>,
    limits: JournalLimits,
    tip: JournalTip,
    bytes: u64,
    seen: BTreeMap<ReplayIdentity, Seen>,
    order: Vec<ReplayIdentity>,
    used_challenges: BTreeSet<[u8; 32]>,
    poisoned: bool,
    _lock: FileLock,
}

/// Inputs verified at the destination before ciphertext is committed.
pub struct JournalAdmission<'a> {
    pub envelope: &'a MailboxEnvelope,
    pub capability: &'a SignedMailboxCapability,
    pub context: &'a OpenContext,
    pub encryption_key: &'a Key,
    pub sender_key: &'a VerifyingKey,
    pub signer: &'a SigningKey,
}

/// Independent reader authority and host-held decryption material for the
/// trusted-host profile. A sender's grant cannot substitute for Receive.
#[derive(Clone, Copy)]
pub struct JournalReceive<'a> {
    pub capability: &'a SignedMailboxCapability,
    pub context: &'a OpenContext,
    pub encryption_key: &'a Key,
    pub sender_key: &'a VerifyingKey,
}

/// Verified current guest facts and proof for issuing one durable lease.
/// The caller must obtain the boot/session and challenge from its authenticated
/// guest channel, not from untrusted request fields.
pub struct JournalGuestLease<'a> {
    pub receive: JournalReceive<'a>,
    pub plan: &'a MailboxGrant,
    pub scope: MailboxGuestReaderScope<'a>,
    pub enrollment: &'a SignedMailboxGuestReaderEnrollment,
    pub challenge: &'a [u8; 32],
    pub possession_signature: &'a [u8],
    pub signer: &'a SigningKey,
}

/// One guest-authored ACK of the previously persisted active lease.
#[derive(Clone, Copy)]
pub struct JournalGuestAck<'a> {
    pub receive: JournalReceive<'a>,
    pub plan: &'a MailboxGrant,
    pub scope: MailboxGuestReaderScope<'a>,
    pub enrollment: &'a SignedMailboxGuestReaderEnrollment,
    pub signed: &'a SignedMailboxDeliveryAck,
}

/// A message whose signed lease was durably committed before payload release.
pub struct LeasedMailboxMessage {
    message: ReceivedMailboxMessage,
    lease: SignedMailboxDeliveryLease,
}

impl LeasedMailboxMessage {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.message.payload()
    }

    #[must_use]
    pub fn lease(&self) -> &SignedMailboxDeliveryLease {
        &self.lease
    }

    #[must_use]
    pub fn content_type(&self) -> &ContentType {
        &self.message.opened.header().content_type
    }
}

/// A pending, independently authorized message. Debug omits its plaintext.
pub struct ReceivedMailboxMessage {
    identity: ReplayIdentity,
    opened: super::OpenedMailboxMessage,
}

impl std::fmt::Debug for ReceivedMailboxMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedMailboxMessage")
            .field("identity", &self.identity)
            .field("payload_len", &self.opened.payload().len())
            .finish_non_exhaustive()
    }
}

impl ReceivedMailboxMessage {
    #[must_use]
    pub const fn identity(&self) -> ReplayIdentity {
        self.identity
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.opened.payload()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorBody {
    version: u8,
    address: MailboxAddress,
    tip: JournalTip,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorRecord {
    body: AnchorBody,
    tag: [u8; 32],
}

/// A software-first, locally fsynced anchor. Keep its file outside the
/// journal directory. It detects journal-only rollback, not simultaneous
/// rollback of the entire trusted host and its anchor storage.
pub struct FileJournalAnchor {
    path: PathBuf,
    address: MailboxAddress,
    key: Zeroizing<[u8; 32]>,
    tip: Mutex<JournalTip>,
    _lock: FileLock,
}

impl FileJournalAnchor {
    /// Open a private anchor file, or genesis if none exists.
    pub fn open(path: &Path, address: MailboxAddress, key: [u8; 32]) -> Result<Self, JournalError> {
        let parent = path.parent().ok_or(JournalError::Corrupt)?;
        private_fs::ensure_private_dir(parent)?;
        let lock = FileLock::try_acquire(path)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or(JournalError::Busy)?;
        let tip = match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalTip::genesis(),
            Err(e) => return Err(e.into()),
            Ok(meta) if !meta.file_type().is_file() || meta.len() > MAX_ANCHOR_BYTES => {
                return Err(JournalError::Corrupt);
            }
            Ok(_) => {
                let mut bytes = Vec::new();
                fs::File::open(path)?
                    .take(MAX_ANCHOR_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_ANCHOR_BYTES {
                    return Err(JournalError::Corrupt);
                }
                let record: AnchorRecord =
                    serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
                let body = serde_json::to_vec(&record.body).map_err(|_| JournalError::Corrupt)?;
                if record.body.version != 1
                    || record.body.address != address
                    || anchor_mac(&key, &body) != record.tag
                {
                    return Err(JournalError::Corrupt);
                }
                record.body.tip
            }
        };
        Ok(Self {
            path: path.to_owned(),
            address,
            key: Zeroizing::new(key),
            tip: Mutex::new(tip),
            _lock: lock,
        })
    }

    #[must_use]
    pub fn tip(&self) -> JournalTip {
        *self.tip.lock().expect("mailbox anchor lock poisoned")
    }

    /// Advance by one committed journal entry, fsyncing the file and its
    /// containing directory before returning.
    pub fn advance(&self, tip: JournalTip) -> Result<(), JournalError> {
        let mut current = self.tip.lock().expect("mailbox anchor lock poisoned");
        if current.cursor.checked_add(1) != Some(tip.cursor) {
            return Err(JournalError::Rollback);
        }
        let body = AnchorBody {
            version: 1,
            address: self.address,
            tip,
        };
        let tag = anchor_mac(
            &self.key[..],
            &serde_json::to_vec(&body).map_err(|_| JournalError::Corrupt)?,
        );
        let bytes =
            serde_json::to_vec(&AnchorRecord { body, tag }).map_err(|_| JournalError::Corrupt)?;
        atomic_write_durable(&self.path, &bytes)
            .map_err(|e| JournalError::Storage(std::io::Error::other(e.to_string())))?;
        *current = tip;
        Ok(())
    }
}

fn anchor_mac(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("a 32-byte HMAC key is valid");
    mac.update(ANCHOR_DOMAIN);
    mac.update(body);
    mac.finalize().into_bytes().into()
}

impl MailboxJournal {
    /// Reconstruct under an exclusive lock and require the separately trusted
    /// high-water mark. Genesis is valid only for an empty journal.
    pub fn open(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: [u8; 32],
        limits: JournalLimits,
        expected: JournalTip,
    ) -> Result<Self, JournalError> {
        Self::open_with_recovery(root, address, authority, key, limits, expected, |_| {
            Err(JournalError::Rollback)
        })
    }

    /// Recover a journal fsynced before its anchor during an interrupted
    /// admission. Only a verified extension of the anchored prefix may advance
    /// the independent anchor; rollback or divergence still refuses startup.
    pub fn open_reconciling(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: [u8; 32],
        limits: JournalLimits,
        anchor: &FileJournalAnchor,
    ) -> Result<Self, JournalError> {
        if anchor.address != address {
            return Err(JournalError::WrongAuthority);
        }
        Self::open_with_recovery(root, address, authority, key, limits, anchor.tip(), |tip| {
            anchor.advance(tip)
        })
    }

    fn open_with_recovery(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: [u8; 32],
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
            key: Zeroizing::new(key),
            limits,
            tip: JournalTip::genesis(),
            bytes: 0,
            seen: BTreeMap::new(),
            order: Vec::new(),
            used_challenges: BTreeSet::new(),
            poisoned: false,
            _lock: lock,
        };
        let mut paths = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() != "journal.lock" {
                paths.push(entry.path());
                if paths.len() > limits.max_records {
                    return Err(JournalError::Full);
                }
            }
        }
        paths.sort();
        for path in paths {
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
            if record.version != 1
                || record.cursor != cursor
                || record.previous != journal.tip.head
                || record.address != address
            {
                return Err(JournalError::Corrupt);
            }
            match record.event {
                JournalEvent::Accepted {
                    identity,
                    frame: encoded_frame,
                    receipt,
                } => {
                    if receipt.receipt.address != address
                        || receipt.receipt.outcome != DeliveryOutcome::AcceptedDurable
                        || receipt.receipt.message_id != identity.message_id
                        || receipt.receipt.execution_epoch != identity.execution_epoch
                    {
                        return Err(JournalError::Corrupt);
                    }
                    verify_receipt(&receipt, &authority).map_err(|_| JournalError::Corrupt)?;
                    let raw = STANDARD_NO_PAD
                        .decode(&encoded_frame)
                        .map_err(|_| JournalError::Corrupt)?;
                    let (capability, envelope) =
                        frame::decode_frame(&raw).map_err(|_| JournalError::Corrupt)?;
                    if receipt.receipt.delivery_id != envelope.routing.delivery_id
                        || receipt.receipt.ciphertext_commitment != envelope.ciphertext_commitment
                        || journal
                            .seen
                            .insert(
                                identity,
                                Seen {
                                    envelope,
                                    capability,
                                    acknowledged: false,
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
                    if entry.acknowledged || acknowledged_at_unix_ms < 0 {
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
                    entry.lease = Some(LeaseState {
                        retry_count: 0,
                        signed: *lease,
                        enrollment: *enrollment,
                        receive_capability: *receive_capability,
                    });
                    if !journal.used_challenges.insert(challenge) {
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
                        .filter(|entry| !entry.acknowledged)
                        .and_then(|entry| entry.lease.as_mut())
                        .ok_or(JournalError::Corrupt)?;
                    active.retry_count = active
                        .retry_count
                        .checked_add(1)
                        .filter(|count| *count <= MAX_LEASE_RETRIES)
                        .ok_or(JournalError::Corrupt)?;
                    if challenge == [0; 32] || !journal.used_challenges.insert(challenge) {
                        return Err(JournalError::Corrupt);
                    }
                }
                JournalEvent::AcknowledgedSigned { identity, ack } => {
                    let entry = journal
                        .seen
                        .get_mut(&identity)
                        .ok_or(JournalError::Corrupt)?;
                    let active = entry.lease.as_ref().ok_or(JournalError::Corrupt)?;
                    if entry.acknowledged || ack.encode().is_err() || ack.ack.lease != active.signed
                    {
                        return Err(JournalError::Corrupt);
                    }
                    entry.acknowledged = true;
                    entry.signed_ack = Some(*ack);
                }
            }
            let next = JournalTip {
                cursor,
                head: expected_tag,
            };
            if cursor == expected.cursor && next != expected {
                return Err(JournalError::Rollback);
            }
            if cursor > expected.cursor {
                reconcile(next)?;
            }
            journal.tip = next;
        }
        if journal.tip.cursor < expected.cursor {
            return Err(JournalError::Rollback);
        }
        Ok(journal)
    }

    /// Verify the canonical envelope and capability, commit ciphertext and
    /// dedup identity, then sign a destination verdict. `anchor` must commit the
    /// new tip in a separate rollback domain before this returns success.
    pub fn admit(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        let JournalAdmission {
            envelope,
            capability,
            context,
            encryption_key,
            sender_key,
            signer,
        } = request;
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if self.address.tenant != context.expected_tenant
            || self.address.authorization_domain != context.expected_authorization_domain
            || self.address.mailbox != context.expected_mailbox
            || self.address.recipient != context.expected_recipient
            || signer.verifying_key() != self.authority
        {
            return Err(JournalError::WrongAuthority);
        }
        let mut probe = Probe::default();
        let opened = open_authenticated_envelope(
            envelope,
            capability,
            context,
            encryption_key,
            sender_key,
            &self.authority,
            &mut probe,
        )?;
        let identity = probe.0.ok_or(JournalError::Corrupt)?;
        let receipt = |outcome| DestinationReceipt {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: envelope.routing.delivery_id,
            message_id: opened.header().message_id,
            address: self.address,
            execution_epoch: opened.header().execution_epoch,
            outcome,
            observed_at_unix_ms: context.now_unix_ms,
            ciphertext_commitment: envelope.ciphertext_commitment,
        };
        if let Some(previous) = self.seen.get(&identity) {
            if previous.envelope != *envelope || previous.capability != *capability {
                return Err(JournalError::ConflictingRetry);
            }
            return Ok(sign_receipt(receipt(DeliveryOutcome::Duplicate), signer)?);
        }
        if self.tip.cursor >= self.limits.max_records as u64 {
            return Err(JournalError::Full);
        }
        let signed = sign_receipt(receipt(DeliveryOutcome::AcceptedDurable), signer)?;
        let encoded_frame =
            frame::encode_frame(capability, envelope).map_err(|_| JournalError::Corrupt)?;
        self.append(
            JournalEvent::Accepted {
                identity,
                frame: STANDARD_NO_PAD.encode(encoded_frame),
                receipt: Box::new(signed.clone()),
            },
            anchor,
        )?;
        self.seen.insert(
            identity,
            Seen {
                envelope: envelope.clone(),
                capability: capability.clone(),
                acknowledged: false,
                lease: None,
                signed_ack: None,
            },
        );
        self.order.push(identity);
        Ok(signed)
    }

    fn append(
        &mut self,
        event: JournalEvent,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        let cursor = self.tip.cursor.checked_add(1).ok_or(JournalError::Full)?;
        if cursor > self.limits.max_records as u64 {
            return Err(JournalError::Full);
        }
        let record = Record {
            version: 1,
            cursor,
            previous: self.tip.head,
            address: self.address,
            event,
        };
        let body = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| JournalError::Corrupt)?);
        if body.len() + 32 + aead::NONCE_SIZE + aead::TAG_SIZE > MAX_RECORD_BYTES {
            return Err(JournalError::Full);
        }
        let ciphertext = aead::seal(
            &self.record_key(),
            &body,
            &[DOMAIN, &self.tip.head].concat(),
        );
        if self
            .bytes
            .checked_add((ciphertext.len() + 32) as u64)
            .is_none_or(|n| n > self.limits.max_bytes)
        {
            return Err(JournalError::Full);
        }
        let tag = self.mac(&ciphertext);
        let mut bytes = tag.to_vec();
        bytes.extend_from_slice(&ciphertext);
        let tip = JournalTip { cursor, head: tag };
        let result = atomic_write_new(&record_path(&self.root, cursor), &bytes)
            .and_then(|()| sync_dir(&self.root))
            .map_err(|e| JournalError::Storage(std::io::Error::other(e.to_string())));
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.tip = tip;
        self.bytes += bytes.len() as u64;
        if let Err(error) = anchor(tip) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(tip)
    }

    /// Inspect the oldest unacknowledged ciphertext under an independently
    /// signed Receive grant. No journal state changes until `acknowledge`.
    pub fn receive_next(
        &self,
        request: JournalReceive<'_>,
    ) -> Result<Option<ReceivedMailboxMessage>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        for identity in &self.order {
            let entry = self.seen.get(identity).ok_or(JournalError::Corrupt)?;
            if entry.acknowledged {
                continue;
            }
            let opened = self.open_for_reader(*identity, entry, &request)?;
            return Ok(Some(ReceivedMailboxMessage {
                identity: *identity,
                opened,
            }));
        }
        Ok(None)
    }

    /// Commit one signed lease and its one-time possession challenge before
    /// releasing plaintext to the authenticated guest reader.
    pub fn lease_next(
        &mut self,
        request: JournalGuestLease<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<LeasedMailboxMessage>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if request.signer.verifying_key() != self.authority
            || request.scope.plan != request.plan
            || request.scope.receive != &request.receive.capability.grant
            || request.scope.now_unix_ms != request.receive.context.now_unix_ms
            || request.scope.current_session.as_bytes() == &[0; 32]
            || request.scope.current_boot.as_bytes() == &[0; 32]
            || request.receive.context.acting_principal != request.enrollment.enrollment.consumer
        {
            return Err(JournalError::WrongAuthority);
        }
        let key = verify_guest_reader_enrollment(
            request.enrollment,
            request.receive.capability,
            &request.scope,
            &self.authority,
            &request.receive.context.revoked_capabilities,
        )?;
        verify_reader_possession(
            request.enrollment,
            request.challenge,
            request.possession_signature,
            &key,
        )?;
        let Some(message) = self.receive_next(request.receive)? else {
            return Ok(None);
        };
        let identity = message.identity;
        let entry = self.seen.get(&identity).ok_or(JournalError::Corrupt)?;
        let now = request.scope.now_unix_ms;
        if let Some(active) = &entry.lease
            && active.signed.lease.expires_at_unix_ms > now
        {
            if active.enrollment != *request.enrollment
                || active.receive_capability != *request.receive.capability
            {
                return Err(JournalError::Busy);
            }
            if self.used_challenges.contains(request.challenge) {
                return Err(JournalError::ConflictingRetry);
            }
            if active.retry_count >= MAX_LEASE_RETRIES {
                return Err(JournalError::Busy);
            }
            let signed = active.signed.clone();
            // A lost delivery response may be retried by this same enrolled
            // guest, but every fresh possession proof gets its own anchored
            // challenge event before plaintext is released again.
            self.append(
                JournalEvent::LeasedRetry {
                    identity,
                    challenge: *request.challenge,
                },
                anchor,
            )?;
            self.used_challenges.insert(*request.challenge);
            self.seen
                .get_mut(&identity)
                .and_then(|entry| entry.lease.as_mut())
                .ok_or(JournalError::Corrupt)?
                .retry_count += 1;
            return Ok(Some(LeasedMailboxMessage {
                message,
                lease: signed,
            }));
        }
        if self.used_challenges.contains(request.challenge) {
            return Err(JournalError::ConflictingRetry);
        }
        let header = message.opened.header();
        let expires_at_unix_ms = now
            .saturating_add(30_000)
            .min(header.expires_at_unix_ms)
            .min(request.receive.capability.grant.expires_at_unix_ms)
            .min(request.enrollment.enrollment.expires_at_unix_ms);
        if expires_at_unix_ms <= now {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
        let signed = sign_delivery_lease(
            MailboxDeliveryLease {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                address: self.address,
                sender: header.sender,
                sender_boot: header.sender_boot,
                message_id: header.message_id,
                delivery_id: entry.envelope.routing.delivery_id,
                execution_epoch: header.execution_epoch,
                consumer: request.enrollment.enrollment.consumer,
                consumer_session: request.scope.current_session,
                receive_capability_id: request.receive.capability.grant.capability_id,
                policy_epoch: request.receive.capability.grant.policy_epoch,
                ciphertext_commitment: entry.envelope.ciphertext_commitment,
                issued_at_unix_ms: now,
                expires_at_unix_ms,
                lease_nonce: DeliveryLeaseNonce::from_bytes(rand::random()),
            },
            request.signer,
        )?;
        verify_delivery_lease(
            &signed,
            &ReaderDeliveryContext {
                plan: request.plan,
                capability: request.receive.capability,
                reader_scope: request.scope,
                consumer_session: request.scope.current_session,
                now_unix_ms: now,
                envelope: &entry.envelope,
                header,
                authority: &self.authority,
                revoked: &request.receive.context.revoked_capabilities,
            },
        )?;
        self.append(
            JournalEvent::Leased {
                identity,
                challenge: *request.challenge,
                lease: Box::new(signed.clone()),
                enrollment: Box::new(request.enrollment.clone()),
                receive_capability: Box::new(request.receive.capability.clone()),
            },
            anchor,
        )?;
        self.used_challenges.insert(*request.challenge);
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .lease = Some(LeaseState {
            retry_count: 0,
            signed: signed.clone(),
            enrollment: request.enrollment.clone(),
            receive_capability: request.receive.capability.clone(),
        });
        Ok(Some(LeasedMailboxMessage {
            message,
            lease: signed,
        }))
    }

    /// Fsync an append-only ACK and advance the trusted tip. An uncertain
    /// commit poisons this writer; recovery must reconcile it before retry.
    pub fn acknowledge(
        &mut self,
        identity: ReplayIdentity,
        request: JournalReceive<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        let entry = self
            .seen
            .get(&identity)
            .ok_or(JournalError::UnknownMessage)?;
        let _opened = self.open_for_reader(identity, entry, &request)?;
        if entry.acknowledged {
            return Ok(self.tip);
        }
        let tip = self.append(
            JournalEvent::Acknowledged {
                identity,
                acknowledged_at_unix_ms: request.context.now_unix_ms,
            },
            anchor,
        )?;
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .acknowledged = true;
        Ok(tip)
    }

    /// Verify the enrolled guest signature over the exact active lease,
    /// commit its replay identity and signed bytes, then advance the anchor.
    pub fn acknowledge_signed(
        &mut self,
        request: JournalGuestAck<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if request.scope.plan != request.plan
            || request.scope.receive != &request.receive.capability.grant
            || request.scope.now_unix_ms != request.receive.context.now_unix_ms
        {
            return Err(JournalError::WrongAuthority);
        }
        let lease = &request.signed.ack.lease.lease;
        let identity = ReplayIdentity {
            sender: lease.sender,
            sender_boot: lease.sender_boot,
            execution_epoch: lease.execution_epoch,
            message_id: lease.message_id,
        };
        let entry = self
            .seen
            .get(&identity)
            .ok_or(JournalError::UnknownMessage)?;
        let active = entry.lease.as_ref().ok_or(JournalError::NoActiveLease)?;
        if active.signed != request.signed.ack.lease
            || active.enrollment != *request.enrollment
            || active.receive_capability != *request.receive.capability
        {
            return Err(JournalError::ConflictingRetry);
        }
        if request
            .receive
            .context
            .revoked_capabilities
            .contains(&request.receive.capability.grant.revocation_id)
        {
            return Err(JournalError::Mailbox(MailboxError::CapabilityRevoked));
        }
        if entry.acknowledged {
            return if entry.signed_ack.as_ref() == Some(request.signed) {
                Ok(self.tip)
            } else {
                Err(JournalError::ConflictingRetry)
            };
        }
        let opened = self.open_for_reader(identity, entry, &request.receive)?;
        let guest_key = VerifyingKey::from_bytes(&request.enrollment.enrollment.ack_public_key)
            .map_err(|_| JournalError::Mailbox(MailboxError::ReaderKeyInvalid))?;
        verify_delivery_ack(
            request.signed,
            &active.signed,
            &ReaderDeliveryContext {
                plan: request.plan,
                capability: request.receive.capability,
                reader_scope: request.scope,
                consumer_session: request.scope.current_session,
                now_unix_ms: request.scope.now_unix_ms,
                envelope: &entry.envelope,
                header: opened.header(),
                authority: &self.authority,
                revoked: &request.receive.context.revoked_capabilities,
            },
            request.enrollment,
            &guest_key,
        )?;
        let tip = self.append(
            JournalEvent::AcknowledgedSigned {
                identity,
                ack: Box::new(request.signed.clone()),
            },
            anchor,
        )?;
        let entry = self.seen.get_mut(&identity).ok_or(JournalError::Corrupt)?;
        entry.acknowledged = true;
        entry.signed_ack = Some(request.signed.clone());
        Ok(tip)
    }

    fn open_for_reader(
        &self,
        identity: ReplayIdentity,
        entry: &Seen,
        request: &JournalReceive<'_>,
    ) -> Result<super::OpenedMailboxMessage, JournalError> {
        if request.context.required_operation != MailboxOperation::Receive
            || request.context.expected_tenant != self.address.tenant
            || request.context.expected_authorization_domain != self.address.authorization_domain
            || request.context.expected_mailbox != self.address.mailbox
            || request.context.expected_recipient != self.address.recipient
        {
            return Err(JournalError::WrongAuthority);
        }
        let mut send_context = request.context.clone();
        send_context.acting_principal = entry.capability.grant.subject;
        send_context.expected_capability_issuer = entry.capability.grant.issuer;
        send_context.required_operation = MailboxOperation::Send;
        let opened = open_authenticated_envelope(
            &entry.envelope,
            &entry.capability,
            &send_context,
            request.encryption_key,
            request.sender_key,
            &self.authority,
            &mut Probe::default(),
        )?;
        if ReplayIdentity::from_header(opened.header()) != identity {
            return Err(JournalError::Corrupt);
        }
        authorize_receive(
            opened.header(),
            request.capability,
            request.context,
            &self.authority,
        )?;
        Ok(opened)
    }

    /// The last committed high-water mark for an independent trusted anchor.
    #[must_use]
    pub const fn tip(&self) -> JournalTip {
        self.tip
    }

    fn mac(&self, bytes: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key[..])
            .expect("a 32-byte HMAC key is valid");
        mac.update(DOMAIN);
        mac.update(&self.tip.head);
        mac.update(bytes);
        mac.finalize().into_bytes().into()
    }

    fn record_key(&self) -> Key {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key[..])
            .expect("a 32-byte HMAC key is valid");
        mac.update(ENCRYPTION_DOMAIN);
        Key::from_bytes(mac.finalize().into_bytes().into())
    }
}

fn record_path(root: &Path, cursor: u64) -> PathBuf {
    root.join(format!("entry-{cursor:020}.bin"))
}

fn read_record(path: &Path) -> Result<Vec<u8>, JournalError> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > MAX_RECORD_BYTES as u64 {
        return Err(JournalError::Corrupt);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Corrupt);
    }
    Ok(bytes)
}
