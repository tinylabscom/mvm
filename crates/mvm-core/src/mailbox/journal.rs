//! Destination-owned, bounded ciphertext admission journal.
//!
//! Each immutable entry is published with a no-clobber rename and a directory
//! sync. The unsigned receipt state and dedup identity live in the same
//! authenticated record as the canonical envelope. The destination signs
//! acceptance only after the journal and independent anchor commit. A hash
//! chain alone cannot detect deletion of its suffix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac, digest::KeyInit};
use mvm_contract::protocol::mailbox::{
    ContentType, DELIVERY_ACK_SIGNATURE_DOMAIN, DeliveryLeaseNonce, DeliveryOutcome,
    DestinationReceipt, EncryptionAlgorithm, ExecutionEpoch, MailboxAddress, MailboxDeliveryLease,
    MailboxEnvelope, MailboxGrant, MailboxGuestReaderScope, MailboxOperation, ProtocolVersion,
    SignatureAlgorithm, SignedDestinationReceipt, SignedMailboxCapability,
    SignedMailboxDeliveryAck, SignedMailboxDeliveryLease, SignedMailboxGuestReaderEnrollment,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::reader::{
    ReaderDeliveryContext, sign_delivery_lease, verify_delivery_ack, verify_delivery_lease,
    verify_delivery_lease_signature, verify_guest_reader_enrollment, verify_reader_possession,
};
use super::{
    MailboxError, OpenContext, ReplayIdentity, ReplayProtector, authorize_receive, canonical_bytes,
    frame, open_authenticated_envelope, sign_receipt,
};
use crate::crypto::aead::{self, Key};
use crate::private_fs;
use crate::util::atomic_io::{FileLock, atomic_write_durable, atomic_write_new, sync_dir};

const DOMAIN: &[u8] = b"mvm.mailbox.journal.v1\0";
const ENCRYPTION_DOMAIN: &[u8] = b"mvm.mailbox.journal.encryption.v1\0";
const ANCHOR_DOMAIN: &[u8] = b"mvm.mailbox.anchor.v1\0";
const ACCEPTANCE_INTENT_DOMAIN_V2: &[u8] = b"mvm.mailbox.journal-acceptance-intent.v2\0";
const ACCEPTANCE_INTENT_DOMAIN_V3: &[u8] = b"mvm.mailbox.journal-acceptance-intent.v3\0";
const EXPIRY_INTENT_DOMAIN: &[u8] = b"mvm.mailbox.journal-expiry.v1\0";
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

/// Independent, authenticated high-water authority for one mailbox.
///
/// Implementations must persist outside the journal host's rollback domain.
/// A local file, an in-memory value, or a best-effort transport acknowledgement
/// cannot authorize durable acceptance. Compare-and-advance must be atomic,
/// refuse divergent tips, and return only after the new tip is durable.
pub trait JournalAnchor {
    /// Read the authoritative tip, including after a host restart.
    fn load(&self, address: MailboxAddress) -> Result<JournalTip, JournalError>;

    /// Commit exactly one successor of `expected`, or refuse a stale writer.
    fn compare_and_advance(
        &self,
        address: MailboxAddress,
        expected: JournalTip,
        next: JournalTip,
    ) -> Result<(), JournalError>;
}

/// Recoverable storage-key identity for one mailbox and execution epoch.
///
/// This identifies the journal key, not the separately encrypted payload's
/// opening key. Deserialization is not admission authority; production must
/// bind it to a verified plan and authenticated restart manifest. A later
/// epoch or rotation needs an explicit anchored handoff.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRef {
    address: MailboxAddress,
    execution_epoch: ExecutionEpoch,
    algorithm: EncryptionAlgorithm,
    key_id: [u8; 32],
    version: u32,
}

impl std::fmt::Debug for HistoryKeyRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HistoryKeyRef")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl HistoryKeyRef {
    /// Identify a custody key version; construction alone is not authority.
    ///
    /// The host must bind these fields to a verified plan and authenticated
    /// restart manifest before using the reference to reopen retained history.
    pub fn new(
        address: MailboxAddress,
        execution_epoch: ExecutionEpoch,
        key_id: [u8; 32],
        version: u32,
    ) -> Result<Self, JournalError> {
        if key_id == [0; 32] || version == 0 {
            return Err(JournalError::HistoryKeyUnavailable);
        }
        Ok(Self {
            address,
            execution_epoch,
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id,
            version,
        })
    }

    #[must_use]
    pub const fn address(&self) -> MailboxAddress {
        self.address
    }

    #[must_use]
    pub const fn execution_epoch(&self) -> ExecutionEpoch {
        self.execution_epoch
    }

    #[must_use]
    pub const fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.key_id == [0; 32]
            || self.version == 0
            || self.algorithm != EncryptionAlgorithm::AES_256_GCM
        {
            return Err(JournalError::HistoryKeyUnavailable);
        }
        Ok(())
    }
}

/// Existing-only key lookup; recovery must never silently mint a new root.
///
/// An implementation must persist the referenced history key independently
/// of the erased per-launch secret and deny missing, retired or revoked keys.
pub trait HistoryKeyCustody {
    /// Load the exact retained version, or refuse without creating a key.
    fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError>;
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
    #[error("mailbox expiry settlement needs another bounded pass")]
    MaintenancePending,
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
    #[error("guest-leased message requires a signed guest acknowledgement")]
    GuestAckRequired,
    #[error("journal cannot be used after an uncertain write")]
    Uncertain,
    #[error("independent rollback anchor and recoverable key custody are required")]
    DurableAuthorityUnavailable,
    #[error("mailbox history key is unavailable")]
    HistoryKeyUnavailable,
    #[error("mailbox history key identity does not match retained records")]
    HistoryKeyMismatch,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history_key: Option<HistoryKeyRef>,
    event: JournalEvent,
}

struct JournalKey {
    bytes: Zeroizing<[u8; 32]>,
    reference: Option<HistoryKeyRef>,
    tier: AcceptanceTier,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AcceptanceTier {
    Independent,
    Local,
}

impl JournalKey {
    fn unversioned(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            reference: None,
            tier: AcceptanceTier::Independent,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEvent {
    Accepted {
        identity: ReplayIdentity,
        frame: String,
        receipt: Box<DestinationReceipt>,
        authorization_signature: Vec<u8>,
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
    Expired {
        identity: ReplayIdentity,
        expired_at_unix_ms: i64,
        authorization_signature: Vec<u8>,
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
    accepted_receipt: DestinationReceipt,
    acknowledged: bool,
    expired_at_unix_ms: Option<i64>,
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
    history_key: Option<HistoryKeyRef>,
    tier: AcceptanceTier,
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

#[derive(Serialize)]
struct AcceptanceIntent<'a> {
    identity: ReplayIdentity,
    frame: &'a str,
    receipt: &'a DestinationReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    history_key: Option<&'a HistoryKeyRef>,
}

fn acceptance_intent_bytes(
    identity: ReplayIdentity,
    frame: &str,
    receipt: &DestinationReceipt,
    history_key: Option<&HistoryKeyRef>,
) -> Result<Vec<u8>, JournalError> {
    let domain = if history_key.is_some() {
        ACCEPTANCE_INTENT_DOMAIN_V3
    } else {
        ACCEPTANCE_INTENT_DOMAIN_V2
    };
    let mut bytes = domain.to_vec();
    bytes.extend(
        serde_jcs::to_vec(&AcceptanceIntent {
            identity,
            frame,
            receipt,
            history_key,
        })
        .map_err(|_| JournalError::Corrupt)?,
    );
    Ok(bytes)
}

#[derive(Serialize)]
struct ExpiryIntent {
    address: MailboxAddress,
    identity: ReplayIdentity,
    ciphertext_commitment: [u8; 32],
    expired_at_unix_ms: i64,
}

fn expiry_intent_bytes(
    address: MailboxAddress,
    identity: ReplayIdentity,
    entry: &Seen,
    expired_at_unix_ms: i64,
) -> Result<Vec<u8>, JournalError> {
    let mut bytes = EXPIRY_INTENT_DOMAIN.to_vec();
    bytes.extend(
        serde_jcs::to_vec(&ExpiryIntent {
            address,
            identity,
            ciphertext_commitment: entry.envelope.ciphertext_commitment,
            expired_at_unix_ms,
        })
        .map_err(|_| JournalError::Corrupt)?,
    );
    Ok(bytes)
}

/// Authenticate retained reader controls at their original issuance time.
/// Current boot, policy and revocation are checked separately before use.
fn verify_recovered_lease(
    entry: &Seen,
    identity: ReplayIdentity,
    lease: &SignedMailboxDeliveryLease,
    enrollment: &SignedMailboxGuestReaderEnrollment,
    capability: &SignedMailboxCapability,
    authority: &VerifyingKey,
    now_unix_ms: i64,
) -> Result<VerifyingKey, JournalError> {
    let plan = MailboxGrant {
        mailbox: lease.lease.address.mailbox,
        authority_key: authority.to_bytes(),
        epoch: lease.lease.execution_epoch,
        report: None,
    };
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &enrollment.enrollment.plan_id,
        plan_nonce: &enrollment.enrollment.plan_nonce,
        receive: &capability.grant,
        current_boot: enrollment.enrollment.consumer_boot,
        current_session: enrollment.enrollment.consumer_session,
        now_unix_ms,
    };
    let guest_key = verify_guest_reader_enrollment(enrollment, capability, &scope, authority, &[])
        .map_err(|_| JournalError::Corrupt)?;
    lease
        .check_scope(&plan, &capability.grant, scope.current_session, now_unix_ms)
        .map_err(|_| JournalError::Corrupt)?;
    verify_delivery_lease_signature(lease, authority).map_err(|_| JournalError::Corrupt)?;
    if lease.lease.sender != identity.sender
        || lease.lease.sender_boot != identity.sender_boot
        || lease.lease.message_id != identity.message_id
        || lease.lease.execution_epoch != identity.execution_epoch
        || lease.lease.delivery_id != entry.envelope.routing.delivery_id
        || lease.lease.ciphertext_commitment != entry.envelope.ciphertext_commitment
        || lease.lease.expires_at_unix_ms > entry.envelope.routing.expires_at_unix_ms
    {
        return Err(JournalError::Corrupt);
    }
    Ok(guest_key)
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
        Self::open_with_recovery(
            root,
            address,
            authority,
            JournalKey::unversioned(key),
            limits,
            expected,
            |_| Err(JournalError::Rollback),
        )
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
        Self::open_with_recovery(
            root,
            address,
            authority,
            JournalKey::unversioned(key),
            limits,
            anchor.tip(),
            |tip| anchor.advance(tip),
        )
    }

    /// Recover a raw-key preproduction journal against an anchor.
    ///
    /// An intact, authenticated journal suffix may be advanced after a crash.
    /// A missing, divergent, or rolled-back anchored prefix is never repaired.
    /// This opener does not establish retained key custody and cannot issue
    /// a durable receipt; use [`Self::open_with_custody`] for versioned history.
    pub fn open_with_anchor(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: [u8; 32],
        limits: JournalLimits,
        anchor: &impl JournalAnchor,
    ) -> Result<Self, JournalError> {
        Self::open_against_anchor(
            root,
            address,
            authority,
            JournalKey::unversioned(key),
            limits,
            anchor,
        )
    }

    /// Reopen a test-scoped versioned history with an existing key.
    ///
    /// The production seam remains unavailable until a verified admission
    /// scope and authenticated restart manifest can supply this reference.
    /// This test path must not derive its key from the erased launch secret.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_with_custody(
        root: &Path,
        reference: HistoryKeyRef,
        authority: VerifyingKey,
        limits: JournalLimits,
        custody: &impl HistoryKeyCustody,
        anchor: &impl JournalAnchor,
    ) -> Result<Self, JournalError> {
        reference.validate()?;
        let key = custody.load_existing(&reference)?;
        Self::open_against_anchor(
            root,
            reference.address,
            authority,
            JournalKey {
                bytes: Zeroizing::new(*key.expose_bytes()),
                reference: Some(reference),
                tier: AcceptanceTier::Independent,
            },
            limits,
            anchor,
        )
    }

    /// Reopen the software-only local tier against a fsynced same-host anchor.
    ///
    /// The trusted host must obtain the reference and existing key from an
    /// authenticated restart manifest bound to its admitted plan/VM/mailbox.
    /// A deserialized reference alone is never authorization to open history.
    pub fn open_local_with_custody(
        root: &Path,
        reference: HistoryKeyRef,
        authority: VerifyingKey,
        limits: JournalLimits,
        custody: &impl HistoryKeyCustody,
        anchor: &FileJournalAnchor,
    ) -> Result<Self, JournalError> {
        reference.validate()?;
        if reference.address != anchor.address {
            return Err(JournalError::WrongAuthority);
        }
        let key = custody.load_existing(&reference)?;
        Self::open_with_recovery(
            root,
            reference.address,
            authority,
            JournalKey {
                bytes: Zeroizing::new(*key.expose_bytes()),
                reference: Some(reference),
                tier: AcceptanceTier::Local,
            },
            limits,
            anchor.tip(),
            |next| anchor.advance(next),
        )
    }

    fn open_against_anchor(
        root: &Path,
        address: MailboxAddress,
        authority: VerifyingKey,
        key: JournalKey,
        limits: JournalLimits,
        anchor: &impl JournalAnchor,
    ) -> Result<Self, JournalError> {
        let expected = anchor.load(address)?;
        let mut previous = expected;
        Self::open_with_recovery(root, address, authority, key, limits, expected, |next| {
            anchor.compare_and_advance(address, previous, next)?;
            previous = next;
            Ok(())
        })
    }

    fn open_with_recovery(
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
        let mut suffix_synced = false;
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
                        .filter(|entry| !entry.acknowledged && entry.expired_at_unix_ms.is_none())
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
        Ok(journal)
    }

    /// The legacy local callback cannot prove an independent anchor or
    /// recoverable key custody, so it cannot issue durable acceptance.
    ///
    /// Use [`Self::admit_with_anchor`] only after provisioning a trusted
    /// external checkpoint and durable mailbox-history keys.
    pub fn admit(
        &mut self,
        _request: JournalAdmission<'_>,
        _anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        Err(JournalError::DurableAuthorityUnavailable)
    }

    fn admit_verified(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        self.admit_at_tier(request, AcceptanceTier::Independent, anchor)
    }

    fn admit_at_tier(
        &mut self,
        request: JournalAdmission<'_>,
        tier: AcceptanceTier,
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
        if self.tier != tier {
            return Err(JournalError::DurableAuthorityUnavailable);
        }
        if self.address.tenant != context.expected_tenant
            || self.address.authorization_domain != context.expected_authorization_domain
            || self.address.mailbox != context.expected_mailbox
            || self.address.recipient != context.expected_recipient
            || signer.verifying_key() != self.authority
        {
            return Err(JournalError::WrongAuthority);
        }
        if self.history_key.is_some_and(|reference| {
            reference.address != self.address
                || reference.execution_epoch != context.current_execution_epoch
        }) {
            return Err(JournalError::HistoryKeyMismatch);
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
            protocol_version: match tier {
                AcceptanceTier::Independent => ProtocolVersion::V1,
                AcceptanceTier::Local => ProtocolVersion::V2,
            },
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
            if previous.expired_at_unix_ms.is_some() {
                return Err(JournalError::Mailbox(MailboxError::Expired));
            }
            let expected_outcome = match tier {
                AcceptanceTier::Independent => DeliveryOutcome::AcceptedDurable,
                AcceptanceTier::Local => DeliveryOutcome::AcceptedLocalDurable,
            };
            if previous.accepted_receipt.outcome != expected_outcome
                || previous.accepted_receipt.address != self.address
                || previous.accepted_receipt.message_id != opened.header().message_id
                || previous.accepted_receipt.ciphertext_commitment != envelope.ciphertext_commitment
            {
                return Err(JournalError::Corrupt);
            }
            return Ok(sign_receipt(
                match tier {
                    AcceptanceTier::Independent => receipt(DeliveryOutcome::Duplicate),
                    AcceptanceTier::Local => previous.accepted_receipt.clone(),
                },
                signer,
            )?);
        }
        if self.tip.cursor >= self.limits.max_records as u64 {
            return Err(JournalError::Full);
        }
        let accepted = receipt(match tier {
            AcceptanceTier::Independent => DeliveryOutcome::AcceptedDurable,
            AcceptanceTier::Local => DeliveryOutcome::AcceptedLocalDurable,
        });
        let encoded_frame =
            frame::encode_frame(capability, envelope).map_err(|_| JournalError::Corrupt)?;
        let encoded_frame = STANDARD_NO_PAD.encode(encoded_frame);
        let authorization_signature = signer
            .sign(&acceptance_intent_bytes(
                identity,
                &encoded_frame,
                &accepted,
                self.history_key.as_ref(),
            )?)
            .to_bytes()
            .to_vec();
        self.append(
            JournalEvent::Accepted {
                identity,
                frame: encoded_frame,
                receipt: Box::new(accepted.clone()),
                authorization_signature,
            },
            anchor,
        )?;
        self.seen.insert(
            identity,
            Seen {
                envelope: envelope.clone(),
                capability: capability.clone(),
                accepted_receipt: accepted.clone(),
                acknowledged: false,
                expired_at_unix_ms: None,
                lease: None,
                signed_ack: None,
            },
        );
        self.order.push(identity);
        sign_receipt(accepted, signer).map_err(JournalError::from)
    }

    /// Admit only against the current independently anchored tip.
    ///
    /// The legacy local-file callback API refuses admission. A service may
    /// use this path only with independent checkpoint and history-key custody.
    pub fn admit_with_anchor(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: &impl JournalAnchor,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        if self.history_key.is_none() {
            return Err(JournalError::DurableAuthorityUnavailable);
        }
        let expected = self.tip;
        if anchor.load(self.address)? != expected {
            return Err(JournalError::Rollback);
        }
        let address = self.address;
        self.admit_verified(request, |next| {
            anchor.compare_and_advance(address, expected, next)
        })
    }

    /// Verify that an opened local journal still agrees with its held anchor
    /// and the destination authority before binding a listener.
    pub fn local_ready(
        &self,
        anchor: &FileJournalAnchor,
        authority: &VerifyingKey,
    ) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if self.tier != AcceptanceTier::Local || self.history_key.is_none() {
            return Err(JournalError::DurableAuthorityUnavailable);
        }
        if &self.authority != authority {
            return Err(JournalError::WrongAuthority);
        }
        if anchor.address != self.address || anchor.tip() != self.tip {
            return Err(JournalError::Rollback);
        }
        Ok(())
    }

    /// Commit local acceptance only after the ciphertext/dedup record and
    /// same-host anchor are fsynced. This cannot detect whole-host rollback.
    pub fn admit_local(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: &FileJournalAnchor,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        self.local_ready(anchor, &request.signer.verifying_key())?;
        self.admit_at_tier(request, AcceptanceTier::Local, |next| anchor.advance(next))
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
            version: if self.history_key.is_some() { 3 } else { 2 },
            cursor,
            previous: self.tip.head,
            address: self.address,
            history_key: self.history_key,
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

    /// Commit one expired message's terminal state before returning its signed
    /// outcome. A full journal refuses rather than dropping retained dedup data.
    pub fn expire_next(
        &mut self,
        now_unix_ms: i64,
        signer: &SigningKey,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<SignedDestinationReceipt>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if now_unix_ms < 0 || signer.verifying_key() != self.authority {
            return Err(JournalError::WrongAuthority);
        }
        let Some(identity) = self.order.iter().copied().find(|identity| {
            self.seen.get(identity).is_some_and(|entry| {
                !entry.acknowledged
                    && entry.expired_at_unix_ms.is_none()
                    && now_unix_ms >= entry.envelope.routing.expires_at_unix_ms
            })
        }) else {
            return Ok(None);
        };
        let entry = self.seen.get(&identity).ok_or(JournalError::Corrupt)?;
        let authorization_signature = signer
            .sign(&expiry_intent_bytes(
                self.address,
                identity,
                entry,
                now_unix_ms,
            )?)
            .to_bytes()
            .to_vec();
        self.append(
            JournalEvent::Expired {
                identity,
                expired_at_unix_ms: now_unix_ms,
                authorization_signature,
            },
            anchor,
        )?;
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .expired_at_unix_ms = Some(now_unix_ms);
        Ok(Some(self.expired_receipt(identity, signer)?))
    }

    /// Reconstruct the original signed terminal expiry after a lost response,
    /// but only from the verified and committed journal state.
    pub fn expired_receipt(
        &self,
        identity: ReplayIdentity,
        signer: &SigningKey,
    ) -> Result<SignedDestinationReceipt, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if signer.verifying_key() != self.authority {
            return Err(JournalError::WrongAuthority);
        }
        let entry = self
            .seen
            .get(&identity)
            .ok_or(JournalError::UnknownMessage)?;
        let observed_at_unix_ms = entry
            .expired_at_unix_ms
            .ok_or(JournalError::UnknownMessage)?;
        Ok(sign_receipt(
            DestinationReceipt {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                delivery_id: entry.envelope.routing.delivery_id,
                message_id: identity.message_id,
                address: self.address,
                execution_epoch: identity.execution_epoch,
                outcome: DeliveryOutcome::Expired,
                observed_at_unix_ms,
                ciphertext_commitment: entry.envelope.ciphertext_commitment,
            },
            signer,
        )?)
    }

    /// Inspect the oldest unacknowledged, unexpired ciphertext under a signed
    /// Receive grant. Call `expire_next` first to durably settle expired entries;
    /// an empty read alone is not an expiry receipt.
    pub fn receive_next(
        &self,
        request: JournalReceive<'_>,
    ) -> Result<Option<ReceivedMailboxMessage>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        for identity in &self.order {
            let entry = self.seen.get(identity).ok_or(JournalError::Corrupt)?;
            if entry.acknowledged
                || entry.expired_at_unix_ms.is_some()
                || request.context.now_unix_ms >= entry.envelope.routing.expires_at_unix_ms
            {
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
        if entry.expired_at_unix_ms.is_some() {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
        let _opened = self.open_for_reader(identity, entry, &request)?;
        if entry.lease.is_some() {
            return Err(JournalError::GuestAckRequired);
        }
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
        if entry.expired_at_unix_ms.is_some() {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
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
        if entry.acknowledged {
            return if entry.signed_ack.as_ref() == Some(request.signed) {
                Ok(self.tip)
            } else {
                Err(JournalError::ConflictingRetry)
            };
        }
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

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
        CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId,
        DeliveryId, DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch,
        MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxId, MailboxMessageKind,
        MailboxRoutingFrame, MessageId, OrderingScope, PrincipalId, ReplayNonce, RevocationId,
        SequenceNumber, TenantId, TransportBindingId,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct IndependentAnchor {
        address: MailboxAddress,
        tip: Mutex<JournalTip>,
    }

    impl IndependentAnchor {
        fn new(address: MailboxAddress) -> Self {
            Self {
                address,
                tip: Mutex::new(JournalTip::genesis()),
            }
        }
    }

    impl JournalAnchor for IndependentAnchor {
        fn load(&self, address: MailboxAddress) -> Result<JournalTip, JournalError> {
            if address != self.address {
                return Err(JournalError::WrongAuthority);
            }
            Ok(*self.tip.lock().expect("test anchor lock"))
        }

        fn compare_and_advance(
            &self,
            address: MailboxAddress,
            expected: JournalTip,
            next: JournalTip,
        ) -> Result<(), JournalError> {
            if address != self.address {
                return Err(JournalError::WrongAuthority);
            }
            let mut tip = self.tip.lock().expect("test anchor lock");
            if *tip != expected || expected.cursor.checked_add(1) != Some(next.cursor) {
                return Err(JournalError::Rollback);
            }
            *tip = next;
            Ok(())
        }
    }

    struct TestCustody {
        reference: HistoryKeyRef,
        bytes: Option<[u8; 32]>,
    }

    impl HistoryKeyCustody for TestCustody {
        fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError> {
            if reference != &self.reference {
                return Err(JournalError::HistoryKeyUnavailable);
            }
            self.bytes
                .map(Key::from_bytes)
                .ok_or(JournalError::HistoryKeyUnavailable)
        }
    }

    fn address() -> MailboxAddress {
        MailboxAddress {
            tenant: TenantId::from_bytes([1; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
            mailbox: MailboxId::from_bytes([3; 32]),
            recipient: PrincipalId::from_bytes([4; 32]),
        }
    }

    fn limits() -> JournalLimits {
        JournalLimits {
            max_records: 4,
            max_bytes: 64 * 1024,
        }
    }

    fn versioned_custody() -> (HistoryKeyRef, TestCustody) {
        let reference = HistoryKeyRef::new(
            address(),
            ExecutionEpoch::new(1).expect("test epoch"),
            [30; 32],
            1,
        )
        .expect("versioned key");
        (
            reference,
            TestCustody {
                reference,
                bytes: Some([21; 32]),
            },
        )
    }

    #[test]
    fn admission_intent_signature_is_bound_to_its_own_domain() {
        let (envelope, capability, context, _, _, signer) = message();
        let identity = ReplayIdentity {
            sender: context.expected_sender,
            sender_boot: BootId::from_bytes([8; 32]),
            execution_epoch: context.current_execution_epoch,
            message_id: MessageId::from_bytes([9; 32]),
        };
        let frame = STANDARD_NO_PAD
            .encode(frame::encode_frame(&capability, &envelope).expect("canonical frame"));
        let receipt = DestinationReceipt {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: envelope.routing.delivery_id,
            message_id: MessageId::from_bytes([9; 32]),
            address: address(),
            execution_epoch: context.current_execution_epoch,
            outcome: DeliveryOutcome::AcceptedDurable,
            observed_at_unix_ms: context.now_unix_ms,
            ciphertext_commitment: envelope.ciphertext_commitment,
        };
        let intent = acceptance_intent_bytes(identity, &frame, &receipt, None).expect("intent");
        let signature = signer.sign(&intent);
        signer
            .verifying_key()
            .verify(&intent, &signature)
            .expect("intended domain");
        let bare = serde_jcs::to_vec(&AcceptanceIntent {
            identity,
            frame: &frame,
            receipt: &receipt,
            history_key: None,
        })
        .expect("canonical intent");
        assert!(signer.verifying_key().verify(&bare, &signature).is_err());
        let wrong_domain = [b"mvm.mailbox.receipt.v1\0".as_slice(), bare.as_slice()].concat();
        assert!(
            signer
                .verifying_key()
                .verify(&wrong_domain, &signature)
                .is_err()
        );
    }

    fn message() -> (
        MailboxEnvelope,
        SignedMailboxCapability,
        OpenContext,
        Key,
        VerifyingKey,
        SigningKey,
    ) {
        let destination = address();
        let signer = SigningKey::from_bytes(&[6; 32]);
        let sender = SigningKey::from_bytes(&[7; 32]);
        let sender_id = PrincipalId::from_bytes(sender.verifying_key().to_bytes());
        let content_type = ContentType::parse("application/vnd.mvm.test", 1).expect("content type");
        let epoch = ExecutionEpoch::new(1).expect("epoch");
        let now = 1_800_000_000_000;
        let header = MailboxEnvelopeHeader {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            tenant: destination.tenant,
            authorization_domain: destination.authorization_domain,
            sender: sender_id,
            recipient: destination.recipient,
            mailbox: destination.mailbox,
            sender_boot: BootId::from_bytes([8; 32]),
            execution_epoch: epoch,
            message_id: MessageId::from_bytes([9; 32]),
            correlation_id: CorrelationId::from_bytes([10; 32]),
            causation_id: CausationId::from_bytes([11; 32]),
            kind: MailboxMessageKind::Cast,
            reply_to: None,
            ordering_scope: OrderingScope::parse("test").expect("scope"),
            sequence: SequenceNumber::new(1).expect("sequence"),
            issued_at_unix_ms: now - 1,
            expires_at_unix_ms: now + 10_000,
            nonce: ReplayNonce::from_bytes([12; 16]),
            content_type: content_type.clone(),
            capability_id: CapabilityId::from_bytes([13; 32]),
            policy_epoch: 1,
            encryption: EncryptionContext {
                algorithm: EncryptionAlgorithm::AES_256_GCM,
                key_id: [14; 32],
            },
            plaintext_len: 5,
        };
        let routing = MailboxRoutingFrame {
            protocol_version: ProtocolVersion::V1,
            authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes([15; 32]),
            destination_route_token: DestinationRouteToken::from_bytes([16; 32]),
            delivery_id: DeliveryId::from_bytes([17; 32]),
            ciphertext_len: 0,
            padding: CiphertextPadding::Exact,
            expires_at_unix_ms: header.expires_at_unix_ms,
            hop_limit: 4,
            transport_binding_id: TransportBindingId::from_bytes([18; 32]),
        };
        let payload_key = Key::from_bytes([19; 32]);
        let envelope = super::super::seal_envelope(
            super::super::SealRequest {
                routing,
                header: header.clone(),
                plaintext: b"hello",
            },
            &payload_key,
            &sender,
        )
        .expect("seal canonical frame");
        let grant = MailboxCapabilityGrant {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            capability_id: header.capability_id,
            issuer: PrincipalId::from_bytes(signer.verifying_key().to_bytes()),
            subject: sender_id,
            address: destination,
            operations: CapabilityOperations::from_operations(&[MailboxOperation::Send]),
            message_kinds: vec![MailboxMessageKind::Cast],
            content_types: vec![content_type.clone()],
            max_payload_bytes: 64,
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 1024,
            minimum_execution_epoch: epoch,
            maximum_execution_epoch: epoch,
            policy_epoch: 1,
            not_before_unix_ms: now - 10,
            expires_at_unix_ms: now + 10_000,
            revocation_id: RevocationId::from_bytes([20; 32]),
            delegation_depth: 0,
        };
        let capability = super::super::sign_capability(grant, &signer).expect("grant");
        let context = OpenContext {
            expected_tenant: destination.tenant,
            expected_authorization_domain: destination.authorization_domain,
            expected_mailbox: destination.mailbox,
            expected_sender: sender_id,
            expected_recipient: destination.recipient,
            acting_principal: sender_id,
            expected_capability_issuer: PrincipalId::from_bytes(signer.verifying_key().to_bytes()),
            current_execution_epoch: epoch,
            current_policy_epoch: 1,
            required_operation: MailboxOperation::Send,
            now_unix_ms: now,
            accepted_content_types: vec![content_type],
            revoked_capabilities: Vec::new(),
        };
        (
            envelope,
            capability,
            context,
            payload_key,
            sender.verifying_key(),
            signer,
        )
    }

    fn admission<'a>(
        envelope: &'a MailboxEnvelope,
        capability: &'a SignedMailboxCapability,
        context: &'a OpenContext,
        payload_key: &'a Key,
        sender_key: &'a VerifyingKey,
        signer: &'a SigningKey,
    ) -> JournalAdmission<'a> {
        JournalAdmission {
            envelope,
            capability,
            context,
            encryption_key: payload_key,
            sender_key,
            signer,
        }
    }

    #[test]
    fn local_acceptance_restarts_with_exact_receipt_and_refuses_rollback() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let anchor_path = dir.path().join("anchor").join("tip.json");
        let (envelope, capability, mut context, payload_key, sender_key, signer) = message();
        let (reference, custody) = versioned_custody();
        let anchor = FileJournalAnchor::open(&anchor_path, address(), [22; 32])
            .expect("local anchor genesis");
        let mut journal = MailboxJournal::open_local_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("empty local journal");
        let accepted = journal
            .admit_local(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("local record and anchor fsynced before signature");
        assert_eq!(accepted.receipt.protocol_version, ProtocolVersion::V2);
        assert_eq!(
            accepted.receipt.outcome,
            DeliveryOutcome::AcceptedLocalDurable
        );
        super::super::verify_receipt(&accepted, &signer.verifying_key())
            .expect("local receipt signature");
        assert_eq!(journal.tip(), anchor.tip());
        drop(journal);
        drop(anchor);

        let anchor = FileJournalAnchor::open(&anchor_path, address(), [22; 32])
            .expect("recover local anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("recover retained ciphertext and dedup");
        context.now_unix_ms += 1;
        let duplicate = journal
            .admit_local(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("recover original local receipt after lost reply");
        assert_eq!(
            serde_jcs::to_vec(&duplicate).expect("signed retry bytes"),
            serde_jcs::to_vec(&accepted).expect("signed original bytes")
        );
        assert_eq!(journal.tip().cursor, 1, "retry must not append");
        assert!(matches!(
            journal.admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &IndependentAnchor::new(address()),
            ),
            Err(JournalError::Rollback | JournalError::DurableAuthorityUnavailable)
        ));
        drop(journal);
        fs::remove_file(record_path(&root, 1)).expect("simulate journal-only rollback");
        assert!(matches!(
            MailboxJournal::open_local_with_custody(
                &root,
                reference,
                signer.verifying_key(),
                limits(),
                &custody,
                &anchor
            ),
            Err(JournalError::Rollback)
        ));
    }

    #[test]
    fn interrupted_terminal_expiry_reconciles_without_an_early_receipt() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let anchor_path = dir.path().join("anchor").join("tip.json");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let (reference, custody) = versioned_custody();
        let anchor =
            FileJournalAnchor::open(&anchor_path, address(), [22; 32]).expect("local anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("empty journal");
        journal
            .admit_local(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("local acceptance");
        let identity = journal.order[0];
        let deadline = envelope.routing.expires_at_unix_ms;
        assert!(
            journal
                .expire_next(deadline - 1, &signer, |_| Ok(()))
                .expect("not expired yet")
                .is_none()
        );
        assert!(matches!(
            journal.expire_next(deadline, &SigningKey::from_bytes(&[42; 32]), |_| Ok(())),
            Err(JournalError::WrongAuthority)
        ));
        assert!(matches!(
            journal.expire_next(deadline, &signer, |_| Err(JournalError::Rollback)),
            Err(JournalError::Rollback)
        ));
        assert_eq!(anchor.tip().cursor, 1, "no unanchored terminal receipt");
        assert!(matches!(
            journal.expired_receipt(identity, &signer),
            Err(JournalError::Uncertain)
        ));
        drop(journal);
        drop(anchor);

        let anchor =
            FileJournalAnchor::open(&anchor_path, address(), [22; 32]).expect("retained anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("verify and reconcile terminal suffix");
        assert_eq!(anchor.tip().cursor, 2);
        let expired = journal
            .expired_receipt(identity, &signer)
            .expect("terminal receipt after reconciliation");
        assert_eq!(expired.receipt.outcome, DeliveryOutcome::Expired);
        assert_eq!(expired.receipt.observed_at_unix_ms, deadline);
        super::super::verify_receipt(&expired, &signer.verifying_key())
            .expect("signed terminal outcome");
        assert!(matches!(
            journal.admit_local(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            ),
            Err(JournalError::Mailbox(MailboxError::Expired))
        ));
        assert!(
            journal
                .expire_next(deadline + 1, &signer, |_| Ok(()))
                .expect("idempotent expiry")
                .is_none()
        );
        assert!(matches!(
            journal.acknowledge(
                identity,
                JournalReceive {
                    capability: &capability,
                    context: &context,
                    encryption_key: &payload_key,
                    sender_key: &sender_key,
                },
                |_| Ok(())
            ),
            Err(JournalError::Mailbox(MailboxError::Expired))
        ));
        assert_eq!(journal.tip(), anchor.tip(), "no duplicate terminal event");
    }

    #[test]
    fn recovered_expiry_rejects_a_forged_authority_signature_even_with_a_valid_history_mac() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let anchor_path = dir.path().join("anchor").join("tip.json");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let (reference, custody) = versioned_custody();
        let anchor =
            FileJournalAnchor::open(&anchor_path, address(), [22; 32]).expect("local anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("empty journal");
        journal
            .admit_local(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("accepted");
        let accepted_tip = journal.tip();
        journal
            .expire_next(envelope.routing.expires_at_unix_ms, &signer, |tip| {
                anchor.advance(tip)
            })
            .expect("expiry commit")
            .expect("terminal receipt");
        let path = record_path(&root, 2);
        let ciphertext = fs::read(&path).expect("expiry record");
        let plaintext = aead::open(
            &journal.record_key(),
            &ciphertext[32..],
            &[DOMAIN, &accepted_tip.head].concat(),
        )
        .expect("decrypt expiry");
        let mut record: Record = serde_json::from_slice(&plaintext).expect("parse expiry");
        let JournalEvent::Expired {
            authorization_signature,
            ..
        } = &mut record.event
        else {
            panic!("the second record must be the terminal expiry");
        };
        authorization_signature[0] ^= 1;
        let forged = aead::seal(
            &journal.record_key(),
            &serde_json::to_vec(&record).expect("encode forged record"),
            &[DOMAIN, &accepted_tip.head].concat(),
        );
        journal.tip = accepted_tip;
        let mut bytes = journal.mac(&forged).to_vec();
        bytes.extend(forged);
        fs::write(path, bytes).expect("install valid-MAC forged expiry");
        drop(journal);
        drop(anchor);

        let anchor =
            FileJournalAnchor::open(&anchor_path, address(), [22; 32]).expect("retained anchor");
        assert!(matches!(
            MailboxJournal::open_local_with_custody(
                &root,
                reference,
                signer.verifying_key(),
                limits(),
                &custody,
                &anchor,
            ),
            Err(JournalError::Corrupt)
        ));
        assert_eq!(anchor.tip().cursor, 2, "recovery must not amend the anchor");
    }

    #[test]
    fn anchored_acceptance_recovers_ciphertext_and_dedup_without_plaintext_on_disk() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let (reference, custody) = versioned_custody();
        let mut journal = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("genesis");
        let accepted = journal
            .admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("anchor committed before receipt");
        assert_eq!(accepted.receipt.outcome, DeliveryOutcome::AcceptedDurable);
        assert_eq!(journal.tip(), anchor.load(address()).expect("remote tip"));
        let record = fs::read(record_path(&root, 1)).expect("encrypted record");
        assert!(
            !record
                .windows(b"hello".len())
                .any(|bytes| bytes == b"hello")
        );
        let decrypted = aead::open(
            &journal.record_key(),
            &record[32..],
            &[DOMAIN, &JournalTip::genesis().head].concat(),
        )
        .expect("authenticated journal record");
        let parsed: Record = serde_json::from_slice(&decrypted).expect("record body");
        let JournalEvent::Accepted {
            receipt,
            authorization_signature,
            ..
        } = parsed.event
        else {
            panic!("the first record must be an admission");
        };
        assert_eq!(*receipt, accepted.receipt);
        assert_eq!(authorization_signature.len(), 64);
        assert!(
            !decrypted
                .windows(accepted.signature.len())
                .any(|bytes| bytes == accepted.signature.as_slice()),
            "an actual acceptance signature must not be persisted before the anchor commit"
        );
        drop(journal);

        let mut recovered = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("restart recovers exact anchored history");
        let duplicate = recovered
            .admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("retry is deduplicated");
        assert_eq!(duplicate.receipt.outcome, DeliveryOutcome::Duplicate);
        assert_eq!(anchor.load(address()).expect("unchanged tip").cursor, 1);
    }

    #[test]
    fn scoped_history_key_survives_restart_and_refuses_missing_or_wrong_versions() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let reference = HistoryKeyRef::new(address(), context.current_execution_epoch, [30; 32], 1)
            .expect("versioned reference");
        let roundtrip: HistoryKeyRef =
            serde_json::from_slice(&serde_json::to_vec(&reference).expect("encode reference"))
                .expect("decode reference");
        assert_eq!(roundtrip, reference);
        assert!(matches!(
            HistoryKeyRef::new(address(), context.current_execution_epoch, [0; 32], 1),
            Err(JournalError::HistoryKeyUnavailable)
        ));
        assert!(matches!(
            HistoryKeyRef::new(address(), context.current_execution_epoch, [30; 32], 0),
            Err(JournalError::HistoryKeyUnavailable)
        ));
        let custody = TestCustody {
            reference,
            bytes: Some([21; 32]),
        };
        let anchor = IndependentAnchor::new(address());
        let missing = TestCustody {
            reference,
            bytes: None,
        };
        assert!(matches!(
            MailboxJournal::open_with_custody(
                &root,
                reference,
                signer.verifying_key(),
                limits(),
                &missing,
                &anchor,
            ),
            Err(JournalError::HistoryKeyUnavailable)
        ));
        assert!(
            !root.exists(),
            "a recovery read must not create missing keys or history"
        );

        let mut journal = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("new history uses retained test key");
        let accepted = journal
            .admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("record and dedup anchored");
        let record = fs::read(record_path(&root, 1)).expect("history record");
        let body = aead::open(
            &journal.record_key(),
            &record[32..],
            &[DOMAIN, &JournalTip::genesis().head].concat(),
        )
        .expect("open authenticated record");
        let parsed: Record = serde_json::from_slice(&body).expect("versioned record");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.history_key, Some(reference));
        let JournalEvent::Accepted {
            identity,
            frame,
            receipt,
            authorization_signature,
        } = parsed.event
        else {
            panic!("versioned record must be an admission");
        };
        let signature: [u8; 64] = authorization_signature
            .try_into()
            .expect("destination intent signature");
        let signature = Signature::from_bytes(&signature);
        signer
            .verifying_key()
            .verify(
                &acceptance_intent_bytes(identity, &frame, &receipt, Some(&reference))
                    .expect("v3 intent"),
                &signature,
            )
            .expect("key reference is signed under the v3 domain");
        assert!(
            signer
                .verifying_key()
                .verify(
                    &acceptance_intent_bytes(identity, &frame, &receipt, None).expect("v2 intent"),
                    &signature,
                )
                .is_err(),
            "a v3 key reference cannot borrow the old intent domain"
        );
        drop(journal);

        let mut recovered = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("exact historical key and ref recover");
        let retained = recovered
            .seen
            .get(&identity)
            .expect("recovered dedup identity")
            .accepted_receipt
            .clone();
        assert_eq!(
            retained, accepted.receipt,
            "original acceptance time is retained"
        );
        assert_eq!(
            sign_receipt(retained, &signer)
                .expect("deterministic original signature")
                .signature,
            accepted.signature,
            "an authorized signer can reproduce the original proof after a lost response"
        );
        assert_eq!(
            recovered
                .admit_with_anchor(
                    admission(
                        &envelope,
                        &capability,
                        &context,
                        &payload_key,
                        &sender_key,
                        &signer,
                    ),
                    &anchor,
                )
                .expect("retry deduplicates")
                .receipt
                .outcome,
            DeliveryOutcome::Duplicate
        );
        drop(recovered);

        for changed in [
            HistoryKeyRef::new(address(), context.current_execution_epoch, [31; 32], 1)
                .expect("other key id"),
            HistoryKeyRef::new(address(), context.current_execution_epoch, [30; 32], 2)
                .expect("other version"),
            HistoryKeyRef::new(
                address(),
                ExecutionEpoch::new(2).expect("other epoch"),
                [30; 32],
                1,
            )
            .expect("other epoch reference"),
        ] {
            let same_bytes = TestCustody {
                reference: changed,
                bytes: Some([21; 32]),
            };
            assert!(matches!(
                MailboxJournal::open_with_custody(
                    &root,
                    changed,
                    signer.verifying_key(),
                    limits(),
                    &same_bytes,
                    &anchor,
                ),
                Err(JournalError::HistoryKeyMismatch)
            ));
        }
        let wrong_bytes = TestCustody {
            reference,
            bytes: Some([22; 32]),
        };
        assert!(matches!(
            MailboxJournal::open_with_custody(
                &root,
                reference,
                signer.verifying_key(),
                limits(),
                &wrong_bytes,
                &anchor,
            ),
            Err(JournalError::Corrupt)
        ));
        for (field, value) in [
            ("/version", serde_json::json!(2)),
            ("/key_id", serde_json::json!(vec![31u8; 32])),
            ("/execution_epoch", serde_json::json!(2)),
        ] {
            let mut forged = serde_json::to_value(reference).expect("reference JSON");
            *forged.pointer_mut(field).expect("reference field") = value;
            let forged: HistoryKeyRef = serde_json::from_value(forged).expect("forged reference");
            assert!(matches!(
                MailboxJournal::open_with_custody(
                    &root,
                    forged,
                    signer.verifying_key(),
                    limits(),
                    &TestCustody {
                        reference: forged,
                        bytes: Some([21; 32]),
                    },
                    &anchor,
                ),
                Err(JournalError::HistoryKeyMismatch)
            ));
        }
        let mut foreign = serde_json::to_value(reference).expect("reference JSON");
        foreign["address"]["authorization_domain"] = serde_json::json!(vec![55u8; 32]);
        let foreign_ref: HistoryKeyRef =
            serde_json::from_value(foreign).expect("forged foreign-domain reference");
        assert!(matches!(
            MailboxJournal::open_with_custody(
                &root,
                foreign_ref,
                signer.verifying_key(),
                limits(),
                &TestCustody {
                    reference: foreign_ref,
                    bytes: Some([21; 32]),
                },
                &anchor,
            ),
            Err(JournalError::WrongAuthority)
        ));
        let mut unsupported = serde_json::to_value(reference).expect("reference value");
        unsupported["algorithm"] = serde_json::json!(42);
        let unsupported: HistoryKeyRef = serde_json::from_value(unsupported).expect("raw version");
        assert!(matches!(
            MailboxJournal::open_with_custody(
                &root,
                unsupported,
                signer.verifying_key(),
                limits(),
                &custody,
                &anchor,
            ),
            Err(JournalError::HistoryKeyUnavailable)
        ));
        assert_eq!(anchor.load(address()).expect("anchor unchanged").cursor, 1);
    }

    #[test]
    fn preproduction_unversioned_history_is_not_reinterpreted_under_v3_custody() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let mut legacy = MailboxJournal::open_with_anchor(
            &root,
            address(),
            signer.verifying_key(),
            [21; 32],
            limits(),
            &anchor,
        )
        .expect("v2 test history");
        let prior = legacy.tip();
        legacy
            .admit_verified(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                |next| anchor.compare_and_advance(address(), prior, next),
            )
            .expect("model a previously written v2 record");
        let record = fs::read(record_path(&root, 1)).expect("v2 bytes");
        let tip = anchor.load(address()).expect("v2 anchored tip");
        drop(legacy);

        let (reference, custody) = versioned_custody();
        assert!(matches!(
            MailboxJournal::open_with_custody(
                &root,
                reference,
                signer.verifying_key(),
                limits(),
                &custody,
                &anchor,
            ),
            Err(JournalError::Corrupt)
        ));
        assert_eq!(
            fs::read(record_path(&root, 1)).expect("retained bytes"),
            record
        );
        assert_eq!(anchor.load(address()).expect("unchanged anchor"), tip);
    }

    #[test]
    fn unsigned_host_ack_remains_available_only_before_a_guest_lease() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let (reference, custody) = versioned_custody();
        let mut journal = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("genesis");
        journal
            .admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("accepted under test anchor");
        let mut receive_grant = capability.grant.clone();
        receive_grant.subject = address().recipient;
        receive_grant.capability_id = CapabilityId::from_bytes([31; 32]);
        receive_grant.operations =
            CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
        let receive = super::super::sign_capability(receive_grant, &signer).expect("Receive grant");
        let mut reader_context = context;
        reader_context.acting_principal = address().recipient;
        reader_context.required_operation = MailboxOperation::Receive;
        let reader = JournalReceive {
            capability: &receive,
            context: &reader_context,
            encryption_key: &payload_key,
            sender_key: &sender_key,
        };
        let identity = ReplayIdentity {
            sender: reader_context.expected_sender,
            sender_boot: BootId::from_bytes([8; 32]),
            execution_epoch: reader_context.current_execution_epoch,
            message_id: MessageId::from_bytes([9; 32]),
        };
        let previous = journal.tip();
        let tip = journal
            .acknowledge(identity, reader, |next| {
                anchor.compare_and_advance(address(), previous, next)
            })
            .expect("never-leased host message can be acknowledged");
        assert_eq!(tip.cursor, 2);
        drop(journal);
        let recovered = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("host ACK survives restart");
        assert!(
            recovered
                .receive_next(reader)
                .expect("authorized reader")
                .is_none()
        );
    }

    #[test]
    fn interrupted_anchor_commit_reconciles_only_intact_suffix() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let (reference, custody) = versioned_custody();
        let mut journal = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("genesis");
        let interrupted = AtomicBool::new(true);
        assert!(matches!(
            journal.admit_verified(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                |tip| {
                    if interrupted.swap(false, Ordering::SeqCst) {
                        return Err(JournalError::Uncertain);
                    }
                    anchor.compare_and_advance(address(), JournalTip::genesis(), tip)
                }
            ),
            Err(JournalError::Uncertain)
        ));
        assert_eq!(
            anchor.load(address()).expect("no receipt"),
            JournalTip::genesis()
        );
        assert!(matches!(
            journal.admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor
            ),
            Err(JournalError::Rollback)
        ));
        drop(journal);
        let recovered = MailboxJournal::open_with_custody(
            &root,
            reference,
            signer.verifying_key(),
            limits(),
            &custody,
            &anchor,
        )
        .expect("verified unanchored suffix is reconciled");
        assert_eq!(
            recovered.tip(),
            anchor.load(address()).expect("advanced tip")
        );
    }

    #[test]
    fn legacy_callback_cannot_issue_durable_acceptance() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let mut journal = MailboxJournal::open_with_anchor(
            &root,
            address(),
            signer.verifying_key(),
            [21; 32],
            limits(),
            &anchor,
        )
        .expect("genesis");
        assert!(matches!(
            journal.admit(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                |_| Ok(())
            ),
            Err(JournalError::DurableAuthorityUnavailable)
        ));
        assert!(matches!(
            journal.admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            ),
            Err(JournalError::DurableAuthorityUnavailable)
        ));
        assert_eq!(journal.tip(), JournalTip::genesis());
        assert_eq!(
            anchor.load(address()).expect("no commit"),
            JournalTip::genesis()
        );
    }

    #[test]
    fn wrong_key_tamper_and_truncation_fail_closed_without_changing_anchor() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let anchor = IndependentAnchor::new(address());
        let (reference, _) = versioned_custody();
        let open = |key_bytes, authority| {
            MailboxJournal::open_with_custody(
                &root,
                reference,
                authority,
                limits(),
                &TestCustody {
                    reference,
                    bytes: Some(key_bytes),
                },
                &anchor,
            )
        };
        let mut journal = open([21; 32], signer.verifying_key()).expect("genesis");
        journal
            .admit_with_anchor(
                admission(
                    &envelope,
                    &capability,
                    &context,
                    &payload_key,
                    &sender_key,
                    &signer,
                ),
                &anchor,
            )
            .expect("admission");
        let tip = anchor.load(address()).expect("committed tip");
        drop(journal);

        assert!(matches!(
            open([22; 32], signer.verifying_key()),
            Err(JournalError::Corrupt)
        ));
        assert!(matches!(
            open([21; 32], SigningKey::from_bytes(&[23; 32]).verifying_key()),
            Err(JournalError::Corrupt)
        ));
        let path = record_path(&root, 1);
        let original = fs::read(&path).expect("stored ciphertext");
        let mut tampered = original.clone();
        tampered[40] ^= 1;
        fs::write(&path, &tampered).expect("tamper record");
        assert!(matches!(
            open([21; 32], signer.verifying_key()),
            Err(JournalError::Corrupt)
        ));
        fs::write(&path, &original[..40]).expect("interrupted write");
        assert!(matches!(
            open([21; 32], signer.verifying_key()),
            Err(JournalError::Corrupt)
        ));
        assert_eq!(anchor.load(address()).expect("unchanged anchor"), tip);
        fs::remove_file(&path).expect("simulate journal rollback");
        assert!(matches!(
            open([21; 32], signer.verifying_key()),
            Err(JournalError::Rollback)
        ));
    }

    #[test]
    fn independent_anchor_refuses_wrong_domain_and_stale_competing_writers() {
        let anchor = IndependentAnchor::new(address());
        let old = JournalTip::genesis();
        let next = JournalTip {
            cursor: 1,
            head: [9; 32],
        };
        let mut foreign = address();
        foreign.authorization_domain = AuthorizationDomainId::from_bytes([5; 32]);
        assert!(matches!(
            anchor.load(foreign),
            Err(JournalError::WrongAuthority)
        ));
        anchor
            .compare_and_advance(address(), old, next)
            .expect("first writer advances");
        assert!(matches!(
            anchor.compare_and_advance(address(), old, next),
            Err(JournalError::Rollback)
        ));
        assert_eq!(anchor.load(address()).expect("authoritative tip"), next);
    }

    #[test]
    fn recovery_refuses_missing_anchored_history_and_wrong_domain() {
        let dir = tempfile::tempdir().expect("journal root");
        let root = dir.path().join("journal");
        let authority = SigningKey::from_bytes(&[6; 32]).verifying_key();
        let anchor = IndependentAnchor::new(address());
        let journal = MailboxJournal::open_with_anchor(
            &root,
            address(),
            authority,
            [7; 32],
            limits(),
            &anchor,
        )
        .expect("empty history agrees with genesis");
        assert_eq!(journal.tip(), JournalTip::genesis());
        drop(journal);

        let anchored = JournalTip {
            cursor: 1,
            head: [8; 32],
        };
        anchor
            .compare_and_advance(address(), JournalTip::genesis(), anchored)
            .expect("external anchor survives local loss");
        assert!(matches!(
            MailboxJournal::open_with_anchor(
                &root,
                address(),
                authority,
                [7; 32],
                limits(),
                &anchor,
            ),
            Err(JournalError::Rollback)
        ));
        let mut foreign = address();
        foreign.tenant = TenantId::from_bytes([9; 32]);
        assert!(matches!(
            MailboxJournal::open_with_anchor(&root, foreign, authority, [7; 32], limits(), &anchor),
            Err(JournalError::WrongAuthority)
        ));
    }
}
