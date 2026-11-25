//! Read-only observation of the durable protected commissioning state log.
//!
//! This module validates public progress evidence only. It does not acquire or
//! validate a lock, perform a transition, reconcile another artifact, or grant
//! readiness authority.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::hvf_owner_commissioning_intent::{LoadedHvfOwnerCommissioningIntent, has_extended_acl};
use crate::hvf_owner_protected_authority_root::ProtectedAuthorityRoot;

/// Fixed child name below the protected authority root.
pub const COMMISSIONING_STATE_NAME: &str = "owner-commissioning-state.jsonl";
/// First and only supported commissioning-state record schema.
pub const COMMISSIONING_STATE_VERSION: u8 = 1;
/// Maximum canonical bytes in one record, excluding its newline delimiter.
pub const MAX_COMMISSIONING_STATE_LINE_BYTES: usize = 8 * 1024;
/// Maximum bytes in the complete state log.
pub const MAX_COMMISSIONING_STATE_BYTES: usize = 64 * 1024;

const RECORD_DOMAIN: &[u8] = b"mvm.hvf-owner.commissioning-state-record.v1\0";
const ZERO_DIGEST: [u8; 32] = [0; 32];

/// A closed commissioning progress phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommissioningPhase {
    /// The fixed intent and authority namespace were accepted for commissioning.
    Prepared,
    /// Public evidence for key creation was retained.
    KeyCreated,
    /// Public evidence for journal initialization was retained.
    JournalInitialized,
    /// Receipt publication remained pending.
    ReceiptPending,
    /// Public evidence for completion publication was retained.
    CompletionPublished,
    /// The append-only protocol reached its terminal observation.
    Ready,
}

impl CommissioningPhase {
    fn ordinal(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::KeyCreated => 1,
            Self::JournalInitialized => 2,
            Self::ReceiptPending => 3,
            Self::CompletionPublished => 4,
            Self::Ready => 5,
        }
    }
}

/// Readiness classification derived only from the retained state log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissioningReadiness {
    /// Commissioning is interrupted and consumers must refuse readiness.
    Interrupted,
    /// The terminal record says `Ready`; no external artifact was reconciled.
    Ready,
}

/// One immutable validated commissioning-state record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommissioningStateRecord {
    content: RecordContentV1,
    record_digest: [u8; 32],
}

impl CommissioningStateRecord {
    /// One-based append sequence.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.content.sequence
    }

    /// Phase represented by this record.
    #[must_use]
    pub fn phase(&self) -> CommissioningPhase {
        self.content.evidence.phase()
    }

    /// Digest of the preceding record, or zero for sequence one.
    #[must_use]
    pub fn previous_record_digest(&self) -> [u8; 32] {
        self.content.previous_record_digest
    }

    /// Domain-separated digest of this record's canonical content.
    #[must_use]
    pub fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Optional bounded public evidence digest for this phase.
    ///
    /// The digest is opaque public correlation evidence. Its presence does not
    /// prove key custody, lock ownership, journal validity, or publication.
    #[must_use]
    pub fn evidence_digest(&self) -> Option<[u8; 32]> {
        self.content.evidence.digest()
    }
}

/// Immutable validated view of a nonempty commissioning-state log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCommissioningState {
    records: Box<[CommissioningStateRecord]>,
    intent_digest: [u8; 32],
    deployment_id: String,
    deployment_epoch: u64,
    authority_uid: u32,
    authority_gid: u32,
    lock_device: u64,
    lock_inode: u64,
}

impl RetainedCommissioningState {
    /// Validated immutable records in append order.
    #[must_use]
    pub fn records(&self) -> &[CommissioningStateRecord] {
        &self.records
    }

    /// Last retained phase.
    #[must_use]
    pub fn phase(&self) -> CommissioningPhase {
        self.records
            .last()
            .expect("retained commissioning state is nonempty")
            .phase()
    }

    /// Readiness classification of the last record.
    #[must_use]
    pub fn readiness(&self) -> CommissioningReadiness {
        if self.phase() == CommissioningPhase::Ready {
            CommissioningReadiness::Ready
        } else {
            CommissioningReadiness::Interrupted
        }
    }

    /// Exact loaded commissioning-intent digest bound by every record.
    #[must_use]
    pub fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Deployment label bound by every record.
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Deployment epoch bound by every record.
    #[must_use]
    pub fn deployment_epoch(&self) -> u64 {
        self.deployment_epoch
    }

    /// Authority UID bound by every record.
    #[must_use]
    pub fn authority_uid(&self) -> u32 {
        self.authority_uid
    }

    /// Authority GID bound by every record.
    #[must_use]
    pub fn authority_gid(&self) -> u32 {
        self.authority_gid
    }

    /// Nonzero device identity reserved for the future commissioning lock.
    #[must_use]
    pub fn lock_device(&self) -> u64 {
        self.lock_device
    }

    /// Nonzero inode identity reserved for the future commissioning lock.
    #[must_use]
    pub fn lock_inode(&self) -> u64 {
        self.lock_inode
    }
}

/// Read-only commissioning-state observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum CommissioningStateObservation {
    /// The exact fixed child does not exist. This grants no freshness authority.
    Absent,
    /// A nonempty strict log was retained and validated.
    Retained(RetainedCommissioningState),
}

/// Commissioning-state filesystem or grammar failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HvfOwnerCommissioningStateError {
    /// The host cannot establish the production macOS observation contract.
    #[error("protected HVF owner commissioning state loading requires macOS")]
    Unsupported,
    /// The fixed state object could not be safely opened or read.
    #[error("protected HVF owner commissioning state is unavailable")]
    Unavailable(#[source] io::Error),
    /// The state object violated type, identity, mode, link, or ACL policy.
    #[error("protected HVF owner commissioning state filesystem policy failed")]
    FilesystemPolicy,
    /// The complete log exceeded its fixed byte bound.
    #[error("protected HVF owner commissioning state exceeds 64 KiB")]
    TooLarge,
    /// A line exceeded its fixed byte bound.
    #[error("protected HVF owner commissioning state line exceeds 8 KiB")]
    LineTooLarge,
    /// Original bytes were not strict canonical v1 JSONL.
    #[error("protected HVF owner commissioning state grammar is invalid")]
    Grammar,
    /// Record bindings, sequence, phase order, or digest chain were invalid.
    #[error("protected HVF owner commissioning state bindings are invalid")]
    Binding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    content: RecordContentV1,
    record_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordContentV1 {
    schema_version: u8,
    sequence: u64,
    previous_record_digest: [u8; 32],
    intent_digest: [u8; 32],
    deployment_id: String,
    deployment_epoch: u64,
    authority_uid: u32,
    authority_gid: u32,
    lock_device: u64,
    lock_inode: u64,
    evidence: PhaseEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum PhaseEvidenceV1 {
    Prepared {
        preparation_evidence_digest: Option<[u8; 32]>,
    },
    KeyCreated {
        public_key_evidence_digest: Option<[u8; 32]>,
    },
    JournalInitialized {
        journal_evidence_digest: Option<[u8; 32]>,
    },
    ReceiptPending {
        receipt_evidence_digest: Option<[u8; 32]>,
    },
    CompletionPublished {
        completion_evidence_digest: Option<[u8; 32]>,
    },
    Ready {
        readiness_evidence_digest: Option<[u8; 32]>,
    },
}

impl PhaseEvidenceV1 {
    fn phase(&self) -> CommissioningPhase {
        match self {
            Self::Prepared { .. } => CommissioningPhase::Prepared,
            Self::KeyCreated { .. } => CommissioningPhase::KeyCreated,
            Self::JournalInitialized { .. } => CommissioningPhase::JournalInitialized,
            Self::ReceiptPending { .. } => CommissioningPhase::ReceiptPending,
            Self::CompletionPublished { .. } => CommissioningPhase::CompletionPublished,
            Self::Ready { .. } => CommissioningPhase::Ready,
        }
    }

    fn digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Prepared {
                preparation_evidence_digest,
            } => *preparation_evidence_digest,
            Self::KeyCreated {
                public_key_evidence_digest,
            } => *public_key_evidence_digest,
            Self::JournalInitialized {
                journal_evidence_digest,
            } => *journal_evidence_digest,
            Self::ReceiptPending {
                receipt_evidence_digest,
            } => *receipt_evidence_digest,
            Self::CompletionPublished {
                completion_evidence_digest,
            } => *completion_evidence_digest,
            Self::Ready {
                readiness_evidence_digest,
            } => *readiness_evidence_digest,
        }
    }
}

/// Load the fixed state child from a retained validated authority root.
///
/// `Absent` means only that the exact child was absent at observation time.
/// A retained `Ready` record is terminal log evidence only and is not
/// reconciliation with a key, journal, receipt, completion, or lock.
///
/// # Errors
/// Refuses unsupported hosts and unsafe, oversized, noncanonical, malformed,
/// incorrectly bound, or concurrently growing state.
#[cfg(target_os = "macos")]
pub fn load_hvf_owner_commissioning_state(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    load_from_root(root, intent)
}

/// Unsupported platforms cannot establish the production observation contract.
///
/// # Errors
/// Always refuses without reading or changing filesystem state.
#[cfg(not(target_os = "macos"))]
pub fn load_hvf_owner_commissioning_state(
    _root: &ProtectedAuthorityRoot,
    _intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    Err(HvfOwnerCommissioningStateError::Unsupported)
}

/// Load through an injected, already validated authority-root descriptor.
///
/// This capability is absent from production builds. It performs the same
/// descriptor-relative fixed-child observation as the production loader.
///
/// # Errors
/// Refuses the same filesystem, bound, grammar, and binding failures.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn load_test_hvf_owner_commissioning_state(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    load_from_root(root, intent)
}

fn load_from_root(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    let file = match root.open_commissioning_state() {
        Ok(file) => file,
        Err(error) if error == rustix::io::Errno::NOENT => {
            return Ok(CommissioningStateObservation::Absent);
        }
        Err(error) => {
            return Err(HvfOwnerCommissioningStateError::Unavailable(error.into()));
        }
    };
    load_open_file(file, intent, || {})
}

fn load_open_file(
    mut file: File,
    intent: &LoadedHvfOwnerCommissioningIntent,
    after_read: impl FnOnce(),
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    require_state_file(&file, intent)?;
    let initial = file
        .metadata()
        .map_err(HvfOwnerCommissioningStateError::Unavailable)?;
    if initial.len() > MAX_COMMISSIONING_STATE_BYTES as u64 {
        return Err(HvfOwnerCommissioningStateError::TooLarge);
    }

    let mut bytes = Vec::with_capacity(initial.len() as usize);
    file.by_ref()
        .take(MAX_COMMISSIONING_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(HvfOwnerCommissioningStateError::Unavailable)?;
    if bytes.len() > MAX_COMMISSIONING_STATE_BYTES {
        return Err(HvfOwnerCommissioningStateError::TooLarge);
    }
    after_read();
    let final_metadata = file
        .metadata()
        .map_err(HvfOwnerCommissioningStateError::Unavailable)?;
    if final_metadata.len() != initial.len()
        || final_metadata.dev() != initial.dev()
        || final_metadata.ino() != initial.ino()
    {
        return Err(HvfOwnerCommissioningStateError::Unavailable(
            io::Error::other("commissioning state changed while being observed"),
        ));
    }

    decode_log(&bytes, intent)
}

fn require_state_file(
    file: &File,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<(), HvfOwnerCommissioningStateError> {
    let metadata = file
        .metadata()
        .map_err(HvfOwnerCommissioningStateError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != intent.authority_role().uid()
        || metadata.gid() != intent.authority_role().gid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || has_extended_acl(file).map_err(HvfOwnerCommissioningStateError::Unavailable)?
    {
        return Err(HvfOwnerCommissioningStateError::FilesystemPolicy);
    }
    Ok(())
}

fn decode_log(
    bytes: &[u8],
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.contains(&b'\r') {
        return Err(HvfOwnerCommissioningStateError::Grammar);
    }

    let mut records: Vec<CommissioningStateRecord> = Vec::new();
    let mut predecessor = ZERO_DIGEST;
    let mut previous_phase = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(HvfOwnerCommissioningStateError::Grammar);
        }
        if line.len() > MAX_COMMISSIONING_STATE_LINE_BYTES {
            return Err(HvfOwnerCommissioningStateError::LineTooLarge);
        }
        let wire: RecordV1 =
            serde_json::from_slice(line).map_err(|_| HvfOwnerCommissioningStateError::Grammar)?;
        let canonical = serde_json::to_vec(&wire)
            .expect("fixed commissioning state schema serializes without failure");
        if canonical != line {
            return Err(HvfOwnerCommissioningStateError::Grammar);
        }

        let expected_sequence = u64::try_from(records.len())
            .expect("bounded commissioning log record count fits u64")
            + 1;
        let phase = wire.content.evidence.phase();
        let digest = record_digest(&wire.content);
        if wire.content.schema_version != COMMISSIONING_STATE_VERSION
            || wire.content.sequence != expected_sequence
            || wire.content.previous_record_digest != predecessor
            || wire.record_digest != digest
            || !record_matches_intent(&wire.content, intent)
            || wire.content.lock_device == 0
            || wire.content.lock_inode == 0
            || (expected_sequence == 1 && phase != CommissioningPhase::Prepared)
            || previous_phase.is_some_and(|previous: CommissioningPhase| {
                phase.ordinal() != previous.ordinal() + 1
            })
        {
            return Err(HvfOwnerCommissioningStateError::Binding);
        }
        if let Some(first) = records.first()
            && !same_log_binding(&wire.content, &first.content)
        {
            return Err(HvfOwnerCommissioningStateError::Binding);
        }

        predecessor = digest;
        previous_phase = Some(phase);
        records.push(CommissioningStateRecord {
            content: wire.content,
            record_digest: wire.record_digest,
        });
    }

    let first = records
        .first()
        .ok_or(HvfOwnerCommissioningStateError::Grammar)?;
    Ok(CommissioningStateObservation::Retained(
        RetainedCommissioningState {
            intent_digest: first.content.intent_digest,
            deployment_id: first.content.deployment_id.clone(),
            deployment_epoch: first.content.deployment_epoch,
            authority_uid: first.content.authority_uid,
            authority_gid: first.content.authority_gid,
            lock_device: first.content.lock_device,
            lock_inode: first.content.lock_inode,
            records: records.into_boxed_slice(),
        },
    ))
}

fn record_matches_intent(
    content: &RecordContentV1,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> bool {
    content.intent_digest == intent.digest()
        && content.deployment_id == intent.deployment_id()
        && content.deployment_epoch == intent.deployment_epoch()
        && content.authority_uid == intent.authority_role().uid()
        && content.authority_gid == intent.authority_role().gid()
}

fn same_log_binding(left: &RecordContentV1, right: &RecordContentV1) -> bool {
    left.intent_digest == right.intent_digest
        && left.deployment_id == right.deployment_id
        && left.deployment_epoch == right.deployment_epoch
        && left.authority_uid == right.authority_uid
        && left.authority_gid == right.authority_gid
        && left.lock_device == right.lock_device
        && left.lock_inode == right.lock_inode
}

fn record_digest(content: &RecordContentV1) -> [u8; 32] {
    let canonical =
        serde_json::to_vec(content).expect("fixed commissioning state content serializes");
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(canonical);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use serde_json::{Value, json};

    use super::*;
    use crate::hvf_owner_commissioning_intent::{
        LoadedHvfOwnerCommissioningIntent, load_test_hvf_owner_commissioning_intent,
    };
    use crate::hvf_owner_commissioning_lock::{
        COMMISSIONING_LOCK_NAME, CommissioningLockBinding,
        try_acquire_test_hvf_owner_commissioning_lock, validate_test_hvf_owner_commissioning_lock,
    };
    use crate::hvf_owner_deployment_receipt::{OwnerComponentPinV1, cohort_digest};
    use crate::hvf_owner_protected_authority_root::{
        ProtectedAuthorityRoot, validate_test_protected_authority_root,
    };

    const LOCK_DEVICE: u64 = 41;
    const LOCK_INODE: u64 = 73;

    struct Fixture {
        root: tempfile::TempDir,
        installer_uid: u32,
        installer_gid: u32,
        authority_uid: u32,
        authority_gid: u32,
        intent: LoadedHvfOwnerCommissioningIntent,
        authority: ProtectedAuthorityRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create protected root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("set root mode");
            let root_metadata = fs::metadata(root.path()).expect("root metadata");
            let installer_uid = root_metadata.uid();
            let installer_gid = root_metadata.gid();
            let authority_uid = installer_uid;
            let authority_gid = installer_gid;
            let deployment = root.path().join("mvm");
            fs::create_dir(&deployment).expect("create deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
                .expect("set deployment mode");
            let authority_path = deployment.join("authority");
            fs::create_dir(&authority_path).expect("create authority");
            fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o700))
                .expect("set authority mode");
            write_intent(
                &deployment,
                authority_uid,
                authority_gid,
                authority_uid.checked_add(1).expect("test uid has room"),
                authority_gid.checked_add(1).expect("test gid has room"),
            );
            let intent = load_test_hvf_owner_commissioning_intent(
                File::open(root.path()).expect("open db root"),
                installer_uid,
                installer_gid,
            )
            .expect("load intent");
            let authority = validate_test_protected_authority_root(
                &intent,
                File::open(root.path()).expect("open db root"),
                installer_uid,
                installer_gid,
            )
            .expect("validate authority");
            Self {
                root,
                installer_uid,
                installer_gid,
                authority_uid,
                authority_gid,
                intent,
                authority,
            }
        }

        fn authority_path(&self) -> std::path::PathBuf {
            self.root.path().join("mvm").join("authority")
        }

        fn state_path(&self) -> std::path::PathBuf {
            self.authority_path().join(COMMISSIONING_STATE_NAME)
        }

        fn write_state(&self, bytes: &[u8]) {
            fs::write(self.state_path(), bytes).expect("write state");
            fs::set_permissions(self.state_path(), fs::Permissions::from_mode(0o600))
                .expect("set state mode");
        }

        fn load(&self) -> Result<CommissioningStateObservation, HvfOwnerCommissioningStateError> {
            load_test_hvf_owner_commissioning_state(&self.authority, &self.intent)
        }

        fn valid_log(&self, through: CommissioningPhase) -> Vec<u8> {
            valid_log(&self.intent, through)
        }
    }

    fn write_intent(
        deployment: &std::path::Path,
        authority_uid: u32,
        authority_gid: u32,
        runtime_uid: u32,
        runtime_gid: u32,
    ) {
        let component = OwnerComponentPinV1 {
            schema_version: 1,
            component: "mvm-hvf-run-owner".into(),
            sha256: "a".repeat(64),
            version: "0.28.0-rc.11".into(),
            target: "aarch64-apple-darwin".into(),
            source_commit: "b".repeat(40),
            bootstrap_protocol_version: 1,
        };
        let digest = cohort_digest(&component);
        let intent = json!({
            "schema_version": 1,
            "deployment_id": "production-1",
            "deployment_epoch": 7,
            "protected_roles": {
                "authority": {
                    "uid": authority_uid,
                    "gid": authority_gid,
                    "executable": "/Library/PrivilegedHelperTools/mvm-authority",
                    "designated_requirement":
                        "identifier \"dev.mvm.authority\" and anchor apple generic"
                },
                "runtime": {
                    "uid": runtime_uid,
                    "gid": runtime_gid,
                    "executable": "/Library/PrivilegedHelperTools/mvm-hvf-run-owner",
                    "designated_requirement":
                        "identifier \"dev.mvm.owner\" and anchor apple generic"
                }
            },
            "approved_owner_code_cohort": {
                "digest": digest,
                "owner_component": component
            }
        });
        let path = deployment.join("owner-commissioning-intent.json");
        fs::write(
            &path,
            serde_json::to_vec(&intent).expect("serialize intent"),
        )
        .expect("write intent");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("set intent mode");
    }

    fn phases_through(through: CommissioningPhase) -> impl Iterator<Item = CommissioningPhase> {
        [
            CommissioningPhase::Prepared,
            CommissioningPhase::KeyCreated,
            CommissioningPhase::JournalInitialized,
            CommissioningPhase::ReceiptPending,
            CommissioningPhase::CompletionPublished,
            CommissioningPhase::Ready,
        ]
        .into_iter()
        .take(usize::from(through.ordinal()) + 1)
    }

    fn evidence(phase: CommissioningPhase) -> PhaseEvidenceV1 {
        let digest = Some([phase.ordinal() + 1; 32]);
        match phase {
            CommissioningPhase::Prepared => PhaseEvidenceV1::Prepared {
                preparation_evidence_digest: digest,
            },
            CommissioningPhase::KeyCreated => PhaseEvidenceV1::KeyCreated {
                public_key_evidence_digest: digest,
            },
            CommissioningPhase::JournalInitialized => PhaseEvidenceV1::JournalInitialized {
                journal_evidence_digest: digest,
            },
            CommissioningPhase::ReceiptPending => PhaseEvidenceV1::ReceiptPending {
                receipt_evidence_digest: digest,
            },
            CommissioningPhase::CompletionPublished => PhaseEvidenceV1::CompletionPublished {
                completion_evidence_digest: digest,
            },
            CommissioningPhase::Ready => PhaseEvidenceV1::Ready {
                readiness_evidence_digest: digest,
            },
        }
    }

    fn valid_records(
        intent: &LoadedHvfOwnerCommissioningIntent,
        through: CommissioningPhase,
    ) -> Vec<RecordV1> {
        let mut predecessor = ZERO_DIGEST;
        phases_through(through)
            .enumerate()
            .map(|(index, phase)| {
                let content = RecordContentV1 {
                    schema_version: COMMISSIONING_STATE_VERSION,
                    sequence: u64::try_from(index).expect("test index fits u64") + 1,
                    previous_record_digest: predecessor,
                    intent_digest: intent.digest(),
                    deployment_id: intent.deployment_id().into(),
                    deployment_epoch: intent.deployment_epoch(),
                    authority_uid: intent.authority_role().uid(),
                    authority_gid: intent.authority_role().gid(),
                    lock_device: LOCK_DEVICE,
                    lock_inode: LOCK_INODE,
                    evidence: evidence(phase),
                };
                let digest = record_digest(&content);
                predecessor = digest;
                RecordV1 {
                    content,
                    record_digest: digest,
                }
            })
            .collect()
    }

    fn encode_records(records: &[RecordV1]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend(serde_json::to_vec(record).expect("serialize record"));
            bytes.push(b'\n');
        }
        bytes
    }

    fn valid_log(
        intent: &LoadedHvfOwnerCommissioningIntent,
        through: CommissioningPhase,
    ) -> Vec<u8> {
        encode_records(&valid_records(intent, through))
    }

    fn retained(observation: CommissioningStateObservation) -> RetainedCommissioningState {
        match observation {
            CommissioningStateObservation::Retained(state) => state,
            CommissioningStateObservation::Absent => panic!("expected retained state"),
        }
    }

    #[test]
    fn loads_valid_log_for_every_phase_and_classifies_readiness() {
        for phase in phases_through(CommissioningPhase::Ready) {
            let fixture = Fixture::new();
            fixture.write_state(&fixture.valid_log(phase));
            let state = retained(fixture.load().expect("load valid state"));
            assert_eq!(state.phase(), phase);
            assert_eq!(state.records().len(), usize::from(phase.ordinal()) + 1);
            assert_eq!(state.intent_digest(), fixture.intent.digest());
            assert_eq!(state.deployment_id(), fixture.intent.deployment_id());
            assert_eq!(state.deployment_epoch(), fixture.intent.deployment_epoch());
            assert_eq!(state.authority_uid(), fixture.authority_uid);
            assert_eq!(state.authority_gid(), fixture.authority_gid);
            assert_eq!(state.lock_device(), LOCK_DEVICE);
            assert_eq!(state.lock_inode(), LOCK_INODE);
            let expected = if phase == CommissioningPhase::Ready {
                CommissioningReadiness::Ready
            } else {
                CommissioningReadiness::Interrupted
            };
            assert_eq!(state.readiness(), expected);
        }
    }

    #[test]
    fn compares_state_log_binding_with_validated_lock_identity() {
        let fixture = Fixture::new();
        let lock_path = fixture.authority_path().join(COMMISSIONING_LOCK_NAME);
        fs::write(&lock_path, []).expect("create lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o444)).expect("set lock mode");
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("chflags")
                .arg("uchg")
                .arg(&lock_path)
                .status()
                .expect("run chflags");
            assert!(status.success(), "chflags uchg must succeed");
        }
        let lock = validate_test_hvf_owner_commissioning_lock(
            &fixture.authority,
            fixture.installer_uid,
            fixture.installer_gid,
        )
        .expect("validate lock");
        let guard = try_acquire_test_hvf_owner_commissioning_lock(
            &fixture.authority,
            lock,
            fixture.installer_uid,
            fixture.installer_gid,
        )
        .expect("acquire lock");

        let mut records = valid_records(&fixture.intent, CommissioningPhase::Prepared);
        records[0].content.lock_device = guard.device();
        records[0].content.lock_inode = guard.inode();
        records[0].record_digest = record_digest(&records[0].content);
        fixture.write_state(&encode_records(&records));
        let state = retained(fixture.load().expect("load matching state"));
        assert_eq!(
            guard.compare_state_binding(&state),
            CommissioningLockBinding::Matches
        );

        records[0].content.lock_inode = guard.inode().checked_add(1).expect("inode has room");
        records[0].record_digest = record_digest(&records[0].content);
        fixture.write_state(&encode_records(&records));
        let state = retained(fixture.load().expect("load mismatched state"));
        assert_eq!(
            guard.compare_state_binding(&state),
            CommissioningLockBinding::Mismatch
        );

        drop(guard);
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("chflags")
                .arg("nouchg")
                .arg(&lock_path)
                .status()
                .expect("clear immutable flag");
            assert!(status.success(), "chflags nouchg must succeed");
        }
    }

    #[test]
    fn verifies_canonical_domain_separated_digest_chain() {
        let fixture = Fixture::new();
        let records = valid_records(&fixture.intent, CommissioningPhase::Ready);
        fixture.write_state(&encode_records(&records));
        let state = retained(fixture.load().expect("load chain"));

        for (index, record) in state.records().iter().enumerate() {
            assert_eq!(record.record_digest(), record_digest(&record.content));
            let predecessor = index.checked_sub(1).map_or(ZERO_DIGEST, |previous| {
                state.records()[previous].record_digest()
            });
            assert_eq!(record.previous_record_digest(), predecessor);
            assert_eq!(
                record.evidence_digest(),
                Some([record.phase().ordinal() + 1; 32])
            );
        }
    }

    #[test]
    fn absent_is_observation_only_and_does_not_create_state() {
        let fixture = Fixture::new();
        let before: Vec<_> = fs::read_dir(fixture.authority_path())
            .expect("read authority")
            .collect();
        assert_eq!(
            fixture.load().expect("observe absent state"),
            CommissioningStateObservation::Absent
        );
        let after: Vec<_> = fs::read_dir(fixture.authority_path())
            .expect("reread authority")
            .collect();
        assert_eq!(before.len(), after.len());
        assert!(!fixture.state_path().exists());
    }

    #[test]
    fn refuses_wrong_schema_sequence_predecessor_and_current_digest() {
        for mutation in 0..4 {
            let fixture = Fixture::new();
            let mut records = valid_records(&fixture.intent, CommissioningPhase::KeyCreated);
            match mutation {
                0 => records[0].content.schema_version = 2,
                1 => records[1].content.sequence = 3,
                2 => records[1].content.previous_record_digest = [9; 32],
                3 => records[1].record_digest = [9; 32],
                _ => unreachable!("bounded test mutation"),
            }
            fixture.write_state(&encode_records(&records));
            assert!(matches!(
                fixture.load(),
                Err(HvfOwnerCommissioningStateError::Binding)
            ));
        }
    }

    #[test]
    fn refuses_wrong_intent_deployment_authority_and_lock_bindings() {
        for mutation in 0..9 {
            let fixture = Fixture::new();
            let mut records = valid_records(&fixture.intent, CommissioningPhase::Prepared);
            match mutation {
                0 => records[0].content.intent_digest = [8; 32],
                1 => records[0].content.deployment_id = "other".into(),
                2 => records[0].content.deployment_epoch += 1,
                3 => records[0].content.authority_uid += 1,
                4 => records[0].content.authority_gid += 1,
                5 => records[0].content.lock_device = 0,
                6 => records[0].content.lock_inode = 0,
                7 => records[0].content.lock_device += 1,
                8 => records[0].content.lock_inode += 1,
                _ => unreachable!("bounded test mutation"),
            }
            if mutation >= 7 {
                let mut second =
                    valid_records(&fixture.intent, CommissioningPhase::KeyCreated)[1].clone();
                second.content.previous_record_digest = record_digest(&records[0].content);
                second.record_digest = record_digest(&second.content);
                records.push(second);
            }
            records[0].record_digest = record_digest(&records[0].content);
            fixture.write_state(&encode_records(&records));
            assert!(matches!(
                fixture.load(),
                Err(HvfOwnerCommissioningStateError::Binding)
            ));
        }
    }

    #[test]
    fn refuses_skipped_repeated_or_regressed_phases() {
        for phases in [
            vec![CommissioningPhase::KeyCreated],
            vec![
                CommissioningPhase::Prepared,
                CommissioningPhase::JournalInitialized,
            ],
            vec![CommissioningPhase::Prepared, CommissioningPhase::Prepared],
        ] {
            let fixture = Fixture::new();
            let mut predecessor = ZERO_DIGEST;
            let records: Vec<_> = phases
                .into_iter()
                .enumerate()
                .map(|(index, phase)| {
                    let content = RecordContentV1 {
                        schema_version: 1,
                        sequence: u64::try_from(index).expect("index fits") + 1,
                        previous_record_digest: predecessor,
                        intent_digest: fixture.intent.digest(),
                        deployment_id: fixture.intent.deployment_id().into(),
                        deployment_epoch: fixture.intent.deployment_epoch(),
                        authority_uid: fixture.authority_uid,
                        authority_gid: fixture.authority_gid,
                        lock_device: LOCK_DEVICE,
                        lock_inode: LOCK_INODE,
                        evidence: evidence(phase),
                    };
                    let digest = record_digest(&content);
                    predecessor = digest;
                    RecordV1 {
                        content,
                        record_digest: digest,
                    }
                })
                .collect();
            fixture.write_state(&encode_records(&records));
            assert!(matches!(
                fixture.load(),
                Err(HvfOwnerCommissioningStateError::Binding)
            ));
        }
    }

    #[test]
    fn refuses_unknown_duplicate_nonobject_and_malformed_nested_forms() {
        let fixture = Fixture::new();
        let baseline = String::from_utf8(fixture.valid_log(CommissioningPhase::Prepared))
            .expect("state is utf8");
        let line = baseline.trim_end_matches('\n');
        let unknown = format!("{}{}\n", &line[..line.len() - 1], ",\"unknown\":1}");
        let duplicate = baseline.replacen(
            "\"record_digest\":",
            "\"record_digest\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"record_digest\":",
            1,
        );
        for bytes in [
            unknown.into_bytes(),
            duplicate.into_bytes(),
            b"[]\n".to_vec(),
            b"{\"content\":[],\"record_digest\":[]}\n".to_vec(),
            b"{\"content\":{\"schema_version\":1}}\n".to_vec(),
        ] {
            fixture.write_state(&bytes);
            assert!(matches!(
                fixture.load(),
                Err(HvfOwnerCommissioningStateError::Grammar)
            ));
        }
    }

    #[test]
    fn refuses_noncanonical_blank_cr_truncated_and_trailing_forms() {
        let fixture = Fixture::new();
        let canonical = fixture.valid_log(CommissioningPhase::Prepared);
        let value: Value =
            serde_json::from_slice(&canonical[..canonical.len() - 1]).expect("decode record");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty record");
        for bytes in [
            [pretty, b"\n".to_vec()].concat(),
            [canonical.clone(), b"\n".to_vec()].concat(),
            canonical[..canonical.len() - 1].to_vec(),
            [canonical.clone(), b"\r\n".to_vec()].concat(),
            [canonical.clone(), b"{}".to_vec()].concat(),
        ] {
            fixture.write_state(&bytes);
            assert!(matches!(
                fixture.load(),
                Err(HvfOwnerCommissioningStateError::Grammar)
            ));
        }
    }

    #[test]
    fn refuses_oversized_line_and_log_before_decode() {
        let fixture = Fixture::new();
        let mut oversized_line = vec![b'x'; MAX_COMMISSIONING_STATE_LINE_BYTES + 1];
        oversized_line.push(b'\n');
        fixture.write_state(&oversized_line);
        assert!(matches!(
            fixture.load(),
            Err(HvfOwnerCommissioningStateError::LineTooLarge)
        ));

        fixture.write_state(&vec![b'x'; MAX_COMMISSIONING_STATE_BYTES + 1]);
        assert!(matches!(
            fixture.load(),
            Err(HvfOwnerCommissioningStateError::TooLarge)
        ));
    }

    #[test]
    fn refuses_symlink_directory_fifo_hardlink_and_wrong_mode() {
        for kind in 0..5 {
            let fixture = Fixture::new();
            let path = fixture.state_path();
            match kind {
                0 => {
                    fs::write(fixture.authority_path().join("target"), b"x")
                        .expect("write symlink target");
                    symlink("target", &path).expect("create symlink");
                }
                1 => fs::create_dir(&path).expect("create directory"),
                2 => {
                    let status = std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .expect("run mkfifo");
                    assert!(status.success(), "create fifo");
                }
                3 => {
                    fixture.write_state(&fixture.valid_log(CommissioningPhase::Prepared));
                    fs::hard_link(&path, fixture.authority_path().join("alias"))
                        .expect("create hardlink");
                }
                4 => {
                    fixture.write_state(&fixture.valid_log(CommissioningPhase::Prepared));
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                        .expect("set wrong mode");
                }
                _ => unreachable!("bounded fixture kind"),
            }
            assert!(fixture.load().is_err(), "unsafe kind {kind} must refuse");
        }
    }

    #[test]
    fn refuses_wrong_file_identity() {
        let fixture = Fixture::new();
        fixture.write_state(&fixture.valid_log(CommissioningPhase::Prepared));
        let deployment = fixture.root.path().join("mvm");
        fs::remove_file(deployment.join("owner-commissioning-intent.json"))
            .expect("remove first intent");
        write_intent(
            &deployment,
            fixture.authority_uid.checked_add(1).expect("uid has room"),
            fixture.authority_gid.checked_add(1).expect("gid has room"),
            fixture.authority_uid.checked_add(2).expect("uid has room"),
            fixture.authority_gid.checked_add(2).expect("gid has room"),
        );
        let other_intent = load_test_hvf_owner_commissioning_intent(
            File::open(fixture.root.path()).expect("open db root"),
            fixture.installer_uid,
            fixture.installer_gid,
        )
        .expect("load mismatched intent");
        let file = File::open(fixture.state_path()).expect("open state");
        assert!(matches!(
            require_state_file(&file, &other_intent),
            Err(HvfOwnerCommissioningStateError::FilesystemPolicy)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_extended_acl() {
        let fixture = Fixture::new();
        fixture.write_state(&fixture.valid_log(CommissioningPhase::Prepared));
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(fixture.state_path())
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install ACL fixture");
        assert!(matches!(
            fixture.load(),
            Err(HvfOwnerCommissioningStateError::FilesystemPolicy)
        ));
    }

    #[test]
    fn detects_growth_and_retains_open_object_across_path_substitution() {
        let fixture = Fixture::new();
        let valid = fixture.valid_log(CommissioningPhase::Prepared);
        fixture.write_state(&valid);
        let state_path = fixture.state_path();
        let file = File::open(&state_path).expect("open state");
        let growth_path = state_path.clone();
        assert!(matches!(
            load_open_file(file, &fixture.intent, || {
                use std::io::Write as _;
                let mut growing = fs::OpenOptions::new()
                    .append(true)
                    .open(growth_path)
                    .expect("open for growth");
                growing.write_all(b"\n").expect("grow state");
            }),
            Err(HvfOwnerCommissioningStateError::Unavailable(_))
        ));

        fixture.write_state(&valid);
        let file = File::open(&state_path).expect("open retained state");
        let replacement_path = state_path.clone();
        let observation = load_open_file(file, &fixture.intent, || {
            fs::rename(&replacement_path, fixture.authority_path().join("old"))
                .expect("retain old object");
            fs::write(&replacement_path, b"malicious replacement").expect("write replacement path");
            fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600))
                .expect("set replacement mode");
        })
        .expect("descriptor must retain the validated open object");
        assert_eq!(retained(observation).phase(), CommissioningPhase::Prepared);
    }

    #[test]
    fn loading_never_mutates_state() {
        let fixture = Fixture::new();
        let bytes = fixture.valid_log(CommissioningPhase::CompletionPublished);
        fixture.write_state(&bytes);
        let before = fs::metadata(fixture.state_path()).expect("metadata before");
        let _ = fixture.load().expect("load state");
        let after = fs::metadata(fixture.state_path()).expect("metadata after");
        assert_eq!(fs::read(fixture.state_path()).expect("read state"), bytes);
        assert_eq!(before.len(), after.len());
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.nlink(), after.nlink());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_loader_refuses_unsupported_platform() {
        let fixture = Fixture::new();
        assert!(matches!(
            load_hvf_owner_commissioning_state(&fixture.authority, &fixture.intent),
            Err(HvfOwnerCommissioningStateError::Unsupported)
        ));
    }
}
