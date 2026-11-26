//! Create-only publication of the first durable owner-commissioning state.
//!
//! This fixed operation linearizes only the authority state child under the
//! cooperating permanent lock. It does not establish deployment-wide sibling
//! freshness or resolve installer transaction and recovery semantics.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

#[cfg(any(test, feature = "test-support"))]
use mvm_commissioning_auth::commissioning_bootstrap_session::test_support::TestPreparedPermit;
use mvm_commissioning_auth::commissioning_bootstrap_session::{
    CommissioningBootstrapPermit, ConsumedPreparedAuthorization, PreparedPermitConsumptionError,
};

use crate::hvf_owner_commissioning_intent::{
    HvfOwnerCommissioningIntentError, LoadedHvfOwnerCommissioningIntent,
};
use crate::hvf_owner_commissioning_lock::{
    CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError,
    HvfOwnerCommissioningLockError, ValidatedCommissioningLock,
};
use crate::hvf_owner_commissioning_state::{
    CommissioningPhase, CommissioningReadiness, CommissioningStateObservation,
    encode_prepared_record,
};
use crate::hvf_owner_protected_authority_root::{
    ProtectedAuthorityRoot, ProtectedAuthorityRootError,
};

/// Durable observation of the one canonical `Prepared` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct PublishedPreparedState {
    intent_digest: [u8; 32],
    lock_device: u64,
    lock_inode: u64,
    record_digest: [u8; 32],
    phase: CommissioningPhase,
}

impl PublishedPreparedState {
    /// Exact intent digest bound by the record and consumed permit.
    #[must_use]
    pub fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Device identity of the held permanent commissioning lock.
    #[must_use]
    pub fn lock_device(&self) -> u64 {
        self.lock_device
    }

    /// Inode identity of the held permanent commissioning lock.
    #[must_use]
    pub fn lock_inode(&self) -> u64 {
        self.lock_inode
    }

    /// Domain-separated digest of the canonical record content.
    #[must_use]
    pub fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Strictly reloaded phase.
    #[must_use]
    pub fn phase(&self) -> CommissioningPhase {
        self.phase
    }
}

/// Refusal or uncertain outcome from the fixed `Prepared` publication.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublishPreparedStateError {
    /// The initially loaded intent did not match the permit.
    #[error("commissioning-bootstrap permit does not match the loaded intent")]
    PermitIntentMismatch,
    /// The fixed commissioning intent could not be loaded or reloaded.
    #[error("protected HVF owner commissioning intent is invalid")]
    Intent(#[source] HvfOwnerCommissioningIntentError),
    /// The authority root did not satisfy its fixed policy.
    #[error("protected HVF authority root is invalid")]
    AuthorityRoot(#[source] ProtectedAuthorityRootError),
    /// The permanent commissioning lock did not satisfy its fixed policy.
    #[error("protected HVF owner commissioning lock is invalid")]
    LockValidation(#[source] HvfOwnerCommissioningLockError),
    /// The permanent commissioning lock could not be acquired immediately.
    #[error("protected HVF owner commissioning lock could not be acquired")]
    LockAcquisition(#[source] HvfOwnerCommissioningLockAcquisitionError),
    /// The intent changed while exclusion was being established.
    #[error("protected HVF owner commissioning intent changed")]
    IntentChanged,
    /// The fixed authority path no longer names the retained directory.
    #[error("protected HVF authority root identity changed")]
    AuthorityRootChanged,
    /// The process does not run as the exact intent authority role.
    #[error("process identity does not match the commissioning authority role")]
    ProcessIdentityMismatch,
    /// The fixed state child was already occupied in any form.
    #[error("protected HVF owner commissioning state already exists")]
    StateExists,
    /// The fixed state child could not be safely inspected before consumption.
    #[error("protected HVF owner commissioning state preflight is unavailable")]
    StatePreflight(#[source] io::Error),
    /// Live peer revalidation refused before any state object was created.
    #[error("commissioning-bootstrap permit revalidation failed")]
    PermitRevalidation,
    /// Permit consumption succeeded, so publication may have occurred.
    #[error("protected HVF owner Prepared publication outcome is unknown")]
    PublicationUnknown(#[source] io::Error),
}

/// Consume one permit and durably create the fixed canonical `Prepared` state.
///
/// The operation loads every filesystem input from fixed production paths. It
/// accepts no caller-selected path, bytes, metadata, identity, evidence, or
/// callback. The permanent advisory guard remains held through strict reload.
///
/// # Errors
///
/// Refuses invalid or changed inputs, contention, process-role mismatch, any
/// preexisting state child, and permit mismatch or revalidation failure before
/// creation. Every failure after successful permit consumption is reported as
/// [`PublishPreparedStateError::PublicationUnknown`].
#[cfg(target_os = "macos")]
pub fn publish_hvf_owner_prepared(
    permit: CommissioningBootstrapPermit,
) -> Result<PublishedPreparedState, PublishPreparedStateError> {
    let intent = crate::hvf_owner_commissioning_intent::load_hvf_owner_commissioning_intent()
        .map_err(PublishPreparedStateError::Intent)?;
    if permit.intent_digest() != &intent.digest() {
        return Err(PublishPreparedStateError::PermitIntentMismatch);
    }
    let root =
        crate::hvf_owner_protected_authority_root::validate_protected_authority_root(&intent)
            .map_err(PublishPreparedStateError::AuthorityRoot)?;
    let lock = crate::hvf_owner_commissioning_lock::validate_hvf_owner_commissioning_lock(&root)
        .map_err(PublishPreparedStateError::LockValidation)?;
    publish_with_inputs(
        PreparedOperationInputs {
            permit: PreparedPermit::Production(permit),
            intent_a: intent,
            root,
            lock,
            effective_identity: EffectiveIdentity {
                uid: rustix::process::geteuid().as_raw(),
                gid: rustix::process::getegid().as_raw(),
            },
            reload: ReloadSource::Production,
        },
        PreparedPublishFault::None,
    )
}

enum PreparedPermit {
    Production(CommissioningBootstrapPermit),
    #[cfg(any(test, feature = "test-support"))]
    Test(TestPreparedPermit),
}

impl PreparedPermit {
    fn intent_digest(&self) -> &[u8; 32] {
        match self {
            Self::Production(permit) => permit.intent_digest(),
            #[cfg(any(test, feature = "test-support"))]
            Self::Test(permit) => permit.intent_digest(),
        }
    }

    fn consume_for_prepared(
        self,
        intent_digest: [u8; 32],
    ) -> Result<ConsumedPreparedAuthorization, PreparedPermitConsumptionError> {
        match self {
            Self::Production(permit) => permit.consume_for_prepared(intent_digest),
            #[cfg(any(test, feature = "test-support"))]
            Self::Test(permit) => permit.consume_for_prepared(intent_digest),
        }
    }
}

#[derive(Clone, Copy)]
struct EffectiveIdentity {
    uid: u32,
    gid: u32,
}

enum ReloadSource {
    Production,
    #[cfg(any(test, feature = "test-support"))]
    Test {
        db_root: File,
        installer_identity: EffectiveIdentity,
    },
}

impl ReloadSource {
    fn intent(
        &self,
    ) -> Result<LoadedHvfOwnerCommissioningIntent, HvfOwnerCommissioningIntentError> {
        match self {
            Self::Production => {
                crate::hvf_owner_commissioning_intent::load_hvf_owner_commissioning_intent()
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Test {
                db_root,
                installer_identity,
            } => crate::hvf_owner_commissioning_intent::load_test_hvf_owner_commissioning_intent(
                db_root
                    .try_clone()
                    .map_err(HvfOwnerCommissioningIntentError::Io)?,
                installer_identity.uid,
                installer_identity.gid,
            ),
        }
    }

    fn root(
        &self,
        intent: &LoadedHvfOwnerCommissioningIntent,
    ) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
        match self {
            Self::Production => {
                crate::hvf_owner_protected_authority_root::validate_protected_authority_root(intent)
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Test {
                db_root,
                installer_identity,
            } => crate::hvf_owner_protected_authority_root::validate_test_protected_authority_root(
                intent,
                db_root
                    .try_clone()
                    .map_err(|_| ProtectedAuthorityRootError::Unavailable)?,
                installer_identity.uid,
                installer_identity.gid,
            ),
        }
    }

    fn test_lock_owner(&self) -> Option<(u32, u32)> {
        match self {
            Self::Production => None,
            #[cfg(any(test, feature = "test-support"))]
            Self::Test {
                installer_identity, ..
            } => Some((installer_identity.uid, installer_identity.gid)),
        }
    }
}

struct PreparedOperationInputs {
    permit: PreparedPermit,
    intent_a: LoadedHvfOwnerCommissioningIntent,
    root: ProtectedAuthorityRoot,
    lock: ValidatedCommissioningLock,
    effective_identity: EffectiveIdentity,
    reload: ReloadSource,
}

fn require_permit_digest(
    permit: &PreparedPermit,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<(), PublishPreparedStateError> {
    if permit.intent_digest() != &intent.digest() {
        return Err(PublishPreparedStateError::PermitIntentMismatch);
    }
    Ok(())
}

fn publish_with_inputs(
    inputs: PreparedOperationInputs,
    fault: PreparedPublishFault,
) -> Result<PublishedPreparedState, PublishPreparedStateError> {
    require_permit_digest(&inputs.permit, &inputs.intent_a)?;
    let test_lock_owner = inputs.reload.test_lock_owner();
    let guard = acquire_lock(&inputs.root, inputs.lock, test_lock_owner)?;
    let intent_b = inputs
        .reload
        .intent()
        .map_err(PublishPreparedStateError::Intent)?;
    if intent_b.digest() != inputs.intent_a.digest() {
        return Err(PublishPreparedStateError::IntentChanged);
    }
    inputs
        .root
        .revalidate(&intent_b)
        .map_err(PublishPreparedStateError::AuthorityRoot)?;
    let fresh_root = inputs
        .reload
        .root(&intent_b)
        .map_err(PublishPreparedStateError::AuthorityRoot)?;
    if !inputs.root.same_identity(&fresh_root) {
        return Err(PublishPreparedStateError::AuthorityRootChanged);
    }
    if inputs.effective_identity.uid != intent_b.authority_role().uid()
        || inputs.effective_identity.gid != intent_b.authority_role().gid()
    {
        return Err(PublishPreparedStateError::ProcessIdentityMismatch);
    }
    match inputs.root.commissioning_state_child_exists() {
        Ok(false) => {}
        Ok(true) => return Err(PublishPreparedStateError::StateExists),
        Err(error) => return Err(PublishPreparedStateError::StatePreflight(error.into())),
    }

    let _authorization = inputs
        .permit
        .consume_for_prepared(intent_b.digest())
        .map_err(|error| match error {
            PreparedPermitConsumptionError::IntentDigestMismatch => {
                PublishPreparedStateError::PermitIntentMismatch
            }
            PreparedPermitConsumptionError::PeerRevalidation => {
                PublishPreparedStateError::PermitRevalidation
            }
        })?;

    publish_after_consumption(
        _authorization,
        &inputs.root,
        &guard,
        &intent_b,
        fault,
        test_lock_owner,
    )
    .map_err(PublishPreparedStateError::PublicationUnknown)
}

fn acquire_lock(
    root: &ProtectedAuthorityRoot,
    lock: ValidatedCommissioningLock,
    test_lock_owner: Option<(u32, u32)>,
) -> Result<CommissioningLockGuard, PublishPreparedStateError> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some((uid, gid)) = test_lock_owner {
        return crate::hvf_owner_commissioning_lock::try_acquire_test_hvf_owner_commissioning_lock(
            root, lock, uid, gid,
        )
        .map_err(PublishPreparedStateError::LockAcquisition);
    }
    let _ = test_lock_owner;
    crate::hvf_owner_commissioning_lock::try_acquire_hvf_owner_commissioning_lock(root, lock)
        .map_err(PublishPreparedStateError::LockAcquisition)
}

fn publish_after_consumption(
    _authorization: ConsumedPreparedAuthorization,
    root: &ProtectedAuthorityRoot,
    guard: &CommissioningLockGuard,
    intent: &LoadedHvfOwnerCommissioningIntent,
    fault: PreparedPublishFault,
    test_lock_owner: Option<(u32, u32)>,
) -> io::Result<PublishedPreparedState> {
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::ExclusiveCreateRace {
        let _racer = root.create_commissioning_state().map_err(io::Error::from)?;
    }

    let mut state = root.create_commissioning_state().map_err(io::Error::from)?;
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::DescriptorPolicy {
        state.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    }
    require_created_state_file(&state, intent)?;

    let encoded = encode_prepared_record(intent, guard.device(), guard.inode());
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::Write {
        return Err(io::Error::other("injected state write failure"));
    }
    state.write_all(&encoded.bytes)?;
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::FileSync {
        return Err(io::Error::other("injected state file sync failure"));
    }
    state.sync_all()?;
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::DirectorySync {
        return Err(io::Error::other(
            "injected authority directory sync failure",
        ));
    }
    root.sync_directory()?;

    let retained = match crate::hvf_owner_commissioning_state::load_from_root(root, intent) {
        Ok(CommissioningStateObservation::Retained(retained)) => retained,
        Ok(CommissioningStateObservation::Absent) => {
            return Err(io::Error::other(
                "published state was absent during strict reload",
            ));
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::PostLoad {
        return Err(io::Error::other("injected post-load observation failure"));
    }
    if retained.records().len() != 1
        || retained.phase() != CommissioningPhase::Prepared
        || retained.readiness() != CommissioningReadiness::Interrupted
        || retained.intent_digest() != intent.digest()
        || retained.lock_device() != guard.device()
        || retained.lock_inode() != guard.inode()
        || retained.records()[0].record_digest() != encoded.digest
    {
        return Err(io::Error::other(
            "published state did not strictly reload as the matching Prepared record",
        ));
    }

    #[cfg(any(test, feature = "test-support"))]
    if fault == PreparedPublishFault::ObserveGuardHeld {
        let (uid, gid) =
            test_lock_owner.ok_or_else(|| io::Error::other("missing test lock owner"))?;
        let contender =
            crate::hvf_owner_commissioning_lock::validate_test_hvf_owner_commissioning_lock(
                root, uid, gid,
            )
            .map_err(io::Error::other)?;
        let result =
            crate::hvf_owner_commissioning_lock::try_acquire_test_hvf_owner_commissioning_lock(
                root, contender, uid, gid,
            );
        if !matches!(result, Err(HvfOwnerCommissioningLockAcquisitionError::Busy)) {
            return Err(io::Error::other(
                "direct contender did not observe the publication guard",
            ));
        }
    }

    Ok(PublishedPreparedState {
        intent_digest: retained.intent_digest(),
        lock_device: retained.lock_device(),
        lock_inode: retained.lock_inode(),
        record_digest: retained.records()[0].record_digest(),
        phase: retained.phase(),
    })
}

fn require_created_state_file(
    file: &File,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != intent.authority_role().uid()
        || metadata.gid() != intent.authority_role().gid()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != 0
        || crate::hvf_owner_commissioning_intent::has_extended_acl(file)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "created commissioning state failed filesystem policy",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedPublishFault {
    None,
    #[cfg(any(test, feature = "test-support"))]
    ExclusiveCreateRace,
    #[cfg(any(test, feature = "test-support"))]
    DescriptorPolicy,
    #[cfg(any(test, feature = "test-support"))]
    Write,
    #[cfg(any(test, feature = "test-support"))]
    FileSync,
    #[cfg(any(test, feature = "test-support"))]
    DirectorySync,
    #[cfg(any(test, feature = "test-support"))]
    PostLoad,
    #[cfg(any(test, feature = "test-support"))]
    ObserveGuardHeld,
}

/// Fault points for the hermetic fixed-operation witness.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TestPreparedPublishFault {
    /// Execute the complete operation without injection.
    None,
    /// Occupy the fixed child after consumption and before exclusive creation.
    ExclusiveCreateRace,
    /// Make the opened descriptor violate exact mode policy.
    DescriptorPolicy,
    /// Fail immediately before writing canonical bytes.
    Write,
    /// Fail after writing and before file synchronization.
    FileSync,
    /// Fail after file synchronization and before directory synchronization.
    DirectorySync,
    /// Fail after strict reload.
    PostLoad,
    /// Require a direct contender to observe the guard during post-write observation.
    ObserveGuardHeld,
}

#[cfg(any(test, feature = "test-support"))]
impl From<TestPreparedPublishFault> for PreparedPublishFault {
    fn from(fault: TestPreparedPublishFault) -> Self {
        match fault {
            TestPreparedPublishFault::None => Self::None,
            TestPreparedPublishFault::ExclusiveCreateRace => Self::ExclusiveCreateRace,
            TestPreparedPublishFault::DescriptorPolicy => Self::DescriptorPolicy,
            TestPreparedPublishFault::Write => Self::Write,
            TestPreparedPublishFault::FileSync => Self::FileSync,
            TestPreparedPublishFault::DirectorySync => Self::DirectorySync,
            TestPreparedPublishFault::PostLoad => Self::PostLoad,
            TestPreparedPublishFault::ObserveGuardHeld => Self::ObserveGuardHeld,
        }
    }
}

/// Injected validated filesystem inputs for the hermetic writer.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct TestPreparedFilesystemInputs {
    /// Initially loaded intent.
    pub intent: LoadedHvfOwnerCommissioningIntent,
    /// Retained validated authority root.
    pub root: ProtectedAuthorityRoot,
    /// Retained validated permanent lock.
    pub lock: ValidatedCommissioningLock,
    /// Injected `/private/var/db` equivalent used for both fresh reloads.
    pub reload_db_root: File,
    /// Expected installer identity for the injected ancestry and lock.
    pub installer_uid: u32,
    /// Expected installer group for the injected ancestry and lock.
    pub installer_gid: u32,
}

/// Injected effective process identity for the hermetic writer.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct TestPreparedProcessIdentity {
    /// Effective user identifier.
    pub uid: u32,
    /// Effective group identifier.
    pub gid: u32,
}

/// Publish through injected validated descriptors for hermetic tests.
///
/// The test seam changes only fixed-path loading and observed process identity.
/// It preserves acquisition, reload, preflight, permit consumption, creation,
/// synchronization, and strict post-write observation ordering.
///
/// A fixture permit is a distinct type and cannot be passed to
/// [`publish_hvf_owner_prepared`].
///
/// ```compile_fail
/// use mvm_commissioning_auth::commissioning_bootstrap_session::test_support::prepared_permit;
/// use mvm_core::hvf_owner_prepared_writer::publish_hvf_owner_prepared;
///
/// let (fixture, _) = prepared_permit([1; 32], true);
/// let _ = publish_hvf_owner_prepared(fixture);
/// ```
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn publish_test_hvf_owner_prepared(
    permit: TestPreparedPermit,
    filesystem: TestPreparedFilesystemInputs,
    effective_identity: TestPreparedProcessIdentity,
    fault: TestPreparedPublishFault,
) -> Result<PublishedPreparedState, PublishPreparedStateError> {
    publish_with_inputs(
        PreparedOperationInputs {
            permit: PreparedPermit::Test(permit),
            intent_a: filesystem.intent,
            root: filesystem.root,
            lock: filesystem.lock,
            effective_identity: EffectiveIdentity {
                uid: effective_identity.uid,
                gid: effective_identity.gid,
            },
            reload: ReloadSource::Test {
                db_root: filesystem.reload_db_root,
                installer_identity: EffectiveIdentity {
                    uid: filesystem.installer_uid,
                    gid: filesystem.installer_gid,
                },
            },
        },
        fault.into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use mvm_commissioning_auth::commissioning_bootstrap_session::test_support::{
        PreparedPermitProbe, TestPreparedPermit, prepared_permit,
    };
    use serde_json::json;

    use super::*;
    use crate::hvf_owner_commissioning_lock::{
        try_acquire_test_hvf_owner_commissioning_lock, validate_test_hvf_owner_commissioning_lock,
    };
    use crate::hvf_owner_deployment_receipt::{OwnerComponentPinV1, cohort_digest};
    use crate::hvf_owner_protected_authority_root::validate_test_protected_authority_root;

    struct Fixture {
        root: tempfile::TempDir,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create fixture root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("set fixture root mode");
            let metadata = fs::metadata(root.path()).expect("read fixture root");
            let uid = metadata.uid();
            let gid = metadata.gid();
            let deployment = root.path().join("mvm");
            fs::create_dir(&deployment).expect("create deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
                .expect("set deployment mode");
            let authority = deployment.join("authority");
            fs::create_dir(&authority).expect("create authority");
            fs::set_permissions(&authority, fs::Permissions::from_mode(0o700))
                .expect("set authority mode");
            write_intent(&deployment, uid, gid, 7);
            let lock = authority.join(crate::hvf_owner_commissioning_lock::COMMISSIONING_LOCK_NAME);
            fs::write(&lock, []).expect("create lock");
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o444)).expect("set lock mode");
            set_immutable(&lock, true);
            Self { root, uid, gid }
        }

        fn deployment(&self) -> PathBuf {
            self.root.path().join("mvm")
        }

        fn authority_path(&self) -> PathBuf {
            self.deployment().join("authority")
        }

        fn state_path(&self) -> PathBuf {
            self.authority_path()
                .join(crate::hvf_owner_commissioning_state::COMMISSIONING_STATE_NAME)
        }

        fn lock_path(&self) -> PathBuf {
            self.authority_path()
                .join(crate::hvf_owner_commissioning_lock::COMMISSIONING_LOCK_NAME)
        }

        fn intent(&self) -> LoadedHvfOwnerCommissioningIntent {
            crate::hvf_owner_commissioning_intent::load_test_hvf_owner_commissioning_intent(
                File::open(self.root.path()).expect("open fixture root"),
                self.uid,
                self.gid,
            )
            .expect("load intent")
        }

        fn inputs(
            &self,
        ) -> (
            LoadedHvfOwnerCommissioningIntent,
            ProtectedAuthorityRoot,
            ValidatedCommissioningLock,
        ) {
            let intent = self.intent();
            let root = validate_test_protected_authority_root(
                &intent,
                File::open(self.root.path()).expect("open root for authority"),
                self.uid,
                self.gid,
            )
            .expect("validate authority");
            let lock = validate_test_hvf_owner_commissioning_lock(&root, self.uid, self.gid)
                .expect("validate lock");
            (intent, root, lock)
        }

        fn permit(&self, succeeds: bool) -> (TestPreparedPermit, PreparedPermitProbe) {
            prepared_permit(self.intent().digest(), succeeds)
        }

        fn filesystem(
            &self,
            intent: LoadedHvfOwnerCommissioningIntent,
            root: ProtectedAuthorityRoot,
            lock: ValidatedCommissioningLock,
        ) -> TestPreparedFilesystemInputs {
            TestPreparedFilesystemInputs {
                intent,
                root,
                lock,
                reload_db_root: File::open(self.root.path()).expect("open root for reload"),
                installer_uid: self.uid,
                installer_gid: self.gid,
            }
        }

        fn identity(&self) -> TestPreparedProcessIdentity {
            TestPreparedProcessIdentity {
                uid: self.uid,
                gid: self.gid,
            }
        }

        fn publish(
            &self,
            permit: TestPreparedPermit,
            fault: TestPreparedPublishFault,
        ) -> Result<PublishedPreparedState, PublishPreparedStateError> {
            let (intent, root, lock) = self.inputs();
            publish_test_hvf_owner_prepared(
                permit,
                self.filesystem(intent, root, lock),
                self.identity(),
                fault,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.lock_path().exists() {
                set_immutable(&self.lock_path(), false);
            }
        }
    }

    fn write_intent(deployment: &Path, uid: u32, gid: u32, epoch: u64) {
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
        let bytes = serde_json::to_vec(&json!({
            "schema_version": 1,
            "deployment_id": "production-1",
            "deployment_epoch": epoch,
            "protected_roles": {
                "authority": {
                    "uid": uid,
                    "gid": gid,
                    "executable": "/Library/PrivilegedHelperTools/mvm-authority",
                    "designated_requirement":
                        "identifier \"dev.mvm.authority\" and anchor apple generic"
                },
                "runtime": {
                    "uid": uid.checked_add(1).expect("test uid has room"),
                    "gid": gid.checked_add(1).expect("test gid has room"),
                    "executable": "/Library/PrivilegedHelperTools/mvm-hvf-run-owner",
                    "designated_requirement":
                        "identifier \"dev.mvm.owner\" and anchor apple generic"
                }
            },
            "approved_owner_code_cohort": {
                "digest": digest,
                "owner_component": component
            }
        }))
        .expect("serialize intent");
        let path = deployment.join("owner-commissioning-intent.json");
        fs::write(&path, bytes).expect("write intent");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("set intent mode");
    }

    #[cfg(target_os = "macos")]
    fn set_immutable(path: &Path, immutable: bool) {
        let flag = if immutable { "uchg" } else { "nouchg" };
        let status = std::process::Command::new("chflags")
            .arg(flag)
            .arg(path)
            .status()
            .expect("run chflags");
        assert!(status.success(), "chflags {flag} must succeed");
    }

    #[cfg(not(target_os = "macos"))]
    fn set_immutable(_path: &Path, _immutable: bool) {}

    #[test]
    fn publishes_exact_canonical_prepared_record_and_observes_under_guard() {
        for fault in [
            TestPreparedPublishFault::None,
            TestPreparedPublishFault::ObserveGuardHeld,
        ] {
            let fixture = Fixture::new();
            let (permit, probe) = fixture.permit(true);
            let intent = fixture.intent();
            let lock_metadata = fs::metadata(fixture.lock_path()).expect("read lock identity");
            let expected =
                encode_prepared_record(&intent, lock_metadata.dev(), lock_metadata.ino());

            let published = fixture.publish(permit, fault).expect("publish Prepared");

            assert!(probe.was_consumed(), "permit must be consumed");
            assert_eq!(
                fs::read(fixture.state_path()).expect("read state"),
                expected.bytes
            );
            assert_eq!(published.intent_digest(), intent.digest());
            assert_eq!(published.lock_device(), lock_metadata.dev());
            assert_eq!(published.lock_inode(), lock_metadata.ino());
            assert_eq!(published.record_digest(), expected.digest);
            assert_eq!(published.phase(), CommissioningPhase::Prepared);
            let mut entries: Vec<_> = fs::read_dir(fixture.authority_path())
                .expect("read authority")
                .map(|entry| entry.expect("read entry").file_name())
                .collect();
            entries.sort();
            let mut expected_entries = vec![
                std::ffi::OsString::from(
                    crate::hvf_owner_commissioning_lock::COMMISSIONING_LOCK_NAME,
                ),
                std::ffi::OsString::from(
                    crate::hvf_owner_commissioning_state::COMMISSIONING_STATE_NAME,
                ),
            ];
            expected_entries.sort();
            assert_eq!(
                entries, expected_entries,
                "writer must create no other authority artifacts"
            );
        }
    }

    #[test]
    fn every_preexisting_state_form_refuses_before_consumption() {
        for form in ["valid", "malformed", "symlink", "directory", "wrong-mode"] {
            let fixture = Fixture::new();
            match form {
                "valid" => {
                    let intent = fixture.intent();
                    let lock = fs::metadata(fixture.lock_path()).expect("read lock");
                    fs::write(
                        fixture.state_path(),
                        encode_prepared_record(&intent, lock.dev(), lock.ino()).bytes,
                    )
                    .expect("write valid state");
                    fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o600))
                        .expect("set state mode");
                }
                "malformed" => {
                    fs::write(fixture.state_path(), b"{bad}\n").expect("write malformed state")
                }
                "symlink" => symlink(fixture.lock_path(), fixture.state_path())
                    .expect("create state symlink"),
                "directory" => fs::create_dir(fixture.state_path()).expect("create state dir"),
                "wrong-mode" => {
                    fs::write(fixture.state_path(), []).expect("create state");
                    fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o644))
                        .expect("set wrong mode");
                }
                _ => unreachable!("closed test form"),
            }
            let (permit, probe) = fixture.permit(true);
            assert!(matches!(
                fixture.publish(permit, TestPreparedPublishFault::None),
                Err(PublishPreparedStateError::StateExists)
            ));
            assert!(
                !probe.was_consumed(),
                "{form} must refuse before consumption"
            );
        }
    }

    #[test]
    fn preconsumption_refusals_create_no_state() {
        let fixture = Fixture::new();
        let (wrong, wrong_probe) = prepared_permit([9; 32], true);
        assert!(matches!(
            fixture.publish(wrong, TestPreparedPublishFault::None),
            Err(PublishPreparedStateError::PermitIntentMismatch)
        ));
        assert!(!wrong_probe.was_consumed());
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (permit, probe) = fixture.permit(false);
        assert!(matches!(
            fixture.publish(permit, TestPreparedPublishFault::None),
            Err(PublishPreparedStateError::PermitRevalidation)
        ));
        assert!(probe.was_consumed(), "revalidation attempt is terminal");
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (permit, probe) = fixture.permit(true);
        let (intent, root, lock) = fixture.inputs();
        let error = publish_test_hvf_owner_prepared(
            permit,
            fixture.filesystem(intent, root, lock),
            TestPreparedProcessIdentity {
                uid: fixture.uid.checked_add(1).expect("uid has room"),
                gid: fixture.gid,
            },
            TestPreparedPublishFault::None,
        )
        .expect_err("wrong effective uid must refuse");
        assert!(matches!(
            error,
            PublishPreparedStateError::ProcessIdentityMismatch
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (permit, probe) = fixture.permit(true);
        let (intent, root, lock) = fixture.inputs();
        let error = publish_test_hvf_owner_prepared(
            permit,
            fixture.filesystem(intent, root, lock),
            TestPreparedProcessIdentity {
                uid: fixture.uid,
                gid: fixture.gid.checked_add(1).expect("gid has room"),
            },
            TestPreparedPublishFault::None,
        )
        .expect_err("wrong effective gid must refuse");
        assert!(matches!(
            error,
            PublishPreparedStateError::ProcessIdentityMismatch
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());
    }

    #[test]
    fn busy_and_intent_drift_refuse_before_consumption() {
        let fixture = Fixture::new();
        let (intent, held_root, held_lock) = fixture.inputs();
        let _guard = try_acquire_test_hvf_owner_commissioning_lock(
            &held_root,
            held_lock,
            fixture.uid,
            fixture.gid,
        )
        .expect("hold lock");
        let (_, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        assert!(matches!(
            publish_test_hvf_owner_prepared(
                permit,
                fixture.filesystem(intent, root, lock),
                fixture.identity(),
                TestPreparedPublishFault::None,
            ),
            Err(PublishPreparedStateError::LockAcquisition(
                HvfOwnerCommissioningLockAcquisitionError::Busy
            ))
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (intent, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        write_intent(&fixture.deployment(), fixture.uid, fixture.gid, 8);
        assert!(matches!(
            publish_test_hvf_owner_prepared(
                permit,
                fixture.filesystem(intent, root, lock),
                fixture.identity(),
                TestPreparedPublishFault::None,
            ),
            Err(PublishPreparedStateError::IntentChanged)
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());
    }

    #[test]
    fn invalid_reloaded_intent_and_lock_refuse_before_consumption() {
        let fixture = Fixture::new();
        let (intent, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        fs::write(
            fixture.deployment().join("owner-commissioning-intent.json"),
            b"{invalid",
        )
        .expect("corrupt intent");
        assert!(matches!(
            publish_test_hvf_owner_prepared(
                permit,
                fixture.filesystem(intent, root, lock),
                fixture.identity(),
                TestPreparedPublishFault::None,
            ),
            Err(PublishPreparedStateError::Intent(_))
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (intent, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        set_immutable(&fixture.lock_path(), false);
        fs::set_permissions(fixture.lock_path(), fs::Permissions::from_mode(0o644))
            .expect("make lock policy invalid");
        assert!(matches!(
            publish_test_hvf_owner_prepared(
                permit,
                fixture.filesystem(intent, root, lock),
                fixture.identity(),
                TestPreparedPublishFault::None,
            ),
            Err(PublishPreparedStateError::LockAcquisition(
                HvfOwnerCommissioningLockAcquisitionError::FilesystemPolicy
            ))
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());
    }

    #[test]
    fn authority_policy_drift_and_valid_replacement_refuse_before_consumption() {
        let fixture = Fixture::new();
        let (intent, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        fs::set_permissions(fixture.authority_path(), fs::Permissions::from_mode(0o755))
            .expect("drift authority policy");
        assert!(matches!(
            publish_test_hvf_owner_prepared(
                permit,
                fixture.filesystem(intent, root, lock),
                fixture.identity(),
                TestPreparedPublishFault::None,
            ),
            Err(PublishPreparedStateError::AuthorityRoot(
                ProtectedAuthorityRootError::AuthorityPolicy
            ))
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());

        let fixture = Fixture::new();
        let (intent, root, lock) = fixture.inputs();
        let (permit, probe) = prepared_permit(intent.digest(), true);
        let original = fixture.deployment().join("authority-original");
        fs::rename(fixture.authority_path(), &original).expect("retain original authority");
        fs::create_dir(fixture.authority_path()).expect("create replacement authority");
        fs::set_permissions(fixture.authority_path(), fs::Permissions::from_mode(0o700))
            .expect("set replacement policy");
        let result = publish_test_hvf_owner_prepared(
            permit,
            fixture.filesystem(intent, root, lock),
            fixture.identity(),
            TestPreparedPublishFault::None,
        );
        assert!(matches!(
            result,
            Err(PublishPreparedStateError::AuthorityRootChanged)
        ));
        assert!(!probe.was_consumed());
        assert!(!fixture.state_path().exists());

        fs::remove_dir(fixture.authority_path()).expect("remove replacement authority");
        fs::rename(original, fixture.authority_path()).expect("restore original authority");
    }

    #[test]
    fn every_postconsumption_failure_is_unknown_and_never_cleaned_up() {
        for fault in [
            TestPreparedPublishFault::ExclusiveCreateRace,
            TestPreparedPublishFault::DescriptorPolicy,
            TestPreparedPublishFault::Write,
            TestPreparedPublishFault::FileSync,
            TestPreparedPublishFault::DirectorySync,
            TestPreparedPublishFault::PostLoad,
        ] {
            let fixture = Fixture::new();
            let (permit, probe) = fixture.permit(true);
            assert!(matches!(
                fixture.publish(permit, fault),
                Err(PublishPreparedStateError::PublicationUnknown(_))
            ));
            assert!(probe.was_consumed(), "{fault:?} must consume the permit");
            assert!(
                fs::symlink_metadata(fixture.state_path()).is_ok(),
                "{fault:?} must retain the uncertain child"
            );

            let (second, second_probe) = fixture.permit(true);
            assert!(matches!(
                fixture.publish(second, TestPreparedPublishFault::None),
                Err(PublishPreparedStateError::StateExists)
            ));
            assert!(
                !second_probe.was_consumed(),
                "{fault:?} must offer no cleanup or retry path"
            );
        }
    }
}
