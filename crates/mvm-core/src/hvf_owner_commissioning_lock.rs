//! Validation and transient exclusion for the permanent commissioning lock inode.
//!
//! Validation retains the observed descriptor without acquiring a lock. A
//! successful guard adds only cooperative, process-lifetime advisory exclusion
//! on that descriptor. The installer alone creates this lifetime-stable object.
//! Neither operation proves installer transaction freshness.

use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::hvf_owner_commissioning_intent::has_extended_acl;
use crate::hvf_owner_commissioning_state::RetainedCommissioningState;
use crate::hvf_owner_protected_authority_root::ProtectedAuthorityRoot;
use crate::util::atomic_io::FileLock;

/// Fixed child name below the protected authority root.
pub const COMMISSIONING_LOCK_NAME: &str = "owner-commissioning.lock";

/// Retained read-only descriptor and public identity of the validated lock inode.
///
/// This unique resource is intentionally neither cloneable nor serializable and
/// exposes no descriptor or lock operation.
#[must_use]
pub struct ValidatedCommissioningLock {
    _file: File,
    device: u64,
    inode: u64,
}

impl ValidatedCommissioningLock {
    /// Device identity used by durable state-log bindings.
    #[must_use]
    pub fn device(&self) -> u64 {
        self.device
    }

    /// Inode identity used by durable state-log bindings.
    #[must_use]
    pub fn inode(&self) -> u64 {
        self.inode
    }

    /// Compare this observation with the retained state log's lock binding.
    ///
    /// This pure comparison grants neither mutation authority nor exclusion.
    pub fn compare_state_binding(
        &self,
        state: &RetainedCommissioningState,
    ) -> CommissioningLockBinding {
        compare_state_binding(self.device, self.inode, state)
    }
}

impl std::fmt::Debug for ValidatedCommissioningLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedCommissioningLock")
            .field("device", &self.device)
            .field("inode", &self.inode)
            .finish_non_exhaustive()
    }
}

/// Exclusive advisory exclusion on the validated permanent lock inode.
///
/// This unique process-local guard is intentionally neither cloneable nor
/// serializable. It exposes observations only, not its descriptor, unlocking,
/// or mutation. Exclusion is effective only while every mutator participates in
/// this advisory locking protocol.
#[must_use]
pub struct CommissioningLockGuard {
    _lock: FileLock,
    device: u64,
    inode: u64,
}

impl CommissioningLockGuard {
    /// Device identity used by durable state-log bindings.
    #[must_use]
    pub fn device(&self) -> u64 {
        self.device
    }

    /// Inode identity used by durable state-log bindings.
    #[must_use]
    pub fn inode(&self) -> u64 {
        self.inode
    }

    /// Compare this held inode with the retained state log's lock binding.
    ///
    /// This pure comparison grants no mutation authority.
    pub fn compare_state_binding(
        &self,
        state: &RetainedCommissioningState,
    ) -> CommissioningLockBinding {
        compare_state_binding(self.device, self.inode, state)
    }
}

impl std::fmt::Debug for CommissioningLockGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommissioningLockGuard")
            .field("device", &self.device)
            .field("inode", &self.inode)
            .finish_non_exhaustive()
    }
}

/// Result of comparing retained state with the observed permanent lock identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum CommissioningLockBinding {
    /// State names the exact observed lock device and inode.
    Matches,
    /// State names a different lock device or inode and must be refused.
    Mismatch,
}

/// Permanent commissioning-lock validation failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HvfOwnerCommissioningLockError {
    /// The host cannot establish the production macOS lock contract.
    #[error("protected HVF owner commissioning lock validation requires macOS")]
    Unsupported,
    /// The installer-provisioned fixed lock child is absent.
    #[error("protected HVF owner commissioning lock is missing")]
    Missing,
    /// The fixed lock child could not be safely opened or inspected.
    #[error("protected HVF owner commissioning lock is unavailable")]
    Unavailable(#[source] io::Error),
    /// Type, ownership, mode, link, length, ACL, or immutable policy failed.
    #[error("protected HVF owner commissioning lock filesystem policy failed")]
    FilesystemPolicy,
    /// The fixed path named a different inode when it was observed again.
    #[error("protected HVF owner commissioning lock identity changed during validation")]
    IdentityChanged,
}

/// Permanent commissioning-lock acquisition failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HvfOwnerCommissioningLockAcquisitionError {
    /// The host cannot establish the production macOS lock contract.
    #[error("protected HVF owner commissioning lock acquisition requires macOS")]
    Unsupported,
    /// Another cooperating process currently holds exclusive exclusion.
    #[error("protected HVF owner commissioning lock is busy")]
    Busy,
    /// The installer-provisioned fixed lock child is absent.
    #[error("protected HVF owner commissioning lock is missing")]
    Missing,
    /// The validated descriptor or fixed child could not be locked or inspected.
    #[error("protected HVF owner commissioning lock is unavailable")]
    Unavailable(#[source] io::Error),
    /// Type, ownership, mode, link, length, ACL, or immutable policy failed.
    #[error("protected HVF owner commissioning lock filesystem policy failed")]
    FilesystemPolicy,
    /// The held descriptor or fixed path no longer names the validated inode.
    #[error("protected HVF owner commissioning lock identity changed")]
    IdentityChanged,
}

/// Validate and retain the permanent installer-provisioned lock inode.
///
/// The fixed child is opened descriptor-relative with read-only, no-follow,
/// nonblocking, and close-on-exec flags. A second observation of the fixed name
/// detects replacement during validation, but is observation only: it does not
/// establish exclusion or an atomic namespace snapshot.
///
/// # Errors
/// Refuses unsupported hosts, absence, aliases, unsafe filesystem metadata,
/// missing user/system immutable flags, and identity replacement.
#[cfg(target_os = "macos")]
pub fn validate_hvf_owner_commissioning_lock(
    root: &ProtectedAuthorityRoot,
) -> Result<ValidatedCommissioningLock, HvfOwnerCommissioningLockError> {
    validate_from_root(root, LockPolicy::production(), || {})
}

/// Unsupported platforms cannot establish the production immutable-inode contract.
///
/// # Errors
/// Always returns [`HvfOwnerCommissioningLockError::Unsupported`] without I/O.
#[cfg(not(target_os = "macos"))]
pub fn validate_hvf_owner_commissioning_lock(
    _root: &ProtectedAuthorityRoot,
) -> Result<ValidatedCommissioningLock, HvfOwnerCommissioningLockError> {
    Err(HvfOwnerCommissioningLockError::Unsupported)
}

/// Validate through an injected protected root for hermetic tests.
///
/// Ownership is injected because unprivileged tests cannot create root-owned
/// fixtures. macOS tests still require a native immutable flag. Other Unix test
/// builds emulate only that unavailable flag check; production remains unsupported.
///
/// # Errors
/// Refuses the same fixed-child and filesystem policy failures as production.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn validate_test_hvf_owner_commissioning_lock(
    root: &ProtectedAuthorityRoot,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<ValidatedCommissioningLock, HvfOwnerCommissioningLockError> {
    validate_from_root(root, LockPolicy::test(expected_uid, expected_gid), || {})
}

/// Try to acquire exclusive advisory exclusion on a validated lock descriptor.
///
/// Acquisition never waits, polls, retries, opens a replacement for locking, or
/// changes durable state. After locking the retained descriptor, this revalidates
/// both that descriptor and a fresh fixed-child open through `root`, including
/// identity and complete filesystem policy. The trusted protected-root owner can
/// still change namespace or inode state after these observations; every mutator
/// must participate in the advisory lock protocol.
///
/// # Errors
/// Returns typed contention immediately and refuses unsupported hosts, absence,
/// unsafe filesystem metadata, identity replacement, and operating-system
/// failures. Every refusal releases any acquired kernel lock on drop.
#[cfg(target_os = "macos")]
pub fn try_acquire_hvf_owner_commissioning_lock(
    root: &ProtectedAuthorityRoot,
    validated: ValidatedCommissioningLock,
) -> Result<CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError> {
    try_acquire_from_root(root, validated, LockPolicy::production(), || {})
}

/// Unsupported platforms cannot establish the production immutable-inode contract.
///
/// # Errors
/// Always returns [`HvfOwnerCommissioningLockAcquisitionError::Unsupported`]
/// without I/O.
#[cfg(not(target_os = "macos"))]
pub fn try_acquire_hvf_owner_commissioning_lock(
    _root: &ProtectedAuthorityRoot,
    _validated: ValidatedCommissioningLock,
) -> Result<CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError> {
    Err(HvfOwnerCommissioningLockAcquisitionError::Unsupported)
}

/// Acquire through an injected protected root for hermetic tests.
///
/// # Errors
/// Refuses the same contention, fixed-child, and filesystem-policy failures as
/// production while injecting only the ownership expectation.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn try_acquire_test_hvf_owner_commissioning_lock(
    root: &ProtectedAuthorityRoot,
    validated: ValidatedCommissioningLock,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError> {
    try_acquire_from_root(
        root,
        validated,
        LockPolicy::test(expected_uid, expected_gid),
        || {},
    )
}

#[derive(Clone, Copy)]
struct LockPolicy {
    expected_uid: u32,
    expected_gid: u32,
    immutable: ImmutablePolicy,
}

impl LockPolicy {
    #[cfg(target_os = "macos")]
    fn production() -> Self {
        Self {
            expected_uid: 0,
            expected_gid: 0,
            immutable: ImmutablePolicy::Native,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test(expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            expected_uid,
            expected_gid,
            immutable: if cfg!(target_os = "macos") {
                ImmutablePolicy::Native
            } else {
                ImmutablePolicy::TestEmulated
            },
        }
    }
}

#[derive(Clone, Copy)]
enum ImmutablePolicy {
    Native,
    #[cfg(any(test, feature = "test-support"))]
    TestEmulated,
}

fn validate_from_root(
    root: &ProtectedAuthorityRoot,
    policy: LockPolicy,
    before_reopen: impl FnOnce(),
) -> Result<ValidatedCommissioningLock, HvfOwnerCommissioningLockError> {
    let file = open_fixed_lock(root)?;
    let (device, inode) = require_lock_file(&file, policy)?;
    before_reopen();
    let reopened = open_fixed_lock(root)?;
    let reopened_metadata = reopened
        .metadata()
        .map_err(HvfOwnerCommissioningLockError::Unavailable)?;
    if reopened_metadata.dev() != device || reopened_metadata.ino() != inode {
        return Err(HvfOwnerCommissioningLockError::IdentityChanged);
    }
    Ok(ValidatedCommissioningLock {
        _file: file,
        device,
        inode,
    })
}

fn try_acquire_from_root(
    root: &ProtectedAuthorityRoot,
    validated: ValidatedCommissioningLock,
    policy: LockPolicy,
    after_acquire: impl FnOnce(),
) -> Result<CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError> {
    let ValidatedCommissioningLock {
        _file: file,
        device,
        inode,
    } = validated;
    let Some(lock) = FileLock::try_acquire_opened(file)
        .map_err(HvfOwnerCommissioningLockAcquisitionError::Unavailable)?
    else {
        return Err(HvfOwnerCommissioningLockAcquisitionError::Busy);
    };

    after_acquire();

    let reopened = root.open_commissioning_lock().map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            HvfOwnerCommissioningLockAcquisitionError::Missing
        } else {
            HvfOwnerCommissioningLockAcquisitionError::Unavailable(error.into())
        }
    })?;
    let reopened_identity =
        require_lock_file(&reopened, policy).map_err(map_acquisition_validation_error)?;
    if reopened_identity != (device, inode) {
        return Err(HvfOwnerCommissioningLockAcquisitionError::IdentityChanged);
    }

    let held_identity =
        require_lock_file(lock.opened_file(), policy).map_err(map_acquisition_validation_error)?;
    if held_identity != (device, inode) {
        return Err(HvfOwnerCommissioningLockAcquisitionError::IdentityChanged);
    }

    Ok(CommissioningLockGuard {
        _lock: lock,
        device,
        inode,
    })
}

fn map_acquisition_validation_error(
    error: HvfOwnerCommissioningLockError,
) -> HvfOwnerCommissioningLockAcquisitionError {
    match error {
        HvfOwnerCommissioningLockError::Unsupported => {
            HvfOwnerCommissioningLockAcquisitionError::Unsupported
        }
        HvfOwnerCommissioningLockError::Missing => {
            HvfOwnerCommissioningLockAcquisitionError::Missing
        }
        HvfOwnerCommissioningLockError::Unavailable(error) => {
            HvfOwnerCommissioningLockAcquisitionError::Unavailable(error)
        }
        HvfOwnerCommissioningLockError::FilesystemPolicy => {
            HvfOwnerCommissioningLockAcquisitionError::FilesystemPolicy
        }
        HvfOwnerCommissioningLockError::IdentityChanged => {
            HvfOwnerCommissioningLockAcquisitionError::IdentityChanged
        }
    }
}

fn open_fixed_lock(root: &ProtectedAuthorityRoot) -> Result<File, HvfOwnerCommissioningLockError> {
    root.open_commissioning_lock().map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            HvfOwnerCommissioningLockError::Missing
        } else {
            HvfOwnerCommissioningLockError::Unavailable(error.into())
        }
    })
}

fn require_lock_file(
    file: &File,
    policy: LockPolicy,
) -> Result<(u64, u64), HvfOwnerCommissioningLockError> {
    let metadata = file
        .metadata()
        .map_err(HvfOwnerCommissioningLockError::Unavailable)?;
    let immutable = has_required_immutable_flag(&metadata, policy.immutable);
    if !metadata.is_file()
        || metadata.uid() != policy.expected_uid
        || metadata.gid() != policy.expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o444
        || metadata.nlink() != 1
        || metadata.len() != 0
        || !immutable
        || has_extended_acl(file).map_err(HvfOwnerCommissioningLockError::Unavailable)?
        || metadata.dev() == 0
        || metadata.ino() == 0
    {
        return Err(HvfOwnerCommissioningLockError::FilesystemPolicy);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn compare_state_binding(
    device: u64,
    inode: u64,
    state: &RetainedCommissioningState,
) -> CommissioningLockBinding {
    if state.lock_device() == device && state.lock_inode() == inode {
        CommissioningLockBinding::Matches
    } else {
        CommissioningLockBinding::Mismatch
    }
}

#[cfg(target_os = "macos")]
fn has_required_immutable_flag(metadata: &std::fs::Metadata, policy: ImmutablePolicy) -> bool {
    use std::os::macos::fs::MetadataExt as _;

    match policy {
        ImmutablePolicy::Native => {
            let immutable_mask = libc::UF_IMMUTABLE | libc::SF_IMMUTABLE;
            metadata.st_flags() & immutable_mask != 0
        }
        #[cfg(any(test, feature = "test-support"))]
        ImmutablePolicy::TestEmulated => true,
    }
}

#[cfg(not(target_os = "macos"))]
fn has_required_immutable_flag(_metadata: &std::fs::Metadata, policy: ImmutablePolicy) -> bool {
    match policy {
        ImmutablePolicy::Native => false,
        #[cfg(any(test, feature = "test-support"))]
        ImmutablePolicy::TestEmulated => true,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::*;
    use crate::hvf_owner_commissioning_intent::load_test_hvf_owner_commissioning_intent;
    use crate::hvf_owner_deployment_receipt::{OwnerComponentPinV1, cohort_digest};
    use crate::hvf_owner_protected_authority_root::validate_test_protected_authority_root;

    struct Fixture {
        root: tempfile::TempDir,
        authority: ProtectedAuthorityRoot,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create fixture root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("set fixture root mode");
            let metadata = fs::metadata(root.path()).expect("read fixture root metadata");
            let uid = metadata.uid();
            let gid = metadata.gid();
            let deployment = root.path().join("mvm");
            fs::create_dir(&deployment).expect("create deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
                .expect("set deployment mode");
            let authority_path = deployment.join("authority");
            fs::create_dir(&authority_path).expect("create authority");
            fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o700))
                .expect("set authority mode");
            write_intent(&deployment, uid, gid);
            let intent = load_test_hvf_owner_commissioning_intent(
                File::open(root.path()).expect("open fixture root"),
                uid,
                gid,
            )
            .expect("load intent");
            let authority = validate_test_protected_authority_root(
                &intent,
                File::open(root.path()).expect("reopen fixture root"),
                uid,
                gid,
            )
            .expect("validate authority");
            Self {
                root,
                authority,
                uid,
                gid,
            }
        }

        fn authority_path(&self) -> PathBuf {
            self.root.path().join("mvm/authority")
        }

        fn lock_path(&self) -> PathBuf {
            self.authority_path().join(COMMISSIONING_LOCK_NAME)
        }

        fn create_lock(&self) {
            fs::write(self.lock_path(), []).expect("create lock");
            fs::set_permissions(self.lock_path(), fs::Permissions::from_mode(0o444))
                .expect("set lock mode");
            set_immutable(&self.lock_path(), true);
        }

        fn validate(&self) -> Result<ValidatedCommissioningLock, HvfOwnerCommissioningLockError> {
            validate_test_hvf_owner_commissioning_lock(&self.authority, self.uid, self.gid)
        }

        fn acquire(
            &self,
            validated: ValidatedCommissioningLock,
        ) -> Result<CommissioningLockGuard, HvfOwnerCommissioningLockAcquisitionError> {
            try_acquire_test_hvf_owner_commissioning_lock(
                &self.authority,
                validated,
                self.uid,
                self.gid,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.lock_path().exists() {
                set_immutable(&self.lock_path(), false);
            }
            let replacement = self.authority_path().join("replacement");
            if replacement.exists() {
                set_immutable(&replacement, false);
            }
        }
    }

    fn write_intent(deployment: &Path, uid: u32, gid: u32) {
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
            "deployment_epoch": 7,
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
    fn validates_fixed_lock_without_side_effects_and_retains_stable_identity() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let before = fs::metadata(fixture.lock_path()).expect("read lock metadata");

        let lock = fixture.validate().expect("validate lock");
        let after = fs::metadata(fixture.lock_path()).expect("reread lock metadata");

        assert_eq!((lock.device(), lock.inode()), (before.dev(), before.ino()));
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.len(), 0);
        assert_eq!(after.permissions().mode() & 0o7777, 0o444);
    }

    #[test]
    fn read_only_immutable_guard_excludes_second_contender_and_drop_releases() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let first = fixture.validate().expect("validate first contender");
        let second = fixture.validate().expect("validate second contender");
        let guard = fixture.acquire(first).expect("acquire first contender");
        assert_eq!((guard.device(), guard.inode()), {
            let metadata = fs::metadata(fixture.lock_path()).expect("read lock identity");
            (metadata.dev(), metadata.ino())
        });
        assert!(matches!(
            fixture.acquire(second),
            Err(HvfOwnerCommissioningLockAcquisitionError::Busy)
        ));

        drop(guard);
        let third = fixture.validate().expect("validate third contender");
        assert!(
            fixture.acquire(third).is_ok(),
            "drop must release exclusion for the next contender"
        );
    }

    #[test]
    fn acquisition_does_not_create_or_mutate_lock_state() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let before = fs::metadata(fixture.lock_path()).expect("read lock metadata");
        let before_bytes = fs::read(fixture.lock_path()).expect("read lock contents");

        let guard = fixture
            .acquire(fixture.validate().expect("validate lock"))
            .expect("acquire lock");
        let after = fs::metadata(fixture.lock_path()).expect("reread lock metadata");
        let after_bytes = fs::read(fixture.lock_path()).expect("reread lock contents");

        assert_eq!(before_bytes, after_bytes);
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.len(), before.len());
        assert_eq!(
            after.permissions().mode() & 0o7777,
            before.permissions().mode() & 0o7777
        );
        drop(guard);
    }

    #[test]
    fn refuses_path_replacement_after_acquisition_and_releases_lock() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let validated = fixture.validate().expect("validate original lock");
        let original = fixture.lock_path();
        let original_probe = File::open(&original).expect("retain independent original descriptor");
        let replacement = fixture.authority_path().join("replacement");
        fs::write(&replacement, []).expect("create replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444))
            .expect("set replacement mode");

        let result = try_acquire_from_root(
            &fixture.authority,
            validated,
            LockPolicy::test(fixture.uid, fixture.gid),
            || {
                set_immutable(&original, false);
                fs::remove_file(&original).expect("remove original path");
                fs::rename(&replacement, &original).expect("replace fixed path");
                set_immutable(&original, true);
            },
        );
        assert!(matches!(
            result,
            Err(HvfOwnerCommissioningLockAcquisitionError::IdentityChanged)
        ));
        assert!(
            FileLock::try_acquire_opened(original_probe)
                .expect("probe original lock")
                .is_some(),
            "refusal must release the original inode"
        );

        let replacement = fixture.validate().expect("validate replacement");
        assert!(
            fixture.acquire(replacement).is_ok(),
            "replacement inode remains independently lockable"
        );
    }

    #[test]
    fn refuses_path_removal_after_acquisition_with_typed_missing() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let validated = fixture.validate().expect("validate lock");
        let path = fixture.lock_path();
        let original_probe = File::open(&path).expect("retain independent original descriptor");

        let result = try_acquire_from_root(
            &fixture.authority,
            validated,
            LockPolicy::test(fixture.uid, fixture.gid),
            || {
                set_immutable(&path, false);
                fs::remove_file(&path).expect("remove fixed lock path");
            },
        );
        assert!(matches!(
            result,
            Err(HvfOwnerCommissioningLockAcquisitionError::Missing)
        ));
        assert!(
            FileLock::try_acquire_opened(original_probe)
                .expect("probe removed original lock")
                .is_some(),
            "missing-path refusal must release the original inode"
        );

        fixture.create_lock();
        let recreated = fixture.validate().expect("validate recreated lock");
        assert!(
            fixture.acquire(recreated).is_ok(),
            "recreated inode remains independently lockable"
        );
    }

    #[test]
    fn refuses_policy_change_after_acquisition_and_releases_lock() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let validated = fixture.validate().expect("validate lock");
        let path = fixture.lock_path();

        let result = try_acquire_from_root(
            &fixture.authority,
            validated,
            LockPolicy::test(fixture.uid, fixture.gid),
            || {
                set_immutable(&path, false);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                    .expect("weaken lock mode");
            },
        );
        assert!(matches!(
            result,
            Err(HvfOwnerCommissioningLockAcquisitionError::FilesystemPolicy)
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("restore lock mode");
        set_immutable(&path, true);
        let repaired = fixture.validate().expect("validate restored policy");
        assert!(
            fixture.acquire(repaired).is_ok(),
            "policy refusal must release the kernel lock"
        );
    }

    #[test]
    fn missing_is_typed_and_does_not_create_lock() {
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.validate(),
            Err(HvfOwnerCommissioningLockError::Missing)
        ));
        assert!(!fixture.lock_path().exists());
    }

    #[test]
    fn refuses_alias_directory_fifo_hardlink_and_nonempty_file() {
        for kind in 0..5 {
            let fixture = Fixture::new();
            let path = fixture.lock_path();
            match kind {
                0 => {
                    fs::write(fixture.authority_path().join("target"), [])
                        .expect("write alias target");
                    symlink("target", path).expect("create alias");
                }
                1 => fs::create_dir(path).expect("create directory"),
                2 => {
                    let status = std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .expect("run mkfifo");
                    assert!(status.success(), "mkfifo must succeed");
                }
                3 => {
                    fs::write(&path, []).expect("create lock");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
                        .expect("set lock mode");
                    fs::hard_link(&path, fixture.authority_path().join("alias"))
                        .expect("create hardlink");
                    set_immutable(&path, true);
                }
                4 => {
                    fs::write(&path, b"x").expect("create nonempty lock");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
                        .expect("set lock mode");
                    set_immutable(&path, true);
                }
                _ => unreachable!("bounded fixture kind"),
            }
            assert!(
                fixture.validate().is_err(),
                "unsafe kind {kind} must refuse"
            );
        }
    }

    #[test]
    fn refuses_wrong_owner_group_and_modes() {
        for mode in [0o400, 0o440, 0o446, 0o644, 0o1444, 0o2444, 0o4444] {
            let fixture = Fixture::new();
            fixture.create_lock();
            set_immutable(&fixture.lock_path(), false);
            fs::set_permissions(fixture.lock_path(), fs::Permissions::from_mode(mode))
                .expect("set wrong mode");
            set_immutable(&fixture.lock_path(), true);
            assert!(
                matches!(
                    fixture.validate(),
                    Err(HvfOwnerCommissioningLockError::FilesystemPolicy)
                ),
                "mode {mode:o} must refuse"
            );
        }

        let fixture = Fixture::new();
        fixture.create_lock();
        let file = File::open(fixture.lock_path()).expect("open lock");
        assert!(matches!(
            require_lock_file(
                &file,
                LockPolicy::test(
                    fixture.uid.checked_add(1).expect("uid has room"),
                    fixture.gid
                )
            ),
            Err(HvfOwnerCommissioningLockError::FilesystemPolicy)
        ));
        assert!(matches!(
            require_lock_file(
                &file,
                LockPolicy::test(
                    fixture.uid,
                    fixture.gid.checked_add(1).expect("gid has room")
                )
            ),
            Err(HvfOwnerCommissioningLockError::FilesystemPolicy)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_missing_immutable_flag_and_extended_acl() {
        let fixture = Fixture::new();
        fs::write(fixture.lock_path(), []).expect("create mutable lock");
        fs::set_permissions(fixture.lock_path(), fs::Permissions::from_mode(0o444))
            .expect("set lock mode");
        assert!(matches!(
            fixture.validate(),
            Err(HvfOwnerCommissioningLockError::FilesystemPolicy)
        ));

        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(fixture.lock_path())
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install ACL fixture");
        set_immutable(&fixture.lock_path(), true);
        assert!(matches!(
            fixture.validate(),
            Err(HvfOwnerCommissioningLockError::FilesystemPolicy)
        ));
    }

    #[test]
    fn detects_fixed_path_replacement_by_inode() {
        let fixture = Fixture::new();
        fixture.create_lock();
        let original = fixture.lock_path();
        let replacement = fixture.authority_path().join("replacement");
        fs::write(&replacement, []).expect("create replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444))
            .expect("set replacement mode");

        let result = validate_from_root(
            &fixture.authority,
            LockPolicy::test(fixture.uid, fixture.gid),
            || {
                set_immutable(&original, false);
                fs::remove_file(&original).expect("remove original path");
                fs::rename(&replacement, &original).expect("replace fixed path");
                set_immutable(&original, true);
            },
        );
        assert!(matches!(
            result,
            Err(HvfOwnerCommissioningLockError::IdentityChanged)
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_validation_is_explicitly_unsupported() {
        let fixture = Fixture::new();
        assert!(matches!(
            validate_hvf_owner_commissioning_lock(&fixture.authority),
            Err(HvfOwnerCommissioningLockError::Unsupported)
        ));
    }
}
