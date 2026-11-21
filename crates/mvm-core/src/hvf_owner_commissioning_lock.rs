//! Read-only validation of the permanent installer-provisioned commissioning lock inode.
//!
//! Validation retains the observed descriptor but never acquires a lock. The
//! installer alone creates this lifetime-stable object. Even a successful
//! validation proves neither installer transaction freshness nor exclusion.

use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::hvf_owner_commissioning_intent::has_extended_acl;
use crate::hvf_owner_commissioning_state::RetainedCommissioningState;
use crate::hvf_owner_protected_authority_root::ProtectedAuthorityRoot;

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
        if state.lock_device() == self.device && state.lock_inode() == self.inode {
            CommissioningLockBinding::Matches
        } else {
            CommissioningLockBinding::Mismatch
        }
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
