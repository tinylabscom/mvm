//! Read-only descriptor validation of the protected macOS HVF authority root.
//!
//! A successful validation retains the exact directory descriptor observed at
//! validation time. It does not establish freshness, exclusion, commissioning
//! progress, an atomic namespace snapshot, or authority to mutate state.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::{Mode, OFlags};

use crate::hvf_owner_commissioning_intent::{LoadedHvfOwnerCommissioningIntent, has_extended_acl};

/// Fixed production authority root. No configuration or environment override exists.
pub const PROTECTED_AUTHORITY_ROOT_PATH: &str = "/private/var/db/mvm/authority";

/// Retained read-only descriptor for a validated protected authority root.
///
/// This type intentionally exposes no descriptor, child-open, metadata, or
/// mutation API. Future mutation must first obtain separately designed
/// exclusion, then reload and revalidate the commissioning intent and root.
#[must_use]
pub struct ProtectedAuthorityRoot {
    directory: File,
}

impl ProtectedAuthorityRoot {
    /// Open only the fixed commissioning-lock child for read-only validation.
    pub(crate) fn open_commissioning_lock(&self) -> Result<File, rustix::io::Errno> {
        rustix::fs::openat(
            &self.directory,
            "owner-commissioning.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
    }

    /// Open only the fixed commissioning-state child for the read-only loader.
    pub(crate) fn open_commissioning_state(&self) -> Result<File, rustix::io::Errno> {
        rustix::fs::openat(
            &self.directory,
            "owner-commissioning-state.jsonl",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
    }
}

/// Protected authority root validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtectedAuthorityRootError {
    /// The host cannot establish the macOS protected-root contract.
    #[error("protected HVF authority root validation requires macOS")]
    Unsupported,
    /// A fixed namespace component could not be opened without following aliases.
    #[error("protected HVF authority root is unavailable")]
    Unavailable,
    /// Root-owned ancestry or the deployment directory violated policy.
    #[error("protected HVF authority root ancestry policy failed")]
    AncestorPolicy,
    /// The authority directory did not match the loaded intent authority identity.
    #[error("protected HVF authority root identity does not match commissioning intent")]
    AuthorityIdentityMismatch,
    /// The authority directory type, mode, or ACL violated policy.
    #[error("protected HVF authority root filesystem policy failed")]
    AuthorityPolicy,
}

/// Validate and retain the fixed production protected authority root.
///
/// Every child is opened descriptor-relative, read-only, directory-only, with
/// symlink following disabled. The authority UID and GID come only from
/// `intent`.
///
/// # Errors
/// Refuses unsupported hosts and every missing, aliased, incorrectly owned,
/// incorrectly permissioned, or extended-ACL namespace component.
#[cfg(target_os = "macos")]
pub fn validate_protected_authority_root(
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
    let root = File::open("/").map_err(|_| ProtectedAuthorityRootError::Unavailable)?;
    require_installer_directory(&root, 0, 0, InstallerDirectoryMode::SecureAncestor)?;
    let private = open_directory(&root, "private")?;
    require_installer_directory(&private, 0, 0, InstallerDirectoryMode::SecureAncestor)?;
    let var = open_directory(&private, "var")?;
    require_installer_directory(&var, 0, 0, InstallerDirectoryMode::SecureAncestor)?;
    let db = open_directory(&var, "db")?;
    validate_from_db_root(intent, InstallerRoot::new(db, 0, 0))
}

/// Unsupported platforms cannot establish the macOS protected-root contract.
///
/// # Errors
/// Always returns [`ProtectedAuthorityRootError::Unsupported`] without reading
/// or changing filesystem state.
#[cfg(not(target_os = "macos"))]
pub fn validate_protected_authority_root(
    _intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
    Err(ProtectedAuthorityRootError::Unsupported)
}

/// Validate through an injected `/private/var/db` descriptor for hermetic tests.
///
/// `expected_installer_uid` and `expected_installer_gid` model root ownership
/// only for the injected ancestry. Authority identity still comes exclusively
/// from `intent`.
///
/// # Errors
/// Refuses the same namespace and filesystem-policy failures as production.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn validate_test_protected_authority_root(
    intent: &LoadedHvfOwnerCommissioningIntent,
    db_root: File,
    expected_installer_uid: u32,
    expected_installer_gid: u32,
) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
    validate_from_db_root(
        intent,
        InstallerRoot::new(db_root, expected_installer_uid, expected_installer_gid),
    )
}

struct InstallerRoot {
    directory: File,
    expected_uid: u32,
    expected_gid: u32,
}

impl InstallerRoot {
    fn new(directory: File, expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            directory,
            expected_uid,
            expected_gid,
        }
    }
}

#[derive(Clone, Copy)]
enum InstallerDirectoryMode {
    SecureAncestor,
    Deployment,
}

fn validate_from_db_root(
    intent: &LoadedHvfOwnerCommissioningIntent,
    root: InstallerRoot,
) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
    require_installer_directory(
        &root.directory,
        root.expected_uid,
        root.expected_gid,
        InstallerDirectoryMode::SecureAncestor,
    )?;
    let deployment = open_directory(&root.directory, "mvm")?;
    require_installer_directory(
        &deployment,
        root.expected_uid,
        root.expected_gid,
        InstallerDirectoryMode::Deployment,
    )?;
    let authority = open_directory(&deployment, "authority")?;
    require_authority_directory(
        &authority,
        intent.authority_role().uid(),
        intent.authority_role().gid(),
    )?;
    Ok(ProtectedAuthorityRoot {
        directory: authority,
    })
}

fn open_directory(parent: &File, name: &str) -> Result<File, ProtectedAuthorityRootError> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ProtectedAuthorityRootError::Unavailable)
}

fn require_installer_directory(
    file: &File,
    uid: u32,
    gid: u32,
    policy: InstallerDirectoryMode,
) -> Result<(), ProtectedAuthorityRootError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedAuthorityRootError::Unavailable)?;
    let secure_mode = match policy {
        InstallerDirectoryMode::SecureAncestor => metadata.mode() & 0o022 == 0,
        InstallerDirectoryMode::Deployment => metadata.mode() & 0o7777 == 0o755,
    };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || !secure_mode
        || has_extended_acl(file).map_err(|_| ProtectedAuthorityRootError::Unavailable)?
    {
        return Err(ProtectedAuthorityRootError::AncestorPolicy);
    }
    Ok(())
}

fn require_authority_directory(
    file: &File,
    uid: u32,
    gid: u32,
) -> Result<(), ProtectedAuthorityRootError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedAuthorityRootError::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.gid() != gid {
        return Err(ProtectedAuthorityRootError::AuthorityIdentityMismatch);
    }
    if metadata.mode() & 0o7777 != 0o700
        || has_extended_acl(file).map_err(|_| ProtectedAuthorityRootError::Unavailable)?
    {
        return Err(ProtectedAuthorityRootError::AuthorityPolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use serde_json::json;

    use super::*;
    use crate::hvf_owner_commissioning_intent::load_test_hvf_owner_commissioning_intent;

    const INTENT_NAME: &str = "owner-commissioning-intent.json";
    struct Fixture {
        root: tempfile::TempDir,
        installer_uid: u32,
        installer_gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create protected root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("set root mode");
            let metadata = fs::metadata(root.path()).expect("read root metadata");
            let deployment = root.path().join("mvm");
            fs::create_dir(&deployment).expect("create deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
                .expect("set deployment mode");
            Self {
                root,
                installer_uid: metadata.uid(),
                installer_gid: metadata.gid(),
            }
        }

        fn deployment(&self) -> std::path::PathBuf {
            self.root.path().join("mvm")
        }

        fn write_intent(&self, authority_uid: u32, authority_gid: u32) {
            let component = crate::hvf_owner_deployment_receipt::OwnerComponentPinV1 {
                schema_version: 1,
                component: "mvm-hvf-run-owner".into(),
                sha256: "a".repeat(64),
                version: "0.28.0-rc.11".into(),
                target: "aarch64-apple-darwin".into(),
                source_commit: "b".repeat(40),
                bootstrap_protocol_version: 1,
            };
            let digest = crate::hvf_owner_deployment_receipt::cohort_digest(&component);
            let component = serde_json::to_value(component).expect("serialize owner component");
            let runtime_uid = authority_uid.checked_add(1).expect("test uid has room");
            let runtime_gid = authority_gid.checked_add(1).expect("test gid has room");
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
            let path = self.deployment().join(INTENT_NAME);
            fs::write(
                &path,
                serde_json::to_vec(&intent).expect("serialize intent"),
            )
            .expect("write intent");
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("set intent mode");
        }

        fn load_intent(
            &self,
            authority_uid: u32,
            authority_gid: u32,
        ) -> LoadedHvfOwnerCommissioningIntent {
            self.write_intent(authority_uid, authority_gid);
            load_test_hvf_owner_commissioning_intent(
                File::open(self.root.path()).expect("open db root"),
                self.installer_uid,
                self.installer_gid,
            )
            .expect("load intent")
        }

        fn create_authority(&self, mode: u32) {
            let authority = self.deployment().join("authority");
            fs::create_dir(&authority).expect("create authority root");
            fs::set_permissions(authority, fs::Permissions::from_mode(mode))
                .expect("set authority mode");
        }

        fn validate(
            &self,
            intent: &LoadedHvfOwnerCommissioningIntent,
        ) -> Result<ProtectedAuthorityRoot, ProtectedAuthorityRootError> {
            validate_from_db_root(
                intent,
                InstallerRoot::new(
                    File::open(self.root.path()).expect("open db root"),
                    self.installer_uid,
                    self.installer_gid,
                ),
            )
        }

        fn entries(&self) -> Vec<(std::ffi::OsString, u32, u64)> {
            let mut entries: Vec<_> = fs::read_dir(self.deployment())
                .expect("read deployment")
                .map(|entry| {
                    let entry = entry.expect("read entry");
                    let metadata = entry.metadata().expect("read entry metadata");
                    (entry.file_name(), metadata.mode(), metadata.len())
                })
                .collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            entries
        }
    }

    #[test]
    fn validates_exact_private_authority_root_without_side_effects() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        fixture.create_authority(0o700);
        let before = fixture.entries();

        let _root = fixture.validate(&intent).expect("validate authority root");

        assert_eq!(
            fixture.entries(),
            before,
            "validation must not mutate state"
        );
    }

    #[test]
    fn refuses_missing_deployment_or_authority_without_creating_state() {
        let missing_deployment = tempfile::tempdir().expect("create root");
        let metadata = fs::metadata(missing_deployment.path()).expect("read root metadata");
        let before = fs::read_dir(missing_deployment.path())
            .expect("read root")
            .count();
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        assert!(matches!(
            validate_from_db_root(
                &intent,
                InstallerRoot::new(
                    File::open(missing_deployment.path()).expect("open root"),
                    metadata.uid(),
                    metadata.gid(),
                ),
            ),
            Err(ProtectedAuthorityRootError::Unavailable)
        ));
        assert_eq!(
            fs::read_dir(missing_deployment.path())
                .expect("reread root")
                .count(),
            before
        );

        let before = fixture.entries();
        assert!(matches!(
            fixture.validate(&intent),
            Err(ProtectedAuthorityRootError::Unavailable)
        ));
        assert_eq!(fixture.entries(), before);
    }

    #[test]
    fn refuses_authority_alias_and_non_directory() {
        for alias in [true, false] {
            let fixture = Fixture::new();
            let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
            if alias {
                fs::create_dir(fixture.deployment().join("target")).expect("create target");
                symlink("target", fixture.deployment().join("authority"))
                    .expect("create authority alias");
            } else {
                fs::write(fixture.deployment().join("authority"), b"not a directory")
                    .expect("write authority file");
            }
            assert!(matches!(
                fixture.validate(&intent),
                Err(ProtectedAuthorityRootError::Unavailable)
            ));
        }
    }

    #[test]
    fn refuses_wrong_authority_uid_and_gid_independently() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        fixture.create_authority(0o700);
        let authority =
            File::open(fixture.deployment().join("authority")).expect("open authority root");

        assert!(matches!(
            require_authority_directory(
                &authority,
                fixture.installer_uid.checked_add(1).expect("uid has room"),
                fixture.installer_gid,
            ),
            Err(ProtectedAuthorityRootError::AuthorityIdentityMismatch)
        ));
        assert!(matches!(
            require_authority_directory(
                &authority,
                fixture.installer_uid,
                fixture.installer_gid.checked_add(1).expect("gid has room"),
            ),
            Err(ProtectedAuthorityRootError::AuthorityIdentityMismatch)
        ));
        assert!(fixture.validate(&intent).is_ok());
    }

    #[test]
    fn refuses_intent_authority_role_that_does_not_own_root() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(
            fixture.installer_uid.checked_add(1).expect("uid has room"),
            fixture.installer_gid.checked_add(1).expect("gid has room"),
        );
        fixture.create_authority(0o700);

        assert!(matches!(
            fixture.validate(&intent),
            Err(ProtectedAuthorityRootError::AuthorityIdentityMismatch)
        ));
    }

    #[test]
    fn refuses_permissive_and_special_authority_modes() {
        for mode in [0o755, 0o750, 0o710, 0o701, 0o1700, 0o2700, 0o4700] {
            let fixture = Fixture::new();
            let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
            fixture.create_authority(mode);
            assert!(
                matches!(
                    fixture.validate(&intent),
                    Err(ProtectedAuthorityRootError::AuthorityPolicy)
                ),
                "mode {mode:o} must be refused"
            );
        }
    }

    #[test]
    fn refuses_substituted_installer_owner_and_unsafe_ancestry() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        fixture.create_authority(0o700);
        assert!(matches!(
            validate_from_db_root(
                &intent,
                InstallerRoot::new(
                    File::open(fixture.root.path()).expect("open root"),
                    fixture.installer_uid.checked_add(1).expect("uid has room"),
                    fixture.installer_gid,
                ),
            ),
            Err(ProtectedAuthorityRootError::AncestorPolicy)
        ));

        fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o777))
            .expect("weaken root");
        assert!(matches!(
            fixture.validate(&intent),
            Err(ProtectedAuthorityRootError::AncestorPolicy)
        ));
        fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700))
            .expect("restore root");
        fs::set_permissions(fixture.deployment(), fs::Permissions::from_mode(0o750))
            .expect("weaken deployment");
        assert!(matches!(
            fixture.validate(&intent),
            Err(ProtectedAuthorityRootError::AncestorPolicy)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_extended_acl_on_authority_root() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        fixture.create_authority(0o700);
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(fixture.deployment().join("authority"))
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install ACL fixture");

        assert!(matches!(
            fixture.validate(&intent),
            Err(ProtectedAuthorityRootError::AuthorityPolicy)
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_validator_refuses_unsupported_platform() {
        let fixture = Fixture::new();
        let intent = fixture.load_intent(fixture.installer_uid, fixture.installer_gid);
        assert!(matches!(
            validate_protected_authority_root(&intent),
            Err(ProtectedAuthorityRootError::Unsupported)
        ));
    }
}
