//! Create-only pre-key commissioning intent for the protected macOS HVF owner.
//!
//! This module publishes public installation metadata only. It creates no key,
//! receipt, journal, service, IPC endpoint, process, or VM.
//!
//! The v1 conflict set covers the fixed sibling names listed below. It does not
//! claim to discover arbitrary authority state beneath a future role-owned
//! subdirectory. Trusted installer/state mutation must be serialized across
//! preflight and publication; `O_EXCL` linearizes only competing intent writers.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::hvf_owner_deployment_receipt::{
    MAX_DEPLOYMENT_ID_BYTES, OwnerCodeCohortV1, ProtectedRolePinsV1, cohort_digest, strict_label,
    valid_component, valid_role,
};

/// Fixed production intent path. No configuration or environment override exists.
pub const COMMISSIONING_INTENT_PATH: &str = "/private/var/db/mvm/owner-commissioning-intent.json";
/// First and only supported commissioning-intent schema.
pub const COMMISSIONING_INTENT_VERSION: u8 = 1;
/// Maximum encoded commissioning-intent size.
pub const MAX_COMMISSIONING_INTENT_BYTES: usize = 64 * 1024;

const INTENT_NAME: &str = "owner-commissioning-intent.json";
const INTENT_DOMAIN: &[u8] = b"mvm.hvf-owner.commissioning-intent.v1\0";
const CONFLICT_NAMES: &[(&str, CommissioningConflict)] = &[
    (
        "deployment-receipt.json",
        CommissioningConflict::DeploymentReceipt,
    ),
    (
        "owner-commissioning-completion.json",
        CommissioningConflict::Completion,
    ),
    ("authority-ready", CommissioningConflict::AuthorityReady),
    ("owner-grants.json", CommissioningConflict::AuthorityJournal),
    ("owner-grants.lock", CommissioningConflict::AuthorityLock),
];

/// Strict public metadata authorized for one commissioning attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfOwnerCommissioningIntentV1 {
    schema_version: u8,
    deployment_id: String,
    deployment_epoch: u64,
    protected_roles: ProtectedRolePinsV1,
    approved_owner_code_cohort: OwnerCodeCohortV1,
}

/// A preexisting artifact that makes fresh commissioning unsafe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissioningConflict {
    /// The deployment is already commissioned.
    DeploymentReceipt,
    /// A prior commissioning attempt reached completion.
    Completion,
    /// Authority readiness has already been published.
    AuthorityReady,
    /// Authority journal state already exists.
    AuthorityJournal,
    /// Authority journal exclusion state already exists.
    AuthorityLock,
}

/// Durable create-only publication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct PublishedCommissioningIntent {
    digest: [u8; 32],
}

impl PublishedCommissioningIntent {
    /// Domain-separated digest of the exact compact typed v1 bytes published.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Commissioning-intent validation or publication failure.
#[derive(Debug, thiserror::Error)]
pub enum HvfOwnerCommissioningIntentError {
    /// The create-only intent name was already occupied.
    #[error("protected HVF owner commissioning intent already exists")]
    AlreadyExists,
    /// Another artifact proves this is not a fresh commissioning namespace.
    #[error("protected HVF owner commissioning conflicts with existing {0:?}")]
    Conflict(CommissioningConflict),
    /// Protected ancestry or deployment-directory policy failed.
    #[error("protected HVF owner commissioning filesystem policy failed")]
    FilesystemPolicy,
    /// Input was not valid strict v1 JSON.
    #[error("protected HVF owner commissioning intent JSON is invalid")]
    Json(#[source] serde_json::Error),
    /// Input fields were outside the closed v1 semantics.
    #[error("protected HVF owner commissioning intent semantics are invalid")]
    Semantic,
    /// Publication may have created bytes but durability could not be established.
    #[error("protected HVF owner commissioning intent publication outcome is unknown")]
    PublicationUnknown(#[source] io::Error),
    /// No publication occurred because protected state could not be inspected.
    #[error("protected HVF owner commissioning state is unavailable")]
    Io(#[source] io::Error),
}

/// Validate and durably create the fixed production commissioning intent.
///
/// The input is decoded into a closed schema and re-encoded as compact typed
/// JSON before publication. No caller-selected path is accepted.
///
/// # Errors
/// Refuses unsupported hosts, malformed or oversized input, insecure ancestry,
/// any existing commissioning state, and every uncertain durable publication.
#[cfg(target_os = "macos")]
pub fn publish_hvf_owner_commissioning_intent(
    source: &[u8],
) -> Result<PublishedCommissioningIntent, HvfOwnerCommissioningIntentError> {
    let root = File::open("/").map_err(HvfOwnerCommissioningIntentError::Io)?;
    require_directory(&root, 0, 0, DirectoryMode::SecureAncestor)?;
    let private = open_directory(&root, "private")?;
    require_directory(&private, 0, 0, DirectoryMode::SecureAncestor)?;
    let var = open_directory(&private, "var")?;
    require_directory(&var, 0, 0, DirectoryMode::SecureAncestor)?;
    let db = open_directory(&var, "db")?;
    publish_from_db_root(source, ProtectedRoot::new(db, 0, 0), PublishFault::None)
}

/// Unsupported platforms cannot establish the macOS protected-root contract.
///
/// # Errors
/// Always refuses without creating state.
#[cfg(not(target_os = "macos"))]
pub fn publish_hvf_owner_commissioning_intent(
    _source: &[u8],
) -> Result<PublishedCommissioningIntent, HvfOwnerCommissioningIntentError> {
    Err(HvfOwnerCommissioningIntentError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "protected HVF owner commissioning requires macOS",
    )))
}

/// Publish through an injected `/private/var/db` descriptor for hermetic tests.
///
/// # Errors
/// Refuses the same deployment, schema, conflict, and durability failures as
/// the production publisher.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn publish_test_hvf_owner_commissioning_intent(
    source: &[u8],
    root: File,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<PublishedCommissioningIntent, HvfOwnerCommissioningIntentError> {
    publish_from_db_root(
        source,
        ProtectedRoot::new(root, expected_uid, expected_gid),
        PublishFault::None,
    )
}

struct ProtectedRoot {
    directory: File,
    expected_uid: u32,
    expected_gid: u32,
}

impl ProtectedRoot {
    fn new(directory: File, expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            directory,
            expected_uid,
            expected_gid,
        }
    }
}

#[derive(Clone, Copy)]
enum DirectoryMode {
    SecureAncestor,
    Deployment,
}

#[derive(Clone, Copy)]
enum PublishFault {
    None,
    #[cfg(test)]
    AfterCreate,
    #[cfg(test)]
    BeforeDirectorySync,
}

fn publish_from_db_root(
    source: &[u8],
    root: ProtectedRoot,
    fault: PublishFault,
) -> Result<PublishedCommissioningIntent, HvfOwnerCommissioningIntentError> {
    require_directory(
        &root.directory,
        root.expected_uid,
        root.expected_gid,
        DirectoryMode::SecureAncestor,
    )?;
    let deployment = open_directory(&root.directory, "mvm")?;
    require_directory(
        &deployment,
        root.expected_uid,
        root.expected_gid,
        DirectoryMode::Deployment,
    )?;
    preflight(&deployment)?;
    let (encoded, digest) = validate_and_encode(source)?;

    let mut intent = match rustix::fs::openat(
        &deployment,
        INTENT_NAME,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
    ) {
        Ok(file) => File::from(file),
        Err(error) if error == rustix::io::Errno::EXIST => {
            return Err(HvfOwnerCommissioningIntentError::AlreadyExists);
        }
        Err(error) => return Err(HvfOwnerCommissioningIntentError::Io(error.into())),
    };

    let mut publish = || -> io::Result<()> {
        intent.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        let metadata = intent.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != root.expected_uid
            || metadata.gid() != root.expected_gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o644
            || has_extended_acl(&intent)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "created commissioning intent failed filesystem policy",
            ));
        }
        if fault_after_create(fault) {
            return Err(io::Error::other("injected failure after create"));
        }
        intent.write_all(&encoded)?;
        intent.sync_all()?;
        if fault_before_directory_sync(fault) {
            return Err(io::Error::other(
                "injected failure before directory synchronization",
            ));
        }
        deployment.sync_all()
    };
    publish().map_err(HvfOwnerCommissioningIntentError::PublicationUnknown)?;
    Ok(PublishedCommissioningIntent { digest })
}

fn fault_after_create(fault: PublishFault) -> bool {
    #[cfg(test)]
    {
        matches!(fault, PublishFault::AfterCreate)
    }
    #[cfg(not(test))]
    {
        let _ = fault;
        false
    }
}

fn fault_before_directory_sync(fault: PublishFault) -> bool {
    #[cfg(test)]
    {
        matches!(fault, PublishFault::BeforeDirectorySync)
    }
    #[cfg(not(test))]
    {
        let _ = fault;
        false
    }
}

fn validate_and_encode(
    source: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), HvfOwnerCommissioningIntentError> {
    if source.len() > MAX_COMMISSIONING_INTENT_BYTES {
        return Err(HvfOwnerCommissioningIntentError::Semantic);
    }
    let value: serde_json::Value =
        serde_json::from_slice(source).map_err(HvfOwnerCommissioningIntentError::Json)?;
    let root = value
        .as_object()
        .ok_or(HvfOwnerCommissioningIntentError::Semantic)?;
    let roles = require_object(root.get("protected_roles"))?;
    require_object(roles.get("authority"))?;
    require_object(roles.get("runtime"))?;
    let cohort = require_object(root.get("approved_owner_code_cohort"))?;
    require_object(cohort.get("owner_component"))?;

    let intent: HvfOwnerCommissioningIntentV1 =
        serde_json::from_slice(source).map_err(HvfOwnerCommissioningIntentError::Json)?;
    if intent.schema_version != COMMISSIONING_INTENT_VERSION
        || intent.deployment_epoch == 0
        || !strict_label(&intent.deployment_id, MAX_DEPLOYMENT_ID_BYTES)
        || !valid_role(&intent.protected_roles.authority)
        || !valid_role(&intent.protected_roles.runtime)
        || intent.protected_roles.authority.uid == intent.protected_roles.runtime.uid
        || intent.protected_roles.authority.gid == intent.protected_roles.runtime.gid
        || !valid_component(&intent.approved_owner_code_cohort.owner_component)
        || cohort_digest(&intent.approved_owner_code_cohort.owner_component)
            != intent.approved_owner_code_cohort.digest
    {
        return Err(HvfOwnerCommissioningIntentError::Semantic);
    }
    let encoded = serde_json::to_vec(&intent)
        .expect("fixed commissioning intent schema serializes without failure");
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DOMAIN);
    hasher.update(&encoded);
    Ok((encoded, hasher.finalize().into()))
}

fn require_object(
    value: Option<&serde_json::Value>,
) -> Result<&serde_json::Map<String, serde_json::Value>, HvfOwnerCommissioningIntentError> {
    value
        .and_then(serde_json::Value::as_object)
        .ok_or(HvfOwnerCommissioningIntentError::Semantic)
}

fn preflight(deployment: &File) -> Result<(), HvfOwnerCommissioningIntentError> {
    if entry_exists(deployment, INTENT_NAME)? {
        return Err(HvfOwnerCommissioningIntentError::AlreadyExists);
    }
    for &(name, conflict) in CONFLICT_NAMES {
        if entry_exists(deployment, name)? {
            return Err(HvfOwnerCommissioningIntentError::Conflict(conflict));
        }
    }
    Ok(())
}

fn entry_exists(parent: &File, name: &str) -> Result<bool, HvfOwnerCommissioningIntentError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(HvfOwnerCommissioningIntentError::Io(error.into())),
    }
}

fn open_directory(parent: &File, name: &str) -> Result<File, HvfOwnerCommissioningIntentError> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| HvfOwnerCommissioningIntentError::Io(error.into()))
}

fn require_directory(
    file: &File,
    uid: u32,
    gid: u32,
    policy: DirectoryMode,
) -> Result<(), HvfOwnerCommissioningIntentError> {
    let metadata = file
        .metadata()
        .map_err(HvfOwnerCommissioningIntentError::Io)?;
    let secure_mode = match policy {
        DirectoryMode::SecureAncestor => metadata.mode() & 0o022 == 0,
        DirectoryMode::Deployment => metadata.mode() & 0o7777 == 0o755,
    };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || !secure_mode
        || has_extended_acl(file).map_err(HvfOwnerCommissioningIntentError::Io)?
    {
        return Err(HvfOwnerCommissioningIntentError::FilesystemPolicy);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn has_extended_acl(file: &File) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }

    // SAFETY: `file` is a live descriptor. A non-null result is an owned ACL.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(error),
        };
    }
    // SAFETY: `acl` came from `acl_get_fd_np` and is freed exactly once.
    if unsafe { acl_free(acl) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn has_extended_acl(_file: &File) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::hvf_owner_deployment_receipt::{
        OwnerComponentPinV1, ProtectedRolePinV1, cohort_digest,
    };

    fn intent() -> HvfOwnerCommissioningIntentV1 {
        let owner_component = OwnerComponentPinV1 {
            schema_version: 1,
            component: "mvm-hvf-run-owner".into(),
            sha256: "a".repeat(64),
            version: "0.28.0-rc.11".into(),
            target: "aarch64-apple-darwin".into(),
            source_commit: "b".repeat(40),
            bootstrap_protocol_version: 1,
        };
        HvfOwnerCommissioningIntentV1 {
            schema_version: COMMISSIONING_INTENT_VERSION,
            deployment_id: "production-1".into(),
            deployment_epoch: 7,
            protected_roles: ProtectedRolePinsV1 {
                authority: ProtectedRolePinV1 {
                    uid: 501,
                    gid: 501,
                    executable: "/Library/PrivilegedHelperTools/mvm-authority".into(),
                    designated_requirement:
                        "identifier \"dev.mvm.authority\" and anchor apple generic".into(),
                },
                runtime: ProtectedRolePinV1 {
                    uid: 502,
                    gid: 502,
                    executable: "/Library/PrivilegedHelperTools/mvm-hvf-run-owner".into(),
                    designated_requirement: "identifier \"dev.mvm.owner\" and anchor apple generic"
                        .into(),
                },
            },
            approved_owner_code_cohort: OwnerCodeCohortV1 {
                digest: cohort_digest(&owner_component),
                owner_component,
            },
        }
    }

    fn protected_tree() -> (tempfile::TempDir, u32, u32) {
        let root = tempfile::tempdir().expect("create protected root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("set root mode");
        let deployment = root.path().join("mvm");
        fs::create_dir(&deployment).expect("create deployment");
        fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
            .expect("set deployment mode");
        let metadata = fs::metadata(root.path()).expect("root metadata");
        (root, metadata.uid(), metadata.gid())
    }

    fn publish(
        root: &tempfile::TempDir,
        uid: u32,
        gid: u32,
        source: &[u8],
        fault: PublishFault,
    ) -> Result<PublishedCommissioningIntent, HvfOwnerCommissioningIntentError> {
        publish_from_db_root(
            source,
            ProtectedRoot::new(File::open(root.path()).expect("open root"), uid, gid),
            fault,
        )
    }

    fn bytes() -> Vec<u8> {
        serde_json::to_vec(&intent()).expect("serialize intent")
    }

    fn entries(root: &tempfile::TempDir) -> Vec<std::ffi::OsString> {
        let mut entries: Vec<_> = fs::read_dir(root.path().join("mvm"))
            .expect("read deployment")
            .map(|entry| entry.expect("read entry").file_name())
            .collect();
        entries.sort();
        entries
    }

    #[test]
    fn happy_path_publishes_exact_typed_bytes_and_stable_digest() {
        let (root, uid, gid) = protected_tree();
        let source = serde_json::to_vec_pretty(&intent()).expect("serialize pretty intent");

        let published = publish(&root, uid, gid, &source, PublishFault::None)
            .expect("publish commissioning intent");
        let path = root.path().join("mvm").join(INTENT_NAME);
        let exact = fs::read(&path).expect("read published intent");
        assert_eq!(exact, bytes(), "publisher emits compact typed v1 bytes");
        let mut hasher = Sha256::new();
        hasher.update(INTENT_DOMAIN);
        hasher.update(&exact);
        assert_eq!(published.digest(), <[u8; 32]>::from(hasher.finalize()));
        assert_eq!(
            fs::metadata(path).expect("intent metadata").mode() & 0o7777,
            0o644
        );
    }

    #[test]
    fn concurrent_create_has_one_winner_and_one_already_exists() {
        let (root, uid, gid) = protected_tree();
        let root = Arc::new(root);
        let barrier = Arc::new(Barrier::new(3));
        let source = Arc::new(bytes());
        let mut workers = Vec::new();
        for _ in 0..2 {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            let source = Arc::clone(&source);
            workers.push(thread::spawn(move || {
                barrier.wait();
                publish(&root, uid, gid, &source, PublishFault::None)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("publisher thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(HvfOwnerCommissioningIntentError::AlreadyExists)
                ))
                .count(),
            1
        );
        assert_eq!(
            fs::read(root.path().join("mvm").join(INTENT_NAME)).unwrap(),
            bytes()
        );
    }

    #[test]
    fn every_existing_state_refuses_without_modification() {
        for &(name, expected) in CONFLICT_NAMES {
            let (root, uid, gid) = protected_tree();
            let path = root.path().join("mvm").join(name);
            fs::write(&path, b"preserve").expect("write conflict");
            let before = entries(&root);
            assert!(matches!(
                publish(&root, uid, gid, &bytes(), PublishFault::None),
                Err(HvfOwnerCommissioningIntentError::Conflict(actual)) if actual == expected
            ));
            assert_eq!(entries(&root), before);
            assert_eq!(fs::read(path).unwrap(), b"preserve");
            assert!(!root.path().join("mvm").join(INTENT_NAME).exists());
        }

        let (root, uid, gid) = protected_tree();
        let path = root.path().join("mvm").join(INTENT_NAME);
        fs::write(&path, b"preserve").unwrap();
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::AlreadyExists)
        ));
        assert_eq!(fs::read(path).unwrap(), b"preserve");
    }

    #[test]
    fn filesystem_policy_and_aliases_refuse_without_side_effects() {
        let missing_parent = tempfile::tempdir().unwrap();
        fs::set_permissions(missing_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(missing_parent.path()).unwrap();
        assert!(
            publish(
                &missing_parent,
                metadata.uid(),
                metadata.gid(),
                &bytes(),
                PublishFault::None
            )
            .is_err()
        );
        assert!(
            fs::read_dir(missing_parent.path())
                .unwrap()
                .next()
                .is_none(),
            "publisher must not create the deployment parent"
        );

        let (root, uid, gid) = protected_tree();
        assert!(matches!(
            publish(
                &root,
                uid.checked_add(1).expect("test uid has room"),
                gid,
                &bytes(),
                PublishFault::None
            ),
            Err(HvfOwnerCommissioningIntentError::FilesystemPolicy)
        ));
        assert!(matches!(
            publish(
                &root,
                uid,
                gid.checked_add(1).expect("test gid has room"),
                &bytes(),
                PublishFault::None
            ),
            Err(HvfOwnerCommissioningIntentError::FilesystemPolicy)
        ));
        assert!(entries(&root).is_empty());

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::FilesystemPolicy)
        ));
        assert!(entries(&root).is_empty());

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.path().join("mvm"), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::FilesystemPolicy)
        ));
        assert!(entries(&root).is_empty());

        fs::set_permissions(root.path().join("mvm"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("missing-target", root.path().join("mvm").join(INTENT_NAME)).unwrap();
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::AlreadyExists)
        ));

        let aliased_root = tempfile::tempdir().unwrap();
        fs::set_permissions(aliased_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(aliased_root.path().join("target")).unwrap();
        symlink("target", aliased_root.path().join("mvm")).unwrap();
        let metadata = fs::metadata(aliased_root.path()).unwrap();
        assert!(
            publish(
                &aliased_root,
                metadata.uid(),
                metadata.gid(),
                &bytes(),
                PublishFault::None
            )
            .is_err()
        );
        assert!(
            fs::read_dir(aliased_root.path().join("target"))
                .unwrap()
                .next()
                .is_none()
        );

        let (root, uid, gid) = protected_tree();
        symlink(
            "missing-receipt",
            root.path().join("mvm").join("deployment-receipt.json"),
        )
        .unwrap();
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::Conflict(
                CommissioningConflict::DeploymentReceipt
            ))
        ));
        assert!(!root.path().join("mvm").join(INTENT_NAME).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extended_acl_on_deployment_is_refused_before_create() {
        use std::process::Command;

        let (root, uid, gid) = protected_tree();
        let status = Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(root.path().join("mvm"))
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install the ACL fixture");
        assert!(matches!(
            publish(&root, uid, gid, &bytes(), PublishFault::None),
            Err(HvfOwnerCommissioningIntentError::FilesystemPolicy)
        ));
        assert!(entries(&root).is_empty());
    }

    #[test]
    fn schema_is_object_only_strict_and_bounded() {
        let baseline = serde_json::to_value(intent()).expect("serialize intent");
        let mutations: &[&dyn Fn(&mut serde_json::Value)] = &[
            &|value| value["unknown"] = serde_json::json!(true),
            &|value| value["schema_version"] = serde_json::json!(2),
            &|value| value["deployment_epoch"] = serde_json::json!(0),
            &|value| value["protected_roles"]["authority"]["uid"] = serde_json::json!(0),
            &|value| {
                value["protected_roles"]["runtime"]["uid"] =
                    value["protected_roles"]["authority"]["uid"].clone()
            },
            &|value| {
                value["protected_roles"]["runtime"]["gid"] =
                    value["protected_roles"]["authority"]["gid"].clone()
            },
            &|value| value["approved_owner_code_cohort"]["digest"][0] = serde_json::json!(99),
            &|value| {
                value["approved_owner_code_cohort"]["owner_component"]["unknown"] =
                    serde_json::json!(true)
            },
        ];
        for mutate in mutations {
            let (root, uid, gid) = protected_tree();
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert!(
                publish(
                    &root,
                    uid,
                    gid,
                    &serde_json::to_vec(&changed).unwrap(),
                    PublishFault::None
                )
                .is_err(),
                "invalid schema published: {changed}"
            );
            assert!(entries(&root).is_empty());
        }

        for invalid in [
            serde_json::to_vec(&serde_json::json!([])).unwrap(),
            serde_json::to_vec(&serde_json::json!({"protected_roles": []})).unwrap(),
            b"{".to_vec(),
            vec![b'x'; MAX_COMMISSIONING_INTENT_BYTES + 1],
        ] {
            let (root, uid, gid) = protected_tree();
            assert!(publish(&root, uid, gid, &invalid, PublishFault::None).is_err());
            assert!(entries(&root).is_empty());
        }

        let baseline = serde_json::to_string(&baseline).unwrap();
        let duplicate = baseline.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        let (root, uid, gid) = protected_tree();
        assert!(publish(&root, uid, gid, duplicate.as_bytes(), PublishFault::None).is_err());
        assert!(entries(&root).is_empty());
    }

    #[test]
    fn post_create_faults_are_unknown_and_never_retried_or_overwritten() {
        for fault in [PublishFault::AfterCreate, PublishFault::BeforeDirectorySync] {
            let (root, uid, gid) = protected_tree();
            assert!(matches!(
                publish(&root, uid, gid, &bytes(), fault),
                Err(HvfOwnerCommissioningIntentError::PublicationUnknown(_))
            ));
            let path = root.path().join("mvm").join(INTENT_NAME);
            assert!(
                path.exists(),
                "created object remains as ambiguous evidence"
            );
            let retained = fs::read(&path).unwrap();
            assert!(matches!(
                publish(&root, uid, gid, &bytes(), PublishFault::None),
                Err(HvfOwnerCommissioningIntentError::AlreadyExists)
            ));
            assert_eq!(fs::read(path).unwrap(), retained);
        }
    }
}
