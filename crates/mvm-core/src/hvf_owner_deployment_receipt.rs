//! Read-only commissioning receipt for the protected macOS cold-HVF owner.
//!
//! Loading proves only that immutable pins came from the protected filesystem
//! object described here. It does not evaluate a designated requirement,
//! authenticate a peer, initialize state, or authorize an owner factory.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use ed25519_dalek::VerifyingKey;
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::crypto::hvf_owner_grant::provider_identity;

/// Fixed production receipt path. No configuration or environment override exists.
pub const DEPLOYMENT_RECEIPT_PATH: &str = "/private/var/db/mvm/deployment-receipt.json";
/// First and only supported receipt schema.
pub const DEPLOYMENT_RECEIPT_VERSION: u8 = 1;
/// Maximum receipt bytes accepted from the protected descriptor.
pub const MAX_DEPLOYMENT_RECEIPT_BYTES: u64 = 64 * 1024;

const RECEIPT_NAME: &str = "deployment-receipt.json";
const COHORT_DOMAIN: &[u8] = b"mvm.hvf-owner.code-cohort.v1\0";
const OWNER_COMPONENT: &str = "mvm-hvf-run-owner";
const OWNER_BOOTSTRAP_PROTOCOL_VERSION: u8 = 1;
const MAX_DEPLOYMENT_ID_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 256;
const MAX_EXECUTABLE_BYTES: usize = 1024;
const MAX_REQUIREMENT_BYTES: usize = 4096;
const MAX_COMPONENT_STRING_BYTES: usize = 128;

/// Exact strict v1 JSON schema stored by the trusted installer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfOwnerDeploymentReceiptV1 {
    schema_version: u8,
    deployment_id: String,
    deployment_epoch: u64,
    provider: ProviderPinV1,
    control_roots: ControlRootPinsV1,
    protected_roles: ProtectedRolePinsV1,
    approved_owner_code_cohort: OwnerCodeCohortV1,
}

/// Provider grant issuer pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPinV1 {
    issuer: String,
    ed25519_public_key: [u8; 32],
}

/// Separate native-supervisor and provider-stop verification roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRootPinsV1 {
    native_challenge_and_finalization_ed25519: [u8; 32],
    provider_stop_ed25519: [u8; 32],
}

/// Protected authority and original-child runtime identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRolePinsV1 {
    authority: ProtectedRolePinV1,
    runtime: ProtectedRolePinV1,
}

/// One protected process identity and its immutable requirement source pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRolePinV1 {
    uid: u32,
    gid: u32,
    executable: String,
    designated_requirement: String,
}

/// Domain-separated approval of the packaged owner component record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCodeCohortV1 {
    digest: [u8; 32],
    owner_component: OwnerComponentPinV1,
}

/// Exact fields emitted by `owner-component.json` after final signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerComponentPinV1 {
    schema_version: u8,
    component: String,
    sha256: String,
    version: String,
    target: String,
    source_commit: String,
    bootstrap_protocol_version: u8,
}

/// Validated immutable receipt loaded from a protected descriptor walk.
#[derive(Debug)]
pub struct LoadedHvfOwnerDeploymentReceipt {
    receipt: HvfOwnerDeploymentReceiptV1,
    provider_key: VerifyingKey,
    native_control_root: VerifyingKey,
    provider_stop_root: VerifyingKey,
    provider_id: [u8; 32],
}

impl LoadedHvfOwnerDeploymentReceipt {
    /// Stable deployment label selected by commissioning.
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.receipt.deployment_id
    }

    /// Monotonic commissioning generation used by provider grants.
    #[must_use]
    pub fn provider_epoch(&self) -> u64 {
        self.receipt.deployment_epoch
    }

    /// Provider issuer label.
    #[must_use]
    pub fn provider_issuer(&self) -> &str {
        &self.receipt.provider.issuer
    }

    /// Provider grant verification key.
    #[must_use]
    pub fn provider_key(&self) -> &VerifyingKey {
        &self.provider_key
    }

    /// Stable provider journal namespace derived from issuer, key, and epoch.
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    /// Native challenge/finalization verification root.
    #[must_use]
    pub fn native_control_root(&self) -> &VerifyingKey {
        &self.native_control_root
    }

    /// Provider stop-request verification root.
    #[must_use]
    pub fn provider_stop_root(&self) -> &VerifyingKey {
        &self.provider_stop_root
    }

    /// Protected authority role pin.
    #[must_use]
    pub fn authority_role(&self) -> &ProtectedRolePinV1 {
        &self.receipt.protected_roles.authority
    }

    /// Protected runtime role pin.
    #[must_use]
    pub fn runtime_role(&self) -> &ProtectedRolePinV1 {
        &self.receipt.protected_roles.runtime
    }

    /// Approved final owner component record.
    #[must_use]
    pub fn owner_component(&self) -> &OwnerComponentPinV1 {
        &self.receipt.approved_owner_code_cohort.owner_component
    }
}

impl ProtectedRolePinV1 {
    /// Expected effective user ID.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Expected effective group ID.
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Absolute executable path pin.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Exact designated-requirement source retained by commissioning.
    ///
    /// This string is an immutable bounded pin. Returning it does not claim
    /// that this module evaluated it against a peer.
    #[must_use]
    pub fn designated_requirement(&self) -> &str {
        &self.designated_requirement
    }
}

impl OwnerComponentPinV1 {
    /// Final packaged owner SHA-256 in lowercase hexadecimal.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Package version pin.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Rust target triple pin.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Exact lowercase Git source revision.
    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
}

/// Receipt loading or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum HvfOwnerDeploymentReceiptError {
    #[error("protected HVF owner deployment receipt is unavailable")]
    Io(#[source] io::Error),
    #[error("protected HVF owner deployment receipt filesystem policy failed")]
    FilesystemPolicy,
    #[error("protected HVF owner deployment receipt exceeds 64 KiB")]
    TooLarge,
    #[error("protected HVF owner deployment receipt JSON is invalid")]
    Json(#[source] serde_json::Error),
    #[error("protected HVF owner deployment receipt semantics are invalid")]
    Semantic,
}

impl From<io::Error> for HvfOwnerDeploymentReceiptError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Load the fixed production receipt through canonical no-follow descriptors.
///
/// # Errors
/// Refuses non-macOS hosts and any missing, aliased, insecure, oversized,
/// malformed, or semantically invalid receipt or ancestor.
#[cfg(target_os = "macos")]
pub fn load_hvf_owner_deployment_receipt()
-> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
    let root = File::open("/")?;
    require_directory(&root, 0, 0, DirectoryMode::SecureAncestor)?;
    let private = open_directory(&root, "private")?;
    require_directory(&private, 0, 0, DirectoryMode::SecureAncestor)?;
    let var = open_directory(&private, "var")?;
    require_directory(&var, 0, 0, DirectoryMode::SecureAncestor)?;
    let db = open_directory(&var, "db")?;
    require_directory(&db, 0, 0, DirectoryMode::SecureAncestor)?;
    load_from_db_root(ProtectedRoot {
        directory: db,
        expected_uid: 0,
        expected_gid: 0,
    })
}

/// Unsupported platforms cannot establish the macOS protected-root contract.
///
/// # Errors
/// Always refuses.
#[cfg(not(target_os = "macos"))]
pub fn load_hvf_owner_deployment_receipt()
-> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
    Err(HvfOwnerDeploymentReceiptError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "protected HVF owner receipt loading requires macOS",
    )))
}

/// Load from an injected descriptor-relative protected root for hermetic tests.
///
/// This capability is absent from production builds. `root` represents the
/// canonical `/private/var/db` descriptor; all remaining opens are relative to
/// it and no directories or files are created.
///
/// # Errors
/// Refuses the same deployment-directory, receipt-object, and schema failures
/// as the production loader.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn load_test_hvf_owner_deployment_receipt(
    root: File,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
    load_from_db_root(ProtectedRoot {
        directory: root,
        expected_uid,
        expected_gid,
    })
}

struct ProtectedRoot {
    directory: File,
    expected_uid: u32,
    expected_gid: u32,
}

enum DirectoryMode {
    SecureAncestor,
    Deployment,
}

fn load_from_db_root(
    root: ProtectedRoot,
) -> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
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
    let receipt = open_regular(&deployment, RECEIPT_NAME)?;
    require_receipt_file(&receipt, root.expected_uid, root.expected_gid)?;
    let metadata = receipt.metadata()?;
    if metadata.len() > MAX_DEPLOYMENT_RECEIPT_BYTES {
        return Err(HvfOwnerDeploymentReceiptError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    receipt
        .take(MAX_DEPLOYMENT_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DEPLOYMENT_RECEIPT_BYTES {
        return Err(HvfOwnerDeploymentReceiptError::TooLarge);
    }
    require_object_shape(&bytes)?;
    let receipt: HvfOwnerDeploymentReceiptV1 =
        serde_json::from_slice(&bytes).map_err(HvfOwnerDeploymentReceiptError::Json)?;
    validate(receipt)
}

fn require_object_shape(bytes: &[u8]) -> Result<(), HvfOwnerDeploymentReceiptError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(HvfOwnerDeploymentReceiptError::Json)?;
    let root = value
        .as_object()
        .ok_or(HvfOwnerDeploymentReceiptError::Semantic)?;
    require_object(root.get("provider"))?;
    require_object(root.get("control_roots"))?;
    let roles = require_object(root.get("protected_roles"))?;
    require_object(roles.get("authority"))?;
    require_object(roles.get("runtime"))?;
    let cohort = require_object(root.get("approved_owner_code_cohort"))?;
    require_object(cohort.get("owner_component"))?;
    Ok(())
}

fn require_object(
    value: Option<&serde_json::Value>,
) -> Result<&serde_json::Map<String, serde_json::Value>, HvfOwnerDeploymentReceiptError> {
    value
        .and_then(serde_json::Value::as_object)
        .ok_or(HvfOwnerDeploymentReceiptError::Semantic)
}

fn validate(
    receipt: HvfOwnerDeploymentReceiptV1,
) -> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
    if receipt.schema_version != DEPLOYMENT_RECEIPT_VERSION
        || receipt.deployment_epoch == 0
        || !strict_label(&receipt.deployment_id, MAX_DEPLOYMENT_ID_BYTES)
        || !strict_label(&receipt.provider.issuer, MAX_ISSUER_BYTES)
        || !valid_role(&receipt.protected_roles.authority)
        || !valid_role(&receipt.protected_roles.runtime)
        || receipt.protected_roles.authority.uid == receipt.protected_roles.runtime.uid
        || receipt.protected_roles.authority.gid == receipt.protected_roles.runtime.gid
        || !valid_component(&receipt.approved_owner_code_cohort.owner_component)
        || cohort_digest(&receipt.approved_owner_code_cohort.owner_component)
            != receipt.approved_owner_code_cohort.digest
    {
        return Err(HvfOwnerDeploymentReceiptError::Semantic);
    }

    let provider_key = verifying_key(receipt.provider.ed25519_public_key)?;
    let native_control_root = verifying_key(
        receipt
            .control_roots
            .native_challenge_and_finalization_ed25519,
    )?;
    let provider_stop_root = verifying_key(receipt.control_roots.provider_stop_ed25519)?;
    if native_control_root == provider_stop_root {
        return Err(HvfOwnerDeploymentReceiptError::Semantic);
    }
    let provider_id = provider_identity(
        &receipt.provider.issuer,
        &provider_key,
        receipt.deployment_epoch,
    );
    Ok(LoadedHvfOwnerDeploymentReceipt {
        receipt,
        provider_key,
        native_control_root,
        provider_stop_root,
        provider_id,
    })
}

fn verifying_key(bytes: [u8; 32]) -> Result<VerifyingKey, HvfOwnerDeploymentReceiptError> {
    if bytes == [0; 32] {
        return Err(HvfOwnerDeploymentReceiptError::Semantic);
    }
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| HvfOwnerDeploymentReceiptError::Semantic)?;
    if key.is_weak() {
        return Err(HvfOwnerDeploymentReceiptError::Semantic);
    }
    Ok(key)
}

fn valid_role(role: &ProtectedRolePinV1) -> bool {
    role.uid != 0
        && role.gid != 0
        && valid_absolute_path(&role.executable)
        && strict_source(&role.designated_requirement, MAX_REQUIREMENT_BYTES)
}

fn valid_absolute_path(value: &str) -> bool {
    if !strict_source(value, MAX_EXECUTABLE_BYTES) {
        return false;
    }
    let path = Path::new(value);
    path != Path::new("/")
        && path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_component(component: &OwnerComponentPinV1) -> bool {
    component.schema_version == 1
        && component.component == OWNER_COMPONENT
        && component.bootstrap_protocol_version == OWNER_BOOTSTRAP_PROTOCOL_VERSION
        && lowercase_hex(&component.sha256, 64)
        && strict_label(&component.version, MAX_COMPONENT_STRING_BYTES)
        && target_triple(&component.target)
        && lowercase_hex(&component.source_commit, 40)
}

fn strict_label(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn strict_source(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && !value.starts_with(' ')
        && !value.ends_with(' ')
}

fn target_triple(value: &str) -> bool {
    strict_label(value, MAX_COMPONENT_STRING_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.contains('-')
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn cohort_digest(component: &OwnerComponentPinV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COHORT_DOMAIN);
    // Serialization of this fully typed fixed-order v1 record is infallible.
    hasher.update(serde_json::to_vec(component).expect("owner component schema serializes"));
    hasher.finalize().into()
}

fn open_directory(parent: &File, name: &str) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn open_regular(parent: &File, name: &str) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn require_directory(
    file: &File,
    uid: u32,
    gid: u32,
    mode_policy: DirectoryMode,
) -> Result<(), HvfOwnerDeploymentReceiptError> {
    let metadata = file.metadata()?;
    let mode = metadata.mode();
    let secure_mode = match mode_policy {
        DirectoryMode::SecureAncestor => mode & 0o022 == 0,
        DirectoryMode::Deployment => mode & 0o7777 == 0o755,
    };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || !secure_mode
        || has_extended_acl(file)?
    {
        return Err(HvfOwnerDeploymentReceiptError::FilesystemPolicy);
    }
    Ok(())
}

fn require_receipt_file(
    file: &File,
    uid: u32,
    gid: u32,
) -> Result<(), HvfOwnerDeploymentReceiptError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o644
        || has_extended_acl(file)?
    {
        return Err(HvfOwnerDeploymentReceiptError::FilesystemPolicy);
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
    // Strict v1 rejects every extended ACL, including deny-only entries.
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
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn component() -> OwnerComponentPinV1 {
        OwnerComponentPinV1 {
            schema_version: 1,
            component: OWNER_COMPONENT.into(),
            sha256: "a".repeat(64),
            version: "0.28.0-rc.11".into(),
            target: "aarch64-apple-darwin".into(),
            source_commit: "b".repeat(40),
            bootstrap_protocol_version: OWNER_BOOTSTRAP_PROTOCOL_VERSION,
        }
    }

    fn receipt() -> HvfOwnerDeploymentReceiptV1 {
        let owner_component = component();
        HvfOwnerDeploymentReceiptV1 {
            schema_version: DEPLOYMENT_RECEIPT_VERSION,
            deployment_id: "production-1".into(),
            deployment_epoch: 7,
            provider: ProviderPinV1 {
                issuer: "mvm-owner-production".into(),
                ed25519_public_key: key(1),
            },
            control_roots: ControlRootPinsV1 {
                native_challenge_and_finalization_ed25519: key(2),
                provider_stop_ed25519: key(3),
            },
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

    fn protected_tree(bytes: &[u8]) -> (tempfile::TempDir, File, u32, u32) {
        let root = tempfile::tempdir().expect("create protected root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("set root mode");
        let deployment = root.path().join("mvm");
        fs::create_dir(&deployment).expect("create deployment directory");
        fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
            .expect("set deployment mode");
        fs::write(deployment.join(RECEIPT_NAME), bytes).expect("write receipt");
        fs::set_permissions(
            deployment.join(RECEIPT_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .expect("set receipt mode");
        let metadata = fs::metadata(root.path()).expect("root metadata");
        let file = File::open(root.path()).expect("open protected root");
        (root, file, metadata.uid(), metadata.gid())
    }

    fn load_fixture(
        bytes: &[u8],
    ) -> Result<LoadedHvfOwnerDeploymentReceipt, HvfOwnerDeploymentReceiptError> {
        let (_temporary, directory, uid, gid) = protected_tree(bytes);
        load_from_db_root(ProtectedRoot {
            directory,
            expected_uid: uid,
            expected_gid: gid,
        })
    }

    #[test]
    fn valid_protected_receipt_loads_and_derives_provider_identity() {
        let expected = receipt();
        let bytes = serde_json::to_vec(&expected).expect("serialize receipt");
        let loaded = load_fixture(&bytes).expect("load protected receipt");
        let provider_key = VerifyingKey::from_bytes(&key(1)).expect("provider key");
        assert_eq!(loaded.deployment_id(), "production-1");
        assert_eq!(loaded.provider_epoch(), 7);
        assert_eq!(
            loaded.provider_id(),
            provider_identity("mvm-owner-production", &provider_key, 7)
        );
        assert_eq!(loaded.native_control_root().to_bytes(), key(2));
        assert_eq!(loaded.provider_stop_root().to_bytes(), key(3));
        assert_eq!(
            loaded.runtime_role().designated_requirement(),
            "identifier \"dev.mvm.owner\" and anchor apple generic"
        );
    }

    #[test]
    fn schema_and_semantic_tampering_refuse() {
        let baseline = serde_json::to_value(receipt()).expect("serialize receipt");
        let mutations: &[&dyn Fn(&mut serde_json::Value)] = &[
            &|value| value["unknown"] = serde_json::json!(true),
            &|value| value["schema_version"] = serde_json::json!(2),
            &|value| value["deployment_epoch"] = serde_json::json!(0),
            &|value| value["provider"]["unknown"] = serde_json::json!("field"),
            &|value| value["provider"]["ed25519_public_key"] = serde_json::json!(vec![0; 32]),
            &|value| {
                let mut weak = vec![0; 32];
                weak[0] = 1;
                value["provider"]["ed25519_public_key"] = serde_json::json!(weak)
            },
            &|value| {
                let mut weak = vec![0; 32];
                weak[0] = 1;
                value["control_roots"]["native_challenge_and_finalization_ed25519"] =
                    serde_json::json!(weak)
            },
            &|value| {
                let mut weak = vec![0; 32];
                weak[0] = 1;
                value["control_roots"]["provider_stop_ed25519"] = serde_json::json!(weak)
            },
            &|value| {
                value["control_roots"]["provider_stop_ed25519"] =
                    value["control_roots"]["native_challenge_and_finalization_ed25519"].clone()
            },
            &|value| value["protected_roles"]["authority"]["uid"] = serde_json::json!(0),
            &|value| {
                value["protected_roles"]["runtime"]["uid"] =
                    value["protected_roles"]["authority"]["uid"].clone()
            },
            &|value| {
                value["protected_roles"]["runtime"]["gid"] =
                    value["protected_roles"]["authority"]["gid"].clone()
            },
            &|value| {
                value["protected_roles"]["runtime"]["executable"] =
                    serde_json::json!("../mvm-hvf-run-owner")
            },
            &|value| {
                value["protected_roles"]["runtime"]["designated_requirement"] =
                    serde_json::json!(" changed")
            },
            &|value| {
                value["approved_owner_code_cohort"]["owner_component"]["component"] =
                    serde_json::json!("another-owner")
            },
            &|value| {
                value["approved_owner_code_cohort"]["owner_component"]["bootstrap_protocol_version"] =
                    serde_json::json!(2)
            },
            &|value| {
                value["approved_owner_code_cohort"]["owner_component"]["target"] =
                    serde_json::json!("AARCH64")
            },
            &|value| {
                value["approved_owner_code_cohort"]["owner_component"]["source_commit"] =
                    serde_json::json!("ABC")
            },
            &|value| value["approved_owner_code_cohort"]["digest"][0] = serde_json::json!(99),
        ];
        for mutate in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            let bytes = serde_json::to_vec(&changed).expect("serialize tampered receipt");
            assert!(
                load_fixture(&bytes).is_err(),
                "tampered receipt unexpectedly loaded: {changed}"
            );
        }
    }

    #[test]
    fn receipt_records_require_object_json_and_strict_fields() {
        let value = serde_json::to_value(receipt()).expect("serialize receipt");
        let top_level_array = serde_json::json!([
            value["schema_version"],
            value["deployment_id"],
            value["deployment_epoch"],
            value["provider"],
            value["control_roots"],
            value["protected_roles"],
            value["approved_owner_code_cohort"]
        ]);
        assert!(load_fixture(&serde_json::to_vec(&top_level_array).unwrap()).is_err());

        let mut nested_array = value.clone();
        nested_array["provider"] = serde_json::json!([
            value["provider"]["issuer"],
            value["provider"]["ed25519_public_key"]
        ]);
        assert!(load_fixture(&serde_json::to_vec(&nested_array).unwrap()).is_err());

        let baseline = serde_json::to_string(&value).unwrap();
        let duplicate = baseline.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(load_fixture(duplicate.as_bytes()).is_err());
        assert!(load_fixture(format!("{baseline} trailing").as_bytes()).is_err());
        assert!(load_fixture(&baseline.as_bytes()[..baseline.len() / 2]).is_err());
    }

    #[test]
    fn filesystem_object_and_ancestor_policy_refuse_without_side_effects() {
        let bytes = serde_json::to_vec(&receipt()).expect("serialize receipt");
        let (root, directory, uid, gid) = protected_tree(&bytes);
        let before: Vec<_> = fs::read_dir(root.path())
            .expect("list before")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777))
            .expect("weaken ancestor");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory,
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
        let after: Vec<_> = fs::read_dir(root.path())
            .expect("list after")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect();
        assert_eq!(before, after, "loader must not create or repair state");

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("restore ancestor");
        fs::set_permissions(root.path().join("mvm"), fs::Permissions::from_mode(0o750))
            .expect("change deployment mode");
        let directory = File::open(root.path()).expect("reopen protected root");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory,
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
    }

    #[test]
    fn symlink_hardlink_nonregular_mode_and_oversize_refuse() {
        let bytes = serde_json::to_vec(&receipt()).expect("serialize receipt");
        let (root, _, uid, gid) = protected_tree(&bytes);
        let deployment = root.path().join("mvm");
        let receipt_path = deployment.join(RECEIPT_NAME);

        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
            .expect("change receipt mode");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );

        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644))
            .expect("restore receipt mode");
        fs::hard_link(&receipt_path, deployment.join("receipt-link")).expect("hard link receipt");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
        fs::remove_file(deployment.join("receipt-link")).expect("remove hard link");

        fs::remove_file(&receipt_path).expect("remove receipt");
        fs::create_dir(&receipt_path).expect("replace receipt with directory");
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644))
            .expect("set directory mode");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
        fs::remove_dir(&receipt_path).expect("remove directory");

        fs::write(
            &receipt_path,
            vec![b'x'; MAX_DEPLOYMENT_RECEIPT_BYTES as usize + 1],
        )
        .expect("write oversized receipt");
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644))
            .expect("set oversized receipt mode");
        assert!(matches!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            }),
            Err(HvfOwnerDeploymentReceiptError::TooLarge)
        ));

        fs::remove_file(&receipt_path).expect("remove oversized receipt");
        fs::write(deployment.join("target"), bytes).expect("write symlink target");
        symlink("target", &receipt_path).expect("create receipt symlink");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extended_acl_is_strictly_refused_when_acl_tool_is_available() {
        use std::process::Command;

        let bytes = serde_json::to_vec(&receipt()).expect("serialize receipt");
        let (root, _, uid, gid) = protected_tree(&bytes);
        let receipt_path = root.path().join("mvm").join(RECEIPT_NAME);
        let status = Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&receipt_path)
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install the ACL fixture");
        assert!(
            load_from_db_root(ProtectedRoot {
                directory: File::open(root.path()).expect("open root"),
                expected_uid: uid,
                expected_gid: gid,
            })
            .is_err()
        );
    }
}
