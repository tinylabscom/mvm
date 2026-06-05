//! Volume wire types — shared between mvm and mvmd.
//!
//! See [`specs/plans/45-filesystem-volumes.md`] for the design.
//! All types here are pure data; behaviour (the `VolumeBackend` trait and
//! its impls) lives in the `mvm-storage` crate.
//!
//! ## Identity
//!
//! A volume is uniquely identified by `(org_id, workspace_id, name)`.
//! Names are unique per workspace, can collide across workspaces, and
//! receive distinct AEAD keys via HKDF-derived per-volume keys (see
//! the encryption section of plan 45).
//!
//! ## Backends
//!
//! [`VolumeBackendConfig`] is the declarative shape of a backend. The
//! mvm-storage crate ships `LocalBackend` only; mvmd ships
//! `ObjectStoreBackend` (wrapping `opendal`) and `EncryptedBackend<B>`
//! per Path C of plan 45.

use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Identifiers
// ============================================================================

const MAX_ID_LEN: usize = 63;
const MAX_VOLUME_NAME_LEN: usize = 63;
const MAX_VOLUME_PATH_LEN: usize = 1024;

fn validate_slug(value: &str, kind: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ID_LEN {
        bail!(
            "{kind} must be 1-{MAX_ID_LEN} characters, got {}",
            value.len()
        );
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("{kind} must be lowercase alphanumeric + hyphens: {value:?}");
    }
    if value.starts_with('-') || value.ends_with('-') {
        bail!("{kind} must not start or end with a hyphen: {value:?}");
    }
    Ok(())
}

/// Organization identifier — top-level billing/auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgId(String);

impl OrgId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_slug(&value, "OrgId")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Workspace identifier — project/isolation boundary within an org.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_slug(&value, "WorkspaceId")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Volume name — unique within a workspace.
///
/// Allowed characters: lowercase alphanumeric, hyphens, underscores.
/// Must not start with `.`, `_`, or `-`. Reserved names (registry, tmp,
/// snapshots) are rejected so the on-disk layout stays unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VolumeName(String);

const RESERVED_VOLUME_NAMES: &[&str] = &["registry", "tmp", "snapshots", "trash", ".", ".."];

impl VolumeName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_VOLUME_NAME_LEN {
            bail!(
                "volume name must be 1-{MAX_VOLUME_NAME_LEN} characters, got {}",
                value.len()
            );
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            bail!("volume name must be lowercase alphanumeric + hyphens/underscores: {value:?}");
        }
        if value.starts_with('-') || value.starts_with('_') || value.starts_with('.') {
            bail!("volume name must not start with '-', '_', or '.': {value:?}");
        }
        if RESERVED_VOLUME_NAMES.contains(&value.as_str()) {
            bail!("volume name {value:?} is reserved");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VolumeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Path within a volume's namespace. Validated to reject `..`, embedded
/// NULs, leading slashes (paths are always volume-relative), and
/// excessive length.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VolumePath(String);

impl VolumePath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            bail!("volume path must not be empty");
        }
        if value.len() > MAX_VOLUME_PATH_LEN {
            bail!(
                "volume path must be 1-{MAX_VOLUME_PATH_LEN} bytes, got {}",
                value.len()
            );
        }
        if value.contains('\0') {
            bail!("volume path must not contain NUL");
        }
        if value.starts_with('/') {
            bail!("volume path must be relative (no leading '/'): {value:?}");
        }
        for segment in value.split('/') {
            if segment == ".." {
                bail!("volume path must not contain '..' segment: {value:?}");
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VolumePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Guest mount path — must be an absolute, validated path inside an
/// allowed mount root. The actual deny-list lives in
/// `crate::crypto::policy::MountPathPolicy`; this newtype only enforces
/// shape (absolute, no NUL, no `..`, length cap).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GuestPath(String);

impl GuestPath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            bail!("guest path must not be empty");
        }
        if value.len() > MAX_VOLUME_PATH_LEN {
            bail!(
                "guest path must be 1-{MAX_VOLUME_PATH_LEN} bytes, got {}",
                value.len()
            );
        }
        if value.contains('\0') {
            bail!("guest path must not contain NUL");
        }
        if !value.starts_with('/') {
            bail!("guest path must be absolute: {value:?}");
        }
        for segment in value.split('/') {
            if segment == ".." {
                bail!("guest path must not contain '..' segment: {value:?}");
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GuestPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reference to a secret stored elsewhere (mvm-security secret store on
/// dev box; mvmd's sealed-creds infrastructure on the fleet side).
/// Never carries the secret value itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_VOLUME_PATH_LEN {
            bail!("secret ref must be 1-{MAX_VOLUME_PATH_LEN} bytes");
        }
        if value.contains('\0') {
            bail!("secret ref must not contain NUL");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// Backend configuration
// ============================================================================

/// Declarative backend shape. Behaviour lives in `mvm-storage`
/// (LocalBackend) and mvmd-side crates (ObjectStoreBackend +
/// EncryptedBackend) — see plan 45 §D5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VolumeBackendConfig {
    /// Host directory served by virtiofsd. The only mountable backend
    /// in v1. mvm-storage ships this impl.
    Local {
        /// Absolute host path that the backing data lives under.
        root: PathBuf,
    },

    /// Object storage via opendal (S3, R2, GCS, Azure, Hetzner, …).
    /// Implemented in mvmd, not mvm-storage. Data-plane only — not
    /// virtio-fs-mountable in v1.
    #[serde(rename = "object-store")]
    ObjectStore(ObjectStoreSpec),
}

impl VolumeBackendConfig {
    /// Stable string identifier used in metrics labels and audit logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::ObjectStore(_) => "object-store",
        }
    }

    /// Returns true if this backend can be mounted into a microVM via
    /// virtio-fs in v1. (Object stores aren't mountable in v1; see
    /// backlog item B3 in plan 45.)
    pub fn is_mountable(&self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

/// Object-store backend specification.
///
/// Provider is selected by URL scheme:
/// - `s3://bucket[/prefix]` (S3-compatible: AWS, R2, Hetzner Object
///   Storage, MinIO, B2 — endpoint provided via `credentials_ref`'s
///   secret payload).
/// - `gs://bucket[/prefix]` (Google Cloud Storage).
/// - `az://container[/prefix]` (Azure Blob).
/// - `file:///path` (local filesystem — testing only).
/// - `memory://` (in-memory — testing only).
///
/// Credentials are referenced, never embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreSpec {
    /// URL whose scheme picks the provider; path picks the bucket and
    /// optional default prefix.
    pub url: String,

    /// Optional key prefix prepended to every operation. Composes with
    /// any prefix in `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// Reference to provider credentials in the secret store. Never
    /// holds the credential material itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_ref: Option<SecretRef>,
}

// ============================================================================
// Top-level resource
// ============================================================================

/// A named, multi-attach volume. Identity is `(org_id, workspace_id,
/// name)`. Mounts inherit scope from the instance they attach to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    pub org_id: OrgId,
    pub workspace_id: WorkspaceId,
    pub name: VolumeName,
    pub created_at: DateTime<Utc>,

    /// Optional soft cap on stored bytes. `None` = unbounded (rely on
    /// host quota). `LocalBackend` enforces this; `ObjectStoreBackend`
    /// can't enforce — provider-side quotas apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,

    pub backend: VolumeBackendConfig,
}

/// Declared mount of a volume into a microVM at boot time.
///
/// `volume` resolves within the instance's `(org_id, workspace_id)`
/// scope; cross-scope mounting is rejected at the mvmd REST layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    pub volume: VolumeName,
    pub guest_path: GuestPath,

    /// Defense-in-depth: enforced both at the kernel mount layer
    /// (`-o ro`) and at the trait dispatch layer (data-plane writes
    /// rejected when true).
    #[serde(default)]
    pub read_only: bool,
}

/// Filesystem-style entry returned by `list`/`stat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeEntry {
    pub path: VolumePath,
    pub size: u64,
    pub is_dir: bool,
    /// Backend-supplied content hash / version tag (provider ETag for
    /// object stores; modification timestamp hash for local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

// ============================================================================
// Encryption-at-rest key wrapping (used by mvmd-side EncryptedBackend)
// ============================================================================

/// Algorithm used to wrap a per-volume data key under a master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrapAlgorithm {
    /// AES Key Wrap with Padding (NIST SP 800-38F / RFC 5649).
    /// Implemented mvmd-side per plan 45 §D5 ("EncryptedBackend
    /// lives in mvmd, not mvm"); `crate::crypto::key_rotation`'s
    /// rewrap path returns `UnsupportedAlgorithm` when asked to
    /// rewrap an `AesKwp` envelope.
    AesKwp,

    /// AES-256-GCM AEAD wrap (12-byte nonce || ciphertext || 16-byte
    /// tag, the `crate::crypto::snapshot_crypto` envelope shape).
    /// mvm-side rotation supports this variant out of the box —
    /// `rewrap_dek` decrypts under the old master and re-encrypts
    /// under the new master with a fresh nonce, preserving the
    /// plaintext DEK. Plan 63 W1.
    Aes256Gcm,
}

/// Plan 122 B2 — binds a wrapped DEK to the artifact it protects, so a DEK
/// can't be lifted onto a different volume than it was minted for.
///
/// `content_hash` is the only field mvm populates today (the sha256 of the
/// local volume's ciphertext archive, re-checked before the DEK is
/// unwrapped). `plan_id` / `audit_head` are reserved for the workload
/// rebuild path, which mvmd owns — it runs the per-rebuild `EncryptedBackend`
/// and holds the signed plan + audit chain. They stay `None` for local
/// volumes, which have no plan at create time. (The deps-volume → signed-plan
/// binding for workloads already exists separately as
/// [`crate::plan::DepsVolumeBinding`]; this is the distinct DEK-envelope ↔
/// artifact layer.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DekBinding {
    /// sha256-hex of the bound artifact (the local volume's ciphertext
    /// archive).
    pub content_hash: String,
    /// Signed-plan id this DEK was minted for. mvmd-populated; `None` local.
    #[serde(default)]
    pub plan_id: Option<String>,
    /// Audit-chain head at mint. mvmd-populated; `None` local.
    #[serde(default)]
    pub audit_head: Option<String>,
}

/// A per-volume AEAD key, wrapped under a versioned master key.
/// Stored in the volume registry record alongside the volume metadata.
///
/// `Debug` is hand-written rather than derived because the default
/// `Vec<u8>` Debug would print the wrapped bytes — even though those
/// are ciphertext, the length leaks key shape, and printing leaks
/// timing patterns to any consumer (logs, panics, error messages).
/// The custom impl prints the byte length only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    /// Selects which master key version to unwrap with. Lets master
    /// rotation re-wrap without forcing data re-encryption.
    pub master_key_version: u32,

    /// Wrapped key bytes.
    pub wrapped: Vec<u8>,

    pub algorithm: WrapAlgorithm,

    /// Plan 122 B2 — optional binding to the artifact this DEK protects.
    /// `None` for pre-B2 / unbound keys (accepted, treated as "no binding
    /// to check").
    #[serde(default)]
    pub bound: Option<DekBinding>,
}

impl WrappedKey {
    /// True when this key is unbound, or its binding's `content_hash`
    /// matches `actual_content_hash`. The admit/unlock gate: a DEK presented
    /// against a different artifact than it was minted for is refused.
    pub fn binding_matches_content(&self, actual_content_hash: &str) -> bool {
        match &self.bound {
            None => true,
            Some(b) => b.content_hash == actual_content_hash,
        }
    }

    /// Re-point the binding at a new artifact `content_hash`, preserving any
    /// `plan_id` / `audit_head`. A mutable local volume is re-sealed on every
    /// lock, so its ciphertext — and thus its hash — changes; the binding
    /// must follow.
    pub fn rebind_content(&mut self, content_hash: String) {
        let (plan_id, audit_head) = self
            .bound
            .take()
            .map(|b| (b.plan_id, b.audit_head))
            .unwrap_or((None, None));
        self.bound = Some(DekBinding {
            content_hash,
            plan_id,
            audit_head,
        });
    }
}

// allow(secret-debug): hand-written Debug below redacts the wrapped
// bytes; reports length only.
impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKey")
            .field("master_key_version", &self.master_key_version)
            .field("wrapped", &format_args!("<{} bytes>", self.wrapped.len()))
            .field("algorithm", &self.algorithm)
            .field("bound", &self.bound)
            .finish()
    }
}

// allow(secret-debug): metadata enum with no payload — variant
// names are the entire information content. Derives Debug for the
// 3 variant strings ("Active" / "Legacy" / "Revoked"), no secret
// material involved.
/// Lifecycle state of a master key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasterKeyState {
    /// Used to wrap new volumes' keys.
    Active,

    /// No longer used for new wraps, but can still unwrap existing
    /// `WrappedKey` records during rotation.
    Legacy,

    /// Tombstone after final re-wrap — unwrap fails.
    Revoked,
}

/// Reference to a master key version managed by the secret store.
/// The actual key material never leaves the secret store; this is
/// just the metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterKeyRef {
    pub org_id: OrgId,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub state: MasterKeyState,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the `VolumeBackend` trait (defined in
/// `mvm-storage`). Lives in `mvm-core` so trait callers and impls can
/// share a single error type without a circular dep.
#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("volume entry not found: {0}")]
    NotFound(VolumePath),

    #[error("volume entry already exists: {0}")]
    AlreadyExists(VolumePath),

    #[error("size cap exceeded ({attempted} > {limit} bytes)")]
    SizeCapExceeded { attempted: u64, limit: u64 },

    #[error("read-only volume rejects mutation")]
    ReadOnly,

    #[error("backend kind {kind} not supported in this context: {reason}")]
    UnsupportedBackend {
        kind: &'static str,
        reason: &'static str,
    },

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("backend I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("backend error: {0}")]
    Other(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-06T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    // ------------- ID validation -------------

    #[test]
    fn org_id_accepts_valid() {
        assert!(OrgId::new("acme").is_ok());
        assert!(OrgId::new("a").is_ok());
        assert!(OrgId::new("org-with-hyphens-123").is_ok());
    }

    #[test]
    fn org_id_rejects_invalid() {
        assert!(OrgId::new("").is_err());
        assert!(OrgId::new("UPPER").is_err());
        assert!(OrgId::new("-leading").is_err());
        assert!(OrgId::new("trailing-").is_err());
        assert!(OrgId::new("has space").is_err());
        assert!(OrgId::new("has/slash").is_err());
        assert!(OrgId::new("a".repeat(64)).is_err());
    }

    #[test]
    fn workspace_id_accepts_valid() {
        assert!(WorkspaceId::new("default").is_ok());
        assert!(WorkspaceId::new("ws-prod-1").is_ok());
    }

    #[test]
    fn volume_name_accepts_valid() {
        assert!(VolumeName::new("scratch").is_ok());
        assert!(VolumeName::new("my_workspace").is_ok());
        assert!(VolumeName::new("data-volume-1").is_ok());
        assert!(VolumeName::new("v".repeat(63)).is_ok());
    }

    #[test]
    fn volume_name_rejects_invalid() {
        assert!(VolumeName::new("").is_err());
        assert!(VolumeName::new("UPPER").is_err());
        assert!(VolumeName::new(".hidden").is_err());
        assert!(VolumeName::new("-leading").is_err());
        assert!(VolumeName::new("_leading").is_err());
        assert!(VolumeName::new("has/slash").is_err());
        assert!(VolumeName::new("has space").is_err());
        assert!(VolumeName::new("v".repeat(64)).is_err());
    }

    #[test]
    fn volume_name_rejects_reserved() {
        for reserved in RESERVED_VOLUME_NAMES {
            assert!(
                VolumeName::new(*reserved).is_err(),
                "reserved name {reserved:?} should be rejected"
            );
        }
    }

    #[test]
    fn volume_path_accepts_valid() {
        assert!(VolumePath::new("foo.txt").is_ok());
        assert!(VolumePath::new("a/b/c.txt").is_ok());
        assert!(VolumePath::new("nested/dir/with-hyphens_and_underscores.txt").is_ok());
    }

    #[test]
    fn volume_path_rejects_traversal() {
        assert!(VolumePath::new("../etc/passwd").is_err());
        assert!(VolumePath::new("a/../b").is_err());
        assert!(VolumePath::new("..").is_err());
    }

    #[test]
    fn volume_path_rejects_absolute() {
        assert!(VolumePath::new("/abs/path").is_err());
    }

    #[test]
    fn volume_path_rejects_nul_and_empty() {
        assert!(VolumePath::new("").is_err());
        assert!(VolumePath::new("foo\0bar").is_err());
    }

    #[test]
    fn guest_path_must_be_absolute() {
        assert!(GuestPath::new("/mnt/scratch").is_ok());
        assert!(GuestPath::new("mnt/scratch").is_err());
    }

    #[test]
    fn guest_path_rejects_traversal_and_nul() {
        assert!(GuestPath::new("/mnt/../etc").is_err());
        assert!(GuestPath::new("/mnt/foo\0bar").is_err());
    }

    // ------------- Serde roundtrips -------------

    #[test]
    fn volume_local_roundtrip() {
        let v = Volume {
            org_id: OrgId::new("acme").unwrap(),
            workspace_id: WorkspaceId::new("prod").unwrap(),
            name: VolumeName::new("scratch").unwrap(),
            created_at: ts(),
            size_bytes: Some(10 * 1024 * 1024 * 1024),
            backend: VolumeBackendConfig::Local {
                root: PathBuf::from("/var/lib/mvm/volumes/scratch"),
            },
        };
        let json = serde_json::to_string(&v).unwrap();
        let v2: Volume = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn volume_object_store_roundtrip() {
        let v = Volume {
            org_id: OrgId::new("acme").unwrap(),
            workspace_id: WorkspaceId::new("prod").unwrap(),
            name: VolumeName::new("fixtures").unwrap(),
            created_at: ts(),
            size_bytes: None,
            backend: VolumeBackendConfig::ObjectStore(ObjectStoreSpec {
                url: "s3://acme-fixtures/".into(),
                prefix: Some("data/".into()),
                credentials_ref: Some(SecretRef::new("aws-prod").unwrap()),
            }),
        };
        let json = serde_json::to_string(&v).unwrap();
        let v2: Volume = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn volume_mount_roundtrip() {
        let m = VolumeMount {
            volume: VolumeName::new("scratch").unwrap(),
            guest_path: GuestPath::new("/mnt/scratch").unwrap(),
            read_only: true,
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: VolumeMount = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn wrapped_key_roundtrip() {
        let w = WrappedKey {
            master_key_version: 7,
            wrapped: vec![1, 2, 3, 4, 5, 6, 7, 8],
            algorithm: WrapAlgorithm::AesKwp,
            bound: None,
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: WrappedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn wrapped_key_without_bound_field_deserializes_as_unbound() {
        // Pre-B2 records carried no `bound` key; `#[serde(default)]` must
        // load them as unbound rather than failing the deny_unknown_fields
        // envelope.
        let legacy = r#"{"master_key_version":1,"wrapped":[1,2,3],"algorithm":"aes256-gcm"}"#;
        let w: WrappedKey = serde_json::from_str(legacy).unwrap();
        assert!(w.bound.is_none());
        assert!(w.binding_matches_content("anything"), "unbound matches all");
    }

    #[test]
    fn binding_refuses_mismatched_content_hash() {
        let mut w = WrappedKey {
            master_key_version: 1,
            wrapped: vec![9, 9, 9],
            algorithm: WrapAlgorithm::Aes256Gcm,
            bound: None,
        };
        w.rebind_content("aaaa".to_string());
        assert!(w.binding_matches_content("aaaa"));
        assert!(
            !w.binding_matches_content("bbbb"),
            "different artifact refused"
        );

        // rebind preserves plan_id / audit_head while moving the content hash.
        if let Some(b) = w.bound.as_mut() {
            b.plan_id = Some("plan-1".into());
            b.audit_head = Some("head-1".into());
        }
        w.rebind_content("cccc".to_string());
        let b = w.bound.as_ref().unwrap();
        assert_eq!(b.content_hash, "cccc");
        assert_eq!(b.plan_id.as_deref(), Some("plan-1"));
        assert_eq!(b.audit_head.as_deref(), Some("head-1"));
    }

    #[test]
    fn master_key_ref_roundtrip() {
        let m = MasterKeyRef {
            org_id: OrgId::new("acme").unwrap(),
            version: 3,
            created_at: ts(),
            state: MasterKeyState::Active,
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: MasterKeyRef = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    // ------------- deny_unknown_fields -------------

    #[test]
    fn volume_rejects_unknown_field() {
        let payload = r#"{
            "org_id": "acme",
            "workspace_id": "prod",
            "name": "scratch",
            "created_at": "2026-05-06T20:00:00Z",
            "backend": {"kind": "local", "root": "/var/lib/mvm/volumes/scratch"},
            "extra_field": "should fail"
        }"#;
        let res: serde_json::Result<Volume> = serde_json::from_str(payload);
        assert!(res.is_err(), "deny_unknown_fields must reject extra_field");
    }

    #[test]
    fn object_store_spec_rejects_unknown_field() {
        let payload = r#"{
            "url": "s3://b/",
            "extra": "no"
        }"#;
        let res: serde_json::Result<ObjectStoreSpec> = serde_json::from_str(payload);
        assert!(res.is_err());
    }

    #[test]
    fn volume_backend_config_kind() {
        let local = VolumeBackendConfig::Local {
            root: PathBuf::from("/x"),
        };
        assert_eq!(local.kind(), "local");
        assert!(local.is_mountable());

        let os = VolumeBackendConfig::ObjectStore(ObjectStoreSpec {
            url: "s3://b/".into(),
            prefix: None,
            credentials_ref: None,
        });
        assert_eq!(os.kind(), "object-store");
        assert!(!os.is_mountable());
    }

    #[test]
    fn backend_config_serde_tag_shape() {
        let local = VolumeBackendConfig::Local {
            root: PathBuf::from("/x"),
        };
        let json = serde_json::to_value(&local).unwrap();
        assert_eq!(json["kind"], "local");
        assert_eq!(json["root"], "/x");
    }

    // ------------- VolumeError -------------

    #[test]
    fn volume_error_display() {
        let path = VolumePath::new("foo.txt").unwrap();
        let err = VolumeError::NotFound(path);
        assert!(err.to_string().contains("foo.txt"));
    }
}
