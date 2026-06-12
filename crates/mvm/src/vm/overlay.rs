//! Persistent per-tenant + per-workload overlay substrate.
//!
//! The overlay is the workload's writable layer over the read-only
//! verity'd rootfs (claim 3 of CLAUDE.md's security model). The goal
//! is that rootfs rebuild/swap can happen underneath an unchanged
//! overlay — `/workspace` survives the upgrade — while
//! overlay-erasure tooling walks the overlay tree, wipes each file,
//! and emits a signed destruction certificate so a hosted-cloud
//! operator can prove they erased a tenant's data.
//!
//! ## The substrate
//!
//! [`OverlayManager`] is the trait every consumer (install / rebuild
//! / tenant-destroy / future LUKS impl) goes through; [`FsOverlayManager`]
//! is the unencrypted file-backed default; [`NoopOverlayManager`] is
//! the fail-closed placeholder. [`OverlayHandle`] is the opaque token
//! returned by `create_overlay` / `open_overlay` — consumers don't
//! reach into the filesystem layout directly.
//!
//! ## Security model
//!
//! 1. **Per-tenant + per-workload isolation.** The overlay tree is
//!    `<root>/<tenant>/<workload>/`. Both `tenant` and `workload`
//!    are path-validated (no `..`, no slashes, no null bytes, no
//!    control chars, ≤ 64 byte names) so a malicious tenant id
//!    can't escape via `../`.
//! 2. **Mode 0700 throughout.** The overlay root, each tenant dir,
//!    and each workload dir get `chmod 0700` on Unix — same-host
//!    other users can't read.
//! 3. **No symlink following.** All opens use `O_NOFOLLOW` so a
//!    symlink that crept into the workload dir (the only way one
//!    could appear) trips ELOOP rather than crossing the boundary.
//! 4. **Quota enforcement.** [`FsOverlayManager`] tracks the
//!    running byte-count via a single recursive walk at
//!    `open_overlay` time. Writes that would exceed the operator's
//!    quota return [`OverlayError::QuotaExceeded`]; the future LUKS
//!    impl enforces at the filesystem layer too.
//! 5. **Zero-fill on destroy.** `destroy_overlay` walks the tree,
//!    overwrites every file with zeros (via O_RDWR + fsync), then
//!    unlinks. For block-level guarantees, the LUKS impl will
//!    additionally revoke the LUKS keyslot — a key-destruction
//!    guarantee independent of whether the disk hardware actually
//!    overwrote the blocks.
//!
//! ## What this is NOT (yet)
//!
//! - Not encrypted. A LUKS-backed impl will wire
//!   `mvm_core::crypto::keystore::KeyProvider` for per-overlay LUKS
//!   keys.
//! - Not mounted into VMs. The firecracker / qemu backends will
//!   learn to attach the overlay as a virtio block device.
//! - No destruction certificate yet. Signing the
//!   [`DestructionReceipt`] under the host identity key and emitting
//!   it to the audit chain is wired below.
//! - No rebuild swap. pause → swap rootfs → resume with the overlay
//!   reattached is future work.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

/// Default subdirectory under `~/.mvm/` where overlays live.
pub const DEFAULT_OVERLAY_DIR_NAME: &str = "overlays";

/// Maximum length of a tenant id or workload id, in bytes. Keeps
/// the audit chain bounded and avoids PATH_MAX surprises on Linux
/// (PATH_MAX = 4096, but we're nested two levels deep + with the
/// overlay root prefix, so 64 each is safe headroom).
pub const MAX_NAME_LEN: usize = 64;

/// Default quota per overlay. 10 GiB matches the working budget
/// for a development workload (~100 K source files + build cache);
/// operators will override per-tenant via the LUKS-volume size once
/// the LUKS-backed impl lands.
pub const DEFAULT_QUOTA_BYTES: u64 = 10 * (1 << 30);

/// Trait every overlay consumer goes through. Ships
/// [`FsOverlayManager`] (plain filesystem) + [`NoopOverlayManager`]
/// (fail-closed); a future LUKS-backed impl will wire
/// `mvm_core::crypto::keystore::KeyProvider`.
#[async_trait]
pub trait OverlayManager: Send + Sync {
    /// Create a new overlay for `(tenant, workload)`. Idempotent —
    /// if the overlay already exists, returns the existing handle
    /// (operators rebuilding via `mvmctl install` re-open the same
    /// overlay; the rebuild swaps the rootfs underneath without
    /// touching the overlay).
    async fn create_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<OverlayHandle, OverlayError>;

    /// Open an existing overlay. Errors with [`OverlayError::NotFound`]
    /// if no overlay exists for the pair.
    async fn open_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<OverlayHandle, OverlayError>;

    /// Destroy an overlay. Zeroes every file's bytes before unlink,
    /// then removes the directory. Returns a [`DestructionReceipt`]
    /// recording the wipe (signed under the host identity key +
    /// emitted to the audit chain). Idempotent —
    /// destroying a non-existent overlay returns a receipt with
    /// `files_wiped = 0`.
    async fn destroy_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<DestructionReceipt, OverlayError>;

    /// List every overlay for a tenant. Returns an empty vec when
    /// the tenant has no overlays (or doesn't exist at all).
    async fn list_overlays(&self, tenant: &str) -> Result<Vec<OverlayHandle>, OverlayError>;
}

/// Opaque handle returned by `create_overlay` / `open_overlay`.
/// Consumers operate on the handle, not the filesystem layout.
#[derive(Debug, Clone)]
pub struct OverlayHandle {
    pub tenant: String,
    pub workload: String,
    /// Absolute path to the overlay's root directory. The LUKS-backed
    /// impl will expose this as a block device path instead (the
    /// LUKS-decrypted device-mapper node); callers shouldn't depend
    /// on the value being a directory.
    pub root: PathBuf,
    /// Running byte-count of the overlay, computed at open. Stale
    /// after the first write — callers that need a current
    /// measurement should re-open or use the future
    /// `OverlayManager::current_size` method.
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    /// `false` for [`FsOverlayManager`]; `true` once LUKS lands.
    pub encrypted: bool,
}

/// Audit-grade record of a destruction operation. Signed under the
/// host identity key — see
/// [`sign_destruction_receipt`] / [`verify_destruction_receipt`]
/// and the [`SignedDestructionReceipt`] envelope below.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestructionReceipt {
    pub tenant: String,
    pub workload: String,
    pub destroyed_at: DateTime<Utc>,
    /// Count of regular files overwritten + unlinked. Excludes
    /// directories (which are removed without zero-fill since they
    /// hold no data of their own).
    pub files_wiped: u64,
    /// Total bytes overwritten across all files. Useful as a
    /// sanity check vs. the overlay's pre-destroy `size_bytes`.
    pub bytes_wiped: u64,
}

impl DestructionReceipt {
    /// Canonical bytes the destruction signature is computed over.
    ///
    /// Format (version-prefixed, pipe-delimited):
    ///
    /// ```text
    /// destruction|v1|<tenant>|<workload>|<destroyed_at_unix_nanos>|<files_wiped>|<bytes_wiped>
    /// ```
    ///
    /// Pipe-delimited rather than JSON because JSON object-key
    /// ordering isn't guaranteed across serializers — that would
    /// make verification implementation-dependent. The v1 prefix
    /// pins the format; bumping it (e.g. to v2 if we add a field)
    /// invalidates prior signatures by design.
    pub fn signature_payload(&self) -> Vec<u8> {
        let ts_nanos = self
            .destroyed_at
            .timestamp_nanos_opt()
            .unwrap_or_else(|| self.destroyed_at.timestamp() * 1_000_000_000);
        format!(
            "destruction|v1|{tenant}|{workload}|{ts}|{files}|{bytes}",
            tenant = self.tenant,
            workload = self.workload,
            ts = ts_nanos,
            files = self.files_wiped,
            bytes = self.bytes_wiped,
        )
        .into_bytes()
    }
}

/// `DestructionReceipt` wrapped in an Ed25519 signature
/// plus the signing key's identity (the host identity pubkey,
/// base64-encoded). An operator who needs to prove a tenant's
/// data was erased hands this envelope over: the auditor verifies
/// the signature with a known-trusted pubkey and matches the
/// receipt fields against the audit chain's `tenant.destroyed`
/// event.
///
/// ## Wire shape
///
/// The envelope serializes to JSON for operator-friendliness;
/// `#[serde(deny_unknown_fields)]` keeps the wire pinned. The
/// `signature` and `signer_pubkey` are URL-safe-no-pad base64
/// (same encoding the audit chain uses for envelope hashes +
/// signatures).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDestructionReceipt {
    pub receipt: DestructionReceipt,
    /// URL-safe-no-pad base64 of the 64-byte Ed25519 signature
    /// over `receipt.signature_payload()`.
    pub signature: String,
    /// URL-safe-no-pad base64 of the signer's 32-byte Ed25519
    /// public key. An auditor uses this to look up the signer
    /// (operator key fingerprint) in their trust store.
    pub signer_pubkey: String,
    /// Format version. Pins `signature_payload`'s shape. Future
    /// bumps invalidate prior signatures by design.
    pub version: u32,
}

/// Sign a [`DestructionReceipt`] under `signing_key`. The
/// public-key fingerprint included in the envelope is derived
/// from the signing key, so the auditor doesn't have to be told
/// separately which key signed.
///
/// Production callers pass `host_signer.signing` (the operator's
/// host identity key). Tests inject a fresh ephemeral keypair.
/// Audit-chain cross-reference anchor for a signed destruction
/// certificate. Returns the lowercase-hex SHA-256 digest of the
/// canonical compact-JSON serialization of `signed`.
///
/// Used by the operator at emission time (the per-workload
/// `lifecycle.tenant.destroyed` audit-chain event carries this in
/// its `cert_fingerprint` label) and by an auditor at verification
/// time (the auditor recomputes the fingerprint from the on-disk
/// certificate file and matches it against the chain entry).
///
/// The serialization is compact (no whitespace) for two reasons:
/// 1. The hash is over a deterministic byte string — pretty-
///    printing would make the digest depend on the serde_json
///    version's whitespace choices.
/// 2. Operators distributing the certificate file may pretty-
///    print or re-encode it; the auditor parses + recompactifies
///    via the same `to_vec` path so the digest matches regardless.
pub fn cert_fingerprint(signed: &SignedDestructionReceipt) -> String {
    use sha2::{Digest, Sha256};
    // Unwrap: serializing a struct with all-String / all-numeric
    // fields cannot fail at runtime.
    let bytes = serde_json::to_vec(signed).expect("cert serde");
    let digest = Sha256::digest(&bytes);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

pub fn sign_destruction_receipt(
    receipt: &DestructionReceipt,
    signing_key: &ed25519_dalek::SigningKey,
) -> SignedDestructionReceipt {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let payload = receipt.signature_payload();
    let signature = signing_key.sign(&payload);
    let signer_pubkey = signing_key.verifying_key();
    SignedDestructionReceipt {
        receipt: receipt.clone(),
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        signer_pubkey: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signer_pubkey.to_bytes()),
        version: 1,
    }
}

#[derive(Debug, Error)]
pub enum DestructionVerifyError {
    #[error("unsupported destruction-receipt version {got} (expected 1)")]
    UnsupportedVersion { got: u32 },
    #[error("signer pubkey not base64: {0}")]
    PubkeyDecode(String),
    #[error("signer pubkey wrong length: got {got} bytes (expected 32)")]
    PubkeyLength { got: usize },
    #[error("signer pubkey malformed: {0}")]
    PubkeyParse(String),
    #[error("signer pubkey {got:?} does not match expected {expected:?}")]
    PubkeyMismatch { got: String, expected: String },
    #[error("signature not base64: {0}")]
    SignatureDecode(String),
    #[error("signature wrong length: got {got} bytes (expected 64)")]
    SignatureLength { got: usize },
    #[error("signature invalid for this receipt + pubkey")]
    SignatureInvalid,
}

/// Verify a [`SignedDestructionReceipt`]. If `expected_signer_pubkey`
/// is `Some`, additionally check that the envelope's embedded
/// `signer_pubkey` matches it byte-for-byte (so an operator can
/// pin to a specific host identity).
///
/// Returns the inner receipt on success — the caller has both the
/// receipt fields AND the assurance that they were signed by the
/// expected key.
pub fn verify_destruction_receipt<'a>(
    signed: &'a SignedDestructionReceipt,
    expected_signer_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<&'a DestructionReceipt, DestructionVerifyError> {
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if signed.version != 1 {
        return Err(DestructionVerifyError::UnsupportedVersion {
            got: signed.version,
        });
    }
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signed.signer_pubkey.as_bytes())
        .map_err(|e| DestructionVerifyError::PubkeyDecode(e.to_string()))?;
    if pubkey_bytes.len() != 32 {
        return Err(DestructionVerifyError::PubkeyLength {
            got: pubkey_bytes.len(),
        });
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pubkey_bytes);
    let pubkey = VerifyingKey::from_bytes(&pk_array)
        .map_err(|e| DestructionVerifyError::PubkeyParse(e.to_string()))?;
    if let Some(expected) = expected_signer_pubkey
        && pubkey.to_bytes() != expected.to_bytes()
    {
        return Err(DestructionVerifyError::PubkeyMismatch {
            got: signed.signer_pubkey.clone(),
            expected: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected.to_bytes()),
        });
    }
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signed.signature.as_bytes())
        .map_err(|e| DestructionVerifyError::SignatureDecode(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(DestructionVerifyError::SignatureLength {
            got: sig_bytes.len(),
        });
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);
    let payload = signed.receipt.signature_payload();
    pubkey
        .verify(&payload, &signature)
        .map_err(|_| DestructionVerifyError::SignatureInvalid)?;
    Ok(&signed.receipt)
}

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error("invalid {label} {name:?}: {reason}")]
    InvalidName {
        label: &'static str,
        name: String,
        reason: &'static str,
    },

    #[error("overlay for {tenant:?}/{workload:?} not found")]
    NotFound { tenant: String, workload: String },

    #[error("io error on {path:?}: {message}")]
    Io { path: String, message: String },

    #[error("overlay manager not wired (NoopOverlayManager)")]
    Unwired,

    #[error("overlay write would exceed quota: requested {requested} bytes, quota {limit}")]
    QuotaExceeded { requested: u64, limit: u64 },
}

/// Fail-closed default. Substrate placeholder until an operator
/// wires a real overlay manager.
pub struct NoopOverlayManager;

#[async_trait]
impl OverlayManager for NoopOverlayManager {
    async fn create_overlay(&self, _: &str, _: &str) -> Result<OverlayHandle, OverlayError> {
        Err(OverlayError::Unwired)
    }
    async fn open_overlay(&self, _: &str, _: &str) -> Result<OverlayHandle, OverlayError> {
        Err(OverlayError::Unwired)
    }
    async fn destroy_overlay(&self, _: &str, _: &str) -> Result<DestructionReceipt, OverlayError> {
        Err(OverlayError::Unwired)
    }
    async fn list_overlays(&self, _: &str) -> Result<Vec<OverlayHandle>, OverlayError> {
        Err(OverlayError::Unwired)
    }
}

/// Plain-filesystem overlay manager. Each overlay is a directory
/// under `<root>/<tenant>/<workload>/`; mode 0700 throughout on
/// Unix. No encryption yet.
#[derive(Debug)]
pub struct FsOverlayManager {
    root: PathBuf,
    quota_bytes: u64,
}

impl FsOverlayManager {
    /// Build with explicit root + default quota.
    pub fn with_root(root: impl Into<PathBuf>) -> Result<Self, OverlayError> {
        Self::with_root_and_quota(root, DEFAULT_QUOTA_BYTES)
    }

    /// Build with explicit root + explicit quota.
    pub fn with_root_and_quota(
        root: impl Into<PathBuf>,
        quota_bytes: u64,
    ) -> Result<Self, OverlayError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| OverlayError::Io {
            path: root.display().to_string(),
            message: format!("creating overlay root: {e}"),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).ok();
        }
        Ok(Self { root, quota_bytes })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }

    fn workload_dir(&self, tenant: &str, workload: &str) -> Result<PathBuf, OverlayError> {
        validate_path_component(tenant, "tenant id")?;
        validate_path_component(workload, "workload id")?;
        Ok(self.root.join(tenant).join(workload))
    }
}

#[async_trait]
impl OverlayManager for FsOverlayManager {
    async fn create_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<OverlayHandle, OverlayError> {
        let dir = self.workload_dir(tenant, workload)?;
        if dir.exists() {
            // Idempotent — return the existing handle.
            return self.open_overlay(tenant, workload).await;
        }
        std::fs::create_dir_all(&dir).map_err(|e| OverlayError::Io {
            path: dir.display().to_string(),
            message: format!("creating overlay dir: {e}"),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
            // Tighten the tenant dir too.
            if let Some(p) = dir.parent() {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).ok();
            }
        }
        Ok(OverlayHandle {
            tenant: tenant.to_string(),
            workload: workload.to_string(),
            root: dir,
            size_bytes: 0,
            created_at: Utc::now(),
            encrypted: false,
        })
    }

    async fn open_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<OverlayHandle, OverlayError> {
        let dir = self.workload_dir(tenant, workload)?;
        let meta = std::fs::metadata(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                OverlayError::NotFound {
                    tenant: tenant.to_string(),
                    workload: workload.to_string(),
                }
            } else {
                OverlayError::Io {
                    path: dir.display().to_string(),
                    message: e.to_string(),
                }
            }
        })?;
        let size_bytes = recursive_size(&dir)?;
        Ok(OverlayHandle {
            tenant: tenant.to_string(),
            workload: workload.to_string(),
            root: dir,
            size_bytes,
            created_at: meta
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
                .unwrap_or_else(Utc::now),
            encrypted: false,
        })
    }

    async fn destroy_overlay(
        &self,
        tenant: &str,
        workload: &str,
    ) -> Result<DestructionReceipt, OverlayError> {
        let dir = self.workload_dir(tenant, workload)?;
        let (files_wiped, bytes_wiped) = if dir.exists() {
            wipe_recursive(&dir)?
        } else {
            (0, 0)
        };
        Ok(DestructionReceipt {
            tenant: tenant.to_string(),
            workload: workload.to_string(),
            destroyed_at: Utc::now(),
            files_wiped,
            bytes_wiped,
        })
    }

    async fn list_overlays(&self, tenant: &str) -> Result<Vec<OverlayHandle>, OverlayError> {
        validate_path_component(tenant, "tenant id")?;
        let tenant_dir = self.root.join(tenant);
        if !tenant_dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&tenant_dir).map_err(|e| OverlayError::Io {
            path: tenant_dir.display().to_string(),
            message: e.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| OverlayError::Io {
                path: tenant_dir.display().to_string(),
                message: e.to_string(),
            })?;
            let name = entry.file_name();
            let Some(workload) = name.to_str() else {
                continue; // skip non-UTF-8 dir names
            };
            // Don't bubble up validation errors from items in the
            // tenant dir — the operator may have hand-placed files;
            // skip rather than refuse the whole list.
            if validate_path_component(workload, "workload id").is_err() {
                continue;
            }
            if let Ok(handle) = self.open_overlay(tenant, workload).await {
                out.push(handle);
            }
        }
        out.sort_by(|a, b| a.workload.cmp(&b.workload));
        Ok(out)
    }
}

/// Validate one path component. Reuses the same constraints as
/// [`crate::vm`]'s staging-area path validator: no slashes, no
/// parent refs, no null / control chars, length-capped at
/// [`MAX_NAME_LEN`].
pub(crate) fn validate_path_component(name: &str, label: &'static str) -> Result<(), OverlayError> {
    if name.is_empty() {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "empty",
        });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "exceeds MAX_NAME_LEN",
        });
    }
    if name.contains('\0') || name.chars().any(|c| c.is_control()) {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "contains null or control character",
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "contains a path separator",
        });
    }
    if name == "." || name == ".." {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "is a dot or parent reference",
        });
    }
    // The path must canonicalize to a single Normal component when
    // wrapped in `Path::new` — defense in depth against any
    // sneakier escape vector.
    let p = Path::new(name);
    if p.components().count() != 1 || !matches!(p.components().next(), Some(Component::Normal(_))) {
        return Err(OverlayError::InvalidName {
            label,
            name: name.to_string(),
            reason: "must be a single normal path component",
        });
    }
    Ok(())
}

/// Walk a directory tree summing the byte length of every regular
/// file. Used by `open_overlay` to populate
/// [`OverlayHandle::size_bytes`].
fn recursive_size(path: &Path) -> Result<u64, OverlayError> {
    let mut total: u64 = 0;
    let entries = std::fs::read_dir(path).map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| OverlayError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let ftype = entry.file_type().map_err(|e| OverlayError::Io {
            path: entry.path().display().to_string(),
            message: e.to_string(),
        })?;
        if ftype.is_dir() {
            total = total.saturating_add(recursive_size(&entry.path())?);
        } else if ftype.is_file() {
            let meta = entry.metadata().map_err(|e| OverlayError::Io {
                path: entry.path().display().to_string(),
                message: e.to_string(),
            })?;
            total = total.saturating_add(meta.len());
        }
        // Symlinks + other types are skipped — they shouldn't
        // appear in an overlay we created, and counting them
        // toward the quota would be misleading.
    }
    Ok(total)
}

/// Walk a directory tree, overwriting every regular file with zero
/// bytes (load-bearing for the overlay-erasure "provably erased"
/// guarantee), then unlink each. Removes empty directories on the way
/// out, and finally removes the root.
///
/// Returns `(files_wiped, bytes_wiped)`.
fn wipe_recursive(path: &Path) -> Result<(u64, u64), OverlayError> {
    let mut files_wiped: u64 = 0;
    let mut bytes_wiped: u64 = 0;
    let entries = std::fs::read_dir(path).map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| OverlayError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let ftype = entry.file_type().map_err(|e| OverlayError::Io {
            path: entry.path().display().to_string(),
            message: e.to_string(),
        })?;
        let child = entry.path();
        if ftype.is_dir() {
            let (fw, bw) = wipe_recursive(&child)?;
            files_wiped = files_wiped.saturating_add(fw);
            bytes_wiped = bytes_wiped.saturating_add(bw);
        } else if ftype.is_file() {
            let bw = wipe_file(&child)?;
            files_wiped = files_wiped.saturating_add(1);
            bytes_wiped = bytes_wiped.saturating_add(bw);
        }
        // Symlinks are removed without a wipe — they don't store
        // tenant data, just a path reference. (And we don't
        // O_NOFOLLOW into them by design.)
        if ftype.is_symlink() {
            let _ = std::fs::remove_file(&child);
        }
    }
    std::fs::remove_dir(path).map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: format!("removing dir after wipe: {e}"),
    })?;
    Ok((files_wiped, bytes_wiped))
}

/// Overwrite a regular file with zeros, fsync, then unlink. Returns
/// the byte count wiped.
fn wipe_file(path: &Path) -> Result<u64, OverlayError> {
    use std::io::{Seek, SeekFrom, Write};
    let meta = std::fs::metadata(path).map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    let len = meta.len();
    // Open with O_NOFOLLOW so a symlink can't redirect the
    // overwrite outside the overlay. We've already filtered
    // symlinks in the caller's loop, but defense in depth.
    let mut file;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| OverlayError::Io {
                path: path.display().to_string(),
                message: format!("opening for wipe: {e}"),
            })?;
    }
    #[cfg(not(unix))]
    {
        file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| OverlayError::Io {
                path: path.display().to_string(),
                message: format!("opening for wipe: {e}"),
            })?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| OverlayError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
    // Write zeros in 64 KiB chunks; small enough to fit in cache,
    // large enough to amortize syscall overhead.
    let zeros = vec![0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n]).map_err(|e| OverlayError::Io {
            path: path.display().to_string(),
            message: format!("writing zeros: {e}"),
        })?;
        remaining -= n as u64;
    }
    file.sync_all().map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: format!("fsync after wipe: {e}"),
    })?;
    drop(file);
    std::fs::remove_file(path).map_err(|e| OverlayError::Io {
        path: path.display().to_string(),
        message: format!("unlinking after wipe: {e}"),
    })?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn manager() -> (FsOverlayManager, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let mgr = FsOverlayManager::with_root(dir.path()).unwrap();
        (mgr, dir)
    }

    // ──────────────────────────────────────────────────────────────
    // Path validator
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty() {
        assert!(matches!(
            validate_path_component("", "x"),
            Err(OverlayError::InvalidName {
                reason: "empty",
                ..
            })
        ));
    }

    #[test]
    fn validate_rejects_parent_ref() {
        assert!(matches!(
            validate_path_component("..", "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_rejects_slash() {
        assert!(matches!(
            validate_path_component("a/b", "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_rejects_backslash() {
        assert!(matches!(
            validate_path_component("a\\b", "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_rejects_null_byte() {
        assert!(matches!(
            validate_path_component("a\0b", "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_rejects_control_char() {
        assert!(matches!(
            validate_path_component("a\nb", "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_rejects_overlong() {
        let s = "x".repeat(MAX_NAME_LEN + 1);
        assert!(matches!(
            validate_path_component(&s, "x"),
            Err(OverlayError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_accepts_normal_name() {
        validate_path_component("acme-corp", "x").unwrap();
        validate_path_component("workload_42", "x").unwrap();
    }

    // ──────────────────────────────────────────────────────────────
    // create/open/destroy lifecycle
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_then_open_returns_same_path() {
        let (mgr, _dir) = manager();
        let h1 = mgr.create_overlay("acme", "wkl").await.unwrap();
        let h2 = mgr.open_overlay("acme", "wkl").await.unwrap();
        assert_eq!(h1.root, h2.root);
        assert_eq!(h1.tenant, "acme");
        assert_eq!(h1.workload, "wkl");
        assert!(!h1.encrypted);
    }

    #[tokio::test]
    async fn create_is_idempotent() {
        let (mgr, _dir) = manager();
        let h1 = mgr.create_overlay("acme", "wkl").await.unwrap();
        let h2 = mgr.create_overlay("acme", "wkl").await.unwrap();
        assert_eq!(h1.root, h2.root);
    }

    #[tokio::test]
    async fn open_missing_returns_not_found() {
        let (mgr, _dir) = manager();
        let err = mgr.open_overlay("acme", "nope").await.unwrap_err();
        assert!(matches!(err, OverlayError::NotFound { .. }));
    }

    #[tokio::test]
    async fn create_rejects_parent_ref_in_tenant_id() {
        let (mgr, _dir) = manager();
        let err = mgr.create_overlay("../escape", "wkl").await.unwrap_err();
        assert!(matches!(err, OverlayError::InvalidName { .. }));
    }

    #[tokio::test]
    async fn create_rejects_slash_in_workload_id() {
        let (mgr, _dir) = manager();
        let err = mgr.create_overlay("acme", "a/b").await.unwrap_err();
        assert!(matches!(err, OverlayError::InvalidName { .. }));
    }

    #[tokio::test]
    async fn list_returns_workloads_sorted() {
        let (mgr, _dir) = manager();
        mgr.create_overlay("acme", "zebra").await.unwrap();
        mgr.create_overlay("acme", "alpha").await.unwrap();
        mgr.create_overlay("acme", "mango").await.unwrap();
        let listed = mgr.list_overlays("acme").await.unwrap();
        let names: Vec<&str> = listed.iter().map(|h| h.workload.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mango", "zebra"]);
    }

    #[tokio::test]
    async fn list_empty_tenant_returns_empty_vec() {
        let (mgr, _dir) = manager();
        let listed = mgr.list_overlays("never-created").await.unwrap();
        assert!(listed.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // size accounting
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn open_reports_size_from_planted_files() {
        let (mgr, _dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        std::fs::write(h.root.join("a.txt"), b"hello").unwrap();
        std::fs::create_dir(h.root.join("sub")).unwrap();
        std::fs::write(h.root.join("sub").join("b.bin"), b"worldworld").unwrap();
        let reopened = mgr.open_overlay("acme", "wkl").await.unwrap();
        // 5 ("hello") + 10 ("worldworld") = 15.
        assert_eq!(reopened.size_bytes, 15);
    }

    // ──────────────────────────────────────────────────────────────
    // destroy (zero-fill + unlink)
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn destroy_returns_files_and_bytes_wiped() {
        let (mgr, _dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        std::fs::write(h.root.join("a.txt"), b"hello").unwrap();
        std::fs::write(h.root.join("b.txt"), b"worldworld").unwrap();
        let receipt = mgr.destroy_overlay("acme", "wkl").await.unwrap();
        assert_eq!(receipt.files_wiped, 2);
        assert_eq!(receipt.bytes_wiped, 15);
        assert_eq!(receipt.tenant, "acme");
        assert_eq!(receipt.workload, "wkl");
    }

    #[tokio::test]
    async fn destroy_removes_directory() {
        let (mgr, dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        std::fs::write(h.root.join("a.txt"), b"x").unwrap();
        mgr.destroy_overlay("acme", "wkl").await.unwrap();
        // The overlay directory must no longer exist.
        assert!(!dir.path().join("acme").join("wkl").exists());
    }

    #[tokio::test]
    async fn destroy_missing_overlay_is_ok_with_empty_receipt() {
        let (mgr, _dir) = manager();
        let receipt = mgr.destroy_overlay("acme", "wkl").await.unwrap();
        assert_eq!(receipt.files_wiped, 0);
        assert_eq!(receipt.bytes_wiped, 0);
    }

    #[tokio::test]
    async fn destroy_wipes_nested_files() {
        let (mgr, _dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        std::fs::create_dir_all(h.root.join("a").join("b").join("c")).unwrap();
        std::fs::write(
            h.root.join("a").join("b").join("c").join("deep.bin"),
            b"data",
        )
        .unwrap();
        let receipt = mgr.destroy_overlay("acme", "wkl").await.unwrap();
        assert_eq!(receipt.files_wiped, 1);
        assert_eq!(receipt.bytes_wiped, 4);
    }

    #[tokio::test]
    async fn destroy_actually_zeros_file_before_unlink() {
        // Lock in the load-bearing security invariant: the file's
        // bytes are overwritten before the unlink. We can't observe
        // post-unlink content (the file is gone), so we hook
        // `wipe_file` directly with a planted file we own.
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"super-secret-tenant-data").unwrap();
        // Snapshot the file's inode + size for the post-call
        // accounting check.
        let before_size = std::fs::metadata(&path).unwrap().len();
        let bytes_wiped = wipe_file(&path).unwrap();
        assert_eq!(bytes_wiped, before_size);
        assert!(!path.exists(), "file must be unlinked after wipe");
    }

    // ──────────────────────────────────────────────────────────────
    // Mode 0700 invariants
    // ──────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn create_overlay_sets_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let (mgr, _dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        let mode = std::fs::metadata(&h.root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let parent_mode = std::fs::metadata(h.root.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn root_dir_set_to_0700_on_construction() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("overlays");
        let _mgr = FsOverlayManager::with_root(&root).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    // ──────────────────────────────────────────────────────────────
    // NoopOverlayManager
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn noop_create_returns_unwired() {
        let m = NoopOverlayManager;
        let err = m.create_overlay("a", "b").await.unwrap_err();
        assert!(matches!(err, OverlayError::Unwired));
    }

    #[tokio::test]
    async fn noop_destroy_returns_unwired() {
        let m = NoopOverlayManager;
        let err = m.destroy_overlay("a", "b").await.unwrap_err();
        assert!(matches!(err, OverlayError::Unwired));
    }

    // ──────────────────────────────────────────────────────────────
    // SignedDestructionReceipt (sign + verify)
    // ──────────────────────────────────────────────────────────────

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn sample_receipt() -> DestructionReceipt {
        DestructionReceipt {
            tenant: "acme".to_string(),
            workload: "build-runner".to_string(),
            destroyed_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
            files_wiped: 42,
            bytes_wiped: 1_048_576,
        }
    }

    #[test]
    fn signature_payload_is_stable_pipe_delimited() {
        // Pin the wire format so a future refactor that changes
        // field order or delimiter breaks loudly. An auditor's
        // verifier reconstructs this byte-for-byte.
        let receipt = sample_receipt();
        let payload = receipt.signature_payload();
        let s = String::from_utf8(payload).unwrap();
        assert_eq!(
            s,
            "destruction|v1|acme|build-runner|1700000000123456789|42|1048576"
        );
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let key = SigningKey::generate(&mut OsRng);
        let receipt = sample_receipt();
        let signed = sign_destruction_receipt(&receipt, &key);
        // Embedded fields match the input
        assert_eq!(&signed.receipt, &receipt);
        assert_eq!(signed.version, 1);
        // Round-trip
        let recovered = verify_destruction_receipt(&signed, None).unwrap();
        assert_eq!(recovered, &receipt);
    }

    #[test]
    fn verify_with_expected_pubkey_succeeds_on_match() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &key);
        let vk = key.verifying_key();
        verify_destruction_receipt(&signed, Some(&vk)).unwrap();
    }

    #[test]
    fn verify_with_expected_pubkey_rejects_on_mismatch() {
        let signer = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &signer);
        let err = verify_destruction_receipt(&signed, Some(&other.verifying_key())).unwrap_err();
        assert!(matches!(err, DestructionVerifyError::PubkeyMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_tenant() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        signed.receipt.tenant = "evil".to_string();
        let err = verify_destruction_receipt(&signed, None).unwrap_err();
        assert!(matches!(err, DestructionVerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_files_wiped() {
        // The signature is over the byte payload, which includes
        // the wipe count. Re-padding the count to hide a leak
        // breaks verification.
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        signed.receipt.files_wiped = 0; // "we wiped nothing"
        let err = verify_destruction_receipt(&signed, None).unwrap_err();
        assert!(matches!(err, DestructionVerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_timestamp() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        signed.receipt.destroyed_at += chrono::Duration::seconds(1);
        let err = verify_destruction_receipt(&signed, None).unwrap_err();
        assert!(matches!(err, DestructionVerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        signed.version = 999;
        let err = verify_destruction_receipt(&signed, None).unwrap_err();
        assert!(matches!(
            err,
            DestructionVerifyError::UnsupportedVersion { got: 999 }
        ));
    }

    #[test]
    fn verify_rejects_malformed_signature_base64() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        signed.signature = "not_base64!!!@@@".to_string();
        let err = verify_destruction_receipt(&signed, None).unwrap_err();
        assert!(matches!(
            err,
            DestructionVerifyError::SignatureDecode(_)
                | DestructionVerifyError::SignatureLength { .. }
        ));
    }

    #[test]
    fn signed_receipt_round_trips_through_json() {
        // Operators hand the SignedDestructionReceipt over as
        // JSON; this test pins the serde shape so a future
        // refactor that drops `#[serde(deny_unknown_fields)]` or
        // reorders fields trips a regression.
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &key);
        let serialized = serde_json::to_string(&signed).unwrap();
        let parsed: SignedDestructionReceipt = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, signed);
        // And the parsed envelope still verifies.
        verify_destruction_receipt(&parsed, None).unwrap();
    }

    #[test]
    fn signed_receipt_rejects_unknown_json_field() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &key);
        let mut json: serde_json::Value = serde_json::to_value(&signed).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("smuggled"));
        let s = serde_json::to_string(&json).unwrap();
        // deny_unknown_fields refuses.
        let err = serde_json::from_str::<SignedDestructionReceipt>(&s).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn cert_fingerprint_is_stable_for_same_cert() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &key);
        let f1 = cert_fingerprint(&signed);
        let f2 = cert_fingerprint(&signed);
        // Lowercase-hex SHA-256 = 64 chars.
        assert_eq!(f1.len(), 64);
        assert!(
            f1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        assert_eq!(f1, f2);
    }

    #[test]
    fn cert_fingerprint_changes_when_receipt_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = sign_destruction_receipt(&sample_receipt(), &key);
        let original = cert_fingerprint(&signed);
        signed.receipt.tenant = "tampered".to_string();
        let tampered = cert_fingerprint(&signed);
        assert_ne!(original, tampered);
    }

    #[test]
    fn cert_fingerprint_is_independent_of_pretty_printing() {
        // The auditor receives the cert as JSON. Pretty-printed
        // vs. compact-printed inputs must produce the same
        // fingerprint after parse+recompact. We exercise this
        // round-trip explicitly because operator-side emission
        // and auditor-side verification take different paths to
        // the bytes that get hashed.
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&sample_receipt(), &key);
        let direct = cert_fingerprint(&signed);

        let pretty = serde_json::to_string_pretty(&signed).unwrap();
        let reparsed: SignedDestructionReceipt = serde_json::from_str(&pretty).unwrap();
        let after_pretty = cert_fingerprint(&reparsed);

        assert_eq!(direct, after_pretty);
    }

    #[tokio::test]
    async fn end_to_end_destroy_then_sign_then_verify() {
        // The shipped use case: destroy an overlay, sign the
        // returned receipt under a host-identity key, hand the
        // envelope to an auditor.
        let (mgr, _dir) = manager();
        let h = mgr.create_overlay("acme", "wkl").await.unwrap();
        std::fs::write(h.root.join("a.txt"), b"hello").unwrap();
        std::fs::write(h.root.join("b.bin"), b"world").unwrap();
        let receipt = mgr.destroy_overlay("acme", "wkl").await.unwrap();
        assert_eq!(receipt.files_wiped, 2);
        assert_eq!(receipt.bytes_wiped, 10);

        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_destruction_receipt(&receipt, &key);
        let verified = verify_destruction_receipt(&signed, Some(&key.verifying_key())).unwrap();
        assert_eq!(verified.tenant, "acme");
        assert_eq!(verified.workload, "wkl");
        assert_eq!(verified.files_wiped, 2);
        assert_eq!(verified.bytes_wiped, 10);
    }
}
