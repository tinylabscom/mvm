//! Portable image bundle (`.mvmpkg`) — content-addressed, signed
//! archive of the artifacts needed to launch one microVM workload.
//!
//! ## Trust model (sigstore/cosign-style)
//!
//! A bundle ships a `manifest.json` listing every artifact + its
//! SHA-256, plus a detached `manifest.sig` over the canonical
//! manifest bytes. The signature is checked against a publisher
//! pubkey looked up *out of band* — concretely, from
//! `~/.mvm/trusted-publishers/<key_id>.pub` on the consumer. The
//! pubkey **never lives inside the bundle**; an attacker swapping
//! the bundle's `key_id` cannot make the bundle verify because the
//! consumer won't have that key_id in its trust store.
//!
//! `key_id` is content-derived from the publisher pubkey
//! (`sha256(pubkey_bytes)`, truncated to 32 hex chars). Truncation
//! is cosmetic: collisions in the truncated form still demand a
//! full Ed25519 key collision to subvert verification. The full
//! pubkey is what the verifier checks against.
//!
//! ## Verification flow
//!
//! 1. Read `manifest.json` + `manifest.sig` from the archive.
//! 2. Look up `<key_id>.pub` in the consumer's trust store.
//!    *Unknown `key_id` → reject before reading any artifact bytes.*
//! 3. Ed25519-verify the signature over the canonical manifest
//!    bytes. *Mismatch → reject.*
//! 4. For each artifact, re-hash its bytes and compare against the
//!    SHA-256 declared in the signed manifest. *Mismatch → reject.*
//! 5. dm-verity (ADR-002 §W3) gives independent per-block integrity
//!    inside the rootfs at boot — the bundle layer covers tamper
//!    detection at extract time.
//!
//! ## What lives in the bundle archive
//!
//! ```text
//! bundle.mvmpkg (tar)
//! ├── manifest.json       # canonical JSON, BundleManifest
//! ├── manifest.sig        # 64 raw Ed25519 signature bytes
//! └── artifacts/
//!     ├── vmlinux         # kernel
//!     ├── rootfs.ext4     # root filesystem
//!     ├── rootfs.verity   # optional dm-verity sidecar (W3)
//!     ├── fc_base_config.json
//!     └── initrd          # optional NixOS stage-1
//! ```
//!
//! The archive layout is plain tar (no gzip) because the rootfs and
//! kernel are already binary blobs that compress poorly; gzip would
//! buy little and add a transitive dep. A future `.mvmpkg.gz`
//! wrapper can layer on if size becomes a real concern.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Highest bundle-manifest schema version this build understands.
/// Verifiers fail closed on a future bump rather than silently
/// dropping fields they don't know about.
///
/// Bumped 1 → 2 in Sprint 52 W2 residual C when `BundleManifest`
/// gained the optional `resources: Option<BundleResources>`
/// field. Older verifiers `#[serde(deny_unknown_fields)]` would
/// refuse v2 bundles on the field alone, but the version sniff
/// runs first and surfaces a clear `UnsupportedSchema` error.
/// Newer verifiers reading a v1 bundle accept the missing field
/// via `#[serde(default)]` and fall back to operator-config
/// defaults at launch time.
pub const BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Filename inside the archive for the canonical-JSON manifest.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Filename inside the archive for the detached Ed25519 signature.
/// 64 raw bytes — no header, no encoding.
pub const SIGNATURE_FILENAME: &str = "manifest.sig";

/// Directory inside the archive that holds the actual artifact
/// bytes (kernel, rootfs, verity sidecar, ...).
pub const ARTIFACTS_DIR: &str = "artifacts";

/// Content-derived identifier for a publisher's Ed25519 key. Equals
/// `sha256(pubkey_bytes)` truncated to 32 hex characters.
///
/// `key_id` is the lookup token a consumer uses to find the matching
/// pubkey in its trust store. It is **not a substitute for the
/// pubkey itself**: verification always uses the full key loaded
/// from `~/.mvm/trusted-publishers/<key_id>.pub`. Truncation is for
/// filesystem readability, not cryptographic strength.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(pub String);

impl KeyId {
    /// Derive the key_id from a verifying-key's bytes.
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        let bytes = pk.to_bytes();
        let digest = Sha256::digest(bytes);
        let hex = format!("{digest:x}");
        Self(hex[..32].to_string())
    }

    /// Validation: 32 lowercase hex characters. Anything else
    /// indicates a tampered or malformed manifest.
    pub fn is_well_formed(&self) -> bool {
        self.0.len() == 32
            && self
                .0
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }
}

/// Role of an artifact inside a bundle. Verifiers + launchers use
/// this to find the kernel, rootfs, verity sidecar, etc. without
/// pinning to specific filenames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    /// Linux kernel image (`vmlinux`).
    Kernel,
    /// Root filesystem block image (ext4 or squashfs).
    Rootfs,
    /// dm-verity Merkle-hash sidecar paired with `Rootfs`. ADR-002 §W3.
    VerityHashSidecar,
    /// Firecracker base VM config JSON.
    FirecrackerBaseConfig,
    /// Initial ramdisk (NixOS stage-1 or similar).
    Initrd,
    /// Catch-all for backend-specific extras. The role consumer
    /// must inspect `name` to know what it's looking at.
    Other,
}

/// One file inside the bundle. The `path` is relative to the
/// archive root (e.g. `artifacts/vmlinux`). `sha256` is the
/// lowercase-hex digest of the file bytes — verifiers re-hash at
/// extract time and reject on mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleArtifact {
    pub name: String,
    pub role: ArtifactRole,
    /// Archive-relative path, forward-slash separated. The verifier
    /// rejects absolute paths, `..` traversal, and `\` separators.
    pub path: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    pub size_bytes: u64,
}

/// Resource expectations the bundle publisher recorded at build
/// time. Optional on the wire (`#[serde(default)]` via the parent
/// struct's `Option<BundleResources>`), present in v2+ bundles.
/// Old (`schema_version = 1`) bundles deserialise with `None` and
/// the template loader defaults to operator config.
///
/// Both fields are advisory: `mvmctl up --cpus / --memory`
/// overrides them. The point is to let a bundle ship with sensible
/// resource expectations baked in so dev-laptop users don't have
/// to remember the right values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleResources {
    /// vCPU count the workload was sized for at build time.
    pub vcpus: u32,
    /// Memory cap in MiB the workload was sized for at build time.
    pub mem_mib: u32,
}

/// dm-verity binding for the rootfs. Present when the workload was
/// built with `verifiedBoot = true` (ADR-002 §W3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerityInfo {
    /// 64-char lowercase-hex Merkle-tree root hash. Baked into the
    /// kernel cmdline as `dm-mod.create=`.
    pub roothash: String,
    /// `name` of the `VerityHashSidecar` artifact inside this
    /// bundle. Verifier matches on `name`, not `path`, so a later
    /// re-layout of the archive doesn't break the binding.
    pub sidecar_artifact: String,
}

/// Top-level signed bundle manifest. Serialised as canonical JSON
/// (via `serde_json::to_vec`); the signed bytes are exactly those.
///
/// `deny_unknown_fields` keeps the wire format strict: a future
/// field added in v2 will fail to parse in a v1 verifier. The
/// `schema_version` sniff happens *after* signature check (same
/// pattern as `ExecutionPlan`), so an attacker who flips
/// `schema_version` doesn't slip in a v2 plan past a v1 build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    /// Human-readable name for the publisher (not authoritative —
    /// trust derives from `key_id` lookup, not from this string).
    pub publisher: String,
    /// Lookup token for the publisher's Ed25519 pubkey. The full
    /// pubkey lives at `~/.mvm/trusted-publishers/<key_id>.pub` on
    /// the consumer side.
    pub key_id: KeyId,
    /// Target architecture (`x86_64`, `aarch64`). Verifiers refuse
    /// to launch a bundle whose arch doesn't match the host.
    pub arch: String,
    /// Optional kernel version string, e.g. `6.6.39`. Surfaced in
    /// `mvmctl bundle inspect` and `mvmctl doctor`; not authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Optional flake profile name the bundle was built for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Optional human-readable workload label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_label: Option<String>,
    /// ISO-8601 timestamp the bundle was sealed at.
    pub created_at: String,
    /// Free-form metadata key/value pairs. Reserved for publisher
    /// annotations; verifiers must not interpret these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Every artifact inside the archive. Order is preserved in the
    /// JSON for determinism; consumers find artifacts by `role` or
    /// `name`, not by index.
    pub artifacts: Vec<BundleArtifact>,
    /// dm-verity binding, when the rootfs was built verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verity: Option<VerityInfo>,
    /// Advisory resource expectations recorded by the publisher at
    /// build time. `Some(...)` in v2+ bundles; `None` for v1
    /// bundles (handled via `#[serde(default)]`). The template
    /// loader uses these to set defaults when `mvmctl up` doesn't
    /// pass `--cpus` / `--memory` explicitly. ADR-002 claim 9
    /// re-verify still re-hashes the field as part of the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<BundleResources>,
}

impl BundleManifest {
    /// Find an artifact by role. Returns the first match — manifests
    /// shouldn't carry two artifacts with the same role, but the
    /// schema doesn't enforce uniqueness so consumers should treat
    /// duplicates as undefined.
    pub fn find_by_role(&self, role: &ArtifactRole) -> Option<&BundleArtifact> {
        self.artifacts.iter().find(|a| &a.role == role)
    }

    /// Find an artifact by exact name.
    pub fn find_by_name(&self, name: &str) -> Option<&BundleArtifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }

    /// Canonical JSON bytes used as the signing input. Pure function;
    /// the same bytes round-trip from sign → verify.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialise BundleManifest to canonical JSON")
    }
}

/// Compute lowercase-hex SHA-256 of arbitrary bytes. Mirrors the
/// hex-digest pattern used in `mvm-core::manifest::canonical_key_for_path`.
pub fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Pin from an `ExecutionPlan` to a specific signed bundle. Captures
/// the three quantities the supervisor needs to re-verify on admit:
///
/// 1. **`bundle_sha256`** — SHA-256 of the entire archive bytes. The
///    plan's pin is "I authorise launching this exact byte string."
/// 2. **`manifest_sig_base64`** — the publisher's signature over the
///    bundle's manifest. Held in the plan so the verifier can refuse
///    the launch without trusting whatever copy of the manifest the
///    archive on disk contains.
/// 3. **`key_id`** — the publisher's key_id. Lets admission reject
///    plans whose pinning publisher isn't in the local trust store
///    *before* opening the archive.
///
/// `serde(deny_unknown_fields)` keeps the wire format strict — a
/// future field added in v2 fails closed in older builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanArtifact {
    /// Lowercase-hex SHA-256 of the entire `.mvmpkg` archive.
    pub bundle_sha256: String,
    /// Base64-encoded 64-byte Ed25519 signature over the bundle's
    /// `manifest.json` bytes. Use [`signature_from_base64`] to decode.
    pub manifest_sig_base64: String,
    /// Publisher key_id the bundle was signed under.
    pub key_id: KeyId,
}

impl PlanArtifact {
    /// Construct from raw signature bytes + bundle hash + key_id.
    pub fn new(bundle_sha256: String, sig: &[u8; 64], key_id: KeyId) -> Self {
        Self {
            bundle_sha256,
            manifest_sig_base64: signature_to_base64(sig),
            key_id,
        }
    }

    /// Decode the base64-encoded signature back to raw bytes.
    /// Returns `None` when the field is malformed.
    pub fn signature_bytes(&self) -> Option<[u8; 64]> {
        signature_from_base64(&self.manifest_sig_base64)
    }
}

/// Look up bundle archive bytes by SHA-256 at admit time.
///
/// The supervisor calls this on every admission whose `ExecutionPlan`
/// carries a `PlanArtifact`. Production impls read from
/// `~/.mvm/bundles/<bundle_sha256>.mvmpkg`; tests inject in-memory
/// resolvers. The trait stays in `mvm_plan` rather than alongside
/// `FsTrustStore` so the supervisor doesn't need a filesystem dep
/// to consume admissions.
pub trait BundleResolver: Send + Sync {
    /// Fetch the archive bytes for `bundle_sha256`. Returns
    /// `Err(MissingBundle)` when the bundle isn't cached locally;
    /// `Err(Io(_))` when it's there but unreadable.
    fn resolve(&self, bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError>;
}

/// Errors specific to bundle resolution at admit time. Distinct
/// from [`BundleVerifyError`] so the supervisor can surface
/// "we don't have the bundle locally" differently from "we have
/// it but the bytes don't verify."
#[derive(Debug, Error)]
pub enum BundleResolveError {
    #[error("no cached bundle for sha256 {bundle_sha256}")]
    MissingBundle { bundle_sha256: String },

    #[error("reading cached bundle {bundle_sha256}: {reason}")]
    Io {
        bundle_sha256: String,
        reason: String,
    },
}

/// Filesystem-backed resolver rooted at `~/.mvm/bundles/`.
/// `<bundle_sha256>.mvmpkg` is the on-disk filename — content-
/// addressed so two bundles with the same bytes share a cache
/// entry. The cache is populated by `mvmctl bundle fetch` once
/// the registry-replacement follow-up lands; until then,
/// publishers write the file by hand.
pub struct FsBundleResolver {
    root: PathBuf,
}

impl FsBundleResolver {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Default path: `~/.mvm/bundles/`. Same shape as
    /// `FsTrustStore::default_path` so admission code can resolve
    /// both with no extra plumbing.
    pub fn default_path() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot resolve bundle cache"))?;
        let p = PathBuf::from(home).join(".mvm").join("bundles");
        Ok(Self::new(p))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl BundleResolver for FsBundleResolver {
    fn resolve(&self, bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
        let path = self.root.join(format!("{bundle_sha256}.mvmpkg"));
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BundleResolveError::MissingBundle {
                    bundle_sha256: bundle_sha256.to_string(),
                })
            }
            Err(e) => Err(BundleResolveError::Io {
                bundle_sha256: bundle_sha256.to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// BundleRegistry — content-addressed installed-bundle layout
// ---------------------------------------------------------------------------

/// A bundle that has been verified and extracted onto disk under
/// `~/.mvm/bundles/<bundle_sha256>/`. Holds the artifact root path
/// plus the parsed manifest so callers can resolve per-role
/// artifact paths without re-reading the JSON.
///
/// Returned by [`BundleRegistry::install`] and
/// [`BundleRegistry::find`]. Drop is a no-op — installs persist
/// across processes; cleanup is the caller's job (typically a
/// future `mvmctl bundle gc`).
#[derive(Debug, Clone)]
pub struct InstalledBundle {
    /// Lowercase-hex SHA-256 of the archive bytes the bundle was
    /// installed from. Equal to the directory name under the
    /// registry root.
    pub sha256: String,
    /// Directory holding the extracted manifest + artifacts. The
    /// `manifest.json` / `manifest.sig` / `artifacts/*` files live
    /// inside this directory.
    pub root: PathBuf,
    /// Parsed manifest, recovered from the extract. Cheap to clone
    /// because the manifest is small (kilobytes at most).
    pub manifest: BundleManifest,
}

impl InstalledBundle {
    /// Find an artifact by role inside the install directory.
    /// Returns the absolute filesystem path; the file existence check
    /// is the caller's responsibility (the manifest's per-artifact
    /// sha256 was already verified at install time, so reading the
    /// file is safe to assume).
    pub fn path_for_role(&self, role: &ArtifactRole) -> Option<PathBuf> {
        self.manifest
            .find_by_role(role)
            .map(|a| self.root.join(&a.path))
    }

    /// Same as [`path_for_role`](Self::path_for_role) but keyed by
    /// the artifact's `name` field. Useful for verity sidecars
    /// whose role is `VerityHashSidecar` but whose binding to the
    /// rootfs is named-not-roled.
    pub fn path_for_name(&self, name: &str) -> Option<PathBuf> {
        self.manifest
            .find_by_name(name)
            .map(|a| self.root.join(&a.path))
    }
}

/// Errors specific to bundle install.
#[derive(Debug, Error)]
pub enum BundleInstallError {
    #[error("bundle archive failed verification: {0}")]
    Verify(#[source] BundleVerifyError),

    #[error("filesystem error installing bundle {bundle_sha256}: {reason}")]
    Io {
        bundle_sha256: String,
        reason: String,
    },

    #[error("bundle {bundle_sha256} is already installed; pass `force` to overwrite")]
    AlreadyInstalled { bundle_sha256: String },
}

/// Content-addressed registry of installed bundles. Each entry is a
/// directory keyed by `<bundle_sha256>` containing the verified
/// manifest, signature, and extracted artifacts. The registry sits
/// next to the archive cache that [`FsBundleResolver`] reads —
/// installs write both the original `<sha>.mvmpkg` (for re-fetch
/// /verify) and the unpacked `<sha>/` (for template loading).
///
/// Install is atomic: extraction happens into a `<sha>.partial/`
/// staging dir; only after every artifact landed does the rename
/// to `<sha>/` happen. Crash mid-install leaves either no entry
/// or the previous entry — never half an install.
pub struct BundleRegistry {
    root: PathBuf,
}

impl BundleRegistry {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Default path: `~/.mvm/bundles/`. Same root [`FsBundleResolver`]
    /// uses — the archive (`<sha>.mvmpkg`) and the unpacked
    /// directory (`<sha>/`) cohabit under one tree.
    pub fn default_path() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            anyhow::anyhow!("$HOME is not set; cannot resolve bundle registry root")
        })?;
        let p = PathBuf::from(home).join(".mvm").join("bundles");
        Ok(Self::new(p))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute path to the archive cache file for a given sha256.
    pub fn archive_path(&self, bundle_sha256: &str) -> PathBuf {
        self.root.join(format!("{bundle_sha256}.mvmpkg"))
    }

    /// Absolute path to the extracted-bundle directory for a given
    /// sha256.
    pub fn install_dir(&self, bundle_sha256: &str) -> PathBuf {
        self.root.join(bundle_sha256)
    }

    /// Install a verified archive into the registry. Verifies the
    /// archive against `trust`, extracts every declared artifact
    /// atomically (stage to `<sha>.partial/`, rename to `<sha>/`),
    /// and writes the archive bytes to `<sha>.mvmpkg` so a later
    /// `BundleResolver::resolve` finds them.
    ///
    /// Idempotent when `force == false`: if `<sha>/` already exists
    /// the call returns `AlreadyInstalled`. `force == true` removes
    /// the existing install and replaces it.
    pub fn install(
        &self,
        archive_bytes: &[u8],
        trust: &dyn TrustStore,
        force: bool,
    ) -> Result<InstalledBundle, BundleInstallError> {
        let verified =
            read_and_verify_bundle(archive_bytes, trust).map_err(BundleInstallError::Verify)?;
        let sha = bundle_sha256(archive_bytes);

        let install_dir = self.install_dir(&sha);
        if install_dir.exists() {
            if !force {
                return Err(BundleInstallError::AlreadyInstalled {
                    bundle_sha256: sha.clone(),
                });
            }
            std::fs::remove_dir_all(&install_dir).map_err(|e| BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason: format!(
                    "removing existing install at {}: {e}",
                    install_dir.display()
                ),
            })?;
        }

        // Ensure the registry root exists with tight perms — same
        // shape as the trust store directory.
        std::fs::create_dir_all(&self.root).map_err(|e| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason: format!("creating registry root {}: {e}", self.root.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&self.root) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(&self.root, perms);
            }
        }

        // Stage extracts into <sha>.partial/. A previous crash
        // could have left this dir behind; remove it first.
        let staging = self.root.join(format!("{sha}.partial"));
        if staging.exists() {
            std::fs::remove_dir_all(&staging).map_err(|e| BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason: format!("removing stale staging at {}: {e}", staging.display()),
            })?;
        }
        std::fs::create_dir_all(&staging).map_err(|e| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason: format!("creating staging dir {}: {e}", staging.display()),
        })?;

        // Write manifest.json + manifest.sig + each artifact into
        // the staging dir. `verified.artifacts` is keyed by the
        // archive-relative path the verifier already validated as
        // safe — direct join is OK.
        let manifest_bytes =
            verified
                .manifest
                .canonical_bytes()
                .map_err(|e| BundleInstallError::Io {
                    bundle_sha256: sha.clone(),
                    reason: format!("re-serialising manifest: {e:#}"),
                })?;
        write_into(&staging, MANIFEST_FILENAME, &manifest_bytes, &sha)?;

        // Recover the signature blob from the original archive —
        // verified.artifacts doesn't carry it as an entry, but the
        // tar does.
        let sig_bytes = read_signature_from_archive(archive_bytes).map_err(|reason| {
            BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason,
            }
        })?;
        write_into(&staging, SIGNATURE_FILENAME, &sig_bytes, &sha)?;

        for (rel_path, bytes) in &verified.artifacts {
            write_into(&staging, rel_path, bytes, &sha)?;
        }

        // Promote the staging dir to its final name. `rename` is
        // atomic on POSIX within the same filesystem; the registry
        // root lives inside `~/.mvm/` so this is always within
        // `$HOME`'s filesystem in practice.
        std::fs::rename(&staging, &install_dir).map_err(|e| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason: format!(
                "promoting staging {} → install {}: {e}",
                staging.display(),
                install_dir.display()
            ),
        })?;

        // Also persist the archive bytes so FsBundleResolver finds
        // them. Atomic via NamedTempFile + persist.
        let archive_path = self.archive_path(&sha);
        let mut tmp =
            tempfile::NamedTempFile::new_in(&self.root).map_err(|e| BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason: format!("creating archive tempfile: {e}"),
            })?;
        std::io::Write::write_all(tmp.as_file_mut(), archive_bytes).map_err(|e| {
            BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason: format!("writing archive bytes: {e}"),
            }
        })?;
        tmp.persist(&archive_path)
            .map_err(|e| BundleInstallError::Io {
                bundle_sha256: sha.clone(),
                reason: format!(
                    "persisting archive {} → {}: {e}",
                    e.file.path().display(),
                    archive_path.display()
                ),
            })?;

        Ok(InstalledBundle {
            sha256: sha,
            root: install_dir,
            manifest: verified.manifest,
        })
    }

    /// Remove an installed bundle. Best-effort symmetric to
    /// [`install`](Self::install): unlinks both the
    /// `<sha>.mvmpkg` cached archive AND the extracted
    /// `<sha>/` directory. Idempotent on already-absent entries
    /// (returns `Ok(false)`); returns `Ok(true)` when at least
    /// one of the two artifacts was found and removed.
    ///
    /// Reports IO failures verbatim. Partial cleanup is possible
    /// (archive removed but directory removal raced an open file);
    /// the caller's audit log should reflect the *attempt*, not
    /// the success — the next install of the same sha will refuse
    /// (or overwrite with `force`) cleanly either way.
    pub fn remove(&self, bundle_sha256: &str) -> anyhow::Result<bool> {
        let mut removed_any = false;

        let archive = self.archive_path(bundle_sha256);
        match std::fs::remove_file(&archive) {
            Ok(()) => removed_any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "removing archive {}: {e}",
                    archive.display()
                ));
            }
        }

        let dir = self.install_dir(bundle_sha256);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => removed_any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "removing install dir {}: {e}",
                    dir.display()
                ));
            }
        }

        Ok(removed_any)
    }

    /// List the bundle sha256s currently installed under the
    /// registry root. Returns sorted output so consumers (CLI
    /// listing, `bundle gc --all`) see deterministic order.
    /// Skips entries that don't look like a bundle install
    /// (anything other than a 64-lowercase-hex directory).
    pub fn list(&self) -> anyhow::Result<Vec<String>> {
        let mut out = Vec::new();
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "reading registry root {}: {e}",
                    self.root.display()
                ));
            }
        };
        for entry in read_dir.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // Bundle sha is 64 lowercase hex chars; staging dirs
            // (`<sha>.partial/`) and archive files don't match.
            if name.len() == 64
                && name
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
            {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Resolve an installed bundle by sha256. Returns `Ok(None)`
    /// when the entry isn't present (the caller often wants to
    /// fall through to a different lookup); errors only on I/O
    /// or corrupt-manifest cases.
    pub fn find(&self, bundle_sha256: &str) -> anyhow::Result<Option<InstalledBundle>> {
        let dir = self.install_dir(bundle_sha256);
        if !dir.exists() {
            return Ok(None);
        }
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let bytes = std::fs::read(&manifest_path).map_err(|e| {
            anyhow::anyhow!(
                "reading installed bundle manifest at {}: {e}",
                manifest_path.display()
            )
        })?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "parsing installed bundle manifest at {}: {e}",
                manifest_path.display()
            )
        })?;
        Ok(Some(InstalledBundle {
            sha256: bundle_sha256.to_string(),
            root: dir,
            manifest,
        }))
    }
}

/// Write a single file under `dir` atomically. Used by
/// [`BundleRegistry::install`] for every staged artifact + the
/// manifest + the signature.
fn write_into(
    dir: &Path,
    rel_path: &str,
    bytes: &[u8],
    bundle_sha256: &str,
) -> Result<(), BundleInstallError> {
    let target = dir.join(rel_path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BundleInstallError::Io {
            bundle_sha256: bundle_sha256.to_string(),
            reason: format!("creating {}: {e}", parent.display()),
        })?;
    }
    std::fs::write(&target, bytes).map_err(|e| BundleInstallError::Io {
        bundle_sha256: bundle_sha256.to_string(),
        reason: format!("writing {}: {e}", target.display()),
    })
}

/// Read just the signature blob from a `.mvmpkg` archive without
/// going through the full verification pass. Used by
/// [`BundleRegistry::install`] to copy the signature into the
/// extracted directory.
fn read_signature_from_archive(archive: &[u8]) -> Result<Vec<u8>, String> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if path == SIGNATURE_FILENAME {
            let mut bytes = Vec::with_capacity(64);
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|e| e.to_string())?;
            return Ok(bytes);
        }
    }
    Err(format!("{SIGNATURE_FILENAME} not present in archive"))
}

/// Verify a plan's pinned bundle at admit time.
///
/// Runs the full [`read_and_verify_bundle`] rejection ladder against
/// the resolved archive bytes, then cross-checks the resulting
/// `bundle_sha256` + `manifest_sig` + `key_id` against the plan's
/// pin. Any mismatch is a refusal — the plan was signed against a
/// bundle that doesn't match what's on disk now.
///
/// Failure modes (any one rejects the admission):
/// - **Pin missing locally**: the supervisor has no cached bundle
///   matching `pin.bundle_sha256` (resolver returns `MissingBundle`).
/// - **Trust store doesn't know the publisher**: same as fetch-time
///   `UnknownKey`.
/// - **Manifest signature doesn't verify**: same as fetch-time
///   `SignatureInvalid`.
/// - **Per-artifact hash mismatch**: same as fetch-time
///   `ArtifactSha256Mismatch`.
/// - **Pin-archive mismatch**: the archive's sha256 doesn't equal
///   `pin.bundle_sha256`. Means the resolver returned the wrong
///   bytes (cache poisoning) or someone tampered with the archive
///   between fetch and admit.
/// - **Pin-signature mismatch**: the archive's signature differs
///   from `pin.manifest_sig_base64`. Means the publisher re-signed
///   the same content with a different envelope — the plan was
///   admitting a specific instance, not just any bundle with the
///   same bytes.
/// - **Pin-key_id mismatch**: the archive declares a different
///   publisher than the plan pinned. Forged-publisher case.
pub fn verify_plan_bundle(
    pin: &PlanArtifact,
    resolver: &dyn BundleResolver,
    trust: &dyn TrustStore,
) -> Result<VerifiedBundle, PlanBundleError> {
    let archive = resolver
        .resolve(&pin.bundle_sha256)
        .map_err(PlanBundleError::Resolve)?;

    let actual_sha = sha256_hex(&archive);
    if actual_sha != pin.bundle_sha256 {
        return Err(PlanBundleError::BundleSha256Mismatch {
            pinned: pin.bundle_sha256.clone(),
            actual: actual_sha,
        });
    }

    let verified = read_and_verify_bundle(&archive, trust).map_err(PlanBundleError::Verify)?;

    if verified.key_id != pin.key_id {
        return Err(PlanBundleError::KeyIdMismatch {
            pinned: pin.key_id.0.clone(),
            actual: verified.key_id.0.clone(),
        });
    }

    // Recover the signature bytes from the archive and compare
    // against the plan's pin. The archive's bytes are the ground
    // truth here; the plan's `manifest_sig_base64` is the
    // assertion. read_and_verify_bundle has already proven the
    // signature is valid; we additionally require it to match the
    // pin so a publisher who re-signs the same content with a new
    // envelope can't satisfy an old plan.
    let archive_sig =
        extract_manifest_signature(&archive).map_err(|reason| PlanBundleError::SignatureRead {
            reason: reason.to_string(),
        })?;
    let pin_sig = pin
        .signature_bytes()
        .ok_or_else(|| PlanBundleError::SignatureRead {
            reason: "plan's pinned signature is not valid base64 or wrong length".to_string(),
        })?;
    if archive_sig != pin_sig {
        return Err(PlanBundleError::SignatureMismatch);
    }

    Ok(verified)
}

/// Errors specific to plan-bundle admission. Wraps the lower-level
/// [`BundleVerifyError`] + [`BundleResolveError`] so a supervisor
/// can branch on "resolver couldn't find the bytes" vs "bytes
/// found but the pin says they shouldn't be these."
#[derive(Debug, Error)]
pub enum PlanBundleError {
    #[error("could not resolve pinned bundle: {0}")]
    Resolve(#[source] BundleResolveError),

    #[error("bundle verification failed: {0}")]
    Verify(#[source] BundleVerifyError),

    #[error("pinned bundle sha256 mismatch: plan pinned {pinned}, archive is {actual}")]
    BundleSha256Mismatch { pinned: String, actual: String },

    #[error("pinned key_id mismatch: plan pinned {pinned}, archive declares {actual}")]
    KeyIdMismatch { pinned: String, actual: String },

    #[error(
        "pinned signature does not match archive signature — bundle was re-signed since the plan was issued"
    )]
    SignatureMismatch,

    #[error("could not read manifest signature from archive: {reason}")]
    SignatureRead { reason: String },
}

/// Pull the 64-byte manifest signature out of a `.mvmpkg` tar
/// archive without going through the full verification path.
/// Used by [`verify_plan_bundle`] to compare against the plan's
/// pin. Errors carry the reason as a string so the calling code
/// can surface it without owning the underlying io::Error.
fn extract_manifest_signature(archive: &[u8]) -> Result<[u8; 64], String> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if path == SIGNATURE_FILENAME {
            let mut bytes = Vec::with_capacity(64);
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|e| e.to_string())?;
            return bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("signature blob is {} bytes; expected 64", bytes.len()));
        }
    }
    Err(format!("{SIGNATURE_FILENAME} not present in archive"))
}

/// Errors that can fall out of bundle verification.
///
/// Each variant carries enough detail to debug a specific failure
/// without exposing artifact bytes to log sinks.
#[derive(Debug, Error)]
pub enum BundleVerifyError {
    #[error("trust store has no entry for key_id {key_id}")]
    UnknownKey { key_id: String },

    #[error("publisher key file at {path} is malformed: {reason}")]
    MalformedPubkey { path: PathBuf, reason: String },

    #[error("signature does not verify under trusted key {key_id}: {reason}")]
    SignatureInvalid { key_id: String, reason: String },

    #[error("schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("manifest JSON parse failed: {0}")]
    ManifestParse(String),

    #[error("manifest declares key_id {declared} but trust store entry is for {actual}")]
    KeyIdMismatch { declared: String, actual: String },

    #[error("artifact {name} sha256 mismatch: manifest says {declared}, actual {actual}")]
    ArtifactSha256Mismatch {
        name: String,
        declared: String,
        actual: String,
    },

    #[error("artifact {name} size mismatch: manifest says {declared}, actual {actual}")]
    ArtifactSizeMismatch {
        name: String,
        declared: u64,
        actual: u64,
    },

    #[error(
        "archive entry path is unsafe: {path:?} (absolute paths, `..` traversal, and \
         backslash separators are rejected)"
    )]
    UnsafePath { path: String },

    #[error("manifest references artifact {name} but it is missing from the archive")]
    ArtifactMissing { name: String },

    #[error("signature blob is the wrong size: expected 64 bytes, got {got}")]
    MalformedSignature { got: usize },
}

/// Validate that an archive-relative path is safe to extract: no
/// absolute roots, no `..` traversal, no backslash separators.
///
/// Returns `Ok(())` if safe; `BundleVerifyError::UnsafePath`
/// otherwise. Surfaced as a free function so the archive reader and
/// the manifest validator both apply the same rule.
pub fn ensure_safe_path(path: &str) -> Result<(), BundleVerifyError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|seg| seg == ".." || seg == ".")
    {
        return Err(BundleVerifyError::UnsafePath {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Build a sealed bundle archive from manifest + artifact byte blobs.
///
/// The caller supplies the manifest (already populated with per-
/// artifact sha256s and sizes) and an iterator yielding
/// `(archive_relative_path, bytes)` pairs for each artifact. The
/// manifest is signed inside this function so the signature lines up
/// exactly with the canonical bytes that get written.
///
/// Returns the full archive bytes as a `Vec<u8>` — the caller is
/// responsible for writing them out. In-memory representation
/// matches the on-disk archive byte-for-byte.
pub fn write_bundle(
    manifest: &BundleManifest,
    signing_key: &SigningKey,
    mut artifacts: Vec<(String, Vec<u8>)>,
) -> Result<Vec<u8>> {
    // Defensive: the manifest must declare the same key_id the
    // signing key would derive. Mismatch is a publisher bug, not a
    // verifier concern, but catching it at write-time stops bad
    // bundles from ever leaving the build host.
    let derived = KeyId::from_pubkey(&signing_key.verifying_key());
    anyhow::ensure!(
        manifest.key_id == derived,
        "manifest key_id ({}) does not match signing key derivation ({})",
        manifest.key_id.0,
        derived.0
    );

    // Same defensive check for declared sha256 vs actual bytes.
    for (path, bytes) in &artifacts {
        let art = manifest
            .artifacts
            .iter()
            .find(|a| a.path == *path)
            .with_context(|| {
                format!("archive contains {path:?} not declared in manifest.artifacts")
            })?;
        let actual = sha256_hex(bytes);
        anyhow::ensure!(
            art.sha256 == actual,
            "artifact {} sha256 mismatch at write time: manifest {}, actual {}",
            art.name,
            art.sha256,
            actual,
        );
        anyhow::ensure!(
            art.size_bytes == bytes.len() as u64,
            "artifact {} size mismatch at write time: manifest {}, actual {}",
            art.name,
            art.size_bytes,
            bytes.len(),
        );
        ensure_safe_path(path).context("artifact path validation")?;
    }

    let manifest_bytes = manifest.canonical_bytes()?;
    let sig: Signature = signing_key.sign(&manifest_bytes);
    let sig_bytes = sig.to_bytes();

    let mut tar_buf = Cursor::new(Vec::<u8>::new());
    {
        let mut tar = tar::Builder::new(&mut tar_buf);

        // manifest.json first so a partial-read consumer can find it
        // without scanning the whole archive.
        append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes)?;
        append_bytes(&mut tar, SIGNATURE_FILENAME, &sig_bytes)?;

        // Artifacts in manifest order — deterministic output.
        artifacts.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (path, bytes) in &artifacts {
            append_bytes(&mut tar, path, bytes)?;
        }
        tar.finish().context("finalise tar archive")?;
    }

    Ok(tar_buf.into_inner())
}

fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .with_context(|| format!("write tar entry {path:?}"))
}

/// Lookup interface for finding a publisher's verifying key by `key_id`.
///
/// Production impl reads `~/.mvm/trusted-publishers/<key_id>.pub`;
/// tests inject an in-memory map. Kept narrow so the verifier
/// doesn't grow a filesystem dependency.
pub trait TrustStore {
    /// Return the verifying key for `key_id`, or `None` if the
    /// consumer has not enrolled this publisher.
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey>;
}

/// Filesystem-backed trust store rooted at `~/.mvm/trusted-publishers/`
/// (or any directory). Pubkey files are named `<key_id>.pub` and
/// hold the 32 raw Ed25519 public-key bytes (no PEM, no headers).
///
/// Production consumers populate this via `mvmctl trust add`
/// (shipped in a follow-up). For now the format is documented here
/// so out-of-band enrolment via plain file copy works too.
pub struct FsTrustStore {
    root: PathBuf,
}

impl FsTrustStore {
    /// Construct rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Default path: `~/.mvm/trusted-publishers/`. Errors when
    /// `$HOME` is unset.
    pub fn default_path() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot resolve trust store"))?;
        let p = PathBuf::from(home).join(".mvm").join("trusted-publishers");
        Ok(Self::new(p))
    }

    /// Underlying directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl TrustStore for FsTrustStore {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        if !key_id.is_well_formed() {
            return None;
        }
        let path = self.root.join(format!("{}.pub", key_id.0));
        let bytes = std::fs::read(&path).ok()?;
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }
}

/// Verified bundle handle: the parsed manifest, the bytes for each
/// artifact, and the `key_id` that signed it.
///
/// Returned by [`read_and_verify_bundle`]. Holding this value is
/// proof the signature checked and every artifact's hash matched
/// the manifest — consumers can use the contents directly without
/// re-verifying.
#[derive(Debug)]
pub struct VerifiedBundle {
    pub manifest: BundleManifest,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub key_id: KeyId,
}

/// Read a bundle archive, look the publisher up in the trust store,
/// verify the signature, then re-hash every artifact against the
/// signed manifest. Returns a [`VerifiedBundle`] on success.
///
/// All four failure modes ([`BundleVerifyError::UnknownKey`],
/// `SignatureInvalid`, `ArtifactSha256Mismatch`, `UnsafePath`)
/// reject *before* the artifact bytes are exposed to anything
/// outside this function's local scope. The bytes ARE held in
/// memory during the size+hash pass; production callers that need
/// streaming verification of multi-GiB rootfs files will want a
/// chunked extractor (Phase 2).
pub fn read_and_verify_bundle(
    archive_bytes: &[u8],
    trust_store: &dyn TrustStore,
) -> Result<VerifiedBundle, BundleVerifyError> {
    // Pass 1: pull every entry into memory. Bundles for v1 are
    // modest in size (≤ a few hundred MiB); a chunked impl can come
    // when that stops being true.
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut archive = tar::Archive::new(Cursor::new(archive_bytes));
    for entry in archive
        .entries()
        .map_err(|e| BundleVerifyError::ManifestParse(format!("tar entries() failed: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| BundleVerifyError::ManifestParse(format!("tar entry read: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| BundleVerifyError::ManifestParse(format!("tar entry path: {e}")))?
            .to_string_lossy()
            .into_owned();
        ensure_safe_path(&path)?;
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| BundleVerifyError::ManifestParse(format!("tar entry body read: {e}")))?;
        entries.insert(path, buf);
    }

    let manifest_bytes = entries
        .get(MANIFEST_FILENAME)
        .ok_or_else(|| BundleVerifyError::ManifestParse(format!("{MANIFEST_FILENAME} missing")))?
        .clone();
    let sig_bytes = entries
        .get(SIGNATURE_FILENAME)
        .ok_or_else(|| BundleVerifyError::ManifestParse(format!("{SIGNATURE_FILENAME} missing")))?
        .clone();

    // ----- Step 1: schema version sniff (pre-signature) -----
    //
    // We deliberately read schema_version *before* checking the
    // signature. If a v2 bundle ever shows up, an older verifier
    // should refuse with UnsupportedSchema, not parse-fail with a
    // misleading deny_unknown_fields error. The signature check
    // still happens before we expose any parsed plan-level fields.
    #[derive(Deserialize)]
    struct SchemaProbe {
        schema_version: u32,
    }
    let probe: SchemaProbe = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("schema_version probe failed: {e}"))
    })?;
    if probe.schema_version > BUNDLE_SCHEMA_VERSION {
        return Err(BundleVerifyError::UnsupportedSchema {
            found: probe.schema_version,
            supported: BUNDLE_SCHEMA_VERSION,
        });
    }

    // ----- Step 2: pull key_id (still pre-signature) -----
    #[derive(Deserialize)]
    struct KeyIdProbe {
        key_id: KeyId,
    }
    let key_probe: KeyIdProbe = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| BundleVerifyError::ManifestParse(format!("key_id probe failed: {e}")))?;
    let declared_key_id = key_probe.key_id;

    // ----- Step 3: trust-store lookup -----
    let pubkey =
        trust_store
            .lookup(&declared_key_id)
            .ok_or_else(|| BundleVerifyError::UnknownKey {
                key_id: declared_key_id.0.clone(),
            })?;

    // Defensive: confirm the pubkey we got back actually derives to
    // the declared key_id. Defends against a misnamed file in the
    // trust store; the trust-store file naming convention is the
    // verifier's only link from declared id to actual key.
    let actual_id = KeyId::from_pubkey(&pubkey);
    if actual_id != declared_key_id {
        return Err(BundleVerifyError::KeyIdMismatch {
            declared: declared_key_id.0,
            actual: actual_id.0,
        });
    }

    // ----- Step 4: signature check -----
    if sig_bytes.len() != 64 {
        return Err(BundleVerifyError::MalformedSignature {
            got: sig_bytes.len(),
        });
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("checked above");
    let signature = Signature::from_bytes(&sig_arr);
    pubkey.verify(&manifest_bytes, &signature).map_err(|e| {
        BundleVerifyError::SignatureInvalid {
            key_id: declared_key_id.0.clone(),
            reason: e.to_string(),
        }
    })?;

    // ----- Step 5: full manifest parse, now that the bytes are
    // proven authentic -----
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| BundleVerifyError::ManifestParse(e.to_string()))?;

    // ----- Step 6: per-artifact hash + size check -----
    let mut artifacts_out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for art in &manifest.artifacts {
        ensure_safe_path(&art.path)?;
        let bytes = entries
            .get(&art.path)
            .ok_or_else(|| BundleVerifyError::ArtifactMissing {
                name: art.name.clone(),
            })?;
        let actual_size = bytes.len() as u64;
        if actual_size != art.size_bytes {
            return Err(BundleVerifyError::ArtifactSizeMismatch {
                name: art.name.clone(),
                declared: art.size_bytes,
                actual: actual_size,
            });
        }
        let actual_sha = sha256_hex(bytes);
        if actual_sha != art.sha256 {
            return Err(BundleVerifyError::ArtifactSha256Mismatch {
                name: art.name.clone(),
                declared: art.sha256.clone(),
                actual: actual_sha,
            });
        }
        artifacts_out.insert(art.path.clone(), bytes.clone());
    }

    Ok(VerifiedBundle {
        manifest,
        artifacts: artifacts_out,
        key_id: declared_key_id,
    })
}

/// Convenience: SHA-256 of the entire archive bytes, encoded as
/// lowercase hex. The `bundle_sha256` field on
/// [`crate::plan::types::PlanArtifact`] holds this exact value, so an
/// `ExecutionPlan` can pin a specific bundle without trusting any
/// publisher metadata.
pub fn bundle_sha256(archive_bytes: &[u8]) -> String {
    sha256_hex(archive_bytes)
}

/// Base64-encode a signature for transport on a JSON wire (e.g.
/// inside an `ExecutionPlan`). Round-trips via [`signature_from_base64`].
pub fn signature_to_base64(sig: &[u8; 64]) -> String {
    B64.encode(sig)
}

/// Inverse of [`signature_to_base64`]. Returns `None` for malformed
/// input; the verifier surfaces this as `MalformedSignature`.
pub fn signature_from_base64(s: &str) -> Option<[u8; 64]> {
    let bytes = B64.decode(s).ok()?;
    bytes.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    /// In-memory trust store for tests. Production uses
    /// [`FsTrustStore`]; the trait split keeps the verifier free of
    /// filesystem I/O when exercised in unit tests.
    struct MapTrustStore(HashMap<KeyId, VerifyingKey>);
    impl TrustStore for MapTrustStore {
        fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            self.0.get(key_id).copied()
        }
    }

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_manifest(key_id: KeyId, artifacts: Vec<BundleArtifact>) -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "test-publisher".to_string(),
            key_id,
            arch: "aarch64".to_string(),
            kernel_version: Some("6.6.0".to_string()),
            profile: Some("worker".to_string()),
            workload_label: None,
            created_at: "2026-05-12T00:00:00Z".to_string(),
            labels: BTreeMap::new(),
            artifacts,
            verity: None,
            resources: None,
        }
    }

    fn art(name: &str, role: ArtifactRole, path: &str, bytes: &[u8]) -> BundleArtifact {
        BundleArtifact {
            name: name.to_string(),
            role,
            path: path.to_string(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }
    }

    fn build_bundle(sk: &SigningKey, kernel: &[u8], rootfs: &[u8]) -> Vec<u8> {
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id,
            vec![
                art("vmlinux", ArtifactRole::Kernel, "artifacts/vmlinux", kernel),
                art(
                    "rootfs.ext4",
                    ArtifactRole::Rootfs,
                    "artifacts/rootfs.ext4",
                    rootfs,
                ),
            ],
        );
        write_bundle(
            &manifest,
            sk,
            vec![
                ("artifacts/vmlinux".to_string(), kernel.to_vec()),
                ("artifacts/rootfs.ext4".to_string(), rootfs.to_vec()),
            ],
        )
        .expect("write_bundle should succeed")
    }

    fn trust(sk: &SigningKey) -> MapTrustStore {
        let mut m = HashMap::new();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        m.insert(key_id, sk.verifying_key());
        MapTrustStore(m)
    }

    #[test]
    fn key_id_is_32_hex_chars() {
        let sk = fresh_key();
        let id = KeyId::from_pubkey(&sk.verifying_key());
        assert_eq!(id.0.len(), 32);
        assert!(id.is_well_formed());
    }

    #[test]
    fn well_formed_rejects_wrong_length_and_case() {
        assert!(!KeyId("abc".to_string()).is_well_formed());
        assert!(!KeyId("X".repeat(32)).is_well_formed());
        assert!(!KeyId("g".repeat(32)).is_well_formed());
    }

    #[test]
    fn round_trip_verifies_clean() {
        let sk = fresh_key();
        let bundle = build_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
        let trust_store = trust(&sk);
        let verified = read_and_verify_bundle(&bundle, &trust_store).expect("verifies");
        assert_eq!(verified.manifest.publisher, "test-publisher");
        assert_eq!(verified.manifest.artifacts.len(), 2);
        assert_eq!(
            verified.artifacts.get("artifacts/vmlinux").unwrap(),
            b"kernel-bytes"
        );
        assert_eq!(
            verified.artifacts.get("artifacts/rootfs.ext4").unwrap(),
            b"rootfs-bytes"
        );
    }

    #[test]
    fn unknown_key_rejected_before_signature_work() {
        let sk = fresh_key();
        let bundle = build_bundle(&sk, b"k", b"r");
        let empty = MapTrustStore(HashMap::new());
        match read_and_verify_bundle(&bundle, &empty) {
            Err(BundleVerifyError::UnknownKey { .. }) => {}
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn tampered_manifest_fails_signature() {
        let sk = fresh_key();
        let mut bundle = build_bundle(&sk, b"k", b"r");
        // Flip a byte deep inside the archive — likely lands inside
        // the manifest.json entry. Some randomly-flipped byte
        // positions may instead invalidate the tar header itself,
        // in which case `read_and_verify_bundle` will surface a
        // ManifestParse error rather than SignatureInvalid; either
        // outcome is a *rejection* (the test asserts that), which
        // is the property that matters for the trust model.
        bundle[200] ^= 0x01;
        match read_and_verify_bundle(&bundle, &trust(&sk)) {
            Err(BundleVerifyError::SignatureInvalid { .. })
            | Err(BundleVerifyError::ManifestParse(_)) => {}
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_in_trust_store_rejected_as_keyid_mismatch() {
        // Publisher A signs the bundle; trust store has key A under
        // the wrong key_id (matching key B). The KeyIdMismatch guard
        // catches this before the signature check would succeed.
        let sk_a = fresh_key();
        let sk_b = fresh_key();
        let bundle = build_bundle(&sk_a, b"k", b"r");
        let mut m = HashMap::new();
        let key_id_a = KeyId::from_pubkey(&sk_a.verifying_key());
        m.insert(key_id_a, sk_b.verifying_key()); // wrong key under A's id
        let bad_store = MapTrustStore(m);
        match read_and_verify_bundle(&bundle, &bad_store) {
            Err(BundleVerifyError::KeyIdMismatch { .. }) => {}
            other => panic!("expected KeyIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_artifact_fails_hash_check() {
        // Sign cleanly, but post-sign rewrite the rootfs bytes by
        // surgically constructing an archive whose manifest declares
        // sha256(X) but whose `rootfs.ext4` entry contains Y.
        let sk = fresh_key();
        let kernel = b"kernel-bytes".to_vec();
        let real_rootfs = b"rootfs-bytes".to_vec();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id,
            vec![
                art(
                    "vmlinux",
                    ArtifactRole::Kernel,
                    "artifacts/vmlinux",
                    &kernel,
                ),
                art(
                    "rootfs.ext4",
                    ArtifactRole::Rootfs,
                    "artifacts/rootfs.ext4",
                    &real_rootfs,
                ),
            ],
        );
        // Sign over the canonical manifest bytes.
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let sig = sk.sign(&manifest_bytes);

        // Hand-roll the archive with a *different* rootfs body.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
            append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
            append_bytes(&mut tar, "artifacts/vmlinux", &kernel).unwrap();
            // 12 bytes — same length as the real rootfs, so the
            // size-check passes and the sha256 check is what
            // catches the tamper.
            append_bytes(&mut tar, "artifacts/rootfs.ext4", b"XXXXXXXXXXXX").unwrap();
            tar.finish().unwrap();
        }
        let archive = buf.into_inner();
        match read_and_verify_bundle(&archive, &trust(&sk)) {
            Err(BundleVerifyError::ArtifactSha256Mismatch { name, .. }) => {
                assert_eq!(name, "rootfs.ext4");
            }
            other => panic!("expected ArtifactSha256Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn missing_artifact_rejected() {
        let sk = fresh_key();
        let kernel = b"kernel-bytes".to_vec();
        let rootfs = b"rootfs-bytes".to_vec();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id,
            vec![
                art(
                    "vmlinux",
                    ArtifactRole::Kernel,
                    "artifacts/vmlinux",
                    &kernel,
                ),
                art(
                    "rootfs.ext4",
                    ArtifactRole::Rootfs,
                    "artifacts/rootfs.ext4",
                    &rootfs,
                ),
            ],
        );
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let sig = sk.sign(&manifest_bytes);

        // Archive omits rootfs.ext4 — manifest still lists it.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
            append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
            append_bytes(&mut tar, "artifacts/vmlinux", &kernel).unwrap();
            tar.finish().unwrap();
        }
        match read_and_verify_bundle(&buf.into_inner(), &trust(&sk)) {
            Err(BundleVerifyError::ArtifactMissing { name }) => {
                assert_eq!(name, "rootfs.ext4");
            }
            other => panic!("expected ArtifactMissing, got {other:?}"),
        }
    }

    #[test]
    fn unsafe_path_rejected_in_manifest() {
        // The path validator runs both at write time and at read
        // time. Build the archive by hand to exercise the read-time
        // branch.
        let sk = fresh_key();
        let kernel = b"k".to_vec();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id,
            vec![BundleArtifact {
                name: "evil".to_string(),
                role: ArtifactRole::Other,
                path: "../etc/passwd".to_string(),
                sha256: sha256_hex(&kernel),
                size_bytes: kernel.len() as u64,
            }],
        );
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let sig = sk.sign(&manifest_bytes);

        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
            append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
            // The tar `append_bytes` would reject `../`-prefixed
            // paths through its own validation, so we don't even
            // get to write the entry — but the manifest-declared
            // path is what we're testing.
        }
        match read_and_verify_bundle(&buf.into_inner(), &trust(&sk)) {
            Err(BundleVerifyError::UnsafePath { .. }) => {}
            // Some tar entry layouts surface this as ArtifactMissing
            // before the path scan reaches the manifest's bad path
            // (the entry was never written). Either rejection is
            // acceptable — the property is "no extraction happens
            // to ../etc/passwd."
            Err(BundleVerifyError::ArtifactMissing { .. }) => {}
            other => panic!("expected rejection of unsafe path, got {other:?}"),
        }
    }

    #[test]
    fn future_schema_version_rejected_after_load() {
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());

        // Hand-roll a manifest at SCHEMA_VERSION + 1 and sign it.
        // Use serde_json::Value so we can bump the version field
        // without changing the struct.
        let valid_manifest = make_manifest(key_id, vec![]);
        let mut value: serde_json::Value = serde_json::to_value(&valid_manifest).unwrap();
        value["schema_version"] = serde_json::Value::Number((BUNDLE_SCHEMA_VERSION + 1).into());
        let manifest_bytes = serde_json::to_vec(&value).unwrap();
        let sig = sk.sign(&manifest_bytes);

        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
            append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
            tar.finish().unwrap();
        }
        match read_and_verify_bundle(&buf.into_inner(), &trust(&sk)) {
            Err(BundleVerifyError::UnsupportedSchema { found, supported }) => {
                assert_eq!(found, BUNDLE_SCHEMA_VERSION + 1);
                assert_eq!(supported, BUNDLE_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn manifest_canonical_bytes_round_trip() {
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let m = make_manifest(
            key_id,
            vec![art("k", ArtifactRole::Kernel, "artifacts/k", b"X")],
        );
        let bytes = m.canonical_bytes().unwrap();
        let parsed: BundleManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn fs_trust_store_loads_pubkey() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let key_id = KeyId::from_pubkey(&vk);
        std::fs::write(tmp.path().join(format!("{}.pub", key_id.0)), vk.to_bytes()).unwrap();
        let store = FsTrustStore::new(tmp.path());
        let recovered = store.lookup(&key_id).expect("found");
        assert_eq!(recovered.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn fs_trust_store_misses_for_unknown_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsTrustStore::new(tmp.path());
        let bogus = KeyId("0".repeat(32));
        assert!(store.lookup(&bogus).is_none());
    }

    #[test]
    fn fs_trust_store_rejects_malformed_key_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsTrustStore::new(tmp.path());
        // A "key_id" that's the right length but wrong shape never
        // gets a filesystem lookup — the well-formedness check
        // short-circuits.
        assert!(
            store
                .lookup(&KeyId("not-hex-but-32-characters-aaaa".to_string()))
                .is_none()
        );
    }

    #[test]
    fn write_bundle_rejects_signing_key_keyid_mismatch() {
        // Manifest says key_id X but we hand a signing key for Y.
        // Caught at write time so a misconfigured publisher can't
        // ship an unverifiable bundle.
        let sk_a = fresh_key();
        let sk_b = fresh_key();
        let key_id_a = KeyId::from_pubkey(&sk_a.verifying_key());
        let manifest = make_manifest(key_id_a, vec![]);
        let err = write_bundle(&manifest, &sk_b, vec![]).expect_err("rejects");
        assert!(format!("{err:#}").contains("does not match"));
    }

    #[test]
    fn write_bundle_rejects_artifact_sha256_drift() {
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id,
            vec![BundleArtifact {
                name: "kernel".to_string(),
                role: ArtifactRole::Kernel,
                path: "artifacts/vmlinux".to_string(),
                // Wrong sha256 vs the bytes we'll hand to write_bundle.
                sha256: "0".repeat(64),
                size_bytes: 5,
            }],
        );
        let err = write_bundle(
            &manifest,
            &sk,
            vec![("artifacts/vmlinux".to_string(), b"abcde".to_vec())],
        )
        .expect_err("rejects");
        assert!(format!("{err:#}").contains("sha256 mismatch"));
    }

    #[test]
    fn bundle_sha256_is_lowercase_hex() {
        let h = bundle_sha256(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn signature_base64_round_trips() {
        let sk = fresh_key();
        let sig = sk.sign(b"some message");
        let s = signature_to_base64(&sig.to_bytes());
        let recovered = signature_from_base64(&s).unwrap();
        assert_eq!(recovered, sig.to_bytes());
    }

    #[test]
    fn plan_artifact_round_trips_and_pins_to_bundle() {
        // End-to-end: build a bundle, derive a PlanArtifact pin from
        // its hash + signature + key_id, and confirm an external
        // re-verify with just those three quantities succeeds.
        let sk = fresh_key();
        let kernel = b"kernel-bytes";
        let rootfs = b"rootfs-bytes";
        let bundle = build_bundle(&sk, kernel, rootfs);
        let store = trust(&sk);

        let verified = read_and_verify_bundle(&bundle, &store).expect("verifies");
        let key_id = verified.key_id.clone();

        // Re-extract the signature bytes from the archive so the
        // pin doesn't depend on internals.
        let mut archive = tar::Archive::new(Cursor::new(&bundle));
        let mut sig_bytes = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            if e.path().unwrap().to_string_lossy() == SIGNATURE_FILENAME {
                e.read_to_end(&mut sig_bytes).unwrap();
            }
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();

        let pin = PlanArtifact::new(bundle_sha256(&bundle), &sig_arr, key_id.clone());

        // The pin can be JSON-roundtripped and still verifies its
        // signature against the archive's manifest.json.
        let json = serde_json::to_string(&pin).unwrap();
        let parsed: PlanArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pin);
        assert_eq!(parsed.signature_bytes().unwrap(), sig_arr);
        assert_eq!(parsed.bundle_sha256, bundle_sha256(&bundle));
        assert_eq!(parsed.key_id, key_id);
    }

    #[test]
    fn plan_artifact_rejects_bad_base64_signature() {
        let pin = PlanArtifact {
            bundle_sha256: "0".repeat(64),
            manifest_sig_base64: "not-base64-!!".to_string(),
            key_id: KeyId("0".repeat(32)),
        };
        assert!(pin.signature_bytes().is_none());
    }

    /// In-memory resolver: hands back a fixed byte string regardless
    /// of what `bundle_sha256` is asked for. Tests choose what to
    /// return by constructing one of these per-test.
    struct FixedResolver(Vec<u8>);
    impl BundleResolver for FixedResolver {
        fn resolve(&self, _bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
            Ok(self.0.clone())
        }
    }

    struct MissingResolver;
    impl BundleResolver for MissingResolver {
        fn resolve(&self, bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
            Err(BundleResolveError::MissingBundle {
                bundle_sha256: bundle_sha256.to_string(),
            })
        }
    }

    /// Helper: build a bundle from a fresh key, then build a
    /// matching PlanArtifact pin pointing at the resulting archive.
    fn pin_for(sk: &SigningKey, kernel: &[u8], rootfs: &[u8]) -> (Vec<u8>, PlanArtifact) {
        let archive = build_bundle(sk, kernel, rootfs);
        let mut sig_bytes: Vec<u8> = Vec::new();
        {
            let mut a = tar::Archive::new(Cursor::new(&archive));
            for e in a.entries().unwrap() {
                let mut e = e.unwrap();
                if e.path().unwrap().to_string_lossy() == SIGNATURE_FILENAME {
                    e.read_to_end(&mut sig_bytes).unwrap();
                }
            }
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let pin = PlanArtifact::new(bundle_sha256(&archive), &sig_arr, key_id);
        (archive, pin)
    }

    #[test]
    fn verify_plan_bundle_happy_path() {
        let sk = fresh_key();
        let (archive, pin) = pin_for(&sk, b"k", b"r");
        let resolver = FixedResolver(archive);
        let store = trust(&sk);
        let verified = verify_plan_bundle(&pin, &resolver, &store).expect("verifies");
        assert_eq!(verified.manifest.artifacts.len(), 2);
    }

    #[test]
    fn verify_plan_bundle_missing_archive_is_resolve_error() {
        let sk = fresh_key();
        let (_archive, pin) = pin_for(&sk, b"k", b"r");
        let resolver = MissingResolver;
        let store = trust(&sk);
        match verify_plan_bundle(&pin, &resolver, &store) {
            Err(PlanBundleError::Resolve(BundleResolveError::MissingBundle { .. })) => {}
            other => panic!("expected MissingBundle, got {other:?}"),
        }
    }

    #[test]
    fn verify_plan_bundle_archive_bytes_mismatch_pin_refused() {
        // Resolver returns a *different* archive than the pin points
        // at. The bundle_sha256 cross-check catches it before going
        // through the full read_and_verify pass.
        let sk = fresh_key();
        let (_archive_a, pin) = pin_for(&sk, b"k1", b"r1");
        let archive_b = build_bundle(&sk, b"k2", b"r2");
        let resolver = FixedResolver(archive_b);
        let store = trust(&sk);
        match verify_plan_bundle(&pin, &resolver, &store) {
            Err(PlanBundleError::BundleSha256Mismatch { .. }) => {}
            other => panic!("expected BundleSha256Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_plan_bundle_unknown_key_in_trust_store_refused() {
        let sk = fresh_key();
        let (archive, pin) = pin_for(&sk, b"k", b"r");
        let resolver = FixedResolver(archive);
        let empty_store = MapTrustStore(std::collections::HashMap::new());
        match verify_plan_bundle(&pin, &resolver, &empty_store) {
            Err(PlanBundleError::Verify(BundleVerifyError::UnknownKey { .. })) => {}
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn verify_plan_bundle_tampered_artifact_refused() {
        // Construct a bundle signed cleanly but with a post-sign
        // surgery that swaps the rootfs bytes (same length so the
        // sha256 check is what fails, not the size check).
        let sk = fresh_key();
        let kernel = b"kernel-bytes".to_vec();
        let real_rootfs = b"rootfs-bytes".to_vec();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(
            key_id.clone(),
            vec![
                art(
                    "vmlinux",
                    ArtifactRole::Kernel,
                    "artifacts/vmlinux",
                    &kernel,
                ),
                art(
                    "rootfs.ext4",
                    ArtifactRole::Rootfs,
                    "artifacts/rootfs.ext4",
                    &real_rootfs,
                ),
            ],
        );
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let sig = sk.sign(&manifest_bytes);

        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
            append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
            append_bytes(&mut tar, "artifacts/vmlinux", &kernel).unwrap();
            append_bytes(&mut tar, "artifacts/rootfs.ext4", b"XXXXXXXXXXXX").unwrap();
            tar.finish().unwrap();
        }
        let tampered = buf.into_inner();
        // The pin records the tampered archive's sha256 — so the
        // bundle_sha256 cross-check passes, and the failure surfaces
        // inside read_and_verify_bundle as ArtifactSha256Mismatch.
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig.to_bytes());
        let pin = PlanArtifact::new(bundle_sha256(&tampered), &sig_arr, key_id);

        let resolver = FixedResolver(tampered);
        let store = trust(&sk);
        match verify_plan_bundle(&pin, &resolver, &store) {
            Err(PlanBundleError::Verify(BundleVerifyError::ArtifactSha256Mismatch { .. })) => {}
            other => panic!("expected ArtifactSha256Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_plan_bundle_signature_repinned_refused() {
        // Publisher re-signs the same content with a fresh nonce-
        // free signature. The archive verifies on its own, but the
        // plan's pin records the OLD signature; admit-time must
        // refuse because the plan was issued against a specific
        // envelope.
        let sk = fresh_key();
        let (archive_a, pin_a) = pin_for(&sk, b"k", b"r");

        // Build a second bundle with the SAME content. Manifest
        // identical → sig over manifest is identical too (Ed25519
        // is deterministic). So forging a different envelope means
        // tampering with the sig bytes specifically.
        //
        // We construct that by hand: take the clean archive, flip
        // the signature blob, and verify rejection. The pin still
        // points at archive_a's original sig; the resolver hands
        // back a tampered-sig archive.
        // Rebuild the archive via tar and flip every bit of the
        // signature blob — keeps the size at 64 (so the size check
        // passes) but the signature won't verify.
        let mut new_archive = Cursor::new(Vec::<u8>::new());
        {
            let mut a = tar::Archive::new(Cursor::new(&archive_a));
            let mut b = tar::Builder::new(&mut new_archive);
            for entry in a.entries().unwrap() {
                let mut entry = entry.unwrap();
                let path = entry.path().unwrap().to_string_lossy().into_owned();
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).unwrap();
                if path == SIGNATURE_FILENAME {
                    // Flip every bit in the signature → still 64 bytes
                    // (size check passes), still parses as Ed25519
                    // signature bytes (read_and_verify_bundle attempts
                    // to verify and fails).
                    for byte in &mut buf {
                        *byte = !*byte;
                    }
                }
                append_bytes(&mut b, &path, &buf).unwrap();
            }
            b.finish().unwrap();
        }
        let tampered = new_archive.into_inner();
        // Pin's bundle_sha256 still matches the *original* archive,
        // but the resolver is going to return the tampered one, so
        // the bundle_sha256 cross-check fires first.
        let resolver = FixedResolver(tampered);
        let store = trust(&sk);
        match verify_plan_bundle(&pin_a, &resolver, &store) {
            Err(PlanBundleError::BundleSha256Mismatch { .. }) => {}
            other => panic!("expected BundleSha256Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bundle_registry_install_roundtrip() {
        // Install a clean bundle → assert both the archive file
        // and the extracted dir exist, and that `find` recovers
        // the parsed manifest.
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
        let store = trust(&sk);

        let installed = registry
            .install(&archive, &store, false)
            .expect("install succeeds");

        // Archive file landed.
        let archive_path = registry.archive_path(&installed.sha256);
        assert!(
            archive_path.exists(),
            "archive missing at {:?}",
            archive_path
        );
        let archive_back = std::fs::read(&archive_path).unwrap();
        assert_eq!(archive_back, archive);

        // Extracted dir landed.
        let install_dir = registry.install_dir(&installed.sha256);
        assert!(install_dir.is_dir());
        assert!(install_dir.join(MANIFEST_FILENAME).exists());
        assert!(install_dir.join(SIGNATURE_FILENAME).exists());
        assert!(install_dir.join("artifacts/vmlinux").exists());
        assert!(install_dir.join("artifacts/rootfs.ext4").exists());

        // find() recovers the same handle.
        let recovered = registry
            .find(&installed.sha256)
            .expect("find succeeds")
            .expect("entry present");
        assert_eq!(recovered.sha256, installed.sha256);
        assert_eq!(recovered.manifest, installed.manifest);
    }

    #[test]
    fn bundle_registry_install_rejects_tampered_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let mut archive = build_bundle(&sk, b"k", b"r");
        archive[200] ^= 0x01; // tamper
        let store = trust(&sk);

        let err = registry
            .install(&archive, &store, false)
            .expect_err("must refuse tampered bundle");
        assert!(matches!(err, BundleInstallError::Verify(_)));

        // No partial state left behind. read_dir's first entry — if
        // any — is unexpected; clippy's `never_loop` lint flags the
        // explicit for-loop form here so the assertion uses next().
        if let Some(entry) = std::fs::read_dir(tmp.path()).unwrap().flatten().next() {
            let name = entry.file_name().into_string().unwrap();
            panic!("unexpected file in registry after refusal: {name}");
        }
    }

    #[test]
    fn bundle_registry_install_refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"k", b"r");
        let store = trust(&sk);

        registry
            .install(&archive, &store, false)
            .expect("first install");
        let err = registry
            .install(&archive, &store, false)
            .expect_err("second install without force must refuse");
        assert!(matches!(err, BundleInstallError::AlreadyInstalled { .. }));
    }

    #[test]
    fn bundle_registry_install_overwrites_with_force() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"k", b"r");
        let store = trust(&sk);

        let first = registry.install(&archive, &store, false).unwrap();
        let second = registry
            .install(&archive, &store, true)
            .expect("force install succeeds");
        assert_eq!(first.sha256, second.sha256);
        // Re-installable means the extracted dir is fresh — at
        // minimum the manifest still parses.
        assert_eq!(first.manifest, second.manifest);
    }

    #[test]
    fn bundle_registry_install_cleans_up_stale_staging() {
        // Simulate a crash mid-install by pre-creating the
        // `<sha>.partial/` staging dir with junk in it. The next
        // install must remove it and replace cleanly.
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"k", b"r");
        let store = trust(&sk);
        let sha = bundle_sha256(&archive);
        let staging = tmp.path().join(format!("{sha}.partial"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("junk"), b"left over from crash").unwrap();

        let installed = registry
            .install(&archive, &store, false)
            .expect("install survives stale staging");
        assert_eq!(installed.sha256, sha);
        // Staging dir got removed during install (rename consumed it).
        assert!(!staging.exists(), "staging dir survived install");
    }

    #[test]
    fn bundle_registry_remove_unlinks_archive_and_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"k", b"r");
        let store = trust(&sk);
        let installed = registry.install(&archive, &store, false).unwrap();
        let sha = installed.sha256.clone();

        assert!(registry.archive_path(&sha).exists());
        assert!(registry.install_dir(&sha).exists());

        let touched = registry.remove(&sha).expect("remove ok");
        assert!(touched, "should report something was removed");
        assert!(!registry.archive_path(&sha).exists());
        assert!(!registry.install_dir(&sha).exists());
    }

    #[test]
    fn bundle_registry_remove_idempotent_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let touched = registry.remove(&"a".repeat(64)).expect("remove ok");
        assert!(!touched, "no archive + no dir → returns false");
    }

    #[test]
    fn bundle_registry_list_returns_installed_shas_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let store = trust(&sk);
        // Two distinct bundles.
        let a = build_bundle(&sk, b"kA", b"rA");
        let b = build_bundle(&sk, b"kB", b"rB");
        let sha_a = registry.install(&a, &store, false).unwrap().sha256;
        let sha_b = registry.install(&b, &store, false).unwrap().sha256;

        let listed = registry.list().expect("list ok");
        assert_eq!(listed.len(), 2);
        // Sorted output.
        let mut expected = vec![sha_a.clone(), sha_b.clone()];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn bundle_registry_list_skips_non_sha_entries() {
        // Stray files / partial-install staging dirs / arbitrary
        // dot-files must not appear in the listing.
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        std::fs::write(tmp.path().join("not-a-bundle.txt"), b"junk").unwrap();
        std::fs::create_dir_all(tmp.path().join("abc.partial")).unwrap();
        std::fs::create_dir_all(tmp.path().join("XYZ".repeat(22) + "ab")).unwrap(); // wrong case
        let sk = fresh_key();
        let store = trust(&sk);
        let archive = build_bundle(&sk, b"k", b"r");
        let sha = registry.install(&archive, &store, false).unwrap().sha256;

        let listed = registry.list().expect("list ok");
        assert_eq!(listed, vec![sha]);
    }

    #[test]
    fn bundle_registry_list_empty_when_root_absent() {
        // Calling list() before any install (root doesn't exist
        // yet) returns an empty vec rather than erroring — the
        // gc verb uses this on a fresh host.
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("never-created");
        let registry = BundleRegistry::new(&absent);
        let listed = registry.list().expect("list ok");
        assert!(listed.is_empty());
    }

    #[test]
    fn bundle_registry_find_misses_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let result = registry.find(&"0".repeat(64)).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn installed_bundle_finds_artifacts_by_role_and_name() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = build_bundle(&sk, b"k", b"r");
        let store = trust(&sk);
        let installed = registry.install(&archive, &store, false).unwrap();

        let kernel = installed
            .path_for_role(&ArtifactRole::Kernel)
            .expect("kernel role present");
        assert!(kernel.ends_with("artifacts/vmlinux"));
        assert!(kernel.exists());

        let by_name = installed
            .path_for_name("rootfs.ext4")
            .expect("rootfs by name present");
        assert!(by_name.exists());

        assert!(installed.path_for_role(&ArtifactRole::Initrd).is_none());
    }

    #[test]
    fn fs_bundle_resolver_reads_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "a".repeat(64);
        let path = tmp.path().join(format!("{sha}.mvmpkg"));
        std::fs::write(&path, b"archive-bytes").unwrap();
        let resolver = FsBundleResolver::new(tmp.path());
        let bytes = resolver.resolve(&sha).expect("resolves");
        assert_eq!(bytes, b"archive-bytes");
    }

    #[test]
    fn fs_bundle_resolver_missing_file_is_missing_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let resolver = FsBundleResolver::new(tmp.path());
        match resolver.resolve(&"0".repeat(64)) {
            Err(BundleResolveError::MissingBundle { .. }) => {}
            other => panic!("expected MissingBundle, got {other:?}"),
        }
    }

    #[test]
    fn bundle_manifest_resources_round_trip_when_set() {
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let mut manifest = make_manifest(key_id, Vec::new());
        manifest.resources = Some(BundleResources {
            vcpus: 4,
            mem_mib: 2048,
        });
        let bytes = manifest.canonical_bytes().unwrap();
        let parsed: BundleManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.resources, manifest.resources);
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("\"resources\""), "got: {json}");
    }

    #[test]
    fn bundle_manifest_resources_omitted_when_none() {
        // Backwards compat: v2-built bundles whose publisher chose
        // not to declare resources still emit the manifest WITHOUT
        // an empty "resources":null object, so a v1 verifier doing
        // a "would this parse as v1?" check sees a clean wire.
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(key_id, Vec::new()); // resources: None
        let bytes = manifest.canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(
            !json.contains("resources"),
            "skip_serializing_if must elide the field: {json}"
        );
    }

    #[test]
    fn bundle_manifest_v1_loads_with_no_resources_field() {
        // Round-trip a hand-rolled v1 manifest (no `resources`
        // field) and assert it parses cleanly into the v2 struct
        // with `resources = None`. Protects against a future
        // accidental drop of `#[serde(default)]` on the field.
        let sk = fresh_key();
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let v1_json = format!(
            r#"{{
                "schema_version": 1,
                "publisher": "test",
                "key_id": "{}",
                "arch": "aarch64",
                "created_at": "2026-05-01T00:00:00Z",
                "artifacts": []
            }}"#,
            key_id.0
        );
        let parsed: BundleManifest = serde_json::from_str(&v1_json).expect("v1 parses");
        assert_eq!(parsed.schema_version, 1);
        assert!(parsed.resources.is_none());
        assert!(parsed.verity.is_none());
    }

    #[test]
    fn bundle_schema_version_is_two() {
        // Pin the current version constant — bumps are deliberate;
        // a silent rev should trip this test.
        assert_eq!(BUNDLE_SCHEMA_VERSION, 2);
    }

    #[test]
    fn plan_artifact_deny_unknown_fields() {
        // Defence in depth: an attacker bumping the schema must
        // fail closed in older verifiers.
        let json = serde_json::json!({
            "bundle_sha256": "0".repeat(64),
            "manifest_sig_base64": "AA==",
            "key_id": "0".repeat(32),
            "extra_future_field": 42,
        });
        let result: Result<PlanArtifact, _> = serde_json::from_value(json);
        assert!(result.is_err(), "deny_unknown_fields must reject");
    }
}
