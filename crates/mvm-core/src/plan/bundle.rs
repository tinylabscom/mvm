//! Portable image bundle (`.mvmpkg`) — content-addressed, signed
//! archive of the artifacts needed to launch one microVM workload.
//!
//! The DTO half — `KeyId`, `ArtifactRole`, `BundleArtifact`,
//! `BundleResources`, `VerityInfo`, `BundleManifest`, `PlanArtifact`, the
//! schema/filename consts, and the base64 signature helpers — lives in
//! `mvm_contract::plan::bundle` and is re-exported below so every existing
//! `crate::plan::bundle::X` / `mvm_core::plan::bundle::X` path keeps
//! resolving unchanged. This module carries the rest: signing, hashing,
//! tar archive I/O, the on-disk resolver/registry/trust-store, and
//! verification.
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
//! 4. Check what the manifest declares: every entry within the size caps
//!    (2 GiB each, 4 GiB in total — archive entries are counted before
//!    their bytes are read), at most one kernel command line, posture, and
//!    provenance member, a posture that agrees with the verity binding, and
//!    provenance digests that match the artifacts. *Incoherent → reject.*
//! 5. For each artifact, re-hash its bytes and compare against the
//!    SHA-256 declared in the signed manifest. *Mismatch → reject.*
//! 6. dm-verity gives independent per-block integrity inside the
//!    rootfs at boot — the bundle layer covers tamper detection at
//!    extract time.
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
//!     ├── rootfs.verity   # optional dm-verity sidecar
//!     ├── fc_base_config.json
//!     └── initrd          # optional NixOS stage-1
//! ```
//!
//! The archive layout is plain tar (no gzip) because the rootfs and
//! kernel are already binary blobs that compress poorly; gzip would
//! buy little and add a transitive dep. A future `.mvmpkg.gz`
//! wrapper can layer on if size becomes a real concern.

use std::collections::BTreeMap;
#[cfg(feature = "host-state")]
use std::collections::BTreeSet;
#[cfg(feature = "host-state")]
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
#[cfg(feature = "host-state")]
use ed25519_dalek::{Signature, Verifier};
#[cfg(feature = "host-state")]
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use mvm_contract::plan::bundle::{
    ARTIFACTS_DIR, ArtifactRole, BOOT_ASSETS_MEMBER_MIN_SCHEMA, BUNDLE_MEMBERS_MIN_SCHEMA,
    BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, BundleMember, BundleResources,
    BundleSecurityPosture, CANONICAL_LINUX_PROOF_MIN_SCHEMA, CLI_BOOT_ASSETS_MEMBER_MIN_SCHEMA,
    CanonicalLinuxProof, ENVIRONMENT_MEMBER_MIN_SCHEMA, EmbeddedCliBootAssets, KeyId,
    MANIFEST_FILENAME, MAX_BUNDLE_ENTRY_BYTES, MAX_BUNDLE_TOTAL_BYTES, MAX_KERNEL_CMDLINE_BYTES,
    PlanArtifact, SIGNATURE_FILENAME, VerityInfo, signature_from_base64, signature_to_base64,
};
pub use mvm_contract::plan::environment::{
    ApplicationService, ENVIRONMENT_DESCRIPTOR_VERSION, EnvironmentCapability,
    EnvironmentDescriptor, EnvironmentDescriptorError, EnvironmentEntrypoint, EnvironmentPolicy,
    EnvironmentVolume, SecretSlot,
};

use crate::arch::GuestArch;
use crate::image_set::{
    BackendImageSupport, HostProtocolSupport, ImageSetError, ImageSetManifest, ImageSetRequirement,
    ImageSetRole, RetiredGuestRuntimeRole, WorkloadImageProfile,
    check_workload_protocol_compatibility, require_complete, select_member, select_workload_image,
    validate_structure,
};
use crate::packs::Sha256Hex;

mod declarations;
mod lookup;
mod signer;
mod stream;
mod verify_error;
pub use declarations::{
    BundleSizeBudget, environment_network_permitted, forbidden_capabilities,
    unbound_environment_secret_slots, unsupported_environment_requirements,
};
pub use lookup::{
    BundleResolveError, BundleResolver, FsBundleResolver, FsTrustStore, LocalBundleTrustStore,
    TrustStore,
};
pub use signer::ManifestSigner;
// The streaming archive I/O half of the bundle surface (seal/verify/install)
// is host-state; the captured-canonical-inputs type stays because
// `canonical_linux::PreparedCanonicalLinux` holds one and is named by
// `vm_backend::VmStartConfig` in every build.
#[cfg(feature = "host-state")]
pub(crate) use stream::HashingWriter;
#[cfg(feature = "host-state")]
pub use stream::{
    BundlePayload, VerifiedBundleFile, capture_canonical_linux_inputs, verify_bundle_file,
    write_bundle_to,
};
pub use stream::{CapturedCanonicalLinuxInputs, MAX_IMAGE_SET_MANIFEST_BYTES};
pub use verify_error::{BundleVerifyError, ensure_safe_path};

/// Signed manifest label written by the local build front door.
pub const BUNDLE_ORIGIN_LABEL: &str = "mvm.origin";
/// Value identifying a bundle as a host-local build.
pub const LOCAL_BUILD_ORIGIN: &str = "local-build";
/// User-facing description of local-build authority.
pub const LOCAL_BUILD_NOTICE: &str = "local build, signed by this host's key; not release-verified";

/// Trust class derived from both the signed manifest and consumer-owned keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleOrigin {
    /// The signing key is enrolled in the consumer trust store.
    ReleaseVerified,
    /// The bundle carries the local-build label and this host signed it.
    LocalBuild,
    /// The bundle has no admissible release or host-local identity.
    Untrusted,
}

/// Mark a manifest produced by the local build front door.
pub fn mark_local_build(manifest: &mut BundleManifest) {
    manifest.labels.insert(
        BUNDLE_ORIGIN_LABEL.to_string(),
        LOCAL_BUILD_ORIGIN.to_string(),
    );
}

/// Classify a bundle without granting authority from a signer-controlled label.
///
/// Signature and artifact verification remain separate mandatory checks. This
/// function only combines the signed manifest with consumer-owned key state.
pub fn bundle_origin(
    manifest: &BundleManifest,
    host_key_id: &KeyId,
    trust: &dyn TrustStore,
) -> BundleOrigin {
    let carries_local_label = manifest
        .labels
        .get(BUNDLE_ORIGIN_LABEL)
        .is_some_and(|value| value == LOCAL_BUILD_ORIGIN);
    let signed_by_this_host = &manifest.key_id == host_key_id;

    if carries_local_label || signed_by_this_host {
        return if carries_local_label && signed_by_this_host {
            BundleOrigin::LocalBuild
        } else {
            BundleOrigin::Untrusted
        };
    }

    match trust.lookup(&manifest.key_id) {
        Some(key) if key_id_from_pubkey(&key) == manifest.key_id => BundleOrigin::ReleaseVerified,
        _ => BundleOrigin::Untrusted,
    }
}

/// Whether registry ingress or egress must reject this manifest before trust
/// lookup. Either the host key or the reserved local-build label is sufficient
/// for refusal; neither can be made publishable by enrolling the host key.
pub fn is_registry_forbidden_local_build(manifest: &BundleManifest, host_key_id: &KeyId) -> bool {
    &manifest.key_id == host_key_id
        || manifest
            .labels
            .get(BUNDLE_ORIGIN_LABEL)
            .is_some_and(|value| value == LOCAL_BUILD_ORIGIN)
}

/// Derive the key_id from a verifying-key's bytes.
///
/// A free function rather than an inherent method on [`KeyId`]: that type
/// now lives in `mvm-contract`, and the orphan rule forbids `mvm-core`
/// from adding inherent `impl`s to a foreign type.
pub fn key_id_from_pubkey(pk: &VerifyingKey) -> KeyId {
    let bytes = pk.to_bytes();
    let hex = hex::encode(Sha256::digest(bytes));
    KeyId(hex[..32].to_string())
}

/// Derive a stable, well-formed key_id from a signer *identity* string (a
/// keyless OIDC subject). Unlike [`key_id_from_pubkey`] there is no key
/// here, so this id is only an identifier for revocation keying and audit
/// — never a lookup into a key store.
pub fn key_id_from_identity(identity: &str) -> KeyId {
    let hex = hex::encode(Sha256::digest(identity.as_bytes()));
    KeyId(hex[..32].to_string())
}

/// Canonical JSON bytes used as the signing input. Pure function;
/// the same bytes round-trip from sign → verify.
///
/// A free function rather than an inherent method on [`BundleManifest`]:
/// that type now lives in `mvm-contract`, and the orphan rule forbids
/// `mvm-core` from adding inherent `impl`s to a foreign type.
pub fn canonical_manifest_bytes(manifest: &BundleManifest) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest).context("serialise BundleManifest to canonical JSON")
}

pub use mvm_contract::hash::sha256_hex;

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

/// Parse only the signed manifest entry for an early refusal decision.
///
/// The returned fields are not authenticated. Callers may use them only to
/// reject an archive before network publication or registry installation;
/// successful admission still requires the normal signature and artifact
/// verification path.
#[cfg(feature = "host-state")]
pub fn inspect_bundle_manifest_for_refusal(
    archive: impl Read,
) -> Result<BundleManifest, BundleVerifyError> {
    let manifest_bytes = stream::read_manifest_entry(archive)?;
    check_schema_cap(&manifest_bytes, BUNDLE_SCHEMA_VERSION)?;
    serde_json::from_slice(&manifest_bytes)
        .map_err(|error| BundleVerifyError::ManifestParse(error.to_string()))
}

/// File-backed form of [`inspect_bundle_manifest_for_refusal`].
#[cfg(feature = "host-state")]
pub fn inspect_bundle_manifest_file_for_refusal(
    path: &Path,
) -> Result<BundleManifest, BundleVerifyError> {
    let file = std::fs::File::open(path).map_err(|error| {
        BundleVerifyError::ManifestParse(format!(
            "opening bundle archive {}: {error}",
            path.display()
        ))
    })?;
    inspect_bundle_manifest_for_refusal(file)
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
        let p = crate::config::mvm_home_strict()?.join("bundles");
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

    /// Content-addressed cache used by embedded image sets. A normal registry
    /// rooted at `~/.mvm/bundles` stores these under `~/.mvm/image-sets`.
    pub fn embedded_image_set_cache_root(&self) -> PathBuf {
        self.root
            .parent()
            .unwrap_or(self.root.as_path())
            .join("image-sets")
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
    ///
    /// The bytes are spooled to a temporary file and installed through
    /// [`install_file`](Self::install_file), so an archive in memory and one
    /// on disk go through the same streaming verification.
    #[cfg(feature = "host-state")]
    pub fn install(
        &self,
        archive_bytes: &[u8],
        trust: &dyn TrustStore,
        force: bool,
    ) -> Result<InstalledBundle, BundleInstallError> {
        let sha = bundle_sha256(archive_bytes);
        let io_error = |reason: String| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason,
        };
        let mut spooled = tempfile::NamedTempFile::new()
            .map_err(|e| io_error(format!("creating archive spool file: {e}")))?;
        spooled
            .write_all(archive_bytes)
            .map_err(|e| io_error(format!("spooling archive bytes: {e}")))?;
        self.install_file(spooled.path(), trust, force)
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
    #[cfg(feature = "host-state")]
    pub fn remove(&self, bundle_sha256: &str) -> anyhow::Result<bool> {
        match std::fs::symlink_metadata(&self.root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        let _lease = self.lock_entry(bundle_sha256).map_err(anyhow::Error::msg)?;
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
    /// The signature-verified manifest of an installed bundle, or `None`
    /// when no archive is installed under `bundle_sha256`.
    ///
    /// Reads `manifest.json` and `manifest.sig` from the head of the
    /// installed archive and runs every manifest check
    /// [`read_and_verify_bundle`] does — trust-store lookup, signature,
    /// schema, declarations — without hashing an artifact. The artifacts were
    /// hashed when the bundle was installed; this is the cheap read a launch
    /// makes to learn what the bundle declares, and it refuses a manifest
    /// whose posture was edited on disk after install.
    #[cfg(feature = "host-state")]
    pub fn verified_manifest(
        &self,
        bundle_sha256: &str,
        trust: &dyn TrustStore,
    ) -> Result<Option<BundleManifest>, BundleVerifyError> {
        let path = self.archive_path(bundle_sha256);
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(BundleVerifyError::ManifestParse(format!(
                    "opening installed bundle archive {}: {e}",
                    path.display()
                )));
            }
        };
        let (manifest_bytes, sig_bytes) = stream::read_manifest_entries(file)?;
        verify_signed_manifest(&manifest_bytes, &sig_bytes, trust)
            .map(|(manifest, _)| Some(manifest))
    }

    /// [`verified_manifest`](Self::verified_manifest) for a launch that may
    /// boot a host-local build.
    ///
    /// This host's own key is trusted for its exact key_id only, and the
    /// result is then classified with [`bundle_origin`]: a bundle is admitted
    /// when `release` enrolls its signer, or when it carries the signed
    /// local-build label and this host signed it. Anything else, including a
    /// host-signed bundle without the label, refuses as an unknown key.
    #[cfg(feature = "host-state")]
    pub fn verified_launch_manifest<T: TrustStore>(
        &self,
        bundle_sha256: &str,
        release: T,
        host_key: Option<VerifyingKey>,
    ) -> Result<Option<BundleManifest>, BundleVerifyError> {
        let Some(host_key) = host_key else {
            return self.verified_manifest(bundle_sha256, &release);
        };
        let host_key_id = key_id_from_pubkey(&host_key);
        let trust = LocalBundleTrustStore::new(release, host_key_id.clone(), host_key);
        let Some(manifest) = self.verified_manifest(bundle_sha256, &trust)? else {
            return Ok(None);
        };
        match bundle_origin(&manifest, &host_key_id, trust.release()) {
            BundleOrigin::Untrusted => Err(BundleVerifyError::UnknownKey {
                key_id: manifest.key_id.0.clone(),
            }),
            BundleOrigin::ReleaseVerified | BundleOrigin::LocalBuild => Ok(Some(manifest)),
        }
    }

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

/// The verified bundle an embedded image-set cache is filled from: its
/// manifest, the image sets it embeds, and where their bytes can be read.
#[cfg(feature = "host-state")]
struct ImageSetSource<'a> {
    manifest: &'a BundleManifest,
    embedded: &'a [VerifiedEmbeddedImageSet],
    artifacts: &'a dyn stream::ArtifactSource,
}

#[cfg(feature = "host-state")]
impl ImageSetSource<'_> {
    fn manifest_declaration(
        &self,
        embedded: &VerifiedEmbeddedImageSet,
    ) -> Result<&BundleArtifact, String> {
        self.manifest
            .find_by_name(&embedded.manifest_artifact)
            .ok_or_else(|| "verified embedded image-set declaration disappeared".to_string())
    }
}

#[cfg(feature = "host-state")]
fn install_embedded_image_set_cache(
    source: &ImageSetSource<'_>,
    cache_root: &Path,
    bundle_sha256: &str,
) -> Result<(), BundleInstallError> {
    if source.embedded.is_empty() {
        return Ok(());
    }
    let io_error = |reason: String| BundleInstallError::Io {
        bundle_sha256: bundle_sha256.to_string(),
        reason,
    };
    std::fs::create_dir_all(cache_root).map_err(|error| {
        io_error(format!(
            "creating embedded image-set cache {}: {error}",
            cache_root.display()
        ))
    })?;

    for embedded in source.embedded {
        let destination = cache_root.join(embedded.manifest_sha256.as_str());
        if destination.exists() {
            verify_cached_embedded_image_set(source, embedded, &destination).map_err(io_error)?;
            continue;
        }

        let staging = tempfile::Builder::new()
            .prefix(".image-set-")
            .tempdir_in(cache_root)
            .map_err(|error| {
                io_error(format!(
                    "creating embedded image-set staging directory: {error}"
                ))
            })?;
        write_embedded_image_set_cache(source, embedded, staging.path()).map_err(io_error)?;
        match std::fs::rename(staging.path(), &destination) {
            Ok(()) => {}
            Err(_) if destination.exists() => {
                verify_cached_embedded_image_set(source, embedded, &destination)
                    .map_err(io_error)?;
            }
            Err(error) => {
                return Err(io_error(format!(
                    "publishing embedded image-set cache {}: {error}",
                    destination.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "host-state")]
fn write_embedded_image_set_cache(
    source: &ImageSetSource<'_>,
    embedded: &VerifiedEmbeddedImageSet,
    destination: &Path,
) -> Result<(), String> {
    let manifest_declaration = source.manifest_declaration(embedded)?;
    source
        .artifacts
        .copy_to(
            &manifest_declaration.path,
            &destination.join("image-set.json"),
        )
        .map_err(|error| format!("writing embedded image-set manifest: {error}"))?;
    let artifact_dir = destination.join("artifacts");
    std::fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("creating embedded image-set artifact directory: {error}"))?;
    for (name, bundle_path) in &embedded.artifact_paths {
        source
            .artifacts
            .copy_to(bundle_path, &artifact_dir.join(name))
            .map_err(|error| format!("writing embedded image-set artifact {name}: {error}"))?;
    }
    Ok(())
}

/// Re-hash an existing cache entry against the digests the verified bundle
/// declares. Streams each file; nothing is held whole.
#[cfg(feature = "host-state")]
fn verify_cached_embedded_image_set(
    source: &ImageSetSource<'_>,
    embedded: &VerifiedEmbeddedImageSet,
    destination: &Path,
) -> Result<(), String> {
    let manifest_declaration = source.manifest_declaration(embedded)?;
    let cached_digest = |path: &Path, what: &str| {
        crate::crypto::image_verify::sha256_file(path)
            .map_err(|error| format!("reading cached embedded image-set {what}: {error}"))
    };
    if cached_digest(&destination.join("image-set.json"), "manifest")?
        != manifest_declaration.sha256
    {
        return Err(format!(
            "cached embedded image set {} failed manifest re-verification",
            embedded.manifest_sha256.as_str()
        ));
    }
    for name in embedded.artifact_paths.keys() {
        let declared = source.manifest.find_by_name(name).ok_or_else(|| {
            format!("verified embedded image-set artifact {name} declaration disappeared")
        })?;
        let cached = cached_digest(&destination.join("artifacts").join(name), name)?;
        if cached != declared.sha256 {
            return Err(format!(
                "cached embedded image-set artifact {name} failed re-verification"
            ));
        }
    }
    Ok(())
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
#[cfg(feature = "host-state")]
pub fn verify_plan_bundle(
    pin: &PlanArtifact,
    resolver: &dyn BundleResolver,
    trust: &dyn TrustStore,
) -> Result<VerifiedBundle, PlanBundleError> {
    verify_plan_bundle_checked(pin, resolver, trust, |verified| {
        if verified
            .manifest
            .members
            .iter()
            .any(|member| matches!(member, BundleMember::CanonicalLinuxProof(_)))
        {
            return Err(PlanBundleError::CanonicalKernelCustodyRequired);
        }
        Ok(())
    })
}

/// The canonical lane additionally requires the SAME in-process owner and
/// actual launch selection. There is no path/hash/JSON fallback.
#[cfg(feature = "host-state")]
pub fn verify_canonical_plan_bundle(
    pin: &PlanArtifact,
    resolver: &dyn BundleResolver,
    trust: &dyn TrustStore,
    owner: &std::sync::Arc<crate::canonical_linux::PreparedCanonicalLinux>,
    config: &crate::vm_backend::VmStartConfig,
    backend: crate::vm_backend::BackendKind,
    host: &crate::image_set::HostProtocolSupport,
) -> Result<VerifiedBundle, PlanBundleError> {
    verify_plan_bundle_checked(pin, resolver, trust, |verified| {
        owner_binds_canonical_bundle(&verified.manifest, owner.pin(), pin)?;
        owner
            .verify_config(config, backend, host)
            .map_err(|error| PlanBundleError::CanonicalKernelBinding(error.to_string()))
    })
}

/// The canonical owner must have been prepared from this very bundle, and the
/// bundle must declare the canonical proof the owner was prepared from.
#[cfg(feature = "host-state")]
fn owner_binds_canonical_bundle(
    manifest: &BundleManifest,
    owner_pin: &PlanArtifact,
    pin: &PlanArtifact,
) -> Result<(), PlanBundleError> {
    let declares_proof = manifest
        .members
        .iter()
        .any(|member| matches!(member, BundleMember::CanonicalLinuxProof(_)));
    if !declares_proof || owner_pin != pin {
        return Err(PlanBundleError::CanonicalKernelBinding(
            "owner does not bind this canonical bundle".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "host-state")]
fn verify_plan_bundle_checked(
    pin: &PlanArtifact,
    resolver: &dyn BundleResolver,
    trust: &dyn TrustStore,
    admit_kernel: impl FnOnce(&VerifiedBundle) -> Result<(), PlanBundleError>,
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

    admit_kernel(&verified)?;

    Ok(verified)
}

/// Errors specific to plan-bundle admission. Wraps the lower-level
/// [`BundleVerifyError`] + [`BundleResolveError`] so a supervisor
/// can branch on "resolver couldn't find the bytes" vs "bytes
/// found but the pin says they shouldn't be these."
#[derive(Debug, Error)]
pub enum PlanBundleError {
    #[error("canonical kernel binding refused: {0}")]
    CanonicalKernelBinding(String),
    #[error(
        "canonical Linux proof requires retained backend kernel custody; this admission path does not yet support it"
    )]
    CanonicalKernelCustodyRequired,

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
#[cfg(feature = "host-state")]
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

/// Build a sealed bundle archive from manifest + artifact byte blobs.
///
/// The caller supplies the manifest (already populated with per-
/// artifact sha256s and sizes) and an iterator yielding
/// `(archive_relative_path, bytes)` pairs for each artifact. The
/// manifest is signed inside this function so the signature lines up
/// exactly with the canonical bytes that get written.
///
/// The signature is checked against `signer`'s verifying key before the
/// archive is assembled. A signer that answers with the wrong bytes is a
/// failed export here, not a bundle that installs nowhere.
///
/// Returns the full archive bytes as a `Vec<u8>` — the caller is
/// responsible for writing them out. In-memory representation
/// matches the on-disk archive byte-for-byte. [`write_bundle_to`] is the same
/// writer streaming into any `Write`, from files as well as bytes.
#[cfg(feature = "host-state")]
pub fn write_bundle(
    manifest: &BundleManifest,
    signer: &dyn ManifestSigner,
    artifacts: Vec<(String, Vec<u8>)>,
) -> Result<Vec<u8>> {
    let payload = artifacts
        .into_iter()
        .map(|(path, bytes)| (path, BundlePayload::Bytes(bytes)))
        .collect();
    let mut archive = Vec::new();
    write_bundle_to(manifest, signer, payload, &mut archive)?;
    Ok(archive)
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
    /// Embedded image sets that passed the same structural, completeness, and
    /// per-artifact validation as a standalone image set.
    pub embedded_image_sets: Vec<VerifiedEmbeddedImageSet>,
    pub boot_assets: Option<VerifiedBootAssets>,
}

/// Architecture-bound boot selection authenticated by the bundle publisher.
/// The embedded Linux manifest's structure and selected artifact hashes are
/// checked here; this is not independent Linux publisher or revocation proof.
/// CLI-runtime release authentication happens again at launch. This is not a
/// complete image set and must never enter the full-set cache.
#[derive(Debug, Clone)]
pub struct VerifiedBootAssets {
    pub arch: GuestArch,
    pub image_set: VerifiedEmbeddedImageSet,
    pub cli_runtime: Option<EmbeddedCliBootAssets>,
}

/// The image-set role of the runtime overlay a bundle's boot assets carry.
///
/// Boot assets are the one consumer of an image set's guest-runtime members:
/// a portable bundle authenticates its overlay and initramfs through the set
/// manifest it embeds, so it can only be built from a set that still publishes
/// them. Every other path assembles the guest runtime from the CLI's own.
pub const BOOT_ASSET_OVERLAY_ROLE: ImageSetRole =
    ImageSetRole::RetiredGuestRuntime(RetiredGuestRuntimeRole::RuntimeOverlay);

/// The image-set role of the universal initramfs a bundle's boot assets carry;
/// see [`BOOT_ASSET_OVERLAY_ROLE`].
pub const BOOT_ASSET_INITRAMFS_ROLE: ImageSetRole =
    ImageSetRole::RetiredGuestRuntime(RetiredGuestRuntimeRole::Initramfs);

/// Select the two portable Linux runtime archives from an original full manifest.
/// Actual launch still checks the target backend and host protocol support.
pub fn select_boot_asset_members(
    manifest: &ImageSetManifest,
    arch: GuestArch,
) -> Result<[&crate::image_set::ImageSetMember; 2], ImageSetError> {
    validate_structure(manifest)?;
    require_complete(manifest, &ImageSetRequirement::current_train())?;
    let mut support = BackendImageSupport::for_backend(crate::vm_backend::BackendKind::Qemu)
        .expect("Qemu declares portable Linux image support");
    support.artifact_formats = vec![crate::image_set::ArtifactFormat::TarGz];
    let selected = [
        select_member(manifest, BOOT_ASSET_OVERLAY_ROLE, arch, &support)?,
        select_member(manifest, BOOT_ASSET_INITRAMFS_ROLE, arch, &support)?,
    ];
    for artifact in selected.iter().flat_map(|member| &member.artifacts) {
        if manifest
            .members
            .iter()
            .flat_map(|member| &member.artifacts)
            .filter(|candidate| candidate.name == artifact.name)
            .count()
            != 1
        {
            return Err(ImageSetError::DuplicateSelectedArtifact {
                name: artifact.name.clone(),
            });
        }
    }
    Ok(selected)
}

/// Select the original production Linux kernel for a CLI-runtime bundle.
/// Runtime archives are deliberately not part of this image-set selection.
pub fn select_cli_boot_kernel(
    manifest: &ImageSetManifest,
    arch: GuestArch,
) -> Result<&crate::image_set::ImageSetMember, ImageSetError> {
    validate_structure(manifest)?;
    require_complete(manifest, &ImageSetRequirement::current_train())?;
    let support = BackendImageSupport::for_backend(crate::vm_backend::BackendKind::Qemu)
        .expect("Qemu declares portable Linux image support");
    select_member(
        manifest,
        ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
        arch,
        &support,
    )
}

/// Check the selected Linux kernel for schema 6, or the historical packaged
/// runtime roles for schema 4, not an unshipped workload base image.
pub fn check_boot_assets_for_backend(
    boot: &VerifiedBootAssets,
    backend: &BackendImageSupport,
    host_protocols: &HostProtocolSupport,
) -> Result<(), ImageSetError> {
    check_workload_protocol_compatibility(&boot.image_set.manifest.compatibility, host_protocols)?;
    if boot.cli_runtime.is_some() {
        select_member(
            &boot.image_set.manifest,
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            boot.arch,
            backend,
        )?;
        return Ok(());
    }
    for role in [BOOT_ASSET_OVERLAY_ROLE, BOOT_ASSET_INITRAMFS_ROLE] {
        select_member(&boot.image_set.manifest, role, boot.arch, backend)?;
    }
    Ok(())
}

/// One embedded image set whose manifest is bound to verified bundle bytes.
#[derive(Debug, Clone)]
pub struct VerifiedEmbeddedImageSet {
    pub manifest_artifact: String,
    pub manifest_sha256: Sha256Hex,
    pub manifest: ImageSetManifest,
    /// Image-set artifact name to archive-relative bundle path.
    pub artifact_paths: BTreeMap<String, String>,
}

/// Refuse an embedded set before boot unless its protocol declaration and
/// selected workload image are both satisfiable by the chosen backend. The
/// guest runtime is not part of the check: it comes from the CLI that boots
/// the bundle, never from the embedded set.
pub fn check_embedded_image_set_for_backend(
    embedded: &VerifiedEmbeddedImageSet,
    arch: GuestArch,
    backend: &BackendImageSupport,
    host_protocols: &HostProtocolSupport,
) -> Result<(), ImageSetError> {
    check_workload_protocol_compatibility(&embedded.manifest.compatibility, host_protocols)?;
    select_workload_image(
        &embedded.manifest,
        WorkloadImageProfile::DefaultTenant,
        arch,
        backend,
    )?;
    Ok(())
}

/// Read a bundle archive, look the publisher up in the trust store,
/// verify the signature, then re-hash every artifact against the
/// signed manifest. Returns a [`VerifiedBundle`] on success.
///
/// All four failure modes ([`BundleVerifyError::UnknownKey`],
/// `SignatureInvalid`, `ArtifactSha256Mismatch`, `UnsafePath`)
/// reject *before* the artifact bytes are exposed to anything
/// outside this function's local scope. Every entry is held in memory
/// for the size and hash pass, which suits bytes that are already in
/// memory. An archive on disk goes through [`verify_bundle_file`] or
/// [`BundleRegistry::install_file`], which stream it instead.
#[cfg(feature = "host-state")]
pub fn read_and_verify_bundle(
    archive_bytes: &[u8],
    trust_store: &dyn TrustStore,
) -> Result<VerifiedBundle, BundleVerifyError> {
    // Pass 1: pull every entry into memory, each counted against the size
    // caps before it is read.
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut budget = declarations::BundleSizeBudget::default();
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
        budget.admit(&path, entry.size())?;
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

    let (manifest, declared_key_id) =
        verify_signed_manifest(&manifest_bytes, &sig_bytes, trust_store)?;

    // ----- Step 6: per-artifact hash + size check -----
    let mut artifacts_out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for art in &manifest.artifacts {
        ensure_safe_path(&art.path)?;
        let bytes = entries
            .get(&art.path)
            .ok_or_else(|| BundleVerifyError::ArtifactMissing {
                name: art.name.clone(),
            })?;
        stream::check_artifact_digest(art, bytes.len() as u64, sha256_hex(bytes))?;
        artifacts_out.insert(art.path.clone(), bytes.clone());
    }

    let embedded_image_sets =
        verify_embedded_image_sets(&manifest, &stream::InMemoryArtifacts(&artifacts_out))?;
    let boot_assets = verify_boot_assets(&manifest, &stream::InMemoryArtifacts(&artifacts_out))?;

    Ok(VerifiedBundle {
        manifest,
        artifacts: artifacts_out,
        key_id: declared_key_id,
        embedded_image_sets,
        boot_assets,
    })
}

/// Verify a manifest's detached signature against the trust store and parse
/// it: the schema sniff, the key lookup, the signature, the full parse, and
/// the declaration checks. Everything [`read_and_verify_bundle`] establishes
/// about the manifest, without looking at a single artifact byte.
#[cfg(feature = "host-state")]
fn check_schema_cap(manifest_bytes: &[u8], supported: u32) -> Result<(), BundleVerifyError> {
    #[derive(Deserialize)]
    struct SchemaProbe {
        schema_version: u32,
    }
    let probe: SchemaProbe = serde_json::from_slice(manifest_bytes).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("schema_version probe failed: {e}"))
    })?;
    if probe.schema_version > supported {
        return Err(BundleVerifyError::UnsupportedSchema {
            found: probe.schema_version,
            supported,
        });
    }
    Ok(())
}

#[cfg(feature = "host-state")]
fn verify_signed_manifest(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    trust_store: &dyn TrustStore,
) -> Result<(BundleManifest, KeyId), BundleVerifyError> {
    // ----- Step 1: schema version sniff (pre-signature) -----
    //
    // We deliberately read schema_version *before* checking the
    // signature. If a v2 bundle ever shows up, an older verifier
    // should refuse with UnsupportedSchema, not parse-fail with a
    // misleading deny_unknown_fields error. The signature check
    // still happens before we expose any parsed plan-level fields.
    check_schema_cap(manifest_bytes, BUNDLE_SCHEMA_VERSION)?;

    // ----- Step 2: pull key_id (still pre-signature) -----
    #[derive(Deserialize)]
    struct KeyIdProbe {
        key_id: KeyId,
    }
    let key_probe: KeyIdProbe = serde_json::from_slice(manifest_bytes)
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
    let actual_id = key_id_from_pubkey(&pubkey);
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
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("checked above");
    let signature = Signature::from_bytes(&sig_arr);
    pubkey
        .verify(manifest_bytes, &signature)
        .map_err(|e| BundleVerifyError::SignatureInvalid {
            key_id: declared_key_id.0.clone(),
            reason: e.to_string(),
        })?;

    // ----- Step 5: full manifest parse, now that the bytes are
    // proven authentic -----
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| BundleVerifyError::ManifestParse(e.to_string()))?;
    if manifest.schema_version < 3 && !manifest.members.is_empty() {
        return Err(BundleVerifyError::MembersRequireSchemaV3 {
            found: manifest.schema_version,
        });
    }
    declarations::validate_declarations(&manifest)?;

    Ok((manifest, declared_key_id))
}

/// Bind each embedded image-set declaration to the already verified bundle
/// artifacts. The image-set module owns structure, completeness and backend
/// compatibility; this adapter owns only the cross-manifest name/hash binding.
#[cfg(feature = "host-state")]
fn verify_embedded_image_sets(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
) -> Result<Vec<VerifiedEmbeddedImageSet>, BundleVerifyError> {
    let mut names = BTreeSet::new();
    for artifact in &bundle.artifacts {
        if !names.insert(artifact.name.as_str()) {
            return Err(BundleVerifyError::DuplicateArtifactName {
                name: artifact.name.clone(),
            });
        }
    }

    bundle
        .members
        .iter()
        .filter_map(|member| match member {
            BundleMember::EmbeddedImageSet { manifest_artifact } => Some(manifest_artifact),
            BundleMember::KernelCmdline { .. }
            | BundleMember::EmbeddedBootAssets { .. }
            | BundleMember::EmbeddedCliBootAssets(_)
            | BundleMember::CanonicalLinuxProof(_)
            | BundleMember::SecurityPosture(_)
            | BundleMember::BuildProvenance(_)
            | BundleMember::Environment(_) => None,
        })
        .map(|manifest_artifact| {
            verify_embedded_image_set(
                bundle,
                artifacts,
                manifest_artifact,
                ImageSetSelection::Full,
            )
        })
        .collect()
}

#[cfg(feature = "host-state")]
fn verify_boot_assets(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
) -> Result<Option<VerifiedBootAssets>, BundleVerifyError> {
    let Some((manifest_artifact, cli_runtime)) =
        bundle.members.iter().find_map(|member| match member {
            BundleMember::EmbeddedBootAssets { manifest_artifact } => {
                Some((manifest_artifact, None))
            }
            BundleMember::EmbeddedCliBootAssets(runtime) => {
                Some((&runtime.manifest_artifact, Some(runtime)))
            }
            BundleMember::EmbeddedImageSet { .. }
            | BundleMember::CanonicalLinuxProof(_)
            | BundleMember::KernelCmdline { .. }
            | BundleMember::SecurityPosture(_)
            | BundleMember::BuildProvenance(_)
            | BundleMember::Environment(_) => None,
        })
    else {
        return Ok(None);
    };
    let arch = match bundle.arch.as_str() {
        "x86_64" => GuestArch::X86_64,
        "aarch64" => GuestArch::Aarch64,
        other => {
            return Err(BundleVerifyError::ManifestParse(format!(
                "unknown boot-assets architecture {other}"
            )));
        }
    };
    let selection = if cli_runtime.is_some() {
        ImageSetSelection::CliKernel(arch)
    } else {
        ImageSetSelection::LegacyRuntime(arch)
    };
    let image_set = verify_embedded_image_set(bundle, artifacts, manifest_artifact, selection)?;
    Ok(Some(VerifiedBootAssets {
        arch,
        image_set,
        cli_runtime: cli_runtime.cloned(),
    }))
}

#[derive(Clone, Copy)]
#[cfg(feature = "host-state")]
enum ImageSetSelection {
    Full,
    LegacyRuntime(GuestArch),
    CliKernel(GuestArch),
}

#[cfg(feature = "host-state")]
fn verify_embedded_image_set(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
    manifest_artifact: &str,
    selection: ImageSetSelection,
) -> Result<VerifiedEmbeddedImageSet, BundleVerifyError> {
    let declaration = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.name == manifest_artifact)
        .ok_or_else(|| BundleVerifyError::ImageSetManifestArtifactMissing {
            name: manifest_artifact.to_string(),
        })?;
    let manifest_bytes = artifacts
        .read_image_set_manifest(&declaration.path)
        .map_err(|reason| BundleVerifyError::ImageSetManifestParse {
            name: manifest_artifact.to_string(),
            reason,
        })?;
    let manifest: ImageSetManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        BundleVerifyError::ImageSetManifestParse {
            name: manifest_artifact.to_string(),
            reason: error.to_string(),
        }
    })?;
    validate_structure(&manifest).map_err(|reason| BundleVerifyError::ImageSetRefused {
        name: manifest_artifact.to_string(),
        reason,
    })?;
    require_complete(&manifest, &ImageSetRequirement::current_train()).map_err(|reason| {
        BundleVerifyError::ImageSetRefused {
            name: manifest_artifact.to_string(),
            reason,
        }
    })?;

    let selected = match selection {
        ImageSetSelection::Full => Ok(manifest.members.iter().collect()),
        ImageSetSelection::LegacyRuntime(arch) => {
            select_boot_asset_members(&manifest, arch).map(|members| members.to_vec())
        }
        ImageSetSelection::CliKernel(arch) => {
            select_cli_boot_kernel(&manifest, arch).map(|member| vec![member])
        }
    };
    let members = selected.map_err(|reason| BundleVerifyError::ImageSetRefused {
        name: manifest_artifact.to_string(),
        reason,
    })?;
    let mut artifact_paths = BTreeMap::new();
    for image_artifact in members
        .into_iter()
        .flat_map(|member| member.artifacts.iter())
    {
        let name = image_artifact.name.as_str();
        let bundle_artifact = bundle
            .artifacts
            .iter()
            .find(|artifact| match selection {
                ImageSetSelection::CliKernel(_) => artifact.role == ArtifactRole::Kernel,
                ImageSetSelection::Full | ImageSetSelection::LegacyRuntime(_) => {
                    artifact.name == name
                }
            })
            .ok_or_else(|| BundleVerifyError::ImageSetArtifactMissing {
                name: name.to_string(),
            })?;
        if image_artifact.sha256.as_str() != bundle_artifact.sha256 {
            return Err(BundleVerifyError::ImageSetArtifactDigestMismatch {
                name: name.to_string(),
                image_set: image_artifact.sha256.as_str().to_string(),
                bundle: bundle_artifact.sha256.clone(),
            });
        }
        if image_artifact.size != bundle_artifact.size_bytes {
            return Err(BundleVerifyError::ImageSetArtifactSizeMismatch {
                name: name.to_string(),
                image_set: image_artifact.size,
                bundle: bundle_artifact.size_bytes,
            });
        }
        artifact_paths.insert(name.to_string(), bundle_artifact.path.clone());
    }

    Ok(VerifiedEmbeddedImageSet {
        manifest_artifact: manifest_artifact.to_string(),
        manifest_sha256: Sha256Hex::from_bytes(&manifest_bytes),
        manifest,
        artifact_paths,
    })
}

/// Convenience: SHA-256 of the entire archive bytes, encoded as
/// lowercase hex. The `bundle_sha256` field on
/// [`PlanArtifact`] holds this exact value, so an
/// `ExecutionPlan` can pin a specific bundle without trusting any
/// publisher metadata.
pub fn bundle_sha256(archive_bytes: &[u8]) -> String {
    sha256_hex(archive_bytes)
}

#[cfg(all(test, feature = "host-state"))]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::Rng;
    use std::collections::HashMap;

    use crate::image_set::{
        ArtifactFormat, ArtifactName, BootProtocol, GitCommit, GuestDeviceRequirement,
        ImageSetCompatibility, ImageSetMember, ImageSetProducer, ImageSetRole, ImageSetVersion,
        MemberArtifact, MemberTarget, NixInputs, ProtocolRange, ReleaseProducer, ReleaseTag,
        RepositorySlug, RevocationChannel, WorkflowPath,
    };
    use crate::kernel_format::KernelFormat;
    use crate::packs::{FlakeLockIdentity, SbomReference, SourceRevisionIdentity};

    fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, Cursor::new(bytes))
            .with_context(|| format!("write tar entry {path:?}"))
    }

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
        {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        }
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
            members: Vec::new(),
            verity: None,
            resources: None,
        }
    }

    #[test]
    fn bundle_origin_is_release_verified_only_for_enrolled_keys() {
        let release = fresh_key();
        let host = fresh_key();
        let manifest = make_manifest(key_id_from_pubkey(&release.verifying_key()), Vec::new());

        assert_eq!(
            bundle_origin(
                &manifest,
                &key_id_from_pubkey(&host.verifying_key()),
                &trust(&release),
            ),
            BundleOrigin::ReleaseVerified
        );
        assert_eq!(
            bundle_origin(
                &manifest,
                &key_id_from_pubkey(&host.verifying_key()),
                &MapTrustStore(HashMap::new()),
            ),
            BundleOrigin::Untrusted
        );
    }

    #[test]
    fn the_local_label_without_the_host_key_grants_no_level() {
        let foreign = fresh_key();
        let host = fresh_key();
        let mut manifest = make_manifest(key_id_from_pubkey(&foreign.verifying_key()), Vec::new());
        mark_local_build(&mut manifest);

        assert_eq!(
            bundle_origin(
                &manifest,
                &key_id_from_pubkey(&host.verifying_key()),
                &trust(&foreign),
            ),
            BundleOrigin::Untrusted
        );
        assert!(is_registry_forbidden_local_build(
            &manifest,
            &key_id_from_pubkey(&host.verifying_key())
        ));
    }

    #[test]
    fn a_host_key_archive_without_the_label_is_not_a_local_build() {
        let host = fresh_key();
        let manifest = make_manifest(key_id_from_pubkey(&host.verifying_key()), Vec::new());
        let enrolled = trust(&host);

        assert_eq!(
            bundle_origin(
                &manifest,
                &key_id_from_pubkey(&host.verifying_key()),
                &enrolled,
            ),
            BundleOrigin::Untrusted
        );
        assert!(is_registry_forbidden_local_build(
            &manifest,
            &key_id_from_pubkey(&host.verifying_key())
        ));
    }

    #[test]
    fn marked_host_bundle_is_local_and_never_registry_eligible() {
        let host = fresh_key();
        let mut manifest = make_manifest(key_id_from_pubkey(&host.verifying_key()), Vec::new());
        mark_local_build(&mut manifest);

        assert_eq!(
            bundle_origin(
                &manifest,
                &key_id_from_pubkey(&host.verifying_key()),
                &trust(&host),
            ),
            BundleOrigin::LocalBuild
        );
        assert!(is_registry_forbidden_local_build(
            &manifest,
            &key_id_from_pubkey(&host.verifying_key())
        ));
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        m.insert(key_id, sk.verifying_key());
        MapTrustStore(m)
    }

    fn image_member_artifact(name: &str, format: ArtifactFormat) -> (MemberArtifact, Vec<u8>) {
        let bytes = format!("embedded bytes for {name}").into_bytes();
        (
            MemberArtifact {
                name: ArtifactName::new(name).expect("artifact name"),
                format,
                sha256: Sha256Hex::from_bytes(&bytes),
                size: bytes.len() as u64,
            },
            bytes,
        )
    }

    fn image_member(
        role: ImageSetRole,
        target: MemberTarget,
    ) -> (ImageSetMember, Vec<(String, Vec<u8>)>) {
        use GuestDeviceRequirement::{DmVerity, VirtioBlk, VirtioVsock};
        let suffix = match target {
            MemberTarget::Arch(arch) => format!("-{arch}"),
            MemberTarget::ArchIndependent => String::new(),
        };
        let kernel = match target {
            MemberTarget::Arch(GuestArch::X86_64) => ArtifactFormat::Kernel(KernelFormat::Elf),
            _ => ArtifactFormat::Kernel(KernelFormat::Image),
        };
        let (specs, boot_protocol, required_capabilities) = match role {
            ImageSetRole::BuilderVm => (
                vec![
                    (format!("builder-vmlinux{suffix}"), kernel),
                    (format!("builder-rootfs{suffix}.ext4"), ArtifactFormat::Ext4),
                ],
                Some(BootProtocol::LinuxDirect),
                vec![VirtioVsock, VirtioBlk],
            ),
            ImageSetRole::WorkloadKernel(profile) => (
                vec![(format!("{profile}-vmlinux{suffix}"), kernel)],
                Some(BootProtocol::LinuxDirect),
                vec![VirtioVsock],
            ),
            ImageSetRole::WorkloadRootfs(profile) => (
                vec![
                    (
                        format!("{profile}-rootfs{suffix}.ext4"),
                        ArtifactFormat::Ext4,
                    ),
                    (
                        format!("{profile}-rootfs{suffix}.verity"),
                        ArtifactFormat::VerityHashTree,
                    ),
                    (
                        format!("{profile}-rootfs{suffix}.roothash"),
                        ArtifactFormat::VerityRootHash,
                    ),
                ],
                None,
                vec![VirtioBlk, DmVerity],
            ),
            ImageSetRole::RetiredGuestRuntime(retired) => (
                vec![(
                    match retired {
                        RetiredGuestRuntimeRole::RuntimeOverlay => {
                            format!("runtime-overlay{suffix}.tar.gz")
                        }
                        RetiredGuestRuntimeRole::SdkSidecar(libc) => {
                            format!("sdk-sidecar{suffix}-{libc}.tar.gz")
                        }
                        RetiredGuestRuntimeRole::Initramfs => format!("initramfs{suffix}.tar.gz"),
                    },
                    ArtifactFormat::TarGz,
                )],
                None,
                vec![],
            ),
            ImageSetRole::Stage0BootstrapKernel => (
                vec![(format!("stage0-vmlinux{suffix}"), kernel)],
                Some(BootProtocol::LinuxDirect),
                vec![VirtioVsock],
            ),
            ImageSetRole::QemuWasmSmokePack => (
                vec![("qemu-wasm-smoke.tar.gz".to_string(), ArtifactFormat::TarGz)],
                None,
                vec![],
            ),
        };
        let (artifacts, bytes): (Vec<_>, Vec<_>) = specs
            .into_iter()
            .map(|(name, format)| {
                let (artifact, bytes) = image_member_artifact(&name, format);
                (artifact, (name, bytes))
            })
            .unzip();
        (
            ImageSetMember {
                role,
                target,
                build_mode: None,
                source_fingerprint: None,
                boot_protocol,
                artifacts,
                required_capabilities,
                pack_hash: Some(Sha256Hex::from_bytes(
                    format!("pack:{role}:{target}").as_bytes(),
                )),
                sbom: Some(SbomReference {
                    uri: format!("https://example.test/{role}/{target}.cdx.json"),
                    sha256: Sha256Hex::from_bytes(format!("sbom:{role}:{target}").as_bytes()),
                }),
            },
            bytes,
        )
    }

    /// A complete set as the image repository still publishes it: the
    /// Linux layer plus the retired overlay and initramfs members a bundle's
    /// boot assets are selected from.
    fn complete_image_set() -> (ImageSetManifest, Vec<(String, Vec<u8>)>) {
        let mut members = Vec::new();
        let mut bytes = Vec::new();
        let retired = [GuestArch::X86_64, GuestArch::Aarch64]
            .into_iter()
            .flat_map(|arch| {
                [BOOT_ASSET_OVERLAY_ROLE, BOOT_ASSET_INITRAMFS_ROLE]
                    .into_iter()
                    .map(move |role| (role, MemberTarget::Arch(arch)))
            });
        let required = ImageSetRequirement::current_train()
            .members()
            .iter()
            .map(|required| (required.role, required.target))
            .collect::<Vec<_>>();
        for (role, target) in required.into_iter().chain(retired) {
            let (member, member_bytes) = image_member(role, target);
            members.push(member);
            bytes.extend(member_bytes);
        }
        (
            ImageSetManifest {
                schema_version: crate::image_set::LEGACY_IMAGE_SET_SCHEMA_VERSION,
                set_version: ImageSetVersion::new("1.0.0").expect("version"),
                issued_at: Utc.with_ymd_and_hms(2026, 9, 23, 0, 0, 0).unwrap(),
                producer: ImageSetProducer::Release(ReleaseProducer {
                    repository: RepositorySlug::new("tinylabscom/mvm-images").expect("repo"),
                    workflow: WorkflowPath::new(".github/workflows/release.yml").expect("workflow"),
                    release_tag: ReleaseTag::new("v1.0.0").expect("tag"),
                    source_commit: GitCommit::new("a".repeat(40)).expect("commit"),
                }),
                mvm_source_commit: Some(GitCommit::new("b".repeat(40)).expect("commit")),
                compatibility: ImageSetCompatibility {
                    guest_agent_protocol: Some(ProtocolRange::new(2, 2).expect("protocol")),
                    builder_cache_contract: 4,
                    builder_boot_abi: None,
                    base_image_contract: None,
                },
                nix_inputs: NixInputs {
                    flake_locks: vec![FlakeLockIdentity {
                        reference: "nix/images".to_string(),
                        lock_hash: Sha256Hex::from_bytes(b"lock"),
                    }],
                    source_revisions: vec![SourceRevisionIdentity {
                        repository: "https://github.com/NixOS/nixpkgs".to_string(),
                        revision: "c".repeat(40),
                        tree_hash: Sha256Hex::from_bytes(b"tree"),
                    }],
                },
                revocation_channel: Some(
                    RevocationChannel::new("https://example.test/revocations.json")
                        .expect("revocation channel"),
                ),
                supersedes: None,
                members,
            },
            bytes,
        )
    }

    fn embedded_bundle(
        sk: &SigningKey,
        image_set: &ImageSetManifest,
        image_bytes: &[(String, Vec<u8>)],
    ) -> Vec<u8> {
        embedded_bundle_with_schema(sk, image_set, image_bytes, BUNDLE_SCHEMA_VERSION)
    }

    fn embedded_bundle_with_schema(
        sk: &SigningKey,
        image_set: &ImageSetManifest,
        image_bytes: &[(String, Vec<u8>)],
        schema_version: u32,
    ) -> Vec<u8> {
        let image_manifest = serde_json::to_vec(image_set).expect("image-set JSON");
        let mut artifacts = vec![art(
            "image-set.json",
            ArtifactRole::Other,
            "artifacts/image-set.json",
            &image_manifest,
        )];
        let mut payload = vec![("artifacts/image-set.json".to_string(), image_manifest)];
        for (name, bytes) in image_bytes {
            let path = format!("artifacts/{name}");
            artifacts.push(art(name, ArtifactRole::Other, &path, bytes));
            payload.push((path, bytes.clone()));
        }
        let mut manifest = make_manifest(key_id_from_pubkey(&sk.verifying_key()), artifacts);
        manifest.schema_version = schema_version;
        manifest.members = vec![BundleMember::EmbeddedImageSet {
            manifest_artifact: "image-set.json".to_string(),
        }];
        write_bundle(&manifest, sk, payload).expect("embedded bundle")
    }

    #[test]
    fn typed_members_require_bundle_schema_v3() {
        let sk = fresh_key();
        // The production writer now refuses this malformed member floor too;
        // hand-seal it to exercise the reader's independent refusal.
        let archive = hand_sealed_bundle_with(
            &sk,
            |manifest| {
                manifest.schema_version = 2;
                manifest.members = vec![BundleMember::EmbeddedImageSet {
                    manifest_artifact: "image-set.json".into(),
                }];
            },
            |_| {},
        );
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::MembersRequireSchemaV3 { found: 2 })
        ));
    }

    #[test]
    fn schema_six_reader_refuses_canonical_seven_before_parsing_its_member() {
        let bytes = br#"{"schema_version":7,"members":[{"class":"canonical_linux_proof"}]}"#;
        assert!(matches!(
            check_schema_cap(bytes, 6),
            Err(BundleVerifyError::UnsupportedSchema {
                found: 7,
                supported: 6
            })
        ));
        assert!(check_schema_cap(br#"{"schema_version":6}"#, 6).is_ok());
    }

    fn boot_bundle(
        sk: &SigningKey,
        image_set: &ImageSetManifest,
        arch: &str,
        image_bytes: &[(String, Vec<u8>)],
    ) -> Vec<u8> {
        let image_manifest = serde_json::to_vec(image_set).unwrap();
        let mut artifacts = vec![art(
            "image-set.json",
            ArtifactRole::Other,
            "artifacts/image-set.json",
            &image_manifest,
        )];
        let mut payload = vec![("artifacts/image-set.json".to_string(), image_manifest)];
        for (name, bytes) in image_bytes {
            let path = format!("artifacts/{name}");
            artifacts.push(art(name, ArtifactRole::Other, &path, bytes));
            payload.push((path, bytes.clone()));
        }
        let mut manifest = make_manifest(key_id_from_pubkey(&sk.verifying_key()), artifacts);
        manifest.schema_version = 4;
        manifest.arch = arch.to_string();
        manifest.members.push(BundleMember::EmbeddedBootAssets {
            manifest_artifact: "image-set.json".into(),
        });
        write_bundle(&manifest, sk, payload).unwrap()
    }

    fn boot_payload(
        image_set: &ImageSetManifest,
        arch: GuestArch,
        bytes: &[(String, Vec<u8>)],
    ) -> Vec<(String, Vec<u8>)> {
        let names: BTreeSet<_> = select_boot_asset_members(image_set, arch)
            .unwrap()
            .into_iter()
            .flat_map(|member| {
                member
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.name.as_str())
            })
            .collect();
        bytes
            .iter()
            .filter(|(name, _)| names.contains(name.as_str()))
            .cloned()
            .collect()
    }

    #[test]
    fn boot_subsets_preserve_original_root_without_poisoning_full_cache() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let home = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(home.path().join("bundles"));
        for (arch, label) in [
            (GuestArch::X86_64, "x86_64"),
            (GuestArch::Aarch64, "aarch64"),
        ] {
            let payload = boot_payload(&image_set, arch, &bytes);
            let archive = boot_bundle(&sk, &image_set, label, &payload);
            let verified = read_and_verify_bundle(&archive, &trust(&sk)).unwrap();
            assert!(verified.embedded_image_sets.is_empty());
            let boot = verified.boot_assets.unwrap();
            assert_eq!(boot.arch, arch);
            assert_eq!(
                boot.image_set.manifest_sha256,
                Sha256Hex::from_bytes(&serde_json::to_vec(&image_set).unwrap())
            );
            assert_eq!(boot.image_set.artifact_paths.len(), 2);
            registry.install(&archive, &trust(&sk), false).unwrap();
            assert!(
                !registry
                    .embedded_image_set_cache_root()
                    .join(boot.image_set.manifest_sha256.as_str())
                    .exists()
            );
            let path = registry.archive_path(&bundle_sha256(&archive));
            assert_eq!(
                verify_bundle_file(&path, &trust(&sk))
                    .unwrap()
                    .boot_assets
                    .unwrap()
                    .arch,
                arch
            );
        }
        let archive = embedded_bundle_with_schema(&sk, &image_set, &bytes, 3);
        registry.install(&archive, &trust(&sk), false).unwrap();
        let full = read_and_verify_bundle(&archive, &trust(&sk)).unwrap();
        assert!(full.boot_assets.is_none());
        assert!(
            registry
                .embedded_image_set_cache_root()
                .join(full.embedded_image_sets[0].manifest_sha256.as_str())
                .exists()
        );
    }

    /// A CLI-assets bundle names its kernel by role: the verifier must pair the
    /// image set's kernel member with the bundle's `Kernel`-role artifact, not
    /// with whichever artifact happens to come first.
    #[test]
    fn cli_boot_assets_pair_the_image_set_kernel_with_the_kernel_role_artifact() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let arch = GuestArch::Aarch64;
        let kernel_member = select_cli_boot_kernel(&image_set, arch).unwrap();
        let kernel_name = kernel_member.artifacts[0].name.as_str().to_string();
        let kernel_bytes = bytes
            .iter()
            .find(|(name, _)| *name == kernel_name)
            .map(|(_, bytes)| bytes.clone())
            .expect("the kernel artifact's bytes");
        let image_manifest = serde_json::to_vec(&image_set).unwrap();

        let runtime_names = [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay",
            "overlay.verity",
        ];
        let mut artifacts = vec![art(
            "image-set.json",
            ArtifactRole::Other,
            "artifacts/image-set.json",
            &image_manifest,
        )];
        let mut payload = vec![("artifacts/image-set.json".to_string(), image_manifest)];
        for name in runtime_names {
            let body = format!("runtime bytes {name}").into_bytes();
            artifacts.push(art(
                name,
                ArtifactRole::Other,
                &format!("artifacts/{name}"),
                &body,
            ));
            payload.push((format!("artifacts/{name}"), body));
        }
        let initrd = b"initramfs bytes".to_vec();
        artifacts.push(art(
            "initrd",
            ArtifactRole::Initrd,
            "artifacts/initrd",
            &initrd,
        ));
        payload.push(("artifacts/initrd".to_string(), initrd));
        artifacts.push(art(
            &kernel_name,
            ArtifactRole::Kernel,
            &format!("artifacts/{kernel_name}"),
            &kernel_bytes,
        ));
        payload.push((format!("artifacts/{kernel_name}"), kernel_bytes));

        let mut manifest = make_manifest(key_id_from_pubkey(&sk.verifying_key()), artifacts);
        manifest.schema_version = 6;
        manifest.arch = arch.to_string();
        manifest.members = vec![BundleMember::EmbeddedCliBootAssets(EmbeddedCliBootAssets {
            manifest_artifact: "image-set.json".into(),
            version: "0.24.0".into(),
            arch: arch.to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        })];
        let archive = write_bundle(&manifest, &sk, payload).unwrap();

        let verified = read_and_verify_bundle(&archive, &trust(&sk)).unwrap();
        let boot = verified.boot_assets.expect("CLI boot assets verified");
        assert_eq!(boot.image_set.artifact_paths.len(), 1);
        assert!(boot.image_set.artifact_paths.contains_key(&kernel_name));
    }

    #[test]
    fn a_canonical_owner_binds_only_the_bundle_it_was_prepared_from() {
        let sk = fresh_key();
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let pin = |sha: &str| PlanArtifact::new(sha.repeat(64), &[7u8; 64], key_id.clone());
        let mut with_proof = make_manifest(key_id.clone(), Vec::new());
        with_proof.members = vec![BundleMember::CanonicalLinuxProof(CanonicalLinuxProof {
            manifest_artifact: "linux.json".into(),
            signature_bundle_artifact: "linux.bundle".into(),
            revocation_document_artifact: "revocations.json".into(),
            revocation_signature_bundle_artifact: "revocations.bundle".into(),
        })];
        let without_proof = make_manifest(key_id.clone(), Vec::new());

        owner_binds_canonical_bundle(&with_proof, &pin("a"), &pin("a")).unwrap();
        for (manifest, owner, bundle) in [
            (&with_proof, "a", "b"),
            (&without_proof, "a", "a"),
            (&without_proof, "a", "b"),
        ] {
            assert!(matches!(
                owner_binds_canonical_bundle(manifest, &pin(owner), &pin(bundle)),
                Err(PlanBundleError::CanonicalKernelBinding(_))
            ));
        }
    }

    #[test]
    fn schema4_file_plan_artifact_pins_the_original_signed_archive() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let payload = boot_payload(&image_set, GuestArch::Aarch64, &bytes);
        let archive = boot_bundle(&sk, &image_set, "aarch64", &payload);
        let expected = PlanArtifact::new(
            bundle_sha256(&archive),
            &extract_manifest_signature(&archive).unwrap(),
            key_id_from_pubkey(&sk.verifying_key()),
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.mvmpkg");
        std::fs::write(&path, &archive).unwrap();
        let verified = verify_bundle_file(&path, &trust(&sk)).unwrap();
        assert_eq!(verified.manifest.schema_version, 4);
        assert!(verified.boot_assets.is_some());
        assert_eq!(verified.plan_artifact(), expected);
        let independently_verified = verify_plan_bundle(
            &verified.plan_artifact(),
            &FixedResolver(archive.clone()),
            &trust(&sk),
        )
        .unwrap();
        assert_eq!(independently_verified.manifest, verified.manifest);

        let needle = b"\"schema_version\":4";
        let position = archive
            .windows(needle.len())
            .position(|bytes| bytes == needle)
            .unwrap();
        let mut tampered = archive;
        tampered[position + needle.len() - 1] = b'3';
        std::fs::write(&path, tampered).unwrap();
        assert!(matches!(
            verify_bundle_file(&path, &trust(&sk)),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn boot_selection_refuses_ambiguous_names_and_non_archive_formats() {
        let (mut image_set, _) = complete_image_set();
        let name = select_boot_asset_members(&image_set, GuestArch::Aarch64).unwrap()[0].artifacts
            [0]
        .name
        .clone();
        let initramfs = image_set
            .members
            .iter_mut()
            .find(|member| {
                member.role == BOOT_ASSET_INITRAMFS_ROLE && member.target.admits(GuestArch::Aarch64)
            })
            .unwrap();
        initramfs.artifacts[0].name = name;
        assert!(matches!(
            select_boot_asset_members(&image_set, GuestArch::Aarch64),
            Err(ImageSetError::DuplicateSelectedArtifact { .. })
        ));
        let (mut image_set, _) = complete_image_set();
        let overlay = image_set
            .members
            .iter_mut()
            .find(|member| {
                member.role == BOOT_ASSET_OVERLAY_ROLE && member.target.admits(GuestArch::Aarch64)
            })
            .unwrap();
        overlay.artifacts[0].format = ArtifactFormat::Text;
        assert!(matches!(
            select_boot_asset_members(&image_set, GuestArch::Aarch64),
            Err(ImageSetError::UnsupportedArtifactFormat { .. })
        ));
    }

    #[test]
    fn boot_assets_refuse_missing_wrong_arch_digest_and_size() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let payload = boot_payload(&image_set, GuestArch::Aarch64, &bytes);
        for arch in ["x86_64", "unknown"] {
            assert!(
                read_and_verify_bundle(&boot_bundle(&sk, &image_set, arch, &payload), &trust(&sk))
                    .is_err()
            );
        }
        assert!(matches!(
            read_and_verify_bundle(
                &boot_bundle(&sk, &image_set, "aarch64", &payload[..1]),
                &trust(&sk)
            ),
            Err(BundleVerifyError::ImageSetArtifactMissing { .. })
        ));
        let mut tampered = payload.clone();
        tampered[0].1[0] ^= 1;
        assert!(matches!(
            read_and_verify_bundle(
                &boot_bundle(&sk, &image_set, "aarch64", &tampered),
                &trust(&sk)
            ),
            Err(BundleVerifyError::ImageSetArtifactDigestMismatch { .. })
        ));
        let mut bad_set = image_set.clone();
        let selected_name = &payload[0].0;
        for artifact in bad_set
            .members
            .iter_mut()
            .flat_map(|member| &mut member.artifacts)
        {
            if artifact.name.as_str() == selected_name {
                artifact.size += 1;
            }
        }
        assert!(matches!(
            read_and_verify_bundle(
                &boot_bundle(&sk, &bad_set, "aarch64", &payload),
                &trust(&sk)
            ),
            Err(BundleVerifyError::ImageSetArtifactSizeMismatch { .. })
        ));
        let mut missing = image_set.clone();
        missing
            .members
            .retain(|member| member.role != BOOT_ASSET_INITRAMFS_ROLE);
        assert!(matches!(
            read_and_verify_bundle(
                &boot_bundle(&sk, &missing, "aarch64", &payload),
                &trust(&sk)
            ),
            Err(BundleVerifyError::ImageSetRefused { .. })
        ));
    }

    #[test]
    fn complete_embedded_image_set_verifies_every_nested_artifact() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let archive = embedded_bundle(&sk, &image_set, &bytes);
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("complete bundle");
        assert_eq!(verified.embedded_image_sets.len(), 1);
        assert_eq!(
            verified.embedded_image_sets[0].artifact_paths.len(),
            bytes.len()
        );
    }

    #[test]
    fn partial_embedded_image_set_is_refused_before_boot() {
        let sk = fresh_key();
        let (mut image_set, mut bytes) = complete_image_set();
        let removed = image_set.members.remove(0);
        let removed_names: BTreeSet<String> = removed
            .artifacts
            .iter()
            .map(|artifact| artifact.name.as_str().to_string())
            .collect();
        bytes.retain(|(name, _)| !removed_names.contains(name));
        let archive = embedded_bundle(&sk, &image_set, &bytes);
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::ImageSetRefused {
                reason: ImageSetError::Incomplete { .. },
                ..
            })
        ));
    }

    #[test]
    fn nested_image_digest_must_match_the_signed_bundle_declaration() {
        let sk = fresh_key();
        let (image_set, mut bytes) = complete_image_set();
        bytes[0]
            .1
            .extend_from_slice(b"tampered before bundle signing");
        let archive = embedded_bundle(&sk, &image_set, &bytes);
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::ImageSetArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn backend_capability_refusal_names_the_missing_device() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let archive = embedded_bundle(&sk, &image_set, &bytes);
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("complete bundle");
        let backend = BackendImageSupport {
            guest_arches: vec![GuestArch::X86_64],
            boot_protocols: vec![BootProtocol::LinuxDirect],
            artifact_formats: vec![
                ArtifactFormat::Kernel(KernelFormat::Elf),
                ArtifactFormat::Ext4,
                ArtifactFormat::VerityHashTree,
                ArtifactFormat::VerityRootHash,
                ArtifactFormat::TarGz,
            ],
            device_capabilities: vec![
                GuestDeviceRequirement::VirtioVsock,
                GuestDeviceRequirement::VirtioBlk,
            ],
        };
        let host = HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
            builder_cache_contract: 4,
            builder_boot_abi: crate::image_set::BuilderBootAbiRange::LEGACY_ONLY,
        };
        assert!(matches!(
            check_embedded_image_set_for_backend(
                &verified.embedded_image_sets[0],
                GuestArch::X86_64,
                &backend,
                &host,
            ),
            Err(ImageSetError::MissingDeviceCapability {
                capability: GuestDeviceRequirement::DmVerity,
                ..
            })
        ));
    }

    #[test]
    fn embedded_bundle_bytes_and_identity_are_host_independent() {
        let sk = SigningKey::from_bytes(&[42; 32]);
        let (image_set, bytes) = complete_image_set();
        let first = embedded_bundle(&sk, &image_set, &bytes);
        let second = embedded_bundle(&sk, &image_set, &bytes);
        assert_eq!(first, second);
        assert_eq!(bundle_sha256(&first), bundle_sha256(&second));
    }

    #[test]
    fn install_populates_and_reverifies_the_image_set_cas() {
        let sk = fresh_key();
        let (image_set, bytes) = complete_image_set();
        let archive = embedded_bundle(&sk, &image_set, &bytes);
        let temp = tempfile::tempdir().expect("tempdir");
        let registry = BundleRegistry::new(temp.path().join("bundles"));
        let installed = registry
            .install(&archive, &trust(&sk), false)
            .expect("install complete bundle");
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("verify");
        let cache = registry
            .embedded_image_set_cache_root()
            .join(verified.embedded_image_sets[0].manifest_sha256.as_str());
        assert!(cache.join("image-set.json").is_file());

        let first_name = verified.embedded_image_sets[0]
            .artifact_paths
            .keys()
            .next()
            .expect("artifact name");
        std::fs::write(cache.join("artifacts").join(first_name), b"tampered")
            .expect("tamper cache");
        let error = registry
            .install(&archive, &trust(&sk), true)
            .expect_err("tampered cache must fail closed");
        assert!(
            error.to_string().contains("failed re-verification"),
            "unexpected error: {error}"
        );
        assert!(registry.install_dir(&installed.sha256).exists());
    }

    #[test]
    fn key_id_is_32_hex_chars() {
        let sk = fresh_key();
        let id = key_id_from_pubkey(&sk.verifying_key());
        assert_eq!(id.0.len(), 32);
        assert!(id.is_well_formed());
    }

    #[test]
    fn key_id_from_identity_is_well_formed_and_stable() {
        let id =
            "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";
        let a = key_id_from_identity(id);
        let b = key_id_from_identity(id);
        assert_eq!(a, b, "same identity yields same id");
        assert!(a.is_well_formed(), "32 lowercase hex");
        assert_ne!(
            a,
            key_id_from_identity("other"),
            "different identity differs"
        );
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
        let key_id_a = key_id_from_pubkey(&sk_a.verifying_key());
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let manifest_bytes = canonical_manifest_bytes(&manifest).unwrap();
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let manifest_bytes = canonical_manifest_bytes(&manifest).unwrap();
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

    /// Each unsafe shape rejected on its own.
    ///
    /// `unsafe_path_rejected_in_manifest` below accepts either
    /// `UnsafePath` *or* `ArtifactMissing`, because the `../` entry never
    /// makes it into the tar. That acceptance is wider than the property,
    /// so deleting the guard entirely still satisfies it — mutation
    /// testing caught `ensure_safe_path -> Ok(())` surviving. This
    /// exercises the function directly, one clause per case, so each
    /// disjunct in the condition is independently load-bearing.
    #[test]
    fn ensure_safe_path_rejects_each_unsafe_shape() {
        for bad in [
            "",                   // empty
            "/etc/passwd",        // absolute
            "a\\b",               // backslash separator
            "../etc/passwd",      // leading traversal
            "a/../../etc/passwd", // interior traversal
            "./a",                // leading single-dot segment
            "a/./b",              // interior single-dot segment
        ] {
            assert!(
                matches!(
                    ensure_safe_path(bad),
                    Err(BundleVerifyError::UnsafePath { .. })
                ),
                "expected {bad:?} to be rejected as an unsafe archive path"
            );
        }
    }

    /// The positive half: an ordinary relative path is admitted. Without
    /// this, a guard that rejected everything would also pass the case
    /// above.
    #[test]
    fn ensure_safe_path_admits_ordinary_relative_paths() {
        for good in ["kernel.bin", "artifacts/kernel.bin", "a/b/c.img"] {
            assert!(
                ensure_safe_path(good).is_ok(),
                "expected {good:?} to be admitted"
            );
        }
    }

    #[test]
    fn unsafe_path_rejected_in_manifest() {
        // The path validator runs both at write time and at read
        // time. Build the archive by hand to exercise the read-time
        // branch.
        let sk = fresh_key();
        let kernel = b"k".to_vec();
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let manifest_bytes = canonical_manifest_bytes(&manifest).unwrap();
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());

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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let m = make_manifest(
            key_id,
            vec![art("k", ArtifactRole::Kernel, "artifacts/k", b"X")],
        );
        let bytes = canonical_manifest_bytes(&m).unwrap();
        let parsed: BundleManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn fs_trust_store_loads_pubkey() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let key_id = key_id_from_pubkey(&vk);
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
        let key_id_a = key_id_from_pubkey(&sk_a.verifying_key());
        let manifest = make_manifest(key_id_a, vec![]);
        let err = write_bundle(&manifest, &sk_b, vec![]).expect_err("rejects");
        assert!(format!("{err:#}").contains("does not match"));
    }

    /// A signer that keeps its key to itself and signs on request, the way a
    /// KMS does. `answer` decides what it sends back.
    struct RemoteSigner {
        key: SigningKey,
        answer: RemoteAnswer,
    }

    enum RemoteAnswer {
        Honest,
        /// A valid signature, but over other bytes.
        WrongMessage,
        /// The service refused or could not be reached.
        Unavailable,
    }

    impl ManifestSigner for RemoteSigner {
        fn verifying_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }

        fn sign_manifest(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]> {
            match self.answer {
                RemoteAnswer::Honest => Ok(self.key.sign(canonical_manifest).to_bytes()),
                RemoteAnswer::WrongMessage => Ok(self.key.sign(b"something else").to_bytes()),
                RemoteAnswer::Unavailable => anyhow::bail!("signing service unavailable"),
            }
        }
    }

    fn remote(answer: RemoteAnswer) -> RemoteSigner {
        RemoteSigner {
            key: fresh_key(),
            answer,
        }
    }

    #[test]
    fn a_signer_that_never_hands_out_its_key_produces_a_verifiable_bundle() {
        let signer = remote(RemoteAnswer::Honest);
        let manifest = make_manifest(key_id_from_pubkey(&signer.verifying_key()), vec![]);

        let archive = write_bundle(&manifest, &signer, vec![]).expect("sealed");

        let store = trust(&signer.key);
        let verified = read_and_verify_bundle(&archive, &store).expect("verifies");
        assert_eq!(verified.key_id, manifest.key_id);
    }

    #[test]
    fn a_signature_over_other_bytes_is_refused_at_write_time() {
        let signer = remote(RemoteAnswer::WrongMessage);
        let manifest = make_manifest(key_id_from_pubkey(&signer.verifying_key()), vec![]);

        let err = write_bundle(&manifest, &signer, vec![]).expect_err("refused");

        assert!(
            format!("{err:#}").contains("does not verify under its own key"),
            "{err:#}"
        );
    }

    #[test]
    fn a_signer_that_fails_fails_the_write() {
        let signer = remote(RemoteAnswer::Unavailable);
        let manifest = make_manifest(key_id_from_pubkey(&signer.verifying_key()), vec![]);

        let err = write_bundle(&manifest, &signer, vec![]).expect_err("refused");

        let message = format!("{err:#}");
        assert!(message.contains("signing the bundle manifest"), "{message}");
        assert!(message.contains("signing service unavailable"), "{message}");
    }

    #[test]
    fn write_bundle_rejects_artifact_sha256_drift() {
        let sk = fresh_key();
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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

    /// Replay vectors: frozen inputs and the addresses they must produce.
    ///
    /// The neighbouring lowercase-hex test uses `sha256("abc")`, a textbook
    /// vector that pins the output *encoding* and nothing about how a bundle
    /// is addressed. These pin the address itself, including that it is taken
    /// over raw archive bytes with no text conversion anywhere in the path.
    ///
    /// `MVM_PRINT_ADDRESS_VECTORS=1` prints instead of asserting.
    #[test]
    fn bundle_sha256_vectors_are_frozen() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "empty",
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "ascii",
                b"mvm bundle contents",
                "05aff18ed1fc9ed295f062e6f279f166cae4dc6dc823007a928f2aa5a54a3e68",
            ),
            // Raw bytes, not text. A digest that went through any string
            // conversion would differ here: 0x00 truncates a C string, 0xff
            // and 0x80 are not valid UTF-8 on their own.
            (
                "binary-with-nul-and-high-bytes",
                &[0x00, 0xff, 0x01, 0xfe, 0x80, 0x7f],
                "609f600034067e63d4c7d4440226395296d0bd91ddcb64ae199b2bdb41224f5a",
            ),
        ];

        for (name, input, expected) in cases {
            let actual = bundle_sha256(input);
            if std::env::var_os("MVM_PRINT_ADDRESS_VECTORS").is_some() {
                println!("bundle_sha256\t{name}\t{actual}");
                continue;
            }
            assert_eq!(
                &actual, expected,
                "bundle_sha256/{name}: address moved — every published bundle \
                 addressed this way just changed"
            );
        }
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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
        let manifest_bytes = canonical_manifest_bytes(&manifest).unwrap();
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

    /// An absent registry root is "nothing installed": `remove` answers
    /// `false` without creating the root as a side effect of locking.
    #[test]
    fn bundle_registry_remove_on_an_absent_root_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("never-created");
        let registry = BundleRegistry::new(&root);
        assert!(!registry.remove(&"a".repeat(64)).expect("remove ok"));
        assert!(!root.exists(), "removing from nothing must not create it");
    }

    #[test]
    fn bundle_registry_remove_reports_root_lookup_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("not-a-directory");
        std::fs::write(&parent, b"retain this file").unwrap();
        let root = parent.join("bundles");
        let lookup_error = std::fs::symlink_metadata(&root).unwrap_err();
        assert_ne!(lookup_error.kind(), std::io::ErrorKind::NotFound);

        let error = BundleRegistry::new(&root)
            .remove(&"a".repeat(64))
            .expect_err("an inaccessible registry is not an absent bundle");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            lookup_error.kind()
        );
        assert_eq!(std::fs::read(parent).unwrap(), b"retain this file");
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let mut manifest = make_manifest(key_id, Vec::new());
        manifest.resources = Some(BundleResources {
            vcpus: 4,
            mem_mib: 2048,
        });
        let bytes = canonical_manifest_bytes(&manifest).unwrap();
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let manifest = make_manifest(key_id, Vec::new()); // resources: None
        let bytes = canonical_manifest_bytes(&manifest).unwrap();
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
        let key_id = key_id_from_pubkey(&sk.verifying_key());
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

    /// A read failure that is not "absent" must not be reported as
    /// absent. The two are different answers: absent means the caller
    /// may go fetch the bundle, unreadable means the local registry is
    /// broken. Collapsing the guard to `true` merged them and nothing
    /// noticed.
    ///
    /// A directory where the archive should be gives a deterministic
    /// non-NotFound errno on every platform and without depending on
    /// the test process being unprivileged.
    #[test]
    fn fs_resolver_reports_io_rather_than_missing_when_the_path_is_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "a".repeat(64);
        std::fs::create_dir_all(tmp.path().join(format!("{sha}.mvmpkg"))).unwrap();

        let resolver = FsBundleResolver::new(tmp.path());
        match resolver.resolve(&sha) {
            Err(BundleResolveError::Io { bundle_sha256, .. }) => assert_eq!(bundle_sha256, sha),
            other => panic!("expected Io for an unreadable archive path, got {other:?}"),
        }

        // The absent case still reports absent — the point is that the
        // two are distinguished, not that everything is now an error.
        match resolver.resolve(&"b".repeat(64)) {
            Err(BundleResolveError::MissingBundle { .. }) => {}
            other => panic!("expected MissingBundle for an absent archive, got {other:?}"),
        }
    }

    /// `remove` swallowing a real removal failure tells the operator a
    /// bundle is gone when it is still installed. Only "already absent"
    /// is allowed to be silent.
    #[test]
    fn bundle_registry_remove_surfaces_a_real_removal_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sha = "c".repeat(64);

        // A non-empty directory where the archive file should be:
        // remove_file refuses it, and the refusal is not NotFound.
        let archive = registry.archive_path(&sha);
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::write(archive.join("occupant"), b"x").unwrap();

        assert!(
            registry.remove(&sha).is_err(),
            "a removal that failed must not be reported as a completed removal"
        );

        // The install dir has its own guard, and it needs its own case:
        // a test that only breaks the archive removal leaves the second
        // guard free to swallow everything. A plain file where the
        // install directory should be makes remove_dir_all refuse.
        let dir_sha = "e".repeat(64);
        std::fs::write(registry.install_dir(&dir_sha), b"not a directory").unwrap();
        assert!(
            registry.remove(&dir_sha).is_err(),
            "a failed install-dir removal must not be reported as a completed removal"
        );

        // Nothing installed at all is still the quiet, successful case.
        let clean = BundleRegistry::new(tmp.path().join("empty"));
        assert!(
            !clean
                .remove(&"d".repeat(64))
                .expect("absent removes cleanly")
        );
    }

    /// An unreadable registry root must error, not read as "no bundles
    /// installed". `gc --all` over a silently-empty list deletes nothing
    /// and reports success.
    #[test]
    fn bundle_registry_list_errors_when_the_root_is_not_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root-is-a-file");
        std::fs::write(&root, b"not a directory").unwrap();

        let registry = BundleRegistry::new(&root);
        assert!(
            registry.list().is_err(),
            "an unreadable registry root must not read as an empty registry"
        );
    }

    /// The name filter is a conjunction: 64 characters *and* all hex.
    /// Weakened to a disjunction it admits any 64-character name and any
    /// short hex name, so staging and scratch directories surface as
    /// installed bundles and `gc` treats them as such.
    #[test]
    fn bundle_registry_list_requires_both_length_and_hex() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let valid = "0123456789abcdef".repeat(4);
        assert_eq!(valid.len(), 64);

        for name in [
            valid.as_str(),
            // 64 characters, not hex.
            "z".repeat(64).as_str(),
            // Hex, not 64 characters.
            "abc",
            // Neither.
            "scratch",
        ] {
            std::fs::create_dir_all(tmp.path().join(name)).unwrap();
        }

        assert_eq!(
            registry.list().expect("list ok"),
            vec![valid],
            "only a 64-char lowercase-hex directory is an installed bundle"
        );
    }

    fn sealed_posture() -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile: crate::policy::security::AgentProfile::SealedProd,
            verity_protected: true,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: false,
        }
    }

    /// A kernel + rootfs + verity bundle carrying `members`, signed by `sk`
    /// without going through [`write_bundle`]'s refusal — what a publisher
    /// with other tooling could hand a consumer.
    fn hand_sealed_bundle(sk: &SigningKey, members: Vec<BundleMember>) -> Vec<u8> {
        hand_sealed_bundle_with(sk, |manifest| manifest.members = members, |_| {})
    }

    /// [`hand_sealed_bundle`], with the manifest edited first as a typed value
    /// and then as signed JSON, so a test can seal what this build's types
    /// cannot express (a capability or field a newer publisher wrote).
    fn hand_sealed_bundle_with(
        sk: &SigningKey,
        edit: impl FnOnce(&mut BundleManifest),
        edit_json: impl FnOnce(&mut serde_json::Value),
    ) -> Vec<u8> {
        let payload = [
            ("artifacts/vmlinux", ArtifactRole::Kernel, b"k".as_slice()),
            ("artifacts/rootfs.ext4", ArtifactRole::Rootfs, b"r"),
            (
                "artifacts/rootfs.verity",
                ArtifactRole::VerityHashSidecar,
                b"v",
            ),
        ];
        let mut manifest = make_manifest(
            key_id_from_pubkey(&sk.verifying_key()),
            payload
                .iter()
                .map(|(path, role, bytes)| {
                    art(path.rsplit('/').next().unwrap(), role.clone(), path, bytes)
                })
                .collect(),
        );
        manifest.verity = Some(VerityInfo {
            roothash: "a".repeat(64),
            sidecar_artifact: "rootfs.verity".to_string(),
        });
        edit(&mut manifest);
        let mut value = serde_json::to_value(&manifest).unwrap();
        edit_json(&mut value);
        let manifest_bytes = serde_json::to_vec(&value).unwrap();
        let sig = sk.sign(&manifest_bytes).to_bytes();
        let mut tar = tar::Builder::new(Vec::new());
        append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
        append_bytes(&mut tar, SIGNATURE_FILENAME, &sig).unwrap();
        for (path, _, bytes) in payload {
            append_bytes(&mut tar, path, bytes).unwrap();
        }
        tar.into_inner().unwrap()
    }

    #[test]
    fn manifest_scan_stops_at_the_first_complete_set_of_entries() {
        // A later duplicate must never replace what the scan already settled on.
        let archive = |entries: &[(&str, &[u8])]| {
            let mut tar = tar::Builder::new(Vec::new());
            for (path, bytes) in entries {
                append_bytes(&mut tar, path, bytes).unwrap();
            }
            tar.into_inner().unwrap()
        };

        let signed = archive(&[
            (MANIFEST_FILENAME, b"first"),
            (SIGNATURE_FILENAME, b"sig"),
            (MANIFEST_FILENAME, b"second"),
        ]);
        let (manifest, signature) = stream::read_manifest_entries(Cursor::new(&signed)).unwrap();
        assert_eq!(manifest, b"first");
        assert_eq!(signature, b"sig");

        let unsigned = archive(&[
            (MANIFEST_FILENAME, b"first"),
            (MANIFEST_FILENAME, b"second"),
        ]);
        assert_eq!(
            stream::read_manifest_entry(Cursor::new(&unsigned)).unwrap(),
            b"first"
        );
    }

    /// A sealed-prod posture that allows egress and volumes, verity-bound.
    fn open_sealed_posture() -> BundleSecurityPosture {
        BundleSecurityPosture {
            allows_egress: true,
            allows_volumes: true,
            ..sealed_posture()
        }
    }

    fn environment_descriptor() -> EnvironmentDescriptor {
        serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "pack": { "name": "acme/agent", "version": "1.2.3" },
            "target": "aarch64-linux",
            "entrypoint": { "argv": ["/usr/bin/agent", "--serve"], "working_dir": "/srv" },
            "resources": { "cpu_cores": 2, "memory_mb": 1024 },
            "volumes": [{ "name": "workspace", "guest_path": "/workspace" }],
            "secret_slots": [{ "name": "AGENT_TOKEN", "required": true }],
            "capabilities": ["egress", "host_volumes"],
            "services": [{ "name": "indexer", "argv": ["/usr/bin/indexer"] }],
        }))
        .expect("environment fixture")
    }

    fn with_environment(manifest: &mut BundleManifest) {
        manifest.members = vec![
            BundleMember::SecurityPosture(open_sealed_posture()),
            BundleMember::Environment(environment_descriptor()),
        ];
    }

    #[test]
    fn an_environment_survives_sign_verify_and_install() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |_| {});
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("coherent bundle");
        assert_eq!(
            verified.manifest.environment(),
            Some(&environment_descriptor())
        );

        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let installed = registry.install(&archive, &trust(&sk), false).unwrap();
        let manifest = registry
            .verified_manifest(&installed.sha256, &trust(&sk))
            .unwrap()
            .expect("installed");
        assert_eq!(manifest.environment(), Some(&environment_descriptor()));
    }

    #[test]
    fn tampering_with_a_signed_environment_breaks_the_signature() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |_| {});
        let needle = br#""/usr/bin/agent""#;
        let at = archive
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("entrypoint is in the manifest bytes");
        let mut tampered = archive.clone();
        tampered[at..at + needle.len()].copy_from_slice(br#""/usr/bin/shell""#);
        assert!(matches!(
            read_and_verify_bundle(&tampered, &trust(&sk)),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_signed_capability_this_reader_does_not_know_is_refused() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |value| {
            value["members"][1]["capabilities"] = serde_json::json!(["raw_network"]);
        });
        let err = read_and_verify_bundle(&archive, &trust(&sk)).unwrap_err();
        assert!(
            matches!(&err, BundleVerifyError::ManifestParse(reason) if reason.contains("raw_network")),
            "{err}"
        );
    }

    #[test]
    fn a_signed_secret_value_in_a_slot_is_refused() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |value| {
            value["members"][1]["secret_slots"][0]["value"] = serde_json::json!("tok-123");
        });
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::ManifestParse(_))
        ));
    }

    #[test]
    fn an_unsupported_descriptor_version_is_refused_at_verify() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |value| {
            value["members"][1]["descriptor_version"] = serde_json::json!(2);
        });
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::MalformedEnvironment(
                EnvironmentDescriptorError::UnsupportedVersion { found: 2, .. }
            ))
        ));
    }

    #[test]
    fn an_environment_for_another_arch_is_refused_at_verify() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(&sk, with_environment, |value| {
            value["members"][1]["target"] = serde_json::json!("x86_64-linux");
        });
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::EnvironmentRefused { .. })
        ));
    }

    #[test]
    fn an_environment_beyond_its_posture_is_refused_at_verify() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(
            &sk,
            |manifest| {
                with_environment(manifest);
                manifest.members[0] = BundleMember::SecurityPosture(sealed_posture());
            },
            |_| {},
        );
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::EnvironmentRefused { reason }) if reason.contains("egress")
        ));
    }

    #[test]
    fn an_environment_stamped_with_an_older_schema_is_refused() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(
            &sk,
            |manifest| {
                with_environment(manifest);
                manifest.schema_version = 4;
            },
            |_| {},
        );
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::EnvironmentRefused { reason }) if reason.contains("schema 5")
        ));
    }

    /// The old-reader fixture: a schema-4 bundle written before the
    /// environment member existed still verifies, carries no descriptor, and
    /// reads exactly as it did.
    #[test]
    fn a_schema_four_bundle_without_an_environment_still_verifies() {
        let sk = fresh_key();
        let archive = hand_sealed_bundle_with(
            &sk,
            |manifest| {
                manifest.schema_version = 4;
                manifest.members = vec![BundleMember::SecurityPosture(sealed_posture())];
            },
            |_| {},
        );
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("v4 still verifies");
        assert_eq!(verified.manifest.schema_version, 4);
        assert!(verified.manifest.environment().is_none());
    }

    #[test]
    fn declarations_survive_sign_and_verify() {
        let sk = fresh_key();
        let members = vec![
            BundleMember::KernelCmdline {
                cmdline: "console=ttyS0".to_string(),
            },
            BundleMember::SecurityPosture(sealed_posture()),
        ];
        let archive = hand_sealed_bundle(&sk, members);
        let verified = read_and_verify_bundle(&archive, &trust(&sk)).expect("coherent bundle");
        assert_eq!(verified.manifest.kernel_cmdline(), Some("console=ttyS0"));
        assert_eq!(
            verified.manifest.security_posture(),
            Some(&sealed_posture())
        );
        assert!(verified.embedded_image_sets.is_empty());
    }

    #[test]
    fn a_signed_but_malformed_posture_is_refused_at_verify() {
        let sk = fresh_key();
        let unauthenticated = BundleSecurityPosture {
            requires_auth: false,
            ..sealed_posture()
        };
        let archive = hand_sealed_bundle(&sk, vec![BundleMember::SecurityPosture(unauthenticated)]);
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::MalformedPosture { .. })
        ));
    }

    #[test]
    fn widening_a_signed_posture_breaks_the_signature() {
        let sk = fresh_key();
        let archive =
            hand_sealed_bundle(&sk, vec![BundleMember::SecurityPosture(sealed_posture())]);
        let needle = br#""allows_egress":false"#;
        let at = archive
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("posture is in the manifest bytes");
        let mut tampered = archive.clone();
        tampered[at..at + needle.len()].copy_from_slice(br#""allows_egress":true "#);
        assert!(matches!(
            read_and_verify_bundle(&tampered, &trust(&sk)),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn write_bundle_refuses_to_seal_a_malformed_posture() {
        let sk = fresh_key();
        let mut manifest = make_manifest(
            key_id_from_pubkey(&sk.verifying_key()),
            vec![art(
                "vmlinux",
                ArtifactRole::Kernel,
                "artifacts/vmlinux",
                b"k",
            )],
        );
        manifest.members = vec![BundleMember::SecurityPosture(sealed_posture())];
        let err = write_bundle(
            &manifest,
            &sk,
            vec![("artifacts/vmlinux".to_string(), b"k".to_vec())],
        )
        .expect_err("sealed-prod posture without verity");
        assert!(format!("{err:#}").contains("verity"), "{err:#}");
    }

    #[test]
    fn an_entry_header_over_the_cap_is_refused_before_its_bytes_are_read() {
        // The header claims 3 GiB; the archive holds a few bytes. Reading the
        // body would fail with a short read; the cap must fire first.
        let mut header = tar::Header::new_gnu();
        header.set_path("artifacts/rootfs.ext4").unwrap();
        header.set_size(3 * 1024 * 1024 * 1024);
        header.set_mode(0o644);
        header.set_cksum();
        let mut archive = header.as_bytes().to_vec();
        archive.extend_from_slice(&[0u8; 512]);
        let sk = fresh_key();
        assert!(matches!(
            read_and_verify_bundle(&archive, &trust(&sk)),
            Err(BundleVerifyError::EntryTooLarge { size, .. }) if size == 3 * 1024 * 1024 * 1024
        ));
    }

    #[test]
    fn verified_manifest_reads_the_posture_of_an_installed_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive =
            hand_sealed_bundle(&sk, vec![BundleMember::SecurityPosture(sealed_posture())]);
        let installed = registry.install(&archive, &trust(&sk), false).unwrap();

        let manifest = registry
            .verified_manifest(&installed.sha256, &trust(&sk))
            .expect("verifies")
            .expect("installed");
        assert_eq!(manifest.security_posture(), Some(&sealed_posture()));
        assert!(
            registry
                .verified_manifest(&"0".repeat(64), &trust(&sk))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn verified_manifest_refuses_a_posture_widened_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive =
            hand_sealed_bundle(&sk, vec![BundleMember::SecurityPosture(sealed_posture())]);
        let installed = registry.install(&archive, &trust(&sk), false).unwrap();
        let path = registry.archive_path(&installed.sha256);
        let mut bytes = std::fs::read(&path).unwrap();
        let needle = br#""allows_egress":false"#;
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        bytes[at..at + needle.len()].copy_from_slice(br#""allows_egress":true "#);
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            registry.verified_manifest(&installed.sha256, &trust(&sk)),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn verified_manifest_refuses_an_unknown_publisher() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let sk = fresh_key();
        let archive = hand_sealed_bundle(&sk, Vec::new());
        let installed = registry.install(&archive, &trust(&sk), false).unwrap();

        assert!(matches!(
            registry.verified_manifest(&installed.sha256, &trust(&fresh_key())),
            Err(BundleVerifyError::UnknownKey { .. })
        ));
    }

    fn installed_with(
        sk: &SigningKey,
        labelled: bool,
    ) -> (tempfile::TempDir, BundleRegistry, String) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        let archive = hand_sealed_bundle_with(
            sk,
            |m| {
                if labelled {
                    mark_local_build(m);
                }
            },
            |_| {},
        );
        let installed = registry.install(&archive, &trust(sk), false).unwrap();
        (tmp, registry, installed.sha256)
    }

    fn no_release_keys() -> MapTrustStore {
        MapTrustStore(HashMap::new())
    }

    #[test]
    fn host_signed_local_build_admits_without_enrolling_the_host_key() {
        let host = fresh_key();
        let (_tmp, registry, sha) = installed_with(&host, true);
        let manifest = registry
            .verified_launch_manifest(&sha, no_release_keys(), Some(host.verifying_key()))
            .expect("verifies")
            .expect("installed");
        assert_eq!(manifest.key_id, key_id_from_pubkey(&host.verifying_key()));
    }

    #[test]
    fn other_key_signed_bundle_is_refused_when_the_host_key_is_known() {
        let (_tmp, registry, sha) = installed_with(&fresh_key(), true);
        assert!(matches!(
            registry.verified_launch_manifest(
                &sha,
                no_release_keys(),
                Some(fresh_key().verifying_key())
            ),
            Err(BundleVerifyError::UnknownKey { .. })
        ));
    }

    #[test]
    fn host_signed_bundle_without_the_local_label_is_refused() {
        let host = fresh_key();
        let (_tmp, registry, sha) = installed_with(&host, false);
        assert!(matches!(
            registry.verified_launch_manifest(&sha, no_release_keys(), Some(host.verifying_key())),
            Err(BundleVerifyError::UnknownKey { .. })
        ));
    }

    #[test]
    fn tampered_host_signed_manifest_is_refused() {
        let host = fresh_key();
        let (_tmp, registry, sha) = installed_with(&host, true);
        let path = registry.archive_path(&sha);
        let mut bytes = std::fs::read(&path).unwrap();
        let needle = b"test-publisher";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        bytes[at] = b'T';
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            registry.verified_launch_manifest(&sha, no_release_keys(), Some(host.verifying_key())),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn an_attacker_key_claiming_the_host_key_id_is_refused() {
        let host = fresh_key();
        let attacker = fresh_key();
        let host_id = key_id_from_pubkey(&host.verifying_key());
        let archive = hand_sealed_bundle_with(
            &attacker,
            |m| {
                mark_local_build(m);
                m.key_id = host_id.clone();
            },
            |_| {},
        );
        let tmp = tempfile::tempdir().unwrap();
        let registry = BundleRegistry::new(tmp.path());
        // Install itself refuses the forgery: the host key_id does not derive
        // from the attacker's key.
        let mut forged_store = HashMap::new();
        forged_store.insert(host_id, attacker.verifying_key());
        assert!(
            registry
                .install(&archive, &MapTrustStore(forged_store), false)
                .is_err()
        );
        // A forged archive planted straight into the registry is refused at
        // launch: the host's real key does not verify the attacker's signature.
        let sha = hex::encode(Sha256::digest(&archive));
        std::fs::write(registry.archive_path(&sha), &archive).unwrap();
        assert!(matches!(
            registry.verified_launch_manifest(&sha, no_release_keys(), Some(host.verifying_key())),
            Err(BundleVerifyError::SignatureInvalid { .. })
        ));
    }
}
