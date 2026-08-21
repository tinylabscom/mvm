//! Content-addressed cache for attested packs.
//!
//! Promotion takes a *staged* (already-placed, local) pack directory and moves
//! it into the cache only after `verify_pack_at` accepts it in place. The
//! verified file set is copied into a same-filesystem quarantine dir and then
//! `rename`d onto the content-addressed `pack_dir`, so the atomic rename is the
//! single publish step — a concurrent reader never observes a half-populated
//! pack dir. Every *use* re-verifies, so a promoted entry that is later tampered
//! with is refused rather than served.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use thiserror::Error;

mod index;
pub use index::{PackEntry, PackIndex, PackKey};

use crate::arch::GuestArch;
use crate::config::{mvm_cache_dir, pack_cache_dir, pack_dir};
use crate::packs::{
    COSIGN_BUNDLE_FILE_NAME, KeylessTrust, LocalPackPolicy, PackBackend, PackKind, PackManifest,
    PackManifestError, PackRevocationChecker, PackTrustStore, PackVerifyError, Sha256Hex,
    VerifiedPack, verify_pack_at, verify_pack_keyless_at,
};
use crate::plan::bundle::KeyId;
use mvm_contract::builder::BuilderError;

/// Serialized manifest written alongside the verified file set so a promoted
/// pack is self-describing and `resolve_pack` can re-verify it without external
/// state. A dotfile name keeps it out of the way of a producer's own paths.
const MANIFEST_FILE_NAME: &str = ".pack-manifest.json";

/// Sibling of the promoted pack dirs used to stage a pack before the atomic
/// rename. On the same filesystem as `pack_dir`, so the rename never crosses a
/// mount boundary (which would degrade to a non-atomic copy).
const QUARANTINE_DIR_NAME: &str = ".incoming";

/// Process-local counter making quarantine dir names unique without a runtime
/// dependency (`tempfile` is a dev-only dep here). `<pid>-<counter>` is unique
/// within this process, and the pid disambiguates concurrent processes.
static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The trust inputs a verification pass needs, grouped so promotion and
/// resolution take one borrow instead of threading references through every
/// call. Authority-agnostic: `promote`/`resolve_pack` dispatch on the variant
/// rather than knowing which signing authority produced the pack.
pub enum PackVerifyCtx<'a> {
    Ed25519 {
        policy: &'a LocalPackPolicy,
        trust: &'a dyn PackTrustStore,
        revocations: &'a dyn PackRevocationChecker,
    },
    Keyless {
        policy: &'a LocalPackPolicy,
        keyless: &'a KeylessTrust,
        revocations: &'a dyn PackRevocationChecker,
    },
}

impl<'a> PackVerifyCtx<'a> {
    pub fn ed25519(
        policy: &'a LocalPackPolicy,
        trust: &'a dyn PackTrustStore,
        revocations: &'a dyn PackRevocationChecker,
    ) -> Self {
        Self::Ed25519 {
            policy,
            trust,
            revocations,
        }
    }

    pub fn keyless(
        policy: &'a LocalPackPolicy,
        keyless: &'a KeylessTrust,
        revocations: &'a dyn PackRevocationChecker,
    ) -> Self {
        Self::Keyless {
            policy,
            keyless,
            revocations,
        }
    }

    /// The local policy every verification variant carries — in particular
    /// `backend`, the concrete backend this host session is operating under.
    /// Used to pin the single `(kind, arch, backend)` index slot a promoted
    /// pack is recorded/activated against: a manifest's
    /// `backend_compatibility` is a set (an eligibility check at resolve
    /// time), not the one slot a given promotion applies to.
    fn policy(&self) -> &LocalPackPolicy {
        match self {
            Self::Ed25519 { policy, .. } | Self::Keyless { policy, .. } => policy,
        }
    }

    fn verify(
        &self,
        manifest: &PackManifest,
        root: &Path,
    ) -> Result<VerifiedPack, PackVerifyError> {
        match self {
            Self::Ed25519 {
                policy,
                trust,
                revocations,
            } => verify_pack_at(manifest, root, policy, *trust, *revocations),
            Self::Keyless {
                policy,
                keyless,
                revocations,
            } => {
                let bundle = std::fs::read(root.join(COSIGN_BUNDLE_FILE_NAME)).map_err(|e| {
                    PackVerifyError::KeylessSignatureInvalid(format!("reading cosign bundle: {e}"))
                })?;
                verify_pack_keyless_at(manifest, root, policy, &bundle, keyless, *revocations)
            }
        }
    }
}

/// A verified, content-addressed pack directory in the cache. Holding one means
/// the file set under `root` verified against its manifest at the moment it was
/// produced.
#[derive(Debug, Clone)]
pub struct VerifiedPackDir {
    pub root: PathBuf,
    pub verified: VerifiedPack,
}

/// Exact manifest and directory returned by digest-pinned resolution.
#[derive(Debug, Clone)]
pub struct VerifiedPackRecord {
    pub dir: VerifiedPackDir,
    pub manifest: PackManifest,
}

#[derive(Debug, Error)]
pub enum PackCacheError {
    #[error("pack verification failed: {0}")]
    Verify(#[from] PackVerifyError),
    #[error("pack manifest error: {0}")]
    Manifest(#[from] PackManifestError),
    #[error("pack cache i/o error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("pack declares a file with the reserved cache-sidecar name {0:?}")]
    ReservedFileName(String),
    #[error("no promoted version {hash:?} recorded for pack key {key:?}")]
    UnknownPackVersion { key: PackKey, hash: Sha256Hex },
    #[error("cached pack manifest at {path} is missing or malformed")]
    CachedManifestUnreadable { path: String },
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> PackCacheError + '_ {
    move |source| PackCacheError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Verify a staged pack in place, then atomically promote it into the cache.
///
/// Fail-closed: if the staged pack does not verify, nothing is written and the
/// cache is left untouched. Idempotent: if the content-addressed dir already
/// holds a still-verifying copy of this pack, that dir is returned unchanged; a
/// promoted dir whose content no longer verifies is replaced.
pub fn promote(
    staged_root: &Path,
    manifest: &PackManifest,
    ctx: &PackVerifyCtx<'_>,
) -> Result<VerifiedPackDir, PackCacheError> {
    promote_at(&pack_cache_dir(), staged_root, manifest, ctx)
}

/// Verify and promote beneath an explicit content-addressed cache root.
///
/// Provider processes use this form so an empty inherited environment cannot
/// redirect an admitted pack through `HOME` or `MVM_HOME`.
pub fn promote_at(
    cache_root: &Path,
    staged_root: &Path,
    manifest: &PackManifest,
    ctx: &PackVerifyCtx<'_>,
) -> Result<VerifiedPackDir, PackCacheError> {
    // A pack may not declare a file whose name collides with a sidecar this
    // cache writes (the manifest, or — for a keyless-authority pack — the
    // detached cosign bundle): doing so would let the sidecar clobber a
    // declared file (breaking re-verify forever) or vice versa. Reject before
    // touching the cache.
    if let Some(file) = manifest
        .outputs
        .files
        .iter()
        .find(|file| file.path == MANIFEST_FILE_NAME || file.path == COSIGN_BUNDLE_FILE_NAME)
    {
        return Err(PackCacheError::ReservedFileName(file.path.clone()));
    }

    // Verify the staged pack before touching the cache; on any error we return
    // it and leave the cache exactly as it was.
    let verified = ctx.verify(manifest, staged_root)?;

    let final_dir = cache_root.join(manifest.outputs.pack_hash.as_str());

    // A pre-existing promoted dir that still verifies is authoritative — skip the
    // copy entirely. One that no longer verifies is poisoned and must be replaced.
    if final_dir.exists() {
        if ctx.verify(manifest, &final_dir).is_ok() {
            return Ok(VerifiedPackDir {
                root: final_dir,
                verified,
            });
        }
        std::fs::remove_dir_all(&final_dir).map_err(io_at(&final_dir))?;
    }

    let quarantine = new_quarantine_dir_at(cache_root)?;
    match populate_and_rename(&quarantine, staged_root, manifest, &final_dir) {
        Ok(()) => Ok(VerifiedPackDir {
            root: final_dir,
            verified,
        }),
        Err(error) => {
            // Leave no partial staging behind on any failure.
            let _ = std::fs::remove_dir_all(&quarantine);
            Err(error)
        }
    }
}

/// Copy the verified file set + manifest into `quarantine`, then rename it onto
/// `final_dir`. The rename is the atomic-publish step.
fn populate_and_rename(
    quarantine: &Path,
    staged_root: &Path,
    manifest: &PackManifest,
    final_dir: &Path,
) -> Result<(), PackCacheError> {
    harden_dir(quarantine)?;
    for file in &manifest.outputs.files {
        let dest = quarantine.join(&file.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(io_at(parent))?;
        }
        let src = staged_root.join(&file.path);
        std::fs::copy(&src, &dest).map_err(io_at(&src))?;
    }
    let manifest_path = quarantine.join(MANIFEST_FILE_NAME);
    std::fs::write(&manifest_path, manifest.canonical_bytes()?).map_err(io_at(&manifest_path))?;

    // A keyless-authority pack carries a detached cosign bundle sidecar
    // alongside the staged files; an ed25519 pack simply won't have one. Carry
    // it through so it rides the atomic rename into the content-addressed dir,
    // where `resolve_pack`'s re-verify expects to find it.
    let staged_bundle = staged_root.join(COSIGN_BUNDLE_FILE_NAME);
    if staged_bundle.exists() {
        let dest_bundle = quarantine.join(COSIGN_BUNDLE_FILE_NAME);
        std::fs::copy(&staged_bundle, &dest_bundle).map_err(io_at(&staged_bundle))?;
    }

    if let Some(parent) = final_dir.parent() {
        harden_dir(parent)?;
    }
    // Atomic within a filesystem: readers see either no dir or the complete one.
    std::fs::rename(quarantine, final_dir).map_err(io_at(final_dir))?;
    harden_dir(final_dir)?;
    Ok(())
}

/// Path to the persisted pack index: `<cache_root>/packs/index.json`.
/// `cache_root` is the top-level mvm cache dir (`mvm_cache_dir()`), the same
/// root `pack_cache_dir()` nests `packs/` under.
fn index_path(cache_root: &Path) -> PathBuf {
    cache_root.join("packs").join("index.json")
}

/// Load the persisted pack index. Fail-open: a missing file or a corrupt one
/// (unreadable, truncated, or no longer matching the schema) yields
/// `PackIndex::default()` rather than an error — the index is a cache of
/// which promoted pack is "active", and every entry it points at is
/// re-verified before use, so losing it only costs the active-pointer
/// shortcut, never correctness.
pub fn load_index(cache_root: &Path) -> PackIndex {
    let Ok(bytes) = std::fs::read(index_path(cache_root)) else {
        return PackIndex::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Persist the pack index. Writes to a `.tmp` sibling and `rename`s it onto
/// the final path so a reader never observes a partially-written file.
pub fn save_index(cache_root: &Path, index: &PackIndex) -> Result<(), PackCacheError> {
    let path = index_path(cache_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_at(parent))?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(index).map_err(PackManifestError::Json)?;
    std::fs::write(&tmp_path, bytes).map_err(io_at(&tmp_path))?;
    std::fs::rename(&tmp_path, &path).map_err(io_at(&path))?;
    Ok(())
}

/// Verify one candidate promoted-pack dir against the requested
/// `(kind, arch, backend)`. Shared by the active-pointer lookup and the
/// directory scan in [`resolve_pack`] so both paths apply the exact same
/// checks: a readable manifest whose declared hash matches the dir's name, a
/// compatible `(kind, arch, backend)`, and a successful re-verify against
/// `ctx`. Returns `None` for any dir that isn't a valid, matching, verifying
/// promoted pack — never distinguishing "not found" from "found but
/// rejected" (callers that need that distinction use [`diagnose_pack`]).
fn verify_candidate_pack_dir(
    dir: &Path,
    kind: &PackKind,
    arch: GuestArch,
    backend: &PackBackend,
    ctx: &PackVerifyCtx<'_>,
) -> Option<VerifiedPackDir> {
    let manifest = read_manifest(dir)?;
    // Defense in depth: a content-addressed dir must be named for the pack
    // hash it holds. A name/content mismatch is observable-and-skipped rather
    // than served under the wrong identity.
    if dir.file_name()?.to_str() != Some(manifest.outputs.pack_hash.as_str()) {
        return None;
    }
    if &manifest.kind != kind
        || manifest.target_arch != arch
        || !manifest.backend_compatibility.contains(backend)
    {
        return None;
    }
    // Re-verify every use: a promoted-then-tampered entry fails here and is
    // skipped, so a poisoned pack is never handed back.
    let verified = ctx.verify(&manifest, dir).ok()?;
    Some(VerifiedPackDir {
        root: dir.to_path_buf(),
        verified,
    })
}

/// Resolve the promoted pack for `(kind, arch, backend)`, preferring the
/// active version recorded in the persisted index. Falls back to a directory
/// scan (today's non-deterministic-order behavior) when there is no index,
/// no active pointer for this key, or the active pack no longer verifies —
/// so an index that is missing, stale, or pointing at a poisoned pack never
/// makes a compatible pack unreachable. Returns `Ok(None)` when nothing
/// compatible verifies anywhere — a poisoned or mismatched entry is skipped,
/// never served.
pub fn resolve_pack(
    kind: PackKind,
    arch: GuestArch,
    backend: PackBackend,
    ctx: &PackVerifyCtx<'_>,
) -> Result<Option<VerifiedPackDir>, PackCacheError> {
    let cache_root = PathBuf::from(mvm_cache_dir());
    let index = load_index(&cache_root);
    let key = PackKey {
        kind: kind.clone(),
        arch,
        backend: backend.clone(),
    };
    if let Some(hash) = index.active_for(&key)
        && let Some(found) =
            verify_candidate_pack_dir(&pack_dir(hash.as_str()), &kind, arch, &backend, ctx)
    {
        return Ok(Some(found));
    }

    let root = pack_cache_dir();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        // No cache dir yet means no packs — not an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_at(&root)(error)),
    };

    for entry in entries {
        let entry = entry.map_err(io_at(&root))?;
        let dir = entry.path();
        let name = entry.file_name();
        if !dir.is_dir() || name.to_str() == Some(QUARANTINE_DIR_NAME) {
            continue;
        }
        if let Some(found) = verify_candidate_pack_dir(&dir, &kind, arch, &backend, ctx) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Resolve and re-verify one exact content-addressed pack.
///
/// Unlike active-version resolution, this never falls back to another pack:
/// a signed execution plan names one digest, so absence, tampering, kind
/// mismatch, or revocation of that digest must refuse the launch.
pub fn resolve_pack_digest(
    kind: PackKind,
    digest: &Sha256Hex,
    ctx: &PackVerifyCtx<'_>,
) -> Result<Option<VerifiedPackRecord>, PackCacheError> {
    resolve_pack_digest_at(&pack_cache_dir(), kind, digest, ctx)
}

/// Resolve and re-verify an exact digest beneath an explicit cache root.
pub fn resolve_pack_digest_at(
    cache_root: &Path,
    kind: PackKind,
    digest: &Sha256Hex,
    ctx: &PackVerifyCtx<'_>,
) -> Result<Option<VerifiedPackRecord>, PackCacheError> {
    let root = cache_root.join(digest.as_str());
    if !root.is_dir() {
        return Ok(None);
    }
    let manifest =
        read_manifest(&root).ok_or_else(|| PackCacheError::CachedManifestUnreadable {
            path: root.display().to_string(),
        })?;
    if manifest.outputs.pack_hash != *digest || manifest.kind != kind {
        return Ok(None);
    }
    let verified = ctx.verify(&manifest, &root)?;
    Ok(Some(VerifiedPackRecord {
        dir: VerifiedPackDir { root, verified },
        manifest,
    }))
}

/// Why a compatible runtime/builder pack is or is not ready for instant launch.
#[derive(Debug)]
pub enum PackDiagnosis {
    /// A pack of the requested kind verified against `ctx` and is ready.
    Ready {
        pack_hash: Sha256Hex,
        file_count: usize,
    },
    /// No cache dir, or no promoted entry of the requested kind at all.
    NoCompatiblePack,
    /// A promoted entry of the requested kind exists but failed verification;
    /// `reason` is the first such rejection observed.
    Rejected {
        pack_hash: Sha256Hex,
        reason: PackVerifyError,
    },
}

/// Diagnose the best available pack of `kind` for the caller. Unlike
/// [`resolve_pack`], which silently skips every non-verifying entry and
/// returns `Ok(None)`, this surfaces the rejection reason so callers can
/// explain precisely why instant launch is unavailable. Filters by `kind`
/// only (not arch/backend) so `ctx.verify` reports architecture/backend
/// incompatibility as a reason rather than hiding those entries.
pub fn diagnose_pack(
    kind: PackKind,
    ctx: &PackVerifyCtx<'_>,
) -> Result<PackDiagnosis, PackCacheError> {
    let root = pack_cache_dir();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        // No cache dir yet means no packs — not an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PackDiagnosis::NoCompatiblePack);
        }
        Err(error) => return Err(io_at(&root)(error)),
    };

    let mut rejected: Option<PackDiagnosis> = None;
    for entry in entries {
        let entry = entry.map_err(io_at(&root))?;
        let dir = entry.path();
        let name = entry.file_name();
        if !dir.is_dir() || name.to_str() == Some(QUARANTINE_DIR_NAME) {
            continue;
        }
        // A dir with no sidecar, or an unreadable/undecodable one, is foreign
        // content — skip it and keep scanning, same as `resolve_pack`.
        let Some(manifest) = read_manifest(&dir) else {
            continue;
        };
        // Defense in depth: a content-addressed dir must be named for the pack
        // hash it holds.
        if name.to_str() != Some(manifest.outputs.pack_hash.as_str()) {
            continue;
        }
        if manifest.kind != kind {
            continue;
        }
        match ctx.verify(&manifest, &dir) {
            Ok(verified) => {
                // A ready pack wins immediately — no need to keep scanning.
                return Ok(PackDiagnosis::Ready {
                    pack_hash: verified.pack_hash,
                    file_count: verified.file_count,
                });
            }
            Err(reason) => {
                if rejected.is_none() {
                    rejected = Some(PackDiagnosis::Rejected {
                        pack_hash: manifest.outputs.pack_hash.clone(),
                        reason,
                    });
                }
            }
        }
    }
    Ok(rejected.unwrap_or(PackDiagnosis::NoCompatiblePack))
}

/// Read a promoted pack's serialized manifest. Any dir that does not present a
/// readable, decodable sidecar — missing, truncated, corrupt, or otherwise
/// unreadable — yields `None` so the scan skips it as foreign content rather
/// than aborting the whole scan.
fn read_manifest(dir: &Path) -> Option<PackManifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE_NAME)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// One promoted pack, as surfaced by [`list_cached_packs`]. The on-demand
/// index over the pack cache — the cache is small, so this is computed by a
/// directory scan rather than a persisted index file.
#[derive(Debug, Clone)]
pub struct PackCacheEntry {
    pub pack_hash: Sha256Hex,
    pub kind: PackKind,
    pub arch: GuestArch,
    pub backends: Vec<PackBackend>,
    pub channel: String,
    pub expires_at: DateTime<Utc>,
    pub signing_key_id: KeyId,
    pub revocation_channel: String,
    /// Sum of the on-disk sizes of the pack's promoted files.
    pub size_bytes: u64,
    /// Directory mtime as a unix timestamp (best-effort; None if unavailable).
    pub last_used_unix: Option<i64>,
}

/// Scan the promoted pack cache and return one entry per valid pack. Skips the
/// quarantine dir, dirs whose name does not equal the manifest's pack hash, and
/// dirs with no readable manifest (foreign content) — same discipline as
/// [`resolve_pack`]. A missing cache dir yields an empty vec, not an error.
/// This does NOT verify signatures (it is a cheap listing); callers that need
/// trust/eligibility use [`diagnose_pack`].
pub fn list_cached_packs() -> Result<Vec<PackCacheEntry>, PackCacheError> {
    let root = pack_cache_dir();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        // No cache dir yet means no packs — not an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_at(&root)(error)),
    };

    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_at(&root))?;
        let dir = entry.path();
        let name = entry.file_name();
        if !dir.is_dir() || name.to_str() == Some(QUARANTINE_DIR_NAME) {
            continue;
        }
        // A dir with no sidecar, or an unreadable/undecodable one, is foreign
        // content — skip it and keep scanning, same as `resolve_pack`.
        let Some(manifest) = read_manifest(&dir) else {
            continue;
        };
        // Defense in depth: a content-addressed dir must be named for the pack
        // hash it holds.
        if name.to_str() != Some(manifest.outputs.pack_hash.as_str()) {
            continue;
        }

        let size_bytes: u64 = manifest
            .outputs
            .files
            .iter()
            .map(|file| {
                std::fs::metadata(dir.join(&file.path))
                    .map(|m| m.len())
                    .unwrap_or(0)
            })
            .sum();
        let last_used_unix = std::fs::metadata(&dir)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        out.push(PackCacheEntry {
            pack_hash: manifest.outputs.pack_hash.clone(),
            kind: manifest.kind.clone(),
            arch: manifest.target_arch,
            backends: manifest.backend_compatibility.clone(),
            channel: manifest.trust.channel_identity.clone(),
            expires_at: manifest.trust.expires_at,
            signing_key_id: manifest.trust.signing_key_id.clone(),
            revocation_channel: manifest.trust.revocation_channel.clone(),
            size_bytes,
            last_used_unix,
        });
    }
    out.sort_by(|a, b| a.pack_hash.as_str().cmp(b.pack_hash.as_str()));
    Ok(out)
}

/// Remove every promoted pack whose trust metadata expired before `now`.
/// Expired packs are never instant-launch-eligible, so removing them is always
/// safe — it never reclaims a pack backing a valid instant launch. Returns the
/// pack hashes removed. With `dry_run`, reports what would be removed without
/// deleting. Valid-but-unused (LRU) pack reclamation with active-standby
/// safety is a separate concern and is not done here.
pub fn prune_expired_packs(
    now: DateTime<Utc>,
    dry_run: bool,
) -> Result<Vec<Sha256Hex>, PackCacheError> {
    let mut removed = Vec::new();
    for entry in list_cached_packs()? {
        if entry.expires_at < now {
            if !dry_run {
                remove_pack_dir(&entry.pack_hash)?;
            }
            removed.push(entry.pack_hash);
        }
    }
    Ok(removed)
}

/// Delete a promoted pack's content-addressed directory. Shared by every
/// prune path so the removal step (and its error mapping) is defined once.
fn remove_pack_dir(hash: &Sha256Hex) -> Result<(), PackCacheError> {
    let dir = pack_dir(hash.as_str());
    std::fs::remove_dir_all(&dir).map_err(io_at(&dir))
}

/// Provenance the lifecycle facade records alongside a promoted pack.
/// `promoted_at_unix` is supplied by the caller — `mvm-core` never reads the
/// clock — so a mvm-cli call site computes "now" and passes it in.
pub struct PackProvenanceInput {
    pub channel: String,
    pub release_version: String,
    pub promoted_at_unix: u64,
}

impl PackProvenanceInput {
    /// Start building a [`PackProvenanceInput`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> PackProvenanceInputBuilder {
        PackProvenanceInputBuilder::new()
    }
}

/// Builder for [`PackProvenanceInput`]. Required fields are checked by
/// [`PackProvenanceInputBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct PackProvenanceInputBuilder {
    channel: Option<String>,
    release_version: Option<String>,
    promoted_at_unix: Option<u64>,
}

impl PackProvenanceInputBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            channel: None,
            release_version: None,
            promoted_at_unix: None,
        }
    }

    /// Set `channel`.
    #[must_use]
    pub fn channel(mut self, channel: String) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Set `release_version`.
    #[must_use]
    pub fn release_version(mut self, release_version: String) -> Self {
        self.release_version = Some(release_version);
        self
    }

    /// Set `promoted_at_unix`.
    #[must_use]
    pub fn promoted_at_unix(mut self, promoted_at_unix: u64) -> Self {
        self.promoted_at_unix = Some(promoted_at_unix);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<PackProvenanceInput, BuilderError> {
        Ok(PackProvenanceInput {
            channel: self
                .channel
                .ok_or(BuilderError::missing("PackProvenanceInput", "channel"))?,
            release_version: self.release_version.ok_or(BuilderError::missing(
                "PackProvenanceInput",
                "release_version",
            ))?,
            promoted_at_unix: self.promoted_at_unix.ok_or(BuilderError::missing(
                "PackProvenanceInput",
                "promoted_at_unix",
            ))?,
        })
    }
}

impl Default for PackProvenanceInputBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// One recorded pack version, as surfaced by [`list_versions`]: the
/// [`PackEntry`] fields plus whether it is the active version for its key.
#[derive(Debug, Clone, PartialEq)]
pub struct PackListEntry {
    pub pack_hash: Sha256Hex,
    pub key: PackKey,
    pub channel: String,
    pub release_version: String,
    pub promoted_at_unix: u64,
    pub active: bool,
}

/// Promote a staged pack (verify + place, as [`promote`] does) and record its
/// provenance into the persisted index.
///
/// A manifest's `backend_compatibility` is a *set* used at resolve time to
/// check eligibility (`resolve_pack`'s `.contains(backend)`); it is not the
/// one `(kind, arch, backend)` index slot this particular promotion should be
/// recorded/activated against — `PackIndex::record` upserts by `pack_hash`
/// alone, so recording the same hash under more than one key would silently
/// collapse into whichever key was recorded last. Instead this pins the
/// single slot from `ctx`'s [`LocalPackPolicy`] (`policy.backend`, the
/// concrete backend this host session is actually running), which is exactly
/// the slot [`resolve_pack`] is queried against for that session. `arch`
/// comes from the manifest since a verifying pack's `target_arch` already
/// matches the policy's `host_arch`.
pub fn promote_and_record(
    staged_root: &Path,
    manifest: &PackManifest,
    prov: &PackProvenanceInput,
    ctx: &PackVerifyCtx<'_>,
) -> Result<VerifiedPackDir, PackCacheError> {
    let promoted = promote(staged_root, manifest, ctx)?;

    let cache_root = PathBuf::from(mvm_cache_dir());
    let mut index = load_index(&cache_root);
    index.record(PackEntry {
        pack_hash: manifest.outputs.pack_hash.clone(),
        key: PackKey {
            kind: manifest.kind.clone(),
            arch: manifest.target_arch,
            backend: ctx.policy().backend.clone(),
        },
        channel: prov.channel.clone(),
        release_version: prov.release_version.clone(),
        promoted_at_unix: prov.promoted_at_unix,
    });
    save_index(&cache_root, &index)?;

    Ok(promoted)
}

/// Point `key`'s active version at `hash`. Errs if `hash` was never recorded
/// for `key` — the index only ever activates a version it already knows
/// about.
pub fn set_active_version(key: &PackKey, hash: &Sha256Hex) -> Result<(), PackCacheError> {
    let cache_root = PathBuf::from(mvm_cache_dir());
    let mut index = load_index(&cache_root);
    if !index.set_active(key, hash) {
        return Err(PackCacheError::UnknownPackVersion {
            key: key.clone(),
            hash: hash.clone(),
        });
    }
    save_index(&cache_root, &index)?;
    Ok(())
}

/// Every recorded pack version, optionally filtered by `kind`, flagged with
/// whether it is the active version for its key.
pub fn list_versions(filter: Option<PackKind>) -> Result<Vec<PackListEntry>, PackCacheError> {
    let cache_root = PathBuf::from(mvm_cache_dir());
    let index = load_index(&cache_root);
    let out = index
        .entries()
        .iter()
        .filter(|entry| filter.as_ref().is_none_or(|kind| entry.key.kind == *kind))
        .map(|entry| PackListEntry {
            pack_hash: entry.pack_hash.clone(),
            key: entry.key.clone(),
            channel: entry.channel.clone(),
            release_version: entry.release_version.clone(),
            promoted_at_unix: entry.promoted_at_unix,
            active: index.active_for(&entry.key) == Some(&entry.pack_hash),
        })
        .collect();
    Ok(out)
}

/// Reclaim non-active pack versions beyond the newest `keep_recent` per key
/// (see [`PackIndex::prunable`]), deleting both the content-addressed
/// directory and the index entry. Never removes a key's active hash. The
/// candidate hash list is deduplicated before acting — defense in depth
/// against a hash ever being recorded under more than one key, so a shared
/// pack directory is removed (and reported) at most once rather than erroring
/// on a second, already-gone directory. With `dry_run`, reports what would be
/// removed without deleting anything.
pub fn prune_versions(keep_recent: usize, dry_run: bool) -> Result<Vec<Sha256Hex>, PackCacheError> {
    let cache_root = PathBuf::from(mvm_cache_dir());
    let mut index = load_index(&cache_root);
    let mut prunable = index.prunable(keep_recent);
    prunable.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    prunable.dedup();

    if !dry_run {
        for hash in &prunable {
            remove_pack_dir(hash)?;
            index.remove(hash);
        }
        save_index(&cache_root, &index)?;
    }

    Ok(prunable)
}

fn new_quarantine_dir_at(cache_root: &Path) -> Result<PathBuf, PackCacheError> {
    let incoming = cache_root.join(QUARANTINE_DIR_NAME);
    harden_dir(&incoming)?;
    let counter = QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = incoming.join(format!("{}-{}", std::process::id(), counter));
    // A recycled pid could collide with a crashed prior run's leftovers; those
    // would otherwise ride the rename into the promoted dir as un-attested extra
    // files. Best-effort clear so the quarantine always starts empty.
    let _ = std::fs::remove_dir_all(&dir);
    Ok(dir)
}

/// Create `dir` (and parents) and, on unix, lock it to `0700`. Idempotent.
fn harden_dir(dir: &Path) -> Result<(), PackCacheError> {
    std::fs::create_dir_all(dir).map_err(io_at(dir))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(dir).map_err(io_at(dir))?.permissions();
        if perms.mode() & 0o777 != 0o700 {
            perms.set_mode(0o700);
            std::fs::set_permissions(dir, perms).map_err(io_at(dir))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::fs;

    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use tempfile::TempDir;

    use super::*;
    use crate::packs::{
        COSIGN_BUNDLE_FILE_NAME, HostCapability, KeylessTrust, PackBuilder, PackMetadata,
        PackOutputHashes, PackProvenanceMeta, PackTrustMeta, PolicyCompatibility,
        ReproducibilityStatus, RevocationStatus, SbomReference, Sha256Hex, SignatureFormat,
        SignatureValidity,
    };
    use crate::plan::bundle::{KeyId, key_id_from_identity, key_id_from_pubkey};
    use crate::util::test_env::TestEnv;

    struct MapTrustStore {
        keys: HashMap<KeyId, VerifyingKey>,
    }

    impl PackTrustStore for MapTrustStore {
        fn verifying_key(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            self.keys.get(key_id).copied()
        }
    }

    struct StaticRevocation {
        status: RevocationStatus,
    }

    impl PackRevocationChecker for StaticRevocation {
        fn status(&self, _key_id: &KeyId, _pack_hash: &Sha256Hex) -> RevocationStatus {
            self.status.clone()
        }
    }

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn metadata(kind: PackKind) -> PackMetadata {
        PackMetadata {
            kind,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Hvf, PackBackend::Libkrun],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: hash("policy"),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: crate::packs::PackInputs {
                flake_locks: Vec::new(),
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: Vec::new(),
                setup_commands: Vec::new(),
                source_revisions: Vec::new(),
                toolchain_versions: BTreeMap::new(),
            },
            provenance: PackProvenanceMeta {
                builder_identity: "ci-builder".to_string(),
                build_environment_identity: "github-actions".to_string(),
                build_timestamp: utc(2026, 6, 23),
                reproducibility: ReproducibilityStatus::Reproduced,
                sbom: SbomReference {
                    uri: "https://example.test/sbom.spdx.json".to_string(),
                    sha256: hash("sbom"),
                },
            },
            trust: PackTrustMeta {
                expires_at: utc(2026, 12, 31),
                revocation_channel: "https://example.test/revocations.json".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            },
        }
    }

    /// Stage a `Builder` pack under a fresh dir and return `(staged_dir, manifest)`.
    fn staged_builder_pack() -> (TempDir, PackManifest) {
        staged_builder_pack_bytes(b"builder-kernel", b"builder-image")
    }

    /// Stage a `Builder` pack whose two files carry the given bytes and whose
    /// trust metadata expires at `expires_at`, for exercising
    /// `prune_expired_packs`.
    fn staged_builder_pack_expiring(
        kernel: &[u8],
        image: &[u8],
        expires_at: DateTime<Utc>,
    ) -> (TempDir, PackManifest) {
        let dir = TempDir::new().expect("tempdir");
        fs::create_dir_all(dir.path().join("boot")).expect("mkdir boot");
        fs::write(dir.path().join("boot/kernel"), kernel).expect("write kernel");
        fs::write(dir.path().join("builder.img"), image).expect("write image");
        let key = signing_key();
        let mut meta = metadata(PackKind::Builder);
        meta.trust.expires_at = expires_at;
        let manifest = PackBuilder::new(dir.path(), meta, &key)
            .files(["boot/kernel", "builder.img"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(kernel)),
                builder_image_hash: Some(Sha256Hex::from_bytes(image)),
                ..Default::default()
            })
            .build()
            .expect("build pack");
        (dir, manifest)
    }

    /// Stage a `Builder` pack whose two files carry the given bytes. Distinct
    /// bytes yield a distinct `pack_hash`, so callers can mint two coexisting
    /// packs in one cache.
    fn staged_builder_pack_bytes(kernel: &[u8], image: &[u8]) -> (TempDir, PackManifest) {
        let dir = TempDir::new().expect("tempdir");
        fs::create_dir_all(dir.path().join("boot")).expect("mkdir boot");
        fs::write(dir.path().join("boot/kernel"), kernel).expect("write kernel");
        fs::write(dir.path().join("builder.img"), image).expect("write image");
        let key = signing_key();
        let manifest = PackBuilder::new(dir.path(), metadata(PackKind::Builder), &key)
            .files(["boot/kernel", "builder.img"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(kernel)),
                builder_image_hash: Some(Sha256Hex::from_bytes(image)),
                ..Default::default()
            })
            .build()
            .expect("build pack");
        (dir, manifest)
    }

    /// Stage a `Builder` pack rewritten for the keyless (Sigstore) authority:
    /// format flipped, the in-manifest signature cleared (a detached bundle
    /// would be authoritative instead), and `signing_key_id` swapped for an
    /// identity-derived id. The pack hash is recomputed since `signing_key_id`
    /// is covered by the pack-hash payload. No cosign bundle sidecar is written
    /// — callers that need one write it themselves.
    fn staged_sigstore_builder_pack() -> (TempDir, PackManifest) {
        let (dir, mut manifest) = staged_builder_pack();
        manifest.provenance.signature_bundle.format = SignatureFormat::Sigstore;
        manifest.provenance.signature_bundle.signatures.clear();
        manifest.trust.signing_key_id = key_id_from_identity("test-identity");
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        (dir, manifest)
    }

    fn keyless_trust() -> KeylessTrust {
        KeylessTrust {
            accepted_identities: vec!["test-identity".to_string()],
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    fn policy() -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: hash("policy"),
            allowed_channels: BTreeSet::from(["stable".to_string()]),
            now: utc(2026, 6, 24),
        }
    }

    fn trust_store() -> MapTrustStore {
        let key = signing_key();
        MapTrustStore {
            keys: HashMap::from([(
                key_id_from_pubkey(&key.verifying_key()),
                key.verifying_key(),
            )]),
        }
    }

    fn good_revocation() -> StaticRevocation {
        StaticRevocation {
            status: RevocationStatus::Good,
        }
    }

    /// Point `MVM_HOME` at a fresh tempdir so the cache is isolated per
    /// test, and hold the env guard for the whole test. Returns both so they
    /// outlive the promotion calls.
    fn isolated_cache() -> (TempDir, TestEnv) {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", cache.path());
        (cache, env)
    }

    #[test]
    fn promote_places_verified_pack_at_content_addressed_dir() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        let expected = pack_dir(manifest.outputs.pack_hash.as_str());
        assert_eq!(promoted.root, expected);
        assert!(expected.join("boot/kernel").exists());
        assert!(expected.join("builder.img").exists());
        // Re-verify the promoted copy directly.
        verify_pack_at(&manifest, &expected, &policy, &trust, &rev).expect("promoted verifies");
    }

    #[test]
    fn explicit_cache_promotion_and_resolution_never_consult_ambient_home() {
        let ambient = TempDir::new().expect("ambient cache");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", ambient.path());
        let explicit = TempDir::new().expect("explicit cache");
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let promoted = promote_at(explicit.path(), staged.path(), &manifest, &ctx)
            .expect("promote under explicit root");
        assert!(promoted.root.starts_with(explicit.path()));
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());

        let resolved = resolve_pack_digest_at(
            explicit.path(),
            PackKind::Builder,
            &manifest.outputs.pack_hash,
            &ctx,
        )
        .expect("resolve explicit pack")
        .expect("pack exists");
        assert_eq!(resolved.dir.root, promoted.root);
    }

    #[test]
    fn promote_is_idempotent() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let first = promote(staged.path(), &manifest, &ctx).expect("first promote");
        let second = promote(staged.path(), &manifest, &ctx).expect("second promote");
        assert_eq!(first.root, second.root);
        assert!(second.root.exists());
    }

    #[test]
    fn promote_refuses_tampered_staged_pack_and_writes_nothing() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        fs::write(staged.path().join("boot/kernel"), b"tampered-kernel-bytes").expect("tamper");
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let err = promote(staged.path(), &manifest, &ctx).expect_err("tamper refused");
        assert!(matches!(err, PackCacheError::Verify(_)));
        // Nothing half-promoted.
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());
    }

    #[test]
    fn promote_refuses_incomplete_staged_pack() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        fs::remove_file(staged.path().join("builder.img")).expect("remove declared file");
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let err = promote(staged.path(), &manifest, &ctx).expect_err("missing file refused");
        assert!(matches!(err, PackCacheError::Verify(_)));
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());
    }

    #[test]
    fn resolve_pack_returns_compatible_promoted_pack() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        promote(staged.path(), &manifest, &ctx).expect("promote");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");
        assert_eq!(found.root, pack_dir(manifest.outputs.pack_hash.as_str()));
        assert_eq!(found.verified.file_count, 2);
    }

    #[test]
    fn resolve_pack_returns_none_when_nothing_matches() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        promote(staged.path(), &manifest, &ctx).expect("promote");

        // Runtime kind is not present, so no compatible pack exists.
        let found = resolve_pack(PackKind::Runtime, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok");
        assert!(found.is_none());
    }

    #[test]
    fn resolve_pack_refuses_poisoned_promoted_entry() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        // Poison the promoted copy after the fact.
        fs::write(promoted.root.join("boot/kernel"), b"poisoned-after-promote").expect("poison");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok");
        assert!(found.is_none(), "poisoned entry must not be served");
    }

    #[cfg(unix)]
    #[test]
    fn promoted_dir_is_mode_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        let mode = fs::metadata(&promoted.root)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "promoted dir mode 0{:o}", mode & 0o777);
    }

    #[test]
    fn promoted_dir_lands_under_configured_cache_dir() {
        let (cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        assert!(
            promoted.root.starts_with(cache.path()),
            "promoted dir {:?} not under MVM_HOME {:?}",
            promoted.root,
            cache.path()
        );
    }

    #[test]
    fn promote_replaces_poisoned_promoted_dir() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("first promote");

        // Poison the promoted copy, then re-promote from the good staged dir.
        fs::write(promoted.root.join("builder.img"), b"corrupted").expect("poison");
        let repromoted = promote(staged.path(), &manifest, &ctx).expect("re-promote replaces");
        assert_eq!(repromoted.root, promoted.root);
        verify_pack_at(&manifest, &repromoted.root, &policy, &trust, &rev)
            .expect("replaced copy verifies");
    }

    #[test]
    fn no_quarantine_left_behind_after_promote() {
        let (cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        promote(staged.path(), &manifest, &ctx).expect("promote");

        let incoming = cache
            .path()
            .join("cache")
            .join("packs")
            .join(super::QUARANTINE_DIR_NAME);
        // The `.incoming` dir may exist but must hold no staging leftovers.
        if let Ok(entries) = fs::read_dir(&incoming) {
            assert_eq!(entries.count(), 0, "quarantine staging not cleaned up");
        }
    }

    #[test]
    fn resolve_pack_skips_corrupt_sidecar_and_finds_valid_pack() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        promote(staged_a.path(), &manifest_a, &ctx).expect("promote a");
        promote(staged_b.path(), &manifest_b, &ctx).expect("promote b");

        // Corrupt the sidecar of the alphabetically-first promoted dir; a naive
        // scan that hard-errors would then hide the pack that sorts after it.
        let hash_a = manifest_a.outputs.pack_hash.as_str();
        let hash_b = manifest_b.outputs.pack_hash.as_str();
        let (corrupt_hash, valid_hash) = if hash_a <= hash_b {
            (hash_a, hash_b)
        } else {
            (hash_b, hash_a)
        };
        fs::write(
            pack_dir(corrupt_hash).join(super::MANIFEST_FILE_NAME),
            b"{ this is not valid json",
        )
        .expect("corrupt sidecar");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("valid pack still found past corrupt entry");
        assert_eq!(found.root, pack_dir(valid_hash));
    }

    #[test]
    fn promote_refuses_pack_declaring_reserved_sidecar_name() {
        let (cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        // Mint a pack that legitimately declares a file named like the sidecar.
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("boot-kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write image");
        fs::write(dir.path().join(super::MANIFEST_FILE_NAME), b"collides").expect("write reserved");
        let key = signing_key();
        let manifest = PackBuilder::new(dir.path(), metadata(PackKind::Builder), &key)
            .files(["boot-kernel", "builder.img", super::MANIFEST_FILE_NAME])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(b"builder-kernel")),
                builder_image_hash: Some(Sha256Hex::from_bytes(b"builder-image")),
                ..Default::default()
            })
            .build()
            .expect("build pack");

        let err = promote(dir.path(), &manifest, &ctx).expect_err("reserved name refused");
        assert!(
            matches!(err, PackCacheError::ReservedFileName(name) if name == super::MANIFEST_FILE_NAME)
        );
        // Nothing written: neither the pack dir nor any packs subtree beyond the
        // cache root exists.
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());
        assert!(
            !cache
                .path()
                .join("cache")
                .join("packs")
                .join(manifest.outputs.pack_hash.as_str())
                .exists()
        );
    }

    #[test]
    fn resolve_pack_skips_dir_whose_name_is_not_its_pack_hash() {
        let (cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        // Rename the content-addressed dir so its name no longer equals the hash.
        let renamed = cache
            .path()
            .join("cache")
            .join("packs")
            .join("not-a-pack-hash");
        fs::rename(&promoted.root, &renamed).expect("rename promoted dir");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok");
        assert!(found.is_none(), "pack under wrong name must not be served");
    }

    #[test]
    fn keyless_ctx_missing_bundle_sidecar_is_signature_invalid() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_sigstore_builder_pack();
        let keyless = keyless_trust();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &rev);

        // No COSIGN_BUNDLE_FILE_NAME sidecar was written under `staged`, so the
        // keyless ctx must fail closed before any signature bytes are touched.
        let err = promote(staged.path(), &manifest, &ctx).expect_err("missing bundle refused");
        assert!(matches!(
            err,
            PackCacheError::Verify(PackVerifyError::KeylessSignatureInvalid(_))
        ));
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());
    }

    #[test]
    fn reserved_cosign_bundle_filename_rejected() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        // Mint a pack that legitimately declares a file named like the cosign
        // bundle sidecar.
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("boot-kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write image");
        fs::write(dir.path().join(COSIGN_BUNDLE_FILE_NAME), b"collides").expect("write reserved");
        let key = signing_key();
        let manifest = PackBuilder::new(dir.path(), metadata(PackKind::Builder), &key)
            .files(["boot-kernel", "builder.img", COSIGN_BUNDLE_FILE_NAME])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(b"builder-kernel")),
                builder_image_hash: Some(Sha256Hex::from_bytes(b"builder-image")),
                ..Default::default()
            })
            .build()
            .expect("build pack");

        let err = promote(dir.path(), &manifest, &ctx).expect_err("reserved name refused");
        assert!(
            matches!(err, PackCacheError::ReservedFileName(name) if name == COSIGN_BUNDLE_FILE_NAME)
        );
        assert!(!pack_dir(manifest.outputs.pack_hash.as_str()).exists());
    }

    #[test]
    fn diagnose_pack_reports_no_compatible_pack_on_empty_cache() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let diagnosis = diagnose_pack(PackKind::Builder, &ctx).expect("diagnose ok");
        assert!(matches!(diagnosis, PackDiagnosis::NoCompatiblePack));
    }

    #[test]
    fn diagnose_pack_reports_ready_for_a_verifiable_promoted_pack() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        promote(staged.path(), &manifest, &ctx).expect("promote");

        let diagnosis = diagnose_pack(PackKind::Builder, &ctx).expect("diagnose ok");
        match diagnosis {
            PackDiagnosis::Ready {
                pack_hash,
                file_count,
            } => {
                assert_eq!(pack_hash, manifest.outputs.pack_hash);
                assert_eq!(file_count, 2);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn diagnose_pack_reports_rejected_reason_for_tampered_promoted_pack() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        let promoted = promote(staged.path(), &manifest, &ctx).expect("promote");

        // Flip a single byte in place (same length as the original) so
        // re-verify fails with a file hash mismatch, not a size mismatch.
        fs::write(promoted.root.join("boot/kernel"), b"buildep-kernel").expect("poison");

        let diagnosis = diagnose_pack(PackKind::Builder, &ctx).expect("diagnose ok");
        match diagnosis {
            PackDiagnosis::Rejected { pack_hash, reason } => {
                assert_eq!(pack_hash, manifest.outputs.pack_hash);
                assert!(
                    matches!(reason, PackVerifyError::FileHashMismatch { .. }),
                    "expected FileHashMismatch, got {reason:?}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn list_cached_packs_empty_on_missing_cache() {
        let (_cache, _env) = isolated_cache();
        let packs = list_cached_packs().expect("list ok");
        assert!(packs.is_empty());
    }

    #[test]
    fn list_cached_packs_returns_promoted_entries() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        promote(staged_a.path(), &manifest_a, &ctx).expect("promote a");
        promote(staged_b.path(), &manifest_b, &ctx).expect("promote b");

        let packs = list_cached_packs().expect("list ok");
        assert_eq!(packs.len(), 2);
        let hashes: Vec<&str> = packs.iter().map(|p| p.pack_hash.as_str()).collect();
        assert!(hashes.contains(&manifest_a.outputs.pack_hash.as_str()));
        assert!(hashes.contains(&manifest_b.outputs.pack_hash.as_str()));
        for p in &packs {
            assert_eq!(p.kind, PackKind::Builder);
            assert_eq!(p.arch, GuestArch::host());
            assert!(p.size_bytes > 0, "size_bytes must reflect on-disk files");
        }
        // Sorted by pack_hash for stable output.
        assert!(packs[0].pack_hash.as_str() <= packs[1].pack_hash.as_str());
    }

    #[test]
    fn prune_expired_packs_dry_run_reports_without_removing() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        // `promote` itself refuses an already-expired pack (it verifies against
        // `policy.now`, 2026-06-24), so the "expired" fixture must still be
        // valid at promote time and only expire before the later `now` this
        // test passes to `prune_expired_packs`.
        let (staged_expired, manifest_expired) =
            staged_builder_pack_expiring(b"kernel-expired", b"image-expired", utc(2026, 6, 25));
        let (staged_future, manifest_future) =
            staged_builder_pack_expiring(b"kernel-future", b"image-future", utc(2099, 1, 1));
        promote(staged_expired.path(), &manifest_expired, &ctx).expect("promote expired");
        promote(staged_future.path(), &manifest_future, &ctx).expect("promote future");

        let now = utc(2026, 7, 1);
        let removed = prune_expired_packs(now, true).expect("dry-run prune ok");
        assert_eq!(removed, vec![manifest_expired.outputs.pack_hash.clone()]);

        // Dry-run removes nothing; both packs remain listable.
        let packs = list_cached_packs().expect("list ok");
        assert_eq!(packs.len(), 2);
    }

    #[test]
    fn prune_expired_packs_removes_only_expired() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        // Same promote-time-vs-prune-time distinction as the dry-run test above.
        let (staged_expired, manifest_expired) =
            staged_builder_pack_expiring(b"kernel-expired", b"image-expired", utc(2026, 6, 25));
        let (staged_future, manifest_future) =
            staged_builder_pack_expiring(b"kernel-future", b"image-future", utc(2099, 1, 1));
        promote(staged_expired.path(), &manifest_expired, &ctx).expect("promote expired");
        promote(staged_future.path(), &manifest_future, &ctx).expect("promote future");

        let now = utc(2026, 7, 1);
        let removed = prune_expired_packs(now, false).expect("prune ok");
        assert_eq!(removed, vec![manifest_expired.outputs.pack_hash.clone()]);

        let packs = list_cached_packs().expect("list ok");
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].pack_hash, manifest_future.outputs.pack_hash);
    }

    /// The `(kind, arch, backend)` slot every index test below records
    /// against — matches what `policy()`/`resolve_pack` calls use.
    fn builder_key() -> PackKey {
        PackKey {
            kind: PackKind::Builder,
            arch: GuestArch::host(),
            backend: PackBackend::Hvf,
        }
    }

    fn entry_for(promoted: &VerifiedPackDir, channel: &str, promoted_at_unix: u64) -> PackEntry {
        PackEntry {
            pack_hash: promoted.verified.pack_hash.clone(),
            key: builder_key(),
            channel: channel.to_string(),
            release_version: "v0.17.0".to_string(),
            promoted_at_unix,
        }
    }

    #[test]
    fn resolve_prefers_active_pointer_over_scan_order() {
        let (cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        let promoted_a = promote(staged_a.path(), &manifest_a, &ctx).expect("promote a");
        let promoted_b = promote(staged_b.path(), &manifest_b, &ctx).expect("promote b");

        // The index lives at `mvm_cache_dir()` (`$MVM_HOME/cache`), the same
        // root `resolve_pack` reads — not the `MVM_HOME` root itself.
        let cache_root = cache.path().join("cache");
        let mut ix = load_index(&cache_root);
        ix.record(entry_for(&promoted_a, "stable", 10));
        ix.record(entry_for(&promoted_b, "stable", 20));
        assert!(ix.set_active(&builder_key(), &promoted_b.verified.pack_hash));
        save_index(&cache_root, &ix).expect("save index");

        // Scan order is by directory name (pack hash), which need not put `b`
        // first — the active pointer must win regardless.
        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");
        assert_eq!(found.verified.pack_hash, promoted_b.verified.pack_hash);
    }

    #[test]
    fn resolve_falls_back_to_scan_when_no_index() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged, manifest) = staged_builder_pack();
        promote(staged.path(), &manifest, &ctx).expect("promote");

        // No `save_index` call at all — `index.json` never existed.
        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found via scan fallback");
        assert_eq!(found.root, pack_dir(manifest.outputs.pack_hash.as_str()));
    }

    #[test]
    fn resolve_falls_back_to_scan_when_index_is_corrupt() {
        let (cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged, manifest) = staged_builder_pack();
        promote(staged.path(), &manifest, &ctx).expect("promote");

        // A truncated / garbage `index.json` must not break resolution:
        // `load_index` fails open and resolve re-verifies via the scan.
        std::fs::write(index_path(&cache.path().join("cache")), b"{ not json")
            .expect("write corrupt index");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found despite corrupt index");
        assert_eq!(found.root, pack_dir(manifest.outputs.pack_hash.as_str()));
    }

    #[test]
    fn resolve_falls_back_when_active_pack_is_corrupt() {
        let (cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        let promoted_a = promote(staged_a.path(), &manifest_a, &ctx).expect("promote a");
        let promoted_b = promote(staged_b.path(), &manifest_b, &ctx).expect("promote b");

        // The index lives at `mvm_cache_dir()` (`$MVM_HOME/cache`), the same
        // root `resolve_pack` reads — not the `MVM_HOME` root itself.
        let cache_root = cache.path().join("cache");
        let mut ix = load_index(&cache_root);
        ix.record(entry_for(&promoted_a, "stable", 10));
        ix.record(entry_for(&promoted_b, "stable", 20));
        assert!(ix.set_active(&builder_key(), &promoted_b.verified.pack_hash));
        save_index(&cache_root, &ix).expect("save index");

        // Poison the active pack's promoted copy after the fact.
        fs::write(
            promoted_b.root.join("boot/kernel"),
            b"poisoned-after-promote",
        )
        .expect("poison active pack");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("falls back to the other verified pack");
        assert_eq!(found.verified.pack_hash, promoted_a.verified.pack_hash);
    }

    fn provenance(
        channel: &str,
        release_version: &str,
        promoted_at_unix: u64,
    ) -> PackProvenanceInput {
        PackProvenanceInput {
            channel: channel.to_string(),
            release_version: release_version.to_string(),
            promoted_at_unix,
        }
    }

    #[test]
    fn promote_and_record_makes_pack_resolvable_and_listed_active() {
        let (_cache, _env) = isolated_cache();
        let (staged, manifest) = staged_builder_pack();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let promoted = promote_and_record(
            staged.path(),
            &manifest,
            &provenance("stable", "v0.17.0", 10),
            &ctx,
        )
        .expect("promote_and_record");

        // The production `mvm_cache_dir()` path is what both `promote_and_record`
        // and `resolve_pack` use internally — this is the end-to-end guard that a
        // cache-root/index-path mismatch would break.
        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");
        assert_eq!(found.verified.pack_hash, promoted.verified.pack_hash);

        let versions = list_versions(Some(PackKind::Builder)).expect("list ok");
        let hvf_entry = versions
            .iter()
            .find(|v| v.key.backend == PackBackend::Hvf)
            .expect("hvf-key entry listed");
        assert_eq!(hvf_entry.pack_hash, promoted.verified.pack_hash);
        assert_eq!(hvf_entry.release_version, "v0.17.0");
        assert!(hvf_entry.active, "sole promoted version must be active");
    }

    #[test]
    fn set_active_version_errors_on_unknown_hash_and_switches_resolution() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        let promoted_a = promote_and_record(
            staged_a.path(),
            &manifest_a,
            &provenance("stable", "v0.17.0", 10),
            &ctx,
        )
        .expect("promote a");
        let promoted_b = promote_and_record(
            staged_b.path(),
            &manifest_b,
            &provenance("stable", "v0.18.0", 20),
            &ctx,
        )
        .expect("promote b");

        // `a` promoted first, so it is the default active version.
        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");
        assert_eq!(found.verified.pack_hash, promoted_a.verified.pack_hash);

        let unknown_hash = Sha256Hex::from_bytes(b"not-a-recorded-pack");
        let err = set_active_version(&builder_key(), &unknown_hash)
            .expect_err("unknown hash must be refused");
        assert!(matches!(err, PackCacheError::UnknownPackVersion { .. }));

        set_active_version(&builder_key(), &promoted_b.verified.pack_hash).expect("set active b");

        let found = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");
        assert_eq!(found.verified.pack_hash, promoted_b.verified.pack_hash);
    }

    #[test]
    fn prune_versions_keeps_active_removes_oldest_and_dry_run_is_noop() {
        let (_cache, _env) = isolated_cache();
        let trust = trust_store();
        let rev = good_revocation();
        let policy = policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        let (staged_a, manifest_a) = staged_builder_pack_bytes(b"kernel-a", b"image-a");
        let (staged_b, manifest_b) = staged_builder_pack_bytes(b"kernel-b", b"image-b");
        let (staged_c, manifest_c) = staged_builder_pack_bytes(b"kernel-c", b"image-c");
        let promoted_a = promote_and_record(
            staged_a.path(),
            &manifest_a,
            &provenance("stable", "v0.17.0", 10),
            &ctx,
        )
        .expect("promote a");
        let promoted_b = promote_and_record(
            staged_b.path(),
            &manifest_b,
            &provenance("stable", "v0.18.0", 20),
            &ctx,
        )
        .expect("promote b");
        let promoted_c = promote_and_record(
            staged_c.path(),
            &manifest_c,
            &provenance("stable", "v0.19.0", 30),
            &ctx,
        )
        .expect("promote c");

        // `a` (promoted first) is active; keep_recent=1 also keeps `c` (the
        // newest by promoted_at_unix); `b` is neither, so it is prunable.
        let dry = prune_versions(1, true).expect("dry-run prune ok");
        assert_eq!(dry, vec![promoted_b.verified.pack_hash.clone()]);
        assert!(promoted_a.root.exists());
        assert!(promoted_b.root.exists(), "dry-run must not delete anything");
        assert!(promoted_c.root.exists());

        let removed = prune_versions(1, false).expect("prune ok");
        assert_eq!(removed, vec![promoted_b.verified.pack_hash.clone()]);
        assert!(promoted_a.root.exists(), "active pack dir must survive");
        assert!(
            !promoted_b.root.exists(),
            "oldest non-active pack dir must be removed"
        );
        assert!(promoted_c.root.exists(), "newest pack dir must be kept");

        let versions = list_versions(Some(PackKind::Builder)).expect("list ok");
        assert!(
            !versions
                .iter()
                .any(|v| v.pack_hash == promoted_b.verified.pack_hash),
            "pruned entry must be gone from the index"
        );
        assert!(
            versions
                .iter()
                .any(|v| v.pack_hash == promoted_a.verified.pack_hash && v.active)
        );
    }
}

#[cfg(test)]
mod pack_provenance_input_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = PackProvenanceInput::builder().build() else {
            panic!("an empty PackProvenanceInput builder must not build");
        };
        assert_eq!(err, BuilderError::missing("PackProvenanceInput", "channel"));
    }
}
