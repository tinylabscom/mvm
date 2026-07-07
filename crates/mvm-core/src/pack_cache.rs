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

use thiserror::Error;

use crate::arch::GuestArch;
use crate::config::{pack_cache_dir, pack_dir};
use crate::packs::{
    COSIGN_BUNDLE_FILE_NAME, KeylessTrust, LocalPackPolicy, PackBackend, PackKind, PackManifest,
    PackManifestError, PackRevocationChecker, PackTrustStore, PackVerifyError, VerifiedPack,
    verify_pack_at, verify_pack_keyless_at,
};

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

    let final_dir = pack_dir(manifest.outputs.pack_hash.as_str());

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

    let quarantine = new_quarantine_dir()?;
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

/// Scan promoted packs for one matching `(kind, arch, backend)` and re-verify it
/// before returning. Returns `Ok(None)` when nothing compatible verifies — a
/// poisoned or mismatched entry is skipped, never served.
pub fn resolve_pack(
    kind: PackKind,
    arch: GuestArch,
    backend: PackBackend,
    ctx: &PackVerifyCtx<'_>,
) -> Result<Option<VerifiedPackDir>, PackCacheError> {
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
        // A dir with no sidecar, or an unreadable/undecodable one, is foreign
        // content — skip it and keep scanning. Never let one damaged entry hide
        // every valid pack that sorts after it.
        let Some(manifest) = read_manifest(&dir) else {
            continue;
        };
        // Defense in depth: a content-addressed dir must be named for the pack
        // hash it holds. A name/content mismatch is observable-and-skipped rather
        // than served under the wrong identity.
        if name.to_str() != Some(manifest.outputs.pack_hash.as_str()) {
            continue;
        }
        if manifest.kind != kind
            || manifest.target_arch != arch
            || !manifest.backend_compatibility.contains(&backend)
        {
            continue;
        }
        // Re-verify every use: a promoted-then-tampered entry fails here and is
        // skipped, so a poisoned pack is never handed back.
        if let Ok(verified) = ctx.verify(&manifest, &dir) {
            return Ok(Some(VerifiedPackDir {
                root: dir,
                verified,
            }));
        }
    }
    Ok(None)
}

/// Read a promoted pack's serialized manifest. Any dir that does not present a
/// readable, decodable sidecar — missing, truncated, corrupt, or otherwise
/// unreadable — yields `None` so the scan skips it as foreign content rather
/// than aborting the whole scan.
fn read_manifest(dir: &Path) -> Option<PackManifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE_NAME)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn new_quarantine_dir() -> Result<PathBuf, PackCacheError> {
    let incoming = pack_cache_dir().join(QUARANTINE_DIR_NAME);
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
    use crate::plan::bundle::KeyId;
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
        manifest.trust.signing_key_id = KeyId::from_identity("test-identity");
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
                KeyId::from_pubkey(&key.verifying_key()),
                key.verifying_key(),
            )]),
        }
    }

    fn good_revocation() -> StaticRevocation {
        StaticRevocation {
            status: RevocationStatus::Good,
        }
    }

    /// Point `MVM_CACHE_DIR` at a fresh tempdir so the cache is isolated per
    /// test, and hold the env guard for the whole test. Returns both so they
    /// outlive the promotion calls.
    fn isolated_cache() -> (TempDir, TestEnv) {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
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
            "promoted dir {:?} not under MVM_CACHE_DIR {:?}",
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

        let incoming = cache.path().join("packs").join(super::QUARANTINE_DIR_NAME);
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
        let renamed = cache.path().join("packs").join("not-a-pack-hash");
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
}
