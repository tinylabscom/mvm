//! Build and resolve the universal initramfs artifact.
//!
//! The initramfs is one static agent packed as `/init` in an epoch-zero newc
//! cpio, cached at `<cache_root>/<version>/<arch>/`. A source checkout takes
//! the distinct size-tuned agent from the verified guest-runtime tree and
//! packs it with [`build_initramfs_from_guest_runtime`]. The image-set
//! download remains a compatibility path. This module is smaller than the
//! overlay assembler because the artifact has no verity sidecar or per-rootfs
//! variation.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::build_env::ShellEnvironment;
use mvm_fs::initramfs::{InitramfsArtifact, InitramfsResolver};
use mvm_fs::parallel::par_map;
use thiserror::Error;

use crate::published_image_set::{MemberVersion, SetMemberCache, SetMemberCacheError};
use crate::runtime_overlay::ExpandedArchiveLimits as InitramfsArchiveLimits;
use mvm_core::image_set::MemberTarget;
use mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE;

/// Failure modes for universal initramfs resolution/build.
#[derive(Debug, Error)]
pub enum InitramfsBuildError {
    /// Cache resolution failed.
    #[error(transparent)]
    Resolve(#[from] mvm_fs::initramfs::InitramfsError),

    /// The deterministic cargo build failed (agent cross-compile or the
    /// cpio assembly).
    #[error("cargo initramfs build failed: {reason}")]
    CargoBuildFailed { reason: String },

    /// An initramfs image does not hash to its own sidecar.
    #[error("checksum mismatch for {name}: expected sha256 {expected}, computed {actual}")]
    ChecksumMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    /// The downloaded initramfs archive was malformed or unsafe to extract.
    #[error("initramfs archive invalid at {archive_path:?}: {reason}")]
    InvalidArchive {
        archive_path: PathBuf,
        reason: String,
    },

    /// No usable initramfs from a bundle's image set is installed, or the one
    /// delivered carries a `VERSION` that cannot name a cache entry.
    #[error(transparent)]
    ImageSetCache(#[from] SetMemberCacheError),

    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve a cached universal initramfs. On a miss with a non-default cache
/// root (e.g. a worktree-isolated `MVM_HOME`), seed that cache by installing
/// the default cache's artifact and retry once. A default-cache miss surfaces
/// the original resolve error unchanged. This is still a pure cache operation —
/// no build, no download.
/// Name of the source-fingerprint file recorded beside a cached initramfs.
///
/// The cache key is otherwise `(version, arch)`, and the version only moves on a
/// release. That makes a locally built artifact outlive every change to the guest
/// sources it was built from: a fix lands, the cache still serves the binary from
/// before it, and the fix looks like it did not work. The runtime overlay and the
/// verity initramfs both record a fingerprint for exactly this reason; this one
/// did not, which is how an agent built before its own trust-anchor fix kept
/// being booted afterwards.
pub const LOCAL_SOURCE_FINGERPRINT_FILE: &str = "SOURCE_FINGERPRINT";

/// Whether a cached artifact was built from `fingerprint`.
///
/// A cache with no fingerprint recorded is *not* fresh for a source checkout:
/// it predates this check and there is no way to tell what built it.
fn cached_artifact_matches_source(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    fingerprint: &str,
) -> bool {
    let recorded = cache_root
        .join(version)
        .join(arch.to_string())
        .join(LOCAL_SOURCE_FINGERPRINT_FILE);
    std::fs::read_to_string(recorded)
        .map(|found| found.trim() == fingerprint.trim())
        .unwrap_or(false)
}

/// Record the fingerprint an artifact was built from.
pub fn record_source_fingerprint(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    fingerprint: &str,
) -> std::io::Result<()> {
    let dir = cache_root.join(version).join(arch.to_string());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(LOCAL_SOURCE_FINGERPRINT_FILE), fingerprint)
}

/// Record the source fingerprint for a resolved artifact, but only when the
/// artifact is the version-keyed local build living in that directory.
///
/// A pinned-set member's provenance is the signed root, not the checkout, and
/// its bytes live under `image-set/<root>/…`. Writing a fingerprint beside a
/// directory the artifact does not live in creates a partial version-keyed
/// entry (the fingerprint alone), which the resolver then reports as a
/// missing artifact instead of a missing cache, and the next boot refuses.
pub fn record_source_fingerprint_for_resolved(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    artifact: &mvm_fs::initramfs::InitramfsArtifact,
    fingerprint: &str,
) -> std::io::Result<()> {
    let local_dir = cache_root.join(version).join(arch.to_string());
    if !artifact.image_path.starts_with(&local_dir) {
        return Ok(());
    }
    record_source_fingerprint(cache_root, version, arch, fingerprint)
}

/// Discard a cached artifact that a source checkout did not build.
///
/// Removing rather than ignoring it, so the next resolve takes the build or
/// download path instead of finding the same stale bytes again.
pub fn evict_if_source_changed(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    fingerprint: &str,
) -> std::io::Result<bool> {
    if cached_artifact_matches_source(cache_root, version, arch, fingerprint) {
        return Ok(false);
    }
    let dir = cache_root.join(version).join(arch.to_string());
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(true)
}

pub fn resolve_or_seed_from_default_cache(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let arch_str = arch.to_string();
    let resolver = InitramfsResolver::new(cache_root, version);
    match resolver.resolve(&arch_str) {
        Ok(artifact) => Ok(artifact),
        Err(initial_error) => {
            if seed_from_default_cache(cache_root, version, arch)? {
                Ok(InitramfsResolver::new(cache_root, version).resolve(&arch_str)?)
            } else {
                Err(initial_error.into())
            }
        }
    }
}

fn seed_from_default_cache(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<bool, InitramfsBuildError> {
    let arch_dir = arch.to_string();
    crate::cache_install::seed_on_miss(
        cache_root,
        &crate::cache_install::default_cache_root().join("initramfs"),
        |root| {
            // Ask the resolver for the directory rather than recovering it
            // from a resolved file path — it is the type that owns the layout.
            let resolver = InitramfsResolver::new(root, version);
            resolver
                .resolve(&arch_dir)
                .ok()
                .map(|_| resolver.artifact_dir(&arch_dir))
        },
        |source_dir| {
            install_initramfs_into_cache(&source_dir, cache_root, version, arch)?;
            carry_source_fingerprint(&source_dir, cache_root, version, arch)?;
            carry_archive_origin(&source_dir, cache_root, version, arch)
        },
    )
}

/// Copy the donor's recorded source fingerprint — the guest-runtime digest it
/// was packed from — beside a seeded copy. The seeded bytes are the donor's, so
/// its provenance is the donor's: fresh for this checkout exactly when the
/// donor was packed from this checkout's archive, and evicted at boot otherwise.
fn carry_source_fingerprint(
    donor_dir: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<(), InitramfsBuildError> {
    match std::fs::read_to_string(donor_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE)) {
        Ok(fingerprint) => Ok(record_source_fingerprint(
            cache_root,
            version,
            arch,
            fingerprint.trim(),
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Copy the donor's archive-origin record beside a seeded copy, for the same
/// reason as its source fingerprint: the bytes are the donor's.
fn carry_archive_origin(
    donor_dir: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<(), InitramfsBuildError> {
    let origin = crate::runtime_pieces::archive_origin(donor_dir)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(digest) = origin {
        let dir = InitramfsResolver::new(cache_root, version).artifact_dir(&arch.to_string());
        crate::runtime_pieces::record_archive_origin(&dir, &digest)?;
    }
    Ok(())
}

/// Whether a failed version-keyed resolve can be recovered by the
/// build/download ladder.
///
/// An absent entry and a partial entry are both recoverable: the ladder ends
/// in a fresh install, so either state just means "nothing usable here yet".
/// A version or size disagreement is not recoverable here — those bytes exist
/// and this cache cannot vouch for them, which is surfaced rather than hidden.
fn is_recoverable_resolve_miss(error: &InitramfsBuildError) -> bool {
    matches!(
        error,
        InitramfsBuildError::Resolve(
            mvm_fs::initramfs::InitramfsError::Missing(_)
                | mvm_fs::initramfs::InitramfsError::MissingEntry(_)
        )
    )
}

/// Resolve a cached universal initramfs, or return an error describing why it
/// is unavailable. A cold contributor cache packs the sealed initramfs agent
/// from this checkout's guest-runtime archive — the same archive the overlay
/// and SDK sidecar are assembled from — on every host. A release binary
/// assembles it from its own release's guest runtime in `mvmctl bootstrap`;
/// there is no published copy to fetch in its place.
///
/// The build is not host-gated: the archive cross-compiles with
/// `cargo zigbuild` and the agent is packed into a deterministic cpio on the
/// host, so every host has the same one arm.
pub fn resolve_or_build_local_initramfs(
    _env: &dyn ShellEnvironment,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let initial = match resolve_or_seed_from_default_cache(cache_root, version, arch) {
        Ok(artifact) => return Ok(artifact),
        Err(e) => e,
    };
    if !is_recoverable_resolve_miss(&initial) {
        return Err(initial);
    }
    // A partial version-keyed dir (a lone recorded fingerprint, an
    // interrupted install) shadows the ladder as a corrupt entry; remove it
    // so the ladder's install is the only writer to that directory.
    let versioned_dir = cache_root.join(version).join(arch.to_string());
    if versioned_dir.is_dir() {
        std::fs::remove_dir_all(&versioned_dir)?;
    }

    if !crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        return Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!(
                "the universal initramfs {version} for {arch} is not prepared; run \
                 `mvmctl bootstrap`, which assembles it from this release's guest runtime ({initial})"
            ),
        });
    }

    if crate::image_source::guest_runtime_source_checkout().is_some() {
        mvm_vmm::host::ui::admit_cold_build("the universal initramfs")
            .map_err(|reason| InitramfsBuildError::CargoBuildFailed { reason })?;
    }
    build_initramfs_from_source_checkout(cache_root, version, arch)
}

/// Pack the initramfs from this checkout's guest-runtime archive, which lives
/// beside the initramfs cache under the mvm cache root. The installed artifact
/// records the archive digest, which is what the boot-time freshness eviction
/// compares against.
fn build_initramfs_from_source_checkout(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let failed = |reason: String| InitramfsBuildError::CargoBuildFailed { reason };
    let workspace = crate::image_source::guest_runtime_source_checkout().ok_or_else(|| {
        failed("no source checkout detected to build the guest runtime from".into())
    })?;
    let shared_cache_root = cache_root.parent().ok_or_else(|| {
        failed(format!(
            "initramfs cache {} has no parent for the shared guest runtime",
            cache_root.display()
        ))
    })?;
    let runtime = crate::guest_runtime::resolve_or_build_source_guest_runtime(
        shared_cache_root,
        version,
        arch,
        &workspace,
    )
    .map_err(|e| failed(format!("build the guest runtime: {e}")))?;
    build_initramfs_from_guest_runtime(cache_root, version, arch, &runtime)
}

/// Pack the size-tuned initramfs agent from the verified guest runtime as
/// `/init`. This archive member is deliberately distinct from the overlay's
/// addons-enabled agent under `<arch>/bin/`.
pub fn build_initramfs_from_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &crate::guest_runtime::GuestRuntime,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    if runtime.manifest.version != version {
        return Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!(
                "guest runtime version {} does not match initramfs version {version}",
                runtime.manifest.version
            ),
        });
    }
    let member = format!("{arch}/initramfs/mvm-guest-agent");
    let Some(expected_digest) = runtime.manifest.files.get(&member) else {
        return Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!("guest runtime manifest does not contain {member}"),
        });
    };
    let agent = runtime.root.join(&member);
    if !std::fs::symlink_metadata(&agent).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!("guest runtime member is not a regular file: {member}"),
        });
    }
    let agent_bytes = std::fs::read(&agent)?;
    if sha256_hex(&agent_bytes) != *expected_digest {
        return Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!("guest runtime member changed while packing: {member}"),
        });
    }
    let artifact_dir = InitramfsResolver::new(cache_root, version).artifact_dir(&arch.to_string());
    if cached_artifact_matches_source(cache_root, version, arch, &runtime.digest)
        && let Ok(cached) = InitramfsResolver::new(cache_root, version).resolve(&arch.to_string())
    {
        // Packed from this digest; a copy written before pieces recorded
        // their origin gains the record here.
        crate::runtime_pieces::record_archive_origin(&artifact_dir, &runtime.digest)?;
        return Ok(cached);
    }
    let staging = tempfile::tempdir()?;
    assemble_initramfs_artifact(&agent_bytes, version, staging.path())?;
    let installed = install_initramfs_into_cache(staging.path(), cache_root, version, arch)?;
    record_source_fingerprint(cache_root, version, arch, &runtime.digest)?;
    crate::runtime_pieces::record_archive_origin(&artifact_dir, &runtime.digest)?;
    Ok(installed)
}

/// Write the four artifact files (image + sidecars) for `agent_bytes` into
/// `out_dir`: the deterministic image, `initramfs.hash` = SHA-256 of the
/// UNCOMPRESSED cpio, `initramfs.size` = the compressed byte length, and
/// `VERSION` — the same contract the publish-path build emits. `pub` as
/// the deterministic-assembly contract surface (the conformance suite
/// drives it hermetically).
pub fn assemble_initramfs_artifact(
    agent_bytes: &[u8],
    version: &str,
    out_dir: &Path,
) -> Result<(), InitramfsBuildError> {
    let cpio = initramfs_cpio(agent_bytes);
    let image = gzip_deterministic(&cpio)?;
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(
        out_dir.join(mvm_fs::initramfs::INITRAMFS_IMAGE_FILE),
        &image,
    )?;
    std::fs::write(
        out_dir.join(mvm_fs::initramfs::INITRAMFS_HASH_FILE),
        format!("{}\n", sha256_hex(&cpio)),
    )?;
    std::fs::write(
        out_dir.join(mvm_fs::initramfs::INITRAMFS_SIZE_FILE),
        format!("{}\n", image.len()),
    )?;
    std::fs::write(
        out_dir.join(mvm_fs::initramfs::VERSION_FILE),
        format!("{version}\n"),
    )?;
    Ok(())
}

/// The deterministic cpio payload: exactly `.` and `./init` (the static
/// agent, mode 0755), epoch-zero metadata in a stable order — the Rust
/// equivalent of `find . | sort | cpio -o -H newc --owner=0:0` with all
/// timestamps touched to the epoch. No `/dev` nodes: PID 1 mounts
/// devtmpfs itself, so the kernel creates the device nodes. `pub` as the
/// determinism contract surface (the conformance suite builds it twice
/// and compares bytes).
pub fn initramfs_cpio(agent_bytes: &[u8]) -> Vec<u8> {
    crate::rootfs_inject::build_newc_cpio(&[
        crate::rootfs_inject::CpioEntry::dir("."),
        crate::rootfs_inject::CpioEntry::file("./init", 0o755, agent_bytes.to_vec()),
    ])
}

/// Gzip at the maximum level with no name/timestamp header — the
/// deterministic counterpart of `gzip -n -9` (the flate2 encoder writes a
/// zero mtime and no original filename by default).
fn gzip_deterministic(data: &[u8]) -> Result<Vec<u8>, InitramfsBuildError> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

use mvm_contract::hash::sha256_hex;

/// Install a prebuilt initramfs directory into the cache atomically.
pub fn install_initramfs_into_cache(
    source_dir: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let target_dir = InitramfsResolver::new(cache_root, version).artifact_dir(&arch.to_string());
    let parent = target_dir.parent().ok_or_else(|| {
        InitramfsBuildError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "computed initramfs artifact dir has no parent",
        ))
    })?;
    std::fs::create_dir_all(parent)?;

    let arch_dir = arch.to_string();
    let staging = parent.join(crate::cache_install::staging_dir_name(&arch_dir));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    // A run killed between here and the rename below orphans its staging dir
    // under another pid, which nothing else would ever clean up.
    crate::cache_install::reap_stale_staging(parent, &arch_dir);
    std::fs::create_dir(&staging)?;

    let files = [
        mvm_fs::initramfs::INITRAMFS_IMAGE_FILE,
        mvm_fs::initramfs::INITRAMFS_HASH_FILE,
        mvm_fs::initramfs::INITRAMFS_SIZE_FILE,
        mvm_fs::initramfs::VERSION_FILE,
    ];
    par_map(files.to_vec(), |file| {
        std::fs::copy(source_dir.join(file), staging.join(file))?;
        set_cache_perms(&staging.join(file))?;
        Ok::<(), InitramfsBuildError>(())
    })
    .into_iter()
    .collect::<Result<(), _>>()?;

    // Verify before the rename, so a corrupt artifact never becomes visible
    // to a resolver.
    verify_staged_image_hash(&staging)?;

    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir)?;
    }
    std::fs::rename(&staging, &target_dir)?;

    mvm_fs::initramfs::read_initramfs_artifact_from_dir(&target_dir).map_err(Into::into)
}

/// Check the staged image against its `initramfs.hash` sidecar.
///
/// This is the one choke point every artifact passes through on its way into
/// a cache root — the download, the local build, and the cross-root seed all
/// land here — so verifying here covers all three without putting the cost on
/// the boot path. `resolve()` deliberately stays cheap: it runs on every VM
/// start, and a decompress-and-hash per start is not affordable.
///
/// The build hashes the *uncompressed* cpio, so this decompresses rather than
/// hashing the compressed file. (`initramfs.size`, checked by the resolver, is
/// the compressed length — the two sidecars describe different bytes.)
fn verify_staged_image_hash(staging: &Path) -> Result<(), InitramfsBuildError> {
    let expected = std::fs::read_to_string(staging.join(mvm_fs::initramfs::INITRAMFS_HASH_FILE))?
        .trim()
        .to_ascii_lowercase();
    let image = staging.join(mvm_fs::initramfs::INITRAMFS_IMAGE_FILE);
    let actual = sha256_of_gunzipped(&image)?;
    if actual != expected {
        return Err(InitramfsBuildError::ChecksumMismatch {
            name: format!("{} (uncompressed)", mvm_fs::initramfs::INITRAMFS_IMAGE_FILE),
            expected,
            actual,
        });
    }
    Ok(())
}

/// SHA-256 over the gunzipped contents of `path`, streamed so a large
/// initramfs never lands in memory whole.
fn sha256_of_gunzipped(path: &Path) -> Result<String, InitramfsBuildError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;

    let file = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let read = decoder.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(unix)]
fn set_cache_perms(p: &Path) -> Result<(), InitramfsBuildError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_cache_perms(_p: &Path) -> Result<(), InitramfsBuildError> {
    Ok(())
}

// =================================================================
// Download the published initramfs (consumer side)
// =================================================================

/// Release-side artifact names for one arch. Pure data so the download path
/// and the release pipeline can agree on filenames without touching network
/// code in the release job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitramfsArtifactNames {
    /// The per-arch release tarball name.
    pub archive: String,
    /// The tarball's sha256 checksum sidecar name, which the CLI release still
    /// publishes for clients that predate the image set.
    pub archive_checksum: String,
}

impl InitramfsArtifactNames {
    /// Compute the per-arch release filenames.
    pub fn for_arch(arch: &str) -> Self {
        Self {
            archive: format!("initramfs-{arch}.tar.gz"),
            archive_checksum: format!("initramfs-{arch}.tar.gz.sha256"),
        }
    }
}

/// Resolve `arch`'s initramfs installed from the image set `set` by a
/// bundle's boot assets, a pure cache read.
///
/// The resolver expects the member `VERSION` recorded when it was installed
/// from its digest-verified bytes, not the running CLI's version; the set is
/// identified by its root, and a CLI version bump does not change the root.
pub fn resolve_image_set_initramfs(
    cache_root: &Path,
    set: &SetMemberCache,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let version = set.installed_version(
        cache_root,
        BOOT_ASSET_INITRAMFS_ROLE,
        MemberTarget::Arch(arch),
    )?;
    Ok(
        InitramfsResolver::new(set.cache_root(cache_root), version.as_str())
            .resolve(&arch.to_string())?,
    )
}

/// Install an already-authenticated initramfs member without registry access.
///
/// The caller must verify the archive against the image set's digest and size
/// before calling; a bundle's boot assets are the one caller. The member is
/// filed under the set's root — at
/// `<cache_root>/image-set/<root>/<member-version>/<arch>/`, still beneath the
/// initramfs cache root every boot path recognises — and labelled with its own
/// `VERSION`. The install is recorded only once the artifact is in place, so
/// an interrupted one reads as a miss.
pub fn install_image_set_initramfs_archive(
    archive: &Path,
    set: &SetMemberCache,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    install_image_set_initramfs_archive_with_limits(
        archive,
        set,
        arch,
        cache_root,
        INITRAMFS_ARCHIVE_LIMITS,
    )
}

// The runtime image is about 1.26 MiB today. Allow substantial growth, but
// never expand a signed outer archive into unbounded temporary storage.
const INITRAMFS_ARCHIVE_LIMITS: InitramfsArchiveLimits = InitramfsArchiveLimits {
    file_bytes: 64 * 1024 * 1024,
    total_bytes: 128 * 1024 * 1024,
};

fn install_image_set_initramfs_archive_with_limits(
    archive: &Path,
    set: &SetMemberCache,
    arch: GuestArch,
    cache_root: &Path,
    limits: InitramfsArchiveLimits,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let tmp = tempfile::tempdir()?;
    let stage = tmp.path();
    extract_initramfs_archive(archive, stage, limits)?;
    let version = MemberVersion::read(&stage.join(mvm_fs::initramfs::VERSION_FILE))?;
    let artifact =
        install_initramfs_into_cache(stage, &set.cache_root(cache_root), version.as_str(), arch)?;
    set.record(
        cache_root,
        BOOT_ASSET_INITRAMFS_ROLE,
        MemberTarget::Arch(arch),
        &version,
    )?;
    Ok(artifact)
}

/// Parse an authenticated legacy archive into a caller-owned empty private
/// directory, without populating a cache or granting publisher authority.
pub fn parse_authenticated_legacy_initramfs(
    archive_path: &Path,
    stage: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    extract_initramfs_archive(archive_path, stage, INITRAMFS_ARCHIVE_LIMITS)?;
    verify_staged_image_hash(stage)?;
    mvm_fs::initramfs::read_initramfs_artifact_from_dir(stage).map_err(Into::into)
}

fn extract_initramfs_archive(
    archive_path: &Path,
    stage: &Path,
    limits: InitramfsArchiveLimits,
) -> Result<(), InitramfsBuildError> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(limits.archive_reader(decoder));
    let mut seen = std::collections::BTreeSet::new();
    let mut remaining = limits.total_bytes;

    for entry in archive
        .entries()
        .map_err(|e| InitramfsBuildError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("read tar entries: {e}"),
        })?
    {
        let mut entry = entry.map_err(|e| InitramfsBuildError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("read tar entry: {e}"),
        })?;
        let path = entry
            .path()
            .map_err(|e| InitramfsBuildError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("read tar path: {e}"),
            })?;
        let Some(name) = canonical_archive_member_name(&path) else {
            return Err(InitramfsBuildError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("unsafe or unexpected path {:?}", path.display()),
            });
        };
        match entry.header().entry_type() {
            tar::EntryType::Regular => {
                if !seen.insert(name.to_string()) {
                    return Err(InitramfsBuildError::InvalidArchive {
                        archive_path: archive_path.to_path_buf(),
                        reason: format!("duplicate archive member {name}"),
                    });
                }
                let dest = stage.join(name);
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)?;
                limits
                    .copy_entry(&mut entry, &mut out, &mut remaining)
                    .map_err(|e| InitramfsBuildError::InvalidArchive {
                        archive_path: archive_path.to_path_buf(),
                        reason: format!("extract {name}: {e}"),
                    })?;
                set_cache_perms(&dest)?;
            }
            other => {
                return Err(InitramfsBuildError::InvalidArchive {
                    archive_path: archive_path.to_path_buf(),
                    reason: format!(
                        "unsupported tar entry type {other:?} for {:?}",
                        path.display()
                    ),
                });
            }
        }
    }

    InitramfsArchiveLimits::finish_archive(archive.into_inner()).map_err(|e| {
        InitramfsBuildError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("finish tar stream: {e}"),
        }
    })?;
    for required in [
        mvm_fs::initramfs::INITRAMFS_IMAGE_FILE,
        mvm_fs::initramfs::INITRAMFS_HASH_FILE,
        mvm_fs::initramfs::INITRAMFS_SIZE_FILE,
        mvm_fs::initramfs::VERSION_FILE,
        mvm_fs::initramfs::CHECKSUM_MANIFEST_FILE,
    ] {
        if !seen.contains(required) {
            return Err(InitramfsBuildError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("missing required archive member {required}"),
            });
        }
    }
    Ok(())
}

fn canonical_archive_member_name(path: &Path) -> Option<&'static str> {
    let mut components = path.components();
    let component = match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(name)), None) => name,
        _ => return None,
    };
    match component.to_str()? {
        "initramfs.cpio.gz" => Some("initramfs.cpio.gz"),
        "initramfs.hash" => Some("initramfs.hash"),
        "initramfs.size" => Some("initramfs.size"),
        "VERSION" => Some("VERSION"),
        "checksums-sha256.txt" => Some("checksums-sha256.txt"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn guest_runtime_initramfs_uses_sealed_agent_and_exact_cpio() {
        use flate2::read::GzDecoder;
        use mvm_core::image_set::{GitCommit, WorktreeState};
        use std::io::Read as _;

        let source = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let sealed_member = format!("{arch}/initramfs/mvm-guest-agent");
        let overlay_member = format!("{arch}/bin/mvm-guest-agent");
        for (member, bytes) in [
            (sealed_member.as_str(), b"sealed-agent".as_slice()),
            (overlay_member.as_str(), b"addons-agent".as_slice()),
        ] {
            let path = source.path().join(member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let files = std::collections::BTreeMap::from([
            (sealed_member.clone(), sha256_hex(b"sealed-agent")),
            (overlay_member, sha256_hex(b"addons-agent")),
        ]);
        let mut runtime = crate::guest_runtime::GuestRuntime {
            root: source.path().to_path_buf(),
            digest: "d".repeat(64),
            release_proof: None,
            manifest: crate::guest_bins::GuestBinsManifest {
                schema_version: crate::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: "1.2.3".into(),
                guest_source_fingerprint: "g".repeat(64),
                sdk_cdylib_source_fingerprint: "s".repeat(64),
                source: crate::image_source::RepoIdentity {
                    commit: GitCommit::new("a".repeat(40)).unwrap(),
                    worktree: WorktreeState::Clean,
                },
                files,
                assemblies: Default::default(),
            },
        };
        let artifact =
            build_initramfs_from_guest_runtime(cache.path(), "1.2.3", arch, &runtime).unwrap();
        let mut cpio = Vec::new();
        GzDecoder::new(std::fs::File::open(&artifact.image_path).unwrap())
            .read_to_end(&mut cpio)
            .unwrap();
        assert_eq!(cpio, initramfs_cpio(b"sealed-agent"));
        assert!(
            !cpio
                .windows(b"addons-agent".len())
                .any(|bytes| bytes == b"addons-agent")
        );
        assert_eq!(
            std::fs::read_to_string(cache.path().join("1.2.3/x86_64/SOURCE_FINGERPRINT")).unwrap(),
            runtime.digest
        );
        assert_eq!(
            crate::runtime_pieces::archive_origin(&cache.path().join("1.2.3/x86_64")).unwrap(),
            Some(runtime.digest.clone()),
            "the packed initramfs names the archive it came from"
        );
        // The boot-time eviction keys on the same digest, so a fresh pack
        // survives the next boot instead of being discarded and rebuilt.
        assert!(!evict_if_source_changed(cache.path(), "1.2.3", arch, &runtime.digest).unwrap());
        assert!(artifact.image_path.is_file());

        let stale = tempfile::tempdir().unwrap();
        assemble_initramfs_artifact(b"older-agent", "1.2.3", stale.path()).unwrap();
        install_initramfs_into_cache(stale.path(), cache.path(), "1.2.3", arch).unwrap();
        record_source_fingerprint(cache.path(), "1.2.3", arch, "older-runtime").unwrap();
        let refreshed =
            build_initramfs_from_guest_runtime(cache.path(), "1.2.3", arch, &runtime).unwrap();
        let mut refreshed_cpio = Vec::new();
        GzDecoder::new(std::fs::File::open(&refreshed.image_path).unwrap())
            .read_to_end(&mut refreshed_cpio)
            .unwrap();
        assert_eq!(refreshed_cpio, initramfs_cpio(b"sealed-agent"));
        assert_eq!(
            std::fs::read_to_string(cache.path().join("1.2.3/x86_64/SOURCE_FINGERPRINT")).unwrap(),
            runtime.digest
        );

        runtime.manifest.files.remove(&sealed_member);
        let error =
            build_initramfs_from_guest_runtime(cache.path(), "1.2.3", arch, &runtime).unwrap_err();
        assert!(error.to_string().contains(&sealed_member), "{error}");
        runtime
            .manifest
            .files
            .insert(sealed_member.clone(), sha256_hex(b"sealed-agent"));
        std::fs::write(source.path().join(&sealed_member), b"changed").unwrap();
        let error =
            build_initramfs_from_guest_runtime(cache.path(), "1.2.3", arch, &runtime).unwrap_err();
        assert!(
            error.to_string().contains("changed while packing"),
            "{error}"
        );
    }

    /// The defect this closes: the cache key is `(version, arch)` and the
    /// version only moves on a release, so an artifact built from older guest
    /// sources outlives every change to them. A guest-side fix lands, the cache
    /// still serves the binary from before it, and the fix looks inert — which
    /// is exactly how an agent built before its own trust-anchor fix kept being
    /// booted afterwards.
    #[test]
    fn a_cached_artifact_from_other_sources_is_evicted() {
        let cache = tempfile::tempdir().unwrap();
        let dir = cache.path().join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), b"stale").unwrap();
        record_source_fingerprint(cache.path(), "0.18.0", GuestArch::Aarch64, "old-sources")
            .unwrap();

        let evicted =
            evict_if_source_changed(cache.path(), "0.18.0", GuestArch::Aarch64, "new-sources")
                .unwrap();
        assert!(
            evicted,
            "a mismatched fingerprint must discard the artifact"
        );
        assert!(
            !dir.exists(),
            "the stale artifact must be gone, not merely ignored"
        );
    }

    /// The matching case must not churn: rebuilding a correct artifact on every
    /// boot would be its own bug.
    #[test]
    fn a_cached_artifact_from_the_same_sources_is_kept() {
        let cache = tempfile::tempdir().unwrap();
        let dir = cache.path().join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), b"fresh").unwrap();
        record_source_fingerprint(cache.path(), "0.18.0", GuestArch::Aarch64, "same").unwrap();

        let evicted =
            evict_if_source_changed(cache.path(), "0.18.0", GuestArch::Aarch64, "same").unwrap();
        assert!(!evicted);
        assert!(dir.join("initramfs.cpio.gz").is_file());
    }

    /// An artifact with no fingerprint recorded predates this check, so nothing
    /// can vouch for what built it. Treating it as fresh is what let the stale
    /// one survive in the first place.
    #[test]
    fn an_unfingerprinted_artifact_is_not_trusted() {
        let cache = tempfile::tempdir().unwrap();
        let dir = cache.path().join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), b"unknown provenance").unwrap();

        let evicted =
            evict_if_source_changed(cache.path(), "0.18.0", GuestArch::Aarch64, "any").unwrap();
        assert!(
            evicted,
            "an artifact of unknown provenance must not be reused"
        );
    }

    /// The ladder's recoverable-miss predicate: an absent or partial
    /// version-keyed entry recovers through build/download, while a version
    /// or size disagreement is surfaced rather than silently reinstalled.
    #[test]
    fn recoverable_miss_classification() {
        use mvm_fs::initramfs::InitramfsError;
        let missing = InitramfsBuildError::Resolve(InitramfsError::Missing(
            std::path::PathBuf::from("/tmp/none"),
        ));
        assert!(
            is_recoverable_resolve_miss(&missing),
            "an absent entry must fall through to the ladder"
        );
        let partial = InitramfsBuildError::Resolve(InitramfsError::MissingEntry(
            std::path::PathBuf::from("/tmp/partial/initramfs.cpio.gz"),
        ));
        assert!(
            is_recoverable_resolve_miss(&partial),
            "a partial entry (fingerprint without an artifact) must fall through too"
        );
        let wrong_version = InitramfsBuildError::Resolve(InitramfsError::VersionMismatch {
            expected: "0.18.1".into(),
            got: Some("0.18.0".into()),
        });
        assert!(
            !is_recoverable_resolve_miss(&wrong_version),
            "bytes for another version must keep refusing"
        );
        let wrong_size = InitramfsBuildError::Resolve(InitramfsError::SizeMismatch {
            expected: 1,
            actual: 2,
        });
        assert!(
            !is_recoverable_resolve_miss(&wrong_size),
            "a size disagreement must keep refusing"
        );
    }

    /// A fingerprint is recorded only when the resolved artifact actually
    /// lives in the version-keyed directory. A pinned-set member resolves from
    /// `image-set/<root>/…`; labeling the version-keyed dir beside it would
    /// leave a partial entry the next resolve reports as a missing artifact.
    #[test]
    fn fingerprint_recording_skips_a_set_member_artifact() {
        let cache = tempfile::tempdir().unwrap();
        let local_dir = cache.path().join("0.18.1").join("aarch64");
        std::fs::create_dir_all(&local_dir).unwrap();

        let local = mvm_fs::initramfs::InitramfsArtifact {
            image_path: local_dir.join("initramfs.cpio.gz"),
            hash_path: local_dir.join("initramfs.hash"),
            size_path: local_dir.join("initramfs.size"),
            version: "0.18.1".into(),
        };
        record_source_fingerprint_for_resolved(
            cache.path(),
            "0.18.1",
            GuestArch::Aarch64,
            &local,
            "local-fingerprint",
        )
        .unwrap();
        assert!(
            local_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE).is_file(),
            "a version-keyed local build is labeled with its fingerprint"
        );

        let member_dir = cache
            .path()
            .join("image-set")
            .join("deadbeef")
            .join("0.18.0-rc.2")
            .join("aarch64");
        std::fs::create_dir_all(&member_dir).unwrap();
        let member = mvm_fs::initramfs::InitramfsArtifact {
            image_path: member_dir.join("initramfs.cpio.gz"),
            hash_path: member_dir.join("initramfs.hash"),
            size_path: member_dir.join("initramfs.size"),
            version: "0.18.0-rc.2".into(),
        };
        record_source_fingerprint_for_resolved(
            cache.path(),
            "0.18.1",
            GuestArch::Aarch64,
            &member,
            "checkout-fingerprint",
        )
        .unwrap();
        let recorded =
            std::fs::read_to_string(local_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE)).unwrap();
        assert!(
            recorded.contains("local-fingerprint"),
            "a set member must not be recorded into the version-keyed dir: {recorded}"
        );
    }

    /// Resolution reports "missing" when the cache is genuinely empty.
    ///
    /// Two isolations are load-bearing. `HOME` moves because the resolver falls
    /// back to `default_mvm_cache_dir`, the one resolver that reads `$HOME` even
    /// when `MVM_HOME` is set, and would otherwise seed this tempdir from the
    /// developer's real cache — asserting "empty" against a machine-dependent
    /// fact. And this exercises the *resolver*, not
    /// `resolve_or_build_local_initramfs`, whose empty-cache path on Linux falls
    /// through to a real `nix build`: with a no-op shell that build reports
    /// success without producing anything and the call never returns. Left that
    /// way the test passed on Linux only by finding an artifact it was supposed
    /// to prove absent, and hung for hours once it genuinely could not.
    #[test]
    fn resolve_returns_missing_when_cache_empty() {
        // Isolate the whole mvm world so the seed-from-default-cache step
        // cannot find the developer's real cache — the assertion is that a
        // truly cold cache errors, which only holds when the default cache
        // is cold too.
        // HOME has to move with the cache root: a miss is seeded from
        // `$HOME/.mvm/cache`, so without this the assertion holds only on a
        // machine that has never built an initramfs — which CI is and a
        // contributor's laptop is not.
        //
        // And this exercises the *resolver* rather than
        // `resolve_or_build_local_initramfs`, whose empty-cache path on Linux
        // falls through to a real `nix build`. With a shell double that reports
        // success without producing an artifact, that call never returns: the
        // test ran for 20,000+ seconds in CI and took the job to its six-hour
        // limit. Isolating HOME is what made it reachable — before that the test
        // passed on Linux by finding an artifact it was supposed to prove absent.
        //
        // One lock, taken once: `ENV_TEST_LOCK` is a plain `std::sync::Mutex`
        // and is not reentrant, so acquiring it twice on this thread deadlocks
        // the test rather than failing it.
        let _lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        let cache = dir.path().join("cache");
        let err = resolve_or_seed_from_default_cache(&cache, "0.18.0", GuestArch::Aarch64)
            .expect_err("an empty cache with nothing to seed from must resolve as missing");
        assert!(
            matches!(
                err,
                InitramfsBuildError::Resolve(mvm_fs::initramfs::InitramfsError::Missing(_))
            ),
            "expected a Missing resolution, got: {err}"
        );
    }

    #[test]
    fn install_initramfs_into_cache_copies_files() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache");
        write_initramfs_artifact(&source, "0.18.0", b"cpio-payload");

        let artifact =
            install_initramfs_into_cache(&source, &cache_root, "0.18.0", GuestArch::Aarch64)
                .unwrap();

        let target_dir = cache_root
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        assert!(target_dir.join("initramfs.cpio.gz").is_file());
        assert_eq!(artifact.image_path, target_dir.join("initramfs.cpio.gz"));
        assert_eq!(artifact.version, "0.18.0");
    }

    #[test]
    fn install_refuses_an_image_that_does_not_match_its_hash_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache");
        write_initramfs_artifact(&source, "0.18.0", b"cpio-payload");

        // Swap in a different payload, leaving the sidecar hash untouched —
        // the substitution a size check alone cannot see, because the
        // replacement is written to the same compressed length.
        let (honest, ..) = initramfs_fixture(b"cpio-payload");
        let (tampered, ..) = initramfs_fixture(b"evil-payload");
        assert_eq!(
            honest.len(),
            tampered.len(),
            "fixture must keep the compressed length identical"
        );
        std::fs::write(source.join("initramfs.cpio.gz"), &tampered).unwrap();

        let err = install_initramfs_into_cache(&source, &cache_root, "0.18.0", GuestArch::Aarch64)
            .unwrap_err();

        assert!(
            matches!(err, InitramfsBuildError::ChecksumMismatch { .. }),
            "expected a checksum mismatch, got {err:?}"
        );
        let target_dir = cache_root
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        assert!(
            !target_dir.exists(),
            "a refused artifact must never become visible to a resolver"
        );
    }

    fn served_initramfs_archive(version: &str) -> Vec<u8> {
        let (image_bytes, hash, size) = initramfs_fixture(b"downloaded-cpio-payload");
        initramfs_archive_bytes(
            &image_bytes,
            format!("{hash}\n").as_bytes(),
            format!("{size}\n").as_bytes(),
            format!("{version}\n").as_bytes(),
        )
    }

    /// A member cut from a workspace at another version than this CLI's.
    const MEMBER_VERSION: &str = "0.0.1-member";

    fn archive_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let mut tar = tar::Builder::new(gzip);
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, *bytes).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn expanded_initramfs_budgets_bound_writes_and_never_publish() {
        let large = vec![0; 1024 * 1024];
        for (entries, limits, expected_written) in [
            (
                vec![("initramfs.cpio.gz", large.as_slice())],
                InitramfsArchiveLimits {
                    file_bytes: 1024,
                    total_bytes: 4096,
                },
                1024,
            ),
            (
                vec![
                    ("initramfs.cpio.gz", &large[..700]),
                    ("initramfs.hash", large.as_slice()),
                ],
                InitramfsArchiveLimits {
                    file_bytes: 1024,
                    total_bytes: 1024,
                },
                1024,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let archive = tmp.path().join("archive.tar.gz");
            let bytes = archive_with_entries(&entries);
            assert!(bytes.len() < 4096, "highly compressed fixture");
            std::fs::write(&archive, bytes).unwrap();
            let stage = tmp.path().join("stage");
            std::fs::create_dir(&stage).unwrap();
            let error = extract_initramfs_archive(&archive, &stage, limits).unwrap_err();
            assert!(error.to_string().contains("budget"), "{error}");
            let written: u64 = std::fs::read_dir(stage)
                .unwrap()
                .map(|file| file.unwrap().metadata().unwrap().len())
                .sum();
            assert_eq!(written, expected_written);
            let set =
                SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"budget-set"));
            let cache = tmp.path().join("cache");
            assert!(
                install_image_set_initramfs_archive_with_limits(
                    &archive,
                    &set,
                    GuestArch::Aarch64,
                    &cache,
                    limits,
                )
                .is_err()
            );
            assert!(!cache.exists());
            assert!(
                set.installed_version(
                    &cache,
                    BOOT_ASSET_INITRAMFS_ROLE,
                    MemberTarget::Arch(GuestArch::Aarch64)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn initramfs_rejects_directory_and_hidden_metadata_expansion() {
        for kind in [
            tar::EntryType::Directory,
            tar::EntryType::GNULongName,
            tar::EntryType::XHeader,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let archive = tmp.path().join("archive.tar.gz");
            let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            let mut tar = tar::Builder::new(gzip);
            let bytes = if kind == tar::EntryType::Directory {
                Vec::new()
            } else {
                vec![b'a'; 1024 * 1024]
            };
            for _ in 0..if kind == tar::EntryType::Directory {
                1024
            } else {
                1
            } {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(kind);
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, "VERSION", bytes.as_slice())
                    .unwrap();
            }
            let compressed = tar.into_inner().unwrap().finish().unwrap();
            assert!(compressed.len() < 4096);
            std::fs::write(&archive, compressed).unwrap();
            let set =
                SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"metadata-set"));
            let cache = tmp.path().join("cache");
            let error = install_image_set_initramfs_archive_with_limits(
                &archive,
                &set,
                GuestArch::Aarch64,
                &cache,
                InitramfsArchiveLimits {
                    file_bytes: 16,
                    total_bytes: 32,
                },
            )
            .unwrap_err();
            assert!(
                matches!(error, InitramfsBuildError::InvalidArchive { .. }),
                "{error}"
            );
            assert!(!cache.exists());
            assert!(
                set.installed_version(
                    &cache,
                    BOOT_ASSET_INITRAMFS_ROLE,
                    MemberTarget::Arch(GuestArch::Aarch64)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn duplicate_initramfs_members_are_rejected_before_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("archive.tar.gz");
        std::fs::write(
            &archive,
            archive_with_entries(&[("VERSION", b"first"), ("VERSION", b"second")]),
        )
        .unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        let error =
            extract_initramfs_archive(&archive, &stage, INITRAMFS_ARCHIVE_LIMITS).unwrap_err();
        assert!(error.to_string().contains("duplicate"), "{error}");
        assert_eq!(std::fs::read(stage.join("VERSION")).unwrap(), b"first");
        let set =
            SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"duplicate-set"));
        let cache = tmp.path().join("cache");
        assert!(
            install_image_set_initramfs_archive(&archive, &set, GuestArch::Aarch64, &cache)
                .is_err()
        );
        assert!(!cache.exists());
        assert!(
            set.installed_version(
                &cache,
                BOOT_ASSET_INITRAMFS_ROLE,
                MemberTarget::Arch(GuestArch::Aarch64)
            )
            .is_err()
        );
    }

    #[test]
    fn valid_initramfs_archive_installs_with_small_expansion_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("archive.tar.gz");
        std::fs::write(&archive, served_initramfs_archive(MEMBER_VERSION)).unwrap();
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"small-set"));
        let cache = tmp.path().join("cache");
        let installed = install_image_set_initramfs_archive_with_limits(
            &archive,
            &set,
            GuestArch::Aarch64,
            &cache,
            InitramfsArchiveLimits {
                file_bytes: 1024,
                total_bytes: 4096,
            },
        )
        .unwrap();
        assert_eq!(
            resolve_image_set_initramfs(&cache, &set, GuestArch::Aarch64).unwrap(),
            installed
        );
    }

    #[test]
    fn initramfs_requires_all_five_regular_members_even_in_populated_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("archive.tar.gz");
        std::fs::write(&archive, archive_with_entries(&[("VERSION", b"1")])).unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("initramfs.cpio.gz"), b"existing").unwrap();
        let error =
            extract_initramfs_archive(&archive, &stage, INITRAMFS_ARCHIVE_LIMITS).unwrap_err();
        assert!(error.to_string().contains("missing required"), "{error}");
    }

    #[test]
    fn an_authenticated_local_initramfs_installs_without_a_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("initramfs.tar.gz");
        std::fs::write(&archive, served_initramfs_archive(MEMBER_VERSION)).unwrap();
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"bundle-set"));
        let cache = tmp.path().join("cache");

        let installed =
            install_image_set_initramfs_archive(&archive, &set, GuestArch::Aarch64, &cache)
                .expect("install authenticated archive");
        std::fs::remove_file(archive).unwrap();

        assert_eq!(installed.version, MEMBER_VERSION);
        assert_eq!(
            resolve_image_set_initramfs(&cache, &set, GuestArch::Aarch64).unwrap(),
            installed
        );
    }

    #[test]
    fn an_invalid_local_initramfs_does_not_record_an_install() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("initramfs.tar.gz");
        std::fs::write(&archive, b"not an initramfs archive").unwrap();
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"bundle-set"));
        let cache = tmp.path().join("cache");

        assert!(
            install_image_set_initramfs_archive(&archive, &set, GuestArch::Aarch64, &cache)
                .is_err()
        );
        assert!(
            set.installed_version(
                &cache,
                BOOT_ASSET_INITRAMFS_ROLE,
                MemberTarget::Arch(GuestArch::Aarch64)
            )
            .is_err()
        );
    }

    /// Write `bytes` as an authenticated archive a bundle's boot assets would
    /// hand over, and return its path.
    fn bundle_archive(dir: &Path, bytes: Vec<u8>) -> PathBuf {
        let path = dir.join("initramfs-aarch64.tar.gz");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// The set's identity is its signed root, so an initramfs a bundle's boot
    /// assets deliver at a `VERSION` that is not this CLI's installs, lands
    /// beneath the initramfs cache root every boot path recognises, and
    /// resolves from the cache afterwards.
    #[test]
    fn a_set_initramfs_at_another_version_installs_and_resolves_from_cache() {
        assert_ne!(MEMBER_VERSION, env!("CARGO_PKG_VERSION"));
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"bundle-set"));
        let archive = bundle_archive(tmp.path(), served_initramfs_archive(MEMBER_VERSION));

        let installed =
            install_image_set_initramfs_archive(&archive, &set, GuestArch::Aarch64, &cache_root)
                .expect("a member at another version must install");
        assert_eq!(installed.version, MEMBER_VERSION);
        assert!(installed.image_path.starts_with(&cache_root));

        std::fs::remove_file(&archive).unwrap();
        let resolved = resolve_image_set_initramfs(&cache_root, &set, GuestArch::Aarch64)
            .expect("the installed member must resolve from the cache");
        assert_eq!(resolved, installed);
    }

    /// An initramfs installed under one root is not a member of another.
    #[test]
    fn a_set_initramfs_from_another_root_is_not_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"bundle-set"));
        let archive = bundle_archive(tmp.path(), served_initramfs_archive(MEMBER_VERSION));
        install_image_set_initramfs_archive(&archive, &set, GuestArch::Aarch64, &cache_root)
            .unwrap();

        let moved = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"next"));
        let err = resolve_image_set_initramfs(&cache_root, &moved, GuestArch::Aarch64)
            .expect_err("another root's initramfs must not resolve");
        assert!(
            matches!(
                err,
                InitramfsBuildError::ImageSetCache(SetMemberCacheError::NotInstalled { .. })
            ),
            "{err:?}"
        );
    }

    /// An initramfs an older CLI installed from the pinned image set is still
    /// on disk after an upgrade. It is the image set's copy, built from
    /// another tree, so the launch-side resolve never returns it: a CLI whose
    /// own initramfs is not prepared misses rather than boots that one.
    #[test]
    fn an_initramfs_installed_from_the_pinned_set_is_never_resolved_for_a_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache").join("initramfs");
        let set = SetMemberCache::locked();
        let version = env!("CARGO_PKG_VERSION");
        write_initramfs_artifact(&source, version, b"cpio-payload");
        install_initramfs_into_cache(
            &source,
            &set.cache_root(&cache_root),
            version,
            GuestArch::Aarch64,
        )
        .unwrap();
        set.record(
            &cache_root,
            BOOT_ASSET_INITRAMFS_ROLE,
            MemberTarget::Arch(GuestArch::Aarch64),
            &MemberVersion::parse(version).unwrap(),
        )
        .unwrap();

        let err = InitramfsResolver::new(&cache_root, version)
            .resolve(&GuestArch::Aarch64.to_string())
            .expect_err("the pinned set's copy is not this CLI's initramfs");
        assert!(
            matches!(err, mvm_fs::initramfs::InitramfsError::Missing(_)),
            "{err:?}"
        );
    }

    /// The version-keyed cache that source builds and seeding use keeps exact
    /// equality with the version it is asked for.
    #[test]
    fn the_version_keyed_initramfs_cache_still_refuses_a_mismatched_version() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache").join("initramfs");
        write_initramfs_artifact(&source, MEMBER_VERSION, b"cpio-payload");
        install_initramfs_into_cache(&source, &cache_root, "9.9.9", GuestArch::Aarch64).unwrap();

        let err = InitramfsResolver::new(&cache_root, "9.9.9")
            .resolve("aarch64")
            .expect_err("a VERSION other than the key's must be refused");
        assert!(
            matches!(
                err,
                mvm_fs::initramfs::InitramfsError::VersionMismatch { .. }
            ),
            "{err:?}"
        );
    }

    fn initramfs_archive_bytes(
        image_bytes: &[u8],
        hash_bytes: &[u8],
        size_bytes: &[u8],
        version_bytes: &[u8],
    ) -> Vec<u8> {
        crate::boot_asset_fixture::initramfs_archive_bytes(
            image_bytes,
            hash_bytes,
            size_bytes,
            version_bytes,
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    /// The three sidecar values the nix build emits for a cpio payload: a real
    /// gzip stream, the SHA-256 of the *uncompressed* payload, and the length
    /// of the *compressed* file. Fixtures have to match that shape or they
    /// cannot exercise the install-time hash check.
    fn initramfs_fixture(payload: &[u8]) -> (Vec<u8>, String, String) {
        crate::boot_asset_fixture::initramfs_fixture(payload)
    }

    /// Write a complete, self-consistent artifact directory.
    fn write_initramfs_artifact(dir: &std::path::Path, version: &str, payload: &[u8]) {
        let (image, hash, size) = initramfs_fixture(payload);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), &image).unwrap();
        std::fs::write(dir.join("initramfs.hash"), format!("{hash}\n")).unwrap();
        std::fs::write(dir.join("initramfs.size"), format!("{size}\n")).unwrap();
        std::fs::write(dir.join("VERSION"), format!("{version}\n")).unwrap();
    }

    #[test]
    fn pure_legacy_initramfs_parser_preserves_payload_without_cache_install() {
        let archive_dir = tempfile::tempdir().unwrap();
        let archive = archive_dir.path().join("initramfs.tar.gz");
        std::fs::write(&archive, served_initramfs_archive("legacy-original")).unwrap();
        let stage = tempfile::tempdir().unwrap();
        let parsed = parse_authenticated_legacy_initramfs(&archive, stage.path()).unwrap();
        assert_eq!(parsed.version, "legacy-original");
        assert_eq!(parsed.image_path, stage.path().join("initramfs.cpio.gz"));
        assert!(parse_authenticated_legacy_initramfs(&archive, stage.path()).is_err());
    }

    #[test]
    fn legacy_initramfs_extraction_refuses_duplicate_links_and_unsafe_paths() {
        for (name, kind, copies) in [
            ("initramfs.cpio.gz", tar::EntryType::Regular, 2),
            ("initramfs.cpio.gz", tar::EntryType::Symlink, 1),
            ("../outside", tar::EntryType::Regular, 1),
            ("/outside", tar::EntryType::Regular, 1),
            ("nested/initramfs.cpio.gz", tar::EntryType::Regular, 1),
        ] {
            let home = tempfile::tempdir().unwrap();
            let archive = home.path().join("bad.tar.gz");
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut tar = tar::Builder::new(encoder);
            for _ in 0..copies {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_size(0);
                header.set_entry_type(kind);
                header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
                header.set_cksum();
                tar.append(&header, std::io::empty()).unwrap();
            }
            std::fs::write(&archive, tar.into_inner().unwrap().finish().unwrap()).unwrap();
            let stage = tempfile::tempdir().unwrap();
            let error = extract_initramfs_archive(&archive, stage.path(), INITRAMFS_ARCHIVE_LIMITS)
                .unwrap_err();
            assert!(!error.to_string().contains("missing required"), "{error}");
        }
    }

    #[test]
    fn legacy_initramfs_extraction_requires_members_from_the_archive() {
        let home = tempfile::tempdir().unwrap();
        let archive = home.path().join("empty.tar.gz");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let tar = tar::Builder::new(encoder);
        std::fs::write(&archive, tar.into_inner().unwrap().finish().unwrap()).unwrap();
        let stage = tempfile::tempdir().unwrap();
        write_initramfs_artifact(stage.path(), "legacy-original", b"original");
        std::fs::write(stage.path().join("checksums-sha256.txt"), b"").unwrap();
        assert!(
            extract_initramfs_archive(&archive, stage.path(), INITRAMFS_ARCHIVE_LIMITS).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_initramfs_extraction_does_not_follow_preexisting_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let archive = home.path().join("initramfs.tar.gz");
        std::fs::write(&archive, served_initramfs_archive("legacy-original")).unwrap();
        let outside = home.path().join("outside");
        std::fs::write(&outside, b"unchanged").unwrap();
        let stage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&outside, stage.path().join("initramfs.cpio.gz")).unwrap();
        assert!(
            extract_initramfs_archive(&archive, stage.path(), INITRAMFS_ARCHIVE_LIMITS).is_err()
        );
        assert_eq!(std::fs::read(outside).unwrap(), b"unchanged");
    }

    // --- deterministic cargo artifact assembly ---

    /// Parse the entry names of a newc archive, stopping at the trailer.
    /// Test-only: the layout assertions need the exact entry sequence.
    fn newc_names(cpio: &[u8]) -> Vec<String> {
        fn hex8(cpio: &[u8], off: usize) -> usize {
            usize::from_str_radix(std::str::from_utf8(&cpio[off..off + 8]).unwrap(), 16).unwrap()
        }
        let mut names = Vec::new();
        let mut off = 0;
        loop {
            assert_eq!(&cpio[off..off + 6], b"070701", "bad magic at {off}");
            let filesize = hex8(cpio, off + 54);
            let namesize = hex8(cpio, off + 94);
            let name =
                String::from_utf8(cpio[off + 110..off + 110 + namesize - 1].to_vec()).unwrap();
            let done = name == "TRAILER!!!";
            names.push(name);
            off = (off + 110 + namesize).div_ceil(4) * 4;
            off = (off + filesize).div_ceil(4) * 4;
            if done {
                return names;
            }
        }
    }

    /// Assert every record in the archive carries epoch-zero mtime and
    /// zero uid/gid — the metadata side of the determinism guarantee.
    fn assert_epoch_zero_metadata(cpio: &[u8]) {
        let mut off = 0;
        loop {
            // uid + gid are zero (root-owned), and mtime is the epoch.
            assert_eq!(&cpio[off + 22..off + 38], b"0000000000000000".as_slice());
            assert_eq!(&cpio[off + 46..off + 54], b"00000000".as_slice());
            let filesize =
                usize::from_str_radix(std::str::from_utf8(&cpio[off + 54..off + 62]).unwrap(), 16)
                    .unwrap();
            let namesize =
                usize::from_str_radix(std::str::from_utf8(&cpio[off + 94..off + 102]).unwrap(), 16)
                    .unwrap();
            let done = &cpio[off + 110..off + 110 + 9] == b"TRAILER!!";
            off = (off + 110 + namesize).div_ceil(4) * 4;
            off = (off + filesize).div_ceil(4) * 4;
            if done {
                return;
            }
        }
    }

    #[test]
    fn initramfs_cpio_is_byte_deterministic_across_builds() {
        let a = initramfs_cpio(b"agent-bytes");
        let b = initramfs_cpio(b"agent-bytes");
        assert_eq!(a, b, "same agent bytes must produce the same cpio");
        assert_eq!(sha256_hex(&a), sha256_hex(&b));
        assert_epoch_zero_metadata(&a);

        let gz_a = gzip_deterministic(&a).unwrap();
        let gz_b = gzip_deterministic(&a).unwrap();
        assert_eq!(gz_a, gz_b, "the gzip stream must be deterministic too");
    }

    #[test]
    fn initramfs_cpio_layout_is_dot_and_init_only() {
        let cpio = initramfs_cpio(b"agent-bytes");
        assert_eq!(
            newc_names(&cpio),
            vec![
                ".".to_string(),
                "./init".to_string(),
                "TRAILER!!!".to_string()
            ]
        );
    }

    #[test]
    fn assemble_writes_the_full_sidecar_contract() {
        let dir = tempfile::tempdir().unwrap();
        assemble_initramfs_artifact(b"agent-bytes", "0.18.0", dir.path()).unwrap();

        let image = std::fs::read(dir.path().join("initramfs.cpio.gz")).unwrap();
        let hash = std::fs::read_to_string(dir.path().join("initramfs.hash")).unwrap();
        let size = std::fs::read_to_string(dir.path().join("initramfs.size")).unwrap();
        let version = std::fs::read_to_string(dir.path().join("VERSION")).unwrap();

        // The hash covers the UNCOMPRESSED cpio; the size covers the
        // compressed file — the resolver's two sidecars describe
        // different bytes.
        let mut uncompressed = Vec::new();
        std::io::Read::read_to_end(
            &mut flate2::read::GzDecoder::new(image.as_slice()),
            &mut uncompressed,
        )
        .unwrap();
        assert_eq!(uncompressed, initramfs_cpio(b"agent-bytes"));
        assert_eq!(hash.trim(), sha256_hex(&uncompressed));
        assert_eq!(size.trim().parse::<usize>().unwrap(), image.len());
        assert_eq!(version.trim(), "0.18.0");
    }

    #[test]
    fn cold_build_output_installs_and_resolves_through_the_resolver() {
        // The hermetic cold-cache path: assemble with stand-in agent bytes,
        // install, and resolve — the same pipeline the cargo build runs
        // after the (separately cached and tested) agent cross-compile.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache");
        assemble_initramfs_artifact(b"fake-agent", "0.18.0", &source).unwrap();

        let artifact =
            install_initramfs_into_cache(&source, &cache_root, "0.18.0", GuestArch::Aarch64)
                .unwrap();
        let resolved = InitramfsResolver::new(&cache_root, "0.18.0")
            .resolve(&GuestArch::Aarch64.to_string())
            .unwrap();
        assert_eq!(resolved.image_path, artifact.image_path);
    }

    /// Shell double that fails loudly if the warm-cache resolve below ever
    /// reaches for the shell — the point of that test is that a warm cache
    /// resolves without one. A silent no-op double is what let the old
    /// empty-cache resolve test fall into a real build and hang, so an empty
    /// cache is exercised through `resolve_or_seed_from_default_cache`
    /// instead of this path.
    struct PanicShell;

    impl ShellEnvironment for PanicShell {
        fn shell_exec(&self, _script: &str) -> anyhow::Result<()> {
            panic!("a warm-cache resolve must not run shell commands")
        }

        fn shell_exec_stdout(&self, _script: &str) -> anyhow::Result<String> {
            panic!("a warm-cache resolve must not run shell commands")
        }

        fn shell_exec_visible(&self, _script: &str) -> anyhow::Result<()> {
            panic!("a warm-cache resolve must not run shell commands")
        }

        fn log_info(&self, _msg: &str) {}

        fn log_success(&self, _msg: &str) {}
    }

    #[test]
    fn warm_cache_resolve_skips_any_build_or_download() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache");
        assemble_initramfs_artifact(b"fake-agent", "0.18.0", &source).unwrap();
        install_initramfs_into_cache(&source, &cache_root, "0.18.0", GuestArch::Aarch64).unwrap();

        // A warm cache resolves without touching the shell environment
        // (PanicShell proves it) and without network.
        let artifact = resolve_or_build_local_initramfs(
            &PanicShell,
            &cache_root,
            "0.18.0",
            GuestArch::Aarch64,
        )
        .unwrap();
        assert_eq!(
            artifact.image_path,
            cache_root
                .join("0.18.0")
                .join(GuestArch::Aarch64.to_string())
                .join("initramfs.cpio.gz")
        );
    }

    #[test]
    fn seed_from_default_cache_installs_into_isolated_cache() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let isolated_cache = tmp.path().join("isolated").join("initramfs");

        // default_mvm_cache_dir() resolves to ~/.mvm/cache, so point HOME at
        // a temp directory and populate ~/.mvm/cache/initramfs/...
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        env.set("HOME", &home);
        let default_mvm = crate::cache_install::default_cache_root().join("initramfs");
        let default_artifact_dir = default_mvm
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        write_initramfs_artifact(&default_artifact_dir, "0.18.0", b"default-cpio-payload");
        std::fs::write(
            default_artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE),
            "donor-runtime-digest\n",
        )
        .unwrap();

        let artifact =
            resolve_or_seed_from_default_cache(&isolated_cache, "0.18.0", GuestArch::Aarch64)
                .unwrap();
        // The seeded copy keeps the donor's provenance rather than being
        // relabelled as built from whatever checkout is asking.
        assert!(cached_artifact_matches_source(
            &isolated_cache,
            "0.18.0",
            GuestArch::Aarch64,
            "donor-runtime-digest"
        ));

        let expected_dir = isolated_cache
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        assert_eq!(artifact.image_path, expected_dir.join("initramfs.cpio.gz"));
        assert!(expected_dir.join("initramfs.hash").is_file());
        assert!(expected_dir.join("initramfs.size").is_file());
        assert!(expected_dir.join("VERSION").is_file());
    }
}
