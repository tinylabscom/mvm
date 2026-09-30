//! Build and resolve the universal initramfs artifact.
//!
//! The initramfs is a tiny deterministic **cargo artifact** — one static
//! `mvm-guest-agent` binary packed as `/init` in an epoch-zero newc cpio —
//! built locally by [`build_initramfs_with_cargo`] on Linux and cached at
//! `<cache_root>/<version>/<arch>/`. Its attestability comes from the
//! reproducible cargo build of the pinned agent source plus the content
//! hash, not from Nix. Nix remains the build for kernels, images, and
//! overlays, where toolchain variance matters; mvm-images' initramfs flake
//! is the publish-path build of the same artifact. This
//! module mirrors the runtime-overlay orchestration but is intentionally
//! smaller because the artifact has no verity sidecar and no per-rootfs
//! variation.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::build_env::ShellEnvironment;
use mvm_fs::initramfs::{InitramfsArtifact, InitramfsResolver};
use mvm_fs::parallel::par_map;
use thiserror::Error;

use crate::published_image_set::{
    ImageSetMemberError, MemberVersion, PublishedImageSet, SetMemberCache, SetMemberCacheError,
};
use mvm_core::image_set::{ImageSetRole, MemberTarget};

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

    /// The image set this build pins could not be acquired and verified.
    #[error("{0:#}")]
    ImageSet(anyhow::Error),

    /// The verified image set could not deliver the initramfs: it declares no
    /// member for the arch, or the bytes served are not the ones it declares.
    /// Boxed so the rare refusal does not widen every `Result` here.
    #[error(transparent)]
    ImageSetMember(Box<ImageSetMemberError>),

    /// No usable initramfs from the pinned image set is installed, or the one
    /// delivered carries a `VERSION` that cannot name a cache entry.
    #[error(transparent)]
    ImageSetCache(#[from] SetMemberCacheError),

    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ImageSetMemberError> for InitramfsBuildError {
    fn from(error: ImageSetMemberError) -> Self {
        Self::ImageSetMember(Box::new(error))
    }
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
            install_initramfs_into_cache(&source_dir, cache_root, version, arch).map(|_| ())
        },
    )
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
/// is unavailable. A cold contributor cache falls back to the deterministic
/// Cargo build on every host; release distributions use the published
/// download.
///
/// The build is not host-gated. It cross-compiles the guest agent with
/// `cargo zigbuild` to the arch's musl triple and packs it into a
/// deterministic cpio — the same portable path the runtime overlay already
/// takes on macOS. Gating it to Linux left the macOS contributor with the
/// download as its only arm; when the release carried no initramfs for the
/// arch, the absence was negative-cached for a day and every launch on that
/// host booted with no initramfs at all.
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
        return resolve_or_download_image_set_initramfs(arch, cache_root);
    }

    // A source checkout builds; only a checkout-less source build falls back to
    // the published artifact. Reporting both failures matters: the download arm
    // fails whenever the locked image set carries no initramfs for this arch,
    // and on its own that reads as "unavailable" rather than "your checkout did
    // not build".
    if crate::guest_agent_build::detect_source_workspace().is_some()
        && let Some(message) = mvm_core::cold_build::refusal("the universal initramfs")
    {
        return Err(InitramfsBuildError::CargoBuildFailed { reason: message });
    }
    let build_err = match build_initramfs_with_cargo(cache_root, version, arch) {
        Ok(artifact) => return Ok(artifact),
        Err(e) => e,
    };
    match resolve_or_download_image_set_initramfs(arch, cache_root) {
        Ok(artifact) => Ok(artifact),
        Err(download_err) => Err(InitramfsBuildError::CargoBuildFailed {
            reason: format!(
                "building the universal initramfs {version} from this checkout failed \
                 ({build_err}), and acquiring the pinned image set's initramfs for {arch} also \
                 failed ({download_err})"
            ),
        }),
    }
}

/// Build the universal initramfs as a deterministic cargo artifact and
/// install it into the cache.
///
/// The initramfs is a tiny artifact — one static binary in a deterministic
/// cpio — so its attestability comes from the reproducible cargo build plus
/// the content hash, not from Nix: the pinned agent source is
/// cross-compiled once by the shared guest-binary builder (`cargo
/// zigbuild` → the arch's musl triple, content-keyed cache, reused as-is),
/// then packed as exactly `/init` (mode 0755) in an epoch-zero,
/// stably-ordered newc cpio, gzipped without name/timestamp. Same source +
/// same toolchain ⇒ the same `initramfs.hash`. Nix remains the build for
/// kernels, images, and overlays, where toolchain variance matters; the
/// flake's initramfs package stays as the optional publish-path build of
/// the same artifact.
fn build_initramfs_with_cargo(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let workspace = crate::guest_agent_build::detect_source_workspace().ok_or_else(|| {
        InitramfsBuildError::CargoBuildFailed {
            reason: "no source checkout detected to build the guest agent from".into(),
        }
    })?;
    let cache_key = crate::guest_agent_build::source_cache_key(&workspace).map_err(|e| {
        InitramfsBuildError::CargoBuildFailed {
            reason: format!("fingerprint guest sources: {e}"),
        }
    })?;
    let phase = mvm_vmm::host::ui::activity::start(format!(
        "Building the {arch} universal initramfs from local sources"
    ));
    let binaries = crate::guest_agent_build::resolve_or_build_guest_binaries(
        cache_root, &cache_key, arch, &workspace,
    )
    .map_err(|e| InitramfsBuildError::CargoBuildFailed {
        reason: format!("build the static guest agent: {e}"),
    })?;
    let agent_bytes = std::fs::read(&binaries.agent)?;

    let staging = tempfile::tempdir()?;
    assemble_initramfs_artifact(&agent_bytes, version, staging.path())?;
    let installed = install_initramfs_into_cache(staging.path(), cache_root, version, arch)?;
    phase.finish();
    Ok(installed)
}

/// Write the four artifact files (image + sidecars) for `agent_bytes` into
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

/// Lowercase-hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

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

/// A locked set without an initramfs is re-checked daily, so a contributor who
/// moves the lock to a set carrying one sees it without making every
/// invocation pay for fetching the root.
const RELEASE_NOT_FOUND_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

const RELEASE_NOT_FOUND_CACHE_DIR: &str = ".release-not-found";

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

fn release_not_found_marker(cache_root: &Path, root: &str, arch: GuestArch) -> PathBuf {
    cache_root
        .join(RELEASE_NOT_FOUND_CACHE_DIR)
        .join(root)
        .join(arch.to_string())
}

fn record_release_not_found(
    cache_root: &Path,
    root: &str,
    arch: GuestArch,
    observed_at: u64,
) -> Result<(), InitramfsBuildError> {
    let marker = release_not_found_marker(cache_root, root, arch);
    mvm_core::util::atomic_io::atomic_write_str(&marker, &observed_at.to_string())
        .map_err(std::io::Error::other)?;
    Ok(())
}

fn release_not_found_is_fresh(cache_root: &Path, root: &str, arch: GuestArch, now: u64) -> bool {
    let marker = release_not_found_marker(cache_root, root, arch);
    let Some(observed_at) = std::fs::read_to_string(marker)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return false;
    };
    now.saturating_sub(observed_at) < RELEASE_NOT_FOUND_TTL.as_secs()
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn not_in_image_set_error(arch: GuestArch) -> InitramfsBuildError {
    InitramfsBuildError::from(ImageSetMemberError::NoMember {
        release_tag: mvm_core::image_set::image_train_lock()
            .image_set
            .release_tag
            .clone(),
        role: ImageSetRole::Initramfs,
        target: MemberTarget::Arch(arch),
    })
}

/// Whether `error` says the locked set carries no initramfs for the arch. The
/// root is pinned, so the answer holds until the lock moves — unlike a
/// transport failure, which is worth retrying on the next invocation.
fn is_absent_from_image_set(error: &InitramfsBuildError) -> bool {
    matches!(
        error,
        InitramfsBuildError::ImageSetMember(member)
            if matches!(**member, ImageSetMemberError::NoMember { .. })
    )
}

fn with_release_negative_cache<T>(
    cache_root: &Path,
    root: &str,
    arch: GuestArch,
    now: u64,
    attempt: impl FnOnce() -> Result<T, InitramfsBuildError>,
) -> Result<T, InitramfsBuildError> {
    if release_not_found_is_fresh(cache_root, root, arch, now) {
        return Err(not_in_image_set_error(arch));
    }

    match attempt() {
        Ok(value) => {
            let marker = release_not_found_marker(cache_root, root, arch);
            if let Err(error) = std::fs::remove_file(&marker)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::debug!(
                    path = %marker.display(),
                    %error,
                    "failed to clear initramfs release negative-cache marker"
                );
            }
            Ok(value)
        }
        Err(error) if is_absent_from_image_set(&error) => {
            if let Err(marker_error) = record_release_not_found(cache_root, root, arch, now) {
                tracing::debug!(
                    %marker_error,
                    "failed to persist initramfs release negative-cache marker"
                );
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// The pinned image set's initramfs for `arch`: from the cache when it is
/// installed there, otherwise acquired and installed.
///
/// A locked set that declares no initramfs for the arch is remembered per
/// root, so the absence is re-checked daily rather than on every launch, and
/// moving the lock to another root asks again at once.
fn resolve_or_download_image_set_initramfs(
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let set = SetMemberCache::locked();
    if let Ok(artifact) = resolve_image_set_initramfs(cache_root, &set, arch) {
        return Ok(artifact);
    }
    with_release_negative_cache(
        cache_root,
        set.root().as_str(),
        arch,
        current_unix_seconds(),
        || download_initramfs(arch, cache_root),
    )
}

/// Resolve `arch`'s initramfs installed from the image set `set`, a pure
/// cache read.
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
        ImageSetRole::Initramfs,
        MemberTarget::Arch(arch),
    )?;
    Ok(
        InitramfsResolver::new(set.cache_root(cache_root), version.as_str())
            .resolve(&arch.to_string())?,
    )
}

/// Download the initramfs tarball for `arch` as a member of the image set
/// this build pins, safely extract it, re-verify each inner artifact, and
/// install it as a member of that set (see [`download_initramfs_from`]).
///
/// The archive is trusted only through the set: the root manifest is held to
/// its locked digest and its publisher's signature, and the archive to the
/// size and digest that root declares, all before extraction.
pub fn download_initramfs(
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let image_set = PublishedImageSet::acquire().map_err(InitramfsBuildError::ImageSet)?;
    download_initramfs_from(&image_set, arch, cache_root)
}

/// [`download_initramfs`] from a set that has already been acquired.
///
/// The member is filed under the set's root — at
/// `<cache_root>/image-set/<root>/<member-version>/<arch>/`, still beneath the
/// initramfs cache root every boot path recognises — and labelled with its own
/// `VERSION`. The install is recorded only once the artifact is in place, so
/// an interrupted one reads as a miss and is acquired again.
pub fn download_initramfs_from(
    image_set: &PublishedImageSet,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let names = InitramfsArtifactNames::for_arch(&arch.to_string());
    let tmp = tempfile::tempdir()?;
    let stage = tmp.path();
    let archive_local = stage.join(&names.archive);
    image_set.fetch_member_artifact(
        ImageSetRole::Initramfs,
        arch,
        &names.archive,
        &archive_local,
    )?;
    extract_initramfs_archive(&archive_local, stage)?;

    let set = image_set.member_cache();
    let version = MemberVersion::read(&stage.join(mvm_fs::initramfs::VERSION_FILE))?;
    let artifact =
        install_initramfs_into_cache(stage, &set.cache_root(cache_root), version.as_str(), arch)?;
    set.record(
        cache_root,
        ImageSetRole::Initramfs,
        MemberTarget::Arch(arch),
        &version,
    )?;
    Ok(artifact)
}

fn extract_initramfs_archive(archive_path: &Path, stage: &Path) -> Result<(), InitramfsBuildError> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = std::collections::BTreeSet::new();

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
                let dest = stage.join(name);
                let mut out = std::fs::File::create(&dest)?;
                std::io::copy(&mut entry, &mut out)?;
                set_cache_perms(&dest)?;
                seen.insert(name.to_string());
            }
            tar::EntryType::Directory => {}
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

    for required in [
        mvm_fs::initramfs::INITRAMFS_IMAGE_FILE,
        mvm_fs::initramfs::INITRAMFS_HASH_FILE,
        mvm_fs::initramfs::INITRAMFS_SIZE_FILE,
        mvm_fs::initramfs::VERSION_FILE,
        mvm_fs::initramfs::CHECKSUM_MANIFEST_FILE,
    ] {
        if !seen.contains(required) && !stage.join(required).is_file() {
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
    use crate::published_image_set::fixture::ImageSetFixture;
    use mvm_core::util::test_env::TestEnv;
    use std::cell::Cell;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn absent(arch: GuestArch) -> InitramfsBuildError {
        not_in_image_set_error(arch)
    }

    #[test]
    fn an_absent_member_is_attempted_once_within_the_negative_cache_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let attempts = Cell::new(0);
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;

        let first = with_release_negative_cache(tmp.path(), version, arch, 1_000, || {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(absent(arch))
        })
        .unwrap_err();
        let second = with_release_negative_cache(tmp.path(), version, arch, 1_001, || {
            attempts.set(attempts.get() + 1);
            Ok(())
        })
        .unwrap_err();

        assert_eq!(attempts.get(), 1);
        assert!(is_absent_from_image_set(&first));
        assert!(is_absent_from_image_set(&second));
        assert!(
            second.to_string().contains("initramfs/aarch64"),
            "a cached refusal must still name the role and arch: {second}"
        );
    }

    #[test]
    fn an_expired_marker_retries_and_refreshes_only_an_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let attempted = Cell::new(false);
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;
        record_release_not_found(tmp.path(), version, arch, 1_000).unwrap();
        let retry_at = 1_000 + RELEASE_NOT_FOUND_TTL.as_secs();

        let error = with_release_negative_cache(tmp.path(), version, arch, retry_at, || {
            attempted.set(true);
            Err::<(), _>(absent(arch))
        })
        .unwrap_err();

        assert!(attempted.get());
        assert!(is_absent_from_image_set(&error));
        let marker = release_not_found_marker(tmp.path(), version, arch);
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            retry_at.to_string()
        );
    }

    /// A transport failure or a refused root says nothing about what the
    /// locked set carries, so it is retried on the next invocation.
    #[test]
    fn a_transient_failure_is_not_negative_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;

        let error = with_release_negative_cache(tmp.path(), version, arch, 1_000, || {
            Err::<(), _>(InitramfsBuildError::ImageSet(anyhow::anyhow!("timeout")))
        })
        .unwrap_err();

        assert!(matches!(error, InitramfsBuildError::ImageSet(_)));
        assert!(!release_not_found_marker(tmp.path(), version, arch).exists());
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

    /// Acquire `fixture` as the verified set. A fixture carries no publisher
    /// signature; that rung has its own witnesses in
    /// `crate::published_image_set`.
    fn acquire(fixture: &ImageSetFixture, served: &Path, env: &mut TestEnv) -> PublishedImageSet {
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        PublishedImageSet::acquire_from(fixture.serve_from(served))
            .expect("the fixture root must be accepted")
    }

    fn with_initramfs(declared: Vec<u8>) -> ImageSetFixture {
        ImageSetFixture::complete().publish(
            mvm_core::image_set::ImageSetRole::Initramfs,
            mvm_core::image_set::MemberTarget::Arch(GuestArch::Aarch64),
            "initramfs-aarch64.tar.gz",
            declared,
        )
    }

    #[test]
    fn download_initramfs_installs_the_member_the_signed_root_names() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;
        let set = acquire(
            &with_initramfs(served_initramfs_archive(version)),
            &tmp.path().join("served"),
            &mut env,
        );

        let artifact = download_initramfs_from(&set, arch, &cache_root).unwrap();

        let expected_dir = set
            .member_cache()
            .cache_root(&cache_root)
            .join(version)
            .join(arch.to_string());
        assert_eq!(artifact.image_path, expected_dir.join("initramfs.cpio.gz"));
        assert!(expected_dir.join("initramfs.hash").is_file());
        assert!(expected_dir.join("initramfs.size").is_file());
        assert!(expected_dir.join("VERSION").is_file());
    }

    /// Bytes other than the ones the signed root declares are refused at the
    /// digest — the served archive differs only in its gzip trailer, so an
    /// extraction attempt would have failed differently — and nothing is
    /// installed.
    #[test]
    fn download_initramfs_refuses_bytes_the_root_does_not_declare() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        let archive = served_initramfs_archive("0.18.0");
        let mut tampered = archive.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let fixture = with_initramfs(archive).serve_instead("initramfs-aarch64.tar.gz", tampered);
        let set = acquire(&fixture, &tmp.path().join("served"), &mut env);

        let err = download_initramfs_from(&set, GuestArch::Aarch64, &cache_root)
            .expect_err("tampered archive must be refused");

        assert!(
            matches!(
                &err,
                InitramfsBuildError::ImageSetMember(member)
                    if matches!(**member, ImageSetMemberError::DigestMismatch { .. })
            ),
            "{err:?}"
        );
        assert!(!set.member_cache().cache_root(&cache_root).exists());
    }

    /// The initramfs is a required member, so a set that omits it for an
    /// architecture is refused when it is acquired, naming the member, and
    /// never reaches the download or the cache.
    #[test]
    fn a_set_without_an_initramfs_for_the_arch_is_refused_before_download() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        let fixture = with_initramfs(served_initramfs_archive("0.18.0")).without_member(
            mvm_core::image_set::ImageSetRole::Initramfs,
            mvm_core::image_set::MemberTarget::Arch(GuestArch::X86_64),
        );

        let err = PublishedImageSet::acquire_from(fixture.serve_from(&tmp.path().join("served")))
            .err()
            .expect("a set without the member must be refused");

        assert!(format!("{err:#}").contains("initramfs/x86_64"), "{err:#}");
        assert!(!cache_root.exists());
    }

    /// A member cut from a workspace at another version than this CLI's.
    const MEMBER_VERSION: &str = "0.0.1-member";

    /// The set's identity is its signed root, so an initramfs whose `VERSION`
    /// is not this CLI's installs, lands beneath the initramfs cache root every
    /// boot path recognises, and resolves from the cache on the next boot
    /// without the set being served.
    #[test]
    fn a_set_initramfs_at_another_version_installs_and_resolves_from_cache() {
        assert_ne!(MEMBER_VERSION, env!("CARGO_PKG_VERSION"));
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let served = tmp.path().join("served");
        let set = acquire(
            &with_initramfs(served_initramfs_archive(MEMBER_VERSION)),
            &served,
            &mut env,
        );

        let installed = download_initramfs_from(&set, GuestArch::Aarch64, &cache_root)
            .expect("a member at another version must install");
        assert_eq!(installed.version, MEMBER_VERSION);
        assert!(installed.image_path.starts_with(&cache_root));

        std::fs::remove_dir_all(&served).unwrap();
        let resolved =
            resolve_image_set_initramfs(&cache_root, &set.member_cache(), GuestArch::Aarch64)
                .expect("the installed member must resolve from the cache");
        assert_eq!(resolved, installed);
    }

    /// An initramfs installed from one root is not a member of another: once
    /// the lock moves, it is acquired again rather than reused.
    #[test]
    fn a_set_initramfs_from_another_root_is_not_reused() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let set = acquire(
            &with_initramfs(served_initramfs_archive(MEMBER_VERSION)),
            &tmp.path().join("served"),
            &mut env,
        );
        download_initramfs_from(&set, GuestArch::Aarch64, &cache_root).unwrap();

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

    /// A release host's boot finds the pinned set's initramfs in the cache and
    /// never reaches for the transport, which here points nowhere.
    #[test]
    fn the_pinned_sets_cached_initramfs_resolves_without_the_network() {
        let mut env = TestEnv::new();
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            "file:///nonexistent/mvm-initramfs-fixture",
        );
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache").join("initramfs");
        let set = SetMemberCache::locked();
        write_initramfs_artifact(&source, MEMBER_VERSION, b"cpio-payload");
        install_initramfs_into_cache(
            &source,
            &set.cache_root(&cache_root),
            MEMBER_VERSION,
            GuestArch::Aarch64,
        )
        .unwrap();
        set.record(
            &cache_root,
            ImageSetRole::Initramfs,
            MemberTarget::Arch(GuestArch::Aarch64),
            &MemberVersion::parse(MEMBER_VERSION).unwrap(),
        )
        .unwrap();

        let artifact = resolve_or_download_image_set_initramfs(GuestArch::Aarch64, &cache_root)
            .expect("the cached member must resolve without the network");
        assert_eq!(artifact.version, MEMBER_VERSION);
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
        let checksums = format!(
            "{}  initramfs.cpio.gz
{}  initramfs.hash
{}  initramfs.size
{}  VERSION
",
            sha256_hex(image_bytes),
            sha256_hex(hash_bytes),
            sha256_hex(size_bytes),
            sha256_hex(version_bytes),
        );
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        append_archive_file(&mut tar, "initramfs.cpio.gz", image_bytes);
        append_archive_file(&mut tar, "initramfs.hash", hash_bytes);
        append_archive_file(&mut tar, "initramfs.size", size_bytes);
        append_archive_file(&mut tar, "VERSION", version_bytes);
        append_archive_file(&mut tar, "checksums-sha256.txt", checksums.as_bytes());
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
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
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let image = encoder.finish().unwrap();
        let hash = sha256_hex(payload);
        let size = image.len().to_string();
        (image, hash, size)
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

    fn append_archive_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
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

        let artifact =
            resolve_or_seed_from_default_cache(&isolated_cache, "0.18.0", GuestArch::Aarch64)
                .unwrap();

        let expected_dir = isolated_cache
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        assert_eq!(artifact.image_path, expected_dir.join("initramfs.cpio.gz"));
        assert!(expected_dir.join("initramfs.hash").is_file());
        assert!(expected_dir.join("initramfs.size").is_file());
        assert!(expected_dir.join("VERSION").is_file());
    }
}
