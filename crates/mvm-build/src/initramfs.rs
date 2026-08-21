//! Build and resolve the universal initramfs artifact.
//!
//! The initramfs is a tiny deterministic **cargo artifact** — one static
//! `mvm-guest-agent` binary packed as `/init` in an epoch-zero newc cpio —
//! built locally by [`build_initramfs_with_cargo`] on Linux and cached at
//! `<cache_root>/<version>/<arch>/`. Its attestability comes from the
//! reproducible cargo build of the pinned agent source plus the content
//! hash, not from Nix. Nix remains the build for kernels, images, and
//! overlays, where toolchain variance matters; `nix/images/initramfs`
//! stays as the optional publish-path build of the same artifact. This
//! module mirrors the runtime-overlay orchestration but is intentionally
//! smaller because the artifact has no verity sidecar and no per-rootfs
//! variation.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::build_env::ShellEnvironment;
use mvm_fs::initramfs::{InitramfsArtifact, InitramfsResolver};
use mvm_fs::parallel::par_map;
use std::collections::HashMap;
use thiserror::Error;

/// Failure modes for universal initramfs resolution/build.
#[derive(Debug, Error)]
pub enum InitramfsBuildError {
    /// Cache resolution failed.
    #[error(transparent)]
    Resolve(#[from] mvm_fs::initramfs::InitramfsError),

    /// The requested operation is not supported on this host.
    #[error("host does not support {operation}: {reason}")]
    HostUnsupported {
        operation: &'static str,
        reason: &'static str,
    },

    /// The deterministic cargo build failed (agent cross-compile or the
    /// cpio assembly).
    #[error("cargo initramfs build failed: {reason}")]
    CargoBuildFailed { reason: String },

    /// A downloaded artifact's sha256 didn't match the pre-committed entry.
    #[error("checksum mismatch for {name}: expected sha256 {expected}, computed {actual}")]
    ChecksumMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    /// The fetched checksum manifest lacked an entry for a required file.
    #[error("checksum manifest at {checksums_url} did not list an entry for {name}")]
    ChecksumMissing { name: String, checksums_url: String },

    /// The downloaded initramfs archive was malformed or unsafe to extract.
    #[error("initramfs archive invalid at {archive_path:?}: {reason}")]
    InvalidArchive {
        archive_path: PathBuf,
        reason: String,
    },

    /// `curl` failed to download the artifact.
    #[error("download failed for {url}: {reason}")]
    DownloadFailed { url: String, reason: String },

    /// The release server confirmed that the requested artifact does not exist.
    #[error("download returned HTTP 404 for {url}")]
    DownloadNotFound { url: String },

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

/// Resolve a cached universal initramfs, or return an error describing why it
/// is unavailable. A cold contributor cache on Linux falls back to the
/// deterministic Cargo build; release distributions and non-Linux hosts use
/// the published download.
pub fn resolve_or_build_local_initramfs(
    _env: &dyn ShellEnvironment,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    match resolve_or_seed_from_default_cache(cache_root, version, arch) {
        Ok(artifact) => return Ok(artifact),
        Err(InitramfsBuildError::Resolve(mvm_fs::initramfs::InitramfsError::Missing(_))) => {
            // Fall through to build attempt.
        }
        Err(e) => return Err(e),
    }

    #[cfg(target_os = "linux")]
    if crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        build_initramfs_with_cargo(cache_root, version, arch)
    } else {
        download_initramfs_with_negative_cache(version, arch, cache_root)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS / non-Linux hosts cannot run the cargo cross-compile for a
        // Linux initramfs here. Try to download a published release artifact
        // into the cache before giving up. This mirrors the runtime-overlay
        // download path.
        match download_initramfs_with_negative_cache(version, arch, cache_root) {
            Ok(artifact) => Ok(artifact),
            Err(download_err) => {
                tracing::debug!(
                    error = %download_err,
                    "initramfs download fallback unavailable"
                );
                Err(InitramfsBuildError::HostUnsupported {
                    operation: "cargo initramfs build",
                    reason: "universal initramfs build requires Linux and no published artifact was available; seed the cache from a Linux build",
                })
            }
        }
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
#[cfg(target_os = "linux")]
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
    let binaries = crate::guest_agent_build::resolve_or_build_guest_binaries(
        cache_root, &cache_key, arch, &workspace,
    )
    .map_err(|e| InitramfsBuildError::CargoBuildFailed {
        reason: format!("build the static guest agent: {e}"),
    })?;
    let agent_bytes = std::fs::read(&binaries.agent)?;

    let staging = tempfile::tempdir()?;
    assemble_initramfs_artifact(&agent_bytes, version, staging.path())?;
    install_initramfs_into_cache(staging.path(), cache_root, version, arch)
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

/// Default GitHub Releases base URL for the initramfs artifact. Override via
/// `MVM_INITRAMFS_BASE_URL` for hermetic tests or a private mirror — same
/// pattern as the runtime overlay downloader.
const DEFAULT_RELEASE_BASE: &str = "https://github.com/tinylabscom/mvm/releases/download";

/// A confirmed release-artifact 404 is retried daily so a late release upload
/// becomes visible without making every invocation pay the network cost.
const RELEASE_NOT_FOUND_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

const RELEASE_NOT_FOUND_CACHE_DIR: &str = ".release-not-found";

/// Documented escape hatch to bypass SHA-256 integrity checks. Mirrors the
/// runtime-overlay and dev-image downloaders.
pub(crate) const SKIP_HASH_VERIFY_ENV: &str = "MVM_SKIP_HASH_VERIFY";

/// Release-side artifact names for one arch. Pure data so the download path
/// and the release pipeline can agree on filenames without touching network
/// code in the release job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitramfsArtifactNames {
    /// The per-arch release tarball name.
    pub archive: String,
    /// The tarball's sha256 checksum sidecar name.
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

/// Construct the per-version release base URL.
pub fn release_base_url(version: &str) -> String {
    let base = std::env::var("MVM_INITRAMFS_BASE_URL")
        .unwrap_or_else(|_| DEFAULT_RELEASE_BASE.to_string());
    format!("{}/v{version}", base.trim_end_matches('/'))
}

fn release_not_found_marker(cache_root: &Path, version: &str, arch: GuestArch) -> PathBuf {
    cache_root
        .join(RELEASE_NOT_FOUND_CACHE_DIR)
        .join(version)
        .join(arch.to_string())
}

fn record_release_not_found(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    observed_at: u64,
) -> Result<(), InitramfsBuildError> {
    let marker = release_not_found_marker(cache_root, version, arch);
    mvm_core::util::atomic_io::atomic_write_str(&marker, &observed_at.to_string())
        .map_err(std::io::Error::other)?;
    Ok(())
}

fn release_not_found_is_fresh(cache_root: &Path, version: &str, arch: GuestArch, now: u64) -> bool {
    let marker = release_not_found_marker(cache_root, version, arch);
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

fn not_found_error(version: &str, arch: GuestArch) -> InitramfsBuildError {
    let names = InitramfsArtifactNames::for_arch(&arch.to_string());
    InitramfsBuildError::DownloadNotFound {
        url: format!("{}/{}", release_base_url(version), names.archive_checksum),
    }
}

fn with_release_negative_cache<T>(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    now: u64,
    uses_default_release: bool,
    attempt: impl FnOnce() -> Result<T, InitramfsBuildError>,
) -> Result<T, InitramfsBuildError> {
    if uses_default_release && release_not_found_is_fresh(cache_root, version, arch, now) {
        return Err(not_found_error(version, arch));
    }

    match attempt() {
        Ok(value) => {
            let marker = release_not_found_marker(cache_root, version, arch);
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
        Err(error @ InitramfsBuildError::DownloadNotFound { .. }) => {
            if uses_default_release
                && let Err(marker_error) = record_release_not_found(cache_root, version, arch, now)
            {
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

fn download_initramfs_with_negative_cache(
    version: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let uses_default_release = std::env::var_os("MVM_INITRAMFS_BASE_URL").is_none();
    with_release_negative_cache(
        cache_root,
        version,
        arch,
        current_unix_seconds(),
        uses_default_release,
        || download_initramfs(version, arch, cache_root),
    )
}

/// Download the published initramfs tarball for `version` + `arch` from the
/// GitHub Release (or mirror), verify the archive checksum, safely extract it,
/// re-verify each inner artifact, and install into `cache_root` under the
/// canonical layout.
pub fn download_initramfs(
    version: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let names = InitramfsArtifactNames::for_arch(&arch.to_string());
    let base = release_base_url(version);
    let archive_checksum_url = format!("{base}/{}", names.archive_checksum);

    let expected = fetch_expected_hashes(&archive_checksum_url, &[&names.archive])?;

    let tmp = tempfile::tempdir()?;
    let stage = tmp.path();
    let archive_local = stage.join(&names.archive);
    curl_download(&format!("{base}/{}", names.archive), &archive_local)?;
    verify_file_sha256(&archive_local, &names.archive, expected.get(&names.archive))?;
    extract_initramfs_archive(&archive_local, stage)?;

    install_initramfs_into_cache(stage, cache_root, version, arch)
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

fn fetch_expected_hashes(
    checksums_url: &str,
    wanted: &[&str],
) -> Result<HashMap<String, String>, InitramfsBuildError> {
    let tmp = tempfile::NamedTempFile::new()?;
    curl_download(checksums_url, tmp.path())?;
    let body = std::fs::read_to_string(tmp.path())?;
    let map = mvm_fs::overlay::parse_checksums_manifest(&body);

    for w in wanted {
        if !map.contains_key(*w) {
            return Err(InitramfsBuildError::ChecksumMissing {
                name: (*w).to_string(),
                checksums_url: checksums_url.to_string(),
            });
        }
    }
    Ok(map)
}

fn verify_file_sha256(
    path: &Path,
    name: &str,
    expected: Option<&String>,
) -> Result<(), InitramfsBuildError> {
    if std::env::var_os(SKIP_HASH_VERIFY_ENV).is_some() {
        tracing::warn!("{SKIP_HASH_VERIFY_ENV} set — skipping integrity check on {name}.");
        return Ok(());
    }
    let Some(expected) = expected else {
        return Err(InitramfsBuildError::ChecksumMissing {
            name: name.to_string(),
            checksums_url: "(internal: missing expected hash)".to_string(),
        });
    };
    let actual = mvm_fs::overlay::compute_file_sha256(path)?;
    if actual != *expected {
        let _ = std::fs::remove_file(path);
        return Err(InitramfsBuildError::ChecksumMismatch {
            name: name.to_string(),
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

fn curl_download(url: &str, dest: &Path) -> Result<(), InitramfsBuildError> {
    let output = std::process::Command::new("curl")
        .args([
            "-fSL",
            "--silent",
            "--show-error",
            "--write-out",
            "%{http_code}",
            "-o",
        ])
        .arg(dest)
        .arg(url)
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let _ = std::fs::remove_file(dest);
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            let http_status = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u16>()
                .ok();
            Err(curl_failure(url, http_status, out.status.code(), &stderr))
        }
        Err(e) => {
            let _ = std::fs::remove_file(dest);
            Err(InitramfsBuildError::DownloadFailed {
                url: url.to_string(),
                reason: format!("spawn curl failed: {e}"),
            })
        }
    }
}

fn curl_failure(
    url: &str,
    http_status: Option<u16>,
    exit_code: Option<i32>,
    stderr: &str,
) -> InitramfsBuildError {
    if http_status == Some(404) {
        return InitramfsBuildError::DownloadNotFound {
            url: url.to_string(),
        };
    }
    let code = exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "signal".to_string());
    InitramfsBuildError::DownloadFailed {
        url: url.to_string(),
        reason: format!("curl exited {code}; stderr={stderr}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use std::cell::Cell;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn confirmed_404_is_attempted_once_within_the_negative_cache_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let attempts = Cell::new(0);
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;

        let first = with_release_negative_cache(tmp.path(), version, arch, 1_000, true, || {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(InitramfsBuildError::DownloadNotFound {
                url: "https://example.invalid/missing".to_string(),
            })
        })
        .unwrap_err();
        let second = with_release_negative_cache(tmp.path(), version, arch, 1_001, true, || {
            attempts.set(attempts.get() + 1);
            Ok(())
        })
        .unwrap_err();

        assert_eq!(attempts.get(), 1);
        assert!(matches!(
            first,
            InitramfsBuildError::DownloadNotFound { .. }
        ));
        assert!(matches!(
            second,
            InitramfsBuildError::DownloadNotFound { .. }
        ));
    }

    #[test]
    fn expired_release_not_found_marker_retries_and_refreshes_only_a_404() {
        let tmp = tempfile::tempdir().unwrap();
        let attempted = Cell::new(false);
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;
        record_release_not_found(tmp.path(), version, arch, 1_000).unwrap();
        let retry_at = 1_000 + RELEASE_NOT_FOUND_TTL.as_secs();

        let error = with_release_negative_cache(tmp.path(), version, arch, retry_at, true, || {
            attempted.set(true);
            Err::<(), _>(InitramfsBuildError::DownloadNotFound {
                url: "https://example.invalid/missing".to_string(),
            })
        })
        .unwrap_err();

        assert!(attempted.get());
        assert!(matches!(
            error,
            InitramfsBuildError::DownloadNotFound { .. }
        ));
        let marker = release_not_found_marker(tmp.path(), version, arch);
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            retry_at.to_string()
        );
    }

    #[test]
    fn transient_download_failure_is_not_negative_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;

        let error = with_release_negative_cache(tmp.path(), version, arch, 1_000, true, || {
            Err::<(), _>(InitramfsBuildError::DownloadFailed {
                url: "https://example.invalid/unreachable".to_string(),
                reason: "timeout".to_string(),
            })
        })
        .unwrap_err();

        assert!(matches!(error, InitramfsBuildError::DownloadFailed { .. }));
        assert!(!release_not_found_marker(tmp.path(), version, arch).exists());
    }

    #[test]
    fn configured_mirror_bypasses_default_release_negative_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let attempted = Cell::new(false);
        let version = "0.18.0";
        let arch = GuestArch::Aarch64;
        record_release_not_found(tmp.path(), version, arch, 1_000).unwrap();

        with_release_negative_cache(tmp.path(), version, arch, 1_001, false, || {
            attempted.set(true);
            Ok(())
        })
        .unwrap();

        assert!(attempted.get());
        assert!(!release_not_found_marker(tmp.path(), version, arch).exists());
    }

    #[test]
    fn curl_404_is_distinct_from_transient_http_failure() {
        let missing = curl_failure(
            "https://example.invalid/missing",
            Some(404),
            Some(22),
            "not found",
        );
        let unavailable = curl_failure(
            "https://example.invalid/unavailable",
            Some(503),
            Some(22),
            "unavailable",
        );

        assert!(matches!(
            missing,
            InitramfsBuildError::DownloadNotFound { .. }
        ));
        assert!(matches!(
            unavailable,
            InitramfsBuildError::DownloadFailed { .. }
        ));
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

    #[test]
    fn download_initramfs_installs_published_artifact_into_cache() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache").join("initramfs");
        let release_root = tmp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();

        let version = "0.18.0";
        let arch = GuestArch::Aarch64;
        seed_release_fixture(&release_root, version, arch);
        env.set(
            "MVM_INITRAMFS_BASE_URL",
            format!("file://{}", release_root.display()),
        );

        let artifact = download_initramfs(version, arch, &cache_root).unwrap();

        let expected_dir = cache_root.join(version).join(arch.to_string());
        assert_eq!(artifact.image_path, expected_dir.join("initramfs.cpio.gz"));
        assert!(expected_dir.join("initramfs.hash").is_file());
        assert!(expected_dir.join("initramfs.size").is_file());
        assert!(expected_dir.join("VERSION").is_file());
    }

    fn seed_release_fixture(base: &std::path::Path, version: &str, arch: GuestArch) {
        let release_dir = base.join(format!("v{version}"));
        std::fs::create_dir_all(&release_dir).unwrap();

        let names = InitramfsArtifactNames::for_arch(&arch.to_string());
        let (image_bytes, hash, size) = initramfs_fixture(b"downloaded-cpio-payload");
        let hash_text = format!(
            "{hash}
"
        );
        let size_text = format!(
            "{size}
"
        );
        let version_text = format!(
            "{version}
"
        );
        let archive_bytes = initramfs_archive_bytes(
            &image_bytes,
            hash_text.as_bytes(),
            size_text.as_bytes(),
            version_text.as_bytes(),
        );
        std::fs::write(release_dir.join(&names.archive), &archive_bytes).unwrap();
        std::fs::write(
            release_dir.join(&names.archive_checksum),
            format!(
                "{}  {}
",
                mvm_fs::overlay::compute_file_sha256(&release_dir.join(&names.archive)).unwrap(),
                names.archive
            ),
        )
        .unwrap();
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
