//! Build and resolve the universal initramfs artifact.
//!
//! The initramfs is built by `nix/images/initramfs/flake.nix` and cached at
//! `<cache_root>/<version>/<arch>/`. This module mirrors the runtime-overlay
//! orchestration but is intentionally smaller because the artifact has no
//! verity sidecar and no per-rootfs variation.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::build_env::ShellEnvironment;
use mvm_fs::initramfs::{InitramfsArtifact, InitramfsResolver};
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

    /// `nix build` failed.
    #[error("nix build failed: {reason}")]
    NixBuildFailed { reason: String },

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

    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve a cached universal initramfs. On a miss with a non-default cache
/// root (e.g. a worktree-isolated `MVM_HOME`), seed that cache by installing
/// the default cache's artifact and retry once. A default-cache miss surfaces
/// the original resolve error unchanged. This is still a pure cache operation —
/// no build, no download.
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
    let default_cache_root =
        PathBuf::from(mvm_core::config::default_mvm_cache_dir()).join("initramfs");
    if cache_root == default_cache_root {
        return Ok(false);
    }

    let source = InitramfsResolver::new(default_cache_root, version).resolve(&arch.to_string());
    let Ok(source) = source else {
        return Ok(false);
    };

    let source_dir = source.image_path.parent().ok_or_else(|| {
        InitramfsBuildError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "resolved initramfs image has no parent directory",
        ))
    })?;

    install_initramfs_into_cache(source_dir, cache_root, version, arch)?;
    Ok(true)
}

/// Resolve a cached universal initramfs, or return an error describing why it
/// is unavailable. A full `nix build` fallback is intentionally gated behind
/// `#[cfg(target_os = "linux")]` and runs through the supplied
/// `ShellEnvironment` so it executes on the current Linux execution boundary
/// (the builder VM on macOS, the native host on Linux).
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
    {
        build_initramfs_with_nix(_env, cache_root, version, arch)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS / non-Linux hosts cannot run `nix build` for a Linux initramfs.
        // Try to download a published release artifact into the cache before
        // giving up. This mirrors the runtime-overlay download path.
        match download_initramfs(version, arch, cache_root) {
            Ok(artifact) => Ok(artifact),
            Err(download_err) => {
                tracing::debug!(
                    error = %download_err,
                    "initramfs download fallback unavailable"
                );
                Err(InitramfsBuildError::HostUnsupported {
                    operation: "nix build",
                    reason: "universal initramfs build requires Linux and no published artifact was available; seed the cache from a Linux build",
                })
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn initramfs_source_checkout_root() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    workspace_root
        .join("nix")
        .join("images")
        .join("initramfs")
        .join("flake.nix")
        .is_file()
        .then(|| workspace_root.to_path_buf())
}

/// Build the universal initramfs via `nix build` and install it into the cache.
#[cfg(target_os = "linux")]
fn build_initramfs_with_nix(
    env: &dyn ShellEnvironment,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<InitramfsArtifact, InitramfsBuildError> {
    let workspace_root =
        initramfs_source_checkout_root().ok_or_else(|| InitramfsBuildError::NixBuildFailed {
            reason: "cannot locate workspace root with nix/images/initramfs/flake.nix".into(),
        })?;
    let flake_ref = format!(
        "path:{}/nix/images/initramfs#packages.{}.initramfs",
        workspace_root.display(),
        nix_system_for_arch(arch),
    );

    let tmp = tempfile::tempdir()?;
    let out_link = tmp.path().join("result");
    let script = format!(
        "MVM_WORKSPACE_PATH={} nix build --extra-experimental-features 'nix-command flakes' --impure --out-link {} {}",
        shell_quote(&workspace_root.display().to_string()),
        shell_quote(&out_link.display().to_string()),
        shell_quote(&flake_ref),
    );

    if let Err(e) = env.shell_exec_capture(&script) {
        return Err(InitramfsBuildError::NixBuildFailed {
            reason: format!("nix build failed: {e}"),
        });
    }

    install_initramfs_into_cache(&out_link, cache_root, version, arch)
}

/// Quote a string for safe interpolation into a single-quoted POSIX shell word.
#[cfg(target_os = "linux")]
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(target_os = "linux")]
fn nix_system_for_arch(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "aarch64-linux",
        GuestArch::X86_64 => "x86_64-linux",
    }
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

    let staging = parent.join(staging_dir_name(&arch.to_string()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir(&staging)?;

    for file in [
        mvm_fs::initramfs::INITRAMFS_IMAGE_FILE,
        mvm_fs::initramfs::INITRAMFS_HASH_FILE,
        mvm_fs::initramfs::INITRAMFS_SIZE_FILE,
        mvm_fs::initramfs::VERSION_FILE,
    ] {
        std::fs::copy(source_dir.join(file), staging.join(file))?;
        set_cache_perms(&staging.join(file))?;
    }

    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir)?;
    }
    std::fs::rename(&staging, &target_dir)?;

    mvm_fs::initramfs::read_initramfs_artifact_from_dir(&target_dir).map_err(Into::into)
}

fn staging_dir_name(arch: &str) -> String {
    format!("{}.tmp.{}", arch, std::process::id())
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
        .args(["-fSL", "--silent", "--show-error", "-o"])
        .arg(dest)
        .arg(url)
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let _ = std::fs::remove_file(dest);
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            Err(InitramfsBuildError::DownloadFailed {
                url: url.to_string(),
                reason: format!("curl exited {code}; stderr={stderr}"),
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_returns_missing_when_cache_empty() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            resolve_or_build_local_initramfs(&NoopShell, dir.path(), "0.18.0", GuestArch::Aarch64)
                .unwrap_err();
        assert!(!format!("{err}").is_empty());
    }

    struct NoopShell;

    impl ShellEnvironment for NoopShell {
        fn shell_exec(&self, _script: &str) -> anyhow::Result<()> {
            Ok(())
        }

        fn shell_exec_stdout(&self, _script: &str) -> anyhow::Result<String> {
            Ok(String::new())
        }

        fn shell_exec_visible(&self, _script: &str) -> anyhow::Result<()> {
            Ok(())
        }

        fn log_info(&self, _msg: &str) {}

        fn log_success(&self, _msg: &str) {}
    }

    #[test]
    fn install_initramfs_into_cache_copies_files() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("initramfs.cpio.gz"), b"image").unwrap();
        std::fs::write(source.join("initramfs.hash"), b"hash").unwrap();
        std::fs::write(source.join("initramfs.size"), "5").unwrap();
        std::fs::write(source.join("VERSION"), "0.18.0").unwrap();

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
        let ext4_bytes = b"downloaded-cpio";
        let hash_text = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
";
        let size_text = b"15
";
        let version_text = format!(
            "{version}
"
        );
        let archive_bytes =
            initramfs_archive_bytes(ext4_bytes, hash_text, size_text, version_text.as_bytes());
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

    fn append_archive_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
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
        let default_mvm =
            PathBuf::from(mvm_core::config::default_mvm_cache_dir()).join("initramfs");
        let default_artifact_dir = default_mvm
            .join("0.18.0")
            .join(GuestArch::Aarch64.to_string());
        std::fs::create_dir_all(&default_artifact_dir).unwrap();
        std::fs::write(
            default_artifact_dir.join("initramfs.cpio.gz"),
            b"default-image",
        )
        .unwrap();
        std::fs::write(default_artifact_dir.join("initramfs.hash"), b"hash").unwrap();
        std::fs::write(default_artifact_dir.join("initramfs.size"), "13").unwrap();
        std::fs::write(default_artifact_dir.join("VERSION"), "0.18.0").unwrap();

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
