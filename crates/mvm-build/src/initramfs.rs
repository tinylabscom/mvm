//! Build and resolve the universal initramfs artifact.
//!
//! The initramfs is built by `nix/images/initramfs/flake.nix` and cached at
//! `<cache_root>/<version>/<arch>/`. This module mirrors the runtime-overlay
//! orchestration but is intentionally smaller because the artifact has no
//! verity sidecar and no per-rootfs variation.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_fs::initramfs::{InitramfsArtifact, InitramfsResolver};
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
/// `#[cfg(target_os = "linux")]` and requires the project builder VM (or a
/// native Linux host with Nix); on macOS callers should rely on a seeded cache.
pub fn resolve_or_build_local_initramfs(
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
        build_initramfs_with_nix(cache_root, version, arch)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(InitramfsBuildError::HostUnsupported {
            operation: "nix build",
            reason: "universal initramfs build requires Linux; seed the cache from a Linux build",
        })
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
    let status = std::process::Command::new("nix")
        .args([
            "build",
            "--extra-experimental-features",
            "nix-command flakes",
            "--impure",
            "--out-link",
            &out_link.display().to_string(),
            &flake_ref,
        ])
        .env("MVM_WORKSPACE_PATH", &workspace_root)
        .status()
        .map_err(|e| InitramfsBuildError::NixBuildFailed {
            reason: format!("failed to spawn nix build: {e}"),
        })?;

    if !status.success() {
        return Err(InitramfsBuildError::NixBuildFailed {
            reason: format!("nix build exited with status {status}"),
        });
    }

    install_initramfs_into_cache(&out_link, cache_root, version, arch)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_returns_missing_when_cache_empty() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            resolve_or_build_local_initramfs(dir.path(), "0.18.0", GuestArch::Aarch64).unwrap_err();
        assert!(!format!("{err}").is_empty());
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
        let default_mvm = home.join(".mvm").join("cache").join("initramfs");
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
