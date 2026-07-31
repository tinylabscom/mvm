//! Host-side resolution of the Apple Container boot artifacts.
//!
//! The Apple Container boot needs two artifacts that mvm does not build:
//! the container kernel (`vmlinux`, an arm64 Linux `Image`) and the
//! `initfs.ext4` initramfs that carries `/sbin/vminitd`. Both come from a
//! local build of Apple's `containerization` package (the initfs build
//! needs the Swift static Linux SDK) and are cached under
//! `<mvm-cache>/apple-container/`. Resolution is pure path probing: a
//! missing artifact is a typed
//! [`AppleContainerError::ArtifactMissing`] whose hint names the exact
//! build command, never an opaque I/O error.

use std::path::PathBuf;

use crate::apple_container_backend::AppleContainerError;

/// Cache subdirectory (under `mvm_cache_dir`) holding the artifacts.
pub const ARTIFACT_DIR_NAME: &str = "apple-container";
/// File name of the container kernel image inside the artifact dir.
pub const KERNEL_FILE_NAME: &str = "vmlinux";
/// File name of the vminitd initfs inside the artifact dir.
pub const INITFS_FILE_NAME: &str = "initfs.ext4";

/// Hint for a missing kernel artifact.
const KERNEL_HINT: &str = "build the container kernel from github.com/apple/containerization \
     (`make kernel`) or copy any compatible arm64 Linux Image here";
/// Hint for a missing initfs artifact.
const INITFS_HINT: &str = "build the vminitd initfs from github.com/apple/containerization \
     (`make init`, requires the Swift static Linux SDK) and copy the resulting initfs.ext4 here";

/// The two resolved boot artifacts, both confirmed to exist on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleContainerArtifacts {
    /// The container kernel (arm64 Linux `Image`).
    pub kernel: PathBuf,
    /// The initfs carrying `/sbin/vminitd`, booted as the root block device.
    pub initfs: PathBuf,
}

/// The cache directory the artifacts are resolved from.
pub fn artifact_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join(ARTIFACT_DIR_NAME)
}

/// Resolve both artifacts from the cache, failing closed with a typed
/// error naming the missing file and the build command that produces it.
pub fn resolve() -> Result<AppleContainerArtifacts, AppleContainerError> {
    resolve_from(&artifact_dir())
}

/// The filesystem-probing core of [`resolve`], split out so tests point it
/// at a tempdir instead of the real cache.
fn resolve_from(dir: &std::path::Path) -> Result<AppleContainerArtifacts, AppleContainerError> {
    let kernel = dir.join(KERNEL_FILE_NAME);
    if !kernel.is_file() {
        return Err(AppleContainerError::ArtifactMissing {
            what: "container kernel (arm64 Linux Image)",
            path: kernel.display().to_string(),
            hint: KERNEL_HINT,
        });
    }
    let initfs = dir.join(INITFS_FILE_NAME);
    if !initfs.is_file() {
        return Err(AppleContainerError::ArtifactMissing {
            what: "vminitd initfs (initfs.ext4)",
            path: initfs.display().to_string(),
            hint: INITFS_HINT,
        });
    }
    Ok(AppleContainerArtifacts { kernel, initfs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_kernel_is_typed_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_from(dir.path()).unwrap_err();
        let AppleContainerError::ArtifactMissing { what, path, hint } = &err else {
            panic!("expected ArtifactMissing, got {err:?}");
        };
        assert!(what.contains("kernel"));
        assert!(path.ends_with("apple-container/vmlinux") || path.ends_with("vmlinux"));
        assert!(hint.contains("make kernel"));
        assert_eq!(
            err.to_string(),
            format!("apple-container artifact missing: {what} at {path} — {hint}")
        );
    }

    #[test]
    fn missing_initfs_is_typed_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(KERNEL_FILE_NAME), b"kernel").expect("kernel");
        let err = resolve_from(dir.path()).unwrap_err();
        assert!(
            matches!(
                &err,
                AppleContainerError::ArtifactMissing { what, hint, .. }
                    if what.contains("initfs") && hint.contains("make init")
            ),
            "expected the initfs ArtifactMissing, got {err:?}"
        );
    }

    #[test]
    fn both_present_resolve() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(KERNEL_FILE_NAME), b"kernel").expect("kernel");
        std::fs::write(dir.path().join(INITFS_FILE_NAME), b"initfs").expect("initfs");
        let artifacts = resolve_from(dir.path()).expect("resolve");
        assert_eq!(artifacts.kernel, dir.path().join(KERNEL_FILE_NAME));
        assert_eq!(artifacts.initfs, dir.path().join(INITFS_FILE_NAME));
    }

    #[test]
    fn artifact_dir_lives_under_the_mvm_cache() {
        let dir = artifact_dir();
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some(ARTIFACT_DIR_NAME)
        );
    }
}
