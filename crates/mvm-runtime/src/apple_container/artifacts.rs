//! Host-side resolution of the Apple Container kernel artifact.
//!
//! The Apple Container backend boots Apple's prebuilt container kernel — a
//! fetched binary artifact mvm does not build — cached at
//! `<mvm-cache>/apple-container/vmlinux`. Everything else in the boot (the
//! universal initramfs, the guest agent, activation) is the same stack
//! every runner backend uses. Resolution is pure path probing: a missing
//! kernel is a typed [`AppleContainerError::ArtifactMissing`] whose hint
//! says where to fetch it, never an opaque I/O error.

use std::path::PathBuf;

use crate::apple_container_backend::AppleContainerError;

/// Cache subdirectory (under `mvm_cache_dir`) holding the artifact.
pub const ARTIFACT_DIR_NAME: &str = "apple-container";
/// File name of the container kernel image inside the artifact dir.
pub const KERNEL_FILE_NAME: &str = "vmlinux";

/// Hint for a missing kernel artifact.
const KERNEL_HINT: &str = "copy an arm64 Linux Image with device-mapper + dm-verity built in \
     (CONFIG_BLK_DEV_DM=y, CONFIG_DM_VERITY=y) here — the stock Apple/Kata container kernels \
     ship no device-mapper, so the universal-initramfs verified boot needs a dm-capable kernel \
     (e.g. build github.com/apple/containerization's kernel with those options enabled)";

/// The cache directory the kernel is resolved from.
pub fn artifact_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join(ARTIFACT_DIR_NAME)
}

/// Resolve the container kernel from the cache, failing closed with a
/// typed error naming the missing file and how to fetch it.
pub fn resolve() -> Result<PathBuf, AppleContainerError> {
    resolve_from(&artifact_dir())
}

/// The filesystem-probing core of [`resolve`], split out so tests point it
/// at a tempdir instead of the real cache.
fn resolve_from(dir: &std::path::Path) -> Result<PathBuf, AppleContainerError> {
    let kernel = dir.join(KERNEL_FILE_NAME);
    if !kernel.is_file() {
        return Err(AppleContainerError::ArtifactMissing {
            what: "Apple container kernel (arm64 Linux Image)",
            path: kernel.display().to_string(),
            hint: KERNEL_HINT,
        });
    }
    Ok(kernel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_kernel_is_typed_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_from(dir.path()).unwrap_err();
        let AppleContainerError::ArtifactMissing { what, path, hint } = &err;
        assert!(what.contains("kernel"));
        assert!(path.ends_with("vmlinux"));
        assert!(hint.contains("container kernel"));
        assert_eq!(
            err.to_string(),
            format!("apple-container artifact missing: {what} at {path} — {hint}")
        );
    }

    #[test]
    fn present_kernel_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(KERNEL_FILE_NAME), b"kernel").expect("kernel");
        assert_eq!(
            resolve_from(dir.path()).expect("resolve"),
            dir.path().join(KERNEL_FILE_NAME)
        );
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
