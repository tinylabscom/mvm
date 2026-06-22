use std::path::{Path, PathBuf};

use mvm_core::kernel_artifact::KernelArtifactId;
use thiserror::Error;

use crate::runtime_overlay::{SKIP_HASH_VERIFY_ENV, compute_file_sha256};

/// Error returned by [`verify_fetched_kernel`].
#[derive(Debug, Error)]
pub enum KernelFetchError {
    /// I/O failure reading the kernel file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file's SHA-256 does not match the expected hash in the
    /// `KernelArtifactId`. The mismatched file is deleted before this
    /// error is returned so a partial download can't be reused on retry.
    #[error("kernel integrity check failed: expected sha256 {expected}, computed {actual}")]
    HashMismatch { expected: String, actual: String },
}

/// Verify that the kernel image at `path` matches the `artifact_hash`
/// recorded in `id`.
///
/// On mismatch the file is deleted (best-effort) before returning
/// `Err(KernelFetchError::HashMismatch)` so a corrupt or partial
/// download cannot be reused on retry.
///
/// Honors `MVM_SKIP_HASH_VERIFY=1` — the same emergency escape hatch
/// used by the runtime-overlay download path.
pub fn verify_fetched_kernel(path: &Path, id: &KernelArtifactId) -> Result<(), KernelFetchError> {
    if std::env::var_os(SKIP_HASH_VERIFY_ENV).is_some() {
        tracing::warn!(
            "{SKIP_HASH_VERIFY_ENV} set — skipping kernel integrity check on {}",
            path.display()
        );
        return Ok(());
    }

    let actual = compute_file_sha256(path)?;

    if actual != id.artifact_hash {
        let _ = std::fs::remove_file(path);
        return Err(KernelFetchError::HashMismatch {
            expected: id.artifact_hash.clone(),
            actual,
        });
    }
    Ok(())
}

/// How a kernel pin resolves to a concrete `vmlinux` for a given backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelResolution {
    /// A cached kernel is already present at this path. Installed builds
    /// should still [`verify_fetched_kernel`] it against the pin before boot.
    Cached(PathBuf),
    /// Source checkout with no cached kernel — build it to this path
    /// (`mvmctl build kernel build`). A source checkout is NEVER fetched: the
    /// local-build invariant forbids depending on a published artifact.
    NeedsBuild(PathBuf),
    /// Installed binary with no cached kernel — fetch the published prebuilt
    /// to this path, then [`verify_fetched_kernel`] it against the pin.
    NeedsFetch(PathBuf),
}

/// Per-arch, per-variant kernel cache path — the location
/// `mvmctl build kernel build` writes and the boot path reads.
pub fn cached_kernel_path(cache_dir: &Path, arch: &str, variant: &str) -> PathBuf {
    cache_dir
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join(variant)
        .join("vmlinux")
}

/// Decide how to obtain the `vmlinux` for a kernel pin without performing any
/// I/O beyond a cache-presence check. Pure policy so the build-local /
/// fetch-verify decision is unit-testable and the local-build invariant is
/// enforced in one place: a source checkout never resolves to `NeedsFetch`.
pub fn resolve_kernel(
    cache_dir: &Path,
    arch: &str,
    variant: &str,
    source_checkout: bool,
) -> KernelResolution {
    let path = cached_kernel_path(cache_dir, arch, variant);
    if path.exists() {
        KernelResolution::Cached(path)
    } else if source_checkout {
        KernelResolution::NeedsBuild(path)
    } else {
        KernelResolution::NeedsFetch(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_core::{kernel_artifact::compute_artifact_hash, util::test_env::TestEnv};
    use tempfile::NamedTempFile;

    fn write_temp(bytes: &[u8]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    fn make_id(bytes: &[u8]) -> KernelArtifactId {
        KernelArtifactId {
            kernel_version: "6.12.0-test".into(),
            config_hash: "fakecfg".into(),
            artifact_hash: compute_artifact_hash(bytes),
        }
    }

    #[test]
    fn match_returns_ok() {
        let _env = TestEnv::new();
        let content = b"vmlinux-content";
        let f = write_temp(content);
        let id = make_id(content);
        assert!(verify_fetched_kernel(f.path(), &id).is_ok());
        // File still present on match.
        assert!(f.path().exists());
    }

    #[test]
    fn mismatch_returns_err_and_deletes_file() {
        // Hold the env lock so this test serializes with skip_env_bypasses_wrong_hash.
        let _env = TestEnv::new();
        let content = b"vmlinux-content";
        let f = write_temp(content);
        let id = KernelArtifactId {
            kernel_version: "6.12.0-test".into(),
            config_hash: "fakecfg".into(),
            artifact_hash: "0".repeat(64),
        };
        // Persist the path before consuming the temp file handle.
        let path = f.path().to_path_buf();
        // Convert to TempPath so the directory cleanup doesn't race with
        // our deletion assertion — drop it immediately so the NamedTempFile
        // destructor doesn't try to remove a file we already deleted.
        let _temp_path = f.into_temp_path();
        let err = verify_fetched_kernel(&path, &id).expect_err("wrong hash must reject");
        assert!(matches!(err, KernelFetchError::HashMismatch { .. }));
        assert!(!path.exists(), "file must be deleted on mismatch");
    }

    #[test]
    fn skip_env_bypasses_wrong_hash() {
        let mut env = TestEnv::new();
        env.set(SKIP_HASH_VERIFY_ENV, "1");

        let content = b"vmlinux-content";
        let f = write_temp(content);
        let id = KernelArtifactId {
            kernel_version: "6.12.0-test".into(),
            config_hash: "fakecfg".into(),
            artifact_hash: "0".repeat(64),
        };
        let result = verify_fetched_kernel(f.path(), &id);
        drop(env);
        assert!(result.is_ok(), "skip env must bypass hash check");
    }

    #[test]
    fn resolve_cached_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = cached_kernel_path(dir.path(), "aarch64", "workload");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"vmlinux").unwrap();
        assert_eq!(
            resolve_kernel(dir.path(), "aarch64", "workload", true),
            KernelResolution::Cached(p.clone())
        );
        // Installed build with a cached kernel also resolves Cached.
        assert_eq!(
            resolve_kernel(dir.path(), "aarch64", "workload", false),
            KernelResolution::Cached(p)
        );
    }

    #[test]
    fn source_checkout_needs_build_never_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolve_kernel(dir.path(), "x86_64", "workload", true);
        assert!(
            matches!(r, KernelResolution::NeedsBuild(_)),
            "source checkout must build locally, never fetch — got {r:?}"
        );
    }

    #[test]
    fn installed_needs_fetch_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolve_kernel(dir.path(), "x86_64", "builder", false);
        assert!(matches!(r, KernelResolution::NeedsFetch(_)));
    }

    #[test]
    fn compute_file_sha256_agrees_with_compute_artifact_hash() {
        let _env = TestEnv::new();
        let bytes = b"cross-check-bytes";
        let f = write_temp(bytes);
        let from_file = compute_file_sha256(f.path()).unwrap();
        let from_mem = compute_artifact_hash(bytes);
        assert_eq!(from_file, from_mem, "file and in-memory sha256 must agree");
    }
}
