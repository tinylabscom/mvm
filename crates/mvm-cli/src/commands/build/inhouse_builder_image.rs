//! In-house builder-image auto-resolver.
//!
//! Produces (or reuses from a hash-keyed cache) the HVF-bootable builder
//! image pair (kernel + injected rootfs) that `InHouseBuilderVm` needs.
//!
//! The cache key is a SHA-256 over the digests of three inputs:
//! - the base kernel image
//! - the base rootfs
//! - the `mvm-host-vm-init` binary that is baked in
//!
//! On a cache hit the existing pair is returned directly. On a miss the
//! rootfs is re-baked via the vsock-less HVF patcher VM and the result is
//! stored under `builder_vm_cache_dir()/inhouse/<key>/`.
//!
//! Baking uses a `<key>.partial` staging directory that is promoted
//! atomically via `fs::rename` only on full success. A failed bake
//! therefore cannot poison the cache: the partial dir is cleaned up on
//! error and the key dir never appears until the image pair is complete.

use std::path::{Path, PathBuf};
use std::{fs, io};

use mvm_build::builder_vm::{BuilderVmError, builder_vm_cache_dir};
use mvm_build::rootfs_inject::InjectBinary;
use mvm_core::crypto::image_verify::sha256_file;
use sha2::{Digest, Sha256};

use crate::host_binaries::extract::ensure_extracted_for_boot;

/// Derive a deterministic cache key from the SHA-256 digests of the three
/// inputs that determine the baked image's content. Pure: reads files, never
/// boots a VM.
fn inhouse_image_cache_key(vmlinux: &Path, rootfs: &Path, host_init: &Path) -> String {
    let mut h = Sha256::new();
    for p in [vmlinux, rootfs, host_init] {
        h.update(sha256_file(p).unwrap_or_default().as_bytes());
    }
    hex::encode(h.finalize())
}

/// Return `true` when a previously baked image pair is present in `out_dir`.
fn is_cached(out_dir: &Path) -> bool {
    out_dir.join("Image").is_file() && out_dir.join("rootfs.ext4").is_file()
}

/// Resolve the HVF-bootable builder image pair `(kernel, rootfs)`.
///
/// - Reads the base `vmlinux` + `rootfs.ext4` from `builder_vm_cache_dir()/<arch>/`
///   (the same source the libkrun/vz builders use).
/// - Injects `mvm-host-vm-init` into a copy of the base rootfs using the
///   vsock-less HVF patcher VM.
/// - Caches the result under `builder_vm_cache_dir()/inhouse/<key>/`.
///
/// On cache hit the existing pair is returned without rebaking.
/// On any VMM-level failure returns `BuilderVmError::InHouseVmmFailed` so the
/// builder auto-detect fallback can retry libkrun.
pub fn resolve_inhouse_builder_image() -> Result<(PathBuf, PathBuf), BuilderVmError> {
    let arch = std::env::consts::ARCH;
    let arch_dir = builder_vm_cache_dir().join(arch);

    let vmlinux = arch_dir.join("vmlinux");
    let base_rootfs = arch_dir.join("rootfs.ext4");

    if !vmlinux.is_file() {
        return Err(BuilderVmError::InHouseVmmFailed {
            detail: format!(
                "base builder-VM kernel not found at {}; run `mvmctl dev up` \
                 with the libkrun builder to produce the base image first",
                vmlinux.display()
            ),
        });
    }
    if !base_rootfs.is_file() {
        return Err(BuilderVmError::InHouseVmmFailed {
            detail: format!(
                "base builder-VM rootfs not found at {}; run `mvmctl dev up` \
                 with the libkrun builder to produce the base image first",
                base_rootfs.display()
            ),
        });
    }

    let host_bins_cache = PathBuf::from(mvm_core::config::mvm_cache_dir()).join("host-bins");
    let host_bin_dir = ensure_extracted_for_boot(&host_bins_cache).map_err(|e| {
        BuilderVmError::InHouseVmmFailed {
            detail: format!("extract embedded host binaries: {e}"),
        }
    })?;

    let host_init = host_bin_dir.join("mvm-host-vm-init");
    let key = inhouse_image_cache_key(&vmlinux, &base_rootfs, &host_init);
    let out_dir = builder_vm_cache_dir().join("inhouse").join(&key);

    if is_cached(&out_dir) {
        return Ok((out_dir.join("Image"), out_dir.join("rootfs.ext4")));
    }

    // Bake into a staging directory; promote atomically so a partial bake
    // can never be mistaken for a complete cache entry.
    let partial = builder_vm_cache_dir()
        .join("inhouse")
        .join(format!("{key}.partial"));
    let _ = fs::remove_dir_all(&partial);
    // Remove any incomplete out_dir from a previous failed rename step.
    let _ = fs::remove_dir_all(&out_dir);

    fs::create_dir_all(&partial).map_err(|e| BuilderVmError::InHouseVmmFailed {
        detail: format!("create staging dir {}: {e}", partial.display()),
    })?;

    let partial_kernel = partial.join("Image");
    let partial_rootfs = partial.join("rootfs.ext4");

    let bake_result = (|| {
        // Copy the base kernel — already a raw arm64 boot Image on aarch64.
        fs::copy(&vmlinux, &partial_kernel).map_err(|e| BuilderVmError::InHouseVmmFailed {
            detail: format!(
                "copy base kernel {} -> {}: {e}",
                vmlinux.display(),
                partial_kernel.display()
            ),
        })?;

        let patcher_path = host_bin_dir.join("mvm-rootfs-patcher");
        let patcher = fs::read(&patcher_path).map_err(|e| BuilderVmError::InHouseVmmFailed {
            detail: format!("read embedded patcher at {}: {e}", patcher_path.display()),
        })?;
        let host_init_bytes =
            fs::read(&host_init).map_err(|e| BuilderVmError::InHouseVmmFailed {
                detail: format!(
                    "read embedded mvm-host-vm-init at {}: {e}",
                    host_init.display()
                ),
            })?;

        let work_dir = partial.join("work");
        mvm_backend::builder_runner::inject::inject_host_binaries(
            &mvm_backend::builder_runner::inject::InjectRequest {
                kernel: &partial_kernel,
                base_rootfs: &base_rootfs,
                out_rootfs: &partial_rootfs,
                work_dir: &work_dir,
                patcher: &patcher,
                binaries: &[InjectBinary {
                    name: "mvm-host-vm-init",
                    install_path: "/sbin/mvm-host-vm-init",
                    bytes: host_init_bytes,
                }],
            },
        )
        .map_err(|e| BuilderVmError::InHouseVmmFailed {
            detail: format!("bake in-house builder rootfs: {e}"),
        })
    })();

    if let Err(e) = bake_result {
        let _ = fs::remove_dir_all(&partial);
        return Err(e);
    }

    // Promote atomically. A concurrent process may have won the race and
    // already placed the final dir; treat that as a cache hit rather than
    // an error.
    match fs::rename(&partial, &out_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists || out_dir.is_dir() => {
            // Another process completed the bake concurrently; clean up our
            // staging copy and use theirs.
            let _ = fs::remove_dir_all(&partial);
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&partial);
            return Err(BuilderVmError::InHouseVmmFailed {
                detail: format!(
                    "promote staged image {} -> {}: {e}",
                    partial.display(),
                    out_dir.display()
                ),
            });
        }
    }

    Ok((out_dir.join("Image"), out_dir.join("rootfs.ext4")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_stable_and_input_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let (k, r, h) = (
            dir.path().join("k"),
            dir.path().join("r"),
            dir.path().join("h"),
        );
        std::fs::write(&k, b"kernelA").unwrap();
        std::fs::write(&r, b"rootfsA").unwrap();
        std::fs::write(&h, b"initA").unwrap();
        let key1 = inhouse_image_cache_key(&k, &r, &h);
        let key2 = inhouse_image_cache_key(&k, &r, &h);
        assert_eq!(key1, key2, "same inputs → same key");
        std::fs::write(&h, b"initB").unwrap();
        assert_ne!(
            key1,
            inhouse_image_cache_key(&k, &r, &h),
            "host-init change → new key"
        );
    }

    #[test]
    fn cache_key_changes_on_kernel_change() {
        let dir = tempfile::tempdir().unwrap();
        let (k, r, h) = (
            dir.path().join("k"),
            dir.path().join("r"),
            dir.path().join("h"),
        );
        std::fs::write(&k, b"kernelA").unwrap();
        std::fs::write(&r, b"rootfsA").unwrap();
        std::fs::write(&h, b"initA").unwrap();
        let key1 = inhouse_image_cache_key(&k, &r, &h);
        std::fs::write(&k, b"kernelB").unwrap();
        assert_ne!(
            key1,
            inhouse_image_cache_key(&k, &r, &h),
            "kernel change → new key"
        );
    }

    #[test]
    fn is_cached_returns_false_when_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_cached(&dir.path().join("nonexistent")));
    }

    #[test]
    fn is_cached_returns_false_when_files_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Only Image present — rootfs.ext4 missing.
        std::fs::write(dir.path().join("Image"), b"kernel").unwrap();
        assert!(!is_cached(dir.path()));
    }

    #[test]
    fn is_cached_returns_true_when_both_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Image"), b"kernel").unwrap();
        std::fs::write(dir.path().join("rootfs.ext4"), b"rootfs").unwrap();
        assert!(is_cached(dir.path()));
    }

    #[test]
    fn partial_dir_does_not_count_as_cached() {
        // A leftover `<key>.partial` staging directory must never be treated
        // as a complete cache entry; `is_cached` only checks the final key dir.
        let dir = tempfile::tempdir().unwrap();
        let partial = dir.path().join("abc123.partial");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("Image"), b"kernel").unwrap();
        std::fs::write(partial.join("rootfs.ext4"), b"rootfs").unwrap();
        // The partial dir itself has both files — but `is_cached` is only
        // called with the final key dir path (never the `.partial` sibling).
        let final_dir = dir.path().join("abc123");
        assert!(
            !is_cached(&final_dir),
            "partial dir must not satisfy is_cached on the final path"
        );
    }
}
