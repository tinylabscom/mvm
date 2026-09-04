use std::path::{Path, PathBuf};

use mvm_core::kernel_artifact::KernelArtifactId;
use thiserror::Error;

use crate::runtime_overlay::SKIP_HASH_VERIFY_ENV;
use mvm_fs::overlay::compute_file_sha256;

/// Error returned by [`verify_fetched_kernel`].
#[derive(Debug, Error)]
pub enum KernelFetchError {
    /// I/O failure reading the kernel file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file's SHA-256 does not match the expected hash. The mismatched
    /// file is deleted before this error is returned so a corrupt or partial
    /// artifact can't be reused on retry.
    #[error("kernel integrity check failed: expected sha256 {expected}, computed {actual}")]
    HashMismatch { expected: String, actual: String },

    /// A cached kernel carries no digest sidecar, so nothing vouches for its
    /// bytes. Untrusted rather than assumed-good.
    #[error("cached kernel at {path} has no digest sidecar — refusing to serve it unverified")]
    Unpinned { path: String },
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

/// File name of the digest sidecar recorded beside a kernel: the lowercase-hex
/// SHA-256 of its bytes.
///
/// SHA-256 rather than the BLAKE3 the apple-container artifact path uses,
/// because this side already speaks SHA-256 everywhere that matters —
/// `KernelArtifactId::artifact_hash` and the published
/// `kernel-<arch>-checksums-sha256.txt` manifests. The two axes coexist
/// deliberately; nothing rehashes across them.
pub const KERNEL_DIGEST_SIDECAR: &str = "vmlinux.sha256";

/// A kernel whose bytes have been checked against a recorded digest.
///
/// The point of the type is that it cannot be built any other way. Before it,
/// [`resolve_kernel`] handed back a bare `PathBuf` on a cache hit, which is a
/// perfectly usable value — so the natural call site used it, no reader could
/// see that a step had been skipped, and `verify_fetched_kernel` sat with no
/// production caller for the life of the function. Adding one call would have
/// fixed that instance and left the same shape for the next caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKernel(PathBuf);

impl VerifiedKernel {
    /// The verified kernel's path. Only reachable through a passing check.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// The digest sidecar beside `kernel`.
pub fn kernel_digest_sidecar(kernel: &Path) -> PathBuf {
    let Some(file_name) = kernel.file_name() else {
        return kernel.with_file_name(KERNEL_DIGEST_SIDECAR);
    };
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".sha256");
    kernel.with_file_name(sidecar_name)
}

/// Record the digest of a kernel just produced, beside it.
///
/// Called by whoever puts a kernel in the cache: the download path after its
/// checksum-manifest check, and the local build path from the bytes it just
/// built. The two have different provenance — one was checked against a
/// published manifest, the other is simply what we compiled — and the sidecar
/// claims only the latter: *these are the bytes that were here*. That is what a
/// later read needs to detect rot, truncation, or a swapped file.
///
/// Written temp-then-rename so an interrupted producer cannot leave a sidecar
/// that disagrees with the kernel beside it.
pub fn record_kernel_digest(kernel: &Path) -> Result<(), KernelFetchError> {
    let digest = compute_file_sha256(kernel)?;
    let sidecar = kernel_digest_sidecar(kernel);
    let tmp = sidecar.with_extension(format!("sha256.tmp{}", std::process::id()));
    std::fs::write(&tmp, format!("{digest}\n"))?;
    std::fs::rename(&tmp, &sidecar)?;
    Ok(())
}

/// Verify a cached kernel against its recorded sidecar.
///
/// Fail-closed: a missing sidecar is untrusted, not "assume fine". Absence of a
/// digest must never degrade into trusting the path, which is the whole failure
/// this replaces. On any failure both the kernel and its sidecar are removed,
/// so the next resolve re-derives rather than re-adopting the same bytes under
/// the same name.
fn verify_cached_kernel(kernel: &Path) -> Result<VerifiedKernel, KernelFetchError> {
    if std::env::var_os(SKIP_HASH_VERIFY_ENV).is_some() {
        tracing::warn!(
            "{SKIP_HASH_VERIFY_ENV} set — serving {} unverified",
            kernel.display()
        );
        return Ok(VerifiedKernel(kernel.to_path_buf()));
    }

    let sidecar = kernel_digest_sidecar(kernel);
    let expected = match std::fs::read_to_string(&sidecar) {
        Ok(contents) => contents.split_whitespace().next().unwrap_or("").to_string(),
        Err(_) => {
            evict_kernel(kernel);
            return Err(KernelFetchError::Unpinned {
                path: kernel.display().to_string(),
            });
        }
    };

    // Through the size+mtime-keyed digest cache, not a raw re-read. This check
    // runs on every kernel resolve, so on an unchanged cached kernel it was
    // re-reading the whole image once per launch to recompute a digest that
    // cannot have changed. The rootfs pin backing claim 8 already reads its
    // (far larger) image through this same cache for the same reason; any
    // rewrite of the file moves its size or mtime and forces a re-hash, so a
    // stale digest cannot be adopted here either.
    let actual = mvm_core::crypto::image_verify::sha256_file_cached(kernel)?;
    if actual != expected {
        evict_kernel(kernel);
        return Err(KernelFetchError::HashMismatch { expected, actual });
    }
    Ok(VerifiedKernel(kernel.to_path_buf()))
}

/// Every file that belongs to a cached kernel entry, in deletion order.
///
/// One definition because a kernel is evicted from more than one place, and a
/// caller that lists the set itself drifts: removing only part of the entry can
/// leave stale capability metadata beside the replacement, or let a poisoned
/// artifact be re-adopted under a digest nothing re-derived.
#[must_use]
pub fn kernel_entry_files(kernel: &Path) -> Vec<PathBuf> {
    vec![
        kernel.to_path_buf(),
        kernel_digest_sidecar(kernel),
        kernel.with_file_name("config"),
        // Keyed on the evicted file's size+mtime, so an orphan can be served to
        // a replacement that happens to land on the same pair.
        mvm_core::crypto::image_verify::sha256_cache_path(kernel),
    ]
}

/// Remove a rejected kernel and everything else in its entry, best-effort.
fn evict_kernel(kernel: &Path) {
    for path in kernel_entry_files(kernel) {
        let _ = std::fs::remove_file(path);
    }
}

/// How a kernel pin resolves to a concrete `vmlinux` for a given backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelResolution {
    /// A cached kernel that verified against its recorded digest.
    Cached(VerifiedKernel),
    /// Source checkout with no cached kernel — build it to this path
    /// (`mvmctl kernel build`). A source checkout is NEVER fetched: the
    /// local-build invariant forbids depending on a published artifact.
    NeedsBuild(PathBuf),
    /// Installed binary with no cached kernel — fetch the published prebuilt
    /// to this path, then [`record_kernel_digest`] beside it.
    NeedsFetch(PathBuf),
}

/// Directory holding one cached kernel entry — the `vmlinux` plus its digest
/// sidecar, `config`, and digest cache.
///
/// A sibling of `builder-vm/`, deliberately not a child of it. The entry used
/// to live at `builder-vm/<arch>/kernels/<variant>/`, inside the directory
/// Stage 0 `remove_dir_all`s whenever the builder-VM source fingerprint
/// changes. Promoting a new builder image therefore destroyed an unrelated
/// artifact that costs half an hour to rebuild, and the next boot rebuilt it
/// from scratch. Nothing about a kernel's identity depends on which builder
/// image compiled it, so it does not belong in a directory whose contract is
/// "atomically replaceable".
pub fn kernel_cache_dir(cache_dir: &Path, arch: &str, variant: &str) -> PathBuf {
    cache_dir.join("kernels").join(arch).join(variant)
}

/// Per-arch, per-variant kernel cache path — the location
/// `mvmctl kernel build` writes and the boot path reads.
pub fn cached_kernel_path(cache_dir: &Path, arch: &str, variant: &str) -> PathBuf {
    kernel_cache_dir(cache_dir, arch, variant).join("vmlinux")
}

/// Where a kernel entry lived before it was moved out of the Stage 0 blast
/// radius. Read only by [`migrate_legacy_kernel_entry`].
fn legacy_kernel_cache_dir(cache_dir: &Path, arch: &str, variant: &str) -> PathBuf {
    cache_dir
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join(variant)
}

/// Adopt a kernel entry left at the pre-relocation path.
///
/// Renames the whole entry directory, so the digest sidecar and the
/// size+mtime-keyed digest cache move with the bytes they describe and stay
/// valid. Only ever moves *into* an absent destination: a kernel already at
/// the current path is newer by construction and is never clobbered.
///
/// Best-effort. A failure here is not an error — the caller falls through to
/// re-deriving the kernel, which is what would have happened anyway.
fn migrate_legacy_kernel_entry(cache_dir: &Path, arch: &str, variant: &str) {
    let destination = kernel_cache_dir(cache_dir, arch, variant);
    if destination.exists() {
        return;
    }
    let legacy = legacy_kernel_cache_dir(cache_dir, arch, variant);
    if !legacy.join("vmlinux").is_file() {
        return;
    }
    let Some(parent) = destination.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    match std::fs::rename(&legacy, &destination) {
        Ok(()) => tracing::info!(
            from = %legacy.display(),
            to = %destination.display(),
            "moved cached kernel out of the builder-VM cache directory"
        ),
        Err(e) => tracing::warn!(
            from = %legacy.display(),
            error = %e,
            "could not move cached kernel to its current location; will re-derive"
        ),
    }
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
    // Every read of a cached kernel comes through here, so this is the one
    // place an entry from the previous layout has to be adopted.
    migrate_legacy_kernel_entry(cache_dir, arch, variant);
    let path = cached_kernel_path(cache_dir, arch, variant);
    if path.exists() {
        match verify_cached_kernel(&path) {
            Ok(verified) => return KernelResolution::Cached(verified),
            Err(e) => {
                // Evicted by the check above, so fall through to re-derive
                // rather than serving bytes nothing vouches for.
                tracing::warn!(
                    kernel = %path.display(),
                    error = %e,
                    "cached kernel did not verify; discarded it and will re-derive"
                );
            }
        }
    }
    if source_checkout {
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

    #[test]
    fn a_kernel_entry_is_not_stored_under_the_builder_vm_cache_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = kernel_cache_dir(tmp.path(), "aarch64", "workload");

        // Stage 0 replaces `builder-vm/<arch>` wholesale on a fingerprint
        // change, so a kernel stored beneath it is collateral damage.
        assert!(
            !entry.starts_with(tmp.path().join("builder-vm")),
            "kernel entry {} must not live under the builder-VM cache dir",
            entry.display()
        );
        assert_eq!(
            entry,
            tmp.path().join("kernels").join("aarch64").join("workload")
        );
    }

    #[test]
    fn a_kernel_left_at_the_previous_location_is_adopted_not_rebuilt() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = legacy_kernel_cache_dir(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(&legacy).unwrap();
        let legacy_kernel = legacy.join("vmlinux");
        std::fs::write(&legacy_kernel, b"previously built kernel").unwrap();
        record_kernel_digest(&legacy_kernel).unwrap();

        let resolved = resolve_kernel(tmp.path(), "aarch64", "workload", true);

        let KernelResolution::Cached(verified) = resolved else {
            panic!("a kernel at the previous location must be adopted, not rebuilt");
        };
        assert_eq!(
            verified.path(),
            cached_kernel_path(tmp.path(), "aarch64", "workload")
        );
        assert!(
            !legacy.exists(),
            "the previous entry should have been moved"
        );
    }

    #[test]
    fn adoption_never_clobbers_a_kernel_already_at_the_current_location() {
        let tmp = tempfile::tempdir().unwrap();

        let current = cached_kernel_path(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(current.parent().unwrap()).unwrap();
        std::fs::write(&current, b"the current kernel").unwrap();
        record_kernel_digest(&current).unwrap();

        let legacy = legacy_kernel_cache_dir(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("vmlinux"), b"a stale kernel").unwrap();
        record_kernel_digest(&legacy.join("vmlinux")).unwrap();

        let KernelResolution::Cached(verified) =
            resolve_kernel(tmp.path(), "aarch64", "workload", true)
        else {
            panic!("the current kernel should still verify");
        };
        assert_eq!(
            std::fs::read(verified.path()).unwrap(),
            b"the current kernel",
            "a stale entry must not overwrite the current one"
        );
    }

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
    fn resolve_cached_when_present_and_pinned() {
        // This test previously staged a kernel with no pin and asserted a hit,
        // which is exactly the behaviour being removed: existence is not
        // evidence. A hit now requires a recorded digest that matches.
        let dir = tempfile::tempdir().unwrap();
        let p = cached_kernel_path(dir.path(), "aarch64", "workload");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"vmlinux").unwrap();
        record_kernel_digest(&p).unwrap();

        match resolve_kernel(dir.path(), "aarch64", "workload", true) {
            KernelResolution::Cached(v) => assert_eq!(v.path(), p),
            other => panic!("expected a verified hit, got {other:?}"),
        }
        // Installed build with a cached, pinned kernel also resolves Cached.
        match resolve_kernel(dir.path(), "aarch64", "workload", false) {
            KernelResolution::Cached(v) => assert_eq!(v.path(), p),
            other => panic!("expected a verified hit, got {other:?}"),
        }
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

    #[test]
    fn digest_sidecars_are_named_for_each_kernel_format() {
        let directory = Path::new("/cache/kernels/x86_64/workload");
        assert_eq!(
            kernel_digest_sidecar(&directory.join("vmlinux")),
            directory.join("vmlinux.sha256")
        );
        assert_eq!(
            kernel_digest_sidecar(&directory.join("bzImage")),
            directory.join("bzImage.sha256")
        );
    }

    /// A cached kernel is only served when its recorded digest matches its
    /// bytes.
    ///
    /// Before this, `resolve_kernel` returned `Cached` whenever the file
    /// existed, and `verify_fetched_kernel` — which hashes against a pin and
    /// deletes on mismatch — had no production caller anywhere. No workload
    /// kernel had ever been checked against a pin on the read path.
    mod verified_reads {
        use super::*;

        /// Every test here calls `resolve_kernel`, which reads
        /// `MVM_SKIP_HASH_VERIFY`. A sibling test sets that variable to cover
        /// the escape hatch, and `set_var` is process-global while tests run in
        /// parallel threads — so without taking the same lock `TestEnv` holds,
        /// a verification test can observe the skip and serve bytes it should
        /// have rejected. Constructing the guard is what serializes them.
        fn env_guard() -> mvm_core::util::test_env::TestEnv {
            mvm_core::util::test_env::TestEnv::new()
        }

        fn staged(dir: &Path, bytes: &[u8], pin: bool) -> PathBuf {
            let kernel = cached_kernel_path(dir, "aarch64", "workload");
            std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
            std::fs::write(&kernel, bytes).unwrap();
            if pin {
                record_kernel_digest(&kernel).unwrap();
            }
            kernel
        }

        #[test]
        fn a_pinned_and_unmodified_kernel_is_served() {
            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"kernel bytes", true);
            match resolve_kernel(dir.path(), "aarch64", "workload", true) {
                KernelResolution::Cached(v) => assert_eq!(v.path(), kernel),
                other => panic!("expected a verified hit, got {other:?}"),
            }
        }

        /// This check runs on every kernel resolve, so on an unchanged cached
        /// kernel it must not re-read the whole image to recompute a digest
        /// that cannot have changed. Asserted by the shared digest cache being
        /// warm afterwards: a raw re-read leaves no entry behind.
        #[test]
        fn serving_a_pinned_kernel_leaves_its_digest_cache_warm() {
            use mvm_core::crypto::image_verify::{DigestSource, sha256_file_cached_with_source};

            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"kernel bytes", true);

            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::Cached(_)
            ));

            let (_, source) = sha256_file_cached_with_source(&kernel).unwrap();
            assert_eq!(
                source,
                DigestSource::Sidecar,
                "the pin check must digest through the shared cache, not re-read the image"
            );
        }

        /// The digest cache is keyed on the evicted file's size+mtime, so an
        /// orphan left behind can be served to a replacement that lands on the
        /// same pair — vouching for bytes nothing re-derived.
        #[test]
        fn evicting_a_kernel_removes_its_digest_cache() {
            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"kernel bytes", true);
            // Warm the cache, then corrupt the pin so the next resolve evicts.
            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::Cached(_)
            ));
            let cache = mvm_core::crypto::image_verify::sha256_cache_path(&kernel);
            assert!(cache.is_file(), "cache must be warm before the eviction");
            std::fs::write(kernel_digest_sidecar(&kernel), "0".repeat(64)).unwrap();

            assert!(!matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::Cached(_)
            ));
            assert!(!kernel.exists(), "the rejected kernel must be gone");
            assert!(
                !cache.exists(),
                "its digest cache must go with it, not outlive the bytes it names"
            );
        }

        #[test]
        fn a_kernel_with_no_pin_is_not_served() {
            let _env = env_guard();
            // Fail closed: absence of a digest must not degrade into trusting
            // the path, which is the exact behaviour this replaces.
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"kernel bytes", false);
            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::NeedsBuild(_)
            ));
            assert!(
                !kernel.exists(),
                "an unpinned kernel is evicted, not left to be re-adopted"
            );
        }

        #[test]
        fn a_modified_kernel_is_rejected_and_the_full_entry_is_evicted() {
            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"the real kernel", true);
            let config = kernel.with_file_name("config");
            std::fs::write(&config, "CONFIG_DM_VERITY=y\n").unwrap();
            // Same length, so a size check would not notice.
            std::fs::write(&kernel, b"the fake kernel").unwrap();

            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::NeedsBuild(_)
            ));
            assert!(!kernel.exists(), "rejected kernel removed");
            assert!(
                !kernel_digest_sidecar(&kernel).exists(),
                "its pin removed too — leaving one lets the other be re-adopted"
            );
            assert!(!config.exists(), "stale capability metadata removed too");
        }

        #[test]
        fn an_intact_kernel_from_another_variant_is_rejected() {
            let _env = env_guard();
            // Identity discrepancy: both files are complete and readable, each
            // simply belongs to the other build. An existence check sees
            // nothing wrong, which is why kernel cache skew mimics real bugs.
            let dir = tempfile::tempdir().unwrap();
            let workload = staged(dir.path(), b"workload kernel", true);
            let builder = cached_kernel_path(dir.path(), "aarch64", "builder");
            std::fs::create_dir_all(builder.parent().unwrap()).unwrap();
            std::fs::write(&builder, b"builder kernel").unwrap();
            record_kernel_digest(&builder).unwrap();

            // Swap the two intact kernels, leaving each pin in place.
            let a = std::fs::read(&workload).unwrap();
            let b = std::fs::read(&builder).unwrap();
            std::fs::write(&workload, &b).unwrap();
            std::fs::write(&builder, &a).unwrap();

            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::NeedsBuild(_)
            ));
        }

        #[test]
        fn a_missing_kernel_still_resolves_to_derive_not_error() {
            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", true),
                KernelResolution::NeedsBuild(_)
            ));
            assert!(matches!(
                resolve_kernel(dir.path(), "aarch64", "workload", false),
                KernelResolution::NeedsFetch(_)
            ));
        }

        #[test]
        fn the_pin_is_the_lowercase_hex_sha256_of_the_bytes() {
            let _env = env_guard();
            let dir = tempfile::tempdir().unwrap();
            let kernel = staged(dir.path(), b"abc", true);
            let recorded = std::fs::read_to_string(kernel_digest_sidecar(&kernel)).unwrap();
            assert_eq!(
                recorded.trim(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }
    }
}
