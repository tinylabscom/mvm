//! The Stage 0 bootstrap kernel — the one kernel that can be neither built nor
//! resolved by the ordinary kernel policy.
//!
//! Stage 0 builds the builder VM from nothing, so at the moment it needs a
//! kernel there is no builder VM to compile one in.
//! [`kernel_fetch::resolve_kernel`](crate::kernel_fetch::resolve_kernel)
//! answers a source checkout with
//! [`NeedsBuild`](crate::kernel_fetch::KernelResolution::NeedsBuild), which is
//! correct for every other kernel and unsatisfiable for this one.
//!
//! The two shipped answers are both host-specific. libkrun extracts a kernel
//! from libkrunfw's dylib, which requires Homebrew; QEMU boots the host distro's
//! `/boot/vmlinuz-$(uname -r)`, which requires a Linux host carrying an
//! initramfs. Neither generalizes to a third VMM, and the first is the sole
//! reason a macOS host needs the `slp/krun` packages at all.
//!
//! # A bootstrap seed, not a build output
//!
//! This module classifies the bootstrap kernel the same way Stage 0 already
//! classifies its root filesystem: as a **seed**. The Nix release tarball
//! (`stage0::NIX_SEED_AARCH64` / `NIX_SEED_X86_64`) is a hash-pinned published
//! artifact that Stage 0 fetches and verifies on a contributor checkout, because
//! it is a means of building rather than the artifact under construction. The
//! bootstrap kernel is the same kind of thing, so it resolves the same way:
//! [`resolve_bootstrap_kernel_with`] passes `source_checkout: false`
//! unconditionally, and that single argument *is* the classification.
//!
//! The scope of that decision is deliberately narrow. It covers the kernel that
//! boots Stage 0 and nothing else — the builder image and the workload kernel
//! keep the local-build invariant unchanged, so a contributor editing
//! `nix/images/builder-vm/flake.nix` still sees their change on the next boot.
//!
//! Net effect on trust: the bootstrap kernel stops arriving inside a
//! third-party Homebrew dylib and starts arriving as our own release artifact,
//! covered by a signed checksum manifest. That is strictly less to trust, not
//! more.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use thiserror::Error;

use crate::kernel_fetch::{KernelResolution, VerifiedKernel, resolve_kernel};

/// Cache variant for the bootstrap kernel.
///
/// Deliberately its own slot rather than sharing `"builder"`. That slot holds
/// the kernel paired into a builder *image*; conflating the two would make
/// "which kernel booted Stage 0" depend on which path last wrote the directory,
/// and a cache entry should say what it is.
pub const BOOTSTRAP_VARIANT: &str = "stage0-bootstrap";

/// Why a bootstrap kernel could not be produced.
#[derive(Debug, Error)]
pub enum Stage0KernelError {
    /// No fetcher was registered, so nothing can acquire the artifact. A
    /// library-only consumer of `mvm-build` hits this; `mvmctl` registers one
    /// during startup.
    #[error(
        "no bootstrap-kernel fetcher is registered, so Stage 0 cannot acquire \
         a kernel for {arch}. This is an mvmctl wiring error, not a host problem."
    )]
    NoFetcher { arch: String },

    /// The registered fetcher failed (network, missing release asset, a
    /// signature or checksum that did not verify).
    #[error("could not fetch the Stage 0 bootstrap kernel for {arch}: {detail}")]
    FetchFailed { arch: String, detail: String },

    /// The artifact landed but did not verify against its recorded digest. The
    /// verifying layer already evicted it.
    #[error(
        "the Stage 0 bootstrap kernel for {arch} did not verify after fetch and \
         was discarded: {detail}"
    )]
    Unverified { arch: String, detail: String },
}

/// Acquires the published bootstrap kernel for an arch into a destination path.
///
/// Injected rather than called directly because the fetch path lives in
/// `mvm-cli` (release-tag resolution, the signed checksum manifest, the
/// progress UI) and `mvm-build` sits below it. An implementation is expected to
/// write the destination only after its signature and checksum rungs pass, and
/// to record a digest sidecar beside it — the resolver re-checks that sidecar
/// and fails closed if it is absent.
pub trait BootstrapKernelFetcher: Send + Sync + 'static {
    /// Place a verified bootstrap kernel for `arch` at `dest`.
    fn fetch(&self, arch: &str, dest: &Path) -> Result<(), String>;
}

impl<F> BootstrapKernelFetcher for F
where
    F: Fn(&str, &Path) -> Result<(), String> + Send + Sync + 'static,
{
    fn fetch(&self, arch: &str, dest: &Path) -> Result<(), String> {
        self(arch, dest)
    }
}

static FETCHER: OnceLock<Box<dyn BootstrapKernelFetcher>> = OnceLock::new();

/// Register the process-wide bootstrap-kernel fetcher. First registration wins,
/// mirroring
/// [`register_hvf_builder`](crate::builder_backend_select::register_hvf_builder).
pub fn register_bootstrap_kernel_fetcher(fetcher: Box<dyn BootstrapKernelFetcher>) {
    let _ = FETCHER.set(fetcher);
}

/// Where the bootstrap kernel for `arch` is cached.
pub fn bootstrap_kernel_path(cache_dir: &Path, arch: &str) -> PathBuf {
    crate::kernel_fetch::cached_kernel_path(cache_dir, arch, BOOTSTRAP_VARIANT)
}

/// Resolve a digest-verified bootstrap kernel using the process-wide fetcher.
///
/// Thin wrapper over [`resolve_bootstrap_kernel_with`]; the policy lives there
/// so it is testable without touching global state.
pub fn resolve_bootstrap_kernel(
    cache_dir: &Path,
    arch: &str,
) -> Result<VerifiedKernel, Stage0KernelError> {
    match FETCHER.get() {
        Some(fetcher) => resolve_bootstrap_kernel_with(cache_dir, arch, fetcher.as_ref()),
        // Distinguished from a fetch failure: nothing was attempted, and the
        // fix is in our wiring rather than on the operator's host.
        None => match resolve_kernel(cache_dir, arch, BOOTSTRAP_VARIANT, false) {
            KernelResolution::Cached(verified) => Ok(verified),
            _ => Err(Stage0KernelError::NoFetcher {
                arch: arch.to_string(),
            }),
        },
    }
}

/// Resolve a digest-verified bootstrap kernel for `arch`, fetching through
/// `fetcher` if the cache is cold.
///
/// Fails closed at every rung: a failing fetch and an artifact that arrives
/// without a verifiable digest are both errors rather than a path handed back
/// unchecked. The return type can only be built by the verifying layer, so a
/// caller cannot skip the check by construction.
pub fn resolve_bootstrap_kernel_with(
    cache_dir: &Path,
    arch: &str,
    fetcher: &dyn BootstrapKernelFetcher,
) -> Result<VerifiedKernel, Stage0KernelError> {
    // `false` is the classification: a bootstrap seed is fetched even in a
    // source checkout, because the alternative — build it — is the thing this
    // kernel exists to make possible. See the module docs.
    let dest = match resolve_kernel(cache_dir, arch, BOOTSTRAP_VARIANT, false) {
        KernelResolution::Cached(verified) => return Ok(verified),
        KernelResolution::NeedsFetch(dest) | KernelResolution::NeedsBuild(dest) => dest,
    };

    tracing::info!(
        arch,
        dest = %dest.display(),
        "fetching the Stage 0 bootstrap kernel"
    );
    fetcher
        .fetch(arch, &dest)
        .map_err(|detail| Stage0KernelError::FetchFailed {
            arch: arch.to_string(),
            detail,
        })?;

    match resolve_kernel(cache_dir, arch, BOOTSTRAP_VARIANT, false) {
        KernelResolution::Cached(verified) => Ok(verified),
        // The fetcher reported success and the artifact still did not verify,
        // so it has been evicted. Re-fetching here would loop on a reproducible
        // failure; surface it instead.
        KernelResolution::NeedsFetch(_) | KernelResolution::NeedsBuild(_) => {
            Err(Stage0KernelError::Unverified {
                arch: arch.to_string(),
                detail: format!(
                    "no verifiable kernel at {} after a successful fetch",
                    dest.display()
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::kernel_fetch::record_kernel_digest;

    /// A fetcher that writes `bytes` and pins them, counting its calls.
    struct FakeFetcher {
        bytes: Vec<u8>,
        /// Skip the digest sidecar, imitating a fetch path that published an
        /// artifact nothing vouches for.
        record_digest: bool,
        calls: AtomicUsize,
    }

    impl FakeFetcher {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                record_digest: true,
                calls: AtomicUsize::new(0),
            }
        }

        fn without_digest(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                record_digest: false,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl BootstrapKernelFetcher for FakeFetcher {
        fn fetch(&self, _arch: &str, dest: &Path) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(dest, &self.bytes).map_err(|e| e.to_string())?;
            if self.record_digest {
                record_kernel_digest(dest).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }

    /// A fetcher that always fails, as a missing release asset would.
    struct FailingFetcher;

    impl BootstrapKernelFetcher for FailingFetcher {
        fn fetch(&self, _arch: &str, _dest: &Path) -> Result<(), String> {
            Err("404 Not Found".to_string())
        }
    }

    /// Write a kernel plus a correct digest sidecar at the bootstrap path.
    fn seed_cached_kernel(cache: &Path, arch: &str, bytes: &[u8]) -> PathBuf {
        let path = bootstrap_kernel_path(cache, arch);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        record_kernel_digest(&path).unwrap();
        path
    }

    #[test]
    fn the_bootstrap_kernel_has_its_own_cache_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let bootstrap = bootstrap_kernel_path(tmp.path(), "aarch64");
        let builder_image_kernel =
            crate::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "builder");

        // Sharing the "builder" slot would make "which kernel booted Stage 0"
        // depend on which path last wrote the directory.
        assert_ne!(
            bootstrap, builder_image_kernel,
            "the bootstrap kernel must not share the builder image's cache slot"
        );
        assert!(bootstrap.ends_with("kernels/aarch64/stage0-bootstrap/vmlinux"));
    }

    #[test]
    fn a_verified_cached_kernel_resolves_without_fetching() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed_cached_kernel(tmp.path(), "aarch64", b"bootstrap kernel bytes");
        let fetcher = FakeFetcher::new(b"should never be called");

        let verified = resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect("a digest-verified cached kernel resolves");

        assert_eq!(verified.path(), path);
        assert_eq!(fetcher.calls(), 0, "a warm cache must not hit the network");
    }

    #[test]
    fn a_cold_cache_fetches_once_and_serves_the_verified_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(b"freshly published kernel");

        let verified = resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect("a cold cache resolves through the fetcher");

        assert_eq!(fetcher.calls(), 1);
        assert_eq!(
            verified.path(),
            bootstrap_kernel_path(tmp.path(), "aarch64")
        );
        assert_eq!(
            std::fs::read(verified.path()).unwrap(),
            b"freshly published kernel"
        );
    }

    /// The classification this module exists for: a source checkout still
    /// fetches. `resolve_kernel` would answer `NeedsBuild` here, which Stage 0
    /// cannot satisfy — nothing can compile a kernel before the builder exists.
    #[test]
    fn a_source_checkout_still_fetches_the_bootstrap_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(b"published kernel");

        // The ordinary policy, asked the same question a contributor's host
        // would ask it, refuses to fetch.
        assert!(matches!(
            resolve_kernel(tmp.path(), "aarch64", BOOTSTRAP_VARIANT, true),
            KernelResolution::NeedsBuild(_)
        ));

        // The bootstrap resolver fetches anyway, because a seed is not a build
        // output.
        resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect("the bootstrap seed is fetched regardless of checkout kind");
        assert_eq!(fetcher.calls(), 1);
    }

    #[test]
    fn a_cached_kernel_without_a_sidecar_is_refetched_not_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = bootstrap_kernel_path(tmp.path(), "aarch64");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Bytes with nothing vouching for them: the shape a partial or
        // tampered-with download leaves behind.
        std::fs::write(&path, b"unvouched bytes").unwrap();
        let fetcher = FakeFetcher::new(b"properly published kernel");

        let verified = resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect("the unpinned entry is replaced by a fetched one");

        assert_eq!(fetcher.calls(), 1, "the unpinned bytes must not be served");
        assert_eq!(
            std::fs::read(verified.path()).unwrap(),
            b"properly published kernel"
        );
    }

    #[test]
    fn a_kernel_whose_bytes_changed_after_pinning_is_not_served() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed_cached_kernel(tmp.path(), "aarch64", b"original bytes");
        // Rot, truncation, or a swap on disk — the case the sidecar exists for.
        std::fs::write(&path, b"different bytes entirely").unwrap();
        let fetcher = FakeFetcher::new(b"republished kernel");

        let verified = resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect("a mismatched entry is evicted and refetched");

        assert_eq!(fetcher.calls(), 1);
        assert_eq!(
            std::fs::read(verified.path()).unwrap(),
            b"republished kernel",
            "the tampered bytes must not survive the resolve"
        );
    }

    #[test]
    fn a_failing_fetch_surfaces_the_fetchers_reason() {
        let tmp = tempfile::tempdir().unwrap();

        let err = resolve_bootstrap_kernel_with(tmp.path(), "x86_64", &FailingFetcher)
            .expect_err("a failing fetch cannot resolve");

        match err {
            Stage0KernelError::FetchFailed { arch, detail } => {
                assert_eq!(arch, "x86_64");
                assert!(detail.contains("404"), "keeps the reason: {detail}");
            }
            other => panic!("expected FetchFailed, got {other:?}"),
        }
    }

    /// A fetcher that publishes bytes but pins nothing must not be trusted on
    /// its own report of success — the digest sidecar is what the read path
    /// checks, and its absence is the failure this asserts.
    #[test]
    fn a_fetch_that_records_no_digest_is_refused_rather_than_served() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::without_digest(b"unpinned download");

        let err = resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &fetcher)
            .expect_err("an unpinned fetch result must not be served");

        assert_eq!(
            fetcher.calls(),
            1,
            "it must not retry a reproducible failure"
        );
        match err {
            Stage0KernelError::Unverified { arch, .. } => assert_eq!(arch, "aarch64"),
            other => panic!("expected Unverified, got {other:?}"),
        }
    }
}
