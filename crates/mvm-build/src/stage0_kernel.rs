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
//! initramfs. Neither generalizes to a third VMM.
//!
//! # A bootstrap seed, pinned in source
//!
//! This module treats the bootstrap kernel exactly the way Stage 0 already
//! treats its root filesystem. The Nix release tarball is a
//! [`BootstrapAsset`](crate::stage0::BootstrapAsset): a URL and a SHA-256
//! pinned in source, fetched on a contributor checkout because it is a means of
//! building rather than the artifact under construction, and held to that pin
//! fail-closed. The bootstrap kernel is the same kind of thing, so it carries
//! the same kind of pin — [`BOOTSTRAP_KERNEL_AARCH64`] and
//! [`BOOTSTRAP_KERNEL_X86_64`].
//!
//! The pin is what makes this work on every build. An earlier shape fetched
//! through the release checksum manifest instead, which needs the
//! `manifest-verify` feature to authenticate; a contributor's `just embed` build
//! does not carry that feature, so every HVF bootstrap on the ordinary inner
//! loop refused before booting anything. A source pin needs no feature and no
//! network trust decision at run time: the decision was made when the pin was
//! reviewed, against a manifest whose signature was checked then.
//!
//! The scope is deliberately narrow. It covers the kernel that boots Stage 0
//! and nothing else — the builder image and the workload kernel keep the
//! local-build invariant unchanged, so a contributor editing
//! `nix/images/builder-vm/flake.nix` still sees their change on the next boot.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use mvm_fs::overlay::compute_file_sha256;
use thiserror::Error;

use crate::kernel_fetch::{
    KernelResolution, VerifiedKernel, kernel_entry_files, record_kernel_digest, resolve_kernel,
};

/// Cache variant for the bootstrap kernel.
///
/// Deliberately its own slot rather than sharing `"builder"`. That slot holds
/// the kernel paired into a builder *image*; conflating the two would make
/// "which kernel booted Stage 0" depend on which path last wrote the directory,
/// and a cache entry should say what it is.
pub const BOOTSTRAP_VARIANT: &str = "stage0-bootstrap";

/// The boot-image release the bootstrap kernel pins are taken from.
///
/// Bump in lockstep with the two digests below, and only against a manifest
/// whose signature has been verified — the pin inherits exactly the trust of
/// the manifest it was copied out of. It does not have to track the default
/// boot image: Stage 0 needs virtio-blk, vsock and ext4 from this kernel and
/// nothing a newer release is likely to change.
pub const BOOTSTRAP_KERNEL_RELEASE: &str = "boot-image/v0.1.5";

/// Where a bootstrap kernel comes from and what its bytes must hash to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapKernelPin {
    /// Download URL. A GitHub release asset, which redirects — see
    /// [`BootstrapKernelFetcher`] for why that decides which transport fetches it.
    pub url: &'static str,
    /// Lowercase-hex SHA-256 of the kernel bytes. The binding integrity check.
    pub sha256_hex: &'static str,
}

/// The aarch64 bootstrap kernel: `builder-vm-vmlinux-aarch64` from
/// [`BOOTSTRAP_KERNEL_RELEASE`].
pub const BOOTSTRAP_KERNEL_AARCH64: BootstrapKernelPin = BootstrapKernelPin {
    url: "https://github.com/tinylabscom/mvm/releases/download/boot-image/v0.1.5/builder-vm-vmlinux-aarch64",
    sha256_hex: "b53be06555a144433369708a57e9e1d278dbad7d26cb31a5fe9167eb7a90f6c1",
};

/// The x86_64 bootstrap kernel: `builder-vm-vmlinux-x86_64` from
/// [`BOOTSTRAP_KERNEL_RELEASE`].
pub const BOOTSTRAP_KERNEL_X86_64: BootstrapKernelPin = BootstrapKernelPin {
    url: "https://github.com/tinylabscom/mvm/releases/download/boot-image/v0.1.5/builder-vm-vmlinux-x86_64",
    sha256_hex: "d07fa3dcca7eac14cd17ffe5c4daeb091676322de9e377a008ba0ec45a382435",
};

/// The pin for a guest architecture, or `None` for one Stage 0 does not support.
pub fn bootstrap_kernel_pin(arch: &str) -> Option<&'static BootstrapKernelPin> {
    match arch {
        "aarch64" => Some(&BOOTSTRAP_KERNEL_AARCH64),
        "x86_64" => Some(&BOOTSTRAP_KERNEL_X86_64),
        _ => None,
    }
}

/// Why a bootstrap kernel could not be produced.
#[derive(Debug, Error)]
pub enum Stage0KernelError {
    /// No transport was registered, so nothing can download the artifact. A
    /// library-only consumer of `mvm-build` hits this; `mvmctl` registers one
    /// during startup.
    #[error(
        "no bootstrap-kernel fetcher is registered, so Stage 0 cannot acquire \
         a kernel for {arch}. This is an mvmctl wiring error, not a host problem."
    )]
    NoFetcher { arch: String },

    /// There is no pinned bootstrap kernel for this architecture.
    #[error("Stage 0 has no pinned bootstrap kernel for {arch}")]
    UnsupportedArch { arch: String },

    /// The transport failed (network, missing asset, curl missing).
    #[error("could not fetch the Stage 0 bootstrap kernel for {arch}: {detail}")]
    FetchFailed { arch: String, detail: String },

    /// The downloaded bytes are not the pinned kernel. Nothing was kept.
    #[error(
        "the Stage 0 bootstrap kernel for {arch} does not match its source pin \
         (expected sha256 {expected}, got {actual}) and was discarded. Either the \
         release asset was replaced or the pin needs an update."
    )]
    PinMismatch {
        arch: String,
        expected: String,
        actual: String,
    },

    /// Local I/O around an otherwise-verified download failed.
    #[error("placing the Stage 0 bootstrap kernel for {arch}: {detail}")]
    Io { arch: String, detail: String },
}

/// Downloads a URL to a path. Transport only — it verifies nothing.
///
/// Injected rather than implemented here because the bootstrap kernel is a
/// GitHub release asset, whose URL answers with a redirect, and `mvm-http`
/// deliberately follows none. `mvmctl` supplies a transport that does. All
/// verification happens in this module against the source pin, so a transport
/// that returned the wrong bytes is refused rather than trusted.
pub trait BootstrapKernelFetcher: Send + Sync + 'static {
    /// Download `url` to `dest`, following redirects.
    fn fetch(&self, url: &str, dest: &Path) -> Result<(), String>;
}

impl<F> BootstrapKernelFetcher for F
where
    F: Fn(&str, &Path) -> Result<(), String> + Send + Sync + 'static,
{
    fn fetch(&self, url: &str, dest: &Path) -> Result<(), String> {
        self(url, dest)
    }
}

static FETCHER: OnceLock<Box<dyn BootstrapKernelFetcher>> = OnceLock::new();

/// Register the process-wide bootstrap-kernel transport. First registration wins.
pub fn register_bootstrap_kernel_fetcher(fetcher: Box<dyn BootstrapKernelFetcher>) {
    let _ = FETCHER.set(fetcher);
}

/// Where the bootstrap kernel for `arch` is cached.
pub fn bootstrap_kernel_path(cache_dir: &Path, arch: &str) -> PathBuf {
    crate::kernel_fetch::cached_kernel_path(cache_dir, arch, BOOTSTRAP_VARIANT)
}

/// Resolve the pinned bootstrap kernel for `arch` using the process-wide
/// transport.
///
/// Thin wrapper over [`resolve_bootstrap_kernel_with`]; the policy lives there
/// so it is testable without touching global state or the real pins.
pub fn resolve_bootstrap_kernel(
    cache_dir: &Path,
    arch: &str,
) -> Result<VerifiedKernel, Stage0KernelError> {
    let pin = bootstrap_kernel_pin(arch).ok_or_else(|| Stage0KernelError::UnsupportedArch {
        arch: arch.to_string(),
    })?;
    match FETCHER.get() {
        Some(fetcher) => resolve_bootstrap_kernel_with(cache_dir, arch, pin, fetcher.as_ref()),
        // A warm cache that already holds the pinned bytes needs no transport.
        None => {
            cached_pinned_kernel(cache_dir, arch, pin).ok_or_else(|| Stage0KernelError::NoFetcher {
                arch: arch.to_string(),
            })
        }
    }
}

/// Resolve the bootstrap kernel for `arch` against `pin`, downloading it through
/// `fetcher` when the cache does not already hold exactly those bytes.
///
/// Fails closed at every rung. A cached kernel is served only if it matches the
/// pin, not merely its own digest sidecar — a sidecar vouches for whatever was
/// last written, so a kernel from an older pin would otherwise survive a pin
/// bump. Downloaded bytes land in a staging file and reach the cache only after
/// they match the pin; a mismatch is deleted, not kept for a retry to adopt.
pub fn resolve_bootstrap_kernel_with(
    cache_dir: &Path,
    arch: &str,
    pin: &BootstrapKernelPin,
    fetcher: &dyn BootstrapKernelFetcher,
) -> Result<VerifiedKernel, Stage0KernelError> {
    if let Some(verified) = cached_pinned_kernel(cache_dir, arch, pin) {
        return Ok(verified);
    }

    let io = |detail: String| Stage0KernelError::Io {
        arch: arch.to_string(),
        detail,
    };
    let dest = bootstrap_kernel_path(cache_dir, arch);
    let parent = dest
        .parent()
        .ok_or_else(|| io(format!("{} has no parent directory", dest.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| io(format!("creating {}: {e}", parent.display())))?;

    let staging = dest.with_file_name(format!("vmlinux.staging.{}", std::process::id()));
    tracing::info!(arch, url = pin.url, "fetching the Stage 0 bootstrap kernel");
    if let Err(detail) = fetcher.fetch(pin.url, &staging) {
        let _ = std::fs::remove_file(&staging);
        return Err(Stage0KernelError::FetchFailed {
            arch: arch.to_string(),
            detail,
        });
    }

    let actual = sha256_hex_of(&staging).map_err(|e| {
        let _ = std::fs::remove_file(&staging);
        io(format!("hashing {}: {e}", staging.display()))
    })?;
    if !actual.eq_ignore_ascii_case(pin.sha256_hex) {
        let _ = std::fs::remove_file(&staging);
        return Err(Stage0KernelError::PinMismatch {
            arch: arch.to_string(),
            expected: pin.sha256_hex.to_string(),
            actual,
        });
    }

    // Replace the whole entry, so a stale sidecar or digest cache from an
    // earlier pin cannot sit beside the new bytes.
    for stale in kernel_entry_files(&dest) {
        let _ = std::fs::remove_file(stale);
    }
    std::fs::rename(&staging, &dest).map_err(|e| {
        let _ = std::fs::remove_file(&staging);
        io(format!("publishing {}: {e}", dest.display()))
    })?;
    record_kernel_digest(&dest).map_err(|e| io(format!("recording digest: {e}")))?;

    cached_pinned_kernel(cache_dir, arch, pin).ok_or_else(|| {
        io(format!(
            "{} did not verify immediately after publishing",
            dest.display()
        ))
    })
}

/// The cached bootstrap kernel, if it both verifies against its sidecar and
/// matches `pin`. Anything else is evicted so the next resolve re-derives it.
fn cached_pinned_kernel(
    cache_dir: &Path,
    arch: &str,
    pin: &BootstrapKernelPin,
) -> Option<VerifiedKernel> {
    let KernelResolution::Cached(verified) =
        resolve_kernel(cache_dir, arch, BOOTSTRAP_VARIANT, false)
    else {
        return None;
    };
    match sha256_hex_of(verified.path()) {
        Ok(actual) if actual.eq_ignore_ascii_case(pin.sha256_hex) => Some(verified),
        _ => {
            for stale in kernel_entry_files(verified.path()) {
                let _ = std::fs::remove_file(stale);
            }
            None
        }
    }
}

fn sha256_hex_of(path: &Path) -> std::io::Result<String> {
    compute_file_sha256(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A pin over bytes a test controls, so the policy is exercised without the
    /// real release assets.
    fn pin_for(bytes: &[u8]) -> BootstrapKernelPin {
        let digest = hex::encode(Sha256::digest(bytes));
        BootstrapKernelPin {
            url: "https://example.invalid/vmlinux",
            sha256_hex: Box::leak(digest.into_boxed_str()),
        }
    }

    /// A transport that writes fixed bytes, counting its calls.
    struct FakeFetcher {
        bytes: Vec<u8>,
        calls: AtomicUsize,
    }

    impl FakeFetcher {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl BootstrapKernelFetcher for FakeFetcher {
        fn fetch(&self, _url: &str, dest: &Path) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::fs::write(dest, &self.bytes).map_err(|e| e.to_string())
        }
    }

    struct FailingFetcher;

    impl BootstrapKernelFetcher for FailingFetcher {
        fn fetch(&self, _url: &str, _dest: &Path) -> Result<(), String> {
            Err("404 Not Found".to_string())
        }
    }

    fn seed_cache(cache: &Path, arch: &str, bytes: &[u8]) -> PathBuf {
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
        assert_ne!(bootstrap, builder_image_kernel);
        assert!(bootstrap.ends_with("kernels/aarch64/stage0-bootstrap/vmlinux"));
    }

    #[test]
    fn a_cached_kernel_matching_the_pin_is_served_without_fetching() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed_cache(tmp.path(), "aarch64", b"pinned kernel");
        let fetcher = FakeFetcher::new(b"never fetched");

        let verified = resolve_bootstrap_kernel_with(
            tmp.path(),
            "aarch64",
            &pin_for(b"pinned kernel"),
            &fetcher,
        )
        .expect("a pinned cached kernel resolves");

        assert_eq!(verified.path(), path);
        assert_eq!(fetcher.calls(), 0, "a warm cache must not hit the network");
    }

    #[test]
    fn a_cold_cache_fetches_once_and_serves_the_pinned_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(b"published kernel");

        let verified = resolve_bootstrap_kernel_with(
            tmp.path(),
            "aarch64",
            &pin_for(b"published kernel"),
            &fetcher,
        )
        .expect("a cold cache resolves through the fetcher");

        assert_eq!(fetcher.calls(), 1);
        assert_eq!(std::fs::read(verified.path()).unwrap(), b"published kernel");
    }

    /// The property the pin exists for: bytes that are not the pinned kernel
    /// are refused, and nothing is left in the cache for a retry to adopt.
    #[test]
    fn a_download_that_does_not_match_the_pin_is_refused_and_discarded() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(b"a substituted kernel");

        let err = resolve_bootstrap_kernel_with(
            tmp.path(),
            "aarch64",
            &pin_for(b"the pinned kernel"),
            &fetcher,
        )
        .expect_err("unpinned bytes must be refused");

        assert!(
            matches!(err, Stage0KernelError::PinMismatch { .. }),
            "{err:?}"
        );
        let dir = bootstrap_kernel_path(tmp.path(), "aarch64")
            .parent()
            .unwrap()
            .to_path_buf();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "nothing may survive a mismatch: {left:?}");
    }

    /// A digest sidecar vouches for whatever was last written, so it cannot be
    /// what decides: after a pin bump the old kernel still has a valid sidecar.
    #[test]
    fn a_cached_kernel_from_an_older_pin_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        seed_cache(tmp.path(), "aarch64", b"the previous release's kernel");
        let fetcher = FakeFetcher::new(b"the new release's kernel");

        let verified = resolve_bootstrap_kernel_with(
            tmp.path(),
            "aarch64",
            &pin_for(b"the new release's kernel"),
            &fetcher,
        )
        .expect("a pin bump re-fetches");

        assert_eq!(fetcher.calls(), 1);
        assert_eq!(
            std::fs::read(verified.path()).unwrap(),
            b"the new release's kernel"
        );
    }

    #[test]
    fn a_cached_kernel_whose_bytes_changed_is_refetched() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed_cache(tmp.path(), "aarch64", b"pinned kernel");
        std::fs::write(&path, b"tampered on disk").unwrap();
        let fetcher = FakeFetcher::new(b"pinned kernel");

        let verified = resolve_bootstrap_kernel_with(
            tmp.path(),
            "aarch64",
            &pin_for(b"pinned kernel"),
            &fetcher,
        )
        .expect("a tampered entry is evicted and refetched");

        assert_eq!(fetcher.calls(), 1);
        assert_eq!(std::fs::read(verified.path()).unwrap(), b"pinned kernel");
    }

    #[test]
    fn a_failing_fetch_surfaces_the_transports_reason_and_leaves_no_staging_file() {
        let tmp = tempfile::tempdir().unwrap();

        let err = resolve_bootstrap_kernel_with(
            tmp.path(),
            "x86_64",
            &pin_for(b"anything"),
            &FailingFetcher,
        )
        .expect_err("a failing fetch cannot resolve");

        match err {
            Stage0KernelError::FetchFailed { arch, detail } => {
                assert_eq!(arch, "x86_64");
                assert!(detail.contains("404"), "{detail}");
            }
            other => panic!("expected FetchFailed, got {other:?}"),
        }
    }

    /// The classification this module exists for, unchanged by the move to a
    /// source pin: a source checkout still fetches, because nothing can compile
    /// a kernel before the builder exists.
    #[test]
    fn a_source_checkout_still_fetches_the_bootstrap_seed() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            resolve_kernel(tmp.path(), "aarch64", BOOTSTRAP_VARIANT, true),
            KernelResolution::NeedsBuild(_)
        ));
        let fetcher = FakeFetcher::new(b"seed");
        resolve_bootstrap_kernel_with(tmp.path(), "aarch64", &pin_for(b"seed"), &fetcher)
            .expect("the bootstrap seed is fetched regardless of checkout kind");
        assert_eq!(fetcher.calls(), 1);
    }

    #[test]
    fn both_supported_arches_have_a_pin_and_nothing_else_does() {
        assert_eq!(
            bootstrap_kernel_pin("aarch64"),
            Some(&BOOTSTRAP_KERNEL_AARCH64)
        );
        assert_eq!(
            bootstrap_kernel_pin("x86_64"),
            Some(&BOOTSTRAP_KERNEL_X86_64)
        );
        assert_eq!(bootstrap_kernel_pin("riscv64"), None);
    }

    /// A pin that is not a full lowercase SHA-256 could never match, and one
    /// whose URL names the other arch would boot the wrong kernel on a
    /// copy-paste slip.
    #[test]
    fn the_shipped_pins_are_well_formed_and_name_their_own_arch() {
        for (arch, pin) in [
            ("aarch64", &BOOTSTRAP_KERNEL_AARCH64),
            ("x86_64", &BOOTSTRAP_KERNEL_X86_64),
        ] {
            assert_eq!(
                pin.sha256_hex.len(),
                64,
                "{arch}: sha256 must be 64 hex chars"
            );
            assert!(
                pin.sha256_hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{arch}: sha256 must be lowercase hex"
            );
            assert!(pin.url.starts_with("https://"), "{arch}: {}", pin.url);
            assert!(
                pin.url.contains(BOOTSTRAP_KERNEL_RELEASE),
                "{arch}: pin must come from {BOOTSTRAP_KERNEL_RELEASE}: {}",
                pin.url
            );
            assert!(
                pin.url.ends_with(&format!("-{arch}")),
                "{arch}: pin URL names the wrong arch: {}",
                pin.url
            );
        }
        assert_ne!(
            BOOTSTRAP_KERNEL_AARCH64.sha256_hex, BOOTSTRAP_KERNEL_X86_64.sha256_hex,
            "the two arches cannot share one kernel"
        );
    }
}
