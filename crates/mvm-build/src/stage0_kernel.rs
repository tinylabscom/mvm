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
//! the same kind of pin — read from `crates/mvm-core/images.lock` through
//! [`bootstrap_kernel_pin`] rather than written out a second time here, because
//! a hand-copied pin beside the boot image's is one that drifts.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use mvm_core::arch::GuestArch;
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

/// The boot-image release the bootstrap kernel pins are taken from, as recorded
/// in `crates/mvm-core/images.lock`.
///
/// It does not have to track the default boot image: Stage 0 needs virtio-blk,
/// vsock and ext4 from this kernel and nothing a newer release is likely to
/// change, which is why the lock pins the two trains separately.
pub fn bootstrap_kernel_release() -> &'static str {
    mvm_core::image_set::image_train_lock()
        .stage0_kernel
        .release_tag
        .as_str()
}

/// Where a bootstrap kernel comes from and what its bytes must hash to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapKernelPin {
    /// Download URL. A GitHub release asset, which redirects — see
    /// [`BootstrapKernelFetcher`] for why that decides which transport fetches it.
    pub url: String,
    /// Lowercase-hex SHA-256 of the kernel bytes. The binding integrity check.
    pub sha256_hex: String,
}

/// Every architecture the lock pins a bootstrap kernel for, resolved once.
///
/// The URL is composed from the locked repository, release tag and asset name
/// rather than stored whole, so a pin cannot name a host the lock does not
/// trust.
static PINS: LazyLock<BTreeMap<GuestArch, BootstrapKernelPin>> = LazyLock::new(|| {
    let lock = mvm_core::image_set::image_train_lock();
    lock.stage0_kernel
        .artifact
        .iter()
        .map(|(arch, artifact)| {
            (
                *arch,
                BootstrapKernelPin {
                    url: lock.asset_url(&lock.stage0_kernel.release_tag, &artifact.name),
                    sha256_hex: artifact.sha256.as_str().to_string(),
                },
            )
        })
        .collect()
});

/// The pin for a guest architecture, or `None` for one Stage 0 does not support.
pub fn bootstrap_kernel_pin(arch: &str) -> Option<&'static BootstrapKernelPin> {
    PINS.get(&arch.parse::<GuestArch>().ok()?)
}

/// Why a bootstrap kernel could not be produced.
#[derive(Debug, Error)]
pub enum Stage0KernelError {
    /// The pinned set cannot communicate with this host. This is checked before
    /// consulting the cache or transport so incompatible bytes are never
    /// acquired speculatively.
    #[error("the pinned image set is incompatible with this host: {detail}")]
    ProtocolIncompatible { detail: String },

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
    ensure_locked_image_set_compatible()?;
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

/// Compatibility range compiled into the host and builder cache implementation.
pub fn current_image_set_protocol_support() -> mvm_core::image_set::HostProtocolSupport {
    mvm_core::image_set::HostProtocolSupport {
        guest_agent_protocol: mvm_core::image_set::ProtocolRange::new(
            mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
            mvm_agentd::vsock::PROTOCOL_VERSION,
        )
        .expect("the compiled guest-agent protocol range must be ordered"),
        builder_cache_contract: crate::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION,
    }
}

/// Refuse the locked set before any member acquisition when protocols diverge.
pub fn ensure_locked_image_set_compatible() -> Result<(), Stage0KernelError> {
    let lock = mvm_core::image_set::image_train_lock();
    mvm_core::image_set::check_declared_protocol_compatibility(
        &lock.compatibility,
        &current_image_set_protocol_support(),
    )
    .map_err(|error| Stage0KernelError::ProtocolIncompatible {
        detail: error.to_string(),
    })
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
    let lock = mvm_core::image_set::image_train_lock();
    resolve_bootstrap_kernel_with_compatibility(
        cache_dir,
        arch,
        pin,
        fetcher,
        &lock.compatibility,
        &current_image_set_protocol_support(),
    )
}

fn resolve_bootstrap_kernel_with_compatibility(
    cache_dir: &Path,
    arch: &str,
    pin: &BootstrapKernelPin,
    fetcher: &dyn BootstrapKernelFetcher,
    declared: &mvm_core::image_set::ImageSetCompatibility,
    host: &mvm_core::image_set::HostProtocolSupport,
) -> Result<VerifiedKernel, Stage0KernelError> {
    mvm_core::image_set::check_declared_protocol_compatibility(declared, host).map_err(
        |error| Stage0KernelError::ProtocolIncompatible {
            detail: error.to_string(),
        },
    )?;
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
    tracing::info!(arch, url = %pin.url, "fetching the Stage 0 bootstrap kernel");
    if let Err(detail) = fetcher.fetch(&pin.url, &staging) {
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
    if !actual.eq_ignore_ascii_case(&pin.sha256_hex) {
        let _ = std::fs::remove_file(&staging);
        return Err(Stage0KernelError::PinMismatch {
            arch: arch.to_string(),
            expected: pin.sha256_hex.clone(),
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
        Ok(actual) if actual.eq_ignore_ascii_case(&pin.sha256_hex) => Some(verified),
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
        BootstrapKernelPin {
            url: "https://example.invalid/vmlinux".to_string(),
            sha256_hex: hex::encode(Sha256::digest(bytes)),
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

    #[test]
    fn an_incompatible_lock_is_refused_before_the_transport_is_called() {
        let incompatible = mvm_core::image_set::ImageSetCompatibility {
            guest_agent_protocol: mvm_core::image_set::ProtocolRange::new(99, 100).unwrap(),
            builder_cache_contract: crate::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION,
        };
        let fetcher = FakeFetcher::new(b"must not be fetched");
        let host = current_image_set_protocol_support();
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_bootstrap_kernel_with_compatibility(
            tmp.path(),
            "aarch64",
            &pin_for(b"must not be fetched"),
            &fetcher,
            &incompatible,
            &host,
        )
        .expect_err("disjoint protocols must refuse");
        assert!(matches!(
            err,
            Stage0KernelError::ProtocolIncompatible { .. }
        ));
        assert_eq!(
            fetcher.calls(),
            0,
            "protocol refusal must precede acquisition"
        );
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
        assert!(bootstrap_kernel_pin("aarch64").is_some());
        assert!(bootstrap_kernel_pin("x86_64").is_some());
        assert_eq!(bootstrap_kernel_pin("riscv64"), None);
    }

    /// The pins are derived from the lock, so nothing else may decide the
    /// release they come from: a Stage 0 kernel fetched from one release and a
    /// digest copied from another is a fetch that can never succeed.
    #[test]
    fn the_shipped_pins_come_from_the_locked_stage0_release() {
        let locked = mvm_core::image_set::image_train_lock();
        assert_eq!(
            bootstrap_kernel_release(),
            locked.stage0_kernel.release_tag.as_str()
        );
        for arch in ["aarch64", "x86_64"] {
            let pin = bootstrap_kernel_pin(arch).expect("a pin per supported arch");
            let parsed: GuestArch = arch.parse().expect("a supported arch parses");
            assert_eq!(
                pin.url,
                locked.stage0_kernel_url(parsed).expect("a locked URL"),
                "{arch}: the pin URL must be the one the lock composes"
            );
        }
    }

    /// A pin that is not a full lowercase SHA-256 could never match, and one
    /// whose URL names the other arch would boot the wrong kernel on a
    /// copy-paste slip.
    #[test]
    fn the_shipped_pins_are_well_formed_and_name_their_own_arch() {
        for arch in ["aarch64", "x86_64"] {
            let pin = bootstrap_kernel_pin(arch).expect("a pin per supported arch");
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
                pin.url.contains(bootstrap_kernel_release()),
                "{arch}: pin must come from {}: {}",
                bootstrap_kernel_release(),
                pin.url
            );
            assert!(
                pin.url.ends_with(&format!("-{arch}")),
                "{arch}: pin URL names the wrong arch: {}",
                pin.url
            );
        }
        assert_ne!(
            bootstrap_kernel_pin("aarch64")
                .expect("aarch64 pin")
                .sha256_hex,
            bootstrap_kernel_pin("x86_64")
                .expect("x86_64 pin")
                .sha256_hex,
            "the two arches cannot share one kernel"
        );
    }
}
