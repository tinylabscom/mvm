//! The universal initramfs every rootfs boot needs, resolved and attached to
//! a launch config.
//!
//! It lives here, below both `mvm-hostd` and `mvm-client`, so every launch
//! path attaches it through one implementation.

use anyhow::Result;

const UNCACHED_SOURCE_RUNTIME_FINGERPRINT: &str = "source-runtime-cache-missing";

/// Discard a cached universal initramfs whose recorded source fingerprint no
/// longer matches the checkout it would be attached from. Returns true when a
/// stale artifact was evicted; rejects a corrupt source-runtime cache.
///
/// A source checkout rebuilds its guest binaries when they change, but the
/// initramfs cache is keyed only on `(version, arch)` — so without this it
/// keeps serving the artifact built before the change, and a guest-side fix
/// appears not to have worked. Evicting on a fingerprint mismatch is what
/// makes the next resolve rebuild rather than re-find the stale bytes.
fn evict_stale_universal_initramfs(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> Result<bool> {
    let Some(workspace_root) = mvm_build::image_source::guest_runtime_source_checkout() else {
        return Ok(false);
    };
    let Some(shared_cache_root) = cache_root.parent() else {
        return Ok(false);
    };
    let fingerprint = match mvm_build::guest_runtime::cached_source_guest_runtime(
        shared_cache_root,
        version,
        arch,
        &workspace_root,
    )? {
        Some(runtime) => runtime.digest,
        None => UNCACHED_SOURCE_RUNTIME_FINGERPRINT.to_string(),
    };
    Ok(mvm_build::initramfs::evict_if_source_changed(
        cache_root,
        version,
        arch,
        &fingerprint,
    )?)
}

/// Pure-read probe: would the universal initramfs attach from the cache
/// without building or downloading anything? Applies the same
/// source-fingerprint eviction as the attach path first, so a stale artifact
/// never counts as available.
#[cfg(test)]
fn universal_initramfs_available() -> bool {
    let version = env!("CARGO_PKG_VERSION");
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    let arch = mvm_core::arch::GuestArch::host();
    if evict_stale_universal_initramfs(&cache_root, version, arch).is_err() {
        return false;
    }
    mvm_fs::initramfs::InitramfsResolver::new(&cache_root, version)
        .resolve(&arch.to_string())
        .is_ok()
}

/// Backends that boot a kernel, and so have something to mount an initramfs
/// with.
///
/// The same allow-list shape `attach_runtime_overlay_if_cached_version` uses to
/// gate its own build arm, and for the same reason: resolving falls through to
/// a `cargo zigbuild` of the guest agent on a cold cache. The overlay has been
/// gated since it was written; this leg was not, so every launch resolution
/// under a backend that never starts a guest cross-compiled one anyway. Four
/// mock-backed audit tests spent eight minutes each doing exactly that, because
/// a test sandbox isolates `MVM_HOME` *and* `HOME` — which makes its cache cold
/// and the seed-from-default-cache fallback empty, every time.
///
/// Spelled out rather than derived from a `BackendDescriptor` field, because
/// neither existing field means this. `bundled_kernel` is "brings its own
/// kernel, so there is no on-disk path to hash" and is true for libkrun alone.
/// `tier` is an isolation statement — Tier 3 happens to hold exactly the three
/// backends excluded here, but it holds them because they are test-only or
/// browser-tier, not because they boot no kernel, and a Tier 3 backend that did
/// boot one would quietly lose its initramfs.
///
/// An allow-list rather than a deny-list of the three, because the two fail in
/// opposite directions. A new *booting* backend missing from this list boots
/// without an initramfs and cannot mount its runtime overlay, which the launch
/// path already fails closed on — loudly. A new *non-booting* backend missing
/// from a deny-list would silently cross-compile a guest agent it never runs,
/// which is this bug again, undetected.
pub const KERNEL_BOOTING_HYPERVISORS: [&str; 5] =
    ["firecracker", "hvf", "qemu", "libkrun", "apple-container"];

/// Attach the universal initramfs to a launch on `hypervisor`, resolving it
/// from the cache, the locked image set, or a source-checkout build.
///
/// A rootfs boot cannot come up without it: the initramfs supplies `/init`
/// and mounts the runtime overlay at `/mvm/runtime`, and once it is attached
/// `WorkloadRunner::start_workload` sends `ActivateEnvironment` over vsock
/// after boot. So a rootfs boot whose initramfs cannot be resolved is refused
/// here. A backend that boots no kernel, and a launch with no kernel, have no
/// initramfs leg and are left alone.
///
/// Every launcher calls this one function — the CLI's boot paths, the
/// persistent start, and the in-process local boot in `mvm-hostd` — so a
/// launch's guest runtime does not depend on which of them started it.
///
/// # Errors
/// A rootfs boot whose initramfs could not be resolved.
#[tracing::instrument(skip_all)]
pub fn attach_universal_initramfs_if_cached(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
) -> Result<()> {
    if let Some(pin) = &start_config.bundle_boot_assets {
        anyhow::ensure!(
            pin.arch == mvm_core::arch::GuestArch::host(),
            "bundle boot-assets architecture differs from host"
        );
        let path = start_config
            .initrd_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("verified bundle initrd is missing"))?;
        let digest = mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(path))?;
        anyhow::ensure!(
            digest == pin.initrd_sha256.as_str(),
            "verified bundle initrd changed; refusing runtime fallback"
        );
        return Ok(());
    }
    // `wasm` runs a WASI module directly and `mock` records calls without
    // starting a guest. Neither can mount an initramfs, so attaching one is
    // meaningless and resolving one is pure cost.
    if !KERNEL_BOOTING_HYPERVISORS.contains(&hypervisor) {
        tracing::debug!(hypervisor, "backend boots no kernel; skipping initramfs");
        return Ok(());
    }
    attach_universal_initramfs_with_resolver(start_config, |_env, cache_root, version, arch| {
        if let Ok(artifact) = mvm_fs::initramfs::InitramfsResolver::new(cache_root, version)
            .resolve(&arch.to_string())
        {
            return Ok(artifact);
        }
        mvm_build::initramfs::resolve_image_set_initramfs(
            cache_root,
            &mvm_build::published_image_set::SetMemberCache::locked(),
            arch,
        )
    })
}

fn attach_universal_initramfs_with_resolver(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    resolve: impl FnOnce(
        &crate::host_shell::HostShellEnvironment,
        &std::path::Path,
        &str,
        mvm_core::arch::GuestArch,
    ) -> Result<
        mvm_fs::initramfs::InitramfsArtifact,
        mvm_build::initramfs::InitramfsBuildError,
    >,
) -> Result<()> {
    // No kernel means no initramfs leg (e.g. the wasm backend).
    if start_config.kernel_path.is_none() {
        return Ok(());
    }
    let version = env!("CARGO_PKG_VERSION");
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    let arch = mvm_core::arch::GuestArch::host();
    let env = crate::host_shell::HostShellEnvironment;
    if evict_stale_universal_initramfs(&cache_root, version, arch)? {
        tracing::info!(
            initramfs_version = version,
            "guest sources changed since the cached universal initramfs was built; discarded it"
        );
    }
    match resolve(&env, &cache_root, version, arch) {
        Ok(artifact) => {
            start_config.initrd_path = Some(artifact.image_path.display().to_string());
            tracing::info!(
                initramfs_version = version,
                path = %artifact.image_path.display(),
                "attached universal initramfs"
            );
        }
        Err(e) => {
            // Fail closed. Nothing else mounts the runtime overlay: the guest
            // `/init` baked into a workload rootfs has no code for it, and the
            // `ActivateEnvironment` that does mount it is only sent on the
            // universal-initramfs path. So a rootfs boot without an initramfs
            // reaches PID 1 with an empty `/mvm/runtime` — no agent, no egress
            // client — and dies as a kernel panic the host only sees as a
            // 30-second agent-readiness timeout naming nothing.
            //
            // Swallowing this at debug level is what turned a missing artifact
            // into that timeout. Refuse here, while the resolver's real error
            // is still in hand.
            if initramfs_is_required(start_config) {
                return Err(anyhow::Error::new(e).context(format!(
                    "the universal initramfs {version} for {arch} could not be resolved, and \
                     this workload cannot boot without it: it is what mounts the guest runtime \
                     overlay at /mvm/runtime, which carries the guest agent and the egress \
                     client. Run `mvmctl doctor` to see the artifact state"
                )));
            }
            tracing::debug!(error = %e, "universal initramfs not attached");
        }
    }
    Ok(())
}

/// Whether this launch cannot boot without the universal initramfs.
///
/// True for every boot that has a guest root to mount and expects its runtime
/// binaries from the overlay. A kernel-less shape (wasm) has no initramfs leg
/// at all, and is the only launch that can come up without one.
fn initramfs_is_required(config: &mvm_core::vm_backend::VmStartConfig) -> bool {
    config.kernel_path.is_some() && !config.rootfs_path.is_empty()
}

#[cfg(any(test, feature = "test-support"))]
/// Install a fixture universal initramfs into `<mvm_home>/cache/initramfs`
/// exactly the way the real build/install path lays it out, for a test that
/// boots or composes a launch without building one.
///
/// # Panics
/// When the fixture cannot be written or installed.
pub fn seed_warm_universal_initramfs(mvm_home: &std::path::Path) {
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let source = mvm_home.join("source");
    std::fs::create_dir_all(&source).unwrap();
    // The installer verifies the image against its hash sidecar, so the
    // fixture has to match what the build emits: a real gzip stream, the
    // SHA-256 of the uncompressed payload, and the compressed length.
    let payload = b"cpio-payload";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, payload).unwrap();
    let image = encoder.finish().unwrap();
    std::fs::write(source.join("initramfs.cpio.gz"), &image).unwrap();
    std::fs::write(
        source.join("initramfs.hash"),
        format!(
            "{}\n",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(payload))
        ),
    )
    .unwrap();
    std::fs::write(source.join("initramfs.size"), format!("{}\n", image.len())).unwrap();
    std::fs::write(source.join("VERSION"), version).unwrap();

    let cache_root = mvm_home.join("cache").join("initramfs");
    mvm_build::initramfs::install_initramfs_into_cache(&source, &cache_root, version, arch)
        .unwrap();
    // A warm cache in a source checkout has to say what built it. Without a
    // fingerprint the artifact is of unknown provenance and is discarded —
    // which is the whole point of the eviction, and would make this fixture
    // describe a cache the attach path is right to refuse.
    if let Some(workspace_root) = mvm_build::image_source::guest_runtime_source_checkout() {
        let fingerprint = match mvm_build::guest_runtime::cached_source_guest_runtime(
            &mvm_home.join("cache"),
            version,
            arch,
            &workspace_root,
        ) {
            Ok(Some(runtime)) => runtime.digest,
            _ => UNCACHED_SOURCE_RUNTIME_FINGERPRINT.to_string(),
        };
        mvm_build::initramfs::record_source_fingerprint(&cache_root, version, arch, &fingerprint)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::arch::GuestArch;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::VmStartConfig;

    #[test]
    fn bundle_initrd_is_preserved_and_tampering_never_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("bundle-initrd");
        std::fs::write(&image, b"signed initrd").unwrap();
        let mut config = VmStartConfig {
            initrd_path: Some(image.display().to_string()),
            bundle_boot_assets: Some(mvm_core::vm_backend::BundleBootAssetsPin {
                manifest_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"original set"),
                arch: GuestArch::host(),
                initrd_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"signed initrd"),
            }),
            ..Default::default()
        };
        attach_universal_initramfs_if_cached(&mut config, "firecracker").unwrap();
        assert_eq!(config.initrd_path.as_deref(), image.to_str());
        std::fs::write(&image, b"replaced initrd").unwrap();
        assert!(attach_universal_initramfs_if_cached(&mut config, "firecracker").is_err());
        std::fs::remove_file(&image).unwrap();
        assert!(attach_universal_initramfs_if_cached(&mut config, "firecracker").is_err());
        config.initrd_path = None;
        assert!(attach_universal_initramfs_if_cached(&mut config, "firecracker").is_err());
    }

    /// The resolver failure a cold cache produces, as the real ladder now
    /// reports it (both acquisition arms having failed).
    fn cold_cache_failure() -> mvm_build::initramfs::InitramfsBuildError {
        mvm_build::initramfs::InitramfsBuildError::CargoBuildFailed {
            reason: "automatic warming is disabled in this test".to_string(),
        }
    }

    #[test]
    fn attach_universal_initramfs_if_cached_cold_cache_is_non_fatal_without_a_rootfs() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // HOME moves with MVM_HOME or the cache under test is not cold: the
        // initramfs resolver seeds a miss from `$HOME/.mvm/cache`.
        env.isolate_mvm_home(dir.path());

        // No rootfs and no virtiofs root: an initramfs-only guest boots
        // entirely from RAM, so there is no runtime overlay to strand.
        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            ..Default::default()
        };
        let resolver_called = std::cell::Cell::new(false);
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| {
            resolver_called.set(true);
            Err(cold_cache_failure())
        })
        .unwrap();

        assert!(
            resolver_called.get(),
            "the cold-cache resolver must be called"
        );
        assert!(
            sc.initrd_path.is_none(),
            "a cold-cache resolution failure leaves no initramfs attached"
        );
    }

    #[test]
    fn attach_universal_initramfs_refuses_a_rootfs_boot_that_cannot_resolve_one() {
        // The regression this exists for: the resolver failure used to be
        // swallowed at debug level, so the launch continued with no initramfs.
        // Nothing else mounts the runtime overlay, so PID 1 came up to an empty
        // /mvm/runtime, found neither the agent nor the egress client, exited,
        // and panicked the kernel. The host saw only "guest agent did not
        // become reachable within 30s" — a message naming nothing that was
        // actually wrong.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            rootfs_path: "/cache/oci/rootfs.ext4".to_string(),
            ..Default::default()
        };
        let error = attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| {
            Err(cold_cache_failure())
        })
        .expect_err("a rootfs boot with no resolvable initramfs must refuse");

        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("universal initramfs"),
            "the refusal must name the missing artifact: {rendered}"
        );
        assert!(
            rendered.contains("/mvm/runtime"),
            "the refusal must say what the artifact would have mounted: {rendered}"
        );
        assert!(
            sc.initrd_path.is_none(),
            "a refused launch attaches nothing"
        );
    }

    #[test]
    fn attach_universal_initramfs_still_refuses_a_prefer_overlay_rootfs_boot() {
        // PreferOverlay is the default policy, and it is the one every
        // `machine run --image` launch actually carries into this function on a
        // non-sealed image. It needs the initramfs for exactly the same reason
        // RequiredOverlay does — only RootfsOnly declares a baked-in agent.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            rootfs_path: "/cache/oci/rootfs.ext4".to_string(),
            ..Default::default()
        };
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| Err(cold_cache_failure()))
            .expect_err("PreferOverlay with a rootfs must refuse too");
    }

    #[test]
    fn attach_universal_initramfs_lets_a_kernel_less_launch_through() {
        // A wasm launch has no kernel and therefore no initramfs leg at all.
        // It is the only shape left that can come up without one — every
        // guest that boots a kernel sources its binaries from the overlay,
        // and the initramfs is what mounts it.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: None,
            ..Default::default()
        };
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| Err(cold_cache_failure()))
            .expect("a kernel-less launch needs no initramfs");
        assert!(sc.initrd_path.is_none());
    }

    #[test]
    fn injected_cache_resolver_attaches_an_initramfs() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            ..Default::default()
        };
        attach_universal_initramfs_with_resolver(&mut sc, |_, cache_root, version, arch| {
            mvm_build::initramfs::resolve_or_seed_from_default_cache(cache_root, version, arch)
        })
        .unwrap();

        assert!(
            sc.initrd_path.is_some(),
            "initramfs path should be attached from a warm cache"
        );
        assert!(
            sc.initrd_path
                .as_deref()
                .unwrap()
                .contains("initramfs.cpio.gz"),
            "attached path should point at the cpio.gz image"
        );
    }

    /// A backend that never boots a kernel must not reach the resolver at all.
    ///
    /// Asserting only that `initrd_path` stays `None` would pass for the
    /// expensive reason too — a cold cache leaves it unset after doing the work.
    /// The cost is the resolve, so the resolver itself is what has to stay
    /// untouched. `seed_warm_universal_initramfs` makes the difference
    /// observable: a resolver that ran would find the warm artifact and attach
    /// it.
    #[test]
    fn a_backend_that_boots_no_kernel_never_resolves_an_initramfs() {
        for hypervisor in ["mock", "wasm"] {
            let mut env = TestEnv::new();
            let dir = tempfile::tempdir().unwrap();
            env.isolate_mvm_home(dir.path());
            seed_warm_universal_initramfs(dir.path());

            let mut sc = VmStartConfig {
                kernel_path: Some("/dummy/vmlinux".to_string()),
                ..Default::default()
            };
            attach_universal_initramfs_if_cached(&mut sc, hypervisor).unwrap();

            assert!(
                sc.initrd_path.is_none(),
                "{hypervisor} boots no kernel, so nothing should have resolved \
                 an initramfs — a warm cache was available and was still not read"
            );
        }
    }

    /// Every name the allow-list admits has to be a backend that exists, or the
    /// gate silently stops covering one. The reverse — a booting backend
    /// missing from the list — surfaces as a guest that cannot mount its
    /// runtime overlay, which the launch path already fails closed on.
    #[test]
    fn the_kernel_booting_allow_list_names_only_real_backends() {
        let known: Vec<String> = crate::catalog::descriptors()
            .iter()
            .map(|d| d.instantiate_dyn().name().to_string())
            .collect();
        for name in KERNEL_BOOTING_HYPERVISORS {
            assert!(
                known.iter().any(|k| k == name),
                "{name} is in the kernel-booting allow-list but is not a backend; known: {known:?}"
            );
        }
    }

    #[test]
    fn universal_initramfs_available_true_on_warm_cache() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        assert!(universal_initramfs_available());
    }

    #[test]
    fn universal_initramfs_available_false_on_cold_cache() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // HOME moves with MVM_HOME or the cache under test is not cold: the
        // initramfs resolver seeds a miss from `$HOME/.mvm/cache`.
        env.isolate_mvm_home(dir.path());

        assert!(!universal_initramfs_available());
    }

    #[test]
    fn universal_initramfs_available_false_when_source_fingerprint_is_stale() {
        let Some(_workspace_root) = mvm_build::image_source::guest_runtime_source_checkout() else {
            // Fingerprint eviction only applies to a source checkout.
            return;
        };
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let cache_root = dir.path().join("cache").join("initramfs");
        mvm_build::initramfs::record_source_fingerprint(
            &cache_root,
            version,
            arch,
            "stale-fingerprint",
        )
        .unwrap();

        assert!(!universal_initramfs_available());
        // The probe evicts the stale artifact rather than merely ignoring it,
        // so the attach path never re-finds the same stale bytes.
        assert!(!cache_root.join(version).join(arch.to_string()).exists());
    }
}
