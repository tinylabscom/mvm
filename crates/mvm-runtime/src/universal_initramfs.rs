//! The universal initramfs every rootfs boot needs, resolved and attached to
//! a launch config.
//!
//! It lives here, below both `mvm-hostd` and `mvm-client`, so every launch
//! path attaches it through one implementation.

use anyhow::{Context, Result};

const UNCACHED_SOURCE_RUNTIME_FINGERPRINT: &str = "source-runtime-cache-missing";

/// Discard a cached universal initramfs whose recorded source fingerprint no
/// longer matches the checkout it would be attached from. Returns true when a
/// stale artifact was evicted; rejects a source pointer that is not a digest.
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
    // Provenance only: the cached initramfs is kept when it was built from
    // the runtime this tree records, and nothing is read from that runtime
    // here, so its archive is not opened. Verifying it on every launch cost
    // a contributor build more than a third of the warm-launch budget.
    let fingerprint = mvm_build::guest_runtime::source_guest_runtime_digest(
        shared_cache_root,
        version,
        arch,
        &workspace_root,
    )?
    .unwrap_or_else(|| UNCACHED_SOURCE_RUNTIME_FINGERPRINT.to_string());
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
    if start_config.legacy_portable_runtime.is_some() {
        crate::runtime_evidence::verify_runtime_for_launch(
            start_config,
            crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        )?;
        return Ok(());
    }
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
    if let Some(proof) = &start_config.runtime_release_proof {
        // Owned, because `start_config` is borrowed mutably below.
        let version = start_config
            .runtime_overlay_version
            .clone()
            .context("signed runtime selection has no overlay version")?;
        let arch = mvm_core::arch::GuestArch::host();
        let verified = mvm_build::guest_runtime::evidence::verify_runtime_release_proof(
            proof, &version, arch,
        )?;
        let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
        let declared = verified.declaration(arch)?.initramfs_sha256.clone();
        attach_declared_release_initramfs(start_config, &declared, &cache, &version, arch)?;
        return Ok(());
    }
    anyhow::ensure!(
        start_config.runtime_overlay_path.is_none() || start_config.unsigned_runtime_development,
        "external runtime overlay has no signed release proof"
    );
    if start_config.unsigned_runtime_development {
        let version = start_config
            .runtime_overlay_version
            .as_deref()
            .context("source runtime selection has no overlay version")?;
        let arch = mvm_core::arch::GuestArch::host();
        let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
        let checked =
            mvm_build::guest_runtime::source::check_source_runtime(&cache, version, arch)?;
        anyhow::ensure!(
            start_config.source_runtime_archive_sha256.as_deref() == Some(checked.archive_sha256()),
            "source runtime archive changed after overlay selection; refusing initramfs fallback"
        );
        let artifact = resolve_cached_initramfs(&cache.join("initramfs"), version, arch)
            .context("source initramfs is not prepared; run `mvmctl bootstrap` first")?;
        anyhow::ensure!(
            mvm_core::crypto::verified_digest::sha256_file_verified(&artifact.image_path)?
                == checked.declaration(arch)?.initramfs_sha256,
            "prepared initramfs differs from the selected source runtime"
        );
        start_config.initrd_path = Some(artifact.image_path.display().to_string());
        return Ok(());
    }
    attach_universal_initramfs_with_resolver(start_config, |_env, cache_root, version, arch| {
        resolve_cached_initramfs(cache_root, version, arch)
    })
}

/// Point `start_config` at the initramfs a signed release declares.
///
/// Keep an initramfs already selected (a portable bundle's own copy) only when
/// it is the exact one the signed archive declares; otherwise require the
/// prepared one under `cache_root`, never re-resolving a channel or assembling
/// a missing piece during startup. Split from [`attach_universal_initramfs_if_cached`]
/// so the choice can be exercised with a declared digest: the proof that
/// yields one is real Sigstore verification, which a unit test cannot mint.
fn attach_declared_release_initramfs(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    declared_sha256: &str,
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> Result<()> {
    let selected =
        select_release_initramfs(start_config.initrd_path.as_deref(), declared_sha256, || {
            resolve_cached_initramfs(&cache_root.join("initramfs"), version, arch)
                .map(|artifact| artifact.image_path)
                .context("selected release initramfs is not prepared; run `mvmctl bootstrap` first")
        })?;
    start_config.initrd_path = Some(selected);
    Ok(())
}

/// The initramfs a signed-release launch boots: the one already selected when
/// its digest is the signed declaration's, else the prepared cached one, which
/// must match it too. A selected file that is unreadable or differs is not
/// trusted and not an error by itself; the cached copy is held to the same bar.
///
/// The digest check here is a pre-check. `RuntimeLifecycleLease::bind` is the
/// custody point: it snapshots the selected artifacts and re-verifies them
/// against the declaration before the backend spawns, so a file swapped after
/// this returns is still caught.
fn select_release_initramfs(
    selected: Option<&str>,
    declared_sha256: &str,
    cached: impl FnOnce() -> Result<std::path::PathBuf>,
) -> Result<String> {
    if let Some(path) = selected
        && mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(path))
            .is_ok_and(|digest| digest == declared_sha256)
    {
        return Ok(path.to_owned());
    }
    let path = cached()?;
    anyhow::ensure!(
        mvm_core::crypto::image_verify::sha256_file(&path)? == declared_sha256,
        "prepared initramfs differs from the selected runtime archive"
    );
    Ok(path.display().to_string())
}

/// The initramfs a launch attaches, from the cache alone: the version-keyed
/// one this CLI assembled from its own guest runtime. There is no other copy
/// to fall back to; a miss names the command that assembles it.
fn resolve_cached_initramfs(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> Result<mvm_fs::initramfs::InitramfsArtifact, mvm_build::initramfs::InitramfsBuildError> {
    mvm_fs::initramfs::InitramfsResolver::new(cache_root, version)
        .resolve(&arch.to_string())
        .map_err(mvm_build::initramfs::InitramfsBuildError::from)
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
    let selected_version = start_config
        .runtime_overlay_version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let version = selected_version.as_str();
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
                     client. Run `mvmctl bootstrap` to assemble it from this CLI's guest \
                     runtime, or `mvmctl doctor` to see the artifact state"
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
    fn release_initramfs_selection_keeps_only_a_digest_matching_selected_file() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("bundle-initrd");
        let cached = dir.path().join("cached-initrd");
        std::fs::write(&good, b"signed").unwrap();
        std::fs::write(&cached, b"other").unwrap();
        let signed = mvm_core::crypto::image_verify::sha256_file(&good).unwrap();
        let cached_fn = || Ok(cached.clone());

        // (1) matching bundle copy is kept although the cache differs.
        let kept = select_release_initramfs(good.to_str(), &signed, || {
            panic!("cache must not be consulted")
        })
        .unwrap();
        assert_eq!(kept, good.display().to_string());

        // (2) a differing selected file is never used; the cache is refused too.
        let bad = dir.path().join("tampered");
        std::fs::write(&bad, b"tampered").unwrap();
        let err = select_release_initramfs(bad.to_str(), &signed, cached_fn).unwrap_err();
        assert!(
            err.to_string()
                .contains("differs from the selected runtime archive")
        );

        // ...but a matching cached copy is accepted in its place.
        std::fs::write(&cached, b"signed").unwrap();
        let used = select_release_initramfs(bad.to_str(), &signed, cached_fn).unwrap();
        assert_eq!(used, cached.display().to_string());

        // (3) missing or absent selection falls back and refuses as before.
        std::fs::write(&cached, b"other").unwrap();
        for sel in [Some("/nonexistent/initrd"), None] {
            let err = select_release_initramfs(sel, &signed, cached_fn).unwrap_err();
            assert!(
                err.to_string()
                    .contains("differs from the selected runtime archive")
            );
        }
        let err =
            select_release_initramfs(None, &signed, || anyhow::bail!("not prepared")).unwrap_err();
        assert!(err.to_string().contains("not prepared"));
    }

    /// What a launch sees when a bundle seals its own initramfs but the home's
    /// cache holds one assembled from a different archive: the v0.24.1 macOS e2e
    /// failure. The signed declaration names the bundle's copy.
    fn bundle_and_stale_cached_initramfs(
        home: &std::path::Path,
    ) -> (std::path::PathBuf, String, std::path::PathBuf) {
        seed_warm_universal_initramfs(home);
        let version = env!("CARGO_PKG_VERSION");
        let cached =
            mvm_fs::initramfs::InitramfsResolver::new(home.join("cache/initramfs"), version)
                .resolve(&GuestArch::host().to_string())
                .expect("the seeded cache resolves")
                .image_path;
        let bundle = home.join("bundle-initrd");
        std::fs::write(&bundle, b"initramfs sealed with the bundle").unwrap();
        let declared = mvm_core::crypto::image_verify::sha256_file(&bundle).unwrap();
        assert_ne!(
            declared,
            mvm_core::crypto::image_verify::sha256_file(&cached).unwrap(),
            "the cached initramfs must differ from the bundle's for this to mean anything"
        );
        (bundle, declared, cached)
    }

    #[test]
    fn a_bundle_initramfs_matching_the_signed_declaration_is_kept_over_a_stale_cached_one() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (bundle, declared, _cached) = bundle_and_stale_cached_initramfs(home.path());
        let mut config = VmStartConfig {
            kernel_path: Some("/mock/kernel".into()),
            initrd_path: Some(bundle.display().to_string()),
            ..Default::default()
        };
        attach_declared_release_initramfs(
            &mut config,
            &declared,
            &home.path().join("cache"),
            env!("CARGO_PKG_VERSION"),
            GuestArch::host(),
        )
        .expect("the bundle's initramfs is the declared one");
        assert_eq!(config.initrd_path.as_deref(), bundle.to_str());
    }

    #[test]
    fn a_bundle_initramfs_that_differs_from_the_signed_declaration_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (bundle, declared, cached) = bundle_and_stale_cached_initramfs(home.path());
        std::fs::write(&bundle, b"initramfs swapped after sealing").unwrap();
        let mut config = VmStartConfig {
            kernel_path: Some("/mock/kernel".into()),
            initrd_path: Some(bundle.display().to_string()),
            ..Default::default()
        };
        let error = attach_declared_release_initramfs(
            &mut config,
            &declared,
            &home.path().join("cache"),
            env!("CARGO_PKG_VERSION"),
            GuestArch::host(),
        )
        .expect_err("a differing bundle initramfs must not boot");
        assert!(
            error
                .to_string()
                .contains("differs from the selected runtime archive"),
            "{error:#}"
        );
        assert_eq!(
            config.initrd_path.as_deref(),
            bundle.to_str(),
            "a refusal leaves the selection as it was"
        );
        // The stale cached copy is held to the same bar and is not a way around it.
        assert_ne!(config.initrd_path.as_deref(), cached.to_str());
    }

    #[test]
    fn no_bundle_initramfs_uses_the_prepared_one_only_when_it_matches_the_declaration() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (_bundle, declared, cached) = bundle_and_stale_cached_initramfs(home.path());
        let cached_digest = mvm_core::crypto::image_verify::sha256_file(&cached).unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let cache = home.path().join("cache");

        let mut config = VmStartConfig::default();
        let error = attach_declared_release_initramfs(
            &mut config,
            &declared,
            &cache,
            version,
            GuestArch::host(),
        )
        .expect_err("a prepared initramfs for a different archive is refused");
        assert!(error.to_string().contains("differs"), "{error:#}");
        assert!(config.initrd_path.is_none());

        let mut config = VmStartConfig::default();
        attach_declared_release_initramfs(
            &mut config,
            &cached_digest,
            &cache,
            version,
            GuestArch::host(),
        )
        .expect("the prepared initramfs is the declared one");
        assert_eq!(config.initrd_path.as_deref(), cached.to_str());
    }

    #[test]
    fn source_initramfs_must_match_the_original_overlay_archive_selection() {
        if !mvm_build::artifact_acquisition::compiled_channel().permits_automatic_builds() {
            return;
        }
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let cache = home.path().join("cache");
        let workspace = mvm_build::image_source::guest_runtime_source_checkout().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
            &cache, &workspace, version, arch,
        )
        .unwrap();
        let artifact = mvm_build::initramfs::build_initramfs_from_guest_runtime(
            &cache.join("initramfs"),
            version,
            arch,
            &runtime,
        )
        .unwrap();
        let mut config = VmStartConfig {
            kernel_path: Some("/mock/kernel".into()),
            runtime_overlay_path: Some("/mock/overlay".into()),
            runtime_overlay_version: Some(version.into()),
            unsigned_runtime_development: true,
            source_runtime_archive_sha256: Some("0".repeat(64)),
            ..Default::default()
        };
        let error = attach_universal_initramfs_if_cached(&mut config, "firecracker").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("archive changed after overlay selection")
        );
        assert!(config.initrd_path.is_none());

        config.source_runtime_archive_sha256 = Some(runtime.digest);
        attach_universal_initramfs_if_cached(&mut config, "firecracker").unwrap();
        assert_eq!(config.initrd_path.as_deref(), artifact.image_path.to_str());
    }

    #[test]
    fn selected_external_runtime_without_proof_cannot_resolve_another_initramfs() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let mut config = VmStartConfig {
            kernel_path: Some("/mock/kernel".into()),
            runtime_overlay_path: Some("/mock/overlay".into()),
            ..Default::default()
        };
        let error = attach_universal_initramfs_if_cached(&mut config, "firecracker").unwrap_err();
        assert!(error.to_string().contains("no signed release proof"));
        assert!(config.initrd_path.is_none());
    }

    #[test]
    fn selected_runtime_wrong_version_or_architecture_refuses_before_initramfs_resolution() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        for (version, arch) in [
            ("stale", GuestArch::host()),
            (
                "selected",
                match GuestArch::host() {
                    GuestArch::X86_64 => GuestArch::Aarch64,
                    GuestArch::Aarch64 => GuestArch::X86_64,
                },
            ),
        ] {
            let mut config = VmStartConfig {
                kernel_path: Some("/mock/kernel".into()),
                runtime_overlay_path: Some("/mock/overlay".into()),
                runtime_overlay_version: Some("selected".into()),
                runtime_release_proof: Some(
                    mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                        archive: "/mock/archive".into(),
                        checksum: "/mock/checksum".into(),
                        signature_bundle: "/mock/bundle".into(),
                        archive_sha256: "a".repeat(64),
                        version: version.into(),
                        arch,
                    },
                ),
                unsigned_runtime_development: true,
                ..Default::default()
            };
            let error =
                attach_universal_initramfs_if_cached(&mut config, "firecracker").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("selected version and guest architecture")
            );
            assert!(config.initrd_path.is_none());
        }
    }

    #[test]
    fn warm_initramfs_cannot_mask_a_rejected_release() {
        for failure in ["corrupt", "unsigned", "wrong-version"] {
            let home = tempfile::tempdir().unwrap();
            let mut env = TestEnv::new();
            env.isolate_mvm_home(home.path());
            seed_warm_universal_initramfs(home.path());
            let cache = home.path().join("cache");
            let version = env!("CARGO_PKG_VERSION");
            let release = cache.join("guest-runtime/releases").join(version);
            std::fs::create_dir_all(&release).unwrap();
            let asset_version = if failure == "wrong-version" {
                "0.0.0-wrong"
            } else {
                version
            };
            let asset = format!("mvm-guest-bins-v{asset_version}.tar.gz");
            let bytes = b"unsigned runtime";
            std::fs::write(release.join(&asset), bytes).unwrap();
            let digest = if failure == "corrupt" {
                "0".repeat(64)
            } else {
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes))
            };
            std::fs::write(
                release.join(format!("{asset}.sha256")),
                format!("{digest}  {asset}\n"),
            )
            .unwrap();
            if failure != "unsigned" {
                std::fs::write(release.join(format!("{asset}.bundle")), b"invalid bundle").unwrap();
            }
            assert!(
                mvm_fs::initramfs::InitramfsResolver::new(cache.join("initramfs"), version)
                    .resolve(&GuestArch::host().to_string())
                    .is_ok()
            );
            mvm_build::guest_runtime::cached_runtime_release_proof(
                &cache,
                version,
                GuestArch::host(),
            )
            .expect_err("a warm initramfs must not bypass released archive verification");
        }
    }

    #[test]
    fn bundle_initrd_is_preserved_and_tampering_never_falls_back() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
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
    /// The image set carries no guest runtime, so a launch never attaches an
    /// initramfs an older CLI installed from it: with only that copy on disk,
    /// the resolve misses, whether or not this version adopted a release
    /// guest runtime.
    #[test]
    fn a_launch_never_attaches_the_image_sets_initramfs() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let initramfs_cache = cache.join("initramfs");
        let arch = GuestArch::host();
        let version = env!("CARGO_PKG_VERSION");
        let set = mvm_build::published_image_set::SetMemberCache::locked();
        let staged = tmp.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        let payload = b"cpio-payload";
        let image = {
            use std::io::Write as _;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(payload).unwrap();
            gz.finish().unwrap()
        };
        std::fs::write(staged.join(mvm_fs::initramfs::INITRAMFS_IMAGE_FILE), &image).unwrap();
        std::fs::write(
            staged.join(mvm_fs::initramfs::INITRAMFS_HASH_FILE),
            format!(
                "{}\n",
                mvm_core::packs::Sha256Hex::from_bytes(payload).as_str()
            ),
        )
        .unwrap();
        std::fs::write(
            staged.join(mvm_fs::initramfs::INITRAMFS_SIZE_FILE),
            format!("{}\n", image.len()),
        )
        .unwrap();
        std::fs::write(
            staged.join(mvm_fs::initramfs::VERSION_FILE),
            format!("{version}\n"),
        )
        .unwrap();
        mvm_build::initramfs::install_initramfs_into_cache(
            &staged,
            &set.cache_root(&initramfs_cache),
            version,
            arch,
        )
        .unwrap();
        set.record(
            &initramfs_cache,
            mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
            mvm_core::image_set::MemberTarget::Arch(arch),
            &mvm_build::published_image_set::MemberVersion::parse(version).unwrap(),
        )
        .unwrap();

        resolve_cached_initramfs(&initramfs_cache, version, arch)
            .expect_err("the image set's initramfs is not this CLI's");
        let record = mvm_build::runtime_pieces::release_adoption_record(&cache, version, arch);
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::write(&record, format!("{}\n", "e".repeat(64))).unwrap();
        resolve_cached_initramfs(&initramfs_cache, version, arch)
            .expect_err("an adopted release has nothing else to attach either");
    }

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
