#[cfg(any(feature = "builder-vm", test))]
use super::*;

/// Which custom kernel `mvmctl kernel build` realizes. Each maps to a
/// flake attr on `nix/images/builder-vm` and a cache subdir.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelVariant {
    /// Builder-VM kernel — shared base + virtio-fs / overlay / netfilter
    /// / nix-sandbox infra (`nix/images/builder-vm/kernel`).
    Builder,
    /// Workload-microVM kernel — the shared base alone (`workload-kernel`).
    Workload,
    /// Workload-microVM kernel for in-guest orchestrators (rootless
    /// Kubernetes guests): the base + dm-verity delta plus
    /// cgroup/namespace/netfilter/bridge plumbing (`workload-k8s-kernel`).
    WorkloadK8s,
    /// Generic rootless-container floor (user/mount/PID/IPC/UTS namespaces,
    /// cgroup v2, PTYs, no network namespace). Defined only in the mvm-images
    /// kernel canon; the in-repo flake has no such variant, so a build from
    /// there fails at evaluation naming the missing attr. Used as the
    /// control when bisecting the in-guest-datapath delta.
    Rootless,
}

#[cfg(feature = "builder-vm")]
impl KernelVariant {
    /// Flake attr under `packages.<arch>-linux`.
    fn attr(self) -> &'static str {
        match self {
            Self::Builder => "builder-kernel",
            Self::Workload => "workload-kernel",
            Self::WorkloadK8s => "workload-k8s-kernel",
            Self::Rootless => "rootless-kernel",
        }
    }

    /// Flake attr for the *resolved `.config`* of this kernel. The names are
    /// historically irregular (the builder's predates the workload split), so
    /// they're spelled out rather than derived from `attr()`. Stage 0 realises
    /// this (a cached build dep of the kernel) and copies it out so the host
    /// can report the `=y` symbol count without a CI round-trip.
    fn config_attr(self) -> &'static str {
        match self {
            Self::Builder => "kernel-configfile",
            Self::Workload => "workload-kernel-configfile",
            Self::WorkloadK8s => "workload-k8s-kernel-configfile",
            Self::Rootless => "rootless-kernel-configfile",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Builder => "builder",
            Self::Workload => "workload",
            Self::WorkloadK8s => "workload-k8s",
            Self::Rootless => "rootless",
        }
    }
}

/// A resolved `kernel build` source: the host directory the Stage 0 guest
/// sees at `/work`, the flake attrs to build, and the in-guest flake-base
/// override (when the source is not the in-repo builder-vm flake).
#[cfg(feature = "builder-vm")]
#[derive(Debug)]
struct KernelFlakeSource {
    /// Host directory mounted at `/work` in the Stage 0 guest. For the
    /// in-repo source this is the mvm workspace; for an mvm-images source
    /// it is the checkout's `kernel/` dir, which is the flake root there.
    work_dir: std::path::PathBuf,
    /// `MVM_STAGE0_FLAKE` base (`...#packages`); `None` keeps the guest's
    /// default `path:/work/nix/images/builder-vm#packages`.
    flake_base: Option<String>,
    /// Attr under `packages.<arch>-linux` realizing the kernel image.
    build_attr: String,
    /// Attr under `packages.<arch>-linux` realizing the resolved `.config`.
    config_attr: String,
}

#[cfg(feature = "builder-vm")]
impl KernelFlakeSource {
    /// Attribute names on an `mvm-images` kernel flake: every variant
    /// publishes `<name>-vmlinux` + `<name>-configfile`. The in-repo
    /// workload-k8s variant maps onto the generically-named datapath
    /// kernel there — the guest capability is "in-guest datapath", and
    /// the kernel canon carries no workload name.
    fn for_images_checkout(variant: KernelVariant, kernel_dir: std::path::PathBuf) -> Self {
        let (build_attr, config_attr) = match variant {
            KernelVariant::Builder => ("builder-vmlinux", "builder-configfile"),
            KernelVariant::Workload => ("workload-vmlinux", "workload-configfile"),
            KernelVariant::WorkloadK8s => ("datapath-vmlinux", "datapath-configfile"),
            KernelVariant::Rootless => ("rootless-vmlinux", "rootless-configfile"),
        };
        Self {
            work_dir: kernel_dir,
            flake_base: Some("path:/work#packages".to_string()),
            build_attr: build_attr.to_string(),
            config_attr: config_attr.to_string(),
        }
    }
}

/// Resolve what `kernel build` compiles from. A valid `MVM_IMAGES_DIR`
/// checkout carrying `kernel/flake.nix` wins — the mvm-images kernel canon
/// is the canonical definition while the in-tree flakes migrate out. A
/// configured checkout that fails validation is an error (the same refusal
/// `build image-set` implements), never a silent fallback; a valid checkout
/// without a kernel flake falls back to the in-repo flake with a note, so
/// an older images pin does not break a build that worked in-repo.
#[cfg(feature = "builder-vm")]
fn resolve_kernel_flake_source(variant: KernelVariant) -> Result<KernelFlakeSource> {
    use mvm_build::image_source::{ImageSource, configured_images_dir, resolve_image_source};
    if let Some(configured) = configured_images_dir() {
        let source = resolve_image_source(
            mvm_build::artifact_acquisition::compiled_channel(),
            Some(&configured),
        )?;
        if let ImageSource::LocalCheckout(checkout) = source {
            let kernel_dir = checkout.root().join("kernel");
            if kernel_dir.join("flake.nix").is_file() {
                ui::info(&format!(
                    "kernel source: mvm-images checkout {} (kernel flake)",
                    checkout.root().display()
                ));
                return Ok(KernelFlakeSource::for_images_checkout(variant, kernel_dir));
            }
            ui::info(&format!(
                "mvm-images checkout {} has no kernel/ flake; using the in-repo kernel flake",
                checkout.root().display()
            ));
        }
    }
    let builder_flake_dir = std::path::PathBuf::from(find_builder_vm_flake().map_err(|_| {
        anyhow::anyhow!(
            "`mvmctl kernel build --source compile` needs an mvm source checkout \
             (nix/images/builder-vm/flake.nix) or an mvm-images checkout named by \
             MVM_IMAGES_DIR carrying kernel/flake.nix. From an installed binary, \
             fetch a published kernel with `--source download` instead."
        )
    })?);
    let work_dir = builder_flake_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive workspace root from {}",
                builder_flake_dir.display()
            )
        })?
        .to_path_buf();
    Ok(KernelFlakeSource {
        work_dir,
        flake_base: None,
        build_attr: variant.attr().to_string(),
        config_attr: variant.config_attr().to_string(),
    })
}

/// Where a kernel comes from during builder bootstrap or workload-kernel
/// acquisition. The value comes from `MVM_KERNEL_SOURCE` (set by the global
/// `--kernel-source` flag). `download` uses a published, hash-verified kernel;
/// `compile` realizes it locally through Stage 0; `auto` prefers the published
/// artifact and falls back to a local build when a source checkout is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelSource {
    Compile,
    Download,
    #[cfg(feature = "builder-vm")]
    Auto,
}

#[cfg(feature = "builder-vm")]
pub(crate) fn resolve_kernel_source() -> Option<KernelSource> {
    let raw = std::env::var("MVM_KERNEL_SOURCE").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "compile" => Some(KernelSource::Compile),
        "download" => Some(KernelSource::Download),
        "auto" => Some(KernelSource::Auto),
        other => {
            ui::warn(&format!(
                "ignoring unrecognised MVM_KERNEL_SOURCE={other:?} \
                 (expected compile|download|auto)"
            ));
            None
        }
    }
}

/// Download + SHA-256-verify the published *builder* kernel for `arch`
/// into the per-arch kernel cache, returning its path.
#[cfg(feature = "builder-vm")]
pub(super) fn download_builder_kernel(arch: &str) -> Result<std::path::PathBuf> {
    let dest = mvm_build::kernel_fetch::cached_kernel_path(
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        arch,
        "builder",
    );
    crate::update::download_kernel(arch, "builder", &dest)?;
    Ok(dest)
}

/// Boot Stage 0 to build the builder rootfs *only* (`stage0-rootfs`
/// attr, kernel-less), then pair `external_kernel` as the image's
/// `vmlinux` and write the cache sidecars. This is the
/// `--kernel-source download` path: the builder VM boots on a published
/// kernel without compiling one inside the `default` image.
#[cfg(feature = "builder-vm")]
pub(super) fn run_stage0_rootfs_with_external_kernel(
    staging_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    guest_root_dir: &std::path::Path,
    host_bin_dir: &std::path::Path,
    external_kernel: &std::path::Path,
    source_fingerprint: &str,
    verbose: bool,
) -> std::result::Result<(), (Stage0FailureStage, anyhow::Error)> {
    use mvm_build::builder_backend_select as bbs;

    std::fs::write(
        staging_dir.join("stage0-build.conf"),
        "MVM_STAGE0_BUILD_ATTR=stage0-rootfs\nMVM_STAGE0_OUTPUT_MODE=rootfs\n",
    )
    .map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("writing stage0-build.conf: {e}"),
        )
    })?;

    let selected = bbs::resolve_choice();
    let explicit = bbs::resolve_env_override().is_some();
    bbs::run_with_builder_fallback(selected, explicit, |choice| {
        bbs::resolve_stage0_backend_for_choice(choice, verbose).run_stage0(
            guest_root_dir,
            "/init",
            workspace_root,
            staging_dir,
            host_bin_dir,
        )
    })
    .map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("Stage 0 rootfs build: {e}"),
        )
    })?;

    std::fs::copy(external_kernel, staging_dir.join("vmlinux")).map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("pairing kernel {}: {e}", external_kernel.display()),
        )
    })?;

    verify_stage0_rootfs_has_init(&staging_dir.join("rootfs.ext4"))
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    write_builder_vm_cache_sidecars(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    Ok(())
}

/// Render the compile heartbeat line. Pure (testable); the live
/// heartbeat thread routes it through `ui::notice` (always-on liveness).
#[cfg(feature = "builder-vm")]
pub(super) fn format_compile_elapsed(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    format!("still compiling… ({}m{:02}s elapsed)", secs / 60, secs % 60)
}

#[cfg(feature = "builder-vm")]
pub(super) fn format_compile_start(label: &str, arch: &str) -> String {
    format!(
        "Compiling {label} kernel ({arch}) via Stage 0 — the first build can take several minutes depending on the host; later runs reuse the persistent Nix store."
    )
}

/// `mvmctl kernel build --source compile`: compile a single kernel attr
/// through the Stage 0 nix-seed bootstrap and land its `vmlinux` in the
/// per-arch builder-VM cache. Returns the cached kernel path.
#[cfg(feature = "builder-vm")]
pub(crate) fn build_kernel_via_stage0(
    variant: KernelVariant,
    verbose: bool,
) -> Result<std::path::PathBuf> {
    let source = resolve_kernel_flake_source(variant)?;

    let arch = builder_vm_host_arch();
    let out_dir_buf = mvm_build::kernel_fetch::kernel_cache_dir(
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        arch,
        variant.label(),
    );
    let out_dir_path = out_dir_buf.as_path();
    let out_dir = out_dir_path.display().to_string();
    std::fs::create_dir_all(out_dir_path)
        .with_context(|| format!("creating kernel cache dir {out_dir}"))?;

    let _stage0_guard = acquire_stage0_lock(&out_dir)?;
    let removed = sweep_stage0_staging_siblings(out_dir_path)?;
    if removed > 0 {
        ui::info(&format!(
            "Removed {removed} incomplete Stage 0 kernel build director{} from an earlier interruption.",
            if removed == 1 { "y" } else { "ies" }
        ));
    }

    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let mut request_builder =
        super::stage0_artifact::Stage0ArtifactBuild::builder(&source.work_dir, &staging_dir)
            .build_attr(&source.build_attr)
            .output_mode("kernel")
            .config_attr(&source.config_attr)
            .verbose(verbose);
    if let Some(flake_base) = source.flake_base.as_deref() {
        request_builder = request_builder.flake_base(flake_base);
    }
    let request = request_builder.build()?;

    ui::info(&format_compile_start(variant.label(), arch));

    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = if verbose {
            None
        } else {
            let stop = Arc::clone(&stop);
            Some(std::thread::spawn(move || {
                let start = std::time::Instant::now();
                let mut ticks: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    ticks += 1;
                    if ticks.is_multiple_of(40) {
                        ui::notice(&format_compile_elapsed(start.elapsed()));
                    }
                }
            }))
        };

        let result = request.run();

        stop.store(true, Ordering::Relaxed);
        if let Some(handle) = heartbeat {
            let _ = handle.join();
        }

        result.context("Stage 0 kernel build")?;
    }

    let published = publish_kernel_artifacts(&staging_dir, out_dir_path, variant);
    let _ = std::fs::remove_dir_all(&staging_dir);
    published
}

#[cfg(feature = "builder-vm")]
fn publish_kernel_artifacts(
    staging_dir: &std::path::Path,
    out_dir: &std::path::Path,
    variant: KernelVariant,
) -> Result<std::path::PathBuf> {
    let built = staging_dir.join("vmlinux");
    let kernel_bytes = std::fs::read(&built)
        .with_context(|| format!("reading Stage 0 kernel {}", built.display()))?;
    if kernel_bytes.is_empty() {
        anyhow::bail!("Stage 0 produced an empty kernel at {}", built.display());
    }

    let staged_config = staging_dir.join("mvm-kernel.config");
    let config = std::fs::read_to_string(&staged_config)
        .with_context(|| format!("reading resolved kernel config {}", staged_config.display()))?;
    if workload_config_carries_dm_verity(&config).is_none() {
        anyhow::bail!(
            "Stage 0 produced no usable resolved kernel config at {}",
            staged_config.display()
        );
    }
    if matches!(
        variant,
        KernelVariant::Workload | KernelVariant::WorkloadK8s | KernelVariant::Rootless
    ) && workload_config_carries_dm_verity(&config) != Some(true)
    {
        anyhow::bail!(
            "Stage 0 workload config must contain CONFIG_BLK_DEV_DM=y and CONFIG_DM_VERITY=y"
        );
    }
    let staged_qemu_kernel = staging_dir.join("bzImage");
    let qemu_kernel_bytes = if staged_qemu_kernel.is_file() {
        let bytes = std::fs::read(&staged_qemu_kernel).with_context(|| {
            format!(
                "reading Stage 0 QEMU kernel {}",
                staged_qemu_kernel.display()
            )
        })?;
        if !has_linux_x86_boot_protocol_header(&bytes) {
            anyhow::bail!(
                "Stage 0 QEMU kernel {} has no Linux x86 boot protocol header",
                staged_qemu_kernel.display()
            );
        }
        Some(bytes)
    } else {
        None
    };

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating kernel cache dir {}", out_dir.display()))?;
    let config_dest = out_dir.join("config");
    mvm_core::util::atomic_io::atomic_write(&config_dest, config.as_bytes())
        .with_context(|| format!("publishing kernel config {}", config_dest.display()))?;
    let dest = out_dir.join("vmlinux");
    mvm_core::util::atomic_io::atomic_write(&dest, &kernel_bytes)
        .with_context(|| format!("publishing kernel {}", dest.display()))?;
    let qemu_dest = out_dir.join("bzImage");
    if let Some(bytes) = &qemu_kernel_bytes {
        mvm_core::util::atomic_io::atomic_write(&qemu_dest, bytes)
            .with_context(|| format!("publishing QEMU kernel {}", qemu_dest.display()))?;
    } else {
        let _ = std::fs::remove_file(&qemu_dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(&qemu_dest));
    }

    // A locally built kernel has no published checksum to compare against. The
    // sidecar records the bytes Stage 0 just produced so later reads detect
    // truncation, rot, or replacement. Failure is fatal and evicts the kernel:
    // no producer may leave a path that the verified resolver cannot serve.
    if let Err(error) = mvm_build::kernel_fetch::record_kernel_digest(&dest) {
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&config_dest);
        let _ = std::fs::remove_file(&qemu_dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(&qemu_dest));
        return Err(error).context("recording locally built kernel digest");
    }
    if qemu_kernel_bytes.is_some()
        && let Err(error) = mvm_build::kernel_fetch::record_kernel_digest(&qemu_dest)
    {
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(&dest));
        let _ = std::fs::remove_file(&config_dest);
        let _ = std::fs::remove_file(&qemu_dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(&qemu_dest));
        return Err(error).context("recording locally built QEMU kernel digest");
    }
    Ok(dest)
}

#[cfg(feature = "builder-vm")]
fn has_linux_x86_boot_protocol_header(bytes: &[u8]) -> bool {
    bytes.get(0x202..0x206) == Some(b"HdrS".as_slice())
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::*;

    fn stage_kernel(dir: &std::path::Path, kernel: &[u8], config: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("mvm-kernel.config"), config).unwrap();
    }

    fn bzimage_stub() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x206];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes
    }

    #[test]
    fn workload_publish_requires_dm_verity_config_and_preserves_old_cache_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let live = tmp.path().join("workload");
        stage_kernel(
            &staging,
            b"new kernel",
            "# CONFIG_BLK_DEV_DM is not set\n# CONFIG_DM_VERITY is not set\n",
        );
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("vmlinux"), b"old kernel").unwrap();
        mvm_build::kernel_fetch::record_kernel_digest(&live.join("vmlinux")).unwrap();

        let err = publish_kernel_artifacts(&staging, &live, KernelVariant::Workload).unwrap_err();

        assert!(err.to_string().contains("CONFIG_DM_VERITY=y"));
        assert_eq!(std::fs::read(live.join("vmlinux")).unwrap(), b"old kernel");
        let expected = mvm_fs::overlay::compute_file_sha256(&live.join("vmlinux")).unwrap();
        assert_eq!(
            std::fs::read_to_string(mvm_build::kernel_fetch::kernel_digest_sidecar(
                &live.join("vmlinux")
            ))
            .unwrap()
            .trim(),
            expected
        );
    }

    #[test]
    fn workload_publish_installs_validated_kernel_config_and_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let live = tmp.path().join("workload");
        stage_kernel(
            &staging,
            b"new kernel",
            "CONFIG_MD=y\nCONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n",
        );

        let kernel = publish_kernel_artifacts(&staging, &live, KernelVariant::Workload).unwrap();

        assert_eq!(kernel, live.join("vmlinux"));
        assert_eq!(std::fs::read(&kernel).unwrap(), b"new kernel");
        assert!(
            std::fs::read_to_string(live.join("config"))
                .unwrap()
                .contains("CONFIG_DM_VERITY=y")
        );
        let expected = mvm_fs::overlay::compute_file_sha256(&kernel).unwrap();
        assert_eq!(
            std::fs::read_to_string(mvm_build::kernel_fetch::kernel_digest_sidecar(&kernel))
                .unwrap()
                .trim(),
            expected
        );
    }

    #[test]
    fn workload_publish_retains_verified_qemu_boot_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let live = tmp.path().join("workload");
        stage_kernel(
            &staging,
            b"elf-kernel",
            "CONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n",
        );
        std::fs::write(staging.join("bzImage"), bzimage_stub()).unwrap();

        publish_kernel_artifacts(&staging, &live, KernelVariant::Workload).unwrap();

        let firecracker_kernel = live.join("vmlinux");
        let qemu_kernel = live.join("bzImage");
        assert_eq!(std::fs::read(&qemu_kernel).unwrap(), bzimage_stub());
        let firecracker_sidecar =
            mvm_build::kernel_fetch::kernel_digest_sidecar(&firecracker_kernel);
        let qemu_sidecar = mvm_build::kernel_fetch::kernel_digest_sidecar(&qemu_kernel);
        assert_ne!(firecracker_sidecar, qemu_sidecar);
        let expected_qemu = mvm_fs::overlay::compute_file_sha256(&qemu_kernel).unwrap();
        assert_eq!(
            std::fs::read_to_string(&qemu_sidecar).unwrap().trim(),
            expected_qemu
        );
        let expected_firecracker =
            mvm_fs::overlay::compute_file_sha256(&firecracker_kernel).unwrap();
        assert_eq!(
            std::fs::read_to_string(&firecracker_sidecar)
                .unwrap()
                .trim(),
            expected_firecracker
        );
    }

    #[test]
    fn images_checkout_attr_mapping_covers_every_variant() {
        for (variant, build, config) in [
            (
                KernelVariant::Builder,
                "builder-vmlinux",
                "builder-configfile",
            ),
            (
                KernelVariant::Workload,
                "workload-vmlinux",
                "workload-configfile",
            ),
            (
                KernelVariant::WorkloadK8s,
                "datapath-vmlinux",
                "datapath-configfile",
            ),
            (
                KernelVariant::Rootless,
                "rootless-vmlinux",
                "rootless-configfile",
            ),
        ] {
            let source =
                KernelFlakeSource::for_images_checkout(variant, std::path::PathBuf::from("/k"));
            assert_eq!(source.build_attr, build, "{variant:?}");
            assert_eq!(source.config_attr, config, "{variant:?}");
            assert_eq!(source.flake_base.as_deref(), Some("path:/work#packages"));
            assert_eq!(source.work_dir, std::path::PathBuf::from("/k"));
        }
    }

    fn images_checkout_fixture(dir: &std::path::Path) {
        for marker in mvm_build::image_source::IMAGES_CHECKOUT_MARKERS {
            let path = dir.join(marker);
            std::fs::create_dir_all(path.parent().expect("marker parent")).expect("mkdir");
            std::fs::write(&path, format!("# {marker}\n")).expect("write marker");
        }
        for args in [
            vec!["init", "-q"],
            vec!["add", "-A"],
            vec!["commit", "-q", "-m", "images"],
        ] {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("run git for fixture");
            assert!(out.status.success(), "git fixture: {out:?}");
        }
    }

    #[test]
    fn resolve_prefers_a_kernel_flake_from_the_images_checkout() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        images_checkout_fixture(dir.path());
        env.set(mvm_build::image_source::MVM_IMAGES_DIR_ENV, dir.path());

        let source = resolve_kernel_flake_source(KernelVariant::WorkloadK8s)
            .expect("images checkout resolves");
        // The checkout root is canonicalized (`/var` -> `/private/var` on
        // macOS); the staged kernel dir inherits that.
        let canonical_root = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        assert_eq!(source.work_dir, canonical_root.join("kernel"));
        assert_eq!(source.build_attr, "datapath-vmlinux");
        assert_eq!(source.config_attr, "datapath-configfile");
        assert_eq!(source.flake_base.as_deref(), Some("path:/work#packages"));
    }

    #[test]
    fn resolve_uses_the_in_repo_flake_when_no_checkout_is_configured() {
        let _env = mvm_core::util::test_env::TestEnv::new();

        let source = resolve_kernel_flake_source(KernelVariant::WorkloadK8s)
            .expect("in-repo source resolves in a source checkout");
        assert_eq!(source.flake_base, None);
        assert_eq!(source.build_attr, "workload-k8s-kernel");
        assert_eq!(source.config_attr, "workload-k8s-kernel-configfile");
        assert!(
            source
                .work_dir
                .join("nix/images/builder-vm/flake.nix")
                .is_file()
        );
    }

    #[test]
    fn resolve_refuses_a_checkout_missing_the_kernel_marker() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        images_checkout_fixture(dir.path());
        // Every marker including kernel/flake.nix is part of the checkout
        // identity: dropping one refuses the selection instead of silently
        // building from a half-checked-out tree.
        std::fs::remove_file(dir.path().join("kernel/flake.nix")).expect("remove kernel flake");
        env.set(mvm_build::image_source::MVM_IMAGES_DIR_ENV, dir.path());

        let error = resolve_kernel_flake_source(KernelVariant::Workload)
            .expect_err("a checkout missing a marker must be refused");
        assert!(
            error.to_string().contains("not an mvm-images checkout"),
            "{error:#}"
        );
    }

    #[test]
    fn resolve_refuses_an_invalid_configured_checkout() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            dir.path().join("nope"),
        );

        let error = resolve_kernel_flake_source(KernelVariant::Workload)
            .expect_err("a bogus checkout must not silently fall back");
        assert!(
            error
                .to_string()
                .contains(mvm_build::image_source::MVM_IMAGES_DIR_ENV),
            "{error:#}"
        );
    }

    #[test]
    fn workload_publish_rejects_malformed_qemu_boot_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let live = tmp.path().join("workload");
        stage_kernel(
            &staging,
            b"elf-kernel",
            "CONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n",
        );
        std::fs::write(staging.join("bzImage"), b"not-a-bzimage").unwrap();

        let error = publish_kernel_artifacts(&staging, &live, KernelVariant::Workload)
            .unwrap_err()
            .to_string();

        assert!(error.contains("Linux x86 boot protocol header"));
        assert!(!live.join("vmlinux").exists());
        assert!(!live.join("bzImage").exists());
    }
}
