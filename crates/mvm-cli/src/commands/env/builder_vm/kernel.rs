#[cfg(any(feature = "builder-vm", test))]
use super::*;

/// Which custom kernel `mvmctl kernel build` realizes. Each maps to a
/// variant of the `mvm-images` kernel flake and a cache subdir.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelVariant {
    /// Builder-VM kernel — shared base + overlay / netfilter / nix-sandbox
    /// infra.
    Builder,
    /// Workload-microVM kernel — the shared base plus dm-verity.
    Workload,
    /// Workload-microVM kernel for in-guest orchestrators (rootless
    /// Kubernetes guests). The `mvm-images` kernel canon deliberately does
    /// not define it, so there is nothing to build it from; a request is
    /// refused with the reason.
    WorkloadK8s,
    /// Generic rootless-container floor (user/mount/PID/IPC/UTS namespaces,
    /// cgroup v2, PTYs, no network namespace). Used as the control when
    /// bisecting the in-guest-datapath delta.
    Rootless,
}

#[cfg(feature = "builder-vm")]
impl KernelVariant {
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
/// sees at `/work`, the flake it builds there, and the flake attrs to build.
#[cfg(feature = "builder-vm")]
#[derive(Debug)]
struct KernelFlakeSource {
    /// Host directory mounted at `/work` in the Stage 0 guest: the image
    /// checkout's `kernel/` dir, which is the flake root there.
    work_dir: std::path::PathBuf,
    /// `MVM_STAGE0_FLAKE` base (`...#packages`) naming the staged flake.
    flake_base: String,
    /// Attr under `packages.<arch>-linux` realizing the kernel image.
    build_attr: String,
    /// Attr under `packages.<arch>-linux` realizing the resolved `.config`.
    config_attr: String,
}

#[cfg(feature = "builder-vm")]
impl KernelFlakeSource {
    /// Attribute names on an `mvm-images` kernel flake: every variant
    /// publishes `<name>-vmlinux` + `<name>-configfile`.
    ///
    /// `WorkloadK8s` deliberately has no mapping: the in-guest-orchestrator
    /// kernel needs an in-guest datapath (bridge/veth/netfilter), and the
    /// mvm-images canon refuses guest network devices as a permanent
    /// invariant. The durable consumer shape per that invariant is host
    /// networking inside the guest plus the loopback/vsock egress proxy,
    /// which needs no datapath kernel.
    fn for_images_checkout(variant: KernelVariant, kernel_dir: std::path::PathBuf) -> Result<Self> {
        let (build_attr, config_attr) = match variant {
            KernelVariant::Builder => ("builder-vmlinux", "builder-configfile"),
            KernelVariant::Workload => ("workload-vmlinux", "workload-configfile"),
            KernelVariant::WorkloadK8s => {
                anyhow::bail!(
                    "the in-guest-orchestrator kernel is not defined in the mvm-images \
                     kernel canon (guest network devices violate its permanent invariant), \
                     and image construction lives in mvm-images, so there is no source to \
                     build it from; use --which rootless for the NIC-less floor"
                )
            }
            KernelVariant::Rootless => ("rootless-vmlinux", "rootless-configfile"),
        };
        Ok(Self {
            work_dir: kernel_dir,
            flake_base: "path:/work#packages".to_string(),
            build_attr: build_attr.to_string(),
            config_attr: config_attr.to_string(),
        })
    }
}

/// Resolve what `kernel build` compiles from, through the same image-source
/// precedence every other image consumer uses: a configured `MVM_IMAGES_DIR`
/// (strict — an invalid one is an error, never a fallback), then a sibling
/// `mvm-images` checkout. Without either there is nothing to compile from.
#[cfg(feature = "builder-vm")]
fn resolve_kernel_flake_source(variant: KernelVariant) -> Result<KernelFlakeSource> {
    let source = mvm_build::image_source::resolve_current_source()?;
    kernel_flake_source_for(variant, &source)
}

/// Map a selected image source onto the kernel flake to build. A local
/// checkout's `kernel/` flake is its kernel canon (`kernel/flake.nix` is a
/// checkout marker, so a valid checkout always carries it). The released set
/// carries built kernels, not their sources, so a compile without a checkout
/// is refused.
#[cfg(feature = "builder-vm")]
fn kernel_flake_source_for(
    variant: KernelVariant,
    source: &mvm_build::image_source::ImageSource,
) -> Result<KernelFlakeSource> {
    use mvm_build::image_source::{ImageConstructionRefused, ImageSource};
    match source {
        ImageSource::LocalCheckout(checkout) => {
            ui::info(&format!(
                "kernel source: mvm-images checkout {} (kernel flake)",
                checkout.root().display()
            ));
            KernelFlakeSource::for_images_checkout(variant, checkout.root().join("kernel"))
        }
        ImageSource::Released => {
            Err(ImageConstructionRefused::new(format!("the {} kernel", variant.label())).into())
        }
    }
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

#[cfg(feature = "builder-vm")]
pub(super) fn format_compile_start(label: &str, arch: &str) -> String {
    format!(
        "Compiling {label} kernel ({arch}) via Stage 0 — the first build can take several minutes depending on the host; later runs reuse the persistent Nix store"
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

    let _stage0_guard =
        acquire_stage0_lock(&out_dir, &format!("the {} kernel build", variant.label()))?;
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

    let request =
        super::stage0_artifact::Stage0ArtifactBuild::builder(&source.work_dir, &staging_dir)
            .build_attr(&source.build_attr)
            .output_mode("kernel")
            .config_attr(&source.config_attr)
            .flake_base(&source.flake_base)
            .verbose(verbose)
            .build()?;

    // Live at every verbosity: the builder runner nests the in-guest nix
    // progress under this line, and `-v` adds the raw build log above it.
    let phase = mvm_runtime::ui::activity::start(format_compile_start(variant.label(), arch));
    request.run().context("Stage 0 kernel build")?;
    phase.finish();

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
                KernelVariant::Rootless,
                "rootless-vmlinux",
                "rootless-configfile",
            ),
        ] {
            let source =
                KernelFlakeSource::for_images_checkout(variant, std::path::PathBuf::from("/k"))
                    .expect("canon variant maps");
            assert_eq!(source.build_attr, build, "{variant:?}");
            assert_eq!(source.config_attr, config, "{variant:?}");
            assert_eq!(source.flake_base, "path:/work#packages");
            assert_eq!(source.work_dir, std::path::PathBuf::from("/k"));
        }
    }

    #[test]
    fn images_checkout_refuses_the_orchestrator_variant() {
        let error = KernelFlakeSource::for_images_checkout(
            KernelVariant::WorkloadK8s,
            std::path::PathBuf::from("/k"),
        )
        .expect_err("the orchestrator variant has no mvm-images home");
        assert!(
            error.to_string().contains("not defined in the mvm-images"),
            "{error:#}"
        );
    }

    fn images_checkout_fixture(dir: &std::path::Path) {
        super::super::test_pair::images_checkout(dir, "{}\n");
    }

    #[test]
    fn resolve_prefers_a_kernel_flake_from_the_images_checkout() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        images_checkout_fixture(dir.path());
        env.set(mvm_build::image_source::MVM_IMAGES_DIR_ENV, dir.path());

        let source =
            resolve_kernel_flake_source(KernelVariant::Workload).expect("images checkout resolves");
        // The checkout root is canonicalized (`/var` -> `/private/var` on
        // macOS); the staged kernel dir inherits that.
        let canonical_root = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        assert_eq!(source.work_dir, canonical_root.join("kernel"));
        assert_eq!(source.build_attr, "workload-vmlinux");
        assert_eq!(source.config_attr, "workload-configfile");
        assert_eq!(source.flake_base, "path:/work#packages");
    }

    fn opened_checkout(dir: &std::path::Path) -> mvm_build::image_source::ImageSource {
        images_checkout_fixture(dir);
        mvm_build::image_source::ImageSource::LocalCheckout(
            mvm_build::image_source::LocalImageCheckout::open(dir).expect("fixture opens"),
        )
    }

    #[test]
    fn a_selected_checkout_builds_from_its_kernel_flake() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = opened_checkout(dir.path());

        let flake = kernel_flake_source_for(KernelVariant::Workload, &source)
            .expect("a selected checkout serves the workload kernel");
        let canonical_root = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        assert_eq!(flake.work_dir, canonical_root.join("kernel"));
        assert_eq!(flake.build_attr, "workload-vmlinux");
        assert_eq!(flake.flake_base, "path:/work#packages");
    }

    #[test]
    fn a_selected_checkout_refuses_workload_k8s() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = opened_checkout(dir.path());

        let error = kernel_flake_source_for(KernelVariant::WorkloadK8s, &source)
            .expect_err("the orchestrator kernel has no source anywhere");
        assert!(
            error.to_string().contains("not defined in the mvm-images"),
            "{error:#}"
        );
    }

    /// Without an image checkout a kernel compile has no source: the released
    /// set carries built kernels only. The refusal names where the sources
    /// live instead of pointing at a flake this repository no longer has.
    #[test]
    fn a_compile_without_an_image_checkout_is_refused() {
        let source = mvm_build::image_source::ImageSource::Released;
        for variant in [
            KernelVariant::Builder,
            KernelVariant::Workload,
            KernelVariant::WorkloadK8s,
            KernelVariant::Rootless,
        ] {
            let error = kernel_flake_source_for(variant, &source)
                .expect_err("the released set has no kernel sources");
            let message = error.to_string();
            assert!(
                message.contains("image construction lives in mvm-images"),
                "{variant:?}: {message}"
            );
            assert!(
                message.contains(&format!("the {} kernel", variant.label())),
                "{variant:?}: {message}"
            );
        }
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
