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
}

#[cfg(feature = "builder-vm")]
impl KernelVariant {
    /// Flake attr under `packages.<arch>-linux`.
    fn attr(self) -> &'static str {
        match self {
            Self::Builder => "builder-kernel",
            Self::Workload => "workload-kernel",
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
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Builder => "builder",
            Self::Workload => "workload",
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
    let builder_flake_dir = find_builder_vm_flake().map_err(|_| {
        anyhow::anyhow!(
            "`mvmctl kernel build --source compile` needs a source checkout of mvm \
             (nix/images/builder-vm/flake.nix). From an installed binary, fetch a \
             published kernel with `--source download` instead."
        )
    })?;

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

    let workspace_root = std::path::Path::new(&builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let request =
        super::stage0_artifact::Stage0ArtifactBuild::builder(&workspace_root, &staging_dir)
            .build_attr(variant.attr())
            .output_mode("kernel")
            .config_attr(variant.config_attr())
            .verbose(verbose)
            .build()?;

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
    if variant == KernelVariant::Workload
        && workload_config_carries_dm_verity(&config) != Some(true)
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
