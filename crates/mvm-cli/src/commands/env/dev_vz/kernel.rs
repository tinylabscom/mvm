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

/// Where the builder VM's kernel comes from when bootstrapping its
/// image, from `MVM_KERNEL_SOURCE` (set by the global `--kernel-source`
/// flag). `download` boots the builder VM on a published, hash-verified
/// kernel — building only the rootfs locally and pairing the kernel in,
/// so a fresh `dev up` skips the multi-minute kernel compile. Unset →
/// the default `nix build default` path (kernel compiled in-image).
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KernelSource {
    Compile,
    Download,
    Auto,
}

#[cfg(feature = "builder-vm")]
pub(super) fn resolve_kernel_source() -> Option<KernelSource> {
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
    let dest = std::path::Path::new(&mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join("builder")
        .join("vmlinux");
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
    let out_dir = format!(
        "{}/builder-vm/{arch}/kernels/{}",
        mvm_core::config::mvm_cache_dir(),
        variant.label()
    );
    let out_dir_path = std::path::Path::new(&out_dir);
    std::fs::create_dir_all(out_dir_path)
        .with_context(|| format!("creating kernel cache dir {out_dir}"))?;

    let _stage0_guard = acquire_stage0_lock(&out_dir)?;

    let stage0_assets = mvm_build::stage0::assets_for_host_arch();
    let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
        .context("preparing Stage 0 bootstrap assets (nix-tarball seed)")?;
    for report in &vendor_reports {
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
            None,
            Some(&report.audit_detail()),
        );
    }

    let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
    let stage0_init = crate::host_binaries::embedded::EMBEDDED
        .iter()
        .find(|b| b.name == "stage0-init")
        .ok_or_else(|| anyhow::anyhow!("stage0-init not in the embedded host binaries"))?;
    if stage0_init.bytes.is_empty() {
        anyhow::bail!(
            "embedded stage0-init is a zero-byte stub — this mvmctl was built with \
             MVM_SKIP_EMBED_BINARIES=1 and cannot seed Stage 0; rebuild without it"
        );
    }
    mvm_build::stage0::materialize_root_dir(&root_dir, stage0_init.bytes)
        .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;

    let workspace_root = std::path::Path::new(&builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let conf = format!(
        "MVM_STAGE0_BUILD_ATTR={}\nMVM_STAGE0_OUTPUT_MODE=kernel\nMVM_STAGE0_CONFIG_ATTR={}\n",
        variant.attr(),
        variant.config_attr(),
    );
    std::fs::write(staging_dir.join("stage0-build.conf"), conf)
        .with_context(|| format!("writing stage0-build.conf in {}", staging_dir.display()))?;

    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir = crate::host_binaries::extract::ensure_extracted_for_boot(
        std::path::Path::new(&host_bins_cache),
    )
    .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    ui::info(&format!(
        "Compiling {} kernel ({arch}) via Stage 0 — first build is slow \
         (3-10 min); later runs hit the nix store cache.",
        variant.label()
    ));

    {
        use mvm_build::builder_backend_select as bbs;
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

        let selected = bbs::resolve_choice();
        let explicit = bbs::resolve_env_override().is_some();
        let result = bbs::run_with_builder_fallback(selected, explicit, |choice| {
            bbs::resolve_stage0_backend_for_choice(choice, verbose).run_stage0(
                &root_dir,
                "/init",
                &workspace_root,
                &staging_dir,
                &host_bin_dir,
            )
        });

        stop.store(true, Ordering::Relaxed);
        if let Some(handle) = heartbeat {
            let _ = handle.join();
        }

        result.map_err(|e| anyhow::anyhow!("Stage 0 kernel build: {e}"))?;
    }

    let built = staging_dir.join("vmlinux");
    if !built.is_file() {
        let _ = std::fs::remove_dir_all(&staging_dir);
        anyhow::bail!(
            "Stage 0 produced no kernel at {} (attr {})",
            built.display(),
            variant.attr()
        );
    }
    let dest = out_dir_path.join("vmlinux");
    std::fs::copy(&built, &dest)
        .with_context(|| format!("copying kernel to {}", dest.display()))?;

    let staged_config = staging_dir.join("mvm-kernel.config");
    if staged_config.is_file() {
        let config_dest = out_dir_path.join("config");
        if let Err(e) = std::fs::copy(&staged_config, &config_dest) {
            ui::warn(&format!("could not cache the resolved kernel config: {e}"));
        }
    }
    let _ = std::fs::remove_dir_all(&staging_dir);

    Ok(dest)
}
