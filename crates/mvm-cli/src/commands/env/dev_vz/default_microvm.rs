use super::*;

pub(crate) fn ensure_default_microvm_image(
    mode: mvm_build::pipeline::BuildMode,
) -> Result<(String, String)> {
    let base = format!("{}/default-microvm", mvm_core::config::mvm_cache_dir());
    match mode {
        mvm_build::pipeline::BuildMode::Prod => {
            ensure_default_microvm_prod_image(&format!("{base}/prod"))
        }
        mvm_build::pipeline::BuildMode::Dev => {
            ensure_default_microvm_dev_image(&format!("{base}/dev"))
        }
    }
}

pub(crate) fn ensure_workload_kernel(prod: bool) -> Result<String> {
    let cache = mvm_core::config::mvm_cache_dir();
    let arch = builder_vm_host_arch();
    let resolved = resolve_workload_kernel_bootstrap(&cache, arch, prod);
    match resolved {
        WorkloadKernelBootstrap::Cached(path) => Ok(path),
        WorkloadKernelBootstrap::ReusableBuilder(path) => {
            ui::info("Reusing builder-image kernel as workload kernel (dev mode).");
            Ok(path)
        }
        WorkloadKernelBootstrap::Download(dest) => {
            download_workload_kernel(arch, &dest)?;
            Ok(dest)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkloadKernelBootstrap {
    Cached(String),
    ReusableBuilder(String),
    Download(String),
}

pub(super) fn resolve_workload_kernel_bootstrap(
    cache_dir: &str,
    arch: &str,
    prod: bool,
) -> WorkloadKernelBootstrap {
    if let Some(cached) = find_cached_workload_kernel(cache_dir, arch) {
        return WorkloadKernelBootstrap::Cached(cached);
    }
    if !prod && let Some(builder) = find_reusable_builder_kernel(cache_dir, arch) {
        return WorkloadKernelBootstrap::ReusableBuilder(builder);
    }
    WorkloadKernelBootstrap::Download(format!(
        "{cache_dir}/builder-vm/{arch}/kernels/workload/vmlinux"
    ))
}

pub(super) fn find_reusable_builder_kernel(cache_dir: &str, arch: &str) -> Option<String> {
    let path = format!("{cache_dir}/builder-vm/{arch}/vmlinux");
    std::path::Path::new(&path).is_file().then_some(path)
}

fn download_workload_kernel(arch: &str, dest: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(dest).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let asset = format!("vmlinux-{arch}-workload");
    let checksums_url = format!("{base_url}/kernel-{arch}-checksums-sha256.txt");

    ui::info(&format!(
        "Downloading workload kernel {asset} (v{version})..."
    ));
    let expected = fetch_expected_hashes(&checksums_url, &[asset.as_str()])?;
    let asset_url = format!("{base_url}/{asset}");
    download_file(&asset_url, dest).with_context(|| format!("Failed to download {asset_url}"))?;
    verify_artifact_hash(dest, &asset, expected.get(&asset))?;
    ui::success(&format!(
        "Workload kernel {asset} downloaded, hash-verified, and cached."
    ));
    Ok(())
}

pub(super) fn find_cached_workload_kernel(cache_dir: &str, arch: &str) -> Option<String> {
    [
        format!("{cache_dir}/builder-vm/{arch}/kernels/workload/vmlinux"),
        format!("{cache_dir}/default-microvm/prod/vmlinux"),
        format!("{cache_dir}/default-microvm/dev/vmlinux"),
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).is_file())
}

fn ensure_default_microvm_prod_image(cache_dir: &str) -> Result<(String, String)> {
    std::fs::create_dir_all(cache_dir)?;
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    let required = [
        kernel_path.clone(),
        rootfs_path.clone(),
        format!("{cache_dir}/mvm-meta.json"),
        format!("{cache_dir}/rootfs.verity"),
        format!("{cache_dir}/rootfs.roothash"),
    ];
    if required.iter().all(|p| std::path::Path::new(p).exists()) {
        return Ok((kernel_path, rootfs_path));
    }
    if let Some(built) = try_build_prod_default_locally(cache_dir)? {
        return Ok(built);
    }
    download_default_microvm_image(cache_dir, &kernel_path, &rootfs_path)
}

#[cfg(feature = "builder-vm")]
fn try_build_prod_default_locally(cache_dir: &str) -> Result<Option<(String, String)>> {
    if find_builder_vm_flake().is_err() {
        return Ok(None);
    }
    ui::info("Building the prod default microVM image locally (source checkout)...");
    build_default_microvm_via_libkrun(cache_dir, DefaultMicrovmVariant::Prod).map(Some)
}

#[cfg(not(feature = "builder-vm"))]
fn try_build_prod_default_locally(_cache_dir: &str) -> Result<Option<(String, String)>> {
    Ok(None)
}

#[cfg(feature = "builder-vm")]
fn ensure_default_microvm_dev_image(cache_dir: &str) -> Result<(String, String)> {
    std::fs::create_dir_all(cache_dir)?;
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    let meta_path = format!("{cache_dir}/mvm-meta.json");
    if [&kernel_path, &rootfs_path, &meta_path]
        .iter()
        .all(|p| std::path::Path::new(p).exists())
    {
        return Ok((kernel_path, rootfs_path));
    }
    ui::info("Building the dev default microVM image locally (dev mode)...");
    build_default_microvm_via_libkrun(cache_dir, DefaultMicrovmVariant::Dev)
}

#[cfg(feature = "builder-vm")]
#[derive(Clone, Copy)]
pub(super) enum DefaultMicrovmVariant {
    Dev,
    Prod,
}

#[cfg(feature = "builder-vm")]
impl DefaultMicrovmVariant {
    pub(super) fn attr(self) -> &'static str {
        match self {
            DefaultMicrovmVariant::Dev => "dev",
            DefaultMicrovmVariant::Prod => "default",
        }
    }

    pub(super) fn required_outputs(self) -> &'static [&'static str] {
        match self {
            DefaultMicrovmVariant::Dev => &["vmlinux", "rootfs.ext4", "mvm-meta.json"],
            DefaultMicrovmVariant::Prod => &[
                "vmlinux",
                "rootfs.ext4",
                "mvm-meta.json",
                "rootfs.verity",
                "rootfs.roothash",
            ],
        }
    }
}

#[cfg(not(feature = "builder-vm"))]
fn ensure_default_microvm_dev_image(_cache_dir: &str) -> Result<(String, String)> {
    anyhow::bail!(
        "dev mode builds the default image locally via the builder VM, but this \
         mvmctl was built without the `builder-vm` feature. Use `--prod` (downloads \
         the published image), or pass a `--flake`."
    )
}

#[cfg(feature = "builder-vm")]
fn build_default_microvm_via_libkrun(
    out_dir: &str,
    variant: DefaultMicrovmVariant,
) -> Result<(String, String)> {
    use mvm_build::builder_backend_select::{
        resolve_choice, resolve_env_override, try_resolve_builder_backend_with_override,
    };
    use mvm_build::builder_vm::{BuilderJob, BuilderMounts, host_system_linux};

    bootstrap_builder_vm_image()
        .context("Stage 0 builder-VM image bootstrap (precondition for libkrun dispatch)")?;

    let builder_flake = find_builder_vm_flake().context(
        "builder-vm flake missing at nix/images/builder-vm/flake.nix; libkrun dispatch needs it",
    )?;
    let workspace_root = std::path::Path::new(&builder_flake)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake}"))?
        .to_path_buf();

    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir =
        crate::host_binaries::extract::ensure_extracted(std::path::Path::new(&host_bins_cache))
            .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating default-microvm dev out dir {out_dir}"))?;

    let job = BuilderJob::Flake {
        flake_ref: "path:/work/nix/images/default-tenant".to_string(),
        attr_path: format!("packages.{}.{}", host_system_linux(), variant.attr()),
    };
    let mounts = BuilderMounts {
        flake_src: workspace_root,
        host_nix_store: None,
        artifact_out: std::path::PathBuf::from(out_dir),
        host_bin_dir,
        staged_user_flake: None,
    };

    let selected = resolve_choice();
    let explicit_override = resolve_env_override().is_some();
    let attempt_order = builder_backend_attempt_order(selected, explicit_override);
    let mut last_error = None;
    for (idx, choice) in attempt_order.iter().copied().enumerate() {
        let backend = try_resolve_builder_backend_with_override(Some(choice));
        let run_result = backend.and_then(|b| b.run_build(&job, &mounts));
        match run_result {
            Ok(_) => {
                mvm_build::builder_health::note_attempt_outcome(choice, true);
                last_error = None;
                break;
            }
            Err(err) => {
                if mvm_build::builder_backend_select::is_builder_vm_level_failure(&err) {
                    mvm_build::builder_health::note_attempt_outcome(choice, false);
                }
                if idx + 1 < attempt_order.len() {
                    ui::warn(&format!(
                        "Auto-selected {} builder failed ({}); retrying with {}.",
                        choice.name(),
                        err,
                        attempt_order[idx + 1].name(),
                    ));
                }
                last_error = Some(anyhow::anyhow!("{} builder VM: {err}", choice.name()));
            }
        }
    }
    if let Some(err) = last_error {
        return Err(err);
    }

    for label in variant.required_outputs() {
        let p = format!("{out_dir}/{label}");
        if !std::path::Path::new(&p).exists() {
            anyhow::bail!("builder VM exited cleanly but did not produce {label} at {p}");
        }
    }
    let kernel = format!("{out_dir}/vmlinux");
    let rootfs = format!("{out_dir}/rootfs.ext4");
    Ok((kernel, rootfs))
}

pub(super) fn default_microvm_assets(cache_dir: &str, arch: &str) -> [(String, String); 5] {
    [
        (
            format!("default-microvm-vmlinux-{arch}"),
            format!("{cache_dir}/vmlinux"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.ext4"),
            format!("{cache_dir}/rootfs.ext4"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.verity"),
            format!("{cache_dir}/rootfs.verity"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.roothash"),
            format!("{cache_dir}/rootfs.roothash"),
        ),
        (
            format!("default-microvm-meta-{arch}.json"),
            format!("{cache_dir}/mvm-meta.json"),
        ),
    ]
}

fn download_default_microvm_image(
    cache_dir: &str,
    kernel_path: &str,
    rootfs_path: &str,
) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    let assets = default_microvm_assets(cache_dir, arch);
    let checksums_name = format!("default-microvm-{arch}-checksums-sha256.txt");
    let checksums_url = format!("{base_url}/{checksums_name}");

    ui::info(&format!(
        "Downloading default microVM image (v{version})..."
    ));

    let asset_names: Vec<&str> = assets.iter().map(|(n, _)| n.as_str()).collect();
    let expected = fetch_expected_hashes(&checksums_url, &asset_names)?;

    for (name, dest) in &assets {
        ui::info(&format!("  Fetching {name}..."));
        let url = format!("{base_url}/{name}");
        download_file(&url, dest).with_context(|| format!("Failed to download {url}"))?;
        verify_artifact_hash(dest, name, expected.get(name.as_str()))?;
    }

    ui::success("Default microVM image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}
