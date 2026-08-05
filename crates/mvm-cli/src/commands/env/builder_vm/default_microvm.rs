use super::*;
use crate::commands::runtime_overlay::{
    RuntimeOverlayAcquireMode, runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};

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

pub(crate) fn ensure_workload_kernel() -> Result<String> {
    let cache = mvm_core::config::mvm_cache_dir();
    let arch = builder_vm_host_arch();
    let source_checkout = find_builder_vm_flake().is_ok();
    let resolved = resolve_workload_kernel_bootstrap(&cache, arch, source_checkout);
    // Name which kernel variant a run resolved and where it came from. Without
    // this breadcrumb a wrong-kernel boot (e.g. a non-verity kernel under a
    // verity-sealed rootfs) is invisible host-side until the guest panics.
    let (provenance, path) = match resolved {
        WorkloadKernelBootstrap::Cached(path) => ("cached", path),
        WorkloadKernelBootstrap::BuildLocal(path) => {
            match workload_kernel_source(source_checkout) {
                KernelSource::Download => {
                    download_workload_kernel(arch, &path)?;
                    ("downloaded", path)
                }
                #[cfg(feature = "builder-vm")]
                KernelSource::Auto => match download_workload_kernel(arch, &path) {
                    Ok(()) => ("downloaded", path),
                    Err(download_error) => {
                        ui::warn(&format!(
                            "Published workload kernel unavailable ({download_error}); building it locally from the source checkout."
                        ));
                        ("built", build_local_workload_kernel()?)
                    }
                },
                KernelSource::Compile => ("built", build_local_workload_kernel()?),
            }
        }
        WorkloadKernelBootstrap::Download(dest) => match workload_kernel_source(source_checkout) {
            KernelSource::Compile => {
                if !source_checkout {
                    anyhow::bail!(
                        "{} MVM_KERNEL_SOURCE=compile requires an mvm source checkout so the workload kernel can be built locally. Set MVM_KERNEL_SOURCE=download or unset it to use the published kernel.",
                        missing_workload_kernel_message(&dest)
                    );
                }
                ("built", build_local_workload_kernel()?)
            }
            KernelSource::Download => {
                download_workload_kernel(arch, &dest)?;
                ("downloaded", dest)
            }
            #[cfg(feature = "builder-vm")]
            KernelSource::Auto => {
                download_workload_kernel(arch, &dest)?;
                ("downloaded", dest)
            }
        },
    };
    ui::info(&format!("Workload kernel: {provenance} at {path}"));
    Ok(path)
}

#[cfg(feature = "builder-vm")]
fn workload_kernel_source(source_checkout: bool) -> KernelSource {
    resolve_kernel_source().unwrap_or_else(|| default_workload_kernel_source(source_checkout))
}

#[cfg(not(feature = "builder-vm"))]
fn workload_kernel_source(source_checkout: bool) -> KernelSource {
    default_workload_kernel_source(source_checkout)
}

pub(super) fn default_workload_kernel_source(source_checkout: bool) -> KernelSource {
    if source_checkout {
        KernelSource::Compile
    } else {
        KernelSource::Download
    }
}

#[cfg(feature = "builder-vm")]
fn build_local_workload_kernel() -> Result<String> {
    ui::notice(
        "No cached workload kernel. Building it once in Stage 0; the first run can take several minutes, then warm starts use the cache.",
    );
    let path = build_kernel_via_stage0(KernelVariant::Workload, false)
        .context("build the dm-verity-capable workload kernel")?;
    let path = path.display().to_string();
    ui::success(&format!(
        "Workload kernel built and cached. Future machine runs will skip this step: {path}"
    ));
    Ok(path)
}

#[cfg(not(feature = "builder-vm"))]
fn build_local_workload_kernel() -> Result<String> {
    anyhow::bail!(
        "building the workload kernel requires the builder-vm feature; use a release binary or set MVM_KERNEL_SOURCE=download"
    )
}

/// Whether a kernel image carries device-mapper + dm-verity support (needed to
/// boot a verity-sealed rootfs). `None` when the input is not a readable,
/// uncompressed kernel we can judge (a compressed `Image`, a truncated file, or
/// any non-kernel blob) — callers must NOT block on `None`. `Some(false)` only
/// when the kernel is readable yet carries no device-mapper/dm-verity symbol at
/// all — the signature of a kernel built without `CONFIG_BLK_DEV_DM`/`DM_VERITY`
/// (e.g. the builder kernel, which force-drops them).
pub(super) fn kernel_carries_dm_verity(bytes: &[u8]) -> Option<bool> {
    // Only an uncompressed vmlinux exposes symbol strings; anything else is
    // inconclusive, and blocking on it would false-reject a valid kernel.
    if !byte_contains(bytes, b"Linux version") {
        return None;
    }
    // A dm-verity-capable kernel carries these device-mapper / dm-verity symbols
    // (via KALLSYMS + the dm subsystem's log strings). A kernel built without the
    // device-mapper umbrella carries none of them.
    const MARKERS: &[&[u8]] = &[
        b"device-mapper",
        b"dm_bufio",
        b"verity_ctr",
        b"dm_table_create",
        b"dm-verity",
    ];
    Some(MARKERS.iter().any(|m| byte_contains(bytes, m)))
}

fn byte_contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fail fast when a verity-sealed launch resolved a kernel with no dm-verity
/// support. Without this the guest panics in early init opening
/// `/dev/mapper/control` ("No such file or directory") with zero host signal —
/// so surface a clear host-side error instead. Conservative: only a *readable*
/// kernel with no dm-verity symbol at all trips it, so an unrecognized/compressed
/// kernel is never wrongly rejected.
pub(crate) fn assert_workload_kernel_supports_verity(kernel_path: &str) -> Result<()> {
    let bytes = std::fs::read(kernel_path)
        .with_context(|| format!("read resolved workload kernel {kernel_path}"))?;
    if kernel_carries_dm_verity(&bytes) == Some(false) {
        anyhow::bail!(
            "resolved workload kernel {kernel_path} carries no device-mapper/dm-verity \
             support, but the workload boots verity-sealed. It would panic the guest at boot \
             (mvm-verity-init: open /dev/mapper/control: No such file or directory). This \
             kernel cannot back a sealed workload — resolve or rebuild the workload kernel."
        );
    }
    Ok(())
}

pub(crate) fn ensure_workload_verity_initrd() -> Result<String> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let layout = mvm_build::verity_initrd::VerityInitrdLayout::under(&cache_root, version, arch);
    let workspace_root = workload_verity_initrd_source_checkout_root().filter(|_| {
        runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
    });
    if let Some(ws) = workspace_root {
        return mvm_build::verity_initrd::resolve_or_build_verity_initrd(
            &cache_root,
            version,
            arch,
            &ws,
        )
        .map(|p| p.display().to_string())
        .context("build verity initrd from the source checkout");
    }
    if layout.initrd.is_file() {
        return Ok(layout.initrd.display().to_string());
    }

    if let Some(bytes) = embedded_verity_init_bytes() {
        return mvm_build::verity_initrd::install_prebuilt_verity_initrd(
            bytes,
            &cache_root,
            version,
            arch,
        )
        .map(|p| p.display().to_string())
        .context("install embedded verity initrd");
    }

    anyhow::bail!(
        "no verity initrd available: this build embeds no mvm-verity-init binary and there is no source checkout to cross-compile from"
    )
}

fn workload_verity_initrd_source_checkout_root() -> Option<std::path::PathBuf> {
    runtime_overlay_source_checkout_root().or_else(|| {
        super::find_builder_vm_flake().ok().and_then(|flake_dir| {
            std::path::PathBuf::from(flake_dir)
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(std::path::Path::to_path_buf)
        })
    })
}

fn embedded_verity_init_bytes() -> Option<&'static [u8]> {
    crate::host_binaries::embedded::EMBEDDED
        .iter()
        .find(|b| b.name == "mvm-verity-init")
        .map(|b| b.bytes)
        .filter(|b| !b.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkloadKernelBootstrap {
    Cached(String),
    BuildLocal(String),
    Download(String),
}

pub(super) fn resolve_workload_kernel_bootstrap(
    cache_dir: &str,
    arch: &str,
    source_checkout: bool,
) -> WorkloadKernelBootstrap {
    if let Some(cached) = find_cached_workload_kernel(cache_dir, arch) {
        return WorkloadKernelBootstrap::Cached(cached);
    }
    // The workload always boots through the verity initrd (mvm-verity-init opens
    // /dev/mapper/control and builds the dm-verity target), so its kernel must
    // carry device-mapper + dm-verity built in. The builder kernel force-drops
    // both (it boots `root=/dev/vda ro` with no roothash), so it can never stand
    // in for the workload kernel — reusing it panics the guest at boot. Always
    // resolve the real workload kernel: build it (source checkout) or download
    // the published one.
    let dest = format!("{cache_dir}/builder-vm/{arch}/kernels/workload/vmlinux");
    if source_checkout {
        WorkloadKernelBootstrap::BuildLocal(dest)
    } else {
        WorkloadKernelBootstrap::Download(dest)
    }
}

pub(super) fn missing_workload_kernel_message(expected_path: &str) -> String {
    format!(
        "workload kernel missing (expected at {expected_path}). \
         `machine run --image` needs a dm-verity-capable workload kernel before the guest can boot. \
         In a source checkout it is built automatically on first use; set \
         `MVM_KERNEL_SOURCE=download` to use the published kernel instead, or create it manually \
         with `mvmctl kernel build --which workload` or `just kernel-workload`."
    )
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

/// The dedicated workload kernel, or `None` when it has not been built or
/// downloaded yet.
///
/// Only the dedicated kernel qualifies. The default-microvm images ship a
/// general-purpose NixOS kernel, and borrowing it used to be allowed here —
/// which meant that on a host with no workload kernel cached, a workload
/// silently booted a kernel built for a different job. Those kernels enable
/// `CONFIG_USER_NS`, which the workload kernel deliberately leaves unset, so
/// the borrow handed the guest a user-namespace escape hatch the workload
/// kernel exists to remove. It was invisible: same command, same image, and a
/// posture that depended on which kernels happened to be in the local cache.
///
/// A cold cache is now resolved by building or downloading the real workload
/// kernel — which is what the caller already does, and what its own comment
/// already claimed it did.
pub(super) fn find_cached_workload_kernel(cache_dir: &str, arch: &str) -> Option<String> {
    let dedicated = format!("{cache_dir}/builder-vm/{arch}/kernels/workload/vmlinux");
    std::path::Path::new(&dedicated)
        .is_file()
        .then_some(dedicated)
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
    let host_bin_dir = crate::host_binaries::extract::ensure_boot_host_binaries(
        std::path::Path::new(&host_bins_cache),
    )?
    .dir;

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
