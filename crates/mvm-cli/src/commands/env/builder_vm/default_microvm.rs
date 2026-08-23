use super::*;
use crate::commands::runtime_overlay::{
    RuntimeOverlayAcquireMode, runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};
use mvm_build::boot_image_select::{self, BootImageAcquisition};

pub(crate) fn ensure_default_microvm_image(
    mode: mvm_build::pipeline::BuildMode,
) -> Result<(String, String)> {
    let base = mvm_core::config::default_microvm_cache_dir();
    match mode {
        mvm_build::pipeline::BuildMode::Prod => ensure_default_microvm_prod_image(&format!(
            "{base}/{}",
            DefaultMicrovmVariant::Prod.cache_subdir()
        )),
        mvm_build::pipeline::BuildMode::Dev => ensure_default_microvm_dev_image(&format!(
            "{base}/{}",
            DefaultMicrovmVariant::Dev.cache_subdir()
        )),
    }
}

pub(crate) fn ensure_workload_kernel() -> Result<String> {
    use mvm_build::kernel_fetch::{KernelResolution, resolve_kernel};

    let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = builder_vm_host_arch();
    let source_checkout = find_builder_vm_flake().is_ok();
    let mut resolved = resolve_kernel(&cache, arch, "workload", source_checkout);

    if let KernelResolution::Cached(verified) = &resolved {
        let cached = verified.path().display().to_string();
        if let Err(error) = assert_workload_kernel_supports_verity(&cached) {
            ui::warn(&format!(
                "Cached workload kernel capability check failed ({error}); discarding it and preparing a correct kernel."
            ));
            evict_incompatible_workload_kernel(verified.path())?;
            resolved = resolve_kernel(&cache, arch, "workload", source_checkout);
        }
    }

    let source = workload_kernel_source(source_checkout);
    let (provenance, path, produced) = match resolved {
        KernelResolution::Cached(verified) => {
            ("cached", verified.path().display().to_string(), false)
        }
        KernelResolution::NeedsBuild(dest) | KernelResolution::NeedsFetch(dest) => {
            let (provenance, path) = acquire_workload_kernel(source, source_checkout, arch, &dest)?;
            (provenance, path, true)
        }
    };

    // Re-enter the shared resolver after every producer. This makes a missing
    // or mismatched digest an acquisition failure instead of allowing the
    // caller to boot bytes merely because the destination path exists.
    let verified_path = if produced {
        match resolve_kernel(&cache, arch, "workload", source_checkout) {
            KernelResolution::Cached(verified) => verified.path().display().to_string(),
            KernelResolution::NeedsBuild(dest) | KernelResolution::NeedsFetch(dest) => {
                anyhow::bail!(
                    "workload kernel producer left no verified artifact at {}",
                    dest.display()
                )
            }
        }
    } else {
        path.clone()
    };
    if verified_path != path {
        anyhow::bail!(
            "workload kernel producer returned {path}, but the verified cache resolved {verified_path}"
        );
    }
    assert_workload_kernel_supports_verity(&verified_path)?;
    ui::info(&format!("Workload kernel: {provenance} at {path}"));
    Ok(path)
}

fn acquire_workload_kernel(
    source: KernelSource,
    source_checkout: bool,
    arch: &str,
    dest: &std::path::Path,
) -> Result<(&'static str, String)> {
    match source {
        KernelSource::Compile => {
            if !source_checkout {
                anyhow::bail!(
                    "{} MVM_KERNEL_SOURCE=compile requires an mvm source checkout so the workload kernel can be built locally. Set MVM_KERNEL_SOURCE=download or unset it to use the published kernel.",
                    missing_workload_kernel_message(&dest.display().to_string())
                );
            }
            Ok(("built", build_local_workload_kernel()?))
        }
        KernelSource::Download => {
            download_workload_kernel(arch, dest)?;
            Ok(("downloaded", dest.display().to_string()))
        }
        #[cfg(feature = "builder-vm")]
        KernelSource::Auto => match download_workload_kernel(arch, dest) {
            Ok(()) => Ok(("downloaded", dest.display().to_string())),
            Err(download_error) if source_checkout => {
                ui::warn(&format!(
                    "Published workload kernel unavailable ({download_error}); building it locally from the source checkout."
                ));
                Ok(("built", build_local_workload_kernel()?))
            }
            Err(download_error) => Err(download_error),
        },
    }
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
    default_workload_kernel_source_for(
        mvm_build::artifact_acquisition::compiled_channel(),
        source_checkout,
    )
}

pub(super) fn default_workload_kernel_source_for(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    source_checkout: bool,
) -> KernelSource {
    match mvm_build::artifact_acquisition::default_acquisition(channel, source_checkout) {
        mvm_build::artifact_acquisition::DefaultAcquisition::Build => KernelSource::Compile,
        mvm_build::artifact_acquisition::DefaultAcquisition::Download => KernelSource::Download,
    }
}

#[cfg(feature = "builder-vm")]
fn build_local_workload_kernel() -> Result<String> {
    ui::notice(
        "Preparing the workload kernel using the Stage 0 builder. The first source build can take several minutes; the persistent Nix store and finished kernel are reused afterward.",
    );
    let path = build_kernel_via_stage0(KernelVariant::Workload, false)
        .context(
            "build the dm-verity-capable workload kernel; retry with `mvmctl kernel build --which workload` or `just kernel-workload`",
        )?;
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

pub(super) fn workload_config_carries_dm_verity(config: &str) -> Option<bool> {
    if !config
        .lines()
        .any(|line| line.starts_with("CONFIG_") || line.starts_with("# CONFIG_"))
    {
        return None;
    }
    Some(
        config.lines().any(|line| line == "CONFIG_BLK_DEV_DM=y")
            && config.lines().any(|line| line == "CONFIG_DM_VERITY=y"),
    )
}

/// Fail fast when a verity-sealed launch resolved a kernel with no dm-verity
/// support. Local builds carry their resolved config beside the kernel, which
/// is authoritative even when the size-optimized image deliberately omits
/// KALLSYMS and contains no searchable dm-verity symbols. Published kernels
/// may not carry a local config; their variant-specific release checksum is the
/// capability identity and the absence of this optional local witness is not a
/// rejection.
pub(crate) fn assert_workload_kernel_supports_verity(kernel_path: &str) -> Result<()> {
    std::fs::metadata(kernel_path)
        .with_context(|| format!("read resolved workload kernel {kernel_path}"))?;
    let config_path = std::path::Path::new(kernel_path).with_file_name("config");
    let capability = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|config| workload_config_carries_dm_verity(&config));
    if capability == Some(false) {
        anyhow::bail!(
            "resolved workload kernel {kernel_path} has a config without CONFIG_BLK_DEV_DM=y \
             and CONFIG_DM_VERITY=y, but the workload boots verity-sealed. This kernel cannot \
             back a sealed workload"
        );
    }
    Ok(())
}

pub(super) fn evict_incompatible_workload_kernel(kernel: &std::path::Path) -> Result<()> {
    for path in [
        kernel.to_path_buf(),
        mvm_build::kernel_fetch::kernel_digest_sidecar(kernel),
        kernel.with_file_name("config"),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "discarding incompatible workload kernel file {}",
                        path.display()
                    )
                });
            }
        }
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

pub(super) fn missing_workload_kernel_message(expected_path: &str) -> String {
    format!(
        "workload kernel missing (expected at {expected_path}). \
         `machine run --image` needs a dm-verity-capable workload kernel before the guest can boot. \
         In a source checkout it is built automatically on first use; set \
         `MVM_KERNEL_SOURCE=download` to use the published kernel instead, or create it manually \
         with `mvmctl kernel build --which workload` or `just kernel-workload`."
    )
}

fn download_workload_kernel(arch: &str, dest: &std::path::Path) -> Result<()> {
    crate::update::download_kernel(arch, "workload", dest)
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
    // Which arm produces the image is a policy decision with an operator
    // override, not a bare "is there a flake here" test. Auto-detect still
    // answers exactly as before — a checkout builds, an installed binary
    // fetches — so an operator who sets nothing sees no change.
    let resolved = boot_image_select::resolve(None, source_checkout_available());
    match resolved.choice {
        BootImageAcquisition::Build => build_prod_default_locally(cache_dir),
        BootImageAcquisition::Fetch => {
            let acquired = download_default_microvm_image(cache_dir, &kernel_path, &rootfs_path)?;
            // Record that these bytes were fetched, not built here. Without it a
            // prebuilt pulled into a source checkout is indistinguishable from a
            // build of the working tree, and the next person to wonder why their
            // flake edit had no effect has nothing to read. The producer's own
            // build facts are left untouched.
            let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
            crate::commands::image::boot::cache::stamp_provenance(
                std::path::Path::new(cache_dir),
                &crate::commands::image::boot::cache::AcquiredProvenance::fetched(&tag),
            )?;
            Ok(acquired)
        }
    }
}

/// Whether this binary can build an image from an in-repo flake.
///
/// The same predicate the acquisition path has always used, named so the
/// selector reads as policy applied to a fact rather than re-deriving the fact.
#[cfg(feature = "builder-vm")]
fn source_checkout_available() -> bool {
    find_builder_vm_flake().is_ok()
}

#[cfg(not(feature = "builder-vm"))]
fn source_checkout_available() -> bool {
    false
}

/// A forced local build with nothing to build from is refused, not quietly
/// downgraded to a fetch.
///
/// `MVM_BOOT_IMAGE=build` on an installed binary is a request the host cannot
/// satisfy. Falling back to a fetch would hand back exactly the image the
/// operator asked not to have, and it would look like the knob had worked.
fn refuse_build_without_a_flake() -> Result<()> {
    if source_checkout_available() {
        return Ok(());
    }
    anyhow::bail!(
        "{env}=build asks for a locally built boot image, but this mvmctl has no \
         in-repo image flake to build from — it is an installed binary, not a \
         source checkout. Unset {env} to fetch the published image, or run from \
         a checkout.",
        env = boot_image_select::MVM_BOOT_IMAGE_ENV
    )
}

#[cfg(feature = "builder-vm")]
fn build_prod_default_locally(cache_dir: &str) -> Result<(String, String)> {
    refuse_build_without_a_flake()?;
    ui::info("Building the prod default microVM image locally (source checkout)...");
    build_default_microvm_via_libkrun(cache_dir, DefaultMicrovmVariant::Prod)
}

#[cfg(not(feature = "builder-vm"))]
fn build_prod_default_locally(_cache_dir: &str) -> Result<(String, String)> {
    // Without the feature there is never a flake, so the refusal always fires.
    refuse_build_without_a_flake()?;
    anyhow::bail!("this build of mvmctl cannot build a boot image locally")
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

/// The two boot-image variants the cache can hold.
///
/// Deliberately not gated on the `builder-vm` feature: a binary that cannot
/// *build* an image still has to read, fetch, and report on one, and the
/// variant's required output set is the same either way.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum DefaultMicrovmVariant {
    Dev,
    Prod,
}

impl DefaultMicrovmVariant {
    /// Cache subdirectory holding this variant's artifacts.
    pub(in crate::commands) fn cache_subdir(self) -> &'static str {
        match self {
            DefaultMicrovmVariant::Dev => "dev",
            DefaultMicrovmVariant::Prod => "prod",
        }
    }

    #[cfg(feature = "builder-vm")]
    pub(super) fn attr(self) -> &'static str {
        match self {
            DefaultMicrovmVariant::Dev => "dev",
            DefaultMicrovmVariant::Prod => "default",
        }
    }

    /// Files that must all be present for the cache entry to be usable.
    pub(in crate::commands) fn required_outputs(self) -> &'static [&'static str] {
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

pub(in crate::commands) fn default_microvm_assets(
    cache_dir: &str,
    arch: &str,
) -> [(String, String); 5] {
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
    // The default microVM ships on the boot image counter, not the CLI's. See
    // `update::boot_image_release` for why deriving this from CARGO_PKG_VERSION
    // 404s for most of a release cycle.
    let (tag, image_version) = crate::update::boot_image_release()?;
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/{tag}");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    let assets = default_microvm_assets(cache_dir, arch);
    let checksums_name = format!("default-microvm-{arch}-checksums-sha256.txt");

    ui::info(&format!("Downloading default microVM image ({tag})..."));

    let asset_names: Vec<&str> = assets.iter().map(|(n, _)| n.as_str()).collect();
    let expected = fetch_expected_hashes(
        &ChecksumManifest {
            base_url: &base_url,
            asset: &checksums_name,
            version: &image_version,
            train: mvm_build::release_signature::ReleaseTrain::BootImage,
        },
        &asset_names,
    )?;

    for (name, dest) in &assets {
        ui::info(&format!("  Fetching {name}..."));
        let url = format!("{base_url}/{name}");
        download_file(&url, dest).with_context(|| format!("Failed to download {url}"))?;
        verify_artifact_hash(dest, name, expected.get(name.as_str()))?;
    }

    ui::success("Default microVM image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}
