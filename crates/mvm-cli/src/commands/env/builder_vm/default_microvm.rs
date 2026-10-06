use super::*;
use mvm_build::boot_image_select::{self, BootImageAcquisition};
use mvm_core::image_set::WorkloadImageProfile;

pub(crate) fn ensure_default_microvm_image(
    mode: mvm_build::pipeline::BuildMode,
) -> Result<(String, String)> {
    let base = mvm_core::config::default_microvm_cache_dir();
    let out = match mode {
        mvm_build::pipeline::BuildMode::Prod => ensure_default_microvm_prod_image(&format!(
            "{base}/{}",
            DefaultMicrovmVariant::Prod.cache_subdir()
        )),
        mvm_build::pipeline::BuildMode::Dev => ensure_default_microvm_dev_image(&format!(
            "{base}/{}",
            DefaultMicrovmVariant::Dev.cache_subdir()
        )),
    }?;
    super::report_recorded_boot_tier("Default image", std::path::Path::new(&out.1));
    Ok(out)
}

pub(crate) fn ensure_workload_kernel() -> Result<String> {
    use mvm_build::kernel_fetch::{KernelResolution, resolve_kernel, workload_kernel_label};

    let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = builder_vm_host_arch();

    // The dev-tier kernel-label override answers before either acquisition
    // branch, so a machine run boots the same kernel family the launch
    // resolve sites pick whether or not a local image checkout is selected.
    // It only ever reads a verified cache entry: every producer below
    // acquires the sealed kernel, so resolving the override label through
    // them would file sealed bytes under a label that says otherwise.
    if let Some(kernel) = dev_tier_kernel_override(&cache, arch, workload_kernel_label()) {
        let path = kernel.display().to_string();
        assert_workload_kernel_supports_verity(&path)?;
        return Ok(path);
    }

    // A selected checkout is the kernel's source: the pair's
    // `default-tenant` set carries the workload kernel, built from the
    // checkout it names. An unusable configured path is an error here,
    // never a quiet fall-through to a download.
    if let Some(checkout) = super::bootstrap::selected_local_checkout()? {
        let path = super::local_pair::ensure_pair_workload_kernel(
            &checkout,
            WorkloadImageProfile::DefaultTenant,
        )?;
        let path = path.display().to_string();
        assert_workload_kernel_supports_verity(&path)?;
        ui::info(&format!("Workload kernel: pair-built at {path}"));
        return Ok(path);
    }

    // Only an image checkout can compile the kernel, and a selected one has
    // answered above; without one the kernel the image lock pins is fetched.
    let source_checkout = super::images_built_from_source();
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

/// The verified cache entry the dev-tier kernel label selects, if any. `None`
/// for the sealed default label, and on a cache miss — which warns and lets
/// the caller acquire the sealed kernel rather than refusing the boot.
fn dev_tier_kernel_override(
    cache: &std::path::Path,
    arch: &str,
    label: &str,
) -> Option<std::path::PathBuf> {
    use mvm_build::kernel_fetch::{KernelResolution, resolve_kernel};
    if label == "workload" {
        return None;
    }
    match resolve_kernel(cache, arch, label, false) {
        KernelResolution::Cached(verified) => {
            ui::info(&format!(
                "Workload kernel: {label} override at {}",
                verified.path().display()
            ));
            Some(verified.path().to_path_buf())
        }
        KernelResolution::NeedsBuild(_) | KernelResolution::NeedsFetch(_) => {
            ui::warn(&format!(
                "MVM_WORKLOAD_KERNEL_VARIANT={label} is set but the local kernel cache has no \
                 verified {label} kernel; booting the sealed workload kernel (build it with \
                 `mvmctl kernel build --which {label}`)"
            ));
            None
        }
    }
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

fn workload_kernel_source(source_checkout: bool) -> KernelSource {
    resolve_kernel_source().unwrap_or_else(|| default_workload_kernel_source(source_checkout))
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

fn build_local_workload_kernel() -> Result<String> {
    // `build_kernel_via_stage0` announces itself with a live status line.
    let path = build_kernel_via_stage0(KernelVariant::Workload, false)
        .context(
            "build the dm-verity-capable workload kernel; retry with `mvmctl kernel build --which workload` or `just kernel::workload`",
        )?;
    let path = path.display().to_string();
    ui::success(&format!(
        "Workload kernel built and cached. Future machine runs will skip this step: {path}"
    ));
    Ok(path)
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
    for path in mvm_build::kernel_fetch::kernel_entry_files(kernel) {
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

pub(super) fn missing_workload_kernel_message(expected_path: &str) -> String {
    format!(
        "workload kernel missing (expected at {expected_path}). \
         `machine run --image` needs a dm-verity-capable workload kernel before the guest can boot. \
         In a source checkout it is built automatically on first use; set \
         `MVM_KERNEL_SOURCE=download` to use the published kernel instead, or create it manually \
         with `mvmctl kernel build --which workload` or `just kernel::workload`."
    )
}

fn download_workload_kernel(arch: &str, dest: &std::path::Path) -> Result<()> {
    let phase = mvm_runtime::ui::activity::start(format!(
        "Downloading the published workload kernel ({arch})"
    ));
    crate::update::download_kernel(arch, "workload", dest)?;
    phase.finish();
    Ok(())
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
    // A selected checkout is the source for the default image: an existing
    // cache only answers when its stamped pair identity is the pair on disk
    // now, and the fetch arm is refused rather than silently overriding the
    // selector. An invalid configured path is an error here, never a quiet
    // fall-through to the published set.
    if let Some(checkout) = super::bootstrap::selected_local_checkout()? {
        if boot_image_select::resolve_env_override() == Some(BootImageAcquisition::Fetch) {
            anyhow::bail!(
                "{}=fetch asks for the published image set while {} names a local image                  checkout; the selector is explicit in both directions — unset {} for                  this run to compare against a signed release",
                boot_image_select::MVM_BOOT_IMAGE_ENV,
                mvm_build::image_source::MVM_IMAGES_DIR_ENV,
                mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            );
        }
        return ensure_pair_workload_image(
            &checkout,
            cache_dir,
            DefaultMicrovmVariant::Prod,
            WorkloadImageProfile::DefaultTenant,
        );
    }
    if required.iter().all(|p| std::path::Path::new(p).exists()) {
        return Ok((kernel_path, rootfs_path));
    }
    // Which arm produces the image is a policy decision with an operator
    // override. Auto-detect fetches here: a selected image checkout has
    // already answered above, and without one there is nothing to build from,
    // so a forced build is refused.
    let resolved = boot_image_select::resolve(None, source_checkout_available());
    match resolved.choice {
        BootImageAcquisition::Build => Err(refuse_build_without_a_checkout()),
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

/// Whether this binary can build an image from source: a local image
/// checkout is selected.
///
/// The same predicate the acquisition path has always used, named so the
/// selector reads as policy applied to a fact rather than re-deriving the fact.
fn source_checkout_available() -> bool {
    super::images_built_from_source()
}

/// A forced local build with nothing to build from is refused, not quietly
/// downgraded to a fetch.
///
/// `MVM_BOOT_IMAGE=build` without an image checkout is a request the host
/// cannot satisfy. Falling back to a fetch would hand back exactly the image
/// the operator asked not to have, and it would look like the knob had worked.
fn refuse_build_without_a_checkout() -> anyhow::Error {
    mvm_build::image_source::ImageConstructionRefused::new(format!(
        "the locally built default image {}=build asks for",
        boot_image_select::MVM_BOOT_IMAGE_ENV
    ))
    .into()
}

/// The dev default image: the writable variant of the default image,
/// built from the selected image checkout's `default-tenant.dev` target.
fn ensure_default_microvm_dev_image(cache_dir: &str) -> Result<(String, String)> {
    dev_image_from(super::bootstrap::selected_local_checkout()?, cache_dir)
}

/// The local cache slot holding the dev default image
/// (`<mvm home>/cache/default-microvm/dev`).
pub(crate) fn dev_default_image_cache_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::default_microvm_cache_dir())
        .join(DefaultMicrovmVariant::Dev.cache_subdir())
}

/// Build the dev image from `checkout`, or answer from a cache a previous
/// build left. Without a checkout and without a cache there is nothing to
/// build it from: the released set publishes the sealed image only.
pub(crate) fn dev_image_from(
    checkout: Option<mvm_build::image_source::LocalImageCheckout>,
    cache_dir: &str,
) -> Result<(String, String)> {
    if let Some(checkout) = checkout {
        ui::info("Preparing the dev default microVM image from the selected image checkout...");
        return ensure_pair_workload_image(
            &checkout,
            cache_dir,
            DefaultMicrovmVariant::Dev,
            WorkloadImageProfile::DefaultTenant,
        );
    }
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    if DefaultMicrovmVariant::Dev
        .required_outputs()
        .iter()
        .all(|label| std::path::Path::new(&format!("{cache_dir}/{label}")).exists())
    {
        return Ok((kernel_path, rootfs_path));
    }
    Err(mvm_build::image_source::ImageConstructionRefused::new("the dev default image").into())
}

/// Serve one profile-qualified workload image from the pair: install the
/// verified set into the caller's profile-specific cache, stamp it with the
/// pair identity, and answer an unchanged pair without a cache lookup.
///
/// The variant picks the checkout's attribute: `default` for the sealed
/// image, `dev` for the writable one.
fn ensure_pair_workload_image(
    checkout: &mvm_build::image_source::LocalImageCheckout,
    cache_dir: &str,
    variant: DefaultMicrovmVariant,
    profile: WorkloadImageProfile,
) -> Result<(String, String)> {
    use mvm_build::image_source::{FlakeAttr, ImageBuildRole, ImageBuildTarget};
    let target = ImageBuildTarget {
        role: ImageBuildRole::for_workload_profile(profile),
        attr: FlakeAttr::new(variant.attr())
            .expect("a variant attribute is a valid flake attribute"),
    };
    let fingerprint = super::local_pair::pair_fingerprint(&super::local_pair::derive_pair_key(
        checkout, &target,
    )?);
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    if variant
        .required_outputs()
        .iter()
        .all(|label| std::path::Path::new(&format!("{cache_dir}/{label}")).exists())
        && installed_pair_fingerprint(std::path::Path::new(cache_dir)).as_deref()
            == Some(fingerprint.as_str())
    {
        return Ok((kernel_path, rootfs_path));
    }

    let contract = mvm_build::image_source::contract_for(&target)?;
    let build = super::local_pair::ensure_pair_built(checkout, target)?;
    let fingerprint = super::local_pair::pair_fingerprint(&build.key);
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating default-image cache dir {cache_dir}"))?;
    for label in variant.required_outputs() {
        // Entry files are named by the producer's manifest; resolve through
        // it so the installed bytes are the ones the set's digests verified.
        // The manifest role for each output comes from the contract itself,
        // so a role rename cannot desynchronize the lookup.
        let role = contract
            .files
            .iter()
            .find(|file| file.name == *label)
            .map(|file| file.role)
            .with_context(|| format!("the contract has no output named {label}"))?;
        let from = build
            .entry
            .contract_file(role, label)
            .with_context(|| format!("the pair's set has no {role} artifact {label}"))?;
        super::local_pair::copy_contract_file(
            from,
            std::path::Path::new(&format!("{cache_dir}/{label}")),
        )?;
    }
    // `copy_contract_file` left every output above owner-writable, the
    // sidecar among them, so it can be rewritten with the pair identity.
    // The sidecar names the pair identity; the next run compares it before
    // deciding the install answers, so a changed pair reinstalls and a
    // fetched or in-tree image is never mistaken for a pair build.
    crate::commands::image::boot::cache::stamp_provenance(
        std::path::Path::new(cache_dir),
        &crate::commands::image::boot::cache::AcquiredProvenance {
            image_tag: fingerprint,
            source: "local-pair",
            acquired_at: mvm_core::util::time::utc_now(),
        },
    )?;
    Ok((kernel_path, rootfs_path))
}

/// The pair fingerprint a cache dir was installed under, when it was
/// installed from a pair. Anything else — an in-tree build, a fetched
/// prebuilt — is not a pair answer and returns `None`.
fn installed_pair_fingerprint(cache_dir: &std::path::Path) -> Option<String> {
    let sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(cache_dir).ok()??;
    (sidecar.source == "local-pair").then_some(sidecar.image_tag)
}

/// The two boot-image variants the cache can hold.
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

fn download_default_microvm_image(
    cache_dir: &str,
    kernel_path: &str,
    rootfs_path: &str,
) -> Result<(String, String)> {
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let guest_arch = arch.parse().context("parse host architecture")?;
    let image_set = crate::commands::env::artifact_verify::acquire_image_set()?;
    let tag = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str();
    ui::info(&format!("Downloading default microVM image ({tag})..."));
    image_set.fetch_default_workload(guest_arch, std::path::Path::new(cache_dir))?;
    ui::success("Default microVM image downloaded from the signed image set and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

#[cfg(test)]
mod pair_default_image_tests {
    use super::*;
    use crate::commands::env::builder_vm::test_pair::{Pair, produced_sidecar};
    use mvm_build::image_source::ImageBuildRole;
    use mvm_core::util::test_env::TestEnv;

    /// The five default-tenant artifacts, with the sizes and ext4 magic the
    /// artifact validator requires, and a producer-shaped sidecar.
    #[test]
    fn the_probe_reads_only_a_pair_installed_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(installed_pair_fingerprint(dir.path()), None);

        std::fs::write(
            dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
            produced_sidecar(),
        )
        .unwrap();
        assert_eq!(installed_pair_fingerprint(dir.path()), None);

        crate::commands::image::boot::cache::stamp_provenance(
            dir.path(),
            &crate::commands::image::boot::cache::AcquiredProvenance {
                image_tag: "fingerprint".to_string(),
                source: "local-pair",
                acquired_at: "now".to_string(),
            },
        )
        .unwrap();
        assert_eq!(
            installed_pair_fingerprint(dir.path()).as_deref(),
            Some("fingerprint")
        );
    }

    #[test]
    fn a_pair_default_image_installs_and_an_unchanged_pair_reanswers() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set("MVM_HOME", pair.tmp.path().join("home"));
        std::fs::create_dir_all(pair.tmp.path().join("home")).unwrap();
        let _entry = pair.publish_default_tenant();
        let cache_dir = pair.tmp.path().join("default-image");

        let (kernel, rootfs) = ensure_pair_workload_image(
            &pair.images,
            &cache_dir.display().to_string(),
            DefaultMicrovmVariant::Prod,
            WorkloadImageProfile::DefaultTenant,
        )
        .expect("install the pair default image");
        assert!(std::path::Path::new(&kernel).is_file());
        assert!(std::path::Path::new(&rootfs).is_file());
        for label in DefaultMicrovmVariant::Prod.required_outputs() {
            assert!(
                cache_dir.join(label).is_file(),
                "installed default image must carry {label}"
            );
        }
        let fingerprint = crate::commands::env::builder_vm::local_pair::pair_fingerprint(
            &crate::commands::env::builder_vm::local_pair::derive_pair_key(
                &pair.images,
                &Pair::target(ImageBuildRole::DefaultTenant, "default"),
            )
            .unwrap(),
        );
        assert_eq!(
            installed_pair_fingerprint(&cache_dir).as_deref(),
            Some(fingerprint.as_str()),
            "the install must stamp the pair identity"
        );

        // Remove the cache entry backing the install: a re-answer that only
        // consults the install must still succeed.
        std::fs::remove_dir_all(mvm_build::image_source::LocalImageCache::open_default().root())
            .unwrap();
        let (again_kernel, again_rootfs) = ensure_pair_workload_image(
            &pair.images,
            &cache_dir.display().to_string(),
            DefaultMicrovmVariant::Prod,
            WorkloadImageProfile::DefaultTenant,
        )
        .expect("an unchanged pair answers from the install");
        assert_eq!(kernel, again_kernel);
        assert_eq!(rootfs, again_rootfs);
    }

    #[test]
    fn a_pair_rootless_image_uses_the_rootless_target_and_cache_identity() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set("MVM_HOME", pair.tmp.path().join("home"));
        std::fs::create_dir_all(pair.tmp.path().join("home")).unwrap();
        let entry = pair.publish_workload_profile(WorkloadImageProfile::RootlessTenant);
        let cache_dir = pair.tmp.path().join("rootless-image");

        let (kernel, rootfs) = ensure_pair_workload_image(
            &pair.images,
            &cache_dir.display().to_string(),
            DefaultMicrovmVariant::Prod,
            WorkloadImageProfile::RootlessTenant,
        )
        .expect("install the pair rootless image");

        assert!(std::path::Path::new(&kernel).is_file());
        assert!(std::path::Path::new(&rootfs).is_file());
        assert_eq!(entry.key.target.role, ImageBuildRole::RootlessTenant);
        assert!(entry.set.manifest.members.iter().all(|member| matches!(
            member.role,
            mvm_core::image_set::ImageSetRole::WorkloadKernel(WorkloadImageProfile::RootlessTenant)
                | mvm_core::image_set::ImageSetRole::WorkloadRootfs(
                    WorkloadImageProfile::RootlessTenant
                )
        )));
    }

    #[test]
    fn the_pair_workload_kernel_is_the_verified_set_artifact() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set("MVM_HOME", pair.tmp.path().join("home"));
        std::fs::create_dir_all(pair.tmp.path().join("home")).unwrap();
        let entry = pair.publish_default_tenant();
        let kernel = super::super::local_pair::ensure_pair_workload_kernel(
            &pair.images,
            WorkloadImageProfile::DefaultTenant,
        )
        .expect("the pair resolves a workload kernel");
        let artifact = entry
            .set
            .artifacts
            .iter()
            .find(|a| {
                a.role
                    == mvm_core::image_set::ImageSetRole::WorkloadKernel(
                        WorkloadImageProfile::DefaultTenant,
                    )
            })
            .expect("the set carries a workload kernel");
        assert_eq!(
            kernel, artifact.path,
            "the resolved kernel is the verified file"
        );
    }

    #[test]
    fn ensure_workload_kernel_answers_from_the_pair_under_a_selector() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set("MVM_HOME", pair.tmp.path().join("home"));
        std::fs::create_dir_all(pair.tmp.path().join("home")).unwrap();
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            pair.images.root(),
        );
        pair.publish_default_tenant();
        let path = ensure_workload_kernel().expect("the kernel resolves from the pair");
        assert!(
            path.ends_with("vmlinux"),
            "the pair kernel path names the kernel artifact: {path}"
        );
    }

    #[test]
    fn fetching_the_published_set_is_refused_while_a_checkout_is_selected() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            pair.images.root(),
        );
        env.set(mvm_build::boot_image_select::MVM_BOOT_IMAGE_ENV, "fetch");
        let cache_dir = pair.tmp.path().join("default-image");
        let err = ensure_default_microvm_prod_image(&cache_dir.display().to_string())
            .expect_err("fetch under a selected checkout must refuse");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(mvm_build::image_source::MVM_IMAGES_DIR_ENV),
            "{rendered}"
        );
        assert!(
            !cache_dir.join("vmlinux").exists(),
            "a refusal must not produce image artifacts"
        );
    }

    /// The released set publishes the sealed image only, so without an image
    /// checkout the dev image has no source; the refusal names where image
    /// sources live rather than a flake this repository no longer carries.
    #[test]
    fn the_dev_image_without_a_checkout_or_cache_is_refused() {
        let cache_dir = tempfile::tempdir().unwrap();

        let err = dev_image_from(None, &cache_dir.path().display().to_string())
            .expect_err("nothing can build the dev image");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("the dev default image is built from an mvm-images checkout"),
            "{rendered}"
        );
        assert!(
            rendered.contains("image construction lives in mvm-images"),
            "{rendered}"
        );
    }

    #[test]
    fn a_dev_image_left_in_the_cache_still_answers_without_a_checkout() {
        let cache_dir = tempfile::tempdir().unwrap();
        for label in DefaultMicrovmVariant::Dev.required_outputs() {
            std::fs::write(cache_dir.path().join(label), b"x").unwrap();
        }

        let (kernel, rootfs) = dev_image_from(None, &cache_dir.path().display().to_string())
            .expect("a cached dev image answers");

        assert!(kernel.ends_with("vmlinux"), "{kernel}");
        assert!(rootfs.ends_with("rootfs.ext4"), "{rootfs}");
    }

    #[test]
    fn a_forced_local_build_without_a_checkout_names_the_knob_and_the_repository() {
        let rendered = refuse_build_without_a_checkout().to_string();

        assert!(rendered.contains("MVM_BOOT_IMAGE=build"), "{rendered}");
        assert!(
            rendered.contains("image construction lives in mvm-images"),
            "{rendered}"
        );
    }
}

#[cfg(test)]
mod dev_tier_kernel_override_tests {
    use super::dev_tier_kernel_override;
    use mvm_core::util::test_env::TestEnv;

    /// Stage a kernel entry under `label` and record its digest, the shape a
    /// `kernel build` leaves in the cache.
    fn stage_labelled_kernel(cache: &std::path::Path, label: &str) -> std::path::PathBuf {
        let kernel = mvm_build::kernel_fetch::cached_kernel_path(cache, "aarch64", label);
        std::fs::create_dir_all(kernel.parent().expect("entry dir")).expect("mkdir entry");
        std::fs::write(&kernel, format!("{label} kernel bytes")).expect("write kernel");
        mvm_build::kernel_fetch::record_kernel_digest(&kernel).expect("record digest");
        kernel
    }

    #[test]
    fn the_sealed_label_is_never_an_override() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().expect("tempdir");
        stage_labelled_kernel(cache.path(), "workload");
        assert_eq!(
            dev_tier_kernel_override(cache.path(), "aarch64", "workload"),
            None
        );
    }

    #[test]
    fn an_override_label_boots_its_verified_cache_entry() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().expect("tempdir");
        let kernel = stage_labelled_kernel(cache.path(), "workload-k8s");
        assert_eq!(
            dev_tier_kernel_override(cache.path(), "aarch64", "workload-k8s"),
            Some(kernel)
        );
    }

    /// A miss must fall through to the sealed acquisition and leave the
    /// override slot empty: acquiring into it would file the sealed kernel
    /// under the override's label.
    #[test]
    fn an_override_label_without_a_cache_entry_falls_through_and_writes_nothing() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            dev_tier_kernel_override(cache.path(), "aarch64", "workload-k8s"),
            None
        );
        let slot =
            mvm_build::kernel_fetch::cached_kernel_path(cache.path(), "aarch64", "workload-k8s");
        assert!(!slot.exists(), "{}", slot.display());
    }

    #[test]
    fn a_tampered_override_entry_is_not_booted() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().expect("tempdir");
        let kernel = stage_labelled_kernel(cache.path(), "workload-k8s");
        std::fs::write(&kernel, b"swapped after the digest was recorded").expect("tamper");
        assert_eq!(
            dev_tier_kernel_override(cache.path(), "aarch64", "workload-k8s"),
            None
        );
    }
}
