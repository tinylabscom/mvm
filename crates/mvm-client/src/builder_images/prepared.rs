//! Launch providers never build or download. A selected checkout remains
//! authoritative even when its cache is cold or invalid.

use anyhow::{Context, Result};
use mvm_build::image_source::{
    CacheLookup, CachedImageSet, EntryContext, ImageBuildTarget, ImageSource, KeyInputs,
    LocalImageCache, LocalImageCacheKey, LocalImageCheckout, contract_for,
};
use mvm_core::{arch::GuestArch, image_set::WorkloadImageProfile};

pub fn selected_local_checkout() -> Result<Option<LocalImageCheckout>> {
    Ok(match mvm_build::image_source::resolve_current_source()? {
        ImageSource::LocalCheckout(checkout) => Some(checkout),
        ImageSource::Released => None,
    })
}

pub fn derive_pair_key(
    checkout: &LocalImageCheckout,
    target: &ImageBuildTarget,
) -> Result<LocalImageCacheKey> {
    let root = mvm_build::image_source::mvm_source_checkout(
        mvm_build::artifact_acquisition::compiled_channel(),
    )
    .context("the mvm source checkout used by this binary is no longer on disk")?;
    Ok(LocalImageCacheKey::derive(&KeyInputs {
        images: checkout,
        mvm_checkout: &root,
        target,
        arch: GuestArch::host(),
    })?)
}

/// Resolve and verify an exact pair entry, without acquiring a replacement.
pub fn resolve_pair(
    checkout: &LocalImageCheckout,
    target: ImageBuildTarget,
) -> Result<CachedImageSet> {
    let root = mvm_build::image_source::mvm_source_checkout(
        mvm_build::artifact_acquisition::compiled_channel(),
    )
    .context("the mvm source checkout used by this binary is no longer on disk")?;
    resolve_pair_in(checkout, &root, target, &LocalImageCache::open_default())
}

fn resolve_pair_in(
    checkout: &LocalImageCheckout,
    mvm_root: &std::path::Path,
    target: ImageBuildTarget,
    cache: &LocalImageCache,
) -> Result<CachedImageSet> {
    let key = LocalImageCacheKey::derive(&KeyInputs {
        images: checkout,
        mvm_checkout: mvm_root,
        target: &target,
        arch: GuestArch::host(),
    })?;
    let contract = contract_for(&target)?;
    let context = EntryContext {
        images: checkout,
        mvm_checkout: mvm_root,
        roles: contract.set_roles,
    };
    match cache.lookup(&key, &context)? {
        CacheLookup::Hit(entry) => Ok(*entry),
        CacheLookup::Miss => anyhow::bail!(
            "selected local image target {target} is not prepared; run `mvmctl build image-set {} --attr {}` with the same MVM_IMAGES_DIR before launching",
            target.role,
            target.attr.as_str()
        ),
        CacheLookup::Evicted { reason } => anyhow::bail!(
            "selected local image target {target} failed verification: {reason}; run `mvmctl build image-set {} --attr {}` with the same MVM_IMAGES_DIR before launching",
            target.role,
            target.attr.as_str()
        ),
    }
}

pub fn workload_kernel_target(profile: WorkloadImageProfile) -> ImageBuildTarget {
    ImageBuildTarget {
        role: mvm_build::image_source::ImageBuildRole::for_workload_profile(profile),
        attr: mvm_build::image_source::FlakeAttr::new("default")
            .expect("default is a valid flake attribute"),
    }
}

pub fn resolve_pair_workload_kernel(
    checkout: &LocalImageCheckout,
    profile: WorkloadImageProfile,
) -> Result<std::path::PathBuf> {
    let entry = resolve_pair(checkout, workload_kernel_target(profile))?;
    let artifact = entry
        .set
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.role == mvm_core::image_set::ImageSetRole::WorkloadKernel(profile)
        })
        .with_context(|| format!("the pair's {profile} set has no workload kernel member"))?;
    Ok(artifact.path.clone())
}

pub fn resolve_workload_kernel(vmlinux: &str, hypervisor: &str) -> Result<String> {
    resolve_workload_kernel_with(vmlinux, hypervisor, selected_local_checkout)
}

/// The selector is evaluated only if this backend actually needs a fallback.
pub fn resolve_workload_kernel_with(
    vmlinux: &str,
    hypervisor: &str,
    selected_checkout: impl FnOnce() -> Result<Option<LocalImageCheckout>>,
) -> Result<String> {
    if std::path::Path::new(vmlinux).exists() || !matches!(hypervisor, "hvf" | "firecracker") {
        return Ok(vmlinux.to_owned());
    }
    if let Some(checkout) = selected_checkout()? {
        return Ok(
            resolve_pair_workload_kernel(&checkout, WorkloadImageProfile::DefaultTenant)?
                .display()
                .to_string(),
        );
    }
    let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = GuestArch::host().to_string();
    if let mvm_build::kernel_fetch::KernelResolution::Cached(verified) =
        mvm_build::kernel_fetch::resolve_kernel(&cache, &arch, "workload", false)
    {
        return Ok(verified.path().display().to_string());
    }
    anyhow::bail!(
        "image has no kernel ({vmlinux} missing) and the {hypervisor} backend needs one; no verified workload kernel is cached at {} — run `mvmctl kernel build --which workload` once to populate it",
        mvm_build::kernel_fetch::cached_kernel_path(&cache, &arch, "workload").display()
    )
}

#[cfg(test)]
mod tests;
