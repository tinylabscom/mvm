//! Builder-VM image bootstrap, Stage 0, workload-kernel build, and
//! bundled-image fetching helpers.

mod bootstrap;
#[cfg(test)]
mod builder_vm_bootstrap_tests;
pub(in crate::commands) mod default_microvm;
mod kernel;
mod local_pair;
#[cfg(test)]
pub(crate) use mvm_client::builder_images::test_pair;
mod stage0_cache;

pub(in crate::commands) use bootstrap::bootstrap_builder_vm_image;
pub(in crate::commands) use bootstrap::bootstrap_tool_builder_vm_image;
pub(crate) use bootstrap::selected_local_checkout;

/// Run `f` with the launch-time pair artifact source when a checkout is
/// selected, or `None` when the selector is unset. Launch is cache-only:
/// explicit build/bootstrap operations prepare entries before this adapter.
pub(crate) fn with_pair_artifact_source<T>(
    f: impl FnOnce(
        Option<&mut mvm_client::launch::runtime_source::PairArtifactSource<'_>>,
    ) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let Some(checkout) = selected_local_checkout()? else {
        return f(None);
    };
    let mut build = mvm_client::builder_images::prepared::resolve_pair;
    let mut pair = mvm_client::launch::runtime_source::PairArtifactSource {
        checkout: &checkout,
        build: &mut build,
    };
    f(Some(&mut pair))
}

/// Report the tier recorded with a managed image cache entry, when `path`
/// is inside one. Ordinary boots read what their image records, so a
/// local-dev boot is visible in the log without running `doctor`.
pub(crate) fn report_recorded_boot_tier(what: &str, path: &std::path::Path) {
    if let Some(tier) = mvm_build::image_source::recorded_tier_for(path) {
        crate::ui::info(&format!("{what}: {tier} (as recorded with the image)"));
    }
}

/// Whether images are built from source here: an explicit local image checkout
/// is selected. Image construction lives in `mvm-images`, so an mvm source
/// checkout without `MVM_IMAGES_DIR` selects the released set like any other
/// binary. An invalid configured path is not an answer either way — the verb
/// that uses the selection reports it.
pub(crate) fn images_built_from_source() -> bool {
    use mvm_build::image_source::resolve_current_source;
    matches!(
        resolve_current_source(),
        Ok(mvm_build::image_source::ImageSource::LocalCheckout(_))
    )
}

pub(crate) use default_microvm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, ensure_workload_kernel,
};
pub(crate) use kernel::KernelSource;
pub(crate) use kernel::resolve_kernel_source;
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(test)]
pub(crate) use local_pair::derive_pair_key;
pub(crate) use local_pair::ensure_pair_built;
pub(crate) use local_pair::staged_contract_files;
pub(in crate::commands) use stage0_cache::stage0_active_in_process;

pub(super) fn builder_vm_host_arch() -> &'static str {
    bootstrap::builder_vm_host_arch()
}
