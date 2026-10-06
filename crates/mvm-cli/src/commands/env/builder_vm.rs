//! Builder-VM image bootstrap, Stage 0, workload-kernel build, and
//! bundled-image fetching helpers.

mod bootstrap;
#[cfg(test)]
mod builder_vm_bootstrap_tests;
pub(in crate::commands) mod default_microvm;
mod image_ops;
mod kernel;
mod local_pair;
#[cfg(test)]
mod published_fetch_tests;
mod shell_job;
mod stage0_artifact;
mod stage0_cache;
#[cfg(test)]
pub(crate) mod test_pair;
#[cfg(test)]
mod tests;
mod vm_helpers;

use anyhow::{Context, Result};

#[cfg(test)]
use super::artifact_verify::bump_verify_outcome;
#[cfg(test)]
use super::artifact_verify::{ChecksumManifest, verify_artifact_hash};
use crate::ui;
pub(in crate::commands) use bootstrap::bootstrap_builder_vm_image;
pub(in crate::commands) use bootstrap::bootstrap_tool_builder_vm_image;
pub(crate) use bootstrap::selected_local_checkout;

/// The `cmdline.txt` recorded beside a fetched builder image. No backend boots
/// from it — every builder boot composes the builder boot contract's own line
/// — so it is written from that contract, for a boot without a payload, to
/// keep the cache's shape and to say what the image would boot with alone.
pub(super) fn synthesized_builder_vm_cmdline() -> String {
    use mvm_build::builder_boot::{
        BuilderBoot, LIBKRUN_BUILDER_CONSOLE_BASE, builder_boot_cmdline,
    };
    format!(
        "{}\n",
        builder_boot_cmdline(LIBKRUN_BUILDER_CONSOLE_BASE, &BuilderBoot::Baked, false)
    )
}

/// Run `f` with the launch-time pair artifact source when a checkout is
/// selected, or `None` when the selector is unset. The build closure runs
/// `ensure_pair_built`, so a launch under a selected checkout builds the
/// overlay or sidecar from the pair — never a download.
pub(crate) fn with_pair_artifact_source<T>(
    f: impl FnOnce(
        Option<&mut mvm_client::launch::runtime_source::PairArtifactSource<'_>>,
    ) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let Some(checkout) = selected_local_checkout()? else {
        return f(None);
    };
    let mut build = |checkout: &mvm_build::image_source::LocalImageCheckout,
                     target: mvm_build::image_source::ImageBuildTarget| {
        Ok(local_pair::ensure_pair_built(checkout, target)?.entry)
    };
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

/// Whether images are built from source here: a local image checkout is
/// selected, configured or found beside this checkout. Image construction
/// lives in `mvm-images`, so an mvm source checkout without one selects the
/// released set like any other binary. An invalid configured path is not an
/// answer either way — the verb that uses the selection reports it.
pub(crate) fn images_built_from_source() -> bool {
    use mvm_build::image_source::resolve_current_source;
    matches!(
        resolve_current_source(),
        Ok(mvm_build::image_source::ImageSource::LocalCheckout(_))
    )
}

#[cfg(test)]
use default_microvm::DefaultMicrovmVariant;
use default_microvm::workload_config_carries_dm_verity;
pub(crate) use default_microvm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, ensure_workload_kernel,
};
#[cfg(test)]
use default_microvm::{evict_incompatible_workload_kernel, missing_workload_kernel_message};
use image_ops::validate_dev_image_artifacts;
pub(crate) use kernel::KernelSource;
#[cfg(test)]
use kernel::format_compile_start;
pub(crate) use kernel::resolve_kernel_source;
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(test)]
pub(crate) use local_pair::derive_pair_key;
pub(crate) use local_pair::ensure_pair_built;
pub(crate) use local_pair::ensure_pair_workload_kernel;
pub(crate) use local_pair::seed_pair_workload_kernel_cache;
pub(crate) use local_pair::staged_contract_files;
#[cfg(test)]
use stage0_cache::builder_vm_artifact_names;
use stage0_cache::download_builder_vm_image;
pub(in crate::commands) use stage0_cache::{
    Stage0SweepOutcome, stage0_active_in_process, stage0_bootstrap_in_flight,
    sweep_orphaned_stage0_staging_dirs,
};
use stage0_cache::{
    acquire_stage0_lock, sweep_stage0_staging_siblings, unique_builder_vm_stage0_staging_dir,
};
#[cfg(test)]
use stage0_cache::{
    builder_vm_source_cache_ready, builder_vm_source_cache_status,
    is_orphan_stage0_staging_dir_name, stage0_bootstrap_in_flight_at,
    sweep_orphaned_stage0_staging_dirs_at, write_builder_vm_artifact_digest_manifest,
    write_builder_vm_source_cache_provenance, write_builder_vm_source_fingerprint,
};
#[cfg(test)]
use vm_helpers::{
    BUILDER_SIDECARS, ProcSnapshot, ReapScope, WORKLOAD_SIDECARS, pid_is_alive,
    reap_orphaned_builder_egress_supervisors, reap_orphaned_vm_helpers_at,
};
pub(in crate::commands) use vm_helpers::{
    sweep_orphaned_vm_helpers_before_spawn, sweep_orphaned_vm_helpers_on_startup,
};

pub(in crate::commands) use vm_helpers::reap_orphaned_vm_helpers;

pub(super) fn builder_vm_host_arch() -> &'static str {
    bootstrap::builder_vm_host_arch()
}

#[cfg(test)]
fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    stage0_cache::promote_builder_vm_stage0_cache(staging_dir, final_dir, source_fingerprint)
}

use mvm_build::cache_install::BUILDER_VM_PROVENANCE_FILE;
use mvm_build::cache_install::{
    BUILDER_VM_ARTIFACT_DIGEST_FILE, BUILDER_VM_SOURCE_FINGERPRINT_FILE,
};
