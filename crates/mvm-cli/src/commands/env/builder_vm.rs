//! Builder-VM image bootstrap, Stage 0, workload-kernel build, and
//! bundled-image fetching helpers.

// `pub(in crate::commands)`: the `attested_builder_pack` release-fetch +
// verification-context helpers are reused by `commands::pack` (a sibling of
// `env`, not a descendant of `builder_vm`) to implement `mvmctl pack
// download/update builder` over the same trust construction, rather than
// forking a second copy.
pub(in crate::commands) mod bootstrap;
#[cfg(test)]
mod bootstrap_tests;
#[cfg(test)]
mod builder_vm_bootstrap_tests;
pub(in crate::commands) mod default_microvm;
mod image_ops;
mod kernel;
#[cfg(feature = "builder-vm")]
mod local_pair;
#[cfg(test)]
mod published_fetch_tests;
#[cfg(feature = "builder-vm")]
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
#[cfg(feature = "builder-vm")]
pub(in crate::commands) use bootstrap::bootstrap_tool_builder_vm_image;
pub(crate) use bootstrap::selected_local_checkout;

pub(super) const SYNTHESIZED_BUILDER_VM_CMDLINE: &str = "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 \
     loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n";

/// Run `f` with the launch-time pair artifact source when a checkout is
/// selected, or `None` when the selector is unset. The build closure runs
/// `ensure_pair_built`, so a launch under a selected checkout builds the
/// overlay or sidecar from the pair — never a download. A binary without the `builder-vm` feature has no pair build to
/// offer; the selector-unset behavior then applies.
#[cfg(feature = "builder-vm")]
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

#[cfg(not(feature = "builder-vm"))]
pub(crate) fn with_pair_artifact_source<T>(
    f: impl FnOnce(
        Option<&mut mvm_client::launch::runtime_source::PairArtifactSource<'_>>,
    ) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    f(None)
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

/// Whether this `mvmctl` is a contributor build running from the mvm source
/// checkout it was compiled from. That decides where helper binaries come
/// from and which shortcuts a published artifact may take; it says nothing
/// about where images come from, which is [`images_built_from_source`].
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
pub(crate) fn is_mvm_source_checkout() -> bool {
    mvm_build::image_source::mvm_source_checkout(
        mvm_build::artifact_acquisition::compiled_channel(),
    )
    .is_some()
}
#[cfg(all(test, feature = "builder-vm"))]
use default_microvm::DefaultMicrovmVariant;
#[cfg(any(feature = "builder-vm", test))]
use default_microvm::workload_config_carries_dm_verity;
pub(crate) use default_microvm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, ensure_workload_kernel,
};
#[cfg(test)]
use default_microvm::{evict_incompatible_workload_kernel, missing_workload_kernel_message};
use image_ops::validate_dev_image_artifacts;
pub(crate) use kernel::KernelSource;
#[cfg(all(test, feature = "builder-vm"))]
use kernel::format_compile_start;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::resolve_kernel_source;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(all(test, feature = "builder-vm"))]
pub(crate) use local_pair::derive_pair_key;
#[cfg(feature = "builder-vm")]
pub(crate) use local_pair::ensure_pair_built;
#[cfg(feature = "builder-vm")]
pub(crate) use local_pair::ensure_pair_workload_kernel;
#[cfg(feature = "builder-vm")]
pub(crate) use local_pair::seed_pair_workload_kernel_cache;
#[cfg(feature = "builder-vm")]
pub(crate) use local_pair::staged_contract_files;
#[cfg(test)]
use stage0_cache::builder_vm_artifact_names;
#[cfg(all(
    feature = "manifest-verify",
    any(
        all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
        test
    )
))]
use stage0_cache::builder_vm_boot_assets;
use stage0_cache::download_builder_vm_image;
pub(in crate::commands) use stage0_cache::{
    Stage0SweepOutcome, stage0_active_in_process, stage0_bootstrap_in_flight,
    sweep_orphaned_stage0_staging_dirs,
};
#[cfg(any(feature = "builder-vm", test))]
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
    BUILDER_SIDECARS, ProcSnapshot, WORKLOAD_SIDECARS, pid_is_alive,
    reap_orphaned_builder_egress_supervisors, reap_orphaned_vm_helpers_at,
    reap_orphaned_vm_helpers_at_with_snapshot,
};
pub(in crate::commands) use vm_helpers::{
    sweep_orphaned_vm_helpers_before_spawn, sweep_orphaned_vm_helpers_on_startup,
};

#[cfg(feature = "builder-vm")]
pub(in crate::commands) use vm_helpers::reap_orphaned_vm_helpers;

#[cfg(not(feature = "builder-vm"))]
pub(in crate::commands) fn reap_orphaned_vm_helpers(
    _dry_run: bool,
) -> Result<vm_helpers::ReapOutcome> {
    anyhow::bail!("builder helper reaping requires the `builder-vm` cargo feature")
}

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
#[cfg(any(feature = "builder-vm", test))]
use mvm_build::cache_install::{
    BUILDER_VM_ARTIFACT_DIGEST_FILE, BUILDER_VM_SOURCE_FINGERPRINT_FILE,
};

/// Env var opting an installed binary into the attested-pack acceleration path:
/// place a verified builder-image pack into the cache in lieu of the plain
/// checksum download. Truthy: `1`, `true`, `yes`, `on`. Off/unset ⇒ the download
/// path is byte-identical to today. Ignored in a contributor build running from
/// its source checkout, which takes no published-artifact shortcut.
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
const MVM_BUILDER_PACK_ENV: &str = "MVM_BUILDER_PACK";
