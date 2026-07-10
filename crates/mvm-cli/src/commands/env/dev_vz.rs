//! Dev environment lifecycle helpers + bundled image fetching, builder-VM
//! image bootstrap, Stage 0, and dev-cache inspection.

// `pub(in crate::commands)`: the `attested_builder_pack` release-fetch +
// verification-context helpers are reused by `commands::pack` (a sibling of
// `env`, not a descendant of `dev_vz`) to implement `mvmctl pack
// download/update builder` over the same trust construction, rather than
// forking a second copy.
pub(in crate::commands) mod bootstrap;
#[cfg(test)]
mod bootstrap_tests;
#[cfg(test)]
mod builder_vm_bootstrap_tests;
mod default_microvm;
mod image_ops;
mod kernel;
mod stage0_cache;
mod status;
#[cfg(test)]
mod tests;
mod vm_helpers;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::artifact_verify::{
    bump_verify_outcome, download_file, fetch_expected_hashes, url_exists, verify_artifact_hash,
};
use crate::ui;
#[cfg(all(test, feature = "builder-vm"))]
use bootstrap::BuildHeartbeat;
pub(in crate::commands) use bootstrap::bootstrap_builder_vm_image;
#[cfg(test)]
use bootstrap::{
    BuilderVmBootstrapAction, STAGE0_FLAVOR_CURRENT, perform_builder_vm_download_published,
    resolve_builder_vm_bootstrap_action,
};
#[cfg(all(test, feature = "builder-vm"))]
use default_microvm::DefaultMicrovmVariant;
#[cfg(test)]
use default_microvm::{
    WorkloadKernelBootstrap, default_microvm_assets, find_cached_workload_kernel,
    find_reusable_builder_kernel, resolve_workload_kernel_bootstrap,
};
pub(crate) use default_microvm::{
    ensure_default_microvm_image, ensure_workload_kernel, ensure_workload_verity_initrd,
};
pub use image_ops::cmd_dev_import_image;
pub(in crate::commands) use image_ops::ensure_dev_image;
#[cfg(test)]
use image_ops::find_local_fallback_image;
use image_ops::validate_dev_image_artifacts;
use image_ops::{
    BuilderVmCacheState, BuilderVmCacheStatusSummary, DevCacheInspectSummary, DevImageCacheSummary,
    DevStatusImage, resolve_dev_status_image,
};
#[cfg(feature = "builder-vm")]
use image_ops::{prepare_dev_image_out_dir, verify_stage0_rootfs_has_init};
#[cfg(all(test, feature = "builder-vm"))]
use kernel::format_compile_elapsed;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(feature = "builder-vm")]
use stage0_cache::Stage0FailureStage;
#[cfg(any(feature = "release-artifact-bootstrap", test))]
use stage0_cache::builder_vm_artifact_names;
#[cfg(feature = "release-artifact-bootstrap")]
use stage0_cache::download_builder_vm_image;
pub(in crate::commands) use stage0_cache::{
    Stage0SweepOutcome, stage0_bootstrap_in_flight, sweep_orphaned_stage0_staging_dirs,
};
#[cfg(any(feature = "builder-vm", test))]
use stage0_cache::{
    acquire_stage0_lock, build_image_via_libkrun, builder_vm_source_cache_status,
    builder_vm_source_fingerprint, stage0_fingerprint_prefix, unique_builder_vm_stage0_staging_dir,
};
#[cfg(test)]
use stage0_cache::{
    builder_vm_source_cache_ready, fold_embedded_binary_identity,
    is_orphan_stage0_staging_dir_name, stage0_bootstrap_in_flight_at,
    sweep_orphaned_stage0_staging_dirs_at, write_builder_vm_artifact_digest_manifest,
    write_builder_vm_source_cache_provenance, write_builder_vm_source_fingerprint,
};
use status::resolve_dev_cache_inspect_summary;
pub(in crate::commands) use status::{
    build_dev_down_json, build_dev_status_json, build_dev_status_json_linux_native,
    build_dev_status_json_vmless, build_dev_up_json,
};
#[cfg(test)]
use status::{builder_vm_cache_status_summary, dev_image_cache_summary};
pub(in crate::commands) use vm_helpers::sweep_orphaned_vm_helpers_on_startup;
#[cfg(test)]
use vm_helpers::{
    BUILDER_SIDECARS, ProcSnapshot, WORKLOAD_SIDECARS, pid_is_alive, reap_orphaned_vm_helpers_at,
    reap_orphaned_vm_helpers_at_with_snapshot,
};

#[cfg(feature = "builder-vm")]
pub(in crate::commands) use vm_helpers::reap_orphaned_vm_helpers;

#[cfg(not(feature = "builder-vm"))]
pub(in crate::commands) fn reap_orphaned_vm_helpers(
    _dry_run: bool,
) -> Result<vm_helpers::ReapOutcome> {
    anyhow::bail!("builder helper reaping requires the `builder-vm` cargo feature")
}

pub(in crate::commands) const DEV_VM_NAME: &str = "mvm-dev";

pub(super) fn builder_vm_host_arch() -> &'static str {
    bootstrap::builder_vm_host_arch()
}

#[cfg(feature = "builder-vm")]
pub(super) fn builder_backend_attempt_order(
    selected: mvm_build::builder_backend_select::BuilderBackendChoice,
    explicit: bool,
) -> Vec<mvm_build::builder_backend_select::BuilderBackendChoice> {
    stage0_cache::builder_backend_attempt_order(selected, explicit)
}

#[cfg(feature = "builder-vm")]
pub(super) fn write_builder_vm_cache_sidecars(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    stage0_cache::write_builder_vm_cache_sidecars(dir, source_fingerprint)
}

#[cfg(test)]
fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    stage0_cache::promote_builder_vm_stage0_cache(staging_dir, final_dir, source_fingerprint)
}

#[cfg(test)]
fn stage0_failure_reason_summary(err: &anyhow::Error) -> String {
    stage0_cache::stage0_failure_reason_summary(err)
}

fn dev_cache_inspect_json(summary: &DevCacheInspectSummary) -> Result<String> {
    status::dev_cache_inspect_json(summary)
}

const BUILDER_VM_SOURCE_FINGERPRINT_FILE: &str = ".mvm-source.sha256";
const BUILDER_VM_ARTIFACT_DIGEST_FILE: &str = ".mvm-artifacts.sha256";
const BUILDER_VM_PROVENANCE_FILE: &str = ".mvm-provenance.json";
/// Env var opting an installed binary into the attested-pack acceleration path:
/// place a verified builder-image pack into the cache in lieu of the plain
/// checksum download. Truthy: `1`, `true`, `yes`, `on`. Off/unset ⇒ the download
/// path is byte-identical to today. Ignored on a source checkout (which builds
/// the builder image locally and never fetches published artifacts).
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
const MVM_BUILDER_PACK_ENV: &str = "MVM_BUILDER_PACK";
/// Absolute path the builder-VM rootfs must carry for the steady-state
/// VM to boot (`init=/sbin/mvm-host-vm-init` on the kernel cmdline).
/// `verify_stage0_rootfs_has_init` looks this inode up directly via a
/// read-only ext4 walk after Stage 0 builds the image.
#[cfg(feature = "builder-vm")]
const HOST_VM_INIT_ROOTFS_PATH: &str = "/sbin/mvm-host-vm-init";

/// Inspect dev caches without booting, rebuilding, or exposing local
/// artifact paths/digests.
pub(super) fn cmd_dev_cache_inspect(json: bool) -> Result<()> {
    let summary = resolve_dev_cache_inspect_summary();
    if json {
        println!("{}", dev_cache_inspect_json(&summary)?);
        return Ok(());
    }

    ui::info("Dev cache:");
    ui::info(&format!(
        "  Dev image: {} (kernel: {}, rootfs: {})",
        summary.dev_image.state, summary.dev_image.kernel, summary.dev_image.rootfs
    ));
    ui::info(&format!(
        "  Builder:   {} cache {} (reason: {})",
        summary.builder_cache.cache_kind,
        summary.builder_cache.state.label(),
        summary.builder_cache.reason_code
    ));
    Ok(())
}

/// Locate the builder-VM flake at `nix/images/builder-vm/flake.nix`.
///
/// The consolidated flake produces both the headless builder VM
/// (`packages.<sys>.default`) and the interactive
/// dev-shell image (`packages.<sys>.dev`). Used by `ensure_dev_image`
/// to detect a source checkout, and by `bootstrap_builder_vm_image`
/// to locate Layer 1. Returns `Err` when not in a source checkout,
/// signalling the caller to fall back to the published prebuilt.
fn find_builder_vm_flake() -> Result<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("images").join("builder-vm");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!("Builder VM flake not found. Expected at nix/images/builder-vm/flake.nix.")
}

/// Returns `true` when the running `mvmctl` is a source-checkout build
/// (the in-repo builder-VM flake is present). The local-build invariant
/// applies when this is true: source checkouts must build kernels
/// locally and never fetch pre-built artifacts.
pub(in crate::commands) fn find_builder_vm_flake_is_source_checkout() -> bool {
    find_builder_vm_flake().is_ok()
}
