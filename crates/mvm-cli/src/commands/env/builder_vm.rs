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
mod sdk_sidecar;
mod stage0_artifact;
mod stage0_cache;
#[cfg(test)]
mod tests;
mod vm_helpers;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

#[cfg(feature = "release-artifact-bootstrap")]
use super::artifact_verify::bump_verify_outcome;
use super::artifact_verify::{
    ChecksumManifest, download_file, fetch_expected_hashes, verify_artifact_hash,
};
use crate::ui;
#[cfg(all(test, feature = "builder-vm"))]
use bootstrap::BuildHeartbeat;
pub(in crate::commands) use bootstrap::bootstrap_builder_vm_image;
#[cfg(all(test, not(feature = "release-artifact-bootstrap")))]
use bootstrap::perform_builder_vm_download_published;
#[cfg(test)]
use bootstrap::{
    BuilderVmBootstrapAction, STAGE0_FLAVOR_CURRENT, resolve_builder_vm_bootstrap_action,
};
#[cfg(all(test, feature = "builder-vm"))]
use default_microvm::DefaultMicrovmVariant;
#[cfg(any(feature = "builder-vm", test))]
use default_microvm::workload_config_carries_dm_verity;
pub(crate) use default_microvm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, ensure_workload_kernel,
};
#[cfg(test)]
use default_microvm::{
    default_microvm_assets, evict_incompatible_workload_kernel, missing_workload_kernel_message,
};
use image_ops::validate_dev_image_artifacts;
#[cfg(feature = "builder-vm")]
use image_ops::verify_stage0_rootfs_has_init;
pub(crate) use kernel::KernelSource;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::resolve_kernel_source;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(all(test, feature = "builder-vm"))]
use kernel::{format_compile_elapsed, format_compile_start};
#[cfg(feature = "builder-vm")]
pub(crate) use sdk_sidecar::build_sdk_sidecar_from_checkout;
#[cfg(feature = "builder-vm")]
use stage0_cache::Stage0FailureStage;
#[cfg(any(
    all(
        feature = "release-artifact-bootstrap",
        feature = "builder-vm",
        feature = "manifest-verify"
    ),
    test
))]
use stage0_cache::builder_vm_artifact_names;
#[cfg(feature = "release-artifact-bootstrap")]
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
    builder_vm_source_cache_ready, builder_vm_source_cache_status, builder_vm_source_fingerprint,
    fold_embedded_binary_identity, is_orphan_stage0_staging_dir_name,
    stage0_bootstrap_in_flight_at, stage0_fingerprint_prefix,
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

/// Locate the builder-VM flake at `nix/images/builder-vm/flake.nix`.
///
/// The flake produces the headless builder VM (`packages.<sys>.default`).
/// Used by `bootstrap_builder_vm_image` to locate Layer 1 and to detect a
/// source checkout. Returns `Err` when not in a source checkout, signalling
/// the caller to fall back to the published prebuilt.
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
pub(crate) fn find_builder_vm_flake_is_source_checkout() -> bool {
    find_builder_vm_flake().is_ok()
}
