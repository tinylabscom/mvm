//! CLI preparation effects around the canonical client image owner.

use anyhow::Result;
use std::path::Path;

use mvm_client::cli_image::{AcquisitionHooks, OciPullRecord, ResolvedOciRunImage};

fn record_pull(node: &OciPullRecord<'_>) -> Result<()> {
    crate::commands::build::image_lineage::record_oci_pull_node(
        &crate::commands::build::image_lineage::OciPullNode {
            registry: node.registry,
            repository: node.repository,
            resolved_digest: node.resolved_digest,
            layer_digests: node.layer_digests.clone(),
            canonical_reference: node.canonical_reference,
            rootfs_path: node.rootfs_path,
        },
    )
}

pub(super) fn acquisition_hooks() -> AcquisitionHooks {
    AcquisitionHooks {
        before_materialize: sweep_before_builder_vm,
        record_pull,
    }
}

fn sweep_before_builder_vm() {
    crate::commands::env::builder_vm::sweep_orphaned_vm_helpers_before_spawn();
}

pub(in crate::commands) fn resolve_or_pull_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    mvm_client::cli_image::validate_preparation(reference, prod)?;
    crate::release_guest_runtime::ensure_release_pieces_prepared()?;
    mvm_client::cli_image::resolve_prepared(cache_root, reference, prod)
}

pub(in crate::commands) fn acquire_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    mvm_client::cli_image::validate_preparation(reference, prod)?;
    crate::release_guest_runtime::ensure_release_pieces_prepared()?;
    mvm_client::cli_image::acquire(cache_root, reference, prod, &acquisition_hooks())
}
