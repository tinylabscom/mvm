//! `mvmctl image pull` — fetch + verify an OCI image into the cache.

use std::path::Path;

use anyhow::Result;

use crate::ui;

pub(super) fn run(cache_root: &Path, reference: String, prod: bool) -> Result<()> {
    match super::source::ImageSource::classify(&reference)? {
        super::source::ImageSource::Registry(_) => {}
        source => {
            mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(cache_root)?;
            let resolved = match source {
                super::source::ImageSource::OciArchive(path) => {
                    super::ingest::ingest_local_archive(cache_root, &path, &reference, prod)?
                }
                super::source::ImageSource::Stdin => {
                    super::ingest::ingest_stdin_archive(cache_root, &reference, prod)?
                }
                super::source::ImageSource::RootfsDir(path) => {
                    super::ingest::ingest_rootfs_dir(cache_root, &path, &reference, prod)?
                }
                super::source::ImageSource::Registry(_) => unreachable!(),
            };
            let provenance = &resolved.provenance;
            mvm_core::audit_emit!(
                ImageFetch,
                "source=image_pull reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source=local",
                resolved.reference,
                resolved.resolved_digest,
                prod,
                provenance.layer_digests.len(),
                provenance.trust_policy,
                provenance.verification_status,
            );
            ui::success(&format!(
                "Prepared {} -> {}",
                resolved.reference, resolved.resolved_digest
            ));
            ui::info(&format!("Rootfs: {}", resolved.rootfs_path.display()));
            return Ok(());
        }
    }

    // Materialization may spawn a builder VM (see `resolve_or_pull_run_image`);
    // sweep any helper processes a prior builder run orphaned before adding
    // another.
    crate::commands::env::builder_vm::sweep_orphaned_vm_helpers_on_startup();

    let (image, trust, auth_source) = super::pull_image_with_trust(cache_root, &reference, prod)?;
    let provenance = image.provenance("image_pull", &reference, &trust);
    mvm_core::audit_emit!(
        ImageFetch,
        "source=image_pull reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source={}",
        image.reference,
        image.resolved_digest,
        prod,
        provenance.layer_digests.len(),
        provenance.trust_policy,
        provenance.verification_status,
        auth_source
    );
    ui::success(&format!(
        "Pulled {} -> {}",
        image.reference, image.resolved_digest
    ));
    if let Some(rootfs_path) = image.rootfs_path {
        ui::info(&format!(
            "Rootfs: {}",
            cache_root.join(rootfs_path).display()
        ));
    }
    Ok(())
}
