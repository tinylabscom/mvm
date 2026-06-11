//! `mvmctl image pull` — fetch + verify an OCI image into the cache.

use std::path::Path;

use anyhow::Result;

use crate::ui;

pub(super) fn run(cache_root: &Path, reference: String, prod: bool) -> Result<()> {
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
