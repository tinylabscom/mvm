//! `mvmctl image rm` — remove a cached OCI image.

use std::path::Path;

use anyhow::Result;

use crate::ui;

use super::super::shared::human_bytes;

pub(super) fn run(cache_root: &Path, reference: &str) -> Result<()> {
    let outcome = super::remove_image(cache_root, reference)?;
    ui::success(&format!(
        "Removed cached image {} ({} file(s), freed {}).",
        outcome.reference,
        outcome.removed_files,
        human_bytes(outcome.freed_bytes)
    ));
    mvm_core::audit_emit!(
        CachePrune,
        "source=image_rm reference={} removed={} freed_bytes={}",
        outcome.reference,
        outcome.removed_files,
        outcome.freed_bytes
    );
    Ok(())
}
