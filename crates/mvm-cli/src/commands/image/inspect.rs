//! `mvmctl image inspect` — show provenance for a cached OCI image.

use std::path::Path;

use anyhow::Result;

pub(super) fn run(cache_root: &Path, reference: &str, json: bool) -> Result<()> {
    let output = super::inspect_image(cache_root, reference)?;
    if json {
        crate::json_out::emit_json(&output)?;
    } else {
        super::render_inspect(&output);
    }
    Ok(())
}
