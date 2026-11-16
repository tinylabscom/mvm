//! `mvmctl image ls` — list cached OCI images.

use std::path::Path;

use anyhow::Result;

pub(super) fn run(cache_root: &Path, registry: Option<&str>, json: bool) -> Result<()> {
    if json {
        crate::json_out::emit_json(&mvm_client::cli_image::list_json(cache_root, registry)?)?;
    } else {
        mvm_client::cli_image::render_list(cache_root, registry)?;
    }
    Ok(())
}
