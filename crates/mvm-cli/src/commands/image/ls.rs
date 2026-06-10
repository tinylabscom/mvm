//! `mvmctl image ls` — list cached OCI images.

use std::path::Path;

use anyhow::Result;

pub(super) fn run(cache_root: &Path, registry: Option<&str>, json: bool) -> Result<()> {
    let rows = super::list_rows(cache_root, registry)?;
    if json {
        crate::json_out::emit_json(&rows)?;
    } else {
        super::render_list(&rows);
    }
    Ok(())
}
