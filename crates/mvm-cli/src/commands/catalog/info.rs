//! `mvmctl catalog info` — print full details of one catalog entry as JSON.

use anyhow::Result;

pub(super) fn run(catalog: &mvm_core::catalog::Catalog, name: String) -> Result<()> {
    let entry = catalog
        .find(&name)
        .ok_or_else(|| anyhow::anyhow!("Catalog entry {:?} not found", name))?;
    println!("{}", serde_json::to_string_pretty(entry)?);
    Ok(())
}
