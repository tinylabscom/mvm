//! `mvmctl catalog search` — search entries by name or tag.

use anyhow::Result;

use crate::ui;

pub(super) fn run(catalog: &mvm_core::catalog::Catalog, query: String) -> Result<()> {
    let results = catalog.search(&query);
    if results.is_empty() {
        ui::info(&format!("No entries matching {:?}", query));
    } else {
        println!("{:<20} {:<40} {:<30}", "NAME", "DESCRIPTION", "TAGS");
        for entry in results {
            println!(
                "{:<20} {:<40} {:<30}",
                entry.name,
                entry.description,
                entry.tags.join(", "),
            );
        }
    }
    Ok(())
}
