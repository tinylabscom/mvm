//! `mvmctl catalog list` — list bundled catalog entries.

use anyhow::Result;

use crate::ui;

pub(super) fn run(catalog: &mvm_core::catalog::Catalog) -> Result<()> {
    if catalog.entries.is_empty() {
        ui::info("No entries in catalog.");
    } else {
        println!(
            "{:<20} {:<40} {:<6} {:<8}",
            "NAME", "DESCRIPTION", "CPUS", "MEM"
        );
        for entry in &catalog.entries {
            println!(
                "{:<20} {:<40} {:<6} {:<8}",
                entry.name,
                entry.description,
                entry.default_cpus,
                format!("{}M", entry.default_memory_mib),
            );
        }
    }
    Ok(())
}
