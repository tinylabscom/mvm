//! `mvmctl pack prune`.

use anyhow::Result;
use serde::Serialize;

use crate::ui;

#[derive(Debug, Serialize)]
struct PruneReport {
    dry_run: bool,
    keep_recent: usize,
    removed: Vec<String>,
}

pub(in crate::commands) fn run(keep_recent: usize, dry_run: bool, json: bool) -> Result<()> {
    let removed = mvm_core::pack_cache::prune_versions(keep_recent, dry_run)?;

    if json {
        let report = PruneReport {
            dry_run,
            keep_recent,
            removed: removed.iter().map(|h| h.as_str().to_string()).collect(),
        };
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }

    if removed.is_empty() {
        ui::info("No prunable pack versions.");
        return Ok(());
    }

    let verb = if dry_run { "Would remove" } else { "Removed" };
    for hash in &removed {
        println!(
            "{verb} pack version {}",
            &hash.as_str()[..hash.as_str().len().min(12)]
        );
    }
    ui::notice(&format!(
        "{verb} {} pack version(s), keeping the {keep_recent} newest per key plus the active one.",
        removed.len()
    ));

    if !dry_run {
        mvm_core::audit_emit!(
            CachePrune,
            "op=pack_prune keep_recent={keep_recent} removed={}",
            removed.len()
        );
    }
    Ok(())
}
