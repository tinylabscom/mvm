//! `mvmctl manifest ls` — list built slots.

use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show slots whose source manifest file is missing on disk
    #[arg(long)]
    pub orphans: bool,
}

#[derive(Serialize)]
struct SlotRow {
    slot_hash: String,
    manifest_path: String,
    name: Option<String>,
    updated_at: String,
    orphan: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let entries = tmpl::template_list_slots()?;

    let rows: Vec<SlotRow> = entries
        .into_iter()
        .map(|e| SlotRow {
            orphan: !std::path::Path::new(&e.manifest_path).exists(),
            slot_hash: e.slot_hash,
            manifest_path: e.manifest_path,
            name: e.name,
            updated_at: e.updated_at,
        })
        .filter(|r| !args.orphans || r.orphan)
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        if args.orphans {
            println!("No orphaned slots.");
        } else {
            println!("No built slots. Run `mvmctl init` then `mvmctl build` to create one.");
        }
        return Ok(());
    }

    for r in rows {
        let label = r.name.as_deref().unwrap_or("(unnamed)");
        let orphan_marker = if r.orphan { "  [ORPHAN]" } else { "" };
        println!(
            "{}  {}  {}{}",
            &r.slot_hash[..r.slot_hash.len().min(12)],
            label,
            r.manifest_path,
            orphan_marker
        );
        println!("    last built: {}", r.updated_at);
    }
    Ok(())
}
