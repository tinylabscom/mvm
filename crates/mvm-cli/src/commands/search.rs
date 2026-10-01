//! `mvmctl search` — search the pack registry index, marking installed packs.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_core::registry_pack_store::load_pack_lockfile;
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::Cli;
use crate::pack_registry;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Optional case-insensitive substring over name and description
    #[arg(value_name = "QUERY")]
    pub query: Option<String>,
    /// Emit machine-readable JSON to stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct SearchRow {
    pack: String,
    description: String,
    versions: Vec<String>,
    installed: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let config = pack_registry::PackRegistryConfig::load();
    let index = pack_registry::fetch_index(&config)?;
    let hits = pack_registry::search_index(&index, args.query.as_deref());

    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let rows: Vec<SearchRow> = hits
        .iter()
        .map(|entry| SearchRow {
            pack: entry.coordinate(),
            description: entry.description.clone(),
            versions: entry.versions.clone(),
            installed: lock.pins().iter().any(|pin| {
                pin.reference().namespace() == entry.namespace
                    && pin.reference().name() == entry.name
            }),
        })
        .collect();

    if args.json {
        return crate::json_out::emit_json(&rows);
    }
    if rows.is_empty() {
        let query = args.query.as_deref().unwrap_or_default();
        println!("no packs match {query:?}");
        return Ok(());
    }
    for row in &rows {
        let marker = if row.installed { "*" } else { " " };
        println!(
            "{marker} {:<28} {:<24} {}",
            row.pack,
            row.versions.join(", "),
            row.description,
        );
    }
    println!("(* marks an installed pack)");
    Ok(())
}
