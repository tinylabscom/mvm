//! `mvmctl pack registry ls`.

use anyhow::Result;
use serde::Serialize;

use mvm_core::registry_pack_store::{list_installed_registry_packs, load_pack_lockfile};

use super::LsArgs;
use crate::ui;

#[derive(Serialize)]
struct RegistryRow {
    pack: String,
    version: String,
    manifest_sha256: String,
    installed: bool,
}

pub(in crate::commands) fn run(args: LsArgs) -> Result<()> {
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let rows: Vec<RegistryRow> =
        list_installed_registry_packs(&mvm_core::config::registry_pack_cache_dir(), &lock)
            .iter()
            .map(|listing| RegistryRow {
                pack: format!(
                    "{}/{}",
                    listing.pin.reference().namespace(),
                    listing.pin.reference().name()
                ),
                version: listing
                    .pin
                    .reference()
                    .version()
                    .map(|version| version.to_string())
                    .unwrap_or_default(),
                manifest_sha256: listing.pin.manifest_sha256().as_str().to_string(),
                installed: listing.installed,
            })
            .collect();

    if args.json {
        return crate::json_out::emit_json(&rows);
    }
    if rows.is_empty() {
        ui::info("No registry packs pinned. `mvmctl search` lists what the registry offers.");
        return Ok(());
    }
    for row in &rows {
        let marker = if row.installed { "*" } else { " " };
        println!(
            "{marker} {:<24} {:<12} {}",
            row.pack,
            row.version,
            &row.manifest_sha256[..row.manifest_sha256.len().min(12)],
        );
    }
    println!("(* marks a pack whose content is installed)");
    Ok(())
}
