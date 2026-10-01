//! `mvmctl pack registry rm`.

use anyhow::{Context, Result};

use mvm_core::registry_pack::PackReference;
use mvm_core::registry_pack_store::remove_installed_registry_pack;

use super::RmArgs;
use crate::ui;

pub(in crate::commands) fn run(args: RmArgs) -> Result<()> {
    let reference: PackReference = args
        .reference
        .parse()
        .with_context(|| format!("invalid pack reference {:?}", args.reference))?;
    if remove_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &mvm_core::config::pack_lockfile_path(),
        &reference,
    )? {
        println!("removed {}", reference.coordinate_string());
    } else {
        ui::warn(&format!(
            "{} is not pinned; nothing to remove",
            reference.coordinate_string()
        ));
    }
    Ok(())
}
