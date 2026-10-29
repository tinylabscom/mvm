//! `mvmctl pack registry rm`.

use anyhow::{Context, Result};

use mvm_core::registry_pack::PackReference;
use mvm_core::registry_pack::application_bundle::names_installed_application;
use mvm_core::registry_pack_store::remove_installed_registry_pack;

use super::RmArgs;
use crate::ui;

pub(in crate::commands) fn store(
    cache: &std::path::Path,
    lock: &std::path::Path,
) -> Result<mvm_core::registry_pack::application_bundle::ApplicationInstallStore> {
    Ok(
        mvm_core::registry_pack::application_bundle::ApplicationInstallStore::new(
            cache,
            lock,
            mvm_core::plan::bundle::BundleRegistry::default_path()?
                .root()
                .to_path_buf(),
        ),
    )
}

pub(in crate::commands) fn run(args: RmArgs) -> Result<()> {
    let reference: PackReference = args
        .reference
        .parse()
        .with_context(|| format!("invalid pack reference {:?}", args.reference))?;
    let cache = mvm_core::config::registry_pack_cache_dir();
    let lock = mvm_core::config::pack_lockfile_path();
    let was_application = names_installed_application(&reference, &store(&cache, &lock)?);
    if remove_installed_registry_pack(&cache, &lock, &reference)? {
        println!("removed {}", reference.coordinate_string());
        if was_application {
            println!("(the installed bundle stays in the shared bundle store)");
        }
    } else {
        ui::warn(&format!(
            "{} is not pinned; nothing to remove",
            reference.coordinate_string()
        ));
    }
    Ok(())
}
