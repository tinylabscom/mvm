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

/// The lines a removal prints, or `None` when `reference` is not pinned.
fn remove(
    cache: &std::path::Path,
    lock: &std::path::Path,
    reference: &PackReference,
) -> Result<Option<Vec<String>>> {
    let was_application = names_installed_application(reference, &store(cache, lock)?);
    if !remove_installed_registry_pack(cache, lock, reference)? {
        return Ok(None);
    }
    let mut lines = vec![format!("removed {}", reference.coordinate_string())];
    if was_application {
        lines.push("(the installed bundle stays in the shared bundle store)".to_string());
    }
    Ok(Some(lines))
}

pub(in crate::commands) fn run(args: RmArgs) -> Result<()> {
    let reference: PackReference = args
        .reference
        .parse()
        .with_context(|| format!("invalid pack reference {:?}", args.reference))?;
    let cache = mvm_core::config::registry_pack_cache_dir();
    let lock = mvm_core::config::pack_lockfile_path();
    match remove(&cache, &lock, &reference)? {
        Some(lines) => lines.iter().for_each(|line| println!("{line}")),
        None => ui::warn(&format!(
            "{} is not pinned; nothing to remove",
            reference.coordinate_string()
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pack::registry::ls::tests::seed;
    use mvm_core::registry_pack::PackLockfile;
    use mvm_core::registry_pack_store::{load_pack_lockfile, save_pack_lockfile};

    fn setup(manifest: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let cache = home.path().join("cache");
        let lock = home.path().join("packs.lock.toml");
        let pin = seed(&cache, "agent/claude@2.0.0", manifest);
        save_pack_lockfile(&lock, &PackLockfile::new(vec![pin]).unwrap()).unwrap();
        (home, cache, lock)
    }

    #[test]
    fn removing_an_application_says_the_bundle_stays_and_drops_only_the_pin() {
        let (_home, cache, lock) = setup(br#"{"kind":"application"}"#);
        let reference = "agent/claude@2.0.0".parse().unwrap();

        let lines = remove(&cache, &lock, &reference).unwrap().unwrap();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "removed agent/claude");
        assert!(lines[1].contains("bundle stays"));
        assert!(load_pack_lockfile(&lock).unwrap().pins().is_empty());
    }

    #[test]
    fn removing_a_policy_pack_does_not_mention_a_bundle() {
        let (_home, cache, lock) = setup(br#"{"files":[]}"#);
        let reference = "agent/claude@2.0.0".parse().unwrap();

        let lines = remove(&cache, &lock, &reference).unwrap().unwrap();

        assert_eq!(lines, ["removed agent/claude"]);
    }

    #[test]
    fn removing_an_unpinned_reference_prints_nothing_and_changes_nothing() {
        let (_home, cache, lock) = setup(br#"{"kind":"application"}"#);
        let reference = "agent/other@1.0.0".parse().unwrap();

        assert_eq!(remove(&cache, &lock, &reference).unwrap(), None);
        assert_eq!(load_pack_lockfile(&lock).unwrap().pins().len(), 1);
    }
}
