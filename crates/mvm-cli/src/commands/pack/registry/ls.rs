//! `mvmctl pack registry ls`.

use anyhow::Result;
use serde::Serialize;

use mvm_core::registry_pack::application_bundle::names_installed_application;
use mvm_core::registry_pack_store::{list_installed_registry_packs, load_pack_lockfile};

use super::LsArgs;
use crate::ui;

#[derive(Serialize)]
struct RegistryRow {
    pack: String,
    version: String,
    manifest_sha256: String,
    kind: &'static str,
    installed: bool,
}

fn rows(cache: &std::path::Path, lock_path: &std::path::Path) -> Result<Vec<RegistryRow>> {
    let lock = load_pack_lockfile(lock_path)?;
    let store = super::rm::store(cache, lock_path)?;
    Ok(list_installed_registry_packs(cache, &lock)
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
            kind: if names_installed_application(listing.pin.reference(), &store) {
                "application"
            } else {
                "policy"
            },
            installed: listing.installed,
        })
        .collect())
}

pub(in crate::commands) fn run(args: LsArgs) -> Result<()> {
    let rows = rows(
        &mvm_core::config::registry_pack_cache_dir(),
        &mvm_core::config::pack_lockfile_path(),
    )?;

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
            "{marker} {:<24} {:<12} {:<12} {}",
            row.pack,
            row.version,
            row.kind,
            &row.manifest_sha256[..row.manifest_sha256.len().min(12)],
        );
    }
    println!("(* marks a pack whose content is installed)");
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use mvm_core::packs::Sha256Hex;
    use mvm_core::registry_pack::{PackLockfile, PackPin};
    use mvm_core::registry_pack_store::save_pack_lockfile;

    /// Pin `reference` to a cached descriptor holding `manifest`.
    pub(in crate::commands::pack::registry) fn seed(
        cache: &std::path::Path,
        reference: &str,
        manifest: &[u8],
    ) -> PackPin {
        let digest = Sha256Hex::from_bytes(manifest);
        let entry = cache.join(digest.as_str());
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("manifest.json"), manifest).unwrap();
        PackPin::new(reference.parse().unwrap(), digest).unwrap()
    }

    #[test]
    fn ls_reports_an_application_and_a_policy_pack_by_kind() {
        let home = tempfile::tempdir().unwrap();
        let cache = home.path().join("cache");
        let lock = home.path().join("packs.lock.toml");
        let pins = vec![
            seed(&cache, "agent/claude@2.0.0", br#"{"kind":"application"}"#),
            seed(&cache, "runtime/go@1.0.0", br#"{"files":[]}"#),
        ];
        save_pack_lockfile(&lock, &PackLockfile::new(pins).unwrap()).unwrap();

        let kinds: Vec<_> = rows(&cache, &lock)
            .unwrap()
            .into_iter()
            .map(|row| (row.pack, row.kind, row.installed))
            .collect();

        assert_eq!(
            kinds,
            [
                ("agent/claude".to_string(), "application", true),
                ("runtime/go".to_string(), "policy", true),
            ]
        );
    }

    #[test]
    fn ls_of_a_pin_with_no_cached_descriptor_is_a_policy_pack_not_installed() {
        let home = tempfile::tempdir().unwrap();
        let cache = home.path().join("cache");
        let lock = home.path().join("packs.lock.toml");
        let pin = PackPin::new(
            "agent/claude@2.0.0".parse().unwrap(),
            Sha256Hex::from_bytes(b"absent"),
        )
        .unwrap();
        save_pack_lockfile(&lock, &PackLockfile::new(vec![pin]).unwrap()).unwrap();

        let rows = rows(&cache, &lock).unwrap();

        assert_eq!((rows[0].kind, rows[0].installed), ("policy", false));
    }
}
