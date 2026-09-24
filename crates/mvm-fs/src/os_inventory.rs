//! OS package inventory of an unpacked rootfs tree.
//!
//! The CVE scan and the production admission gate both key off the exact
//! tree that ships, so the inventory reads the package databases of the
//! unpacked OCI rootfs directly: dpkg's `var/lib/dpkg/status`, apk's
//! `lib/apk/db/installed`, and the distribution identity from
//! `etc/os-release` (falling back to `usr/lib/os-release`). When the tree
//! carries a kernel — `boot/vmlinuz-*` or `lib/modules/<version>/` — its
//! version is recorded too.
//!
//! Everything here is fail-closed at the *record* level: a dpkg paragraph
//! or apk record missing its name or version field is skipped and counted
//! in [`OsInventory::limitations`], never guessed at, because a partially
//! parsed package database would report a smaller attack surface than the
//! image actually has.
//!
//! What this deliberately does not parse: the rpm database
//! (`var/lib/rpm`), a binary Berkeley DB whose absence from the inventory
//! is reported as [`RPM_UNSUPPORTED`] rather than silently producing an
//! incomplete component list.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Coverage marker for the honest rpm gap: `var/lib/rpm` is a binary
/// Berkeley DB and this module does not parse it.
pub const RPM_UNSUPPORTED: &str = "rpm_db_binary_format";

/// One OS package discovered in a rootfs package database.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OsComponent {
    /// Advisory-ecosystem name the component is queried under
    /// (`Debian`, `Alpine`, ...).
    pub ecosystem: String,
    pub name: String,
    /// Installed version, verbatim — a Debian epoch (`1:2.3-4`) is part
    /// of the version and is never rewritten.
    pub version: String,
    /// Rootfs-relative path of the database the component was read from.
    pub source: String,
}

/// The distribution identity from os-release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    pub id: String,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
}

/// The full inventory of one unpacked rootfs tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInventory {
    pub distribution: Option<OsRelease>,
    /// Sorted and deduplicated on `(ecosystem, name, version)`.
    pub components: Vec<OsComponent>,
    /// Kernel version discovered under `boot/` or `lib/modules/`, when the
    /// image carries one. Most OCI base images do not.
    pub kernel_version: Option<String>,
    /// Rootfs-relative paths of the package databases parsed, sorted.
    pub package_databases: Vec<String>,
    /// Everything the inventory had to skip or approximate, spelled out.
    pub limitations: Vec<String>,
    /// Package database formats present but not parsed (see
    /// [`RPM_UNSUPPORTED`]).
    pub unsupported: Vec<String>,
}

/// Inventory failures. Individual *files* that are missing or unreadable
/// are inventory limitations, not errors; the error case is a root that
/// cannot be inventoried at all.
#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("rootfs path {path} does not resolve to a directory")]
    NotADirectory { path: String },
}

/// Walk the well-known package databases of the rootfs at `root` and
/// return the inventory. Never silently empty: a tree with no supported
/// package database is reported in `limitations`.
pub fn inventory_rootfs(root: &Path) -> Result<OsInventory, InventoryError> {
    if !root.is_dir() {
        return Err(InventoryError::NotADirectory {
            path: root.display().to_string(),
        });
    }
    let mut inventory = OsInventory::default();

    inventory.distribution = read_os_release(root, &mut inventory.limitations);

    if let Some(text) = read_db_file(root, "var/lib/dpkg/status", &mut inventory.limitations) {
        let ecosystem = match inventory.distribution.as_ref() {
            Some(release) => os_ecosystem(&release.id, &mut inventory.limitations),
            None => {
                inventory.limitations.push(
                    "var/lib/dpkg/status is present but no os-release file identifies the distribution; dpkg components are inventoried under ecosystem \"Debian\""
                        .to_string(),
                );
                "Debian".to_string()
            }
        };
        parse_dpkg_status(
            &text,
            "var/lib/dpkg/status",
            &ecosystem,
            &mut inventory.components,
            &mut inventory.limitations,
        );
        inventory
            .package_databases
            .push("var/lib/dpkg/status".to_string());
    }

    if let Some(text) = read_db_file(root, "lib/apk/db/installed", &mut inventory.limitations) {
        parse_apk_installed(
            &text,
            "lib/apk/db/installed",
            &mut inventory.components,
            &mut inventory.limitations,
        );
        inventory
            .package_databases
            .push("lib/apk/db/installed".to_string());
    }

    // rpm's database is a binary Berkeley DB (or sqlite, depending on rpm
    // vintage); neither is parsed. Naming the gap beats inventing a parser
    // over a format that was never read.
    if root.join("var/lib/rpm").is_dir() {
        inventory.unsupported.push(RPM_UNSUPPORTED.to_string());
        inventory.limitations.push(
            "var/lib/rpm exists but the rpm database is a binary format this inventory does not parse; rpm-installed packages are absent from the component list"
                .to_string(),
        );
    }

    if inventory.package_databases.is_empty() {
        inventory.limitations.push(
            "no supported package database (dpkg status, apk installed) was found in the rootfs; the OS component inventory is empty"
                .to_string(),
        );
    }

    inventory.kernel_version = discover_kernel_version(root, &mut inventory.limitations);

    inventory.package_databases.sort();
    inventory.components.sort();
    inventory.components.dedup_by(|left, right| left == right);
    Ok(inventory)
}

/// Read a rootfs-relative database file. Absent is `None`; present but
/// unreadable is a limitation, because an unreadable package database is
/// not the same as no package database.
fn read_db_file(root: &Path, relative: &str, limitations: &mut Vec<String>) -> Option<String> {
    let path = root.join(relative);
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(error) => {
            limitations.push(format!(
                "{relative} exists but could not be read ({error}); its packages are absent from the component list"
            ));
            None
        }
    }
}

fn read_os_release(root: &Path, limitations: &mut Vec<String>) -> Option<OsRelease> {
    for relative in ["etc/os-release", "usr/lib/os-release"] {
        let path = root.join(relative);
        if !path.is_file() {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                limitations.push(format!(
                    "{relative} could not be read ({error}); the distribution identity is unknown"
                ));
                continue;
            }
        };
        return match parse_os_release(&text) {
            Ok(release) => Some(release),
            Err(reason) => {
                limitations.push(format!(
                    "{relative} could not be parsed ({reason}); the distribution identity is unknown"
                ));
                None
            }
        };
    }
    None
}

/// The advisory-ecosystem name for a distribution id from os-release.
/// The known mappings name the ecosystems OSV queries understand;
/// anything else passes through lowercased with a limitation, matching
/// OSV's verbatim pass-through for ecosystems it does not know.
fn os_ecosystem(id: &str, limitations: &mut Vec<String>) -> String {
    match id {
        "debian" => "Debian".to_string(),
        "ubuntu" => "Ubuntu".to_string(),
        "alpine" => "Alpine".to_string(),
        "wolfi" => "Wolfi".to_string(),
        "chainguard" => "Chainguard".to_string(),
        other => {
            limitations.push(format!(
                "unrecognised distribution id \"{other}\"; using the lowercased id as the advisory ecosystem"
            ));
            other.to_ascii_lowercase()
        }
    }
}

/// dpkg's `var/lib/dpkg/status`: paragraph blocks separated by blank
/// lines, `Package:`/`Version:` fields per block. Fail-closed: a block
/// missing either field is skipped and counted in a limitation rather
/// than guessed at.
fn parse_dpkg_status(
    text: &str,
    source: &str,
    ecosystem: &str,
    components: &mut Vec<OsComponent>,
    limitations: &mut Vec<String>,
) {
    let mut malformed = 0usize;
    let mut block_index = 0usize;
    for block in text.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        block_index += 1;
        let mut package = None;
        let mut version = None;
        for line in block.lines() {
            // Continuation lines (leading whitespace) belong to the
            // previous field and never carry Package:/Version:.
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            if let Some(value) = line.strip_prefix("Package:") {
                package = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Version:") {
                version = Some(value.trim().to_string());
            }
        }
        match (package, version) {
            (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
                components.push(OsComponent {
                    ecosystem: ecosystem.to_string(),
                    name,
                    version,
                    source: source.to_string(),
                });
            }
            _ => malformed += 1,
        }
    }
    if malformed > 0 {
        limitations.push(format!(
            "{source}: {malformed} of {block_index} paragraph block(s) lacked a Package: or Version: field and were skipped rather than parsed partially"
        ));
    }
}

/// apk's `lib/apk/db/installed`: records separated by blank lines, with
/// the package name on `P:` and its version on `V:`. Fail-closed like the
/// dpkg parser: a record missing either field is skipped and counted.
fn parse_apk_installed(
    text: &str,
    source: &str,
    components: &mut Vec<OsComponent>,
    limitations: &mut Vec<String>,
) {
    let mut malformed = 0usize;
    let mut record_index = 0usize;
    for record in text.split("\n\n") {
        if record.trim().is_empty() {
            continue;
        }
        record_index += 1;
        let mut package = None;
        let mut version = None;
        for line in record.lines() {
            if let Some(value) = line.strip_prefix("P:") {
                package = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("V:") {
                version = Some(value.trim().to_string());
            }
        }
        match (package, version) {
            (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
                components.push(OsComponent {
                    ecosystem: "Alpine".to_string(),
                    name,
                    version,
                    source: source.to_string(),
                });
            }
            _ => malformed += 1,
        }
    }
    if malformed > 0 {
        limitations.push(format!(
            "{source}: {malformed} of {record_index} record(s) lacked a P: or V: line and were skipped rather than parsed partially"
        ));
    }
}

/// `KEY=value` lines, optionally double- or single-quoted. `ID` is
/// required; without it the file does not identify a distribution and the
/// caller treats it as unparsed.
fn parse_os_release(text: &str) -> Result<OsRelease, String> {
    let mut id = None;
    let mut version_id = None;
    let mut pretty_name = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        match key.trim() {
            "ID" => id = Some(value),
            "VERSION_ID" => version_id = Some(value),
            "PRETTY_NAME" => pretty_name = Some(value),
            _ => {}
        }
    }
    match id {
        Some(id) if !id.is_empty() => Ok(OsRelease {
            id,
            version_id,
            pretty_name,
        }),
        _ => Err("no ID field".to_string()),
    }
}

/// Discover the version of a kernel the image itself carries, from
/// `boot/vmlinuz-<version>` files or `lib/modules/<version>/`
/// directories. OCI base images rarely ship one; the kernel a guest
/// actually boots is resolved separately, so this is strictly the
/// in-image kernel. With several candidates the first sorted version
/// wins and the rest are named in a limitation.
fn discover_kernel_version(root: &Path, limitations: &mut Vec<String>) -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    let modules = root.join("lib/modules");
    if modules.is_dir()
        && let Ok(entries) = std::fs::read_dir(&modules)
    {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                candidates.push(name.to_string());
            }
        }
    }
    let boot = root.join("boot");
    if boot.is_dir()
        && let Ok(entries) = std::fs::read_dir(&boot)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(version) = name.strip_prefix("vmlinuz-") {
                candidates.push(version.to_string());
            }
        }
    }
    candidates.retain(|version| version.as_bytes().first().is_some_and(u8::is_ascii_digit));
    candidates.sort();
    candidates.dedup();
    if candidates.len() > 1 {
        limitations.push(format!(
            "the rootfs carries several kernel versions ({}); the first sorted one is inventoried",
            candidates.join(", ")
        ));
    }
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse_dpkg(text: &str) -> (Vec<OsComponent>, Vec<String>) {
        let mut components = Vec::new();
        let mut limitations = Vec::new();
        parse_dpkg_status(
            text,
            "var/lib/dpkg/status",
            "Debian",
            &mut components,
            &mut limitations,
        );
        (components, limitations)
    }

    #[test]
    fn dpkg_status_parses_paragraph_blocks() {
        let text = "Package: base-files\nVersion: 12.4\nDescription: base\n files\n\nPackage: openssl\nVersion: 1.1.1n\n\n";
        let (components, limitations) = parse_dpkg(text);
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].name, "base-files");
        assert_eq!(components[0].version, "12.4");
        assert_eq!(components[0].ecosystem, "Debian");
        assert_eq!(components[0].source, "var/lib/dpkg/status");
        assert_eq!(components[1].name, "openssl");
        assert!(limitations.is_empty(), "clean input: {limitations:?}");
    }

    #[test]
    fn dpkg_status_keeps_epoch_versions_verbatim() {
        let (components, limitations) = parse_dpkg("Package: zlib1g\nVersion: 1:1.2.11.dfsg-2\n\n");
        assert_eq!(components.len(), 1);
        assert_eq!(
            components[0].version, "1:1.2.11.dfsg-2",
            "the epoch is part of the installed version and must not be rewritten"
        );
        assert!(limitations.is_empty());
    }

    #[test]
    fn dpkg_status_is_fail_closed_on_malformed_blocks() {
        let text = "Package: ok\nVersion: 1.0\n\nPackage: no-version\nDescription: oops\n\nVersion: 2.0\n\n";
        let (components, limitations) = parse_dpkg(text);
        assert_eq!(components.len(), 1, "only the complete block is parsed");
        assert_eq!(components[0].name, "ok");
        assert_eq!(limitations.len(), 1, "{limitations:?}");
        assert!(limitations[0].contains("2 of 3"));
    }

    #[test]
    fn apk_installed_parses_records() {
        let text = "P:musl\nV:1.2.3\nA:x86_64\n\nP:busybox\nV:1.36.0\n\n";
        let mut components = Vec::new();
        let mut limitations = Vec::new();
        parse_apk_installed(
            text,
            "lib/apk/db/installed",
            &mut components,
            &mut limitations,
        );
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].ecosystem, "Alpine");
        assert_eq!(components[1].name, "busybox");
        assert_eq!(components[1].version, "1.36.0");
        assert!(limitations.is_empty(), "clean input: {limitations:?}");
    }

    #[test]
    fn apk_installed_is_fail_closed_on_malformed_records() {
        let text = "P:musl\nV:1.2.3\n\nP:orphan\n\n";
        let mut components = Vec::new();
        let mut limitations = Vec::new();
        parse_apk_installed(
            text,
            "lib/apk/db/installed",
            &mut components,
            &mut limitations,
        );
        assert_eq!(components.len(), 1);
        assert_eq!(limitations.len(), 1);
        assert!(limitations[0].contains("1 of 2"));
    }

    #[test]
    fn os_release_parses_quoted_values() {
        let release = parse_os_release(
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
        )
        .expect("parses");
        assert_eq!(release.id, "debian");
        assert_eq!(release.version_id.as_deref(), Some("12"));
        assert_eq!(
            release.pretty_name.as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert!(
            parse_os_release("NAME=thing\n").is_err(),
            "no ID, no identity"
        );
    }

    #[test]
    fn os_ecosystem_maps_known_distributions_and_flags_unknown_ones() {
        let mut limitations = Vec::new();
        assert_eq!(os_ecosystem("debian", &mut limitations), "Debian");
        assert_eq!(os_ecosystem("ubuntu", &mut limitations), "Ubuntu");
        assert_eq!(os_ecosystem("alpine", &mut limitations), "Alpine");
        assert_eq!(os_ecosystem("wolfi", &mut limitations), "Wolfi");
        assert!(limitations.is_empty());
        assert_eq!(os_ecosystem("centos", &mut limitations), "centos");
        assert_eq!(limitations.len(), 1, "unknown ids carry a limitation");
    }

    fn write_tree(root: &Path, files: &[(&str, &str)]) {
        for (relative, text) in files {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("relative has parent")).expect("mkdir");
            fs::write(path, text).expect("write");
        }
    }

    #[test]
    fn inventory_reads_dpkg_apk_and_os_release_from_a_tree() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_tree(
            tmp.path(),
            &[
                ("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
                (
                    "var/lib/dpkg/status",
                    "Package: openssl\nVersion: 1.1.1n\n\n",
                ),
                ("lib/apk/db/installed", "P:musl\nV:1.2.3\n\n"),
            ],
        );
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert_eq!(inventory.distribution.expect("distro").id, "debian");
        assert_eq!(inventory.components.len(), 2);
        assert_eq!(
            inventory.package_databases,
            vec![
                "lib/apk/db/installed".to_string(),
                "var/lib/dpkg/status".to_string()
            ]
        );
        assert!(
            inventory.limitations.is_empty(),
            "{:?}",
            inventory.limitations
        );
    }

    #[test]
    fn inventory_falls_back_to_usr_lib_os_release() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_tree(
            tmp.path(),
            &[("usr/lib/os-release", "ID=alpine\nVERSION_ID=3.20\n")],
        );
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        let release = inventory.distribution.expect("distro");
        assert_eq!(release.id, "alpine");
        assert_eq!(release.version_id.as_deref(), Some("3.20"));
    }

    #[test]
    fn dpkg_without_os_release_inventories_as_debian_with_a_limitation() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_tree(
            tmp.path(),
            &[(
                "var/lib/dpkg/status",
                "Package: openssl\nVersion: 1.1.1n\n\n",
            )],
        );
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert!(inventory.distribution.is_none());
        assert_eq!(inventory.components[0].ecosystem, "Debian");
        assert!(
            inventory
                .limitations
                .iter()
                .any(|line| line.contains("no os-release")),
            "{:?}",
            inventory.limitations
        );
    }

    #[test]
    fn an_rpm_database_is_reported_as_an_unsupported_gap() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("var/lib/rpm")).expect("mkdir");
        fs::write(tmp.path().join("var/lib/rpm/Packages"), b"\x00\x01binary").expect("write");
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert!(inventory.unsupported.iter().any(|u| u == RPM_UNSUPPORTED));
        assert!(
            inventory
                .limitations
                .iter()
                .any(|line| line.contains("rpm")),
            "{:?}",
            inventory.limitations
        );
    }

    #[test]
    fn a_rootfs_without_package_databases_reports_an_empty_inventory_honestly() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_tree(tmp.path(), &[("etc/shadow", "root:*:19000:0:99999:7:::\n")]);
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert!(inventory.components.is_empty());
        assert!(inventory.package_databases.is_empty());
        assert!(
            inventory
                .limitations
                .iter()
                .any(|line| line.contains("no supported package database")),
            "{:?}",
            inventory.limitations
        );
    }

    #[test]
    fn kernel_version_is_discovered_from_lib_modules_and_boot() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("lib/modules/6.8.0-41-generic")).expect("mkdir");
        write_tree(tmp.path(), &[("boot/vmlinuz-6.8.0-41-generic", "x")]);
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert_eq!(
            inventory.kernel_version.as_deref(),
            Some("6.8.0-41-generic")
        );
    }

    #[test]
    fn several_kernel_versions_pick_the_first_sorted_and_say_so() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("lib/modules/6.8.0-41-generic")).expect("mkdir");
        fs::create_dir_all(tmp.path().join("lib/modules/5.15.0-1")).expect("mkdir");
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert_eq!(inventory.kernel_version.as_deref(), Some("5.15.0-1"));
        assert!(
            inventory
                .limitations
                .iter()
                .any(|line| line.contains("several kernel versions")),
            "{:?}",
            inventory.limitations
        );
    }

    #[test]
    fn non_version_kernel_artifacts_are_ignored() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_tree(
            tmp.path(),
            &[("boot/vmlinuz", "x"), ("boot/initrd.img", "y")],
        );
        let inventory = inventory_rootfs(tmp.path()).expect("inventory");
        assert_eq!(inventory.kernel_version, None);
    }

    #[test]
    fn inventory_refuses_a_root_that_is_not_a_directory() {
        let err = inventory_rootfs(Path::new("/definitely/not/a/rootfs"))
            .expect_err("a missing root must fail");
        assert!(matches!(err, InventoryError::NotADirectory { .. }));
    }

    #[test]
    fn inventory_types_round_trip_through_serde() {
        let inventory = OsInventory {
            distribution: Some(OsRelease {
                id: "debian".to_string(),
                version_id: Some("12".to_string()),
                pretty_name: None,
            }),
            components: vec![OsComponent {
                ecosystem: "Debian".to_string(),
                name: "openssl".to_string(),
                version: "1:1.1.1n-0+deb12u1".to_string(),
                source: "var/lib/dpkg/status".to_string(),
            }],
            kernel_version: Some("6.1.0-21-amd64".to_string()),
            package_databases: vec!["var/lib/dpkg/status".to_string()],
            limitations: vec!["a limitation".to_string()],
            unsupported: vec![RPM_UNSUPPORTED.to_string()],
        };
        let json = serde_json::to_string(&inventory).expect("serialize");
        let back: OsInventory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inventory, back);
    }
}
