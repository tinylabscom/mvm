//! `mvmctl search` — search the pack registry index, marking installed packs.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_core::registry_pack_store::load_pack_lockfile;
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::Cli;
use crate::commands::pack::inspect::safe;
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
    /// Per-version detail from the (untrusted) index; absent fields are omitted.
    version_details: Vec<VersionRow>,
    installed: bool,
}

#[derive(Serialize)]
struct VersionRow {
    version: String,
    tags: Vec<String>,
    platform: Option<String>,
    manifest_sha256: String,
    size_bytes: Option<u64>,
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
            versions: entry
                .versions
                .iter()
                .map(|version| version.version.clone())
                .collect(),
            version_details: entry
                .versions
                .iter()
                .map(|version| VersionRow {
                    version: version.version.clone(),
                    tags: version.tags.clone(),
                    platform: version.platform(),
                    manifest_sha256: version.manifest_sha256.as_str().to_string(),
                    size_bytes: version.size_bytes,
                })
                .collect(),
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
            safe(&row.pack),
            safe(&row.versions.join(", ")),
            safe(&row.description),
        );
        for detail in &row.version_details {
            println!("    {}", version_line(detail));
        }
    }
    println!("(* marks an installed pack)");
    Ok(())
}

/// One printable line per version. Every field came from the untrusted index,
/// so each is escaped before it reaches the terminal.
fn version_line(detail: &VersionRow) -> String {
    let tags = if detail.tags.is_empty() {
        "-".to_string()
    } else {
        detail.tags.join(",")
    };
    let size = detail
        .size_bytes
        .map_or_else(|| "-".to_string(), |bytes| format!("{bytes} bytes"));
    let platform = detail.platform.as_deref().unwrap_or("-");
    let digest = detail
        .manifest_sha256
        .get(..12)
        .unwrap_or(&detail.manifest_sha256);
    safe(&format!(
        "{} tags={tags} platform={platform} sha256={digest} size={size}",
        detail.version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(tags: &[&str], platform: Option<&str>, size: Option<u64>) -> VersionRow {
        VersionRow {
            version: "1.0.0".into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            platform: platform.map(str::to_string),
            manifest_sha256: "ab".repeat(32),
            size_bytes: size,
        }
    }

    #[test]
    fn version_line_shows_tag_platform_short_digest_and_size() {
        let line = version_line(&row(&["latest"], Some("linux/aarch64"), Some(42)));
        assert_eq!(
            line,
            "1.0.0 tags=latest platform=linux/aarch64 sha256=abababababab size=42 bytes"
        );
    }

    #[test]
    fn version_line_of_an_old_index_entry_uses_placeholders() {
        let line = version_line(&row(&[], None, None));
        assert!(
            line.contains("tags=- platform=- ") && line.ends_with("size=-"),
            "{line}"
        );
    }

    #[test]
    fn hostile_index_strings_never_print_a_control_character() {
        let hostile = "x\u{1b}[2J\r\n\u{9b}";
        let line = version_line(&row(&[hostile], Some(hostile), None));
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.contains("\\u{1b}"));
    }
}
