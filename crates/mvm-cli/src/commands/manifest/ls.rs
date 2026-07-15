//! `mvmctl manifest ls` — list built slots, with optional tag filter.

use std::collections::BTreeSet;

use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_core::domain::template_tags::TemplateTags;
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
    /// Filter to slots whose template carries this tag. Repeatable;
    /// the slot must carry every supplied tag (intersection
    /// semantics). Tag-less slots are always excluded when this
    /// filter is in effect.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
}

#[derive(Serialize)]
struct SlotRow {
    slot_hash: String,
    manifest_path: String,
    name: Option<String>,
    updated_at: String,
    orphan: bool,
    /// Tags from the template's tag catalog. Empty when the slot
    /// has no associated catalog or no tags set.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    tags: BTreeSet<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let entries = tmpl::template_list_slots()?;

    // Convert the user-supplied filter once. Sorted so the
    // intersection check below has a stable shape; we don't validate
    // here because `add` is the canonical insertion site that does.
    let want_tags: BTreeSet<String> = args.tags.iter().cloned().collect();

    let rows: Vec<SlotRow> = entries
        .into_iter()
        .map(|e| {
            // The template's tag catalog is keyed by template name.
            // For unnamed slots there's no catalog to load; the row
            // ends up with an empty tag set. Forgiving load semantics
            // (missing file → empty) means `template_tags::load`
            // never returns an error here.
            let tags = match e.name.as_deref() {
                Some(n) => TemplateTags::load(n).map(|t| t.tags).unwrap_or_default(),
                None => BTreeSet::new(),
            };
            SlotRow {
                orphan: !std::path::Path::new(&e.manifest_path).exists(),
                slot_hash: e.slot_hash,
                manifest_path: e.manifest_path,
                name: e.name,
                updated_at: e.updated_at,
                tags,
            }
        })
        .filter(|r| !args.orphans || r.orphan)
        .filter(|r| {
            // Empty filter: keep everything. Non-empty: every
            // requested tag must be present (intersection).
            want_tags.iter().all(|t| r.tags.contains(t))
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        if args.orphans {
            println!("No orphaned slots.");
        } else if !want_tags.is_empty() {
            let tag_list = want_tags
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            println!("No built slots match tag filter [{tag_list}].");
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
        if !r.tags.is_empty() {
            let tag_list = r
                .tags
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            println!("    tags: {tag_list}");
        }
    }
    Ok(())
}
