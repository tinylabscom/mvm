//! `mvmctl manifest ls` — list built slots, with optional tag filter.

use std::collections::BTreeSet;

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, ListRequest};
use mvm_core::user_config::MvmConfig;

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

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let rows = manifest::list(&ListRequest {
        orphans: args.orphans,
        tags: args.tags.clone(),
    })?;
    // Sorted and deduplicated only for the human empty-result message.
    let want_tags: BTreeSet<String> = args.tags.iter().cloned().collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn list_parser_keeps_json_orphans_and_repeatable_tags() {
        let args =
            Command::try_parse_from(["ls", "--json", "--orphans", "--tag", "b", "--tag", "a"])
                .unwrap()
                .args;
        assert!(args.json && args.orphans);
        assert_eq!(args.tags, ["b", "a"]);
        let defaults = Command::try_parse_from(["ls"]).unwrap().args;
        assert!(!defaults.json && !defaults.orphans && defaults.tags.is_empty());
    }
}
