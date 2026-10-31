//! `mvmctl manifest prune` — sweep orphaned slots.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Remove slots whose source manifest file is missing on disk.
    /// (Today this is the only prune mode; the flag is required so
    /// the verb is explicit and future modes — `--all`, `--legacy`,
    /// `--keep <N>` — slot in cleanly.)
    #[arg(long)]
    pub orphans: bool,
    /// Show what would be removed without actually deleting.
    #[arg(long)]
    pub dry_run: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if !args.orphans {
        anyhow::bail!(
            "no prune mode specified. Pass `--orphans` to remove slots whose manifest file is gone."
        );
    }

    let orphans = manifest::prune_orphans(args.dry_run)?;
    let prefix = if args.dry_run { "(dry-run) " } else { "" };

    if args.json {
        if args.dry_run {
            println!("{}", serde_json::to_string_pretty(&orphans)?);
        } else {
            #[derive(serde::Serialize)]
            struct Out {
                removed_count: usize,
                removed: Vec<String>,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&Out {
                    removed_count: orphans.len(),
                    removed: orphans.into_iter().map(|o| o.slot_hash).collect(),
                })?
            );
        }
        return Ok(());
    }

    if orphans.is_empty() {
        println!("{prefix}No orphaned slots.");
        return Ok(());
    }
    if args.dry_run {
        println!("(dry-run) Would remove {} orphaned slot(s):", orphans.len());
    } else {
        println!("Removed {} orphaned slot(s):", orphans.len());
    }
    for o in orphans {
        let short = &o.slot_hash[..o.slot_hash.len().min(12)];
        match o.reason {
            Some(reason) => println!("  {short}  ({reason})"),
            None => println!("  {short}"),
        }
    }
    Ok(())
}
