//! `mvmctl manifest prune` — sweep orphaned slots.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, PruneCandidate, PruneRequest};
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
    let report = manifest::prune(&PruneRequest {
        orphans: args.orphans,
        dry_run: args.dry_run,
    })?;
    if args.dry_run {
        return run_dry(args.json, report.candidates);
    }

    let count = report.removed_count;
    let removed = report.removed;

    if args.json {
        #[derive(serde::Serialize)]
        struct Out {
            removed_count: usize,
            removed: Vec<String>,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Out {
                removed_count: count,
                removed,
            })?
        );
        return Ok(());
    }

    if count == 0 {
        println!("No orphaned slots.");
    } else {
        println!("Removed {} orphaned slot(s):", count);
        for h in removed {
            println!("  {}", &h[..h.len().min(12)]);
        }
    }
    Ok(())
}

fn run_dry(json: bool, would_remove: Vec<PruneCandidate>) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&would_remove)?);
        return Ok(());
    }

    if would_remove.is_empty() {
        println!("(dry-run) No orphaned slots.");
    } else {
        println!(
            "(dry-run) Would remove {} orphaned slot(s):",
            would_remove.len()
        );
        for PruneCandidate {
            slot_hash: h,
            reason,
        } in would_remove
        {
            println!("  {}  ({})", &h[..h.len().min(12)], reason);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn prune_keeps_its_explicit_mode_and_apply_default() {
        let args = Harness::parse_from(["prune", "--orphans"]).args;
        assert!(args.orphans);
        assert!(!args.dry_run);
        let args = Harness::parse_from(["prune", "--orphans", "--dry-run", "--json"]).args;
        assert!(args.orphans && args.dry_run && args.json);
    }
}
