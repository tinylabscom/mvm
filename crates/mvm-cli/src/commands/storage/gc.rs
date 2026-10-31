//! `mvmctl storage gc` — reclaim unreferenced thin volumes.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::storage::{self, GcOutcome};

use super::Cli;
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Actually remove orphaned volumes. Without this flag, the
    /// command only reports what it would remove.
    #[arg(long)]
    pub apply: bool,
    /// Use the in-memory mock backend (for dev/macOS hosts).
    #[arg(long)]
    pub mock: bool,
    /// Comma-separated list of volume name prefixes to consider
    /// "live" (not removable). Anything not matching is candidate
    /// for removal. Default: empty (treat all volumes as candidates;
    /// dry-run only reports them).
    #[arg(long, value_delimiter = ',', default_values_t = Vec::<String>::new())]
    pub keep_prefix: Vec<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if !args.apply {
        match storage::gc_candidates(args.mock, &args.keep_prefix) {
            Err(e) => eprintln!("mvmctl storage gc: pool unavailable: {e}"),
            Ok(c) if c.is_empty() => println!("storage gc: no orphan volumes (dry-run)"),
            Ok(c) => {
                println!("storage gc: would remove {} volume(s) (dry-run):", c.len());
                for name in &c {
                    println!("  {name}");
                }
                println!("re-run with --apply to actually remove");
            }
        }
        return Ok(());
    }
    match storage::gc_apply(args.mock, &args.keep_prefix)? {
        GcOutcome::Removed(removed) => {
            println!("storage gc: removed {} volume(s)", removed.len());
            for name in &removed {
                println!("  {name}");
            }
        }
        GcOutcome::Empty => println!("storage gc: no orphan volumes"),
        GcOutcome::PoolUnavailable(e) => eprintln!("mvmctl storage gc: pool unavailable: {e}"),
    }
    Ok(())
}
