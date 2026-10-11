//! `mvmctl storage gc` — reclaim unreferenced thin volumes.

use anyhow::Result;
use clap::Args as ClapArgs;

use super::Cli;
use mvm_client::storage::{self, GcRequest};
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
    let report = storage::gc(&GcRequest {
        apply: args.apply,
        mock: args.mock,
        keep_prefix: args.keep_prefix,
    })?;
    if let Some(error) = report.pool_unavailable {
        eprintln!("mvmctl storage gc: pool unavailable: {error}");
    } else if !report.applied {
        if report.candidates.is_empty() {
            println!("storage gc: no orphan volumes (dry-run)");
        } else {
            println!(
                "storage gc: would remove {} volume(s) (dry-run):",
                report.candidates.len()
            );
            for name in report.candidates {
                println!("  {name}");
            }
            println!("re-run with --apply to actually remove");
        }
    } else if report.candidates.is_empty() {
        println!("storage gc: no orphan volumes");
    } else {
        println!("storage gc: removed {} volume(s)", report.removed.len());
        for name in report.removed {
            println!("  {name}");
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
    fn gc_defaults_to_preview_and_preserves_prefix_flags() {
        let args = Harness::parse_from(["gc"]).args;
        assert!(!args.apply);
        assert!(!args.mock);
        assert!(args.keep_prefix.is_empty());
        let args = Harness::parse_from(["gc", "--apply", "--keep-prefix", "live-,base-"]).args;
        assert!(args.apply);
        assert_eq!(args.keep_prefix, ["live-", "base-"]);
    }
}
