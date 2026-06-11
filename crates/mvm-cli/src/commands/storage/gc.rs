//! `mvmctl storage gc` — reclaim unreferenced thin volumes.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::sync::Arc;

use super::Cli;
use mvm::storage::{Backend, DmsetupBackend, MockBackend, PoolConfig, ThinPool, ThinPoolImpl};
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
    let backend: Arc<dyn Backend> = if args.mock {
        Arc::new(MockBackend::new())
    } else {
        Arc::new(DmsetupBackend::new())
    };
    let pool = ThinPoolImpl::new(PoolConfig::default(), backend);

    // Outcome of one `storage gc` attempt. Drives both the operator-
    // facing printout and the audit `detail` field. Every `--apply`
    // attempt emits one audit record regardless of
    // outcome — pool-unavailable and empty-pool are no-op branches of
    // the same commit path, not free passes out of audit.
    enum Outcome {
        Removed(Vec<String>),
        Empty,
        PoolUnavailable(String),
    }

    let outcome = match pool.list_volumes() {
        Ok(volumes) => {
            let candidates: Vec<String> = volumes
                .into_iter()
                .filter(|name| !args.keep_prefix.iter().any(|p| name.starts_with(p)))
                .collect();
            if !args.apply {
                if candidates.is_empty() {
                    println!("storage gc: no orphan volumes (dry-run)");
                } else {
                    println!(
                        "storage gc: would remove {} volume(s) (dry-run):",
                        candidates.len()
                    );
                    for name in &candidates {
                        println!("  {name}");
                    }
                    println!("re-run with --apply to actually remove");
                }
                return Ok(());
            }
            if candidates.is_empty() {
                Outcome::Empty
            } else {
                let removed = pool
                    .gc(|name| !args.keep_prefix.iter().any(|p| name.starts_with(p)))
                    .context("dmsetup gc failed")?;
                Outcome::Removed(removed)
            }
        }
        Err(e) => {
            eprintln!("mvmctl storage gc: pool unavailable: {e}");
            if !args.apply {
                // Dry-run with no reachable pool: report-only, no
                // emit (dry-runs are read-only by contract).
                return Ok(());
            }
            Outcome::PoolUnavailable(e.to_string())
        }
    };

    // `--apply` reached. Route through the canonical `audit::emit`
    // (XDG state path) so `mvmctl audit tail` and the live drive-and-
    // assert tests in `tests/audit_emissions_live.rs` see the same
    // stream as every other state-changing verb. Earlier versions
    // wrote to `<data_dir>/audit.log` (singular, no `/log/` subdir,
    // `.log` suffix) which bypassed both readers.
    let detail = match &outcome {
        Outcome::Removed(removed) => {
            println!("storage gc: removed {} volume(s)", removed.len());
            for name in removed {
                println!("  {name}");
            }
            if removed.len() <= 8 {
                format!("removed=[{}]", removed.join(","))
            } else {
                format!("count={}", removed.len())
            }
        }
        Outcome::Empty => {
            println!("storage gc: no orphan volumes");
            "count=0".to_string()
        }
        Outcome::PoolUnavailable(err) => format!("pool_unavailable={err}"),
    };
    mvm_core::audit_emit!(StorageGc, "{detail}");

    Ok(())
}
