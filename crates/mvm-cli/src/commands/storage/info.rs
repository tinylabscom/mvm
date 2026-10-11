//! `mvmctl storage info` — read-only pool stats. Audit-emit exempt
//! per the `info.rs` filename convention.

use anyhow::Result;
use clap::Args as ClapArgs;

use super::Cli;
use mvm_client::storage::{self, InfoRequest};
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Use the in-memory mock backend (for dev/macOS hosts where
    /// dmsetup is unavailable). Default uses the production
    /// `DmsetupBackend`.
    #[arg(long)]
    pub mock: bool,
    /// Emit JSON instead of human-readable text. Useful for
    /// scripting + CI.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let report = storage::info(&InfoRequest { mock: args.mock })?;
    let stats = match report.stats {
        Some(s) => s,
        None => {
            let e = report.reason.as_deref().unwrap_or_default();
            // BackendUnavailable is the common case on macOS dev hosts
            // before phase 2 lands. Fall through to a "no pool" report
            // rather than fail the verb.
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "pool": report.pool,
                        "available": false,
                        "reason": e.to_string(),
                    })
                );
            } else {
                println!("pool {}: unavailable ({e})", report.pool);
            }
            return Ok(());
        }
    };
    let volumes = report.volumes;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "pool": report.pool,
                "available": true,
                "stats": stats,
                "volumes": volumes,
            })
        );
    } else {
        println!("pool: {}", report.pool);
        println!(
            "  used: {} / {} bytes ({:.1}%)",
            stats.used_bytes,
            stats.capacity_bytes,
            stats.fill_fraction() * 100.0
        );
        println!("  volumes: {}", stats.volume_count);
        for vs in &report.volume_stats {
            let name = &vs.name;
            println!(
                "    {name}: {} / {} bytes",
                vs.used_bytes, vs.virtual_size_bytes
            );
        }
    }

    Ok(())
}
