//! `mvmctl storage info` — read-only pool stats. Audit-emit exempt
//! per the `info.rs` filename convention.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::storage::{self, PoolInfo};

use super::Cli;
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
    match storage::info(args.mock) {
        // Unreachable on macOS dev hosts: report it rather than fail the verb.
        PoolInfo::Unavailable { pool, reason } if args.json => println!(
            "{}",
            serde_json::json!({"pool": pool, "available": false, "reason": reason})
        ),
        PoolInfo::Unavailable { pool, reason } => println!("pool {pool}: unavailable ({reason})"),
        PoolInfo::Ready {
            pool,
            stats,
            volumes,
        } if args.json => {
            let names: Vec<&str> = volumes.iter().map(|v| v.name.as_str()).collect();
            println!(
                "{}",
                serde_json::json!({
                    "pool": pool,
                    "available": true,
                    "stats": stats,
                    "volumes": names,
                })
            );
        }
        PoolInfo::Ready {
            pool,
            stats,
            volumes,
        } => {
            println!("pool: {pool}");
            println!(
                "  used: {} / {} bytes ({:.1}%)",
                stats.used_bytes,
                stats.capacity_bytes,
                stats.fill_fraction() * 100.0
            );
            println!("  volumes: {}", stats.volume_count);
            for v in volumes {
                if let Some(vs) = v.stats {
                    println!(
                        "    {}: {} / {} bytes",
                        v.name, vs.used_bytes, vs.virtual_size_bytes
                    );
                }
            }
        }
    }
    Ok(())
}
