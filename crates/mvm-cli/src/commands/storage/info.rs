//! `mvmctl storage info` — read-only pool stats. Audit-emit exempt
//! per the `info.rs` filename convention.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::sync::Arc;

use super::Cli;
use mvm::storage::{
    DeviceMapperBackend, DmsetupBackend, MockBackend, PoolConfig, ThinPool, ThinPoolImpl,
};
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
    let backend: Arc<dyn DeviceMapperBackend> = if args.mock {
        Arc::new(MockBackend::new())
    } else {
        Arc::new(DmsetupBackend::new())
    };
    let pool = ThinPoolImpl::new(PoolConfig::default(), backend);

    let stats = match pool.stats() {
        Ok(s) => s,
        Err(e) => {
            // BackendUnavailable is the common case on macOS dev hosts
            // before phase 2 lands. Fall through to a "no pool" report
            // rather than fail the verb.
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "pool": pool.config().name,
                        "available": false,
                        "reason": e.to_string(),
                    })
                );
            } else {
                println!("pool {}: unavailable ({e})", pool.config().name);
            }
            return Ok(());
        }
    };
    let volumes = pool.list_volumes().unwrap_or_default();

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "pool": pool.config().name,
                "available": true,
                "stats": stats,
                "volumes": volumes,
            })
        );
    } else {
        println!("pool: {}", pool.config().name);
        println!(
            "  used: {} / {} bytes ({:.1}%)",
            stats.used_bytes,
            stats.capacity_bytes,
            stats.fill_fraction() * 100.0
        );
        println!("  volumes: {}", stats.volume_count);
        for name in &volumes {
            if let Ok(vs) = pool.volume_stats(&mvm::storage::VolumeId::new(name)) {
                println!(
                    "    {name}: {} / {} bytes",
                    vs.used_bytes, vs.virtual_size_bytes
                );
            }
        }
    }

    Ok(())
}
