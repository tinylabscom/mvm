//! `mvmctl storage` — dm-thin pool inspection + GC.
//!
//! Ships the read-only `info` verb and a `gc --dry-run` /
//! `gc --apply` verb that operate against the storage abstraction in
//! `mvm/src/storage/`. The MockBackend is the only impl that
//! actually does anything today; the production DmsetupBackend lands
//! its real `dmsetup` invocations later alongside the
//! instance-create migration in `vm/template/lifecycle.rs`.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use super::Cli;
use mvm_core::user_config::MvmConfig;

mod gc;
mod info;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: StorageAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum StorageAction {
    /// Print pool utilization + per-volume stats (read-only).
    Info(info::Args),
    /// Reclaim unreferenced thin volumes. `--dry-run` (default) only
    /// reports; `--apply` actually removes.
    Gc(gc::Args),
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        StorageAction::Info(a) => info::run(cli, a, cfg),
        StorageAction::Gc(a) => gc::run(cli, a, cfg),
    }
}
