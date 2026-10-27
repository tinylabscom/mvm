//! `mvmctl backend <sub>` — inspect and manage the per-backend host
//! component sets that ship inside the signed release archive.
//!
//! The component table (`host_binaries::backend_components`) decides which
//! backends this host supports and which files each needs; these verbs never
//! re-derive that. `install.sh` reads the same table through the archive's
//! generated `components.tsv`.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod add;
mod detect;
mod layout;
mod list;
mod remove;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: BackendCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BackendCmd {
    /// List every backend with this host's support, install state, and default
    List(list::Args),
    /// Fetch and place a backend's signed component set from this install's release
    Add(add::Args),
    /// Remove a backend's component files, leaving state, caches and VMs behind
    Remove(remove::Args),
    /// Print the backend install.sh would select on this host
    Detect(detect::Args),
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BackendCmd::List(a) => list::run(a),
        BackendCmd::Add(a) => add::run(a),
        BackendCmd::Remove(a) => remove::run(a),
        BackendCmd::Detect(a) => detect::run(&a),
    }
}

/// The early dispatch for `backend detect`: identical to the regular path,
/// reached before startup creates any state (install.sh probes a just-extracted
/// mvmctl that has no config, keys, or audit envelope yet).
pub(in crate::commands) fn run_detect_early(args: &detect::Args) -> Result<()> {
    detect::run(args)
}
