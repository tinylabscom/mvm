//! `mvmctl deployments` — inventory of the local deployment store.
//!
//! Every `mvmctl deploy` writes a `DeployRecord` under
//! `<mvm_home>/deployments/<ir-hash>/` before anything ships anywhere;
//! this group is the read side of that local-first record. It answers
//! "what have I deployed from this machine, and what exact bytes were
//! sealed?" — the same record shape the control-plane query answers
//! fleet-wide.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod list;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: DeploymentsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DeploymentsAction {
    /// List recorded local deployments
    Ls {
        /// Only list deployments of this workload id
        #[arg(long)]
        workload: Option<String>,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        DeploymentsAction::Ls { workload, json } => list::run(workload, json),
    }
}
