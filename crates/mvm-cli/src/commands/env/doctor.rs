//! `mvmctl doctor` — environment diagnostics.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Scope checks to a specific user workflow. Filters the report
    /// (and the exit-code blocking set) to checks relevant for the
    /// named workflow. Default is all checks.
    #[arg(long, value_enum)]
    pub workflow: Option<crate::doctor::DoctorWorkflow>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    crate::doctor::run(args.json, args.workflow)
}
