//! `mvmctl metrics` — emit Prometheus-style metrics.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let metrics = mvm_core::observability::metrics::global();
    if args.json {
        let snap = metrics.snapshot();
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        print!("{}", metrics.prometheus_exposition());
    }
    Ok(())
}
