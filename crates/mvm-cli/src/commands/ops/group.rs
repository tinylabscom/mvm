//! `mvmctl ops <sub>` — operational / observability commands.
//!
//! `metrics`, `config`, and `mcp` live under one `ops` namespace.
//! Leaf modules are unchanged.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{config, mcp, metrics};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: OpsCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum OpsCmd {
    /// Show runtime metrics (Prometheus text format by default)
    Metrics(metrics::Args),
    /// Read or write global operator config (~/.mvm/config.toml)
    Config(config::Args),
    /// Serve MvmClient operations to local MCP clients
    Mcp(mcp::Args),
}

impl OpsCmd {
    /// Audit verb name — unchanged from the pre-grouping top-level names.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            OpsCmd::Metrics(_) => "metrics",
            OpsCmd::Config(_) => "config",
            OpsCmd::Mcp(_) => "mcp",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        OpsCmd::Metrics(a) => metrics::run(cli, a, cfg),
        OpsCmd::Config(a) => config::run(cli, a, cfg),
        OpsCmd::Mcp(a) => mcp::run(a),
    }
}
