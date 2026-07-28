//! `mvmctl ops <sub>` — operational / observability commands.
//!
//! `metrics`, `config`, `mcp` collapse under one `ops`
//! namespace. Leaf modules are unchanged.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
#[cfg(feature = "mcp")]
use super::mcp;
use super::{config, metrics};

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
    /// Expose mvmctl over Model Context Protocol
    #[cfg(feature = "mcp")]
    Mcp(mcp::Args),
}

impl OpsCmd {
    /// Audit verb name — unchanged from the pre-grouping top-level names.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            OpsCmd::Metrics(_) => "metrics",
            OpsCmd::Config(_) => "config",
            #[cfg(feature = "mcp")]
            OpsCmd::Mcp(_) => "mcp",
        }
    }

    /// Whether this op is the MCP server (needs stderr-only log routing so
    /// stdout stays clean JSON-RPC). Lets `run()` keep its mcp special-case
    /// after the grouping.
    pub(in crate::commands) fn is_mcp(&self) -> bool {
        #[cfg(feature = "mcp")]
        {
            matches!(self, OpsCmd::Mcp(_))
        }
        #[cfg(not(feature = "mcp"))]
        {
            false
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        OpsCmd::Metrics(a) => metrics::run(cli, a, cfg),
        OpsCmd::Config(a) => config::run(cli, a, cfg),
        #[cfg(feature = "mcp")]
        OpsCmd::Mcp(a) => mcp::run(cli, a, cfg),
    }
}
