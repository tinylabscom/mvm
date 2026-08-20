//! Local MCP process transport. The protocol and dispatch live in `mvm-mcp`;
//! this module only selects the local `MvmClient` and connects stdio.

use std::io;
use std::sync::Arc;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub transport: Transport,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Transport {
    /// Read and write newline-delimited JSON-RPC on stdin/stdout
    Stdio,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    match args.transport {
        Transport::Stdio => {
            let server = mvm_mcp::McpServer::new(Arc::new(mvm_client::LocalBackend::new()));
            let stdin = io::stdin();
            let stdout = io::stdout();
            server.serve(stdin.lock(), stdout.lock())?;
            Ok(())
        }
    }
}
