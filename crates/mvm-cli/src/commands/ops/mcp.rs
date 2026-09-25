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
    Stdio {
        /// Bind drive tools to this machine when its signed plan grants them
        #[arg(long)]
        machine: Option<String>,
    },
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    match args.transport {
        Transport::Stdio { machine } => {
            let client: Arc<dyn mvm_client::MvmClient> = Arc::new(mvm_client::LocalBackend::new());
            let drive = machine
                .as_deref()
                .map(mvm_client::drive::LocalDrive::bind)
                .transpose()?
                .flatten();
            let server = match drive {
                Some(drive) => mvm_mcp::McpServer::new(client).with_drive(Arc::new(drive)),
                None => mvm_mcp::McpServer::new(client),
            };
            let stdin = io::stdin();
            let stdout = io::stdout();
            server.serve(stdin.lock(), stdout.lock())?;
            Ok(())
        }
    }
}
