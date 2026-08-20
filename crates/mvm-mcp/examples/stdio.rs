use std::io;
use std::sync::Arc;

use mvm_client::LocalBackend;
use mvm_mcp::{McpServer, ServerError};

fn main() {
    if let Err(error) = run() {
        eprintln!("MCP stdio example failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ServerError> {
    let server = McpServer::new(Arc::new(LocalBackend::new()));
    let stdin = io::stdin();
    let stdout = io::stdout();
    server.serve(stdin.lock(), stdout.lock())
}
