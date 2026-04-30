//! Transport-agnostic `Dispatcher` trait.
//!
//! Available under `protocol-only` so plan 33's mvmd hosted variant
//! can plug in its own dispatcher (HTTP-fronted, tenant-aware) without
//! depending on this crate's stdio loop. The mvm stdio binary
//! provides one impl in `mvm-cli::commands::ops::mcp`.

use crate::protocol::ToolResult;
use crate::tools::RunParams;

/// One method per MCP tool we expose. Currently just `run`.
pub trait Dispatcher {
    /// Validate `params`, dispatch into a microVM (or whatever the
    /// transport's analog is), capture output, return an MCP-shaped
    /// `ToolResult`.
    ///
    /// Errors should be rendered as `ToolResult { is_error: true,
    /// content: [Text { text: ... }] }` — *not* propagated as
    /// `Result::Err` — so the LLM client sees the failure rather than
    /// a JSON-RPC `internal_error` (which clients tend to retry
    /// instead of surfacing).
    fn run(&self, params: RunParams) -> ToolResult;
}
