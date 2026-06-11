//! Transport-agnostic `Dispatcher` trait.
//!
//! Available under `protocol-only` so the mvmd hosted variant
//! can plug in its own dispatcher (HTTP-fronted, tenant-aware) without
//! depending on this crate's stdio loop. The mvm stdio binary
//! provides one impl in `mvm-cli::commands::ops::mcp`.
//!
//! ## Two method surfaces
//!
//! - [`Dispatcher::run`] — the legacy "single parameterized tool"
//!   `run` from the original MCP design. Dispatches code into a
//!   transient microVM (or the transport's equivalent). Kept as a
//!   dedicated method because the wire shape is fixed and the VM
//!   dispatch path is structurally different from a JSON-only tool.
//! - [`Dispatcher::invoke_tool`] — routes
//!   the typed-name tools (`mvm.time_now`, `mvm.web_fetch`,
//!   `mvm.web_search`, future `mvm.upload` / `mvm.download` /
//!   `mvm.code_eval`) through a shared registry. Default impl
//!   returns an `is_error: true` ToolResult so a dispatcher that
//!   doesn't opt in still answers MCP `tools/call` without trapping.

use crate::protocol::{ContentBlock, ToolResult};
use crate::tools::RunParams;

/// One method per MCP tool surface we expose.
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

    /// Dispatch a named registry tool (anything
    /// other than the legacy `run`). `params` is the raw `arguments`
    /// JSON the MCP client sent; the impl deserializes into its own
    /// typed shape and calls the matching tool in
    /// `mvm-supervisor::tools::ToolRegistry`.
    ///
    /// Default impl returns an `is_error: true` ToolResult naming
    /// the unwired tool. Dispatchers that don't yet route
    /// registry tools inherit this default and degrade gracefully:
    /// the MCP client sees a clear "tool not implemented" message
    /// rather than a JSON-RPC method-not-found, which keeps the
    /// retry behaviour off.
    fn invoke_tool(&self, name: &str, _params: serde_json::Value) -> ToolResult {
        ToolResult {
            content: vec![ContentBlock::Text {
                text: format!(
                    "tool {name:?} is registered in tools/list but the local \
                     dispatcher does not yet route it (Dispatcher::invoke_tool \
                     not overridden). Update the dispatcher impl or remove the \
                     tool from tools/list."
                ),
            }],
            is_error: true,
        }
    }
}
