//! `mvm-mcp` — Model Context Protocol server for mvm.
//!
//! Exposes mvm's microVM template registry as a single parameterized
//! `run` tool. LLM clients (Claude Code, opencode, etc.) connect over
//! stdio, list tools, and dispatch code into transient microVMs.
//!
//! ## Features
//!
//! - `protocol-only` — JSON-RPC frames, tool schemas, `Dispatcher`
//!   trait. No I/O. Consumed by mvmd for the hosted
//!   HTTP/SSE transport.
//!
//! - `stdio` (default) — adds the JSON-RPC stdio loop. Callers
//!   provide their own [`Dispatcher`] implementation; the local
//!   mvmctl impl lives in `mvm-cli::commands::ops::mcp` (which has
//!   access to `crate::exec` for the actual VM dispatch).
//!
//! ## Threat model
//!
//! The transport is host-local stdio. No new attacker
//! surface beyond the baseline microVM posture — code runs entirely
//! inside the already-isolated microVM. The `env` parameter is allowlisted
//! against the existing template registry; `code` is passed as a
//! single argv element to the guest interpreter.

pub mod dispatcher;
pub mod protocol;
pub mod session;
pub mod tools;

pub use dispatcher::Dispatcher;
pub use protocol::{
    ContentBlock, JsonRpcError, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, SERVER_NAME,
    SERVER_VERSION, ToolResult,
};
pub use session::{
    DEFAULT_IDLE_SECS, DEFAULT_MAX_SECS, ReapReason, Reaper, SessionConfig, SessionLookup,
    SessionMap, SessionState,
};
pub use tools::{RunParams, ToolSchema, all_tools, run_input_schema};

#[cfg(feature = "stdio")]
pub mod server;

#[cfg(feature = "stdio")]
pub use server::{init_stderr_tracing, run_with_dispatcher};
