// mvm-guest: vsock protocol and openclaw connector mapping for mvm
// Depends on mvm-core

pub mod builder_agent;
pub mod console;
pub mod entrypoint;
pub mod fs_rpc;
pub mod integrations;
pub mod lifecycle_hooks;
pub mod probes;
pub mod runtime_config;
pub mod volume;
pub mod vsock;
pub mod worker_pool;
pub mod worker_protocol;

/// Process control RPC handler — A2 of the filesystem-volumes plan.
/// Dev-only: gated behind `dev-shell` so symbols are stripped from
/// production guest agents (ADR-002 §W4.3 + ADR-007 §W5).
#[cfg(feature = "dev-shell")]
pub mod process_rpc;
