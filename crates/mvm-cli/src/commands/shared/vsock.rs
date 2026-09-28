//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through the canonical `mvm_runtime::vsock_transport::for_vm`
//! dispatcher — the same selector `invoke`/`exec`/`readiness` use. It
//! probes the live backend (hvf agent bridge → libkrun → hvf per-port vsock →
//! firecracker) per VM, so a VM started under any backend reaches its agent
//! on the right transport.

pub use mvm_client::readiness::wait_for_guest_agent;

pub use mvm_client::guest::emit_vsock_rpc_audit;
