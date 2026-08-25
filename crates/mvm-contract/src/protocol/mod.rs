//! Wire-protocol DTO leaves — the pure serde types that cross the
//! guest/host/broker/tunnel boundaries. Logic (dispatch, signing,
//! transport I/O) stays in `mvm-core::protocol`, which re-exports these
//! modules at their existing paths.

pub mod agent_capability;
pub mod agent_session;
pub mod audit_signer;
pub mod broker;
pub mod broker_control;
pub mod capability_negotiation;
pub mod dns;
pub mod extension_controller;
pub mod extension_pack;
pub mod handler;
pub mod host_audit;
pub mod host_cost;
pub mod host_kv;
pub mod host_signer;
pub mod host_time;
/// Bounded, flow-aware guest/host networking wire contract: framing,
/// opcodes, and the session/stream state machine shared by guest and host.
pub mod network_flow;
pub mod resource_controls;
pub mod routing;
pub mod signed_config;
pub mod signing;
pub mod upstream_tools;
pub mod vcpu_quota;
pub mod vm_backend;
