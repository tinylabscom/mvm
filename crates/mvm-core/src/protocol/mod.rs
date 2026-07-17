//! Wire protocol, signing, routing, and the VmBackend trait contract.

pub mod audit_signer;
pub mod broker_control;
pub mod handler;
pub mod host_signer;
#[allow(clippy::module_inception)]
pub mod protocol;
pub mod signed_config;
pub mod vm_backend;

// `broker`, `host_audit`, `host_cost`, `host_time`, `network_tunnel`,
// `routing`, `signing` are pure-DTO leaves that now live in
// `mvm-protocol`; re-exported here as module aliases so every existing
// `crate::protocol::{broker,host_audit,host_cost,host_time,network_tunnel,
// routing,signing}::X` path keeps resolving unchanged.
pub use mvm_protocol::protocol::{
    broker, host_audit, host_cost, host_time, network_tunnel, routing, signing,
};

// Flatten protocol.rs contents up to `mvm_core::protocol::*`.
pub use self::protocol::*;
