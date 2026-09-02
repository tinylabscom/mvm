//! Wire protocol, signing, routing, and the VmBackend trait contract.

pub mod broker_control;
pub mod handler;
#[allow(clippy::module_inception)]
pub mod protocol;
pub mod signed_config;
pub mod vm_backend;
pub mod volume_bridge;

// `audit_signer`, `broker`, `host_audit`, `host_cost`, `host_kv`,
// `host_signer`, `host_time`, `routing`, `signing` are pure-DTO leaves
// that now live in `mvm-contract`; re-exported here as module aliases so
// every existing `crate::protocol::{audit_signer,broker,host_audit,
// host_cost,host_kv,host_signer,host_time,routing,signing}::X`
// path keeps resolving unchanged.
pub use mvm_contract::protocol::{
    audit_signer, broker, dns, host_audit, host_beacon, host_cost, host_kv, host_signer, host_time,
    routing, signing,
};

// Flatten protocol.rs contents up to `mvm_core::protocol::*`.
pub use self::protocol::*;
