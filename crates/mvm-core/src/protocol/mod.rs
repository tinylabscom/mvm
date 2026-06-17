//! Wire protocol, signing, routing, and the VmBackend trait contract.

pub mod audit_signer;
pub mod broker;
pub mod broker_control;
pub mod handler;
pub mod host_audit;
pub mod host_cost;
pub mod host_signer;
pub mod host_time;
#[allow(clippy::module_inception)]
pub mod protocol;
pub mod routing;
pub mod signed_config;
pub mod signing;
pub mod vm_backend;

// Flatten protocol.rs contents up to `mvm_core::protocol::*`.
pub use self::protocol::*;
