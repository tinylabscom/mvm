//! Wire-protocol DTO leaves — the pure serde types that cross the
//! guest/host/broker/tunnel boundaries. Logic (dispatch, signing,
//! transport I/O) stays in `mvm-core::protocol`, which re-exports these
//! modules at their existing paths.

pub mod audit_signer;
pub mod broker;
pub mod broker_control;
pub mod dns;
pub mod handler;
pub mod host_audit;
pub mod host_cost;
pub mod host_signer;
pub mod host_time;
pub mod routing;
pub mod signed_config;
pub mod signing;
pub mod vm_backend;
