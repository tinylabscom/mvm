//! Host-agent control protocol — moved to `mvm_core::protocol::broker_control`
//! so the daemon (here) and the registering backend (`mvm-backend`, which
//! cannot depend on `mvm-hostd`) share one wire contract. Re-exported here so
//! existing `super::control::…` paths keep resolving.

pub use mvm_core::protocol::broker_control::*;
