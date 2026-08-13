//! Concrete `ServiceHandler` implementations hosted by `mvm-broker`.
//!
//! Each submodule is one handler; the binary's `main` wires them into
//! the [`crate::broker::registry::Registry`] at startup.

pub mod host_audit_v1;
pub mod host_time_v1;

use std::sync::Arc;

use mvm_core::protocol::broker::ServiceId;

use self::host_time_v1::HostTimeV1Handler;
use super::registry::Registry;

/// Register stateless built-in handlers named by an admitted service binding.
/// Services absent from `bindings` remain unregistered and therefore fail with
/// `NotBound` at the registry gate.
pub fn register_bound_handlers(registry: &mut Registry, bindings: &[ServiceId]) {
    let host_time = ServiceId::parse("host.time.v1").expect("host.time.v1 is a valid ServiceId");
    if bindings.contains(&host_time) {
        registry.register(Arc::new(HostTimeV1Handler::new()));
    }
}
