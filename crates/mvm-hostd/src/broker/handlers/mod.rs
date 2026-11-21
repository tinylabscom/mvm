//! Concrete `ServiceHandler` implementations hosted by `mvm-broker`.
//!
//! Each submodule is one handler; the binary's `main` wires them into
//! the [`crate::broker::registry::Registry`] at startup.

pub mod host_assurance_v1;
pub mod host_audit_v1;
pub mod host_beacon_v1;
pub mod host_cell_v1;
pub mod host_kv_v1;
pub mod host_time_v1;

use std::sync::Arc;

use mvm_core::protocol::broker::ServiceId;

use self::host_assurance_v1::HostAssuranceV1Handler;
use self::host_kv_v1::HostKvV1Handler;
use self::host_time_v1::HostTimeV1Handler;
use super::registry::Registry;
use crate::audit::refusal::RefusalAudit;

/// Handles for stateful handlers the caller has to drive after registration.
///
/// Most handlers are stateless and need nothing back. The assurance handler
/// does: a session has to be opened on it from an admitted plan before any
/// probe can land, so the registering caller keeps the `Arc`.
#[derive(Default)]
pub struct BoundHandlers {
    /// Present exactly when `host.assurance.v1` was bound and registered.
    pub assurance: Option<Arc<HostAssuranceV1Handler>>,
}

/// Register stateless built-in handlers named by an admitted service binding.
/// Services absent from `bindings` remain unregistered and therefore fail with
/// `NotBound` at the registry gate.
///
/// `host.cell.v1` is registered only when it is bound, the registration
/// carries a unit and epoch (the registry has an epoch gate), and the caller
/// supplies `refusals`, the signer that records its refusals on the tenant's
/// chain. Those are recorded at a bounded rate per registration
/// ([`crate::audit::refusal::ThrottledRefusals`]).
pub fn register_bound_handlers(
    registry: &mut Registry,
    bindings: &[ServiceId],
    refusals: Option<Arc<dyn RefusalAudit>>,
) -> BoundHandlers {
    let mut bound = BoundHandlers::default();

    let host_cell = ServiceId::parse(mvm_core::protocol::host_cell::HOST_CELL_SERVICE)
        .expect("host.cell.v1 is a valid ServiceId");
    if bindings.contains(&host_cell)
        && registry.epoch_gate.is_some()
        && let Some(refusals) = refusals
    {
        let clock: Arc<dyn mvm_core::time::Clock> = Arc::new(mvm_core::time::SystemClock);
        // Each registration counts its own refusals, so one guest's repeats
        // cannot crowd out another's first entry.
        let refusals = Arc::new(crate::audit::refusal::ThrottledRefusals::new(
            refusals,
            Arc::clone(&clock),
        ));
        registry.register(Arc::new(host_cell_v1::HostCellV1Handler::new(
            refusals, clock,
        )));
    }

    let host_time = ServiceId::parse("host.time.v1").expect("host.time.v1 is a valid ServiceId");
    if bindings.contains(&host_time) {
        registry.register(Arc::new(HostTimeV1Handler::new()));
    }

    let host_kv =
        ServiceId::parse(host_kv_v1::HOST_KV_SERVICE).expect("host.kv.v1 is a valid ServiceId");
    if bindings.contains(&host_kv) {
        registry.register(Arc::new(HostKvV1Handler::new()));
    }

    let host_assurance = ServiceId::parse(host_assurance_v1::HOST_ASSURANCE_SERVICE)
        .expect("host.assurance.v1 is a valid ServiceId");
    if bindings.contains(&host_assurance) {
        let handler = Arc::new(HostAssuranceV1Handler::new());
        let as_service: Arc<dyn mvm_core::protocol::handler::ServiceHandler> = handler.clone();
        registry.register(Arc::clone(&as_service));
        registry
            .register_capability(as_service, HostAssuranceV1Handler::capability_descriptor())
            .expect("built-in assurance capability descriptor is valid");
        // Publish it process-wide so the admit path can open a session on the
        // same instance the broker dispatches against. A second registry in one
        // process keeps its own handler and does not displace the first — the
        // alternative would point an opened session at a handler no workload
        // calls, which reads as a campaign that ran and observed nothing.
        crate::assurance_session::install_host_assurance_plane(Arc::clone(&handler));
        bound.assurance = Some(handler);
    }

    bound
}
