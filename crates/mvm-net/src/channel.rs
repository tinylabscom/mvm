//! Typed guest services over whatever the VMM uses to terminate vsock.
//!
//! A guest always speaks AF_VSOCK. What the *host* holds varies: Firecracker
//! hands us a per-port Unix socket that is its own termination of the
//! guest's virtio-vsock connection, libkrun does the same at a different
//! path, the in-house HVF VMM hands us an owned stream, QEMU exposes a real
//! AF_VSOCK socket, and a future Windows host would expose AF_HYPERV. All
//! five are the same fact — the host end of a guest vsock connection — and
//! none of them is an authorization input.
//!
//! Callers select semantic services rather than copying transport-specific
//! port numbers throughout backend implementations.

use std::fmt;

/// A typed guest channel.
///
/// Named services rather than bare port numbers, so a caller cannot ask for
/// "port 5260" and get whatever happens to be there; the backend owns the
/// mapping from service to endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestService {
    /// The machine-control RPC: exec, fs, health, lifecycle.
    MachineControl,
    /// One-shot workload exit reporting.
    WorkloadExit,
    /// The host-services broker.
    Broker,
    /// The one flow-aware networking endpoint.
    NetworkFlow,
    /// One dev-only interactive console data stream.
    ///
    /// The guest allocates these ports from its console session range. The
    /// numeric value remains transport detail; callers still select the
    /// service by its semantic role.
    ConsoleData { port: u32 },
    /// Job dispatch into a persistent builder VM's in-guest loop.
    ///
    /// Builder-tier only: the guest end is `mvm-host-vm-init`'s dispatch
    /// listener, which exists only while a builder VM is running as a
    /// long-lived session. A workload guest never serves this.
    BuilderDispatch,
    /// The resident builder daemon's typed control plane (`mvm-builderd`).
    ///
    /// Builder-tier only, same as [`BuilderDispatch`](Self::BuilderDispatch).
    BuilderdControl,
}

impl GuestService {
    /// The vsock port this service uses today.
    ///
    /// Backends may map services to endpoints however they like; this is the
    /// port the guest dials, and it is the single place the mapping lives so
    /// the two ends cannot drift.
    pub fn port(self) -> u32 {
        match self {
            Self::WorkloadExit => 5251,
            Self::MachineControl => 5252,
            Self::NetworkFlow => mvm_contract::protocol::network_flow::NETWORK_FLOW_PORT,
            Self::Broker => 5300,
            Self::ConsoleData { port } => port,
            // Pinned literals, mirroring `mvm_agentd::builder_agent`'s
            // constants. This crate sits below `mvm-agentd` and cannot name
            // them; the tests below pin both ends to the same numbers.
            Self::BuilderDispatch => 21471,
            Self::BuilderdControl => 21473,
        }
    }

    /// Stable label for audit and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MachineControl => "machine-control",
            Self::WorkloadExit => "workload-exit",
            Self::Broker => "broker",
            Self::NetworkFlow => "network-flow",
            Self::ConsoleData { .. } => "console-data",
            Self::BuilderDispatch => "builder-dispatch",
            Self::BuilderdControl => "builderd-control",
        }
    }

    /// Whether this service exists only on a builder-tier guest.
    ///
    /// A workload guest serves none of these; a spec that names one is
    /// describing the build engine, not a tenant workload. Backends use this
    /// to keep the builder's control ports out of workload wiring.
    pub fn is_builder_tier(self) -> bool {
        matches!(self, Self::BuilderDispatch | Self::BuilderdControl)
    }
}

impl fmt::Display for GuestService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConsoleData { port } => write!(f, "console-data[{port}]"),
            other => write!(f, "{}", other.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_map_to_the_ports_both_ends_agree_on() {
        assert_eq!(GuestService::MachineControl.port(), 5252);
        assert_eq!(GuestService::WorkloadExit.port(), 5251);
        // Pins the wire value. The constant it derives from lives in
        // `mvm-contract` so the guest — which cannot depend on this crate —
        // names the same number; this asserts the derivation still lands on
        // the port deployed guests actually dial.
        assert_eq!(GuestService::NetworkFlow.port(), 5253);
        assert_eq!(
            GuestService::NetworkFlow.port(),
            mvm_contract::protocol::network_flow::NETWORK_FLOW_PORT,
            "the service mapping and the shared contract constant must not drift"
        );
        assert_eq!(GuestService::Broker.port(), 5300);
        // Both ends of the builder control plane pin these literals: the guest
        // side in `mvm_agentd::builder_agent`, which this crate sits below.
        assert_eq!(GuestService::BuilderDispatch.port(), 21471);
        assert_eq!(GuestService::BuilderdControl.port(), 21473);
    }

    #[test]
    fn every_service_has_a_distinct_port() {
        let ports = [
            GuestService::MachineControl.port(),
            GuestService::WorkloadExit.port(),
            GuestService::Broker.port(),
            GuestService::NetworkFlow.port(),
        ];
        let mut sorted = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ports.len(),
            "service ports collide: {ports:?}"
        );
    }

    #[test]
    fn service_display_names_the_service() {
        assert_eq!(GuestService::MachineControl.to_string(), "machine-control");
        assert_eq!(
            GuestService::BuilderDispatch.to_string(),
            "builder-dispatch"
        );
    }

    #[test]
    fn only_the_builder_control_plane_is_builder_tier() {
        // A workload guest serves none of these; the split keeps the build
        // engine's control ports out of workload wiring.
        assert!(GuestService::BuilderDispatch.is_builder_tier());
        assert!(GuestService::BuilderdControl.is_builder_tier());
        for service in [
            GuestService::MachineControl,
            GuestService::WorkloadExit,
            GuestService::Broker,
            GuestService::NetworkFlow,
            GuestService::ConsoleData { port: 20001 },
        ] {
            assert!(!service.is_builder_tier(), "{service} is not builder-tier");
        }
    }
}
