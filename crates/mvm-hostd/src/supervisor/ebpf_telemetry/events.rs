//! Telemetry event types for host-side vsock egress observation.

use std::net::SocketAddr;

/// One telemetry event observed from the host-side egress path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressEvent {
    /// Resolved destination of the outbound connection.
    pub destination: SocketAddr,
    /// Cumulative bytes observed on this flow (best-effort).
    pub bytes: u64,
    /// Latency in microseconds, if measured.
    pub latency_us: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryEvent {
    Egress(EgressEvent),
}
