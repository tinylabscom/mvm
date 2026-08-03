//! Bounded gateway metrics.
//!
//! Counters, not events. A per-packet log line on a path a guest drives is
//! itself a denial of service, so drops and policy refusals move a counter
//! and the audit log records decision *classes* with their totals.
//!
//! The deny map is keyed by [`DenyCode`], a closed enum, so the label set
//! cannot grow at runtime.

use std::collections::BTreeMap;

use mvm_net::l3::DenyCode;

/// One machine's counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayMetrics {
    pub packets_egress: u64,
    pub packets_ingress: u64,
    pub bytes_egress: u64,
    pub bytes_ingress: u64,
    /// Frames that failed validation. Each one also ends a connection.
    pub malformed_frames: u64,
    /// Frames carrying a session that is not the live one.
    pub stale_session_frames: u64,
    pub queue_drops_ingress: u64,
    pub queue_drops_egress: u64,
    pub dns_admitted: u64,
    pub dns_denied: u64,
    pub dns_rate_limited: u64,
    pub dns_bindings_expired: u64,
    pub flows_expired: u64,
    pub flows_closed_on_teardown: u64,
    pub ingress_closed_on_teardown: u64,
    pub heartbeats_received: u64,
    pub datapath_errors: u64,
    pub tunnel_reconnects: u64,
    /// When the tunnel reached readiness, for a startup-latency figure.
    pub tunnel_ready_at_millis: Option<u64>,
    /// Refusals by reason.
    denies: BTreeMap<&'static str, u64>,
}

impl GatewayMetrics {
    /// Count one policy refusal.
    pub fn record_deny(&mut self, code: DenyCode) {
        *self.denies.entry(code.as_str()).or_insert(0) += 1;
    }

    /// Refusals for one reason.
    pub fn denies_for(&self, code: DenyCode) -> u64 {
        self.denies.get(code.as_str()).copied().unwrap_or(0)
    }

    /// Every refusal reason seen, with its count.
    pub fn denies(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.denies.iter().map(|(k, v)| (*k, *v))
    }

    /// Total refusals across every reason.
    pub fn total_denies(&self) -> u64 {
        self.denies.values().sum()
    }

    /// Whether anything at all has been refused. Cheap enough for a
    /// health check.
    pub fn has_denies(&self) -> bool {
        !self.denies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_accumulate_per_reason() {
        let mut m = GatewayMetrics::default();
        m.record_deny(DenyCode::SpoofedSource);
        m.record_deny(DenyCode::SpoofedSource);
        m.record_deny(DenyCode::PortNotAdmitted);
        assert_eq!(m.denies_for(DenyCode::SpoofedSource), 2);
        assert_eq!(m.denies_for(DenyCode::PortNotAdmitted), 1);
        assert_eq!(m.denies_for(DenyCode::FlowTableFull), 0);
        assert_eq!(m.total_denies(), 3);
    }

    #[test]
    fn a_fresh_metric_set_has_recorded_nothing() {
        let m = GatewayMetrics::default();
        assert!(!m.has_denies());
        assert_eq!(m.total_denies(), 0);
        assert_eq!(m.denies().count(), 0);
    }

    #[test]
    fn the_label_set_is_bounded_by_the_deny_code_enum() {
        let mut m = GatewayMetrics::default();
        for code in [
            DenyCode::MalformedPacket,
            DenyCode::SpoofedSource,
            DenyCode::FragmentRefused,
            DenyCode::OversizedPacket,
            DenyCode::AddressFamilyUnassigned,
            DenyCode::MulticastDenied,
            DenyCode::BroadcastDenied,
            DenyCode::ReservedRangeDenied,
            DenyCode::MandatoryDeny,
            DenyCode::PrivateRangeDenied,
            DenyCode::LoopbackDenied,
            DenyCode::LinkLocalDenied,
            DenyCode::ProtocolDenied,
            DenyCode::DestinationNotAdmitted,
            DenyCode::PortNotAdmitted,
            DenyCode::IcmpDenied,
            DenyCode::GatewayServiceDenied,
            DenyCode::FlowTableFull,
            DenyCode::HostSocketUnavailable,
            DenyCode::UnsolicitedInbound,
            DenyCode::WrongDestination,
            DenyCode::SessionNotReady,
        ] {
            m.record_deny(code);
            m.record_deny(code);
        }
        // Recording the same closed set twice cannot grow the label set.
        assert_eq!(m.denies().count(), 22);
        assert_eq!(m.total_denies(), 44);
    }
}
