//! Plan 129 egress-proxy seams (plan 123 Phase A / A3): two pluggable stages
//! on the per-packet egress path. **No-op by default** — Plan 129 supplies the
//! real handlers later. These are designed to run *inside*
//! `run_packet_pipeline` (the claim-10 egress chokepoint every guest byte
//! transits), so they are never a bypass.
//!
//! A3.1 (this) introduces the seam: the traits + no-op defaults. A3.2 wires
//! them into the pipeline runner + the gateway bridge (substitution maps to the
//! existing `Verdict::Modify` rebuild path; a scan `Drop` maps to the same
//! fail-closed kill the observers use).

use crate::supervisor::network::PacketCtx;
use crate::supervisor::network::packet::ParsedPacket;

/// Outcome of the scan stage. `Pass` forwards the packet; `Drop` kills the
/// flow — the same fail-closed path as `Verdict::Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    Pass,
    Drop,
}

/// Rewrites outbound L4 payload bytes when a secret binding applies (Plan 129
/// substitution). The default is pass-through.
pub trait SubstitutionStage: Send + Sync {
    /// Stable identifier for audit / metrics.
    fn name(&self) -> &'static str;

    /// Return `Some(new_payload)` to rewrite the outbound L4 payload, or `None`
    /// to pass it through unchanged.
    fn substitute(&self, _ctx: &PacketCtx<'_>, _pkt: &ParsedPacket<'_>) -> Option<Vec<u8>> {
        None
    }
}

/// Observes the outbound payload and may request a drop (Plan 129 leak-scan).
/// The default observes nothing and always passes.
pub trait ScanStage: Send + Sync {
    /// Stable identifier for audit / metrics.
    fn name(&self) -> &'static str;

    fn scan(&self, _ctx: &PacketCtx<'_>, _pkt: &ParsedPacket<'_>) -> ScanOutcome {
        ScanOutcome::Pass
    }
}

/// Default no-op substitution: never rewrites.
pub struct NoopSubstitution;

impl SubstitutionStage for NoopSubstitution {
    fn name(&self) -> &'static str {
        "noop-substitution"
    }
}

/// Default no-op scan: never drops.
pub struct NoopScan;

impl ScanStage for NoopScan {
    fn name(&self) -> &'static str {
        "noop-scan"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::network::FlowDirection;
    use crate::supervisor::network::packet::{FiveTuple, L4Proto};

    #[test]
    fn noop_stages_pass_through_and_never_drop() {
        let pkt = ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Tcp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 5000,
                dst_port: 443,
            },
            l4_payload: b"hello-SECRET",
            raw_frame: b"hello-SECRET",
        };
        let ctx = PacketCtx {
            vm_name: "vm",
            tenant: "t",
            direction: FlowDirection::Egress,
            flow_id: "vm-egress",
        };
        // No binding applies → no rewrite; scan never drops. This is the
        // claim-10-safe default posture before Plan 129 plugs in real handlers.
        assert_eq!(NoopSubstitution.substitute(&ctx, &pkt), None);
        assert_eq!(NoopScan.scan(&ctx, &pkt), ScanOutcome::Pass);
    }
}
