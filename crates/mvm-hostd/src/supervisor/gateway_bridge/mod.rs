//! Per-VM gateway audit bridge — claim 10 leg 2 (no bytes leave the
//! trust boundary unaudited).
//!
//! Sits in-process between the guest virtio-net fd and the host
//! gateway (passt / native gateway). Two variants cover the backends
//! mvm ships today:
//!
//! - [`BridgeEndpoints::Passt`] — libkrun on Linux. SOCK_STREAM
//!   socketpair between supervisor + passt; bridge wraps both ends
//!   with `tokio::io::copy_bidirectional`. The libkrun-side fd is
//!   the supervisor's half of a *second* socketpair, so libkrun
//!   reads bridge-relayed bytes instead of passt directly.
//! - [`BridgeEndpoints::LibkrunNativeGateway`] — libkrun on macOS.
//!   SOCK_DGRAM (vfkit unixgram); the native gateway creates a listener,
//!   bridge binds an outer listener libkrun connects to, shuffles
//!   datagrams both ways. SOCK_DGRAM preserves packet boundaries.
//!
//! Both feed one ordered audit-event channel into a per-VM
//! `signer_task` that is the **sole** caller of
//! `AuditSigner::sign_and_emit` — combined with the
//! `FileAuditSigner` flock precursor (commit 2), this guarantees
//! per-tenant chain integrity even when multiple bridge tasks emit
//! concurrently within one supervisor process.
//!
//! In parallel, each event is published on a
//! `broadcast::Sender<String>` so live subscribers (`nc -U`) get
//! the same NDJSON in real time. The broadcast is informational;
//! the signed chain is the source of truth.
//!
//! Mediation seam: the bridge consults [`FlowPolicy::evaluate`]
//! before emitting `FlowOpened`. The live flow policy is derived from
//! the admitted bundle or threaded bare [`mvm_core::network_policy::NetworkPolicy`];
//! if neither is present, the bridge fails closed to deny-all.
//!
//! Concurrency model: each VM gets a dedicated `std::thread`
//! hosting a current-thread tokio runtime + `LocalSet`. Three
//! tasks run on that runtime — the bridge, the signer, and the
//! [`crate::supervisor::gateway_audit::GatewayAuditSink`] accept loop. Bridge
//! thread panic → `std::process::exit(1)` (fail-closed; the
//! gateway audit substrate is claim-10 load-bearing).
//!
//! ## Module map
//!
//! - [`flow_policy`] — the [`FlowPolicy`] mediation trait, [`PlanFlowPolicy`]
//!   (the deny-by-default flow gate), and the bare-`NetworkPolicy` lowering.
//!   Claim-10 frozen surface.
//! - [`config`] — [`BridgeEndpoints`] / [`BridgeConfig`].
//! - [`events`] — [`FlowEvent`] / [`FlowEventKind`] / [`ObserverWiring`] /
//!   [`FlowEventWire`].
//! - [`signer`] — the per-VM `signer_task`.
//! - [`run`] — [`spawn_bridge_thread`] / [`spawn_native_audit_feed`] and the
//!   thread + runtime entry points that dispatch to a variant.
//! - [`passt`] — the SOCK_STREAM splice (Linux libkrun + passt).
//! - [`native_gateway`] — the SOCK_DGRAM shuffle (macOS libkrun + native
//!   gateway).
//! - `native_gateway_live` (test-only) — end-to-end tests against a real
//!   gateway subprocess; split out from `native_gateway` to keep both files
//!   under a manageable size.

mod config;
mod events;
mod flow_policy;
mod native_gateway;
#[cfg(test)]
mod native_gateway_live;
mod passt;
mod run;
mod signer;

pub use config::{BridgeConfig, BridgeEndpoints};
pub use events::{
    BRIDGE_MTU, EVENT_CHANNEL_CAPACITY, FlowEvent, FlowEventKind, FlowEventWire, ObserverWiring,
    TranscriptCaptureRoots,
};
pub use flow_policy::{DropReason, FlowAction, FlowDecisionCtx, FlowPolicy, PlanFlowPolicy};
pub use run::{spawn_bridge_thread, spawn_native_audit_feed};
pub(crate) use signer::signer_task;

/// Shared `#[cfg(test)]` fixtures used by more than one submodule's test
/// block, so each can drive the live bridge end-to-end without duplicating
/// frame-builder / wiring-builder helpers. Kept out of any single
/// submodule so ownership of a fixture doesn't imply it only exercises
/// that submodule's code.
#[cfg(test)]
mod test_support {
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::supervisor::network::latency::ObserverLatency;
    use crate::supervisor::network::packet::ParsedPacket;
    use crate::supervisor::network::stages::{NoopScan, NoopSubstitution};
    use crate::supervisor::network::{
        Directions, Observer, PacketCtx, RequiredCapabilities, Verdict,
    };

    use super::events::{BRIDGE_MTU, FlowEvent, ObserverWiring};
    use super::flow_policy::{FlowPolicy, PlanFlowPolicy};

    pub(super) fn unrestricted_flow_policy() -> Arc<dyn FlowPolicy> {
        Arc::new(PlanFlowPolicy::from_network_policy(
            &mvm_core::network_policy::NetworkPolicy::unrestricted(),
        ))
    }

    pub(super) fn payload_tap_caps() -> RequiredCapabilities {
        RequiredCapabilities {
            flow_events: true,
            payload_tap: true,
        }
    }

    /// Egress observer that redacts "SECRET" → "XXXXXX" (same length).
    pub(super) struct RedactorObs;
    impl Observer for RedactorObs {
        fn name(&self) -> &'static str {
            "test-redactor"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            payload_tap_caps()
        }
        fn on_flow_event(&self, _: &FlowEvent) {}
        fn directions(&self) -> Directions {
            Directions::Egress
        }
        fn on_packet(&self, _c: &PacketCtx<'_>, p: &ParsedPacket<'_>) -> Verdict {
            let s = String::from_utf8_lossy(p.l4_payload).replace("SECRET", "XXXXXX");
            Verdict::Modify(s.into_bytes())
        }
    }

    pub(super) fn tcp_egress_frame(payload: &[u8]) -> Vec<u8> {
        tcp_egress_frame_to([93, 184, 216, 34], 443, payload)
    }

    /// A TCP egress frame (guest 10.0.0.2 → `dst:port`). Lets the bare-L4 tests
    /// dial an unlisted IP or the wrong port to prove the L4 scan drops it.
    pub(super) fn tcp_egress_frame_to(dst: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 2], dst, 64)
            .tcp(40000, dst_port, 1, 64000);
        let mut o = Vec::new();
        b.write(&mut o, payload).unwrap();
        o
    }

    pub(super) fn wiring_with(observers: Vec<Arc<dyn Observer>>) -> ObserverWiring {
        ObserverWiring {
            observers,
            latency: Arc::new(ObserverLatency::new("vm-test", "t")),
            killed_flows: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            mtu: BRIDGE_MTU,
            transcript_capture_roots: None,
            substitution: Arc::new(NoopSubstitution),
            scan: Arc::new(NoopScan),
        }
    }
}
