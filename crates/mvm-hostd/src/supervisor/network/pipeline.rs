//! Plan 141 / ADR-064 — synchronous observer fan-out runner. Pure: takes
//! a raw frame + the observer slice, returns a `PacketDecision`. Reuses
//! the `catch_unwind` panic-isolation pattern from `signer_task`
//! (`gateway_bridge::signer_task`): a panicking observer is logged and
//! treated as `Forward`; siblings continue.
//!
//! Verdict semantics (Q8/Q9):
//! - Observers run in policy order; `Modify` chains (observer N+1 sees N's
//!   output); the first `Drop` wins and kills the flow.
//! - Any `Modify` the bridge cannot safely emit (over-MTU, unserializable)
//!   fails closed → `Kill`. `Modify(==current payload)` is a no-op.
//! - An observer whose `directions()` excludes the current direction is
//!   skipped (least-privilege).
//! - Non-IP/TCP/UDP frames (ARP, ICMP, malformed) forward unchanged with
//!   no flow key — the pipeline only engages parseable L4 packets.

use crate::supervisor::network::latency::ObserverLatency;
use crate::supervisor::network::packet::{self, FlowKey};
use crate::supervisor::network::{Observer, PacketCtx, Verdict};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

/// Why the runner forced a fail-closed flow kill (Plan 141 Q8). Maps to
/// the `reason` label on the `gateway.flow_observer_fault` chain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillReason {
    Drop,
    ModifyOverMtu,
    ModifyUnserializable,
}

impl KillReason {
    pub fn as_str(self) -> &'static str {
        match self {
            KillReason::Drop => "drop",
            KillReason::ModifyOverMtu => "modify_over_mtu",
            KillReason::ModifyUnserializable => "modify_unserializable",
        }
    }
}

/// Outcome the bridge acts on. `Forward` carries the (possibly rebuilt)
/// frame as `Cow` — `Borrowed` when nothing changed (zero-copy), `Owned`
/// after a `Modify`. `Kill` means: insert `flow_key` into `killed_flows`,
/// emit a fault entry, drop this + all subsequent packets on the flow.
#[derive(Debug)]
pub enum PacketDecision<'a> {
    Forward {
        frame: Cow<'a, [u8]>,
        flow_key: Option<FlowKey>,
    },
    Kill {
        observer: &'static str,
        reason: KillReason,
        flow_key: Option<FlowKey>,
    },
}

/// Run the observer chain over one raw ethernet frame. See module docs for
/// verdict semantics. `latency` records each `on_packet` wall time.
pub fn run_packet_pipeline<'a>(
    observers: &[Arc<dyn Observer>],
    ctx: PacketCtx<'_>,
    raw_frame: &'a [u8],
    mtu: usize,
    latency: &ObserverLatency,
) -> PacketDecision<'a> {
    // Parse once for the flow key + the unparseable short-circuit.
    let Some(parsed) = packet::parse(raw_frame) else {
        return PacketDecision::Forward {
            frame: Cow::Borrowed(raw_frame),
            flow_key: None,
        };
    };
    // `parsed` borrows raw_frame immutably; the per-observer loop below
    // re-parses the current frame so a chained Modify is visible to the
    // next observer.
    let flow_key = Some(parsed.five_tuple.flow_key());

    // `owned` holds the live frame once an observer has rebuilt it.
    let mut owned: Option<Vec<u8>> = None;

    for obs in observers {
        if !obs.directions().includes(ctx.direction) {
            continue;
        }
        let cur: &[u8] = owned.as_deref().unwrap_or(raw_frame);
        let Some(cur_parsed) = packet::parse(cur) else {
            // A prior rebuild produced something unparseable — fail closed.
            return PacketDecision::Kill {
                observer: obs.name(),
                reason: KillReason::ModifyUnserializable,
                flow_key,
            };
        };

        let start = Instant::now();
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            obs.on_packet(&ctx, &cur_parsed)
        }));
        latency.record(
            obs.name(),
            ctx.direction,
            start.elapsed().as_micros() as u64,
        );

        let verdict = match verdict {
            Ok(v) => v,
            Err(panic) => {
                tracing::warn!(
                    observer = obs.name(),
                    flow_id = ctx.flow_id,
                    panic = %downcast_panic(&panic),
                    "on_packet panicked; isolated via catch_unwind, treated as Forward"
                );
                continue;
            }
        };

        match verdict {
            Verdict::Forward => {}
            Verdict::Drop => {
                return PacketDecision::Kill {
                    observer: obs.name(),
                    reason: KillReason::Drop,
                    flow_key,
                };
            }
            Verdict::Modify(new_payload) => {
                if new_payload == cur_parsed.l4_payload {
                    continue; // no-op modify — skip the rebuild
                }
                match packet::rebuild_with_payload(cur, &new_payload, mtu) {
                    Ok(new_frame) => owned = Some(new_frame),
                    Err(packet::RebuildError::ExceedsMtu { .. }) => {
                        return PacketDecision::Kill {
                            observer: obs.name(),
                            reason: KillReason::ModifyOverMtu,
                            flow_key,
                        };
                    }
                    Err(_) => {
                        return PacketDecision::Kill {
                            observer: obs.name(),
                            reason: KillReason::ModifyUnserializable,
                            flow_key,
                        };
                    }
                }
            }
        }
    }

    PacketDecision::Forward {
        frame: match owned {
            Some(v) => Cow::Owned(v),
            None => Cow::Borrowed(raw_frame),
        },
        flow_key,
    }
}

fn downcast_panic(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::FlowDirection;
    use crate::supervisor::network::latency::ObserverLatency;
    use crate::supervisor::network::packet::{ParsedPacket, parse};
    use crate::supervisor::network::{
        Directions, Observer, PacketCtx, RequiredCapabilities, Verdict,
    };
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(
                Ipv4Addr::new(10, 0, 0, 2).octets(),
                Ipv4Addr::new(1, 1, 1, 1).octets(),
                64,
            )
            .tcp(5000, 443, 1, 64000);
        let mut o = Vec::new();
        b.write(&mut o, payload).unwrap();
        o
    }

    fn lat() -> ObserverLatency {
        ObserverLatency::new("vm", "t")
    }

    fn ctx<'a>(dir: FlowDirection) -> PacketCtx<'a> {
        PacketCtx {
            vm_name: "vm",
            tenant: "t",
            direction: dir,
            flow_id: "vm-egress",
        }
    }

    /// Test observer driven by a payload->verdict closure + direction.
    struct PayloadObs<F: Fn(&[u8]) -> Verdict + Send + Sync>(F, Directions);
    impl<F: Fn(&[u8]) -> Verdict + Send + Sync> Observer for PayloadObs<F> {
        fn name(&self) -> &'static str {
            "payload-obs"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            RequiredCapabilities {
                flow_events: true,
                payload_tap: true,
            }
        }
        fn on_flow_event(&self, _: &crate::supervisor::gateway_bridge::FlowEvent) {}
        fn directions(&self) -> Directions {
            self.1
        }
        fn on_packet(&self, _c: &PacketCtx<'_>, p: &ParsedPacket<'_>) -> Verdict {
            (self.0)(p.l4_payload)
        }
    }

    #[test]
    fn empty_observers_forwards_unmodified() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![];
        match run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat()) {
            PacketDecision::Forward { frame, flow_key } => {
                assert_eq!(&*frame, &f[..]);
                assert!(flow_key.is_some());
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn non_ip_frame_forwards_unchanged_with_no_flow_key() {
        let arp = [0xffu8; 14];
        let obs: Vec<Arc<dyn Observer>> = vec![];
        match run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &arp, 1514, &lat()) {
            PacketDecision::Forward { flow_key, .. } => assert!(flow_key.is_none()),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn modify_rebuilds_and_chains_to_next_observer() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![
            Arc::new(PayloadObs(
                |p: &[u8]| {
                    let s = String::from_utf8_lossy(p).replace("SECRET", "XXXXXX");
                    Verdict::Modify(s.into_bytes())
                },
                Directions::Egress,
            )),
            Arc::new(PayloadObs(
                |p: &[u8]| {
                    assert!(
                        p.windows(6).any(|w| w == b"XXXXXX"),
                        "obs2 must see obs1's modify"
                    );
                    Verdict::Forward
                },
                Directions::Egress,
            )),
        ];
        match run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat()) {
            PacketDecision::Forward { frame, .. } => {
                let p = parse(&frame).unwrap();
                assert!(p.l4_payload.windows(6).any(|w| w == b"XXXXXX"));
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn first_drop_wins_and_kills_flow() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![
            Arc::new(PayloadObs(|_| Verdict::Drop, Directions::Egress)),
            Arc::new(PayloadObs(
                |_| panic!("must not run after Drop"),
                Directions::Egress,
            )),
        ];
        match run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat()) {
            PacketDecision::Kill {
                observer,
                reason,
                flow_key,
            } => {
                assert_eq!(observer, "payload-obs");
                assert!(matches!(reason, KillReason::Drop));
                assert!(flow_key.is_some());
            }
            other => panic!("expected Kill, got {other:?}"),
        }
    }

    #[test]
    fn modify_over_mtu_kills_flow_failclosed() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![Arc::new(PayloadObs(
            |_| Verdict::Modify(vec![0u8; 4096]),
            Directions::Egress,
        ))];
        let d = run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat());
        assert!(matches!(
            d,
            PacketDecision::Kill {
                reason: KillReason::ModifyOverMtu,
                ..
            }
        ));
    }

    #[test]
    fn direction_filter_skips_non_matching_observer() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![Arc::new(PayloadObs(
            |_| panic!("ingress observer ran on egress packet"),
            Directions::Ingress,
        ))];
        let d = run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat());
        assert!(matches!(d, PacketDecision::Forward { .. }));
    }

    #[test]
    fn panicking_observer_is_isolated_and_forwards() {
        let f = frame(b"hello-SECRET");
        let obs: Vec<Arc<dyn Observer>> = vec![
            Arc::new(PayloadObs(|_| panic!("boom"), Directions::Egress)),
            Arc::new(PayloadObs(|_| Verdict::Forward, Directions::Egress)),
        ];
        let d = run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat());
        assert!(
            matches!(d, PacketDecision::Forward { .. }),
            "panic must be isolated -> Forward"
        );
    }

    #[test]
    fn modify_equal_to_original_is_treated_as_forward() {
        let f = frame(b"hello-SECRET");
        let original_payload = parse(&f).unwrap().l4_payload.to_vec();
        let obs: Vec<Arc<dyn Observer>> = vec![Arc::new(PayloadObs(
            move |_| Verdict::Modify(original_payload.clone()),
            Directions::Egress,
        ))];
        match run_packet_pipeline(&obs, ctx(FlowDirection::Egress), &f, 1514, &lat()) {
            // Borrowed (not Owned) proves no rebuild happened.
            PacketDecision::Forward { frame, .. } => {
                assert!(matches!(frame, std::borrow::Cow::Borrowed(_)))
            }
            other => panic!("got {other:?}"),
        }
    }
}
