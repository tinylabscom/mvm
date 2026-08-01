//! libkrun + native-gateway bridge (SOCK_DGRAM shuffle) — the macOS path
//! where the native gateway owns a listener and this bridge shuffles
//! datagrams between it and libkrun's own listener.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use crate::supervisor::audit::{FlowCloseReason, FlowDirection};
use crate::supervisor::network::PacketCtx;
use crate::supervisor::network::packet::{self, FlowKey};
use crate::supervisor::network::pipeline::{PacketDecision, run_packet_pipeline};

use super::events::{FlowEvent, FlowEventKind, GatewayAuditEventSender, ObserverWiring};
use super::flow_policy::{FlowAction, FlowDecisionCtx, FlowPolicy};

/// True if `raw` parses to a flow already in `killed`. Cheap:
/// only parses when at least one flow has been killed. The async-mutex
/// guard is held across the synchronous parse (no await in between).
pub(super) async fn flow_is_killed(
    killed: &tokio::sync::Mutex<HashSet<FlowKey>>,
    raw: &[u8],
) -> bool {
    let guard = killed.lock().await;
    if guard.is_empty() {
        return false;
    }
    match packet::parse(raw) {
        Some(p) => {
            let key = p.five_tuple.flow_key();
            guard.contains(&key) || guard.contains(&key.reversed())
        }
        None => false,
    }
}

pub(super) async fn run_libkrun_native_gateway_bridge(
    gateway_socket_path: PathBuf,
    supervisor_listen_path: PathBuf,
    vm_name: String,
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: GatewayAuditEventSender,
    wiring: ObserverWiring,
) {
    use tokio::net::UnixDatagram;

    // Pre-unlink the supervisor listen path so a fresh bind works
    // after an ungraceful exit() of a prior supervisor.
    let _ = std::fs::remove_file(&supervisor_listen_path);

    let inbound = match UnixDatagram::bind(&supervisor_listen_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                path = %supervisor_listen_path.display(),
                error = %e,
                "native gateway bridge: failed to bind libkrun-facing socket"
            );
            return;
        }
    };
    // The gateway-facing socket MUST be bound to a pathname, not left
    // unbound/autobind: the gateway refuses datagrams from an empty-address
    // peer ("vfkit accept error: vfkit socket address is empty") and needs
    // a concrete address to send replies back to. macOS additionally never
    // autobinds AF_UNIX datagram sockets, so an unbound socket here has no
    // address at all and the gateway can neither accept our frames nor
    // reply. Bind a sibling path next to the libkrun-facing listener.
    let outbound_bind_path = native_gateway_outbound_bind_path(&supervisor_listen_path);
    let _ = std::fs::remove_file(&outbound_bind_path);
    let outbound = match UnixDatagram::bind(&outbound_bind_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                path = %outbound_bind_path.display(),
                error = %e,
                "native gateway bridge: failed to bind gateway-facing socket"
            );
            return;
        }
    };
    if let Err(e) = outbound.connect(&gateway_socket_path) {
        tracing::error!(
            path = %gateway_socket_path.display(),
            error = %e,
            "native gateway bridge: failed to connect to gateway"
        );
        return;
    }

    let flow_egress = format!("{vm_name}-egress");
    let flow_ingress = format!("{vm_name}-ingress");

    // libkrun does not reply to the recvfrom source of its egress datagrams; it
    // binds and listens for the return path on a derived sibling of the path it
    // was told to connect to (`<listen>-krun.sock`). Address ingress there — the
    // recvfrom source is not a usable reply target on macOS, so the prior
    // `peer.as_pathname()` return silently dropped every inbound frame and the
    // guest never saw a response regardless of policy.
    let krun_reply_path = libkrun_reply_path(&supervisor_listen_path);
    let mut egress_opened = false;
    let mut ingress_opened = false;

    let inbound = Arc::new(inbound);
    let outbound = Arc::new(outbound);

    // Per-direction clones of the packet-observer wiring.
    let mtu = wiring.mtu;
    let policy_a = policy.clone();
    let event_a = event_tx.clone();
    let inbound_a = inbound.clone();
    let outbound_a = outbound.clone();
    let flow_egress_a = flow_egress.clone();
    let observers_a = wiring.observers.clone();
    let latency_a = wiring.latency.clone();
    let killed_flows_a = wiring.killed_flows.clone();
    let substitution_a = wiring.substitution.clone();
    let scan_a = wiring.scan.clone();
    let vm_name_a = vm_name.clone();
    let tenant_a = tenant.clone();

    let egress = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match inbound_a.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => return Err::<(), std::io::Error>(e),
            };

            if !egress_opened {
                let action = policy_a.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Egress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                });
                match action {
                    FlowAction::Allow => {
                        let _ = event_a
                            .send(FlowEvent {
                                flow_id: flow_egress_a.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        egress_opened = true;
                    }
                    FlowAction::Drop { reason: _ } => {
                        let _ = event_a
                            .send(FlowEvent {
                                flow_id: flow_egress_a.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        return Ok(());
                    }
                }
            }

            // Packet-observer pipeline. Short-circuit packets on
            // an already-killed flow, then fan out; `Forward` relays the
            // (possibly rebuilt) frame, `Kill` records the flow + emits a
            // fault and drops (fail-closed).
            let raw = &buf[..n];
            if flow_is_killed(&killed_flows_a, raw).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name_a,
                tenant: &tenant_a,
                direction: FlowDirection::Egress,
                flow_id: &flow_egress_a,
            };
            match run_packet_pipeline(
                &observers_a,
                substitution_a.as_ref(),
                scan_a.as_ref(),
                ctx,
                raw,
                mtu,
                &latency_a,
            ) {
                PacketDecision::Forward { frame, .. } => {
                    // send (not send_to) — outbound is connected to the gateway.
                    outbound_a.send(&frame).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows_a.lock().await.insert(k);
                    }
                    let _ = event_a
                        .send(FlowEvent {
                            flow_id: flow_egress_a.clone(),
                            direction: FlowDirection::Egress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency_a.write_scrape_file();
        }
    };

    let policy_b = policy.clone();
    let event_b = event_tx.clone();
    let inbound_b = inbound.clone();
    let outbound_b = outbound.clone();
    let flow_ingress_b = flow_ingress.clone();
    let observers_b = wiring.observers.clone();
    let latency_b = wiring.latency.clone();
    let killed_flows_b = wiring.killed_flows.clone();
    let substitution_b = wiring.substitution.clone();
    let scan_b = wiring.scan.clone();
    let vm_name_b = vm_name.clone();
    let tenant_b = tenant.clone();

    let ingress = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match outbound_b.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !ingress_opened {
                let action = policy_b.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Ingress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                });
                match action {
                    FlowAction::Allow => {
                        let _ = event_b
                            .send(FlowEvent {
                                flow_id: flow_ingress_b.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        ingress_opened = true;
                    }
                    FlowAction::Drop { reason: _ } => {
                        let _ = event_b
                            .send(FlowEvent {
                                flow_id: flow_ingress_b.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        return Ok(());
                    }
                }
            }

            // Packet-observer pipeline (ingress direction).
            let raw = &buf[..n];
            if flow_is_killed(&killed_flows_b, raw).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name_b,
                tenant: &tenant_b,
                direction: FlowDirection::Ingress,
                flow_id: &flow_ingress_b,
            };
            match run_packet_pipeline(
                &observers_b,
                substitution_b.as_ref(),
                scan_b.as_ref(),
                ctx,
                raw,
                mtu,
                &latency_b,
            ) {
                PacketDecision::Forward { frame, .. } => {
                    // Return to libkrun's bound listener (`<listen>-krun.sock`),
                    // not the recvfrom source of its egress traffic.
                    inbound_b.send_to(&frame, &krun_reply_path).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows_b.lock().await.insert(k);
                    }
                    let _ = event_b
                        .send(FlowEvent {
                            flow_id: flow_ingress_b.clone(),
                            direction: FlowDirection::Ingress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency_b.write_scrape_file();
        }
    };

    let result = tokio::join!(egress, ingress);
    let _ = result;
    // Cleanup both bound sockets on shutdown.
    let _ = std::fs::remove_file(&supervisor_listen_path);
    let _ = std::fs::remove_file(&outbound_bind_path);
}

/// Bind path for the bridge's gateway-facing datagram socket — a sibling
/// of the libkrun-facing listener (`<listen>.gw-out`). Must be a real
/// pathname: the gateway rejects empty-address peers and macOS never
/// autobinds AF_UNIX datagram sockets.
fn native_gateway_outbound_bind_path(supervisor_listen_path: &std::path::Path) -> PathBuf {
    let mut s = supervisor_listen_path.as_os_str().to_os_string();
    s.push(".gw-out");
    PathBuf::from(s)
}

/// The path libkrun binds its own datagram socket to for the return path when
/// told to connect to `supervisor_listen_path` — a `-krun.sock` sibling. libkrun
/// listens for ingress here, and (unlike a connected stream) its egress
/// datagrams do not carry a recvfrom source the bridge can reply to, so the
/// internet→guest leg must target this derived path.
pub(super) fn libkrun_reply_path(supervisor_listen_path: &std::path::Path) -> PathBuf {
    let mut s = supervisor_listen_path.as_os_str().to_os_string();
    s.push("-krun.sock");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::super::events::{BRIDGE_MTU, audit_event_channel};
    use super::super::flow_policy::{PlanFlowPolicy, bare_network_policy_egress};
    use super::super::test_support::*;
    use super::*;
    use crate::supervisor::network::latency::ObserverLatency;
    use crate::supervisor::network::packet::ParsedPacket;
    use crate::supervisor::network::stages::{NoopSubstitution, build_egress_scan};
    use crate::supervisor::network::{Directions, Observer, RequiredCapabilities, Verdict};
    use mvm_core::policy::projection::CanonicalEgress;
    use mvm_core::policy::{L4RuleSpec, canonicalize_l4};

    /// Egress observer that drops everything.
    struct DropObs;
    impl Observer for DropObs {
        fn name(&self) -> &'static str {
            "test-drop"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            payload_tap_caps()
        }
        fn on_flow_event(&self, _: &FlowEvent) {}
        fn directions(&self) -> Directions {
            Directions::Egress
        }
        fn on_packet(&self, _c: &PacketCtx<'_>, _p: &ParsedPacket<'_>) -> Verdict {
            Verdict::Drop
        }
    }

    /// A TCP ingress frame (internet `src:port` → guest 10.0.0.2) — the return
    /// direction of [`tcp_egress_frame_to`]. Drives the bridge's internet→guest
    /// leg so the full-duplex return path is exercised, not just egress.
    fn tcp_ingress_frame_from(src: [u8; 4], src_port: u16, payload: &[u8]) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([2; 6], [1; 6])
            .ipv4(src, [10, 0, 0, 2], 64)
            .tcp(src_port, 40000, 1, 64000);
        let mut o = Vec::new();
        b.write(&mut o, payload).unwrap();
        o
    }

    /// A bare DNS pin registry pinning `host` to `ips`, valid now — the
    /// admission-time pin `run_bridge_inner` resolves on the host. Tests build it
    /// by hand so the bare-L4 lowering is exercised without real DNS.
    fn bare_pins(host: &str, ips: &[&str]) -> mvm_core::policy::dns_pin::DnsPinRegistry {
        let mut reg = mvm_core::policy::dns_pin::DnsPinRegistry::new();
        reg.add(mvm_core::policy::dns_pin::new_pin(
            host,
            ips.iter().map(|s| s.parse().unwrap()).collect(),
            chrono::Duration::hours(1),
        ));
        reg
    }

    #[test]
    fn observer_wiring_defaults_to_noop_stages() {
        // The bridge wiring carries the egress stages; the default is
        // no-op, so the secrets subsystem opts in by setting them — never the reverse.
        let w = wiring_with(vec![]);
        assert_eq!(w.substitution.name(), "noop-substitution");
        assert_eq!(w.scan.name(), "noop-scan");
    }

    /// Connect a libkrun-side datagram socket to the bridge's listener,
    /// retrying until the bridge has bound it.
    async fn connect_libkrun(path: &std::path::Path) -> tokio::net::UnixDatagram {
        let sock = tokio::net::UnixDatagram::unbound().unwrap();
        for _ in 0..100 {
            if sock.connect(path).is_ok() {
                return sock;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sock.connect(path).expect("bridge never bound its listener");
        sock
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_gateway_pipeline_forwards_modified_frame() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("native-gateway.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gateway = tokio::net::UnixDatagram::bind(&gateway_path).unwrap();

        let (tx, _rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gateway_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(RedactorObs)]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&tcp_egress_frame(b"hello-SECRET-bye"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gateway.recv(&mut buf))
            .await
            .expect("gateway must receive the forwarded frame in time")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert!(
            parsed.l4_payload.windows(6).any(|w| w == b"XXXXXX"),
            "gateway must see the redacted payload"
        );
        assert!(
            !parsed.l4_payload.windows(6).any(|w| w == b"SECRET"),
            "the secret must not reach the gateway"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_gateway_pipeline_drop_kills_flow_and_emits_fault() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("native-gateway.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gateway = tokio::net::UnixDatagram::bind(&gateway_path).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gateway_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(DropObs)]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"anything")).await.unwrap();

        // The dropped packet must NOT reach the gateway.
        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gateway.recv(&mut buf),
        )
        .await;
        assert!(got.is_err(), "dropped packet must not reach the gateway");

        // A FlowOpened then an ObserverFault must arrive on the event stream.
        let mut saw_fault = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    let ev = ev.into_flow().expect("bridge emits a flow event");
                    if let FlowEventKind::ObserverFault { observer, reason } = ev.kind {
                        assert_eq!(observer, "test-drop");
                        assert_eq!(reason, "drop");
                        saw_fault = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(saw_fault, "an ObserverFault event must be emitted on drop");
        bridge.abort();
    }

    // ───────────────────────────────────────────────────────────────
    // Per-tenant L4 egress enforcement exercised
    // through the LIVE libkrun native-gateway bridge (real Unix datagram
    // sockets, no VM). Drives the production scan (`build_egress_scan`)
    // over `run_libkrun_native_gateway_bridge`: a denied flow is withheld from
    // the gateway, an allowed flow is forwarded.
    // ───────────────────────────────────────────────────────────────

    /// A bridge `ObserverWiring` whose egress scan is the real production scan for
    /// `l4` + `dns_allow` (mandatory-deny + L4 + DNS sink-hole), no observers.
    fn wiring_with_egress_scan(
        l4: Option<CanonicalEgress>,
        dns_allow: Vec<String>,
    ) -> ObserverWiring {
        ObserverWiring {
            observers: vec![],
            latency: Arc::new(ObserverLatency::new("vm-test", "t")),
            killed_flows: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            mtu: BRIDGE_MTU,
            transcript_capture_roots: None,
            substitution: Arc::new(NoopSubstitution),
            scan: build_egress_scan(l4, dns_allow),
        }
    }

    /// A UDP/53 frame (guest 10.0.0.2 → resolver 1.1.1.1) carrying a DNS query
    /// for `qname` (A/IN). 1.1.1.1 is a public IP, so mandatory-deny passes it
    /// and the DNS sink-hole decides on the qname.
    fn udp_dns_frame(qname: &str) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let mut dns = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in qname.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype A, qclass IN
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .udp(40000, 53);
        let mut o = Vec::new();
        b.write(&mut o, &dns).unwrap();
        o
    }

    /// A DHCP DISCOVER-shaped egress frame (guest 0.0.0.0:68 → broadcast
    /// 255.255.255.255:67). The payload is a stub — only the UDP 5-tuple matters
    /// to the flow gate. Used to pin the deny-all control-plane posture: DHCP is
    /// an egress flow and is dropped at the gate under deny-all (the guest then
    /// self-assigns the static native-gateway fallback address — no lease, no hang).
    fn dhcp_discover_frame() -> Vec<u8> {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([1; 6], [0xff; 6])
            .ipv4([0, 0, 0, 0], [255, 255, 255, 255], 64)
            .udp(68, 67);
        let mut o = Vec::new();
        b.write(&mut o, &[0u8; 32]).unwrap();
        o
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn l4_policy_denied_flow_is_dropped_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("native-gateway.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gateway = tokio::net::UnixDatagram::bind(&gateway_path).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        // deny_all egress → the egress frame to 93.184.216.34:443 has no
        // matching rule → L4PolicyScan drops it at the chokepoint.
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gateway_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(Some(CanonicalEgress::Rules(vec![])), vec![]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        // The denied packet must NOT reach the gateway helper.
        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gateway.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "an L4-denied egress packet must not reach the gateway helper"
        );

        // The scan-chain kill surfaces as an ObserverFault on the flow stream.
        let mut saw_fault = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    let ev = ev.into_flow().expect("bridge emits a flow event");
                    if let FlowEventKind::ObserverFault { observer, reason } = ev.kind {
                        assert_eq!(observer, "l4-policy");
                        assert_eq!(reason, "drop");
                        saw_fault = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_fault,
            "an ObserverFault must be emitted when the L4 policy drops"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn l4_policy_allowed_flow_is_forwarded_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, _rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        // Allow tcp to exactly 93.184.216.34:443 — the frame's destination.
        let allow = canonicalize_l4(&[L4RuleSpec {
            proto: "tcp".into(),
            dst_cidr: "93.184.216.34/32".into(),
            port_lo: 443,
            port_hi: 443,
        }])
        .unwrap();
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(Some(allow), vec![]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        // The allowed packet is forwarded to gvproxy.
        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("an L4-allowed egress packet must reach gvproxy")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 443);
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_sinkhole_drops_a_denied_lookup_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        // Egress allow-list = {example.com} → a UDP/53 query for a host outside
        // it is sink-holed at the chokepoint.
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(None, vec!["example.com".to_string()]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&udp_dns_frame("tracker.evil.test"))
            .await
            .unwrap();

        // The denied lookup must NOT reach gvproxy.
        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "a sink-holed DNS query must not reach gvproxy"
        );

        let mut saw_fault = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    let ev = ev.into_flow().expect("bridge emits a flow event");
                    if let FlowEventKind::ObserverFault { observer, reason } = ev.kind {
                        assert_eq!(observer, "dns-sinkhole");
                        assert_eq!(reason, "drop");
                        saw_fault = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_fault,
            "an ObserverFault must fire when DNS is sink-holed"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_sinkhole_forwards_an_allowed_lookup_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, _rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(None, vec!["example.com".to_string()]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&udp_dns_frame("api.example.com"))
            .await
            .unwrap();

        // An allowed lookup is forwarded to gvproxy.
        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("an allowed DNS query must reach gvproxy")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 53);
        bridge.abort();
    }

    // ───────────────────────────────────────────────────────────────
    // Per-tenant FlowPolicy enforce exercised through the
    // LIVE libkrun native-gateway bridge (real Unix datagram sockets, no VM). Unlike
    // the L4/DNS scan tests above, these drive the *flow-open* gate
    // (`PlanFlowPolicy`) with a NoopScan wiring, isolating the coarse
    // deny-by-default gate from the packet-scan layer.
    // ───────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plan_flow_policy_deny_all_drops_egress_flow_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        // Deny-all resolved policy → PlanFlowPolicy drops the egress flow at
        // open, before any packet scan runs. NoopScan wiring proves the drop is
        // the FlowPolicy's, not the packet layer's.
        let policy: Arc<dyn FlowPolicy> = Arc::new(PlanFlowPolicy::from_effective(
            &mvm_core::policy::EffectivePolicy::default(),
        ));
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        // The denied flow's packet must NOT reach gvproxy.
        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "a flow-policy-denied egress packet must not reach gvproxy"
        );

        // The drop surfaces as FlowClosed{PolicyDropped} on the event stream.
        let mut saw_drop = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    let ev = ev.into_flow().expect("bridge emits a flow event");
                    if let FlowEventKind::Closed { reason } = ev.kind {
                        assert!(matches!(reason, FlowCloseReason::PolicyDropped));
                        assert_eq!(ev.direction, FlowDirection::Egress);
                        saw_drop = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_drop,
            "a FlowClosed{{PolicyDropped}} must fire when the flow policy denies egress"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plan_flow_policy_open_allows_egress_flow_through_the_live_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, _rx) = audit_event_channel(64);
        // `open` egress mode → the flow opens; with NoopScan the frame is
        // forwarded to the gateway.
        let eff = mvm_core::policy::EffectivePolicy {
            egress: mvm_core::policy::EgressPolicy {
                mode: Some("open".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy: Arc<dyn FlowPolicy> = Arc::new(PlanFlowPolicy::from_effective(&eff));
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("an open-policy egress packet must reach gvproxy")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 443);
        bridge.abort();
    }

    // ───────────────────────────────────────────────────────────────
    // The BARE `NetworkPolicy` no-bundle lowering (`bare_network_policy_egress`,
    // the exact path `run_bridge_inner` takes for `VmStartConfig.network_policy`
    // → `--net` / `--allow-host` on libkrun transient runs) exercised through
    // the LIVE bridge. These drive the *production* lowering (flow gate + scan)
    // end-to-end, so they validate egress enforcement on the no-bundle path even
    // though a macOS transient guest can't be networked directly (the init
    // doesn't DHCP and the exec is unprivileged).
    // ───────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_deny_all_policy_drops_egress_through_the_live_bridge() {
        // No flag ⇒ deny-all. The bare lowering's flow gate drops egress at open.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::deny_all(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, mut rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "deny-all bare policy must withhold egress from the gateway"
        );
        let mut saw_drop = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    let ev = ev.into_flow().expect("bridge emits a flow event");
                    if matches!(
                        ev.kind,
                        FlowEventKind::Closed {
                            reason: FlowCloseReason::PolicyDropped
                        }
                    ) {
                        saw_drop = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_drop,
            "deny-all bare policy must emit FlowClosed{{PolicyDropped}}"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_unrestricted_policy_forwards_egress_through_the_live_bridge() {
        // `--network-preset unrestricted`: the bare lowering opens the flow gate
        // and the L4 scan resolves to `Unrestricted` (no host:port gate), so
        // arbitrary egress reaches the gateway under the always-on mandatory-deny
        // backstop. This is the verdict-0 arm of the libkrun egress matrix
        // (`up --network-preset unrestricted`), the sibling of the deny-all and
        // allow-list arms above. Its absence let the "drops every flow regardless
        // of policy" regression hide: deny-all *looked* right while unrestricted
        // silently dropped too.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::unrestricted(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
        );
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("native-gateway.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gateway = tokio::net::UnixDatagram::bind(&gateway_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gateway_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        // An arbitrary host:port a deny-all or allow-list policy would drop.
        libkrun
            .send(&tcp_egress_frame_to([203, 0, 113, 9], 8443, b"payload"))
            .await
            .unwrap();
        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gateway.recv(&mut buf))
            .await
            .expect("unrestricted egress must reach the gateway")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 8443);
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_bridge_relays_ingress_reply_back_to_the_guest() {
        // Full-duplex proof: an internet→guest reply the gateway emits must traverse
        // the bridge back to the guest. libkrun listens for the return path on a
        // derived `<listen>-krun.sock` sibling — NOT the recvfrom source of its
        // egress datagrams (on macOS that source is not a usable reply target).
        // Model that faithfully: the guest's reply listener is the derived path,
        // and egress arrives from a *separate* sender so the recvfrom source is
        // unusable — exactly the condition under which the old `as_pathname()`
        // return silently dropped every inbound frame and the guest saw a
        // deny-all regardless of policy. So this test now fails if the return
        // path regresses to the recvfrom source.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::unrestricted(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
        );
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("native-gateway.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gateway = tokio::net::UnixDatagram::bind(&gateway_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gateway_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        // libkrun's reply listener is the derived `-krun.sock` path.
        let krun_reply = libkrun_reply_path(&sup_listen);
        let guest = tokio::net::UnixDatagram::bind(&krun_reply).unwrap();
        // A distinct sender for egress so the bridge's recvfrom source is NOT the
        // reply listener (mirrors libkrun, whose egress source is not the reply
        // address). Send via send_to so the source stays unnamed.
        let sender = tokio::net::UnixDatagram::unbound().unwrap();
        let mut sent = false;
        for _ in 0..100 {
            if sender
                .send_to(&tcp_egress_frame_to([1, 1, 1, 1], 443, b"syn"), &sup_listen)
                .await
                .is_ok()
            {
                sent = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sent, "bridge never bound {}", sup_listen.display());
        let mut buf = vec![0u8; 65536];
        let (n, bridge_peer) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            gateway.recv_from(&mut buf),
        )
        .await
        .expect("egress must reach the gateway")
        .expect("recv ok");
        assert!(n > 0);
        // The gateway emits the internet→guest reply back to the bridge's
        // gateway-facing socket.
        let bridge_outbound = bridge_peer
            .as_pathname()
            .expect("the bridge's gateway-facing socket is bound to a pathname");
        gateway
            .send_to(
                &tcp_ingress_frame_from([1, 1, 1, 1], 443, b"synack"),
                bridge_outbound,
            )
            .await
            .unwrap();
        // The reply must reach the guest's derived reply listener.
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), guest.recv(&mut buf))
            .await
            .expect("the ingress reply must reach the guest")
            .expect("recv ok");
        let parsed =
            crate::supervisor::network::packet::parse(&buf[..n]).expect("ingress frame re-parses");
        assert_eq!(parsed.five_tuple.src_port, 443);
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_deny_all_drops_dhcp_discover_through_the_live_bridge() {
        // Deny-all control-plane posture (loopback-only): DHCP is an egress flow,
        // so it is dropped at the flow gate under deny-all — no lease reaches the
        // guest. The guest then self-assigns the static native-gateway fallback address
        // (udhcpc `-n` exits rather than hanging on a never-arriving OFFER). This
        // pins the decision: deny-all admits NO control-plane carve-out; egress
        // (incl. DHCP) is uniformly denied and the static fallback keeps eth0 up.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::deny_all(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&dhcp_discover_frame()).await.unwrap();

        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "deny-all must drop the guest's DHCP DISCOVER (no lease under deny-all)"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_allow_list_policy_forwards_allowed_host_through_the_live_bridge() {
        // `--allow-host example.com:443` ⇒ flow opens AND a DNS lookup for the
        // listed host is forwarded — the end-to-end "allow-host actually opens
        // egress" proof the macOS VM-level test could not produce.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            &bare_pins("example.com", &["93.184.216.34"]),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&udp_dns_frame("example.com")).await.unwrap();

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("an allow-listed host's DNS lookup must reach gvproxy")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 53);
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_allow_list_policy_narrows_to_unlisted_host_through_the_live_bridge() {
        // `--allow-host example.com:443` ⇒ a lookup for a DIFFERENT host is
        // sink-holed: the allow-list narrows, it does not open everything.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            &bare_pins("example.com", &["93.184.216.34"]),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&udp_dns_frame("tracker.evil.test"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "an unlisted host's DNS lookup must be sink-holed under a bare allow-list"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_allow_list_l4_forwards_pinned_host_port_through_the_live_bridge() {
        // `--allow-host example.com:443` with the admission-time pin
        // example.com → 93.184.216.34 ⇒ a TCP connection to the pinned IP:port is
        // forwarded. Proves the L4 scan admits the allowed host:port (the allow
        // path is not over-blocked now that L4 gates it).
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            &bare_pins("example.com", &["93.184.216.34"]),
        );
        assert!(l4.is_some(), "bare allow-list now installs an L4 scan");
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"payload")).await.unwrap();

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("a TCP packet to the pinned host:port must reach gvproxy")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert_eq!(parsed.five_tuple.dst_port, 443);
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_allow_list_l4_drops_direct_ip_to_unlisted_through_the_live_bridge() {
        // THE direct-IP bypass, closed: `--allow-host example.com:443` pinned to
        // 93.184.216.34, but the guest dials a raw, unlisted IP (8.8.8.8:443) with
        // no DNS lookup. Name gating can't see it; the L4 scan must drop it —
        // uniform with Firecracker's nftables.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            &bare_pins("example.com", &["93.184.216.34"]),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&tcp_egress_frame_to([8, 8, 8, 8], 443, b"payload"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "a direct-IP dial to an unlisted address must be dropped at L4"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_allow_list_l4_drops_wrong_port_on_pinned_host_through_the_live_bridge() {
        // Port gating: `--allow-host example.com:443` pinned to 93.184.216.34, but
        // the guest dials the pinned IP on a DIFFERENT port (8080). The L4 scan
        // gates host:port, so this must drop — what a name-only gate would miss.
        let (l4, dns_allow, policy) = bare_network_policy_egress(
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            &bare_pins("example.com", &["93.184.216.34"]),
        );
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();
        let (tx, _rx) = audit_event_channel(64);
        let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with_egress_scan(l4, dns_allow),
        ));
        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&tcp_egress_frame_to([93, 184, 216, 34], 8080, b"payload"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "a connection to the pinned host on an unlisted port must drop at L4"
        );
        bridge.abort();
    }
}
