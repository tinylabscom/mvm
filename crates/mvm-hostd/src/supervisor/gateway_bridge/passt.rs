//! Passt bridge — the SOCK_STREAM splice used on Linux libkrun. Frames are
//! length-prefixed (the qemu socket wire format passt's `--fd` backend
//! speaks); each direction runs the packet-observer pipeline before
//! re-emitting.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use crate::supervisor::audit::{FlowCloseReason, FlowDirection};
use crate::supervisor::network::PacketCtx;
use crate::supervisor::network::pipeline::{PacketDecision, run_packet_pipeline};

use super::events::{
    FlowEvent, FlowEventKind, GatewayAuditEventSender, ObserverWiring, TranscriptCaptureRoots,
    TranscriptSealedEvent,
};
use super::flow_policy::{FlowAction, FlowDecisionCtx, FlowPolicy};
use super::native_gateway::flow_is_killed;

pub(super) async fn run_passt_bridge(
    gateway_fd: OwnedFd,
    supervisor_fd: OwnedFd,
    vm_name: String,
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: GatewayAuditEventSender,
    wiring: ObserverWiring,
) {
    let gateway_std = std::os::unix::net::UnixStream::from(gateway_fd);
    if let Err(e) = gateway_std.set_nonblocking(true) {
        tracing::error!(error = %e, "passt: failed to set gateway fd nonblocking");
        return;
    }
    let gateway = match tokio::net::UnixStream::from_std(gateway_std) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "passt: failed to wrap gateway fd");
            return;
        }
    };
    let guest_std = std::os::unix::net::UnixStream::from(supervisor_fd);
    if let Err(e) = guest_std.set_nonblocking(true) {
        tracing::error!(error = %e, "passt: failed to set supervisor fd nonblocking");
        return;
    }
    let guest = match tokio::net::UnixStream::from_std(guest_std) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "passt: failed to wrap supervisor fd");
            return;
        }
    };

    let _ =
        bridge_copy_bidirectional(gateway, guest, vm_name, tenant, policy, event_tx, wiring).await;
}

/// Read one length-prefixed frame from a passt/qemu stream socket. passt's
/// `--fd` backend (which libkrun's `krun_add_net_unixstream_fd` path
/// speaks) uses the qemu socket protocol: each ethernet frame is prefixed
/// with a 4-byte big-endian length. Returns `Ok(None)` on a clean EOF at a
/// frame boundary. Caps the frame at 65535 — a bogus length fails closed
/// instead of allocating gigabytes.
///
/// NOTE: the 4-byte-BE qemu-socket framing is the documented passt wire
/// format, but the live Passt path is Linux-only and is validated on
/// Linux/KVM CI (this host cannot exercise it). The reframing logic itself
/// is unit-tested via an in-memory duplex.
async fn read_one_frame<R>(r: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut lenbuf = [0u8; 4];
    match r.read_exact(&mut lenbuf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len > 65_535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "passt frame length-prefix exceeds 65535",
        ));
    }
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// Write one length-prefixed frame (inverse of [`read_one_frame`]).
async fn write_one_frame<W>(w: &mut W, frame: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(frame.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large for 4-byte length prefix",
        )
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(frame).await?;
    Ok(())
}

/// Frame-aware bidirectional bridge between two passt/qemu stream sockets.
/// Reads one length-prefixed ethernet frame at a time, runs the
/// packet-observer pipeline, and re-emits the (possibly rebuilt) frame
/// with a corrected length prefix. Emits `FlowOpened` on
/// the first frame per direction (after `FlowPolicy::evaluate` returns
/// `Allow`) and `FlowClosed { Eof }` on a clean EOF; `BridgeError` on I/O
/// error.
///
/// Direction semantics (the earlier opaque-copy code had the labels
/// reversed, which didn't matter for a byte pump but does for observers):
/// `a` faces passt/internet, `b` faces libkrun/guest. **Egress** = guest →
/// internet (read `b`, write `a`); **ingress** = internet → guest (read
/// `a`, write `b`).
async fn bridge_copy_bidirectional(
    a: tokio::net::UnixStream,
    b: tokio::net::UnixStream,
    vm_name: String,
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: GatewayAuditEventSender,
    wiring: ObserverWiring,
) -> std::io::Result<()> {
    let (mut a_rd, mut a_wr) = a.into_split();
    let (mut b_rd, mut b_wr) = b.into_split();

    let flow_egress = format!("{vm_name}-egress");
    let flow_ingress = format!("{vm_name}-ingress");

    let mut egress_opened = false;
    let mut ingress_opened = false;

    let observers = wiring.observers;
    let latency = wiring.latency;
    let killed_flows = wiring.killed_flows;
    let mtu = wiring.mtu;
    let transcript_capture_roots = wiring.transcript_capture_roots;
    let substitution = wiring.substitution;
    let scan = wiring.scan;

    // Forensic transcript capture (opt-in). If an operator armed a capture for
    // this VM, fan the forwarded frames into its sink; `None` (the common case)
    // costs nothing. The two directions share the sink behind an async mutex.
    let capture_roots = transcript_capture_roots.unwrap_or_else(|| TranscriptCaptureRoots {
        transcripts_dir: mvm_core::config::mvm_transcripts_dir(),
        keys_dir: mvm_core::config::mvm_keys_dir(),
    });
    let capture = crate::supervisor::transcript_sink::TranscriptCaptureSink::open_for_vm(
        &capture_roots.transcripts_dir,
        &capture_roots.keys_dir,
        &tenant,
        &vm_name,
    )
    .ok()
    .flatten()
    .map(|s| std::sync::Arc::new(tokio::sync::Mutex::new(Some(s))));
    let cap_e = capture.clone();
    let cap_i = capture.clone();

    // Egress: guest → internet. Read framed from b, observe, write to a.
    let egress = async {
        loop {
            let frame = match read_one_frame(&mut b_rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !egress_opened {
                match policy.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Egress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                }) {
                    FlowAction::Allow => {
                        let _ = event_tx
                            .send(FlowEvent {
                                flow_id: flow_egress.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        egress_opened = true;
                    }
                    FlowAction::Drop { reason } => {
                        let _ = event_tx
                            .send(FlowEvent {
                                flow_id: flow_egress.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        tracing::info!(flow_id = %flow_egress, reason = %reason.0, "egress flow dropped by FlowPolicy");
                        return Ok(());
                    }
                }
            }
            if flow_is_killed(&killed_flows, &frame).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name,
                tenant: &tenant,
                direction: FlowDirection::Egress,
                flow_id: &flow_egress,
            };
            match run_packet_pipeline(
                &observers,
                substitution.as_ref(),
                scan.as_ref(),
                ctx,
                &frame,
                mtu,
                &latency,
            ) {
                PacketDecision::Forward { frame: out, .. } => {
                    if let Some(cap) = &cap_e
                        && let Some(sink) = cap.lock().await.as_mut()
                    {
                        let _ = sink.push(mvm_core::transcript::Direction::Egress, &out);
                    }
                    write_one_frame(&mut a_wr, &out).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    // Forensic capture records the denied frame (the original,
                    // un-forwarded bytes) flagged dropped, so an armed transcript
                    // shows attempted-but-blocked egress, not only allowed traffic.
                    if let Some(cap) = &cap_e
                        && let Some(sink) = cap.lock().await.as_mut()
                    {
                        let _ = sink.push_dropped(mvm_core::transcript::Direction::Egress, &frame);
                    }
                    if let Some(k) = flow_key {
                        killed_flows.lock().await.insert(k);
                    }
                    let _ = event_tx
                        .send(FlowEvent {
                            flow_id: flow_egress.clone(),
                            direction: FlowDirection::Egress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency.write_scrape_file();
        }
        Ok(())
    };

    // Ingress: internet → guest. Read framed from a, observe, write to b.
    let ingress = async {
        loop {
            let frame = match read_one_frame(&mut a_rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !ingress_opened {
                match policy.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Ingress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                }) {
                    FlowAction::Allow => {
                        let _ = event_tx
                            .send(FlowEvent {
                                flow_id: flow_ingress.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        ingress_opened = true;
                    }
                    FlowAction::Drop { reason } => {
                        let _ = event_tx
                            .send(FlowEvent {
                                flow_id: flow_ingress.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        tracing::info!(flow_id = %flow_ingress, reason = %reason.0, "ingress flow dropped by FlowPolicy");
                        return Ok(());
                    }
                }
            }
            if flow_is_killed(&killed_flows, &frame).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name,
                tenant: &tenant,
                direction: FlowDirection::Ingress,
                flow_id: &flow_ingress,
            };
            match run_packet_pipeline(
                &observers,
                substitution.as_ref(),
                scan.as_ref(),
                ctx,
                &frame,
                mtu,
                &latency,
            ) {
                PacketDecision::Forward { frame: out, .. } => {
                    if let Some(cap) = &cap_i
                        && let Some(sink) = cap.lock().await.as_mut()
                    {
                        let _ = sink.push(mvm_core::transcript::Direction::Ingress, &out);
                    }
                    write_one_frame(&mut b_wr, &out).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    // Capture the denied ingress frame (flagged dropped) too.
                    if let Some(cap) = &cap_i
                        && let Some(sink) = cap.lock().await.as_mut()
                    {
                        let _ = sink.push_dropped(mvm_core::transcript::Direction::Ingress, &frame);
                    }
                    if let Some(k) = flow_key {
                        killed_flows.lock().await.insert(k);
                    }
                    let _ = event_tx
                        .send(FlowEvent {
                            flow_id: flow_ingress.clone(),
                            direction: FlowDirection::Ingress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency.write_scrape_file();
        }
        Ok(())
    };

    let result = tokio::try_join!(egress, ingress);

    // Seal an armed transcript capture on teardown so the operator CLI can
    // list/export it, and record the seal in the local audit log.
    if let Some(cap) = capture
        && let Some(sink) = cap.lock().await.take()
    {
        match sink.seal() {
            Ok(manifest) => {
                if let Err(error) = event_tx
                    .send_transcript_sealed(TranscriptSealedEvent {
                        capture_id: manifest.capture_id.clone(),
                        vm_name: vm_name.clone(),
                        sealed_root_hex: manifest.sealed_root_hex.clone(),
                        chunk_count: manifest.chunks.len(),
                    })
                    .await
                {
                    tracing::warn!(
                        capture_id = %manifest.capture_id,
                        %error,
                        "transcript seal could not reach the audit signer"
                    );
                }
                mvm_core::audit_emit!(
                    TranscriptSealed,
                    vm: &vm_name,
                    "tenant={tenant} vm={vm_name} capture={} chunks={} root={}",
                    manifest.capture_id,
                    manifest.chunks.len(),
                    manifest.sealed_root_hex
                );
            }
            Err(e) => {
                tracing::warn!(vm = %vm_name, error = %e, "transcript capture seal failed")
            }
        }
    }

    // Emit close events for any direction that opened. EOF on a
    // direction = Eof reason; I/O error = BridgeError.
    let (egress_reason, ingress_reason) = match result {
        Ok(_) => (FlowCloseReason::Eof, FlowCloseReason::Eof),
        Err(_) => (FlowCloseReason::BridgeError, FlowCloseReason::BridgeError),
    };
    if egress_opened {
        let _ = event_tx
            .send(FlowEvent {
                flow_id: flow_egress,
                direction: FlowDirection::Egress,
                kind: FlowEventKind::Closed {
                    reason: egress_reason,
                },
            })
            .await;
    }
    if ingress_opened {
        let _ = event_tx
            .send(FlowEvent {
                flow_id: flow_ingress,
                direction: FlowDirection::Ingress,
                kind: FlowEventKind::Closed {
                    reason: ingress_reason,
                },
            })
            .await;
    }
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::super::events::{GatewayAuditEvent, audit_event_channel};
    use super::super::test_support::*;
    use super::*;

    // -----------------------------------------------------------------
    // Passt bridge: end-to-end via socketpair
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn read_write_one_frame_roundtrips_through_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let frame = tcp_egress_frame(b"payload-bytes");
        write_one_frame(&mut client, &frame).await.unwrap();
        let got = read_one_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(got, frame);
        // Clean EOF at a frame boundary returns None.
        drop(client);
        assert!(read_one_frame(&mut server).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passt_bridge_emits_open_close_pair_on_framed_traffic() {
        use std::os::unix::net::UnixStream as StdUs;

        // pair_a: (gateway_a, gateway_b=passt); pair_b: (guest_a, guest_b=libkrun).
        // The bridge holds gateway_a (a, faces passt) + guest_a (b, faces guest).
        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        for s in [&gateway_a, &gateway_b, &guest_a, &guest_b] {
            s.set_nonblocking(true).unwrap();
        }
        let supervisor_gateway = tokio::net::UnixStream::from_std(gateway_a).unwrap();
        let supervisor_guest = tokio::net::UnixStream::from_std(guest_a).unwrap();
        let mut passt = tokio::net::UnixStream::from_std(gateway_b).unwrap();
        let mut libkrun = tokio::net::UnixStream::from_std(guest_b).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        let bridge_task = tokio::spawn(bridge_copy_bidirectional(
            supervisor_gateway,
            supervisor_guest,
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![]),
        ));

        // passt → guest = ingress. Frame must round-trip byte-identically.
        let f1 = tcp_egress_frame(b"from-passt");
        write_one_frame(&mut passt, &f1).await.unwrap();
        let got = read_one_frame(&mut libkrun).await.unwrap().unwrap();
        assert_eq!(got, f1);
        let ev1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("open in time")
            .expect("event")
            .into_flow()
            .expect("bridge emits a flow event");
        assert!(matches!(ev1.kind, FlowEventKind::Opened));
        assert_eq!(ev1.direction, FlowDirection::Ingress);

        // guest → passt = egress.
        let f2 = tcp_egress_frame(b"from-guest");
        write_one_frame(&mut libkrun, &f2).await.unwrap();
        let got = read_one_frame(&mut passt).await.unwrap().unwrap();
        assert_eq!(got, f2);
        let ev2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("second open in time")
            .expect("event")
            .into_flow()
            .expect("bridge emits a flow event");
        assert!(matches!(ev2.kind, FlowEventKind::Opened));
        assert_ne!(ev1.direction, ev2.direction);

        drop(passt);
        drop(libkrun);
        let c1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("close")
            .expect("event")
            .into_flow()
            .expect("bridge emits a flow event");
        let c2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("second close")
            .expect("event")
            .into_flow()
            .expect("bridge emits a flow event");
        assert!(matches!(c1.kind, FlowEventKind::Closed { .. }));
        assert!(matches!(c2.kind, FlowEventKind::Closed { .. }));
        bridge_task
            .await
            .expect("bridge task joins cleanly")
            .expect("bridge copy succeeds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn armed_capture_records_forwarded_frames_and_export_round_trips() {
        use std::os::unix::net::UnixStream as StdUs;

        let tmp = tempfile::tempdir().unwrap();
        let capture_roots = TranscriptCaptureRoots {
            transcripts_dir: tmp.path().join("audit").join("transcripts"),
            keys_dir: tmp.path().join("keys"),
        };

        // Arm a capture for tenant "t" / vm "vm-test", the way the operator CLI
        // does: a sealed-but-empty manifest with the data key wrapped under KEK.
        let cap_dir = capture_roots.transcripts_dir.join("t").join("cap-test");
        std::fs::create_dir_all(&cap_dir).unwrap();
        let kek = mvm_core::transcript::load_or_init_kek(&capture_roots.keys_dir).unwrap();
        let data_key = mvm_core::crypto::aead::Key::random();
        let cfg = mvm_core::transcript::TranscriptWriterConfig {
            capture_id: "cap-test".into(),
            binding: mvm_core::transcript::CaptureBinding {
                tenant_id: "t".into(),
                vm_name: "vm-test".into(),
                session_id: None,
            },
            bounds: mvm_core::transcript::CaptureBounds {
                max_duration_secs: 60,
                max_bytes: 1 << 20,
                max_chunks: 64,
            },
            retention: mvm_core::transcript::RetentionPolicy::FailClosed,
            created_unix_secs: 1_700_000_000,
            recipient: "transcript-kek".into(),
            wrapped_data_key_b64: mvm_core::transcript::wrap_data_key(&kek, &data_key),
        };
        let armed = mvm_core::transcript::TranscriptWriter::new(&cap_dir, data_key, cfg).seal();
        std::fs::write(
            cap_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&armed).unwrap(),
        )
        .unwrap();

        // Drive the bridge for that VM.
        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        for s in [&gateway_a, &gateway_b, &guest_a, &guest_b] {
            s.set_nonblocking(true).unwrap();
        }
        let supervisor_gateway = tokio::net::UnixStream::from_std(gateway_a).unwrap();
        let supervisor_guest = tokio::net::UnixStream::from_std(guest_a).unwrap();
        let mut passt = tokio::net::UnixStream::from_std(gateway_b).unwrap();
        let mut libkrun = tokio::net::UnixStream::from_std(guest_b).unwrap();

        let (tx, mut rx) = audit_event_channel(64);
        let bridge_task = tokio::spawn(bridge_copy_bidirectional(
            supervisor_gateway,
            supervisor_guest,
            "vm-test".to_string(),
            "t".to_string(),
            unrestricted_flow_policy(),
            tx,
            ObserverWiring {
                transcript_capture_roots: Some(capture_roots.clone()),
                ..wiring_with(vec![])
            },
        ));

        // guest → passt = egress; the forwarded frame must be captured.
        let frame = tcp_egress_frame(b"capture-me");
        write_one_frame(&mut libkrun, &frame).await.unwrap();
        let got = read_one_frame(&mut passt).await.unwrap().unwrap();
        assert_eq!(got, frame);

        // Teardown seals the manifest.
        drop(passt);
        drop(libkrun);
        let _ = bridge_task.await;

        // The sealed manifest carries the forwarded frame; operator export
        // verifies + decrypts it back byte-for-byte.
        let raw = std::fs::read(cap_dir.join("manifest.json")).unwrap();
        let manifest: mvm_core::transcript::TranscriptManifest =
            serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            manifest.chunks.len(),
            1,
            "the forwarded egress frame was captured + sealed"
        );
        let data_key =
            mvm_core::transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let out = mvm_core::transcript::export(&manifest, &cap_dir, &data_key).unwrap();
        assert_eq!(out, frame, "export round-trips the captured frame bytes");

        let sealed = std::iter::from_fn(|| rx.try_recv().ok()).find_map(|event| match event {
            GatewayAuditEvent::TranscriptSealed(sealed) => Some(sealed),
            GatewayAuditEvent::Flow(_) => None,
        });
        let sealed = sealed.expect("bridge queues the transcript seal for chain signing");
        assert_eq!(sealed.capture_id, manifest.capture_id);
        assert_eq!(sealed.vm_name, manifest.binding.vm_name);
        assert_eq!(sealed.sealed_root_hex, manifest.sealed_root_hex);
        assert_eq!(sealed.chunk_count, manifest.chunks.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passt_bridge_redacts_egress_frame() {
        use std::os::unix::net::UnixStream as StdUs;

        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        for s in [&gateway_a, &gateway_b, &guest_a, &guest_b] {
            s.set_nonblocking(true).unwrap();
        }
        let supervisor_gateway = tokio::net::UnixStream::from_std(gateway_a).unwrap();
        let supervisor_guest = tokio::net::UnixStream::from_std(guest_a).unwrap();
        let mut passt = tokio::net::UnixStream::from_std(gateway_b).unwrap();
        let mut libkrun = tokio::net::UnixStream::from_std(guest_b).unwrap();

        let (tx, _rx) = audit_event_channel(64);
        let policy = unrestricted_flow_policy();
        let bridge_task = tokio::spawn(bridge_copy_bidirectional(
            supervisor_gateway,
            supervisor_guest,
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(RedactorObs)]),
        ));

        // guest → internet = egress; RedactorObs redacts SECRET on this path.
        write_one_frame(&mut libkrun, &tcp_egress_frame(b"hello-SECRET-bye"))
            .await
            .unwrap();
        let out = read_one_frame(&mut passt).await.unwrap().unwrap();
        let parsed = crate::supervisor::network::packet::parse(&out).expect("re-parses");
        assert!(parsed.l4_payload.windows(6).any(|w| w == b"XXXXXX"));
        assert!(!parsed.l4_payload.windows(6).any(|w| w == b"SECRET"));
        bridge_task.abort();
    }
}
