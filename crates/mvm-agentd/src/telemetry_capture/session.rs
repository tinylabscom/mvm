//! The capture session: one authenticated connection draining the shared
//! outbox to the host, with the session plane's own records on the
//! transport's direct path.
//!
//! The serve half in `telemetry_service` authenticates and announces; this
//! module is what a capture-wired agent serves instead: announce under the
//! process-wide epoch, then alternate between draining queued records and
//! summarizing per-producer losses, on a timed cadence with no producer-side
//! wakeup. The announcement and the loss summaries never ride the data
//! queue — a saturated queue must still be able to say it is losing records —
//! so they are prepared directly and sent on the reserved path.
//!
//! The session is one-way after the handshake, so peer death cannot wait
//! for the next write: an idle host session would linger forever and — the
//! listener serving one session at a time — block every later dial. Each
//! tick therefore probes the stream with one read, which the caller must
//! bound with a read timeout (the tests set one on their socket pair; the
//! agent's accept path sets one on the accepted connection): end-of-file is
//! the peer gone, a timeout is the peer alive. Producer teardown never
//! joins or flushes this loop.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::net::telemetry::TelemetrySender;
use mvm_core::protocol::telemetry::{
    CoverageState, GuestLossStage, LossReason, RecordBody, SourceKind, TailState,
};

use super::state::{CaptureState, ProducerId, SourceLosses};
use crate::telemetry_service::{AGENT_COVERAGE_CODE, SessionEnd};

/// How often the drain loop wakes to look for queued records and loss
/// deltas. Producers never notify — the offer budget forbids it — so this
/// cadence is the delivery latency ceiling, and telemetry tolerates it.
const DRAIN_INTERVAL: Duration = Duration::from_millis(25);

/// How often accumulated losses are summarized to the host, in drain ticks.
/// Coarser than the drain so a steady shed does not halve the session's
/// bandwidth with summaries about itself.
const SUMMARY_EVERY_TICKS: u32 = 40;

/// Serve one capture session over an accepted, peer-gated stream: announce
/// coverage under the shared epoch, then drain records and summarize losses
/// until the peer dies, the queue closes, or `stop` is set.
///
/// `bound_reads` runs once, after the handshake succeeds and before the
/// first probe: the caller installs its read timeout there. Installing it
/// earlier races the handshake — a peer thread scheduled late makes the
/// handshake read time out and the session fail spuriously, stranding a
/// test (or a collector) that then blocks on the half-open socket — so
/// handshake reads stay patient and only the probes are bounded.
pub fn serve_capture_session<S: Read + Write>(
    stream: &mut S,
    signing_key: SigningKey,
    host_anchor: &VerifyingKey,
    capture: &CaptureState,
    stop: &AtomicBool,
    bound_reads: impl FnOnce(&mut S),
) -> SessionEnd {
    let mut sender = match TelemetrySender::connect(stream, signing_key, host_anchor) {
        Ok(sender) => sender,
        Err(_) => return SessionEnd::Failed,
    };
    bound_reads(stream);
    let announced = capture.prepare_direct(
        SourceKind::GuestAgent,
        ProducerId::AgentDiagnostics,
        RecordBody::Coverage {
            state: CoverageState::Started,
            code: match AGENT_COVERAGE_CODE.try_into() {
                Ok(code) => code,
                Err(_) => return SessionEnd::Failed,
            },
        },
    );
    let Some(announced) = announced else {
        return SessionEnd::Failed;
    };
    if sender.send_prepared(stream, &announced).is_err() {
        return SessionEnd::Failed;
    }

    let mut summarized = SourceLosses::default();
    let mut ticks = 0u32;
    loop {
        if stop.load(Ordering::Acquire) {
            return SessionEnd::PeerClosed;
        }
        loop {
            match sender.send_next(stream, capture.outbox()) {
                Ok(true) => continue,
                Ok(false) => break,
                Err(_) => return SessionEnd::Failed,
            }
        }
        ticks += 1;
        if ticks.is_multiple_of(SUMMARY_EVERY_TICKS)
            && summarize_losses(stream, &mut sender, capture, &mut summarized).is_err()
        {
            return SessionEnd::Failed;
        }
        match probe_peer(stream) {
            PeerProbe::Alive => {}
            PeerProbe::Closed => return SessionEnd::PeerClosed,
            PeerProbe::Broken => return SessionEnd::Failed,
        }
        std::thread::sleep(DRAIN_INTERVAL);
    }
}

enum PeerProbe {
    Alive,
    Closed,
    Broken,
}

/// One bounded read against a one-way peer: EOF is a clean close, a timeout
/// is life, unexpected bytes are ignored (the host never speaks after its
/// handshake ack, but tolerating noise beats failing collection over it).
fn probe_peer<S: Read + Write>(stream: &mut S) -> PeerProbe {
    let mut probe = [0u8; 8];
    match stream.read(&mut probe) {
        Ok(0) => PeerProbe::Closed,
        Ok(_) => PeerProbe::Alive,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ) =>
        {
            PeerProbe::Alive
        }
        Err(_) => PeerProbe::Broken,
    }
}

/// Send one Loss record per loss family that grew since the last summary,
/// on the direct path. The snapshot advances only for what was sent, so a
/// failed send re-reports the same delta on the next session.
fn summarize_losses<S: Read + Write>(
    stream: &mut S,
    sender: &mut TelemetrySender,
    capture: &CaptureState,
    summarized: &mut SourceLosses,
) -> Result<(), ()> {
    let current = capture.losses(ProducerId::AgentDiagnostics);
    // Contention is admission pressure like capacity — the wire reason
    // merges them, and the per-producer counters keep the finer split.
    let capacity_records = current.capacity.records + current.contention.records;
    let capacity_bytes = current.capacity.bytes + current.contention.bytes;
    let sent_capacity_records = summarized.capacity.records + summarized.contention.records;
    let sent_capacity_bytes = summarized.capacity.bytes + summarized.contention.bytes;
    let rows = [
        (
            LossReason::Capacity,
            capacity_records.saturating_sub(sent_capacity_records),
            capacity_bytes.saturating_sub(sent_capacity_bytes),
        ),
        (
            LossReason::Unavailable,
            current
                .unavailable
                .records
                .saturating_sub(summarized.unavailable.records),
            current
                .unavailable
                .bytes
                .saturating_sub(summarized.unavailable.bytes),
        ),
        (
            LossReason::Rejected,
            current
                .rejected
                .records
                .saturating_sub(summarized.rejected.records),
            current
                .rejected
                .bytes
                .saturating_sub(summarized.rejected.bytes),
        ),
        (
            LossReason::Truncated,
            current
                .truncated
                .records
                .saturating_sub(summarized.truncated.records),
            current
                .truncated
                .bytes
                .saturating_sub(summarized.truncated.bytes),
        ),
    ];
    for (reason, records, bytes) in rows {
        if records == 0 && bytes == 0 {
            continue;
        }
        let Some(prepared) = capture.prepare_direct(
            SourceKind::GuestAgent,
            ProducerId::AgentDiagnostics,
            RecordBody::Loss {
                stage: GuestLossStage::Capture,
                reason,
                records,
                bytes,
                tail: TailState::Known,
            },
        ) else {
            // An unbuildable summary is itself counted; report it next round.
            continue;
        };
        sender.send_prepared(stream, &prepared).map_err(|_| ())?;
        advance_sent(summarized, &current, reason);
    }
    Ok(())
}

/// Advance the sent snapshot for the families a summary row covered.
fn advance_sent(summarized: &mut SourceLosses, current: &SourceLosses, reason: LossReason) {
    match reason {
        LossReason::Capacity => {
            summarized.capacity = current.capacity;
            summarized.contention = current.contention;
        }
        LossReason::Unavailable => summarized.unavailable = current.unavailable,
        LossReason::Rejected => summarized.rejected = current.rejected,
        LossReason::Truncated => summarized.truncated = current.truncated,
        LossReason::Filtered | LossReason::Sampled => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use mvm_core::net::telemetry::outbox::Outbox;
    use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
    use mvm_core::protocol::telemetry::{Attributes, Level, MAX_RECORD_BYTES, TelemetryRecord};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
        )
    }

    /// The probe contract: reads become bounded only after the handshake,
    /// via the serve hook — earlier would race a slow peer thread.
    fn bound(stream: &mut UnixStream) {
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
    }

    fn capture_over(records: usize) -> CaptureState {
        let outbox = Arc::new(Outbox::new(records, records * MAX_RECORD_BYTES).unwrap());
        CaptureState::new(outbox).unwrap()
    }

    fn diagnostic(capture: &CaptureState, name: &str) {
        capture.emit(
            SourceKind::GuestAgent,
            ProducerId::AgentDiagnostics,
            RecordBody::Event {
                context: None,
                level: Level::Info,
                name: name.try_into().unwrap(),
                attributes: Attributes::default(),
            },
        );
    }

    /// Host side: authenticate, receive until the guest half is released,
    /// return everything received.
    fn host_receives(
        mut stream: UnixStream,
        anchor_key: SigningKey,
        expected_guest: VerifyingKey,
        until: usize,
    ) -> std::thread::JoinHandle<Vec<TelemetryRecord>> {
        std::thread::spawn(move || {
            let anchor = anchor_key.verifying_key();
            let mut receiver =
                TelemetryReceiver::connect_with_signer(&mut stream, &anchor, &expected_guest, {
                    let signer = anchor_key.clone();
                    move |hello, ack| {
                        let bytes = handshake_signing_bytes(hello, ack, &signer.verifying_key())
                            .map_err(|_| {
                                mvm_core::net::session::SessionError::InvalidHandshake(
                                    "bad handshake".into(),
                                )
                            })?;
                        Ok(signer.sign(&bytes))
                    }
                })
                .expect("host authenticates");
            let mut received = Vec::new();
            while received.len() < until {
                match receiver.receive(&mut stream) {
                    Ok(record) => received.push(record),
                    Err(_) => break,
                }
            }
            drop(stream);
            received
        })
    }

    #[test]
    fn records_emitted_before_connect_are_delivered_after_the_announcement() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(8);
        diagnostic(&capture, "before-one");
        diagnostic(&capture, "before-two");

        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_receives(host, anchor_key.clone(), guest_key.verifying_key(), 3);
        let stop = AtomicBool::new(false);
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bound,
        );
        // The host closes after three records; the idle probe observes it
        // without any further write.
        assert_eq!(end, SessionEnd::PeerClosed);
        let received = collector.join().unwrap();
        assert!(matches!(
            received[0].body(),
            RecordBody::Coverage {
                state: CoverageState::Started,
                ..
            }
        ));
        let names: Vec<_> = received[1..]
            .iter()
            .map(|r| match r.body() {
                RecordBody::Event { name, .. } => name.as_str().to_string(),
                other => panic!("expected events, got {other:?}"),
            })
            .collect();
        assert_eq!(names, ["before-one", "before-two"]);
        // Everything rode the shared epoch: announcement and backlog alike.
        assert!(received.iter().all(|r| r.epoch() == received[0].epoch()));
    }

    #[test]
    fn shed_evidence_reaches_the_host_as_a_capacity_loss_summary() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(1);
        diagnostic(&capture, "kept");
        for _ in 0..3 {
            diagnostic(&capture, "shed");
        }

        let (mut guest, host) = UnixStream::pair().unwrap();
        // Announcement + the kept record + one loss summary.
        let collector = host_receives(host, anchor_key.clone(), guest_key.verifying_key(), 3);
        let stop = AtomicBool::new(false);
        serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bound,
        );
        let received = collector.join().unwrap();
        let loss = received
            .iter()
            .find_map(|r| match *r.body() {
                RecordBody::Loss {
                    reason, records, ..
                } => Some((reason, records)),
                _ => None,
            })
            .expect("a loss summary crossed");
        assert_eq!(loss, (LossReason::Capacity, 3));
    }

    #[test]
    fn a_second_session_restates_the_same_epoch_and_reports_no_stale_losses() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(1);
        diagnostic(&capture, "kept");
        diagnostic(&capture, "shed");

        let stop = AtomicBool::new(false);
        let mut epochs = Vec::new();
        for expected in [3usize, 1] {
            let (mut guest, host) = UnixStream::pair().unwrap();
            let collector = host_receives(
                host,
                anchor_key.clone(),
                guest_key.verifying_key(),
                expected,
            );
            serve_capture_session(
                &mut guest,
                guest_key.clone(),
                &anchor_key.verifying_key(),
                &capture,
                &stop,
                bound,
            );
            let received = collector.join().unwrap();
            epochs.push(received[0].epoch());
            let summaries = received
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Loss { .. }))
                .count();
            // First session: backlog + its loss summary. Second: only the
            // fresh announcement — the sent snapshot survives the session.
            if expected == 3 {
                assert_eq!(summaries, 1);
            } else {
                assert_eq!(summaries, 0);
            }
        }
        assert_eq!(epochs[0], epochs[1], "sessions restate, never remint");
    }

    #[test]
    fn stop_ends_an_idle_session_within_its_cadence() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(1);
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_receives(host, anchor_key.clone(), guest_key.verifying_key(), 1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(120));
                stop.store(true, Ordering::Release);
            })
        };
        let started = std::time::Instant::now();
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bound,
        );
        assert_eq!(end, SessionEnd::PeerClosed);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(guest);
        stopper.join().unwrap();
        let _ = collector.join();
    }

    #[test]
    fn a_dead_peer_fails_the_session_at_the_next_send() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(4);
        let (mut guest, host) = UnixStream::pair().unwrap();
        drop(host);
        let stop = AtomicBool::new(false);
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bound,
        );
        assert_eq!(end, SessionEnd::Failed);
    }
}
