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
//! Every wait in a session is bounded, because the listener serves one
//! session at a time and a pinned session would silence the plane for the
//! rest of the boot:
//!
//! - The handshake runs under one overall deadline. A host that connects and
//!   then says nothing is dropped, not waited on.
//! - Each sealed frame is written under its own deadline. Writes never block
//!   in the kernel: each writes what fits, then waits for room only for the
//!   time left, so a host that reads a byte at a time cannot stretch one
//!   frame past its deadline on any platform. A stalled host fails the
//!   session; the record in flight is counted as a transport loss.
//! - A turn sends at most [`RECORDS_PER_TURN`] records, so under a
//!   continuous flood the loop still reaches its stop check and its loss
//!   summaries between turns instead of draining forever.
//!
//! The session is one-way after the handshake, so an idle host's death
//! cannot wait for the next write: each idle turn probes the stream with one
//! read under a short timeout. End-of-file is the peer gone, a timeout is
//! the peer alive. Under load the probe is skipped, because the next write
//! observes a dead peer anyway. Producer teardown never joins or flushes
//! this loop, and nothing here makes a producer wait.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::net::telemetry::TelemetrySender;
use mvm_core::protocol::telemetry::{
    CoverageState, GuestLossStage, LossReason, RecordBody, SourceKind, TailState,
};

use super::state::{CaptureState, ProducerId, SourceLosses};
use crate::telemetry_service::{AGENT_COVERAGE_CODE, SessionEnd};

/// How long the loop waits between turns once the queue is empty.
/// Producers never notify — the offer budget forbids it — so this cadence
/// is the delivery latency ceiling, and telemetry tolerates it.
const DRAIN_INTERVAL: Duration = Duration::from_millis(25);

/// How often accumulated losses are summarized to the host. Measured in
/// time, not turns, so a flood that shortens turns does not turn the
/// session's bandwidth into summaries about itself.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(1);

/// The most records one turn sends before the loop checks stop, summarizes
/// and starts the next turn. Half the agent's capture queue: a flood cannot
/// keep the loop away from its housekeeping for more than one bounded batch.
pub const RECORDS_PER_TURN: usize = 64;

/// Time limits a session applies to its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDeadlines {
    /// The whole authenticated handshake must finish within this.
    pub handshake: Duration,
    /// Read timeout for the idle liveness probe after the handshake.
    pub probe: Duration,
    /// Writing one sealed frame must finish within this.
    pub write: Duration,
}

impl SessionDeadlines {
    /// The guest agent's limits. The handshake allowance is generous because
    /// a slow host is normal at boot; a write allowance of two seconds is far
    /// above a healthy frame's microseconds and far below "forever".
    pub const AGENT: Self = Self {
        handshake: Duration::from_secs(5),
        probe: Duration::from_millis(25),
        write: Duration::from_secs(2),
    };
}

/// A stream whose kernel read and write timeouts the session can set.
pub trait TimedStream: Read + Write {
    /// Set the per-call receive and send timeouts. A stream that refuses
    /// either cannot be served with bounded waits, and the session refuses
    /// it rather than serving it unbounded.
    fn set_timeouts(&mut self, read: Duration, write: Duration) -> io::Result<()>;

    /// Write what fits now without waiting: `WouldBlock` when nothing does.
    fn write_now(&mut self, buf: &[u8]) -> io::Result<usize>;

    /// Wait at most `timeout` for room to write. `Ok` on room or timeout
    /// alike; the caller's deadline decides which it was.
    fn wait_writable(&mut self, timeout: Duration) -> io::Result<()>;
}

impl<T: Read + Write + AsRawFd> TimedStream for T {
    fn set_timeouts(&mut self, read: Duration, write: Duration) -> io::Result<()> {
        let fd = self.as_raw_fd();
        set_socket_timeout(fd, libc::SO_RCVTIMEO, read)?;
        set_socket_timeout(fd, libc::SO_SNDTIMEO, write)
    }

    fn write_now(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Non-blocking for this one call. `MSG_DONTWAIT` would be simpler,
        // but macOS ignores it on Unix-domain streams and blocks anyway.
        let fd = self.as_raw_fd();
        // SAFETY: `fd` is borrowed from a live stream for the duration of
        // these calls; F_GETFL/F_SETFL take and return plain flag words.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let written = self.write(buf);
        // SAFETY: as above; restores the flags read before the write.
        let restored = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        if restored < 0 {
            return Err(io::Error::last_os_error());
        }
        written
    }

    fn wait_writable(&mut self, timeout: Duration) -> io::Result<()> {
        let millis = libc::c_int::try_from(timeout.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        let mut fds = [libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        }];
        // SAFETY: one live pollfd, its length passed alongside.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, millis) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }
}

fn set_socket_timeout(fd: i32, option: libc::c_int, timeout: Duration) -> io::Result<()> {
    // A zero timeval means "no timeout" to the kernel; never pass one.
    let timeout = timeout.max(Duration::from_millis(1));
    let value = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    // SAFETY: `fd` is borrowed from a live stream for the duration of the
    // call; the timeval is a local of exactly the size passed.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &value as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Enforces one wall-clock deadline across every call on the wrapped stream.
/// The socket timeouts bound each call; this bounds their sum.
struct Deadline<'a, S> {
    inner: &'a mut S,
    until: Instant,
}

impl<'a, S> Deadline<'a, S> {
    fn new(inner: &'a mut S, allowance: Duration) -> Self {
        Self {
            inner,
            until: Instant::now() + allowance,
        }
    }

    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.until {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "telemetry session deadline",
            ))
        } else {
            Ok(())
        }
    }
}

impl<S: Read> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.read(buf)
    }
}

impl<S: TimedStream> Write for Deadline<'_, S> {
    /// Never a blocking write: the kernel's send timeout restarts on every
    /// wakeup on some platforms, so a host draining a byte at a time could
    /// hold one blocking call open indefinitely. Instead, write what fits
    /// now, and wait for room only for the time left before the deadline.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.inner.write_now(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let left = self.until.saturating_duration_since(Instant::now());
                    self.inner.wait_writable(left)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}

/// Serve one capture session over an accepted, peer-gated stream: announce
/// coverage under the shared epoch, then drain records and summarize losses
/// until the peer dies, the queue closes, a deadline passes, or `stop` is
/// set.
pub fn serve_capture_session<S: TimedStream>(
    stream: &mut S,
    signing_key: SigningKey,
    host_anchor: &VerifyingKey,
    capture: &CaptureState,
    stop: &AtomicBool,
    deadlines: SessionDeadlines,
) -> SessionEnd {
    if stream
        .set_timeouts(deadlines.handshake, deadlines.handshake)
        .is_err()
    {
        return SessionEnd::Failed;
    }
    let connected = {
        let mut bounded = Deadline::new(stream, deadlines.handshake);
        TelemetrySender::connect(&mut bounded, signing_key, host_anchor)
    };
    let Ok(mut sender) = connected else {
        return SessionEnd::Failed;
    };
    if stream
        .set_timeouts(deadlines.probe, deadlines.write)
        .is_err()
    {
        return SessionEnd::Failed;
    }
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
    if sender
        .send_prepared(&mut Deadline::new(stream, deadlines.write), &announced)
        .is_err()
    {
        return SessionEnd::Failed;
    }

    let mut summarized = [SourceLosses::default(); ProducerId::ALL.len()];
    let mut last_summary = Instant::now();
    loop {
        if stop.load(Ordering::Acquire) {
            return SessionEnd::PeerClosed;
        }
        let Ok(sent) = drain_turn(stream, &mut sender, capture, deadlines.write) else {
            return SessionEnd::Failed;
        };
        if last_summary.elapsed() >= SUMMARY_INTERVAL {
            if summarize_losses(
                stream,
                &mut sender,
                capture,
                &mut summarized,
                deadlines.write,
            )
            .is_err()
            {
                return SessionEnd::Failed;
            }
            last_summary = Instant::now();
        }
        if sent == RECORDS_PER_TURN {
            // More is probably queued: take the next turn straight away.
            continue;
        }
        match probe_peer(stream) {
            PeerProbe::Alive => {}
            PeerProbe::Closed => return SessionEnd::PeerClosed,
            PeerProbe::Broken => return SessionEnd::Failed,
        }
        std::thread::sleep(DRAIN_INTERVAL);
    }
}

/// Send up to [`RECORDS_PER_TURN`] queued records, each under its own write
/// deadline. Returns how many were sent; fewer than the cap means the queue
/// ran empty.
fn drain_turn<S: TimedStream>(
    stream: &mut S,
    sender: &mut TelemetrySender,
    capture: &CaptureState,
    write: Duration,
) -> Result<usize, ()> {
    // One record from each queue in turn, so a producer flooding its own
    // queue cannot keep another's records waiting for a later turn.
    let queues = capture.queues();
    let mut drained = vec![false; queues.len()];
    let mut sent = 0;
    while sent < RECORDS_PER_TURN && drained.iter().any(|done| !done) {
        for (queue, done) in queues.iter().zip(drained.iter_mut()) {
            if *done || sent == RECORDS_PER_TURN {
                continue;
            }
            match sender.send_next(&mut Deadline::new(stream, write), queue) {
                Ok(true) => sent += 1,
                Ok(false) => *done = true,
                Err(_) => return Err(()),
            }
        }
    }
    Ok(sent)
}

enum PeerProbe {
    Alive,
    Closed,
    Broken,
}

/// One bounded read against a one-way peer: EOF is a clean close, a timeout
/// is life, unexpected bytes are ignored (the host never speaks after its
/// handshake ack, but tolerating noise beats failing collection over it).
fn probe_peer<S: Read>(stream: &mut S) -> PeerProbe {
    let mut probe = [0u8; 8];
    match stream.read(&mut probe) {
        Ok(0) => PeerProbe::Closed,
        Ok(_) => PeerProbe::Alive,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
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
fn summarize_losses<S: TimedStream>(
    stream: &mut S,
    sender: &mut TelemetrySender,
    capture: &CaptureState,
    summarized: &mut [SourceLosses; ProducerId::ALL.len()],
    write: Duration,
) -> Result<(), ()> {
    // Every producer's losses, each under its own producer, so a source that
    // sheds — a workload flooding stdout, say — is reported, never silent.
    for (producer, summarized) in ProducerId::ALL.into_iter().zip(summarized.iter_mut()) {
        summarize_producer(stream, sender, capture, producer, summarized, write)?;
    }
    Ok(())
}

/// Send one Loss record per loss family that grew since `producer`'s last
/// summary.
fn summarize_producer<S: TimedStream>(
    stream: &mut S,
    sender: &mut TelemetrySender,
    capture: &CaptureState,
    producer: ProducerId,
    summarized: &mut SourceLosses,
    write: Duration,
) -> Result<(), ()> {
    let current = capture.losses(producer);
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
            producer.default_source(),
            producer,
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
        sender
            .send_prepared(&mut Deadline::new(stream, write), &prepared)
            .map_err(|_| ())?;
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

    /// Short probe so idle tests observe a closed host quickly.
    const BOUNDS: SessionDeadlines = SessionDeadlines {
        handshake: Duration::from_secs(5),
        probe: Duration::from_millis(10),
        write: Duration::from_secs(2),
    };

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
                TelemetryReceiver::connect_authenticated(&mut stream, &anchor, &expected_guest, {
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
            BOUNDS,
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
            BOUNDS,
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
                BOUNDS,
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
            BOUNDS,
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
            BOUNDS,
        );
        assert_eq!(end, SessionEnd::Failed);
    }

    fn authenticate(
        stream: &mut UnixStream,
        anchor_key: &SigningKey,
        expected_guest: &VerifyingKey,
    ) -> TelemetryReceiver {
        let anchor = anchor_key.verifying_key();
        let signer = anchor_key.clone();
        TelemetryReceiver::connect_authenticated(
            stream,
            &anchor,
            expected_guest,
            move |hello, ack| {
                let bytes =
                    handshake_signing_bytes(hello, ack, &signer.verifying_key()).map_err(|_| {
                        mvm_core::net::session::SessionError::InvalidHandshake(
                            "bad handshake".into(),
                        )
                    })?;
                Ok(signer.sign(&bytes))
            },
        )
        .expect("host authenticates")
    }

    /// A ~2 KiB log record, so a stalled peer's socket buffer fills fast.
    fn bulky(capture: &CaptureState) -> crate::telemetry_capture::EmitOutcome {
        capture.emit(
            SourceKind::GuestAgent,
            ProducerId::AgentDiagnostics,
            RecordBody::Log {
                context: None,
                level: Level::Info,
                message: "x".repeat(2000).as_str().try_into().unwrap(),
                attributes: Attributes::default(),
            },
        )
    }

    /// Emit until `done`, returning how many emissions ran and the slowest.
    fn flood(
        capture: Arc<CaptureState>,
        done: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<(u64, Duration)> {
        std::thread::spawn(move || {
            let (mut emitted, mut slowest) = (0u64, Duration::ZERO);
            while !done.load(Ordering::Relaxed) {
                let started = std::time::Instant::now();
                let _ = bulky(&capture);
                slowest = slowest.max(started.elapsed());
                emitted += 1;
            }
            (emitted, slowest)
        })
    }

    #[test]
    fn a_turn_sends_at_most_its_cap_and_leaves_the_rest_queued() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(128);
        for _ in 0..100 {
            diagnostic(&capture, "queued");
        }
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_receives(host, anchor_key.clone(), guest_key.verifying_key(), 100);
        let mut sender =
            TelemetrySender::connect(&mut guest, guest_key, &anchor_key.verifying_key()).unwrap();
        let write = Duration::from_secs(2);
        assert_eq!(
            drain_turn(&mut guest, &mut sender, &capture, write),
            Ok(RECORDS_PER_TURN)
        );
        assert_eq!(
            drain_turn(&mut guest, &mut sender, &capture, write),
            Ok(100 - RECORDS_PER_TURN)
        );
        assert_eq!(drain_turn(&mut guest, &mut sender, &capture, write), Ok(0));
        drop(guest);
        assert_eq!(collector.join().unwrap().len(), 100);
    }

    #[test]
    fn stop_ends_a_session_under_a_continuous_flood() {
        let (guest_key, anchor_key) = keys();
        let capture = Arc::new(capture_over(128));
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let expected = guest_key.verifying_key();
        let anchor = anchor_key.clone();
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let collector = {
            let received = Arc::clone(&received);
            std::thread::spawn(move || {
                let mut receiver = authenticate(&mut host, &anchor, &expected);
                while receiver.receive(&mut host).is_ok() {
                    received.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let done = Arc::new(AtomicBool::new(false));
        let producer = flood(Arc::clone(&capture), Arc::clone(&done));
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = {
            let stop = Arc::clone(&stop);
            let received = Arc::clone(&received);
            std::thread::spawn(move || {
                // Stop only once the flood is demonstrably crossing, so the
                // stop lands mid-flood rather than before it started.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while received.load(Ordering::Relaxed) < 4 * RECORDS_PER_TURN
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                stop.store(true, Ordering::Release);
                std::time::Instant::now()
            })
        };
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            BOUNDS,
        );
        let returned = std::time::Instant::now();
        let stopped = stopper.join().unwrap();
        done.store(true, Ordering::Relaxed);
        let (emitted, _) = producer.join().unwrap();
        drop(guest);
        collector.join().unwrap();
        let received = received.load(Ordering::Relaxed);
        assert_eq!(end, SessionEnd::PeerClosed);
        // The flood never ends on its own, so the session returning at all is
        // the property: stop is checked between capped turns, not only once
        // the queue runs dry. The wait between the stop and the return is one
        // turn of at most `RECORDS_PER_TURN` frame writes, whose wall-clock
        // length depends on how fast the host reads; on a loaded runner that
        // has been seen at 650 ms. The ceiling here only catches a stop that
        // is never observed, without timing the runner.
        assert!(
            returned.duration_since(stopped) < Duration::from_secs(10),
            "stop observed {:?} after it was set",
            returned.duration_since(stopped)
        );
        assert!(
            emitted > 0 && received > 1,
            "the flood was live: {emitted} emitted, {received} received"
        );
    }

    #[test]
    fn loss_summaries_still_cross_while_a_flood_keeps_the_queue_full() {
        let (guest_key, anchor_key) = keys();
        let capture = Arc::new(capture_over(2));
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let expected = guest_key.verifying_key();
        let anchor = anchor_key.clone();
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let collector = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut receiver = authenticate(&mut host, &anchor, &expected);
                let mut shed_reported = 0u64;
                while let Ok(record) = receiver.receive(&mut host) {
                    if let RecordBody::Loss { records, .. } = *record.body() {
                        shed_reported += records;
                        stop.store(true, Ordering::Release);
                    }
                }
                shed_reported
            })
        };
        let producer = flood(Arc::clone(&capture), Arc::clone(&done));
        let started = std::time::Instant::now();
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            BOUNDS,
        );
        done.store(true, Ordering::Relaxed);
        producer.join().unwrap();
        drop(guest);
        let shed_reported = collector.join().unwrap();
        assert_eq!(end, SessionEnd::PeerClosed);
        assert!(shed_reported > 0, "a summary reported the flood's losses");
        // The flood never ends on its own: it stops only because a summary
        // crossed. The bound is generous because a loaded CI runner stretches
        // the handshake and the first turns; the property is that a summary
        // arrives while the flood is still running, not its exact cadence.
        assert!(
            started.elapsed() < SUMMARY_INTERVAL * 15,
            "the summary came on its cadence, not after the flood"
        );
    }

    /// Collect what a host receives from a session over `capture` until the
    /// guest ends it, stopping the session once `until` has seen enough.
    fn receive_until(
        capture: &CaptureState,
        until: impl Fn(&[TelemetryRecord]) -> bool + Send + 'static,
    ) -> Vec<TelemetryRecord> {
        let (guest_key, anchor_key) = keys();
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let expected = guest_key.verifying_key();
        let anchor = anchor_key.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let collector = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut receiver = authenticate(&mut host, &anchor, &expected);
                // A bound on the wait, so a witness whose condition never
                // holds fails instead of hanging; well past the summary clock.
                let give_up = std::time::Instant::now() + SUMMARY_INTERVAL * 5;
                host.set_read_timeout(Some(SUMMARY_INTERVAL * 5)).unwrap();
                let mut seen = Vec::new();
                while let Ok(record) = receiver.receive(&mut host) {
                    seen.push(record);
                    if until(&seen) || std::time::Instant::now() >= give_up {
                        stop.store(true, Ordering::Release);
                    }
                }
                seen
            })
        };
        let _ = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            capture,
            &stop,
            BOUNDS,
        );
        drop(guest);
        collector.join().unwrap()
    }

    fn stdout_chunk(capture: &CaptureState) {
        crate::telemetry_capture::offer_stdio_to(
            capture,
            mvm_core::protocol::telemetry::StdioStream::Stdout,
            &[b'o'; 4096],
        );
    }

    fn stdout_losses(seen: &[TelemetryRecord]) -> u64 {
        seen.iter()
            .filter(|record| record.producer() == ProducerId::Stdout.number())
            .map(|record| match record.body() {
                RecordBody::Loss { records, .. } => *records,
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn a_workload_flooding_stdout_has_its_losses_summarized_not_dropped_silently() {
        let capture = capture_over(4);
        for _ in 0..40 {
            stdout_chunk(&capture);
        }
        let shed = capture.losses(ProducerId::Stdout).capacity.records;
        assert!(shed > 0, "the flood overflowed the queue");
        let seen = receive_until(&capture, move |seen| stdout_losses(seen) >= shed);
        assert_eq!(
            stdout_losses(&seen),
            shed,
            "every stdout record shed is reported under the stdout producer"
        );
    }

    #[test]
    fn a_stdout_flood_in_its_own_queue_cannot_crowd_out_diagnostics() {
        let capture = capture_over(8).with_queue_for(
            ProducerId::Stdout,
            Arc::new(Outbox::new(4, 4 * MAX_RECORD_BYTES).unwrap()),
        );
        for _ in 0..40 {
            stdout_chunk(&capture);
        }
        diagnostic(&capture, "after-the-flood");
        assert_eq!(
            capture
                .losses(ProducerId::AgentDiagnostics)
                .capacity
                .records,
            0,
            "the diagnostic was admitted beside a full stdout queue"
        );
        let seen = receive_until(&capture, |seen| {
            seen.iter().any(|record| {
                matches!(record.body(), RecordBody::Event { name, .. } if name.as_str() == "after-the-flood")
            })
        });
        let position = seen
            .iter()
            .position(|record| {
                matches!(record.body(), RecordBody::Event { name, .. } if name.as_str() == "after-the-flood")
            })
            .expect("the diagnostic arrived");
        // Announcement, then queues drained in turn: the diagnostic is not
        // held behind the four queued stdout records.
        assert!(position <= 2, "diagnostic arrived at {position}");
    }

    #[test]
    fn a_stalled_host_fails_the_session_within_the_write_deadline_without_slowing_producers() {
        let (guest_key, anchor_key) = keys();
        let capture = Arc::new(capture_over(128));
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let expected = guest_key.verifying_key();
        let anchor = anchor_key.clone();
        let release = Arc::new(AtomicBool::new(false));
        let stalled_host = {
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                let _receiver = authenticate(&mut host, &anchor, &expected);
                // Authenticated, then never reads again.
                while !release.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
        };
        let done = Arc::new(AtomicBool::new(false));
        let producer = flood(Arc::clone(&capture), Arc::clone(&done));
        let bounds = SessionDeadlines {
            write: Duration::from_millis(200),
            ..BOUNDS
        };
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bounds,
        );
        let elapsed = started.elapsed();
        done.store(true, Ordering::Relaxed);
        let (emitted, slowest) = producer.join().unwrap();
        release.store(true, Ordering::Relaxed);
        stalled_host.join().unwrap();
        assert_eq!(end, SessionEnd::Failed);
        assert!(
            elapsed < Duration::from_secs(3),
            "session pinned for {elapsed:?}"
        );
        let losses = capture.outbox().losses();
        assert!(losses.transport.records >= 1 && losses.transport_tail_unknown);
        // Producers never waited on the stalled transport.
        assert!(emitted > 0);
        assert!(
            slowest < Duration::from_millis(100),
            "an emission took {slowest:?}"
        );
    }

    #[test]
    fn a_host_reading_one_byte_at_a_time_cannot_stretch_a_frame_past_its_deadline() {
        let (guest_key, anchor_key) = keys();
        let capture = Arc::new(capture_over(128));
        for _ in 0..128 {
            let _ = bulky(&capture);
        }
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let expected = guest_key.verifying_key();
        let anchor = anchor_key.clone();
        let release = Arc::new(AtomicBool::new(false));
        let trickle = {
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                let _receiver = authenticate(&mut host, &anchor, &expected);
                host.set_read_timeout(Some(Duration::from_millis(5)))
                    .unwrap();
                let mut byte = [0u8; 1];
                while !release.load(Ordering::Relaxed) {
                    let _ = host.read(&mut byte);
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        let bounds = SessionDeadlines {
            write: Duration::from_millis(300),
            ..BOUNDS
        };
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bounds,
        );
        let elapsed = started.elapsed();
        release.store(true, Ordering::Relaxed);
        trickle.join().unwrap();
        assert_eq!(end, SessionEnd::Failed);
        assert!(
            elapsed < Duration::from_secs(3),
            "session pinned for {elapsed:?}"
        );
    }

    #[test]
    fn a_host_that_never_answers_the_handshake_is_dropped_at_the_deadline() {
        let (guest_key, anchor_key) = keys();
        let capture = capture_over(4);
        let (mut guest, _silent_host) = UnixStream::pair().unwrap();
        let bounds = SessionDeadlines {
            handshake: Duration::from_millis(200),
            ..BOUNDS
        };
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let end = serve_capture_session(
            &mut guest,
            guest_key,
            &anchor_key.verifying_key(),
            &capture,
            &stop,
            bounds,
        );
        assert_eq!(end, SessionEnd::Failed);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
