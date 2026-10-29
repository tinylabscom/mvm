//! The host telemetry collector worker: one thread that owns a VM's
//! telemetry session for as long as it is asked to.
//!
//! Each connection attempt runs the required dialer sequence — resolve the
//! expected peer from the boot registration, assert the expectation is still
//! current, and only then open a stream and authenticate — so a warm-claimed
//! or restored boot is picked up by re-resolving rather than authenticated
//! under a stale expectation. Records are handed to a bounded, non-waiting
//! sink; a full sink is a counted host-side shed, never backpressure on the
//! receive loop. Failure marks coverage degraded and retries under a capped
//! backoff. The stream connector and the handshake signer are injected, so
//! the worker composes over any byte stream and any signing authority; the
//! supervisor slot and per-backend socket wiring live with the runtime
//! owner, not here.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::net::telemetry::TelemetryReceiver;
use mvm_core::protocol::telemetry::served::HostLosses;
use mvm_core::security::{SessionHello, SessionHelloAck};
use mvm_vmm::host::telemetry_registration::{
    assert_peer_is_current, resolve_expected_telemetry_peer,
};

mod sink;

pub use sink::{
    CappedJsonlSink, IngestOutcome, LossClass, LossCounters, QueuedSink, RecordFile, RecordSink,
    ScrubbingSink, WRITE_QUEUE_MAX_BYTES, WRITE_QUEUE_RECORDS,
};

/// Base of the reconnect backoff schedule.
const BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Ceiling the reconnect backoff saturates at.
const BACKOFF_CAP: Duration = Duration::from_secs(5);
/// How often a backoff sleep re-checks the stop flag, bounding how long a
/// stop request can go unnoticed.
const STOP_POLL: Duration = Duration::from_millis(25);

/// Where the collector stands, for the supervisor and diagnostics to read.
/// Codes are static labels, never payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageStatus {
    /// No session yet; the worker is resolving or dialing.
    Connecting,
    /// An authenticated session is live under this boot generation.
    Collecting { generation: u64 },
    /// The last attempt failed for the named reason; the worker is backing
    /// off and will retry.
    Degraded { code: &'static str },
    /// The worker was asked to stop and has exited.
    Stopped,
}

/// Everything one collector worker needs, built once and moved into its
/// thread. The connector opens a fresh stream per attempt; the signer answers
/// the receiver's handshake challenge (in production, through the resident
/// signer's delegated client).
pub struct CollectorConfig<S, C, F> {
    state_dir: PathBuf,
    vm: String,
    host_anchor: VerifyingKey,
    connector: C,
    signer: F,
    // A fn-pointer marker: streams are only ever created inside the worker
    // thread, so the config itself never holds one and stays `Send`
    // regardless of the stream type.
    _stream: std::marker::PhantomData<fn() -> S>,
}

impl<S, C, F> CollectorConfig<S, C, F>
where
    S: Read + Write + 'static,
    C: FnMut() -> std::io::Result<S> + Send + 'static,
    F: Fn(
            &SessionHello,
            &SessionHelloAck,
        ) -> Result<Signature, mvm_core::net::session::SessionError>
        + Send
        + 'static,
{
    pub fn new(
        state_dir: PathBuf,
        vm: impl Into<String>,
        host_anchor: VerifyingKey,
        connector: C,
        signer: F,
    ) -> Self {
        Self {
            state_dir,
            vm: vm.into(),
            host_anchor,
            connector,
            signer,
            _stream: std::marker::PhantomData,
        }
    }
}

/// The running worker's handle: status snapshot, shed count, and stop.
pub struct CollectorHandle {
    status: Arc<Mutex<CoverageStatus>>,
    losses: Arc<LossCounters>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CollectorHandle {
    /// The worker's current standing. Never blocks meaningfully: the lock is
    /// held only for assignment.
    pub fn status(&self) -> CoverageStatus {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records the sink refused since the worker started.
    pub fn shed(&self) -> u64 {
        self.losses.total()
    }

    /// Records shed since the worker started, by reason.
    pub fn losses(&self) -> HostLosses {
        self.losses.snapshot()
    }

    /// Shared views for the embedded status writer, which reports on its own
    /// cadence without borrowing the handle across threads.
    fn status_shared(&self) -> &Arc<Mutex<CoverageStatus>> {
        &self.status
    }

    fn losses_shared(&self) -> &Arc<LossCounters> {
        &self.losses
    }

    /// Ask the worker to stop and wait for it. Takes effect between attempts,
    /// between backoff polls, and at the next receive boundary of a live
    /// session (peer close or error); a session blocked in a read ends when
    /// its peer or its stream's own timeout ends the read.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Spawn the collector worker thread for one VM.
pub fn spawn_collector<S, C, F>(
    config: CollectorConfig<S, C, F>,
    sink: impl RecordSink + 'static,
) -> std::io::Result<CollectorHandle>
where
    S: Read + Write + 'static,
    C: FnMut() -> std::io::Result<S> + Send + 'static,
    F: Fn(
            &SessionHello,
            &SessionHelloAck,
        ) -> Result<Signature, mvm_core::net::session::SessionError>
        + Send
        + 'static,
{
    spawn_collector_counting(config, sink, Arc::new(LossCounters::default()))
}

/// [`spawn_collector`] with the loss counters supplied, so a sink that sheds
/// on another thread (a [`QueuedSink`]'s writer) counts into the same tally
/// the handle reports.
fn spawn_collector_counting<S, C, F>(
    config: CollectorConfig<S, C, F>,
    sink: impl RecordSink + 'static,
    losses: Arc<LossCounters>,
) -> std::io::Result<CollectorHandle>
where
    S: Read + Write + 'static,
    C: FnMut() -> std::io::Result<S> + Send + 'static,
    F: Fn(
            &SessionHello,
            &SessionHelloAck,
        ) -> Result<Signature, mvm_core::net::session::SessionError>
        + Send
        + 'static,
{
    let status = Arc::new(Mutex::new(CoverageStatus::Connecting));
    let stop = Arc::new(AtomicBool::new(false));
    let shared = WorkerShared {
        status: Arc::clone(&status),
        losses: Arc::clone(&losses),
        stop: Arc::clone(&stop),
    };
    let thread = std::thread::Builder::new()
        .name(format!("mvm-telemetry-collector-{}", config.vm))
        .spawn(move || run_worker(config, sink, &shared))?;
    Ok(CollectorHandle {
        status,
        losses,
        stop,
        thread: Some(thread),
    })
}

struct WorkerShared {
    status: Arc<Mutex<CoverageStatus>>,
    losses: Arc<LossCounters>,
    stop: Arc<AtomicBool>,
}

impl WorkerShared {
    fn set_status(&self, status: CoverageStatus) {
        *self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Sleep out `backoff` in stop-aware slices; true when stop arrived.
    fn backoff_interrupted(&self, backoff: Duration) -> bool {
        let deadline = Instant::now() + backoff;
        while Instant::now() < deadline {
            if self.stopped() {
                return true;
            }
            std::thread::sleep(STOP_POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
        self.stopped()
    }
}

fn run_worker<S, C, F>(
    mut config: CollectorConfig<S, C, F>,
    mut sink: impl RecordSink,
    shared: &WorkerShared,
) where
    S: Read + Write + 'static,
    C: FnMut() -> std::io::Result<S> + Send + 'static,
    F: Fn(
            &SessionHello,
            &SessionHelloAck,
        ) -> Result<Signature, mvm_core::net::session::SessionError>
        + Send
        + 'static,
{
    let mut backoff = BACKOFF_BASE;
    loop {
        if shared.stopped() {
            break;
        }
        shared.set_status(CoverageStatus::Connecting);
        match attempt_session(&mut config, &mut sink, shared) {
            AttemptEnd::PeerClosed => {
                // A clean close reconnects without penalty, but never
                // spins: one base delay paces even an instantly-closing
                // peer.
                backoff = BACKOFF_BASE;
                if shared.backoff_interrupted(backoff) {
                    break;
                }
            }
            AttemptEnd::Failed(code) => {
                shared.set_status(CoverageStatus::Degraded { code });
                if shared.backoff_interrupted(backoff) {
                    break;
                }
                backoff = (backoff * 2).min(BACKOFF_CAP);
            }
        }
    }
    shared.set_status(CoverageStatus::Stopped);
}

enum AttemptEnd {
    /// The session ended by the peer closing after a clean run; reconnect
    /// without penalty.
    PeerClosed,
    /// The attempt failed at the named stage; back off before retrying.
    Failed(&'static str),
}

/// One full pass of the required sequence: resolve → assert current →
/// connect → authenticate → receive until the session ends.
fn attempt_session<S, C, F>(
    config: &mut CollectorConfig<S, C, F>,
    sink: &mut impl RecordSink,
    shared: &WorkerShared,
) -> AttemptEnd
where
    S: Read + Write + 'static,
    C: FnMut() -> std::io::Result<S> + Send + 'static,
    F: Fn(
            &SessionHello,
            &SessionHelloAck,
        ) -> Result<Signature, mvm_core::net::session::SessionError>
        + Send
        + 'static,
{
    let peer = match resolve_expected_telemetry_peer(&config.state_dir, &config.vm) {
        Ok(peer) => peer,
        Err(_) => return AttemptEnd::Failed("registration-unresolved"),
    };
    if assert_peer_is_current(&config.state_dir, &peer).is_err() {
        // A superseded expectation is the re-registration signal: the next
        // attempt's resolve reads the new boot.
        return AttemptEnd::Failed("registration-stale");
    }
    let mut stream = match (config.connector)() {
        Ok(stream) => stream,
        Err(_) => return AttemptEnd::Failed("connect-failed"),
    };
    let mut receiver = match TelemetryReceiver::connect_authenticated(
        &mut stream,
        &config.host_anchor,
        &peer.key,
        &config.signer,
    ) {
        Ok(receiver) => receiver,
        Err(_) => return AttemptEnd::Failed("authentication-failed"),
    };
    shared.set_status(CoverageStatus::Collecting {
        generation: peer.generation,
    });
    let end = receive_until_end(&mut receiver, &mut stream, sink, shared);
    // Nothing held for a later decision outlives its session.
    sink.release_held();
    end
}

fn receive_until_end<S: Read + Write>(
    receiver: &mut TelemetryReceiver,
    stream: &mut S,
    sink: &mut impl RecordSink,
    shared: &WorkerShared,
) -> AttemptEnd {
    let mut received_any = false;
    loop {
        if shared.stopped() {
            // Deliberately not a Failed: the stop flag ends the outer loop.
            return AttemptEnd::PeerClosed;
        }
        match receiver.receive(stream) {
            Ok(record) => {
                received_any = true;
                if let IngestOutcome::Shed(class) = sink.try_ingest(&record) {
                    shared.losses.record(class);
                }
            }
            Err(mvm_core::net::telemetry::TelemetryError::Closed) => {
                return AttemptEnd::PeerClosed;
            }
            // A guest tearing its socket down mid-session surfaces as a
            // transport error rather than a clean close; a session that
            // already delivered records reconnects without penalty.
            Err(_) if received_any => return AttemptEnd::PeerClosed,
            Err(_) => return AttemptEnd::Failed("session-failed"),
        }
    }
}

#[cfg(test)]
mod collector_only_tests {
    use super::*;

    #[test]
    fn collector_only_config_is_selected_by_its_key_and_refuses_unknown_fields() {
        let telemetry = serde_json::json!({
            "state_dir": "/s", "telemetry_sock": "/s/t.sock", "signer_sock": "/h/s.sock",
            "host_anchor_path": "/k/a.pub", "records_byte_cap": 1, "records_key_b64": "AA=="
        });
        let only = serde_json::json!({ TELEMETRY_ONLY_KEY: {
            "instance_id": "vm", "redaction": mvm_core::policy::RedactionPolicy::default(),
            "telemetry": telemetry,
        }});
        let parsed = TelemetryOnlyConfig::parse(only.to_string().as_bytes())
            .unwrap()
            .expect("selected by its key");
        assert_eq!(parsed.instance_id, "vm");

        // A full endpoint config is not mistaken for one.
        assert!(
            TelemetryOnlyConfig::parse(br#"{"tenant_id":"local"}"#)
                .unwrap()
                .is_none()
        );

        // A malformed collector-only config is an error, not a fallback.
        let mut extra = only.clone();
        extra[TELEMETRY_ONLY_KEY]["surprise"] = serde_json::json!(true);
        assert!(TelemetryOnlyConfig::parse(extra.to_string().as_bytes()).is_err());
    }

    #[test]
    fn the_config_debug_never_prints_the_records_key() {
        let config = TelemetryEmbedConfig {
            state_dir: "/s".into(),
            telemetry_sock: "/s/t.sock".into(),
            signer_sock: "/h/s.sock".into(),
            host_anchor_path: "/k/a.pub".into(),
            records_byte_cap: 1,
            records_key_b64: "c2VjcmV0LWtleS1ieXRlcw==".into(),
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains("c2VjcmV0"), "{printed}");
        assert!(printed.contains("<redacted>"));
    }

    #[test]
    fn without_a_per_port_socket_the_guest_is_dialed_through_the_firecracker_mux() {
        use std::io::{BufRead as _, BufReader};
        // Short path: a socket path must fit `sun_path`.
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mux = dir.path().join("v.sock");
        let listener = std::os::unix::net::UnixListener::bind(&mux).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut stream = stream;
            stream.write_all(b"OK 1073741824\n").unwrap();
            // Hold the guest end open, as a live guest does.
            let _ = done_rx.recv();
            line
        });
        let stream = dial_guest_telemetry(&dir.path().join("absent.sock"), &mux).unwrap();
        let timeout = stream.read_timeout().unwrap();
        drop(done_tx);
        assert_eq!(
            server.join().unwrap().trim(),
            format!("CONNECT {}", mvm_core::protocol::telemetry::TELEMETRY_PORT)
        );
        assert_eq!(
            timeout, None,
            "a quiet session is not cut by the dial's timeout"
        );

        // With neither socket there is nothing to dial.
        assert!(
            dial_guest_telemetry(&dir.path().join("a.sock"), &dir.path().join("b.sock")).is_err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use mvm_core::net::telemetry::{TelemetrySender, handshake_signing_bytes};
    use mvm_core::protocol::telemetry::{
        CoverageState, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
    };
    use mvm_vmm::host::telemetry_registration::register_telemetry_boot;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
        )
    }

    fn register(state: &std::path::Path, vm: &str, guest_key: &SigningKey) {
        let key_b64 =
            base64::engine::general_purpose::STANDARD.encode(guest_key.verifying_key().as_bytes());
        register_telemetry_boot(state, vm, &key_b64).unwrap();
    }

    /// A connector fed streams by the test; an empty feed is a failed dial.
    fn fed_connector(
        feed: Receiver<UnixStream>,
    ) -> impl FnMut() -> std::io::Result<UnixStream> + Send + 'static {
        move || {
            feed.try_recv()
                .map_err(|_| std::io::Error::other("no stream available"))
        }
    }

    fn direct_signer(
        anchor_key: SigningKey,
    ) -> impl Fn(
        &SessionHello,
        &SessionHelloAck,
    ) -> Result<Signature, mvm_core::net::session::SessionError>
    + Send
    + 'static {
        move |hello, ack| {
            let bytes =
                handshake_signing_bytes(hello, ack, &anchor_key.verifying_key()).map_err(|_| {
                    mvm_core::net::session::SessionError::InvalidHandshake("bad handshake".into())
                })?;
            Ok(anchor_key.sign(&bytes))
        }
    }

    /// A bounded, non-waiting sink over a sync channel: full means shed.
    struct ChannelSink(SyncSender<TelemetryRecord>);

    impl RecordSink for ChannelSink {
        fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
            match self.0.try_send(record.clone()) {
                Ok(()) => IngestOutcome::Ingested,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    IngestOutcome::Shed(LossClass::QueueFull)
                }
            }
        }
    }

    fn record(sequence: u64) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([9; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "collector-witness".try_into().unwrap(),
            })
            .build()
            .unwrap()
    }

    /// A guest session held open until the test releases it, so status
    /// snapshots taken while it lives are deterministic.
    struct HeldSession {
        release: SyncSender<()>,
        thread: std::thread::JoinHandle<()>,
    }

    impl HeldSession {
        fn release(self) {
            drop(self.release);
            self.thread.join().unwrap();
        }
    }

    fn guest_sends_and_holds(
        mut stream: UnixStream,
        guest_key: SigningKey,
        anchor: VerifyingKey,
    ) -> HeldSession {
        let (release, held) = sync_channel::<()>(1);
        let thread = std::thread::spawn(move || {
            let mut sender = TelemetrySender::connect(&mut stream, guest_key, &anchor).unwrap();
            sender.send(&mut stream, &record(1)).unwrap();
            // Blocks until the test drops its sender; then the stream drops
            // and the session ends.
            let _ = held.recv();
        });
        HeldSession { release, thread }
    }

    /// Run the guest half over `stream`: authenticate, send `count` records,
    /// close cleanly.
    fn guest_sends(
        mut stream: UnixStream,
        guest_key: SigningKey,
        anchor: VerifyingKey,
        count: u64,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut sender = TelemetrySender::connect(&mut stream, guest_key, &anchor).unwrap();
            for sequence in 1..=count {
                sender.send(&mut stream, &record(sequence)).unwrap();
            }
        })
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if done() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn a_registered_peer_session_delivers_records_to_the_sink_in_order() {
        let state = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = keys();
        register(state.path(), "vm-a", &guest_key);
        let (feed_tx, feed_rx) = sync_channel(1);
        let (host, guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        let producer = guest_sends(guest, guest_key, anchor_key.verifying_key(), 3);

        let (sink_tx, sink_rx) = sync_channel(16);
        let handle = spawn_collector(
            CollectorConfig::new(
                state.path().to_path_buf(),
                "vm-a",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();

        let mut got = Vec::new();
        wait_until("three records", || {
            got.extend(sink_rx.try_iter());
            got.len() == 3
        });
        assert_eq!(
            got.iter().map(|r| r.sequence()).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(handle.shed(), 0);
        producer.join().unwrap();
        handle.stop();
    }

    #[test]
    fn a_reregistered_boot_is_picked_up_by_re_resolving() {
        let state = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = keys();
        register(state.path(), "vm-b", &guest_key);
        let (feed_tx, feed_rx) = sync_channel(2);
        let (host, guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        // Hold each session open until its status has been observed, so the
        // Collecting snapshot cannot race the guest's teardown.
        let first = guest_sends_and_holds(guest, guest_key.clone(), anchor_key.verifying_key());

        let (sink_tx, sink_rx) = sync_channel(16);
        let handle = spawn_collector(
            CollectorConfig::new(
                state.path().to_path_buf(),
                "vm-b",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();
        wait_until("first session's record", || sink_rx.try_iter().count() >= 1);
        let first_generation = match handle.status() {
            CoverageStatus::Collecting { generation } => generation,
            other => panic!("expected a live session, got {other:?}"),
        };
        first.release();

        // Warm-claim-shaped re-registration under the same key, then a new
        // stream: the worker must re-resolve and serve the new boot.
        register(state.path(), "vm-b", &guest_key);
        let (host, guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        let second = guest_sends_and_holds(guest, guest_key, anchor_key.verifying_key());
        wait_until("second session's record", || {
            sink_rx.try_iter().count() >= 1
        });
        match handle.status() {
            CoverageStatus::Collecting { generation } => {
                assert!(
                    generation > first_generation,
                    "a re-registered boot has a newer generation"
                );
            }
            other => panic!("expected a live second session, got {other:?}"),
        }
        second.release();
        handle.stop();
    }

    #[test]
    fn a_full_sink_sheds_with_evidence_and_never_blocks_the_receive_loop() {
        let state = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = keys();
        register(state.path(), "vm-c", &guest_key);
        let (feed_tx, feed_rx) = sync_channel(1);
        let (host, guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        let producer = guest_sends(guest, guest_key, anchor_key.verifying_key(), 5);

        // Capacity one and never drained: one record lands, four shed.
        let (sink_tx, _sink_rx) = sync_channel(1);
        let handle = spawn_collector(
            CollectorConfig::new(
                state.path().to_path_buf(),
                "vm-c",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();
        wait_until("four shed records", || handle.shed() == 4);
        producer.join().unwrap();
        handle.stop();
    }

    #[test]
    fn stop_interrupts_a_backing_off_worker_promptly() {
        let state = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = keys();
        register(state.path(), "vm-d", &guest_key);
        // No streams ever: every attempt fails at connect and backs off.
        let (_feed_tx, feed_rx) = sync_channel::<UnixStream>(1);
        let (sink_tx, _sink_rx) = sync_channel(1);
        let handle = spawn_collector(
            CollectorConfig::new(
                state.path().to_path_buf(),
                "vm-d",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();
        wait_until("a degraded status", || {
            matches!(handle.status(), CoverageStatus::Degraded { .. })
        });
        let started = Instant::now();
        handle.stop();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop must interrupt the backoff, not wait it out"
        );
    }

    #[test]
    fn a_guest_with_an_unregistered_key_fails_authentication_and_degrades() {
        let state = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = keys();
        register(state.path(), "vm-e", &guest_key);
        let (feed_tx, feed_rx) = sync_channel(1);
        let (host, mut guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        let imposter = SigningKey::from_bytes(&[43; 32]);
        let anchor = anchor_key.verifying_key();
        let producer = std::thread::spawn(move || {
            // The imposter's handshake must fail; a connect error is the point.
            let _ = TelemetrySender::connect(&mut guest, imposter, &anchor);
        });

        let (sink_tx, sink_rx) = sync_channel(16);
        let handle = spawn_collector(
            CollectorConfig::new(
                state.path().to_path_buf(),
                "vm-e",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();
        wait_until("an authentication-failed status", || {
            matches!(
                handle.status(),
                CoverageStatus::Degraded {
                    code: "authentication-failed"
                }
            )
        });
        assert_eq!(sink_rx.try_iter().count(), 0, "no record crosses");
        producer.join().unwrap();
        handle.stop();
    }

    #[test]
    fn a_sibling_vms_registered_guest_cannot_feed_this_vms_collector() {
        // Two VMs, each with its own registered guest key. VM B's genuine
        // guest reaching VM A's collector is a forged identity from A's side:
        // A authenticates only the key A's own registration names.
        let a_state = tempfile::tempdir().unwrap();
        let b_state = tempfile::tempdir().unwrap();
        let (a_guest, anchor_key) = keys();
        let b_guest = SigningKey::from_bytes(&[44; 32]);
        register(a_state.path(), "vm-a", &a_guest);
        register(b_state.path(), "vm-b", &b_guest);

        let (feed_tx, feed_rx) = sync_channel(1);
        let (host, mut guest) = UnixStream::pair().unwrap();
        feed_tx.send(host).unwrap();
        let anchor = anchor_key.verifying_key();
        let producer = std::thread::spawn(move || {
            if let Ok(mut sender) = TelemetrySender::connect(&mut guest, b_guest, &anchor) {
                let _ = sender.send(&mut guest, &record(1));
            }
        });

        let (sink_tx, sink_rx) = sync_channel(16);
        let handle = spawn_collector(
            CollectorConfig::new(
                a_state.path().to_path_buf(),
                "vm-a",
                anchor_key.verifying_key(),
                fed_connector(feed_rx),
                direct_signer(anchor_key.clone()),
            ),
            ChannelSink(sink_tx),
        )
        .unwrap();
        wait_until("the sibling's session to be refused", || {
            matches!(
                handle.status(),
                CoverageStatus::Degraded {
                    code: "authentication-failed"
                }
            )
        });
        assert_eq!(sink_rx.try_iter().count(), 0, "no sibling record crosses");
        producer.join().unwrap();
        handle.stop();
    }

    #[test]
    fn a_stalled_vms_collector_does_not_slow_another_vms_collector() {
        // Each VM owns its own worker, queue and sink. VM A's sink never
        // drains; VM B still receives every record its guest sends.
        let (anchor_key, a_guest, b_guest) = (
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[45; 32]),
            SigningKey::from_bytes(&[46; 32]),
        );
        let start = |vm: &'static str, guest_key: SigningKey, sink: ChannelSink, count: u64| {
            let state = tempfile::tempdir().unwrap();
            register(state.path(), vm, &guest_key);
            let (feed_tx, feed_rx) = sync_channel(1);
            let (host, guest) = UnixStream::pair().unwrap();
            feed_tx.send(host).unwrap();
            let producer = guest_sends(guest, guest_key, anchor_key.verifying_key(), count);
            let handle = spawn_collector(
                CollectorConfig::new(
                    state.path().to_path_buf(),
                    vm,
                    anchor_key.verifying_key(),
                    fed_connector(feed_rx),
                    direct_signer(anchor_key.clone()),
                ),
                sink,
            )
            .unwrap();
            (state, producer, handle)
        };

        let (a_tx, _a_never_drained) = sync_channel(1);
        let (b_tx, b_rx) = sync_channel(64);
        let (_a_state, a_producer, a) = start("vm-a", a_guest, ChannelSink(a_tx), 50);
        let (_b_state, b_producer, b) = start("vm-b", b_guest, ChannelSink(b_tx), 50);

        let mut got = 0;
        wait_until("all of B's records", || {
            got += b_rx.try_iter().count();
            got == 50
        });
        assert_eq!(b.shed(), 0, "B shed nothing");
        wait_until("A to shed what its stalled sink could not take", || {
            a.shed() == 49
        });
        assert_eq!(a.losses().queue_full, 49);
        a_producer.join().unwrap();
        b_producer.join().unwrap();
        a.stop();
        b.stop();
    }
}

/// The status snapshot the collector process persists beside the VM state,
/// for `doctor` and the future CLI seam to read.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CollectorStatusSnapshot {
    pub vm_name: String,
    pub status: String,
    /// Boot generation when a session is live; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Every record the host shed after receipt; the sum of `losses`.
    pub shed: u64,
    /// The same sheds by reason. Absent from a snapshot written before the
    /// reasons were recorded, which reads as all zero.
    #[serde(default, skip_serializing_if = "HostLosses::is_zero")]
    pub losses: HostLosses,
}

fn status_snapshot(
    vm_name: &str,
    status: &CoverageStatus,
    losses: HostLosses,
) -> CollectorStatusSnapshot {
    let (label, generation) = match status {
        CoverageStatus::Connecting => ("connecting".to_string(), None),
        CoverageStatus::Collecting { generation } => ("collecting".to_string(), Some(*generation)),
        CoverageStatus::Degraded { code } => (format!("degraded:{code}"), None),
        CoverageStatus::Stopped => ("stopped".to_string(), None),
    };
    CollectorStatusSnapshot {
        vm_name: vm_name.to_string(),
        status: label,
        generation,
        shed: losses.total(),
        losses,
    }
}

/// Atomically replace the status file with the current snapshot.
fn write_status(path: &std::path::Path, snapshot: &CollectorStatusSnapshot) {
    let tmp = path.with_extension("json.tmp");
    if let Ok(bytes) = serde_json::to_vec_pretty(snapshot)
        && std::fs::write(&tmp, bytes).is_ok()
    {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// How long one dial of a Firecracker vsock mux may take, handshake included.
/// The worker retries on its own backoff, so this bounds one attempt only.
const MUX_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Dial the guest's telemetry listener. A VMM that bridges host-dialed ports
/// (HVF, libkrun) exposes it as a per-port socket; Firecracker does not, and
/// is reached through its vsock mux with the `CONNECT <port>` handshake.
fn dial_guest_telemetry(
    per_port: &std::path::Path,
    firecracker_mux: &std::path::Path,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    match std::os::unix::net::UnixStream::connect(per_port) {
        Ok(stream) => Ok(stream),
        Err(_) if firecracker_mux.exists() => {
            let stream = mvm_agentd::vsock::connect_to_port_once(
                &firecracker_mux.to_string_lossy(),
                mvm_core::protocol::telemetry::TELEMETRY_PORT,
                MUX_CONNECT_TIMEOUT_SECS,
            )
            .map_err(|error| std::io::Error::other(format!("{error:#}")))?;
            // The handshake's timeouts bounded the dial. A telemetry session
            // is long and often quiet; left in place they would end it, and
            // re-announce it, every few idle seconds.
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            Ok(stream)
        }
        Err(error) => Err(error),
    }
}

/// What a collector-only process reads on stdin: the collector's own inputs
/// plus what scrubbing needs, for a VM that has no network endpoint to embed
/// the collector in. Wrapped as `{"telemetry_only": …}` so the endpoint
/// binary can tell it from a full endpoint config before parsing either.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryOnlyConfig {
    /// The VM this collector serves.
    pub instance_id: String,
    /// The launch's redaction policy, for the curated seam.
    pub redaction: mvm_core::policy::RedactionPolicy,
    /// The collector's inputs.
    pub telemetry: TelemetryEmbedConfig,
}

/// The stdin wrapper key that selects collector-only mode.
pub const TELEMETRY_ONLY_KEY: &str = "telemetry_only";

impl TelemetryOnlyConfig {
    /// `Some` when `raw` is a collector-only config; `None` when it is
    /// anything else (a full endpoint config). A malformed collector-only
    /// config is an error, never a fallback to the other mode.
    pub fn parse(raw: &[u8]) -> anyhow::Result<Option<Self>> {
        let value: serde_json::Value = serde_json::from_slice(raw)?;
        let Some(inner) = value.get(TELEMETRY_ONLY_KEY) else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_value(inner.clone())?))
    }
}

/// The embedded collector's inputs, carried inside the endpoint's stdin
/// config. `deny_unknown_fields` so a section from a newer spawner fails
/// closed rather than half-applying.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEmbedConfig {
    /// The VM's state dir: registration, status and records live here.
    pub state_dir: std::path::PathBuf,
    /// The per-VM host UDS the backend bridges to the guest telemetry port.
    pub telemetry_sock: std::path::PathBuf,
    /// The delegated signer's UDS (the audit-signer subprocess).
    pub signer_sock: std::path::PathBuf,
    /// The host-signer public key the receiver authenticates itself under.
    pub host_anchor_path: std::path::PathBuf,
    /// Byte cap for the records file; beyond it records are shed and counted.
    pub records_byte_cap: u64,
    /// The records data key, base64. Every line of the records file is
    /// sealed under it; the spawner keeps it on disk only wrapped under the
    /// host key-encryption key, which this confined process cannot reach.
    pub records_key_b64: String,
}

impl std::fmt::Debug for TelemetryEmbedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryEmbedConfig")
            .field("state_dir", &self.state_dir)
            .field("telemetry_sock", &self.telemetry_sock)
            .field("signer_sock", &self.signer_sock)
            .field("host_anchor_path", &self.host_anchor_path)
            .field("records_byte_cap", &self.records_byte_cap)
            .field("records_key_b64", &"<redacted>")
            .finish()
    }
}

impl TelemetryEmbedConfig {
    /// The records data key, or an error naming only what is wrong with it.
    fn records_key(&self) -> anyhow::Result<mvm_core::crypto::aead::Key> {
        use base64::Engine as _;
        let bytes = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(self.records_key_b64.trim())
                .map_err(|_| anyhow::anyhow!("records key is not base64"))?,
        );
        mvm_core::crypto::aead::Key::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("records key is not 32 bytes"))
    }
}

/// The embedded collector: the worker plus its status writer, running as
/// threads of the host process that owns the VM (the network endpoint).
/// There is deliberately no `Drop` that joins — the collector dies with its
/// process, which is the ownership contract; `stop` exists for tests.
pub struct EmbeddedCollector {
    handle: CollectorHandle,
    status_stop: std::sync::Arc<AtomicBool>,
    status_thread: Option<std::thread::JoinHandle<()>>,
}

impl EmbeddedCollector {
    /// The worker's current standing.
    pub fn status(&self) -> CoverageStatus {
        self.handle.status()
    }

    /// Stop both threads and wait for them. Test seam; production never
    /// calls it — process death is the teardown.
    pub fn stop(mut self) {
        self.status_stop.store(true, Ordering::Release);
        if let Some(thread) = self.status_thread.take() {
            let _ = thread.join();
        }
        self.handle.stop();
    }
}

/// Where the embedded collector persists its status snapshot.
fn status_path(config: &TelemetryEmbedConfig) -> std::path::PathBuf {
    config
        .state_dir
        .join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_COLLECTOR_STATUS_FILE)
}

/// Start the embedded collector inside the current process: dial the bridged
/// telemetry socket, authenticate through the delegated signer, persist
/// records to the capped JSONL and a status snapshot on a fixed cadence.
/// The first snapshot is written before anything is dialed, so a slow or
/// absent guest never looks like a failed start. `secret_fingerprints` are
/// the endpoint's bound secrets: a record carrying one is withheld before it
/// is queued or written. `redaction` is the stream plane's curated seam,
/// built from the launch's redaction policy: every record is masked by it
/// before it is queued, so telemetry and the transcript redact alike.
pub fn start_embedded(
    vm_name: &str,
    config: &TelemetryEmbedConfig,
    secret_fingerprints: Vec<SecretFingerprint>,
    redaction: crate::stream::redact::StreamRedaction,
) -> anyhow::Result<EmbeddedCollector> {
    use anyhow::Context as _;

    let status_file = status_path(config);
    write_status(
        &status_file,
        &status_snapshot(vm_name, &CoverageStatus::Connecting, HostLosses::default()),
    );

    let anchor_bytes: [u8; 32] = std::fs::read(&config.host_anchor_path)
        .with_context(|| format!("reading host anchor {}", config.host_anchor_path.display()))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("host anchor is not 32 bytes"))?;
    let host_anchor = VerifyingKey::from_bytes(&anchor_bytes).context("invalid host anchor")?;

    let records = CappedJsonlSink::create(
        &config
            .state_dir
            .join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE),
        config.records_byte_cap,
        config.records_key()?,
    )
    .context("opening the records file")?;
    // The disk write runs on its own thread behind a bounded queue, so a
    // slow or full disk sheds records instead of stalling the session; the
    // secret scrub runs before the queue, so a withheld record is never
    // buffered at all.
    let losses = Arc::new(LossCounters::default());
    let sink = ScrubbingSink::new(
        secret_fingerprints,
        redaction,
        QueuedSink::spawn(vm_name, WRITE_QUEUE_RECORDS, records, Arc::clone(&losses))
            .context("starting the records writer")?,
        Arc::clone(&losses),
    );

    let telemetry_sock = config.telemetry_sock.clone();
    let firecracker_mux = PathBuf::from(mvm_agentd::vsock::vsock_uds_path(
        &config.state_dir.to_string_lossy(),
    ));
    let connector = move || dial_guest_telemetry(&telemetry_sock, &firecracker_mux);

    let signer_sock = config.signer_sock.clone();
    let signer = move |hello: &mvm_core::security::SessionHello,
                       ack: &mvm_core::security::SessionHelloAck|
          -> Result<Signature, mvm_core::net::session::SessionError> {
        // Handshakes are per-session and rare; a throwaway current-thread
        // runtime per call keeps the worker thread runtime-free.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                mvm_core::net::session::SessionError::InvalidHandshake("signer runtime".into())
            })?;
        let client = crate::audit_signer::helper_client::SignerHelperClient::new(&signer_sock);
        let anchor = VerifyingKey::from_bytes(&anchor_bytes).map_err(|_| {
            mvm_core::net::session::SessionError::InvalidHandshake("bad anchor".into())
        })?;
        runtime
            .block_on(client.sign_telemetry_handshake(
                hello,
                ack,
                &anchor,
                std::time::Duration::from_secs(5),
            ))
            .map_err(|_| {
                mvm_core::net::session::SessionError::InvalidHandshake("signer refused".into())
            })
    };

    let handle = spawn_collector_counting(
        CollectorConfig::new(
            config.state_dir.clone(),
            vm_name.to_string(),
            host_anchor,
            connector,
            signer,
        ),
        sink,
        losses,
    )?;

    let status_stop = std::sync::Arc::new(AtomicBool::new(false));
    let status_thread = {
        let stop = std::sync::Arc::clone(&status_stop);
        let status = std::sync::Arc::clone(handle.status_shared());
        let losses = std::sync::Arc::clone(handle.losses_shared());
        let vm_name = vm_name.to_string();
        std::thread::Builder::new()
            .name(format!("mvm-telemetry-status-{vm_name}"))
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let current = status
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    write_status(
                        &status_file,
                        &status_snapshot(&vm_name, &current, losses.snapshot()),
                    );
                }
            })?
    };

    Ok(EmbeddedCollector {
        handle,
        status_stop,
        status_thread: Some(status_thread),
    })
}
