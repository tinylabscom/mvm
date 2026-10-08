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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use mvm_core::net::telemetry::TelemetryReceiver;
use mvm_core::protocol::telemetry::TelemetryRecord;
use mvm_core::security::{SessionHello, SessionHelloAck};
use mvm_vmm::host::telemetry_registration::{
    assert_peer_is_current, resolve_expected_telemetry_peer,
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

/// What a sink did with one offered record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Ingested,
    /// The sink is full; the collector counts the shed and keeps receiving.
    Shed,
}

/// A bounded, non-waiting home for received records. `try_ingest` must never
/// block: a slow consumer costs shed records, not a stalled receive loop.
pub trait RecordSink: Send {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome;
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
    shed: Arc<AtomicU64>,
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
        self.shed.load(Ordering::Relaxed)
    }

    /// Shared views for the embedded status writer, which reports on its own
    /// cadence without borrowing the handle across threads.
    fn status_shared(&self) -> &Arc<Mutex<CoverageStatus>> {
        &self.status
    }

    fn shed_shared(&self) -> &Arc<AtomicU64> {
        &self.shed
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
    let status = Arc::new(Mutex::new(CoverageStatus::Connecting));
    let shed = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let shared = WorkerShared {
        status: Arc::clone(&status),
        shed: Arc::clone(&shed),
        stop: Arc::clone(&stop),
    };
    let thread = std::thread::Builder::new()
        .name(format!("mvm-telemetry-collector-{}", config.vm))
        .spawn(move || run_worker(config, sink, &shared))?;
    Ok(CollectorHandle {
        status,
        shed,
        stop,
        thread: Some(thread),
    })
}

struct WorkerShared {
    status: Arc<Mutex<CoverageStatus>>,
    shed: Arc<AtomicU64>,
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
    let mut receiver = match TelemetryReceiver::connect_with_signer(
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
    receive_until_end(&mut receiver, &mut stream, sink, shared)
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
                if sink.try_ingest(&record) == IngestOutcome::Shed {
                    shared.shed.fetch_add(1, Ordering::Relaxed);
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
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use mvm_core::net::telemetry::{TelemetrySender, handshake_signing_bytes};
    use mvm_core::protocol::telemetry::{CoverageState, ProducerEpoch, RecordBody, SourceKind};
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
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => IngestOutcome::Shed,
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
}

/// A size-capped JSONL sink: each record appends as one JSON line until the
/// cap, then sheds. This file exists so collection is observable — retention
/// and durable storage are their own workstream, and nothing here claims
/// them. Writes are local file appends; a failed write is a shed, never a
/// stall.
pub struct CappedJsonlSink {
    file: std::fs::File,
    written: u64,
    cap: u64,
}

impl CappedJsonlSink {
    pub fn create(path: &std::path::Path, cap: u64) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { file, written, cap })
    }
}

impl RecordSink for CappedJsonlSink {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        use std::io::Write as _;
        let Ok(mut line) = serde_json::to_vec(record) else {
            return IngestOutcome::Shed;
        };
        line.push(b'\n');
        if self.written.saturating_add(line.len() as u64) > self.cap {
            return IngestOutcome::Shed;
        }
        match self.file.write_all(&line) {
            Ok(()) => {
                self.written += line.len() as u64;
                IngestOutcome::Ingested
            }
            Err(_) => IngestOutcome::Shed,
        }
    }
}

/// The status snapshot the collector persists beside the VM state. The type
/// lives in `mvm-core` beside the record contract so the reader behind the
/// `MvmClient` telemetry methods shares it with this writer.
pub use mvm_core::protocol::telemetry::CollectorStatusSnapshot;

fn status_snapshot(vm_name: &str, status: &CoverageStatus, shed: u64) -> CollectorStatusSnapshot {
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
        shed,
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

/// The embedded collector's inputs, carried inside the endpoint's stdin
/// config. `deny_unknown_fields` so a section from a newer spawner fails
/// closed rather than half-applying.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
/// absent guest never looks like a failed start.
pub fn start_embedded(
    vm_name: &str,
    config: &TelemetryEmbedConfig,
) -> anyhow::Result<EmbeddedCollector> {
    use anyhow::Context as _;

    let status_file = status_path(config);
    write_status(
        &status_file,
        &status_snapshot(vm_name, &CoverageStatus::Connecting, 0),
    );

    let anchor_bytes: [u8; 32] = std::fs::read(&config.host_anchor_path)
        .with_context(|| format!("reading host anchor {}", config.host_anchor_path.display()))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("host anchor is not 32 bytes"))?;
    let host_anchor = VerifyingKey::from_bytes(&anchor_bytes).context("invalid host anchor")?;

    let sink = CappedJsonlSink::create(
        &config
            .state_dir
            .join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE),
        config.records_byte_cap,
    )
    .context("opening the records file")?;

    let telemetry_sock = config.telemetry_sock.clone();
    let connector = move || std::os::unix::net::UnixStream::connect(&telemetry_sock);

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

    let handle = spawn_collector(
        CollectorConfig::new(
            config.state_dir.clone(),
            vm_name.to_string(),
            host_anchor,
            connector,
            signer,
        ),
        sink,
    )?;

    let status_stop = std::sync::Arc::new(AtomicBool::new(false));
    let status_thread = {
        let stop = std::sync::Arc::clone(&status_stop);
        let status = std::sync::Arc::clone(handle.status_shared());
        let shed = std::sync::Arc::clone(handle.shed_shared());
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
                        &status_snapshot(&vm_name, &current, shed.load(Ordering::Relaxed)),
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
