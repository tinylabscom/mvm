//! The socket a follower connects to: one per VM, serving whatever the
//! broker has fanned out to that follower's queue.
//!
//! Everything policy-shaped happens on the reading side — the `from_seq`
//! resume point, the kind filter, and chain verification all live in the
//! consumer. This end deliberately does none of it. Dropping records here to
//! honour a filter would punch holes in the hash chain the consumer is meant
//! to check, so the window that goes on the wire is always whole and the
//! consumer narrows it after it verifies.
//!
//! **Threads, not tasks.** The broker and its queues are guarded by plain
//! `std::sync::Mutex`, and a blocking accept loop with one thread per
//! follower never holds one of those across an await point. It also matches
//! [`super::console_source`], the module's other long-running poller.
//!
//! **Fails closed on bind, not on connect.** A follower that cannot be
//! served gets a closed connection; the workload keeps running. Losing the
//! stream must never take the VM with it.

use std::io::{self, Write};
use std::ops::Range;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mvm_core::stream_client::{
    MAX_BATCH_PAYLOAD_BYTES, MAX_BATCH_RECORDS, StreamBatch, write_batch,
};
use mvm_protocol::stream::StreamRecord;
use tracing::warn;

use super::console_source::SharedBroker;
use super::fanout::{DrainedWindow, ReaderHandle};

/// How often a connection re-checks its queue for new records. Short enough
/// that live output feels attached, long enough that an idle follower is not
/// a spin loop.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How often the accept loop wakes to notice a stop request.
const ACCEPT_INTERVAL: Duration = Duration::from_millis(25);

/// How long one write to a follower may block before the server re-checks
/// its stop flag.
///
/// A consumer that stops reading without closing fills the socket buffer,
/// and an untimed write there blocks forever. Shutdown joins the follower
/// threads, so an unbounded write is not just a stuck follower — it is a
/// stuck host.
const WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// Socket permissions: owner only. The parent directory is already 0700, but
/// the short `/tmp` fallback namespace a deep worktree path lands in is
/// shared, so the socket states its own access rather than inheriting it.
const SOCKET_MODE: u32 = 0o600;

/// A bound stream socket, serving followers until it is stopped.
///
/// Owns its accept thread. Dropping the handle stops it, so a caller that
/// forgets to call [`StreamServerHandle::stop`] still releases the socket.
pub struct StreamServerHandle {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl StreamServerHandle {
    /// The socket followers connect to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop accepting and unlink the socket. Idempotent with `Drop`.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            // A panicked accept thread has already stopped accepting, which
            // is what this call is for; the socket cleanup below still runs.
            let _ = accept.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for StreamServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Bind `path` and serve `broker`'s output to every follower that connects.
///
/// A stale socket left by a crashed predecessor is reclaimed: if nothing
/// answers on it, it is unlinked and rebound. A socket something *is*
/// answering on is left alone and reported as in use — taking it would
/// silently steal a live VM's followers.
pub fn serve_stream(path: &Path, broker: SharedBroker) -> io::Result<StreamServerHandle> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    reclaim_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;

    let stop = Arc::new(AtomicBool::new(false));
    let accept = spawn_accept_loop(listener, broker, Arc::clone(&stop))?;
    Ok(StreamServerHandle {
        path: path.to_path_buf(),
        stop,
        accept: Some(accept),
    })
}

fn spawn_accept_loop(
    listener: UnixListener,
    broker: SharedBroker,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("mvm-stream-serve".to_string())
        .spawn(move || accept_loop(&listener, &broker, &stop))
        .inspect_err(|error| {
            // Thread exhaustion is the realistic cause, and it is exactly the
            // state an operator needs the stream for. Report it rather than
            // panicking the caller that was trying to boot a workload.
            warn!(%error, "stream socket accept thread could not start");
        })
}

/// A socket file with no listener behind it is debris from a crash. One
/// connect attempt tells the two cases apart.
fn reclaim_stale_socket(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{} is already serving a stream", path.display()),
        ));
    }
    std::fs::remove_file(path)
}

fn accept_loop(listener: &UnixListener, broker: &SharedBroker, stop: &Arc<AtomicBool>) {
    let mut connections: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _addr)) => {
                connections.retain(|handle| !handle.is_finished());
                // Subscribe here, on the accepting thread, not inside the
                // follower it spawns. The broker attaches a reader at the
                // live head, so every record ingested between accept and
                // subscribe is one this follower never sees — and deferring
                // the subscribe onto a fresh thread widens that window to
                // however long the scheduler takes.
                let reader = subscribe(broker);
                match spawn_connection(socket, reader, Arc::clone(stop)) {
                    Ok(handle) => connections.push(handle),
                    Err(error) => warn!(%error, "stream follower thread could not start"),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_INTERVAL),
            Err(error) => {
                warn!(%error, "stream socket accept failed");
                thread::sleep(ACCEPT_INTERVAL);
            }
        }
    }
    for handle in connections {
        let _ = handle.join();
    }
}

fn spawn_connection(
    socket: UnixStream,
    reader: ReaderHandle,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("mvm-stream-follower".to_string())
        .spawn(move || {
            if let Err(error) = serve_follower(socket, reader, &stop) {
                // A follower hanging up mid-write is ordinary, not an
                // incident: `mvmctl logs` exiting looks exactly like this.
                warn!(%error, "stream follower disconnected");
            }
        })
}

/// Serve one follower until it hangs up or the server stops.
fn serve_follower(
    mut socket: UnixStream,
    mut reader: ReaderHandle,
    stop: &AtomicBool,
) -> io::Result<()> {
    // `accept` does not normalise the listener's non-blocking flag the same
    // way on every platform: inherited, every write past a full send buffer
    // fails on the spot and truncates a follower that was merely reading
    // slowly. So state both — blocking, with a timeout that is what actually
    // bounds a write and lets the loop below notice a stop request.
    socket.set_nonblocking(false)?;
    socket.set_write_timeout(Some(WRITE_TIMEOUT))?;

    let mut announced = false;
    let mut last_gap = None;
    let mut frame = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        let window = reader.drain_verified();
        let moved = window.gap != last_gap;
        last_gap = window.gap;
        // Say nothing when there is nothing to say — except the first time
        // round, because a non-following consumer waits for a caught-up
        // marker and a VM that has produced no output yet would hang it.
        if window.records.is_empty() && !moved && announced {
            thread::sleep(POLL_INTERVAL);
            continue;
        }
        let caught_up = reader.is_empty();
        for batch in split_window(&window, caught_up) {
            frame.clear();
            write_batch(&mut frame, &batch)?;
            if !send_frame(&mut socket, &frame, stop)? {
                return Ok(());
            }
        }
        announced = true;
    }
    Ok(())
}

/// Write one whole frame, or report that the server stopped mid-way.
///
/// Resumes from the byte it reached rather than re-issuing the frame: a
/// timed-out write reports how much it sent, and starting over would splice
/// a duplicate prefix into the follower's stream. Between attempts it
/// re-checks the stop flag, so a consumer that stopped reading without
/// closing cannot hold shutdown open. Abandoning mid-frame leaves that
/// consumer a short read — which it was not reading anyway, and which is
/// what the alternative of waiting on it costs the whole host.
fn send_frame<W: Write>(socket: &mut W, frame: &[u8], stop: &AtomicBool) -> io::Result<bool> {
    let mut sent = 0usize;
    while sent < frame.len() {
        if stop.load(Ordering::SeqCst) {
            return Ok(false);
        }
        match socket.write(&frame[sent..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => sent += n,
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    socket.flush()?;
    Ok(true)
}

/// A write that made no progress but left the connection usable: the send
/// timeout expired, or a signal interrupted the syscall.
fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn subscribe(broker: &SharedBroker) -> ReaderHandle {
    // A follower that panicked must not silence the broker for everyone
    // else; the broker is plain data across this call.
    broker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .subscribe()
}

/// Cut one drained window into frames the wire contract allows.
///
/// Each cut re-anchors on the hash of the record before it, so every frame
/// is independently verifiable and a follower that fell a long way behind
/// does not force one enormous allocation on either end.
///
/// The gap rides the first frame only: it describes the transition into
/// this window, and a consumer folds it cumulatively — a later frame
/// arriving without one means "no new loss", not "recovered". `caught_up`
/// likewise rides the last frame only — it is a statement about the queue
/// after the whole window left it.
///
/// Always yields at least one frame. An empty window still has to carry the
/// caught-up marker, or a non-following consumer never learns it is done.
fn split_window(window: &DrainedWindow, caught_up: bool) -> Vec<StreamBatch> {
    let runs = frame_runs(&window.records);
    let last = runs.len().saturating_sub(1);
    let mut anchor = window.anchor;
    let mut gap = window.gap;
    let mut batches = Vec::with_capacity(runs.len().max(1));
    for (idx, run) in runs.into_iter().enumerate() {
        let records = window.records[run].to_vec();
        let next_anchor = records.last().map_or(anchor, StreamRecord::hash);
        batches.push(StreamBatch {
            anchor,
            records,
            gap: gap.take(),
            caught_up: idx == last && caught_up,
        });
        anchor = next_anchor;
    }
    if batches.is_empty() {
        batches.push(StreamBatch {
            anchor,
            records: Vec::new(),
            gap,
            caught_up,
        });
    }
    batches
}

/// Cut `records` into runs, one frame's worth each.
///
/// A run closes *before* the record that would overflow it, so a frame
/// exceeds `MAX_BATCH_PAYLOAD_BYTES` only when a single record does on its
/// own — a record is atomic, so that is the one case a cut cannot help
/// with. Closing after the overflowing record instead would let every frame
/// run a full record over the cap the reading side sizes its frame gate
/// against.
///
/// Runs are capped by count as well as by bytes. With byte-sized writes the
/// payload bound alone leaves the record count — and the per-record JSON
/// metadata that dominates such a frame — unbounded.
fn frame_runs(records: &[StreamRecord]) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0usize;
    let mut bytes = 0usize;
    for (idx, record) in records.iter().enumerate() {
        let over_bytes = bytes + record.payload.len() > MAX_BATCH_PAYLOAD_BYTES;
        let over_count = idx - start >= MAX_BATCH_RECORDS;
        if idx > start && (over_bytes || over_count) {
            runs.push(start..idx);
            start = idx;
            bytes = 0;
        }
        bytes += record.payload.len();
    }
    if start < records.len() {
        runs.push(start..records.len());
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    use mvm_core::crypto::aead;
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::stream_client::{
        FramedStreamReader, KindFilter, StreamOpts, StreamReader, connect_stream_at,
    };
    use mvm_core::transcript::{CaptureBinding, CaptureBounds, TranscriptWriter};
    use mvm_protocol::stream::{StreamKind, StreamRecord, StreamSource};

    use crate::stream::broker::{StreamBroker, StreamCaptureIdentity, stream_capture_config};
    use crate::stream::fanout::DEFAULT_READER_BOUNDS;
    use crate::stream::redact::StreamRedaction;

    /// A broker configured the way production configures one: the single
    /// `stream_capture_config` door, over a real encrypted transcript dir.
    fn broker_in(dir: &Path) -> SharedBroker {
        broker_with_reader_bounds(dir, DEFAULT_READER_BOUNDS)
    }

    fn broker_with_reader_bounds(dir: &Path, reader_bounds: CaptureBounds) -> SharedBroker {
        let identity = StreamCaptureIdentity {
            capture_id: "capture-vm".to_string(),
            binding: CaptureBinding {
                tenant_id: "local".to_string(),
                vm_name: "vm".to_string(),
                session_id: None,
            },
            created_unix_secs: 0,
            recipient: "host:test".to_string(),
            wrapped_data_key_b64: String::new(),
        };
        let writer = TranscriptWriter::new(
            dir.join("transcript"),
            aead::Key::from_bytes([0x5a; 32]),
            stream_capture_config(identity),
        );
        Arc::new(Mutex::new(
            StreamBroker::new(
                "vm",
                writer,
                StreamRedaction::curated(&RedactionPolicy::default()),
            )
            .with_reader_bounds(reader_bounds),
        ))
    }

    fn feed(broker: &SharedBroker, kind: StreamKind, bytes: &[u8]) {
        broker
            .lock()
            .expect("broker lock")
            .ingest(StreamSource::Entrypoint, kind, bytes);
    }

    /// Block until `want` followers have attached.
    ///
    /// `connect` returns as soon as the socket is queued in the listen
    /// backlog, which is before the server has subscribed — and a broker
    /// attaches a reader at the *live head*, so anything ingested in that
    /// window is genuinely not this follower's to see. Feeding before the
    /// subscription lands would make these tests race the scheduler rather
    /// than test the server.
    fn wait_for_readers(broker: &SharedBroker, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if broker.lock().expect("broker lock").reader_count() >= want {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("only {want} followers never attached");
    }

    /// Read until `want` records arrive or the deadline passes. A follower
    /// polls, so a fixed sleep would either flake or slow the suite.
    fn read_until(reader: &mut dyn StreamReader, want: usize) -> Vec<StreamRecord> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut out = Vec::new();
        while out.len() < want && Instant::now() < deadline {
            match reader.next_record().expect("reader must not fail") {
                Some(record) => out.push(record),
                None => break,
            }
        }
        out
    }

    #[test]
    fn a_follower_reads_records_the_broker_ingested_after_it_attached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server = serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker))
            .expect("bind stream socket");

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = connect_stream_at(server.path(), opts).expect("connect");
        wait_for_readers(&broker, 1);
        feed(&broker, StreamKind::Stdout, b"one");
        feed(&broker, StreamKind::Stderr, b"two");

        let got = read_until(reader.as_mut(), 2);
        assert_eq!(got.len(), 2, "got {got:?}");
        assert_eq!(got[0].payload, b"one");
        assert_eq!(got[1].payload, b"two");
        assert_eq!(got[1].kind, StreamKind::Stderr);
        server.stop();
    }

    #[test]
    fn a_non_following_follower_terminates_when_it_is_caught_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        let mut reader = connect_stream_at(server.path(), StreamOpts::default()).expect("connect");
        // Nothing was ever ingested: the read must end, not hang.
        assert_eq!(reader.next_record().expect("no error"), None);
        server.stop();
    }

    #[test]
    fn a_pruned_window_verifies_through_the_client_with_no_anchor_in_the_api() {
        // The property the anchored check exists for, end to end over the
        // real broker: a follower falls behind, its oldest records are
        // evicted, and the survivors still verify — with the consumer only
        // ever calling `next_record`.
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_with_reader_bounds(
            dir.path(),
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 4,
            },
        );

        // Attach a follower that never drains, then overrun its ring.
        let mut starved = broker.lock().expect("broker lock").subscribe();
        for seq in 0..12u64 {
            feed(
                &broker,
                StreamKind::Stdout,
                format!("line-{seq}").as_bytes(),
            );
        }
        let window = starved.drain_verified();
        let gap = window.gap.expect("the follower fell behind");
        assert_eq!(window.records.len(), 4);
        assert!(gap.dropped_chunks >= 8);

        // Hand the pruned window to the consumer through the real wire.
        let mut framed = Vec::new();
        for batch in split_window(&window, true) {
            write_batch(&mut framed, &batch).expect("frame");
        }
        let mut reader = FramedStreamReader::new(framed.as_slice(), StreamOpts::default());
        let seqs: Vec<u64> = read_until(&mut reader, 4).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![8, 9, 10, 11]);
        assert_eq!(reader.gap().map(|g| g.after_seq), Some(7));
    }

    #[test]
    fn a_kind_filter_narrows_what_the_consumer_sees_not_what_is_verified() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        let opts = StreamOpts::builder()
            .follow(true)
            .kinds(KindFilter::only(StreamKind::Stderr))
            .build();
        let mut reader = connect_stream_at(server.path(), opts).expect("connect");
        wait_for_readers(&broker, 1);
        feed(&broker, StreamKind::Stdout, b"noise");
        feed(&broker, StreamKind::Stderr, b"signal");
        feed(&broker, StreamKind::Stdout, b"more noise");
        feed(&broker, StreamKind::Stderr, b"more signal");

        let got = read_until(reader.as_mut(), 2);
        assert_eq!(got.len(), 2, "got {got:?}");
        assert!(got.iter().all(|r| r.kind == StreamKind::Stderr));
        assert_eq!(got[0].payload, b"signal");
        assert_eq!(got[1].payload, b"more signal");
        server.stop();
    }

    #[test]
    fn from_seq_resumes_over_a_live_connection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        let opts = StreamOpts::builder().follow(true).from_seq(3).build();
        let mut reader = connect_stream_at(server.path(), opts).expect("connect");
        wait_for_readers(&broker, 1);
        for seq in 0..6u64 {
            feed(&broker, StreamKind::Stdout, format!("{seq}").as_bytes());
        }
        let seqs: Vec<u64> = read_until(reader.as_mut(), 3)
            .iter()
            .map(|r| r.seq)
            .collect();
        assert_eq!(seqs, vec![3, 4, 5]);
        server.stop();
    }

    #[test]
    fn two_followers_each_get_the_whole_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        let opts = StreamOpts::builder().follow(true).build();
        let mut first = connect_stream_at(server.path(), opts).expect("first connect");
        let mut second = connect_stream_at(server.path(), opts).expect("second connect");
        wait_for_readers(&broker, 2);
        feed(&broker, StreamKind::Stdout, b"shared");

        assert_eq!(read_until(first.as_mut(), 1)[0].payload, b"shared");
        assert_eq!(read_until(second.as_mut(), 1)[0].payload, b"shared");
        server.stop();
    }

    #[test]
    fn stopping_the_server_unlinks_the_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let path = dir.path().join("stream.sock");
        let server = serve_stream(&path, broker).expect("bind");
        assert!(path.exists());
        server.stop();
        assert!(!path.exists());
    }

    #[test]
    fn the_socket_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let path = dir.path().join("stream.sock");
        let server = serve_stream(&path, broker).expect("bind");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, SOCKET_MODE, "mode was {:o}", mode & 0o777);
        server.stop();
    }

    #[test]
    fn a_stale_socket_from_a_dead_server_is_reclaimed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stream.sock");
        // Debris: a socket file nothing is listening on.
        drop(UnixListener::bind(&path).expect("bind debris"));
        assert!(path.exists());
        let server = serve_stream(&path, broker_in(dir.path())).expect("rebind over debris");
        server.stop();
    }

    #[test]
    fn a_live_socket_is_never_stolen_from_the_server_holding_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stream.sock");
        let first = serve_stream(&path, broker_in(dir.path())).expect("first bind");
        let Err(err) = serve_stream(&path, broker_in(dir.path())) else {
            panic!("a second server must not take a live socket");
        };
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        first.stop();
    }

    /// A real chain of `count` records, each carrying `payload_len` bytes.
    fn chained(count: u64, payload_len: usize) -> Vec<StreamRecord> {
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..count {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: vec![b'x'; payload_len],
            };
            prev = record.hash();
            records.push(record);
        }
        records
    }

    #[test]
    fn a_window_over_the_payload_cap_is_split_into_verifiable_frames() {
        let records = chained(5, MAX_BATCH_PAYLOAD_BYTES / 2 + 1);
        let batches = split_window(
            &DrainedWindow {
                records,
                anchor: [0u8; 32],
                gap: None,
            },
            true,
        );
        assert!(batches.len() > 1, "one huge frame was not split");
        assert!(
            batches
                .iter()
                .all(|b| b.payload_bytes() <= MAX_BATCH_PAYLOAD_BYTES)
        );
        assert_eq!(
            batches.iter().filter(|b| b.caught_up).count(),
            1,
            "only the final frame marks caught up"
        );

        let mut framed = Vec::new();
        for batch in &batches {
            write_batch(&mut framed, batch).expect("frame");
        }
        let mut reader = FramedStreamReader::new(framed.as_slice(), StreamOpts::default());
        let seqs: Vec<u64> = read_until(&mut reader, 5).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4], "every split frame verified");
    }

    #[test]
    fn a_frame_never_runs_a_whole_record_over_the_payload_cap() {
        // Cutting *after* the record that overflows, rather than before it,
        // puts every frame up to a full record over the cap the reading side
        // sizes its frame gate against.
        let records = chained(9, MAX_BATCH_PAYLOAD_BYTES / 3 + 1);
        let batches = split_window(
            &DrainedWindow {
                records,
                anchor: [0u8; 32],
                gap: None,
            },
            true,
        );
        for batch in &batches {
            assert!(
                batch.payload_bytes() <= MAX_BATCH_PAYLOAD_BYTES,
                "frame carried {} bytes",
                batch.payload_bytes()
            );
        }
    }

    #[test]
    fn a_record_bigger_than_the_cap_travels_alone_rather_than_being_split() {
        // A record is atomic — the chain covers it whole — so this is the one
        // case a cut cannot help with, and the frame gate is sized for it.
        let mut records = chained(1, 8);
        let mut oversized = chained(2, MAX_BATCH_PAYLOAD_BYTES + 4_096);
        oversized[1].prev_hash = oversized[0].hash();
        records.extend(oversized);
        let batches = split_window(
            &DrainedWindow {
                records,
                anchor: [0u8; 32],
                gap: None,
            },
            true,
        );
        assert_eq!(
            batches.len(),
            3,
            "each oversized record needs its own frame"
        );
        assert_eq!(batches[1].records.len(), 1);
        assert_eq!(batches[2].records.len(), 1);
    }

    #[test]
    fn the_record_bound_splits_a_window_the_byte_bound_never_would() {
        // Byte-sized writes: the payload cap is nowhere near, but the
        // per-record JSON metadata is what a frame is then made of.
        let records = chained(MAX_BATCH_RECORDS as u64 + 10, 1);
        let batches = split_window(
            &DrainedWindow {
                records,
                anchor: [0u8; 32],
                gap: None,
            },
            true,
        );
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].records.len(), MAX_BATCH_RECORDS);
        assert_eq!(batches[1].records.len(), 10);
    }

    #[test]
    fn the_gap_rides_only_the_first_frame_of_a_split_window() {
        let records = chained(4, MAX_BATCH_PAYLOAD_BYTES);
        let gap = mvm_core::transcript::GapMarker {
            after_seq: 9,
            dropped_chunks: 3,
            dropped_bytes: 12,
        };
        let batches = split_window(
            &DrainedWindow {
                records,
                anchor: [1u8; 32],
                gap: Some(gap),
            },
            true,
        );
        assert!(batches.len() > 1);
        assert_eq!(batches[0].gap, Some(gap));
        assert!(
            batches[1..].iter().all(|b| b.gap.is_none()),
            "the marker describes the transition into the window, once"
        );
    }

    #[test]
    fn a_window_after_a_split_gapped_one_verifies_instead_of_reading_as_tampering() {
        // What an ordinary chatty workload does: a follower overruns its byte
        // bound, so its next drain is a gapped window too big for one frame.
        // The marker rides the first frame, the queue's marker is cumulative
        // and its anchor does not move again — so the *next* window repeats
        // that marker beside an anchor from far behind the records in hand.
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let mut follower = broker.lock().expect("broker lock").subscribe();

        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..20 {
            feed(&broker, StreamKind::Stdout, &chunk);
        }
        let first = follower.drain_verified();
        assert!(first.gap.is_some(), "the follower must have fallen behind");
        assert!(
            first.records.iter().map(|r| r.payload.len()).sum::<usize>() > MAX_BATCH_PAYLOAD_BYTES,
            "the window must be big enough to split"
        );

        // The drain emptied the queue, so nothing else is lost: the second
        // window carries the same cumulative marker over the same anchor.
        for _ in 0..2 {
            feed(&broker, StreamKind::Stdout, &chunk);
        }
        let second = follower.drain_verified();
        assert_eq!(second.gap, first.gap, "no new loss between the windows");
        assert_eq!(
            second.anchor, first.anchor,
            "and so the anchor did not move"
        );

        let first_frames = split_window(&first, false);
        let second_frames = split_window(&second, true);
        assert!(first_frames.len() > 1, "the first window must have split");
        let mut framed = Vec::new();
        for batch in first_frames.iter().chain(second_frames.iter()) {
            write_batch(&mut framed, batch).expect("frame");
        }

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(framed.as_slice(), opts);
        let mut got = Vec::new();
        loop {
            match reader.next_record() {
                Ok(Some(record)) => got.push(record),
                Ok(None) => break,
                Err(err) => panic!("the second window must verify, not error: {err}"),
            }
        }
        assert_eq!(got.len(), first.records.len() + second.records.len());
        assert_eq!(
            reader.gap(),
            first.gap,
            "the loss stays reported across the split"
        );
    }

    /// A writer that never takes a byte, the way a socket whose buffer is
    /// full behaves once the send timeout expires. Flips the stop flag on its
    /// way past `stop_after` so the retry loop has something to notice.
    struct WedgedWriter<'a> {
        attempts: usize,
        stop_after: usize,
        stop: &'a AtomicBool,
    }

    impl Write for WedgedWriter<'_> {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            self.attempts += 1;
            if self.attempts >= self.stop_after {
                self.stop.store(true, Ordering::SeqCst);
            }
            Err(io::ErrorKind::TimedOut.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that takes a few bytes, then stalls, then takes a few more —
    /// the shape a nearly-full socket buffer produces.
    #[derive(Default)]
    struct DribbleWriter {
        written: Vec<u8>,
        stalling: bool,
    }

    impl Write for DribbleWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stalling = !self.stalling;
            if self.stalling {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let take = buf.len().min(3);
            self.written.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_that_keeps_timing_out_yields_to_the_stop_flag() {
        let stop = AtomicBool::new(false);
        let mut writer = WedgedWriter {
            attempts: 0,
            stop_after: 3,
            stop: &stop,
        };
        let served =
            send_frame(&mut writer, b"a frame", &stop).expect("a timeout is not a transport error");
        assert!(!served, "the frame was abandoned, not delivered");
        assert!(writer.attempts >= 3, "the write must retry, not give up");
    }

    #[test]
    fn a_partially_written_frame_resumes_rather_than_restarting() {
        // Re-issuing the frame from byte zero would splice a duplicate prefix
        // into the follower's stream, which reads as a malformed frame.
        let stop = AtomicBool::new(false);
        let frame = b"length-prefixed-body-bytes".to_vec();
        let mut writer = DribbleWriter::default();
        assert!(send_frame(&mut writer, &frame, &stop).expect("write"));
        assert_eq!(writer.written, frame);
    }

    #[test]
    fn a_burst_larger_than_the_socket_buffer_reaches_the_follower_whole() {
        // `accept` may hand back a socket carrying the listener's
        // non-blocking flag, and an untimed `write_all` on one of those fails
        // the instant the send buffer fills — dropping a follower that was
        // only reading a little slower than the producer writes.
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = connect_stream_at(server.path(), opts).expect("connect");
        wait_for_readers(&broker, 1);

        // Far past any platform's default AF_UNIX buffer, and well inside the
        // reader ring so nothing is dropped for falling behind either.
        let chunk = vec![b'x'; 32 * 1024];
        for _ in 0..16 {
            feed(&broker, StreamKind::Stdout, &chunk);
        }

        let got = read_until(reader.as_mut(), 16);
        assert_eq!(got.len(), 16, "the follower was dropped mid-burst");
        server.stop();
    }

    #[test]
    fn a_follower_that_stops_reading_cannot_wedge_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = broker_in(dir.path());
        let server =
            serve_stream(&dir.path().join("stream.sock"), Arc::clone(&broker)).expect("bind");

        // Connect and never read: the socket buffer fills and the server's
        // write to this follower blocks with nobody draining the other end.
        let _wedged = UnixStream::connect(server.path()).expect("connect");
        wait_for_readers(&broker, 1);
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..24 {
            feed(&broker, StreamKind::Stdout, &chunk);
        }
        thread::sleep(Duration::from_millis(200));

        // `stop` joins the accept thread, which joins the followers, so an
        // unbounded write in one of them is an unbounded shutdown.
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            server.stop();
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(20))
            .expect("shutdown must not wait on a consumer that stopped reading");
    }
}
