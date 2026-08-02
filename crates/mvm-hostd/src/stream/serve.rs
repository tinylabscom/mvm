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

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mvm_core::stream_client::{MAX_BATCH_PAYLOAD_BYTES, StreamBatch, write_batch};
use tracing::warn;

use super::console_source::SharedBroker;
use super::fanout::{DrainedWindow, ReaderHandle};

/// How often a connection re-checks its queue for new records. Short enough
/// that live output feels attached, long enough that an idle follower is not
/// a spin loop.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How often the accept loop wakes to notice a stop request.
const ACCEPT_INTERVAL: Duration = Duration::from_millis(25);

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
    let mut announced = false;
    let mut last_gap = None;
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
            write_batch(&mut socket, &batch)?;
        }
        announced = true;
    }
    Ok(())
}

fn subscribe(broker: &SharedBroker) -> ReaderHandle {
    // A follower that panicked must not silence the broker for everyone
    // else; the broker is plain data across this call.
    broker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .subscribe()
}

/// Cut one drained window into frames no larger than the payload cap.
///
/// Each cut re-anchors on the hash of the record before it, so every frame
/// is independently verifiable and a follower that fell a long way behind
/// does not force one enormous allocation on either end. The gap rides the
/// first frame only: it describes the transition into this window, and
/// repeating it would read as a fresh loss on every frame. `caught_up`
/// likewise rides the last frame only — it is a statement about the queue
/// after the whole window left it.
///
/// Always yields at least one frame. An empty window still has to carry the
/// caught-up marker, or a non-following consumer never learns it is done.
fn split_window(window: &DrainedWindow, caught_up: bool) -> Vec<StreamBatch> {
    let mut batches = Vec::new();
    let mut anchor = window.anchor;
    let mut gap = window.gap;
    let mut start = 0usize;
    let mut bytes = 0usize;
    for (idx, record) in window.records.iter().enumerate() {
        bytes += record.payload.len();
        let last = idx + 1 == window.records.len();
        if bytes < MAX_BATCH_PAYLOAD_BYTES && !last {
            continue;
        }
        let next_anchor = record.hash();
        batches.push(StreamBatch {
            anchor,
            records: window.records[start..=idx].to_vec(),
            gap: gap.take(),
            caught_up: last && caught_up,
        });
        anchor = next_anchor;
        start = idx + 1;
        bytes = 0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    use mvm_core::crypto::aead;
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
            StreamBroker::new("vm", writer, StreamRedaction::curated())
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

    #[test]
    fn a_window_over_the_payload_cap_is_split_into_verifiable_frames() {
        let big = vec![b'x'; MAX_BATCH_PAYLOAD_BYTES / 2 + 1];
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..5u64 {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: big.clone(),
            };
            prev = record.hash();
            records.push(record);
        }
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
                .all(|b| b.payload_bytes() <= MAX_BATCH_PAYLOAD_BYTES * 2)
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
    fn the_gap_rides_only_the_first_frame_of_a_split_window() {
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..4u64 {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: vec![b'y'; MAX_BATCH_PAYLOAD_BYTES],
            };
            prev = record.hash();
            records.push(record);
        }
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
            "a repeated gap reads as a fresh loss"
        );
    }
}
