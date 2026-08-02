//! Republishes the write-only console capture every workload backend already
//! writes to `<state_dir>/console.log` as a second, always-on
//! [`StreamSource::Console`] source over the same broker the guest agent's
//! entrypoint pump feeds.
//!
//! The vsock path has two blind windows: nothing before the guest agent
//! starts, nothing after it dies. A guest that panics on boot, fails
//! dm-verity, or OOMs its agent produces an entirely empty stream on that
//! path — exactly when a user most needs to see what happened. The console
//! capture is already running the whole time (every backend opens it before
//! boot), so following it closes both windows.
//!
//! **Polling, not a watch API.** A held read offset re-checked on an
//! interval behaves identically on macOS and Linux and across all four
//! workload backends; an OS-specific watch (inotify/FSEvents/kqueue) would
//! need a second implementation to keep in sync with the first, for a file
//! that is at most a few kilobytes a second.
//!
//! **Read-only, always.** This module only ever opens the capture file for
//! reading. The console itself has no host input fd by design (a sealed
//! production guest must never gain one); nothing here adds one — it reads a
//! plain file the backend already writes, the same way any other log reader
//! would.
//!
//! **Fails closed on spawn, not open.** [`ConsoleSource::follow`] reports a
//! thread-spawn failure as `Err` rather than panicking. Fd/thread exhaustion
//! is the realistic cause, which is exactly the resource-starved state an
//! operator most needs this stream in — panicking there would take down
//! whatever booted the workload instead of just leaving that one workload
//! without a console stream.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use mvm_protocol::stream::{StreamKind, StreamSource};

use crate::stream::broker::StreamBroker;

/// A [`StreamBroker`] shared between producers. `ingest` takes `&mut self`,
/// and the console follower runs on its own thread alongside whatever else
/// feeds the same VM's broker (the guest agent's entrypoint pump), so two
/// producers need a lock around one instance rather than one broker each —
/// the chain and `seq` are per-broker, not per-source.
pub type SharedBroker = Arc<Mutex<StreamBroker>>;

/// How often the follower re-checks the file for new bytes.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Largest read per poll tick. Bounds one tick's memory use even after the
/// file grew hugely while the follower was busy elsewhere; the remainder is
/// picked up by the next tick(s) — [`run`] does not sleep while a tick made
/// progress, so a backlog drains in bounded chunks rather than one huge read.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// How many further chunks the follower reads after it is told to stop.
///
/// Stop arrives when a VM ends, and the last thing a workload wrote is the
/// part an operator is most likely to be looking for — a panic, a stack
/// trace, an exit message. Returning the instant the flag is seen would leave
/// whatever the final poll interval accumulated unread forever, because
/// nothing reopens a stopped VM's follower.
///
/// Bounded rather than drain-to-end: the file is only guaranteed to stop
/// growing once the VMM is gone, and teardown joins this thread, so an
/// unbounded final drain against a still-writing console would hold the whole
/// host's shutdown open. This many chunks is far more than a console emits in
/// one poll interval and still a hard ceiling on how long stopping can take.
const FINAL_DRAIN_CHUNKS: usize = 64;

/// Follows `path`, ingesting whatever is appended to it into `broker`.
pub struct ConsoleSource;

impl ConsoleSource {
    /// Start following `path` on a dedicated thread. Returns immediately;
    /// `path` need not exist yet — see the module docs on the boot-failure
    /// case this exists for.
    ///
    /// Returns `Err` if the OS refuses to create the follower thread instead
    /// of panicking — fd/thread exhaustion is the realistic cause, and that
    /// is precisely the resource-starved state an operator most needs this
    /// stream in. This function already logs the reason before returning it,
    /// so the failure is visible even to a caller that only matches `Err`
    /// and moves on; a caller must do exactly that (log-and-continue, the
    /// same best-effort contract the runtime's `ConsoleStreamer::start` hook
    /// documents) rather than propagate it into a workload boot failure over
    /// what is, at bottom, an observability feature.
    pub fn follow(path: &Path, broker: SharedBroker) -> io::Result<ConsoleSourceHandle> {
        Self::follow_with(std::thread::Builder::new(), path, broker)
    }

    /// Same as [`follow`](Self::follow), parameterized on the thread
    /// `Builder` to spawn on — the seam a test uses to force a deterministic
    /// spawn failure (an unsatisfiable `stack_size`) without exhausting the
    /// process's real thread/fd limits, which would starve every other test
    /// running alongside it under full-suite parallelism.
    fn follow_with(
        builder: std::thread::Builder,
        path: &Path,
        broker: SharedBroker,
    ) -> io::Result<ConsoleSourceHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let owned_path = path.to_path_buf();
        let thread = match builder
            .name(format!("mvm-console-source-{}", path.display()))
            .spawn(move || run(&owned_path, &broker, &thread_stop))
        {
            Ok(thread) => thread,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "console-source follower thread could not be spawned; \
                     console capture will not be streamed for this workload"
                );
                return Err(err);
            }
        };
        Ok(ConsoleSourceHandle {
            stop,
            thread: Some(thread),
        })
    }
}

/// A running follower. Its `Drop` also stops the thread, so a handle that
/// falls out of scope without an explicit [`stop`](Self::stop) still leaves
/// no thread behind — `stop` is the documented, join-and-confirm way to end
/// it, not the only way it ends.
pub struct ConsoleSourceHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ConsoleSourceHandle {
    /// Stop the follower and wait for it to exit. Every byte the follower
    /// read was ingested synchronously, on the same tick, before the next
    /// read — so nothing already read is discarded by stopping, and the
    /// bounded final drain in [`run`] means bytes written during the last
    /// poll interval are not either.
    pub fn stop(mut self) {
        self.join();
    }

    fn join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // A follower panic is not this caller's problem to propagate;
            // the thread is already gone either way once join returns.
            let _ = thread.join();
        }
    }
}

impl Drop for ConsoleSourceHandle {
    fn drop(&mut self) {
        self.join();
    }
}

/// The follower loop: drain whatever is available, checking `stop` between
/// chunks so a stop signal is honored within one chunk read even under a
/// heavy backlog, then idle-poll once caught up. A stop request takes the
/// bounded final drain on the way out rather than returning on the spot.
fn run(path: &Path, broker: &SharedBroker, stop: &AtomicBool) {
    let mut state = FollowState::default();
    loop {
        while poll_once(path, &mut state, broker) {
            if stop.load(Ordering::Relaxed) {
                return final_drain(path, &mut state, broker);
            }
        }
        if stop.load(Ordering::Relaxed) {
            // Drains here too, not just out of the loop above. A caught-up
            // tick followed by a write and a stop — the exact shape of a
            // workload's last line before teardown — would otherwise exit on
            // a stop flag set after the poll that missed those bytes.
            return final_drain(path, &mut state, broker);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Read out what the console accumulated since the last tick, up to
/// [`FINAL_DRAIN_CHUNKS`]. See that constant for why the last bytes matter
/// most and why the drain is capped rather than run to the end of the file.
fn final_drain(path: &Path, state: &mut FollowState, broker: &SharedBroker) {
    final_drain_with(path, state, broker, FINAL_DRAIN_CHUNKS);
}

/// Same as [`final_drain`], parameterized on the cap — the seam a test uses
/// to exercise the ceiling without writing [`FINAL_DRAIN_CHUNKS`] chunks of
/// real bytes through the redaction seam and the encrypted transcript.
fn final_drain_with(
    path: &Path,
    state: &mut FollowState,
    broker: &SharedBroker,
    max_chunks: usize,
) {
    for _ in 0..max_chunks {
        if !poll_once(path, state, broker) {
            return;
        }
    }
}

/// The follower's held position: the currently-open file (if any), its
/// identity, and how far into it has already been ingested.
#[derive(Default)]
struct FollowState {
    open: Option<OpenFile>,
}

struct OpenFile {
    file: File,
    dev: u64,
    ino: u64,
    offset: u64,
}

/// One poll tick. Returns whether it ingested anything, so [`run`] can keep
/// draining without sleeping while a backlog remains.
///
/// Notices three distinct discontinuities and treats them all the same way —
/// forget the stale position and resume from the file's current content
/// rather than an offset that describes bytes which no longer exist there:
/// the file not existing (yet, or anymore), the file being a different inode
/// at the same path (rotated), and the file being shorter than the held
/// offset (truncated in place). Reading from 0 after any of these is not a
/// replay: nothing at those positions has been ingested since the file was
/// (re)opened.
fn poll_once(path: &Path, state: &mut FollowState, broker: &SharedBroker) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        state.open = None;
        return false;
    };
    let (dev, ino, len) = (meta.dev(), meta.ino(), meta.len());

    let stale = match &state.open {
        None => true,
        Some(open) => open.dev != dev || open.ino != ino || len < open.offset,
    };
    if stale {
        let Ok(file) = File::open(path) else {
            state.open = None;
            return false;
        };
        state.open = Some(OpenFile {
            file,
            dev,
            ino,
            offset: 0,
        });
    }

    let open = state
        .open
        .as_mut()
        .expect("populated by the stale branch above");
    if len <= open.offset {
        return false;
    }
    let want = (len - open.offset).min(READ_CHUNK_BYTES as u64) as usize;
    let mut buf = vec![0u8; want];
    if open.file.seek(SeekFrom::Start(open.offset)).is_err() {
        // The file moved again between the metadata call above and this
        // seek. Drop the handle; the next tick re-evaluates from scratch
        // rather than trust an offset that may no longer mean anything.
        state.open = None;
        return false;
    }
    match open.file.read_exact(&mut buf) {
        Ok(()) => {
            open.offset += want as u64;
            lock_broker(broker).ingest(StreamSource::Console, StreamKind::Stdout, &buf);
            true
        }
        Err(_) => {
            state.open = None;
            false
        }
    }
}

fn lock_broker(broker: &SharedBroker) -> MutexGuard<'_, StreamBroker> {
    broker.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::redact::StreamRedaction;
    use mvm_core::transcript::{CaptureBinding, TranscriptWriter};
    use std::path::PathBuf;
    use std::time::Instant;
    use tempfile::TempDir;

    /// Holds the transcript tempdir alive alongside the broker writing into
    /// it, and the console-log tempdir the follower reads from.
    struct Fixture {
        broker: SharedBroker,
        _capture_dir: TempDir,
        console_dir: TempDir,
    }

    impl Fixture {
        fn console_path(&self) -> PathBuf {
            self.console_dir.path().join("console.log")
        }
    }

    fn broker_fixture(vm: &str) -> Fixture {
        let capture_dir = tempfile::tempdir().expect("capture tempdir");
        let config = crate::stream::broker::stream_capture_config(
            crate::stream::broker::StreamCaptureIdentity {
                capture_id: format!("capture-{vm}"),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: vm.to_string(),
                    session_id: None,
                },
                created_unix_secs: 0,
                recipient: "host:test".to_string(),
                wrapped_data_key_b64: String::new(),
            },
        );
        let writer = TranscriptWriter::new(
            capture_dir.path(),
            mvm_core::crypto::aead::Key::from_bytes([0x5a; 32]),
            config,
        );
        let broker = StreamBroker::new(vm, writer, StreamRedaction::curated());
        Fixture {
            broker: Arc::new(Mutex::new(broker)),
            _capture_dir: capture_dir,
            console_dir: tempfile::tempdir().expect("console tempdir"),
        }
    }

    /// Poll `f` until it returns `Some`, or panic after `bound` — keeps a
    /// timing-dependent assertion from hanging forever on a real failure
    /// while still tolerating scheduler jitter under full-suite parallelism.
    fn wait_for<T>(bound: Duration, mut f: impl FnMut() -> Option<T>) -> T {
        let start = Instant::now();
        loop {
            if let Some(v) = f() {
                return v;
            }
            if start.elapsed() > bound {
                panic!("condition did not become true within {bound:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // --- the required behaviours -----------------------------------------

    #[test]
    fn bytes_appended_after_follow_starts_reach_the_broker_tagged_console() {
        let fx = broker_fixture("vm-a");
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let handle = ConsoleSource::follow(&fx.console_path(), Arc::clone(&fx.broker))
            .expect("follow the console log");

        std::fs::write(fx.console_path(), b"booting kernel...\n").expect("write console log");

        let record = wait_for(Duration::from_secs(5), || reader.recv());
        assert_eq!(record.source, StreamSource::Console);
        assert_eq!(record.payload, b"booting kernel...\n");

        handle.stop();
    }

    #[test]
    fn a_file_that_does_not_exist_yet_is_tolerated_and_picked_up_on_creation() {
        let fx = broker_fixture("vm-b");
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let path = fx.console_path();
        assert!(!path.exists(), "fixture must not pre-create the file");

        let handle =
            ConsoleSource::follow(&path, Arc::clone(&fx.broker)).expect("follow the console log");

        // Give the follower a couple of poll ticks against the absent file —
        // proving it neither panics nor errors out permanently.
        std::thread::sleep(POLL_INTERVAL * 3);
        assert_eq!(fx.broker.lock().unwrap().counters().ingested, 0);

        std::fs::write(&path, b"agent up\n").expect("create console log late");
        let record = wait_for(Duration::from_secs(5), || reader.recv());
        assert_eq!(record.source, StreamSource::Console);
        assert_eq!(record.payload, b"agent up\n");

        handle.stop();
    }

    #[test]
    fn stop_terminates_the_follower_without_losing_already_read_bytes() {
        let fx = broker_fixture("vm-c");
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let path = fx.console_path();
        std::fs::write(&path, b"line one\n").expect("write console log");

        let handle =
            ConsoleSource::follow(&path, Arc::clone(&fx.broker)).expect("follow the console log");
        let record = wait_for(Duration::from_secs(5), || reader.recv());
        assert_eq!(record.payload, b"line one\n");

        handle.stop();

        // The thread is joined by the time `stop` returns: a further append
        // must not be ingested, proving the follower is genuinely gone
        // rather than merely slow.
        std::fs::write(&path, b"line two\n").expect("append after stop");
        std::thread::sleep(POLL_INTERVAL * 3);
        assert_eq!(fx.broker.lock().unwrap().counters().ingested, 1);
    }

    // --- the last thing the workload said ---------------------------------

    #[test]
    fn the_final_drain_takes_a_multi_chunk_backlog_the_stop_check_would_have_cut_short() {
        // A VM ending is exactly when its last words matter: returning on the
        // stop flag mid-backlog would leave a panic and its stack trace on
        // disk and out of the stream forever.
        let fx = broker_fixture("vm-final-drain");
        let path = fx.console_path();
        std::fs::write(&path, vec![b'x'; READ_CHUNK_BYTES * 3]).expect("write a 3-chunk backlog");

        let mut state = FollowState::default();
        final_drain(&path, &mut state, &fx.broker);

        assert_eq!(fx.broker.lock().unwrap().counters().ingested, 3);
        assert_eq!(
            state.open.as_ref().unwrap().offset,
            (READ_CHUNK_BYTES * 3) as u64
        );
    }

    #[test]
    fn the_final_drain_stops_at_its_cap_rather_than_following_a_still_writing_console() {
        // Teardown joins this thread, so an unbounded drain against a console
        // still being written to would hold the whole host's shutdown open.
        let fx = broker_fixture("vm-final-drain-cap");
        let path = fx.console_path();
        std::fs::write(&path, vec![b'x'; READ_CHUNK_BYTES * 3]).expect("write a 3-chunk backlog");

        let mut state = FollowState::default();
        final_drain_with(&path, &mut state, &fx.broker, 2);

        assert_eq!(fx.broker.lock().unwrap().counters().ingested, 2);
    }

    // --- spawn failure ------------------------------------------------------

    /// Before this fix, an unspawnable follower thread panicked via
    /// `.expect(...)` — exactly the fd/thread-exhaustion condition an
    /// operator most needs the console stream for. Forces that OS-level
    /// failure deterministically (an unsatisfiable `stack_size`, which
    /// `std::thread::Builder::spawn` rejects with an `Err` before it ever
    /// asks the OS for real thread/fd resources) rather than by starving the
    /// test process of real threads, which would also wedge every other test
    /// running alongside this one under full-suite parallelism.
    #[test]
    fn follow_returns_err_instead_of_panicking_when_the_thread_cannot_be_spawned() {
        let fx = broker_fixture("vm-spawn-fail");
        let path = fx.console_path();

        let doomed = std::thread::Builder::new().stack_size(usize::MAX);
        let result = ConsoleSource::follow_with(doomed, &path, Arc::clone(&fx.broker));
        assert!(
            result.is_err(),
            "an unspawnable follower thread must surface as Err, not a panic"
        );

        // Not contagious: a normal follow against the same path and broker
        // right after the failed attempt still works, proving nothing was
        // left poisoned or half-initialized by it — the process (and, by
        // extension, the workload that would have booted alongside it) just
        // keeps running.
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let handle = ConsoleSource::follow(&path, Arc::clone(&fx.broker))
            .expect("a normal-stack follow must still succeed");
        std::fs::write(&path, b"still working\n").expect("write console log");
        let record = wait_for(Duration::from_secs(5), || reader.recv());
        assert_eq!(record.payload, b"still working\n");
        handle.stop();
    }

    // --- truncation / rotation --------------------------------------------

    #[test]
    fn a_truncated_file_does_not_replay_old_bytes_and_does_not_wedge() {
        let fx = broker_fixture("vm-d");
        // Subscribed before either poll, so both records are visible here —
        // `subscribe` only sees records ingested after attach.
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let path = fx.console_path();
        std::fs::write(&path, b"aaaaaaaaaa").expect("initial content");

        let mut state = FollowState::default();
        assert!(poll_once(&path, &mut state, &fx.broker));
        assert_eq!(state.open.as_ref().unwrap().offset, 10);

        // Truncate in place: `fs::write` opens the existing path with
        // truncate, so the inode is typically unchanged but the length
        // drops below the held offset.
        std::fs::write(&path, b"bb").expect("truncate to shorter content");

        // Must make progress on the very next tick (no wedge) and must
        // ingest exactly the new content, not the old bytes at the same
        // offsets or any concatenation of the two (no replay).
        assert!(poll_once(&path, &mut state, &fx.broker));
        assert_eq!(state.open.as_ref().unwrap().offset, 2);

        let first = reader.recv().expect("first record");
        let second = reader.recv().expect("second record");
        assert_eq!(first.payload, b"aaaaaaaaaa");
        assert_eq!(second.payload, b"bb");
    }

    #[test]
    fn a_rotated_file_starts_fresh_instead_of_reading_the_old_inode() {
        let fx = broker_fixture("vm-e");
        let mut reader = fx.broker.lock().unwrap().subscribe();
        let path = fx.console_path();
        std::fs::write(&path, b"pre-rotation").expect("initial content");

        let mut state = FollowState::default();
        assert!(poll_once(&path, &mut state, &fx.broker));
        let original_ino = state.open.as_ref().unwrap().ino;

        // Rotate by replacing the path with a new inode (the classic
        // logrotate shape: write elsewhere, then rename over the original —
        // unlike an in-place truncate, the old fd would otherwise keep
        // reading the renamed-away file forever).
        let replacement = fx.console_dir.path().join("console.log.new");
        std::fs::write(&replacement, b"post-rotation").expect("write replacement");
        std::fs::rename(&replacement, &path).expect("rotate over the original path");

        assert!(poll_once(&path, &mut state, &fx.broker));
        let new_ino = state.open.as_ref().unwrap().ino;
        assert_ne!(
            original_ino, new_ino,
            "fixture must actually exercise an inode change"
        );
        assert_eq!(state.open.as_ref().unwrap().offset, 13);

        let first = reader.recv().expect("first record");
        let second = reader.recv().expect("second record");
        assert_eq!(first.payload, b"pre-rotation");
        assert_eq!(second.payload, b"post-rotation");
    }
}
