//! The durable half of an ingest: the transcript append, off the producer's
//! thread.
//!
//! An append is a stat, an open, a write and a close against whatever the
//! host's disk is doing at that moment — measured at 20 µs for a 64-byte
//! record where redacting, chaining and fanning it out together cost 0.1 µs.
//! For the entrypoint source the producer *is* the RPC read thread, so paying
//! that inline makes the guest's pace a function of the host's disk: the wire
//! backs up and the guest's own retention ring starts evicting output nobody
//! asked it to drop.
//!
//! So the append runs on a per-broker writer thread behind a bounded queue,
//! and — this is the part that matters — **the bound sheds, it does not
//! wait**. A queue that blocks when it fills is a slow disk stalling the
//! workload, which is the stalled-reader failure with a different door. The
//! fan-out already made this call: it evicts its oldest and records the loss.
//! Here the newest record is the one dropped, because the writer has already
//! taken the older ones.
//!
//! Nothing shed is silent. [`DurableCounts::shed_chunks`] and its byte total
//! fold into the sealed manifest's `refused_chunks`/`refused_bytes` at
//! [`DurableSink::seal`], so `TranscriptManifest::is_truncated` reports a
//! transcript that lost records rather than handing back an artifact that
//! verifies clean while being quietly incomplete.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mvm_core::transcript::{Direction, TranscriptManifest, TranscriptWriter, sealed_root_hex};
use mvm_protocol::stream::{StreamKind, StreamRecord};

use crate::stream::journal::{CaptureJournal, JournalShortfall};

/// Records the writer thread may fall behind before the hand-off starts
/// dropping.
///
/// Sized against the guest's own retention ring rather than a round number:
/// the guest's pump holds at most `1 MiB / 4 KiB` events per byte stream
/// before it starts evicting, so a host queue that deep means a burst the
/// guest can hold is a burst the host takes without losing any of it. Past it
/// the transcript loses its newest records and says so, which is the only
/// remaining option once waiting is off the table.
pub(in crate::stream) const DURABLE_QUEUE_DEPTH: usize = 256;

/// Work handed to a broker's durable writer thread.
enum PersistJob {
    /// Append this record's payload to the transcript. The record is shared
    /// rather than copied — the fan-out already holds it behind an `Arc`.
    Chunk(Arc<StreamRecord>),
    /// Answer once every earlier job has been taken. A test asserting on what
    /// landed needs a point at which "queued" and "written" are the same
    /// thing; nothing in production waits on the store.
    #[cfg(test)]
    Drained(SyncSender<()>),
}

impl PersistJob {
    /// The record this job wants appended, if it carries one. Answering a
    /// drain request is the other thing a job can be, and it is done here so
    /// the writer loop has one shape whatever the queue is carrying.
    fn record(self) -> Option<Arc<StreamRecord>> {
        match self {
            Self::Chunk(record) => Some(record),
            #[cfg(test)]
            Self::Drained(done) => {
                let _ = done.send(());
                None
            }
        }
    }
}

/// Counters the durable half keeps. Atomics because the thread that writes
/// them is not the thread that reads them, and because the two producers
/// differ: the writer thread owns what the store refused, the ingesting thread
/// owns what the hand-off shed.
#[derive(Debug, Default)]
struct PersistCounters {
    /// Records the store would not take.
    refused: AtomicU64,
    /// Transitions into a store outage, so the log carries one line per outage
    /// rather than one per record.
    lapses: AtomicU64,
    /// Records dropped at the hand-off because the writer was a full queue
    /// behind.
    shed_chunks: AtomicU64,
    /// Plaintext bytes in `shed_chunks`, so the seal can carry the same
    /// shortfall the store's own refusals get.
    shed_bytes: AtomicU64,
    /// Whether the hand-off is currently dropping. Same reason as `lapses`:
    /// the transition is what gets logged.
    shedding: AtomicBool,
    /// Every record ever offered to [`DurableSink::push`], regardless of what
    /// happened to it. Kept independent of the writer's own bookkeeping
    /// because [`DurableSink::seal`]'s degraded path cannot read the writer
    /// at all — this is the one count it can still trust.
    total: AtomicU64,
    /// Plaintext bytes in `total`.
    total_bytes: AtomicU64,
}

/// What the durable half has done, for a caller assembling broker counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(in crate::stream) struct DurableCounts {
    /// Records the store refused.
    pub refused: u64,
    /// Transitions into a store outage.
    pub lapses: u64,
    /// Records the hand-off dropped rather than wait for the writer.
    pub shed_chunks: u64,
}

impl DurableCounts {
    /// Records that never reached the transcript, whichever end lost them.
    /// Equal, by construction, to the sealed manifest's `refused_chunks`.
    pub fn missing(self) -> u64 {
        self.refused.saturating_add(self.shed_chunks)
    }
}

/// The durable half of an ingest, off the producer's thread.
pub(in crate::stream) struct DurableSink {
    vm: String,
    /// Shared with the writer thread. The sink only takes it to seal, and only
    /// after that thread has joined.
    writer: Arc<Mutex<TranscriptWriter>>,
    /// A fresh, chunkless manifest for this capture, captured before `writer`
    /// ever moved behind the lock. [`seal`](Self::seal)'s degraded path reads
    /// this instead of `writer` when the writer thread never releases it —
    /// the one manifest shape this sink can produce without touching a lock
    /// that may be held by a disk syscall that is never coming back.
    seed: TranscriptManifest,
    /// `None` if the writer thread could not be spawned, or once it has
    /// stopped taking work. Either way `push` sheds rather than falling back
    /// to an inline write — see the module docs.
    jobs: Option<SyncSender<PersistJob>>,
    worker: Option<JoinHandle<()>>,
    counters: Arc<PersistCounters>,
    /// The journal the writer thread mirrors landed chunks into, so a process
    /// that did not open this capture can still seal it. Held here only to
    /// unlink it once a manifest supersedes it — the file itself belongs to
    /// the writer thread.
    journal_path: PathBuf,
}

impl DurableSink {
    pub fn new(vm: &str, writer: TranscriptWriter) -> Self {
        // Taken before the writer moves behind the lock: an empty manifest is
        // cheap to build and is the only state `seal` can still hand back if
        // that lock is never released. The journal mirrors the same seed.
        let seed = writer.sealed_manifest();
        let journal = CaptureJournal::new(writer.dir(), seed.clone());
        let journal_path = journal.path().to_path_buf();
        let writer = Arc::new(Mutex::new(writer));
        let counters = Arc::new(PersistCounters::default());
        let (jobs, inbox) = sync_channel(DURABLE_QUEUE_DEPTH);
        let worker = spawn_writer(
            vm,
            WriterThread {
                writer: Arc::clone(&writer),
                counters: Arc::clone(&counters),
                journal,
            },
            inbox,
        );
        Self {
            vm: vm.to_string(),
            writer,
            seed,
            journal_path,
            // A thread that would not start must not cost the capture its
            // transcript by pulling the disk onto the producer's own thread:
            // without one, `push` sheds every record, same as a full queue.
            jobs: worker.as_ref().map(|_| jobs),
            worker,
            counters,
        }
    }

    /// A sink with no writer thread at all, as if [`spawn_writer`] had
    /// failed — the thread-table-exhaustion case a real spawn failure cannot
    /// be made to happen on demand.
    #[cfg(test)]
    fn new_without_writer_thread(vm: &str, writer: TranscriptWriter) -> Self {
        let seed = writer.sealed_manifest();
        let journal_path = writer.dir().join(crate::stream::journal::JOURNAL_FILENAME);
        Self {
            vm: vm.to_string(),
            writer: Arc::new(Mutex::new(writer)),
            seed,
            journal_path,
            jobs: None,
            worker: None,
            counters: Arc::new(PersistCounters::default()),
        }
    }

    /// Hand one record to the writer, or drop it. Never waits, and never
    /// touches the disk itself: whether there is no writer thread to hand
    /// this to, or its queue is full, or the thread has already died, the
    /// answer is the same shed a full queue gets, accounted the same way.
    /// Writing inline here would put the producer's own thread behind
    /// whatever the disk is doing at that moment — the exact stall this
    /// whole module exists to remove, reached through the one door that
    /// used to bypass it.
    pub fn push(&self, record: &Arc<StreamRecord>) {
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        self.counters
            .total_bytes
            .fetch_add(record.payload.len() as u64, Ordering::Relaxed);
        let Some(jobs) = self.jobs.as_ref() else {
            return note_shed(&self.vm, &self.counters, record);
        };
        match jobs.try_send(PersistJob::Chunk(Arc::clone(record))) {
            Ok(()) => note_handed_over(&self.vm, &self.counters),
            Err(TrySendError::Full(_)) => note_shed(&self.vm, &self.counters, record),
            // The writer thread is gone; the shed path applies here too.
            Err(TrySendError::Disconnected(_)) => note_shed(&self.vm, &self.counters, record),
        }
    }

    /// Block until every record pushed so far has reached the writer.
    #[cfg(test)]
    pub fn drain(&self) {
        let Some(jobs) = self.jobs.as_ref() else {
            return; // no writer thread: `push` sheds, nothing is ever queued
        };
        let (done, wait) = sync_channel(1);
        if jobs.send(PersistJob::Drained(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// The lock the writer thread takes for every append.
    ///
    /// Test-only: holding it is how a test stands in for a disk that stopped
    /// answering, which is the one way to observe the hand-off shedding.
    #[cfg(test)]
    pub fn writer_lock(&self) -> Arc<Mutex<TranscriptWriter>> {
        Arc::clone(&self.writer)
    }

    pub fn counts(&self) -> DurableCounts {
        DurableCounts {
            refused: self.counters.refused.load(Ordering::Relaxed),
            lapses: self.counters.lapses.load(Ordering::Relaxed),
            shed_chunks: self.counters.shed_chunks.load(Ordering::Relaxed),
        }
    }

    /// Stop taking work, wait — up to a bound — for what is queued to land,
    /// and seal.
    ///
    /// This runs on whatever thread tears the VM down
    /// (`ConsoleStreamer::stop` → `release`), so it cannot wait out a
    /// genuinely hung disk: the writer thread holds `writer`'s lock for the
    /// length of its blocking append, and a syscall stuck in the kernel is
    /// not something this process can interrupt. Past
    /// [`SEAL_JOIN_TIMEOUT`] this gives up on ever reading that writer again
    /// and reports the whole capture as unwritten instead — the shed
    /// hand-off's own rule ("an honest hole beats a stall"), extended to the
    /// one thing it didn't cover: the writer itself never finishing.
    pub fn seal(mut self) -> TranscriptManifest {
        self.jobs = None;
        let joined = match self.worker.take() {
            Some(worker) => wait_for_writer(worker, SEAL_JOIN_TIMEOUT),
            None => true,
        };
        // The journal exists so a *different* process can seal this capture.
        // This one just did, and leaving the mirror behind would invite a
        // later stop to adopt a capture that already has a manifest. Only on
        // the joined path: a writer still running owns that file.
        if joined {
            CaptureJournal::discard(&self.journal_path);
        }
        if !joined {
            tracing::warn!(
                vm = %self.vm,
                "durable writer did not exit within the seal deadline; this capture's \
                 transcript is reported as fully unwritten rather than block VM teardown on \
                 a disk that may never answer"
            );
            return self.degraded_manifest();
        }
        let mut writer = lock_writer(&self.writer);
        // Records shed at the hand-off never reached the writer, so it cannot
        // have counted them. Folding them in before the root is computed is
        // what puts the whole shortfall inside the sealed manifest instead of
        // only the part the store saw.
        writer.note_unwritten(
            self.counters.shed_chunks.load(Ordering::Relaxed),
            self.counters.shed_bytes.load(Ordering::Relaxed),
        );
        writer.sealed_manifest()
    }

    /// The manifest for a writer this sink gave up waiting on: no chunks,
    /// because none can be vouched for without the lock, and every record
    /// this sink was ever handed counted as refused — `total` rather than
    /// just `shed_chunks`, because some of what the wedged writer already
    /// took before it stopped answering may in fact be sitting on disk, and
    /// this manifest cannot tell which. Declaring all of it missing is the
    /// direction that never overclaims completeness.
    fn degraded_manifest(&self) -> TranscriptManifest {
        let mut manifest = self.seed.clone();
        manifest.refused_chunks = self.counters.total.load(Ordering::Relaxed);
        manifest.refused_bytes = self.counters.total_bytes.load(Ordering::Relaxed);
        manifest.sealed_root_hex =
            sealed_root_hex(&manifest).expect("fixed transcript root metadata serializes");
        manifest
    }
}

/// A sink dropped without sealing still lets its writer finish, under the same
/// bound the seal uses, so the records already handed over reach the journal
/// instead of racing the unwind.
///
/// **This does not run at process exit, and must not be relied on to.** The
/// production plane is held in a process-global `OnceLock`, and Rust does not
/// drop statics — so for the shape this whole mechanism exists for, a detached
/// start whose host process exits, nothing here fires. What the later seal
/// rebuilds is whatever the writer thread had finished appending, and an
/// adopted manifest declares itself a floor precisely because of that. This
/// impl covers the cases where a sink genuinely is dropped: an embedder that
/// owns its own plane, and this crate's tests.
///
/// Bounded, for the reason [`DurableSink::seal`] is bounded: a disk that has
/// stopped answering must not hold a caller open on the way out.
impl Drop for DurableSink {
    fn drop(&mut self) {
        self.jobs = None;
        if let Some(worker) = self.worker.take() {
            wait_for_writer(worker, SEAL_JOIN_TIMEOUT);
        }
    }
}

/// How long [`DurableSink::seal`] waits for the writer thread to exit before
/// giving up on it. Bounded so a teardown that races a hung disk returns in
/// seconds rather than never — see the module docs on why the hand-off would
/// rather shed than couple the workload to that same disk.
const SEAL_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

/// How often [`wait_for_writer`] checks whether the writer thread has exited.
const SEAL_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Wait for `worker` to exit, but not past `timeout`. Polls rather than
/// joining directly because a plain `join` has no timeout in `std`, and this
/// module cannot add a dependency to get one.
///
/// A worker still running once the deadline passes is detached here: dropping
/// a [`JoinHandle`] without joining does not stop the thread, but nothing in
/// this process waits on it again. Whatever kept it alive this long — a write
/// syscall blocked in the kernel — is not something a timeout in this
/// function can do anything about; the thread finishes, if it ever does, on
/// its own.
fn wait_for_writer(worker: JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !worker.is_finished() {
        if Instant::now() >= deadline {
            drop(worker);
            return false;
        }
        std::thread::sleep(SEAL_JOIN_POLL_INTERVAL);
    }
    let _ = worker.join();
    true
}

/// Drop one record at the hand-off, and account for it.
///
/// Waiting instead would put the workload behind the disk — the coupling the
/// fan-out already refuses to have. The count is what keeps the drop from
/// being a lie: [`DurableSink::seal`] folds it into the manifest's refusal
/// totals, so the artifact declares its own hole.
fn note_shed(vm: &str, counters: &PersistCounters, record: &StreamRecord) {
    counters.shed_chunks.fetch_add(1, Ordering::Relaxed);
    counters
        .shed_bytes
        .fetch_add(record.payload.len() as u64, Ordering::Relaxed);
    if !counters.shedding.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            vm = %vm,
            from_seq = record.seq,
            "durable writer is behind; stream chunks are being dropped from the transcript, \
             live readers unaffected"
        );
    }
}

/// Note that the queue took a record again, ending an episode of shedding.
///
/// A plain load on the common path: the swap only runs on the one record that
/// ends the episode, so a broker that never sheds pays a relaxed read.
fn note_handed_over(vm: &str, counters: &PersistCounters) {
    if !counters.shedding.load(Ordering::Relaxed) {
        return;
    }
    counters.shedding.store(false, Ordering::Relaxed);
    tracing::info!(
        vm = %vm,
        dropped = counters.shed_chunks.load(Ordering::Relaxed),
        "durable writer caught up; stream chunks reaching the transcript again"
    );
}

/// Everything one capture's writer thread owns: the transcript it appends to,
/// the counters it keeps, and the journal it mirrors each landed chunk into.
struct WriterThread {
    writer: Arc<Mutex<TranscriptWriter>>,
    counters: Arc<PersistCounters>,
    journal: CaptureJournal,
}

/// Start the writer thread, or report that this capture has none.
fn spawn_writer(
    vm: &str,
    mut owned_state: WriterThread,
    inbox: Receiver<PersistJob>,
) -> Option<JoinHandle<()>> {
    let owned = vm.to_string();
    std::thread::Builder::new()
        .name(format!("mvm-transcript-{vm}"))
        .spawn(move || run_writer(&owned, &mut owned_state, &inbox))
        .inspect_err(|error| {
            tracing::warn!(
                vm = %vm,
                error = %error,
                "no durable writer thread for this stream; transcript appends will run on the \
                 producer's thread"
            );
        })
        .ok()
}

/// Drain the queue into the transcript until the sink stops feeding it.
fn run_writer(vm: &str, state: &mut WriterThread, inbox: &Receiver<PersistJob>) {
    let mut degraded = false;
    while let Ok(job) = inbox.recv() {
        if let Some(record) = job.record() {
            degraded = append(vm, state, &record, degraded);
        }
    }
}

/// Append one record, mirror it into the journal, and report whether
/// persistence is still degraded.
///
/// The *transition* into an outage is what gets logged, never the records: a
/// store that has failed usually keeps failing, so a warning per record would
/// emit thousands of lines a second for the life of the workload — trading a
/// bounded disk problem for an unbounded log one. The count keeps climbing;
/// the log says it started, and says when it stopped.
///
/// The mirror happens under the same lock as the append, and reads the
/// writer's own totals rather than recomputing them: a journal line that
/// disagreed with the writer about what had landed would rebuild into a
/// manifest that does not describe the segments beside it.
fn append(vm: &str, state: &mut WriterThread, record: &StreamRecord, degraded: bool) -> bool {
    let mut writer = lock_writer(&state.writer);
    let outcome = writer.push(direction_for(record.kind), &record.payload);
    if outcome.is_ok() {
        let shortfall = JournalShortfall {
            // The hand-off's own drops belong in the same total the writer's
            // refusals do — see the module docs on why nothing shed is
            // silent — so a replayed seal carries the whole shortfall the
            // owning process knew about.
            refused_chunks: writer
                .refused_chunks()
                .saturating_add(state.counters.shed_chunks.load(Ordering::Relaxed)),
            refused_bytes: writer
                .refused_bytes()
                .saturating_add(state.counters.shed_bytes.load(Ordering::Relaxed)),
            evicted_chunks: writer.evicted_chunks(),
            evicted_bytes: writer.evicted_bytes(),
        };
        if let Some(chunk) = writer.last_chunk() {
            state.journal.record(chunk, shortfall);
        }
    }
    drop(writer);

    match outcome {
        Ok(()) => {
            if degraded {
                tracing::info!(
                    vm = %vm,
                    missed = state.counters.refused.load(Ordering::Relaxed),
                    "stream chunks reaching the transcript again"
                );
            }
            false
        }
        Err(err) => {
            state.counters.refused.fetch_add(1, Ordering::Relaxed);
            if !degraded {
                state.counters.lapses.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    vm = %vm,
                    from_seq = record.seq,
                    error = %err,
                    "stream chunks no longer reaching the transcript; live readers unaffected"
                );
            }
            true
        }
    }
}

fn direction_for(kind: StreamKind) -> Direction {
    match kind {
        StreamKind::Stdout => Direction::Stdout,
        StreamKind::Stderr => Direction::Stderr,
        StreamKind::Trace => Direction::Trace,
    }
}

/// A panic under this lock leaves a writer mid-append, which the segment
/// store's own disturbance repair already handles on the next push. Refusing
/// to write for the rest of the capture would be the worse outcome.
fn lock_writer(writer: &Mutex<TranscriptWriter>) -> MutexGuard<'_, TranscriptWriter> {
    writer.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{
        CaptureBinding, CaptureBounds, RetentionPolicy, TranscriptWriterConfig, verify_sealed_root,
    };
    use mvm_protocol::stream::StreamSource;
    use std::path::Path;
    use std::time::Duration;

    fn writer_at(dir: &Path) -> TranscriptWriter {
        TranscriptWriter::new(
            dir,
            aead::Key::from_bytes([0x5a; 32]),
            TranscriptWriterConfig {
                capture_id: "capture-durable".to_string(),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: "vm-durable".to_string(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: u64::MAX,
                    max_bytes: 64 << 20,
                    max_chunks: 1_000_000,
                },
                retention: RetentionPolicy::Ring,
                created_unix_secs: 0,
                recipient: "host:test".to_string(),
                wrapped_data_key_b64: String::new(),
            },
        )
    }

    const PAYLOAD: &[u8] = b"payload";

    fn record(seq: u64) -> Arc<StreamRecord> {
        Arc::new(StreamRecord {
            seq,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stdout,
            host_unix_nanos: seq,
            prev_hash: [0u8; 32],
            payload: PAYLOAD.to_vec(),
        })
    }

    /// A burst that ran against a writer which could not answer.
    struct WedgedPush {
        sink: DurableSink,
        /// Whether the burst came back at all, inside a bound no working
        /// hand-off comes close to.
        returned: bool,
    }

    /// Push `total` records while the writer is unable to take any of them.
    ///
    /// The pushing runs on its own thread on purpose: a hand-off that waited
    /// would sit there for as long as the store is wedged, and a test that
    /// deadlocks reports nothing. This one always comes back and says which
    /// happened.
    fn push_against_a_wedged_writer(sink: DurableSink, total: u64) -> WedgedPush {
        let held = sink.writer_lock();
        let wedged = held.lock().expect("the writer lock");

        let (finished, pushing) = std::sync::mpsc::channel();
        let pusher = std::thread::spawn(move || {
            for seq in 0..total {
                sink.push(&record(seq));
            }
            let _ = finished.send(());
            sink
        });
        let returned = pushing.recv_timeout(Duration::from_secs(5)).is_ok();
        // Only now: a pusher the queue held has to be released to join.
        drop(wedged);

        WedgedPush {
            sink: pusher.join().expect("the pushing thread"),
            returned,
        }
    }

    #[test]
    fn a_wedged_writer_does_not_hold_the_pusher() {
        // The unit-level statement of the invariant: with the store unable to
        // answer, `push` still returns.
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DurableSink::new("vm-durable", writer_at(dir.path()));
        let pushed = push_against_a_wedged_writer(sink, DURABLE_QUEUE_DEPTH as u64 * 4);

        assert!(pushed.returned, "push waited on the writer");
        let counts = pushed.sink.counts();
        assert!(counts.shed_chunks > 0, "a wedged writer must shed");
        assert_eq!(counts.refused, 0, "shedding is not a store refusal");
    }

    #[test]
    fn what_the_hand_off_shed_lands_in_the_sealed_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DurableSink::new("vm-durable", writer_at(dir.path()));
        let total = DURABLE_QUEUE_DEPTH as u64 * 4;
        let pushed = push_against_a_wedged_writer(sink, total);
        assert!(pushed.returned, "push waited on the writer");

        let shed = pushed.sink.counts().shed_chunks;
        let manifest = pushed.sink.seal();
        assert!(shed > 0);
        assert_eq!(manifest.refused_chunks, shed);
        assert_eq!(manifest.refused_bytes, shed * PAYLOAD.len() as u64);
        assert!(
            manifest.is_truncated(),
            "a transcript that lost records must not look complete"
        );
        assert_eq!(
            manifest.chunks.len() as u64 + manifest.refused_chunks,
            total
        );
    }

    #[test]
    fn a_writer_that_keeps_up_sheds_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DurableSink::new("vm-durable", writer_at(dir.path()));
        for seq in 0..64 {
            sink.push(&record(seq));
            sink.drain();
        }

        assert_eq!(sink.counts(), DurableCounts::default());
        let manifest = sink.seal();
        assert_eq!(manifest.chunks.len(), 64);
        assert!(!manifest.is_truncated());
    }

    #[test]
    fn missing_counts_both_ends_of_the_loss() {
        let counts = DurableCounts {
            refused: 3,
            lapses: 1,
            shed_chunks: 4,
        };
        assert_eq!(counts.missing(), 7);
    }

    #[test]
    fn a_missing_writer_thread_sheds_rather_than_writing_inline() {
        // `jobs` reads `None` for a second reason besides a full queue: no
        // writer thread was ever spawned for this capture (thread-table
        // exhaustion on a busy host). The old fallback wrote inline here on
        // the producer's own thread — holding the writer's lock, standing in
        // for a disk that cannot answer, proves the difference: that
        // fallback would block on it forever, this path must not touch it
        // at all.
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DurableSink::new_without_writer_thread("vm-durable", writer_at(dir.path()));
        let held = sink.writer_lock();
        let wedged = held.lock().expect("the writer lock");

        let total = 8u64;
        let (finished, pushing) = std::sync::mpsc::channel();
        let pusher = std::thread::spawn(move || {
            for seq in 0..total {
                sink.push(&record(seq));
            }
            let _ = finished.send(());
            sink
        });
        let returned = pushing.recv_timeout(Duration::from_secs(5)).is_ok();
        drop(wedged);
        assert!(
            returned,
            "push must never write inline on the producer thread"
        );

        let sink = pusher.join().expect("the pushing thread");
        let counts = sink.counts();
        assert_eq!(
            counts.shed_chunks, total,
            "every record must be accounted as shed, not written inline"
        );
        let manifest = sink.seal();
        assert_eq!(manifest.refused_chunks, total);
        assert!(
            manifest.is_truncated(),
            "a transcript that dropped every record must say so"
        );
    }

    #[test]
    fn seal_does_not_hang_when_the_writer_thread_cannot_return() {
        // The writer thread holds `writer`'s lock for the length of its
        // blocking append, same as a hung disk would. Holding that lock from
        // the test simulates the writer never returning, which is exactly
        // the case `seal` cannot wait out — it runs on the VM teardown path.
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DurableSink::new("vm-durable", writer_at(dir.path()));
        let held = sink.writer_lock();
        let wedged = held.lock().expect("the writer lock");

        let total = 4u64;
        for seq in 0..total {
            sink.push(&record(seq));
        }

        let (finished, sealing) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = finished.send(sink.seal());
        });
        let outcome = sealing.recv_timeout(SEAL_JOIN_TIMEOUT + Duration::from_secs(5));
        // Only now: the writer thread these records were handed to is stuck
        // acquiring this same lock, and would otherwise hold it forever.
        drop(wedged);
        let manifest = outcome.expect(
            "seal must return within its bound even when the writer \
                                        thread never does",
        );

        assert!(
            manifest.chunks.is_empty(),
            "a writer that never released its lock cannot be vouched for"
        );
        assert_eq!(manifest.refused_chunks, total);
        assert_eq!(manifest.refused_bytes, total * PAYLOAD.len() as u64);
        assert!(
            manifest.is_truncated(),
            "a degraded seal must not look like a complete capture"
        );
        verify_sealed_root(&manifest).expect("the degraded manifest still verifies");
    }
}
