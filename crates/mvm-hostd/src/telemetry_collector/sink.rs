//! Where received records go, and the three things that stand between the
//! receive loop and the disk.
//!
//! The receive loop must never wait on anything slower than itself. Records
//! therefore pass, in order, through:
//!
//! 1. [`ScrubbingSink`] — on the receive thread, a whole-field scan against
//!    the fingerprints of the secrets this VM's endpoint holds. A record that
//!    carries one is withheld before it is queued, so the plaintext never
//!    reaches the queue, the disk or a reader.
//! 2. [`QueuedSink`] — a bounded queue in front of a dedicated writer thread.
//!    Admission is a single `try_send`; a full queue is a counted shed, never
//!    a wait. A stalled disk costs records, not the session.
//! 3. [`CappedJsonlSink`] — the writer thread's append to the records file,
//!    capped in bytes, and rolled back to its last whole line when a write
//!    fails, so a full disk leaves no torn line and the next write that
//!    succeeds starts clean.
//!
//! Every shed is counted under its reason in one shared [`LossCounters`], which
//! the status writer snapshots; the reasons are distinct because a reader
//! needs to tell "the disk was full" from "the guest printed a secret".

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::protocol::telemetry::served::{HostLosses, ReceivedRecord};
use mvm_core::protocol::telemetry::{
    AttributeValue, Attributes, MAX_RECORD_BYTES, RecordBody, TelemetryRecord,
};

use crate::stream::secret_scan::SecretScanner;

/// Records the writer queue holds before the receive loop starts shedding.
/// With every record bounded by [`MAX_RECORD_BYTES`], the queue can never hold
/// more than [`WRITE_QUEUE_MAX_BYTES`].
pub const WRITE_QUEUE_RECORDS: usize = 256;
/// The most memory the writer queue can pin, whatever the guest sends.
pub const WRITE_QUEUE_MAX_BYTES: usize = WRITE_QUEUE_RECORDS * MAX_RECORD_BYTES;

/// Why the host shed a record it had already received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossClass {
    /// The writer queue was full.
    QueueFull,
    /// The records file reached its byte cap.
    CapReached,
    /// The write to the records file failed.
    WriteFailed,
    /// The record carried a secret the host holds for this VM.
    SecretWithheld,
}

/// What a sink did with one offered record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Ingested,
    /// The sink did not keep the record, for the named reason. The collector
    /// counts it and keeps receiving.
    Shed(LossClass),
}

/// A bounded, non-waiting home for received records. `try_ingest` must never
/// block: a slow consumer costs shed records, not a stalled receive loop.
pub trait RecordSink: Send {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome;
}

/// Shed counts by reason, shared between the receive loop, the writer thread
/// and the status writer. Relaxed atomics: these are tallies, not a protocol.
#[derive(Debug, Default)]
pub struct LossCounters {
    queue_full: AtomicU64,
    cap_reached: AtomicU64,
    write_failed: AtomicU64,
    secret_withheld: AtomicU64,
}

impl LossCounters {
    /// Count one shed record under `class`.
    pub fn record(&self, class: LossClass) {
        let counter = match class {
            LossClass::QueueFull => &self.queue_full,
            LossClass::CapReached => &self.cap_reached,
            LossClass::WriteFailed => &self.write_failed,
            LossClass::SecretWithheld => &self.secret_withheld,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The counts as they stand.
    pub fn snapshot(&self) -> HostLosses {
        HostLosses {
            queue_full: self.queue_full.load(Ordering::Relaxed),
            cap_reached: self.cap_reached.load(Ordering::Relaxed),
            write_failed: self.write_failed.load(Ordering::Relaxed),
            secret_withheld: self.secret_withheld.load(Ordering::Relaxed),
        }
    }

    /// Every record shed so far.
    pub fn total(&self) -> u64 {
        self.snapshot().total()
    }
}

/// Withholds any record whose text or bytes contain a secret bound to this
/// VM, before the record goes anywhere else.
///
/// The guest never holds a bound secret — the endpoint substitutes it on
/// egress — so a match means a workload printed something it was never
/// handed, or a placeholder was resolved where it should not have been.
/// Either way the host is the last place it can be stopped. Each field is
/// scanned whole; the limits are the scanner's own (no encoded or derived
/// form of a secret is recognised).
pub struct ScrubbingSink<S> {
    scanner: Option<SecretScanner>,
    inner: S,
}

impl<S: RecordSink> ScrubbingSink<S> {
    /// Scrub against `fingerprints`; an empty set scans nothing.
    pub fn new(fingerprints: Vec<SecretFingerprint>, inner: S) -> Self {
        let scanner =
            (!fingerprints.is_empty()).then(|| SecretScanner::new(Arc::new(fingerprints)));
        Self { scanner, inner }
    }

    fn carries_secret(&self, record: &TelemetryRecord) -> bool {
        let Some(scanner) = &self.scanner else {
            return false;
        };
        let mut found = false;
        for_each_payload_field(record, |bytes| {
            found = found || scanner.contains_bound_secret(bytes);
        });
        found
    }
}

impl<S: RecordSink> RecordSink for ScrubbingSink<S> {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        if self.carries_secret(record) {
            return IngestOutcome::Shed(LossClass::SecretWithheld);
        }
        self.inner.try_ingest(record)
    }
}

/// Every guest-authored byte run a record carries: names, messages, attribute
/// keys and text values, coverage codes and stdio chunks.
fn for_each_payload_field(record: &TelemetryRecord, mut visit: impl FnMut(&[u8])) {
    let attributes = |attributes: &Attributes, visit: &mut dyn FnMut(&[u8])| {
        for attribute in attributes.as_slice() {
            visit(attribute.key.as_str().as_bytes());
            if let AttributeValue::Text(text) = &attribute.value {
                visit(text.as_str().as_bytes());
            }
        }
    };
    match record.body() {
        RecordBody::SpanOpen {
            name,
            attributes: a,
            ..
        } => {
            visit(name.as_str().as_bytes());
            attributes(a, &mut visit);
        }
        RecordBody::SpanUpdate { attributes: a, .. } => attributes(a, &mut visit),
        RecordBody::SpanClose { .. } | RecordBody::Loss { .. } => {}
        RecordBody::Event {
            name,
            attributes: a,
            ..
        } => {
            visit(name.as_str().as_bytes());
            attributes(a, &mut visit);
        }
        RecordBody::Log {
            message,
            attributes: a,
            ..
        } => {
            visit(message.as_str().as_bytes());
            attributes(a, &mut visit);
        }
        RecordBody::Stdio { bytes, .. } => visit(bytes.as_slice()),
        RecordBody::Coverage { code, .. } => visit(code.as_str().as_bytes()),
    }
}

/// A bounded queue in front of a writer thread that owns the inner sink.
///
/// The receive loop's only cost is one `try_send`. The writer thread drains in
/// order into the inner sink and counts the inner sink's own sheds. Dropping
/// the queue closes it; the writer finishes what was queued and exits. Nothing
/// joins it on drop — a writer stuck on a dead disk must not hold the
/// collector — so [`QueuedSink::close`] exists for callers that need the
/// drain to have happened.
pub struct QueuedSink {
    tx: Option<SyncSender<TelemetryRecord>>,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl QueuedSink {
    /// Start the writer thread over `inner`, with room for `capacity` records.
    pub fn spawn(
        name: &str,
        capacity: usize,
        inner: impl RecordSink + 'static,
        losses: Arc<LossCounters>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(capacity.max(1));
        let writer = std::thread::Builder::new()
            .name(format!("mvm-telemetry-writer-{name}"))
            .spawn(move || drain(rx, inner, &losses))?;
        Ok(Self {
            tx: Some(tx),
            writer: Some(writer),
        })
    }

    /// Close the queue and wait for the writer to finish what it holds.
    pub fn close(mut self) {
        self.tx.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn drain(rx: Receiver<TelemetryRecord>, mut inner: impl RecordSink, losses: &LossCounters) {
    for record in rx {
        if let IngestOutcome::Shed(class) = inner.try_ingest(&record) {
            losses.record(class);
        }
    }
}

impl RecordSink for QueuedSink {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        let Some(tx) = &self.tx else {
            return IngestOutcome::Shed(LossClass::QueueFull);
        };
        match tx.try_send(record.clone()) {
            Ok(()) => IngestOutcome::Ingested,
            // A writer that died has stopped writing just as surely as a
            // full one; either way the record is not going to disk.
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                IngestOutcome::Shed(LossClass::QueueFull)
            }
        }
    }
}

/// The file a [`CappedJsonlSink`] appends to: a writer that can also cut
/// itself back to a length, so a failed append can be undone.
pub trait RecordFile: Write + Send {
    /// The file's current length.
    fn current_len(&self) -> std::io::Result<u64>;
    /// Truncate to `len`, discarding a partial line a failed write left.
    fn truncate_to(&mut self, len: u64) -> std::io::Result<()>;
}

impl RecordFile for std::fs::File {
    fn current_len(&self) -> std::io::Result<u64> {
        self.metadata().map(|meta| meta.len())
    }

    fn truncate_to(&mut self, len: u64) -> std::io::Result<()> {
        // Append mode writes at the end whatever the cursor says, so cutting
        // the length is all a rollback needs.
        self.set_len(len)
    }
}

/// A size-capped JSONL sink: each record appends as one JSON line — the
/// record inside the served envelope, stamped with the host receive time —
/// until the cap, then sheds. This file exists so collection is observable
/// through the read seam; it is bounded, not a durable store.
///
/// A failed write is a shed, never a stall, and never a torn line: the file
/// is cut back to the end of the last whole record, so a reader keeps
/// decoding and the next successful write starts on a line boundary. That is
/// what lets collection resume by itself once a full disk has room again.
pub struct CappedJsonlSink<F = std::fs::File> {
    file: F,
    written: u64,
    cap: u64,
}

impl CappedJsonlSink<std::fs::File> {
    pub fn create(path: &std::path::Path, cap: u64) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Self::over(file, cap)
    }
}

impl<F: RecordFile> CappedJsonlSink<F> {
    /// Append to an already-open file; its existing length counts against
    /// the cap.
    pub fn over(file: F, cap: u64) -> std::io::Result<Self> {
        let written = file.current_len()?;
        Ok(Self { file, written, cap })
    }
}

impl<F: RecordFile> RecordSink for CappedJsonlSink<F> {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        // The persisted line carries the host receive time beside the
        // record: the guest's monotonic clock orders records within one
        // producer and epoch, and only this stamp places them on a wall clock.
        let received_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let Ok(line) = ReceivedRecord::encode_line(received_at_ms, record) else {
            return IngestOutcome::Shed(LossClass::WriteFailed);
        };
        if self.written.saturating_add(line.len() as u64) > self.cap {
            return IngestOutcome::Shed(LossClass::CapReached);
        }
        match self.file.write_all(&line) {
            Ok(()) => {
                self.written += line.len() as u64;
                IngestOutcome::Ingested
            }
            Err(_) => {
                // Undo whatever part of the line landed. If even that fails,
                // re-read the length so the cap stays honest; the reader
                // skips a torn line as undecodable rather than misparsing it.
                if self.file.truncate_to(self.written).is_err() {
                    self.written = self.file.current_len().unwrap_or(self.written);
                }
                IngestOutcome::Shed(LossClass::WriteFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::secret_fingerprint::SecretCategory;
    use mvm_core::protocol::telemetry::{
        Attribute, CoverageState, Level, ProducerEpoch, SourceKind, StdioStream,
    };
    use std::sync::Mutex;
    use std::sync::mpsc::Sender;

    const SECRET: &str = "sk-live-0123456789abcdefSYNTHETIC";

    fn build(sequence: u64, body: RecordBody) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([5; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .source(SourceKind::GuestAgent)
            .body(body)
            .build()
            .unwrap()
    }

    fn coverage(sequence: u64) -> TelemetryRecord {
        build(
            sequence,
            RecordBody::Coverage {
                state: CoverageState::Started,
                code: "sink-witness".try_into().unwrap(),
            },
        )
    }

    fn fingerprints() -> Vec<SecretFingerprint> {
        vec![SecretFingerprint::of(SECRET.as_bytes(), SecretCategory::HostSecret).unwrap()]
    }

    /// Records everything it is offered; never sheds.
    #[derive(Clone, Default)]
    struct Keep(Arc<Mutex<Vec<TelemetryRecord>>>);

    impl RecordSink for Keep {
        fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
            self.0.lock().unwrap().push(record.clone());
            IngestOutcome::Ingested
        }
    }

    fn records_carrying(text: &str) -> Vec<TelemetryRecord> {
        let attr = |value: &str| {
            Attributes::new(vec![Attribute {
                key: "detail".try_into().unwrap(),
                value: AttributeValue::Text(value.try_into().unwrap()),
            }])
            .unwrap()
        };
        let empty = Attributes::new(Vec::new()).unwrap();
        vec![
            build(
                1,
                RecordBody::Log {
                    context: None,
                    level: Level::Info,
                    message: format!("token={text}").as_str().try_into().unwrap(),
                    attributes: empty.clone(),
                },
            ),
            build(
                2,
                RecordBody::Event {
                    context: None,
                    level: Level::Warn,
                    name: "login".try_into().unwrap(),
                    attributes: attr(text),
                },
            ),
            build(
                3,
                RecordBody::Stdio {
                    stream: StdioStream::Stdout,
                    bytes: mvm_core::protocol::telemetry::BoundedList::new(
                        format!("printing {text} to stdout").into_bytes(),
                    )
                    .unwrap(),
                },
            ),
        ]
    }

    #[test]
    fn a_record_carrying_a_bound_secret_is_withheld_in_every_field_kind() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), kept.clone());
        for record in records_carrying(SECRET) {
            assert_eq!(
                sink.try_ingest(&record),
                IngestOutcome::Shed(LossClass::SecretWithheld),
                "record {} must not pass",
                record.sequence()
            );
        }
        assert!(
            kept.0.lock().unwrap().is_empty(),
            "nothing reached the inner sink"
        );
    }

    #[test]
    fn records_without_a_bound_secret_pass_through_untouched() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), kept.clone());
        for record in records_carrying("not-the-secret") {
            assert_eq!(sink.try_ingest(&record), IngestOutcome::Ingested);
        }
        assert_eq!(kept.0.lock().unwrap().len(), 3);

        // A VM with no bound secrets scans nothing at all.
        let mut open = ScrubbingSink::new(Vec::new(), Keep::default());
        for record in records_carrying(SECRET) {
            assert_eq!(open.try_ingest(&record), IngestOutcome::Ingested);
        }
    }

    /// A sink whose every ingest blocks until the test releases it — a disk
    /// that has stopped answering.
    struct Stalled {
        entered: Sender<()>,
        release: Arc<Mutex<Receiver<()>>>,
    }

    impl RecordSink for Stalled {
        fn try_ingest(&mut self, _record: &TelemetryRecord) -> IngestOutcome {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
            IngestOutcome::Ingested
        }
    }

    #[test]
    fn a_stalled_writer_costs_counted_records_never_a_waiting_receive_loop() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let losses = Arc::new(LossCounters::default());
        let mut queued = QueuedSink::spawn(
            "stalled",
            2,
            Stalled {
                entered: entered_tx,
                release: Arc::new(Mutex::new(release_rx)),
            },
            Arc::clone(&losses),
        )
        .unwrap();

        // The writer takes the first record and blocks inside the "disk".
        assert_eq!(queued.try_ingest(&coverage(1)), IngestOutcome::Ingested);
        entered_rx.recv().unwrap();
        // Two more fill the queue behind it; everything after sheds at once.
        assert_eq!(queued.try_ingest(&coverage(2)), IngestOutcome::Ingested);
        assert_eq!(queued.try_ingest(&coverage(3)), IngestOutcome::Ingested);
        for sequence in 4..=100 {
            assert_eq!(
                queued.try_ingest(&coverage(sequence)),
                IngestOutcome::Shed(LossClass::QueueFull)
            );
        }

        // The disk comes back: the queued records drain and the queue admits
        // again — recovery needs no restart.
        for _ in 0..3 {
            release_tx.send(()).unwrap();
        }
        entered_rx.recv().unwrap();
        entered_rx.recv().unwrap();
        assert_eq!(queued.try_ingest(&coverage(101)), IngestOutcome::Ingested);
        drop(release_tx);
        queued.close();
    }

    #[test]
    fn the_writer_counts_the_inner_sinks_sheds_by_class() {
        let dir = tempfile::tempdir().unwrap();
        let one_line = ReceivedRecord::encode_line(u64::MAX / 2, &coverage(1))
            .unwrap()
            .len() as u64;
        let inner = CappedJsonlSink::create(&dir.path().join("r.jsonl"), one_line).unwrap();
        let losses = Arc::new(LossCounters::default());
        let mut queued = QueuedSink::spawn("cap", 8, inner, Arc::clone(&losses)).unwrap();
        for sequence in 1..=4 {
            assert_eq!(
                queued.try_ingest(&coverage(sequence)),
                IngestOutcome::Ingested
            );
        }
        queued.close();
        assert_eq!(
            losses.snapshot(),
            HostLosses {
                cap_reached: 3,
                ..HostLosses::default()
            }
        );
    }

    /// A file that fails writes on demand, landing half a line first — a
    /// disk that fills mid-record.
    #[derive(Default)]
    struct FlakyFile {
        bytes: Vec<u8>,
        full: bool,
    }

    impl Write for FlakyFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.full {
                let half = buf.len() / 2;
                self.bytes.extend_from_slice(&buf[..half]);
                self.full = false; // the next call reports the failure
                return Ok(half);
            }
            if self.bytes.last() != Some(&b'\n') && !self.bytes.is_empty() {
                return Err(std::io::Error::other("no space left on device"));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordFile for FlakyFile {
        fn current_len(&self) -> std::io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn truncate_to(&mut self, len: u64) -> std::io::Result<()> {
            self.bytes.truncate(len as usize);
            Ok(())
        }
    }

    #[test]
    fn a_full_disk_leaves_no_torn_line_and_writing_resumes_when_space_returns() {
        let mut sink = CappedJsonlSink::over(FlakyFile::default(), u64::MAX).unwrap();
        assert_eq!(sink.try_ingest(&coverage(1)), IngestOutcome::Ingested);

        sink.file.full = true;
        assert_eq!(
            sink.try_ingest(&coverage(2)),
            IngestOutcome::Shed(LossClass::WriteFailed)
        );
        assert!(
            sink.file.bytes.ends_with(b"\n"),
            "the half-written line was rolled back"
        );

        // Space again: the next record lands on a clean boundary.
        assert_eq!(sink.try_ingest(&coverage(3)), IngestOutcome::Ingested);
        let lines: Vec<_> = sink
            .file
            .bytes
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| ReceivedRecord::decode_line(line).expect("every line decodes"))
            .map(|received| received.record.sequence())
            .collect();
        assert_eq!(lines, vec![1, 3]);
    }

    #[test]
    fn the_capped_sink_persists_each_record_in_the_served_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.jsonl");
        let record = coverage(1);
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Sized with a receive time of today's width, so the cap admits
        // exactly two lines as the sink will stamp them.
        let one_line = ReceivedRecord::encode_line(before, &record).unwrap().len() as u64;
        let mut sink = CappedJsonlSink::create(&path, one_line * 2 + 1).unwrap();
        assert_eq!(sink.try_ingest(&record), IngestOutcome::Ingested);
        assert_eq!(sink.try_ingest(&record), IngestOutcome::Ingested);
        assert_eq!(
            sink.try_ingest(&record),
            IngestOutcome::Shed(LossClass::CapReached),
            "the third line would cross the cap"
        );
        let text = std::fs::read(&path).unwrap();
        let lines: Vec<&[u8]> = text
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let served = ReceivedRecord::decode_line(line).expect("the served envelope");
            assert_eq!(served.record, record);
            assert!(served.received_at_ms.is_some_and(|at| at >= before));
        }
        // Reopening appends: the cap counts what is already there.
        let mut reopened = CappedJsonlSink::create(&path, one_line * 3).unwrap();
        assert_eq!(reopened.try_ingest(&record), IngestOutcome::Ingested);
        assert_eq!(
            reopened.try_ingest(&record),
            IngestOutcome::Shed(LossClass::CapReached)
        );
    }

    #[test]
    fn loss_counters_total_every_class() {
        let losses = LossCounters::default();
        for class in [
            LossClass::QueueFull,
            LossClass::CapReached,
            LossClass::CapReached,
            LossClass::WriteFailed,
            LossClass::SecretWithheld,
        ] {
            losses.record(class);
        }
        assert_eq!(losses.total(), 5);
        assert_eq!(losses.snapshot().cap_reached, 2);
    }
}
