//! Where received records go, and the three things that stand between the
//! receive loop and the disk.
//!
//! The receive loop must never wait on anything slower than itself. Records
//! therefore pass, in order, through:
//!
//! 1. [`ScrubbingSink`] — on the receive thread, a whole-field scan against
//!    the fingerprints of the secrets this VM's endpoint holds. A record that
//!    carries one is withheld before it is queued, so the plaintext never
//!    reaches the queue, the disk or a reader. Stdio arrives in chunks, so a
//!    VM with bound secrets also holds back as much of each stream as a
//!    secret could straddle: a secret split across any number of chunks
//!    withholds every one. Every record that passes is then masked by the
//!    stream plane's curated redaction seam, the same rules a transcript gets.
//! 2. [`QueuedSink`] — a bounded queue in front of a dedicated writer thread.
//!    Admission is a single `try_send`; a full queue is a counted shed, never
//!    a wait. A stalled disk costs records, not the session.
//! 3. [`CappedJsonlSink`] — the writer thread's append to the records file,
//!    each line sealed under the boot's records data key, capped in bytes, and rolled back to its last whole line when a write
//!    fails, so a full disk leaves no torn line and the next write that
//!    succeeds starts clean.
//!
//! Every shed is counted under its reason in one shared [`LossCounters`], which
//! the status writer snapshots; the reasons are distinct because a reader
//! needs to tell "the disk was full" from "the guest printed a secret".

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::protocol::telemetry::served::{HostLosses, ReceivedRecord};
use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, Attributes, BoundedList, MAX_RECORD_BYTES, RecordBody, StdioStream,
    TelemetryRecord, Text,
};

use mvm_core::crypto::aead;

use crate::stream::redact::{StreamRedaction, StreamRedactor as _};
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

    /// Pass on anything held back for a later decision. Called when a session
    /// ends; a sink that holds nothing does nothing.
    fn release_held(&mut self) {}
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

/// How long a stdio chunk may be held back waiting for the rest of its stream
/// before it is passed on anyway. Bounds the latency the straddle check adds.
/// Releasing a chunk never forgets its bytes: the stream's scan context keeps
/// them, so a secret completed after the hold still withholds the chunk that
/// completes it. What the hold buys is that the *first* part of the secret is
/// not written either when the rest follows within it.
pub const STDIO_HOLD: Duration = Duration::from_millis(500);

/// Stdio streams with records held back at once. A guest has a handful of
/// producers; past this the stream held longest is released early (its scan
/// context stays).
const MAX_HELD_STREAMS: usize = 8;

/// Stdio streams whose scan context is remembered. Past this the stream idle
/// longest loses its context: a guest would need more stdio producers than
/// this, each active between the two halves of one secret, to split a secret
/// across a forgotten boundary.
const MAX_STREAM_CONTEXTS: usize = 64;

/// One stdio stream as the scrubber sees it.
///
/// `context` is the last `carry` bytes the stream produced — passed on,
/// still held or withheld alike — so every chunk is scanned joined to every
/// byte a straddling secret could have started in, however small the chunks
/// and however long the gaps between them. It is updated on every chunk and
/// never cleared by a release, a timeout or the end of a session: no state
/// the sink can reach scans a chunk with less context than the stream had.
///
/// `chunks` are the records not yet passed on, oldest first. A chunk is held
/// until the stream has produced at least `carry` bytes after it.
struct StreamState {
    key: (u32, StdioStream),
    context: Vec<u8>,
    chunks: VecDeque<(TelemetryRecord, Instant)>,
    held_bytes: usize,
    last_seen: Instant,
}

impl StreamState {
    fn new(key: (u32, StdioStream), now: Instant) -> Self {
        Self {
            key,
            context: Vec::new(),
            chunks: VecDeque::new(),
            held_bytes: 0,
            last_seen: now,
        }
    }

    fn oldest_held(&self) -> Option<Instant> {
        self.chunks.front().map(|(_, since)| *since)
    }

    /// Fold `bytes` into the context, keeping its last `carry` bytes.
    fn remember(&mut self, bytes: &[u8], carry: usize) {
        self.context.extend_from_slice(bytes);
        let excess = self.context.len().saturating_sub(carry);
        self.context.drain(..excess);
    }
}

/// The host's last check on what a guest record says before anything else
/// sees it: withholds a record carrying a secret bound to this VM, and masks
/// what the curated redaction seam masks in every other record.
///
/// The guest never holds a bound secret — the endpoint substitutes it on
/// egress — so a fingerprint match means a workload printed something it was
/// never handed, or a placeholder was resolved where it should not have been.
/// Either way the host is the last place it can be stopped. Each field is
/// scanned whole; the limits are the scanner's own (no encoded or derived
/// form of a secret is recognised).
///
/// Stdio is the one source that arrives chopped: a secret printed across
/// chunk boundaries is whole in no chunk. So, only on a VM with bound
/// secrets, every chunk is scanned joined to its stream's remembered tail,
/// and each stream's chunks are held until the stream has produced at least
/// the scanner's carry beyond them, or until [`STDIO_HOLD`] passes, or until
/// the session ends. A match withholds the completing chunk and every chunk
/// still held; a bound secret never reaches the inner sink whole.
///
/// Then every text and byte field goes through the same
/// [`StreamRedaction`] the stream plane uses, so a guest's telemetry is
/// redacted to the same rules as its transcript. Every failure is closed: a
/// field the seam cannot vouch for, or cannot hold once masked, withholds the
/// record, and the shed is counted. Nothing here has an "off" state: the
/// scanner and the seam are fixed at construction for the sink's life.
pub struct ScrubbingSink<S> {
    scanner: Option<SecretScanner>,
    redaction: StreamRedaction,
    inner: S,
    losses: Arc<LossCounters>,
    streams: Vec<StreamState>,
}

impl<S: RecordSink> ScrubbingSink<S> {
    /// Scrub against `fingerprints` (an empty set scans nothing and holds
    /// nothing back) and redact through `redaction`. Sheds this sink decides
    /// on its own — a held chunk withheld, or refused by `inner` when
    /// released — count into `losses`.
    pub fn new(
        fingerprints: Vec<SecretFingerprint>,
        redaction: StreamRedaction,
        inner: S,
        losses: Arc<LossCounters>,
    ) -> Self {
        let scanner =
            (!fingerprints.is_empty()).then(|| SecretScanner::new(Arc::new(fingerprints)));
        Self {
            scanner,
            redaction,
            inner,
            losses,
            streams: Vec::new(),
        }
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

    /// Redact a record that passed the secret checks and offer it to the
    /// inner sink.
    fn pass_on(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        match redact_record(&self.redaction, record) {
            Some(Cow::Borrowed(record)) => self.inner.try_ingest(record),
            Some(Cow::Owned(redacted)) => self.inner.try_ingest(&redacted),
            None => IngestOutcome::Shed(LossClass::SecretWithheld),
        }
    }

    /// Pass on a released record, counting its shed here, since nobody else
    /// sees this outcome.
    fn forward(&mut self, record: &TelemetryRecord) {
        if let IngestOutcome::Shed(class) = self.pass_on(record) {
            self.losses.record(class);
        }
    }

    /// Pass on every chunk `streams[at]` holds. Its context stays.
    fn release_chunks(&mut self, at: usize) {
        let chunks = std::mem::take(&mut self.streams[at].chunks);
        self.streams[at].held_bytes = 0;
        for (record, _) in chunks {
            self.forward(&record);
        }
    }

    fn release_expired(&mut self, now: Instant) {
        for at in 0..self.streams.len() {
            let expired = self.streams[at]
                .oldest_held()
                .is_some_and(|since| now.duration_since(since) >= STDIO_HOLD);
            if expired {
                self.release_chunks(at);
            }
        }
    }

    /// The index of `key`'s state, created (and the idle-longest context
    /// evicted, its held chunks passed on first) when it is new.
    fn stream_index(&mut self, key: (u32, StdioStream), now: Instant) -> usize {
        if let Some(at) = self.streams.iter().position(|s| s.key == key) {
            return at;
        }
        if self.streams.len() >= MAX_STREAM_CONTEXTS
            && let Some(at) = self
                .streams
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(at, _)| at)
        {
            self.release_chunks(at);
            self.streams.swap_remove(at);
        }
        self.streams.push(StreamState::new(key, now));
        self.streams.len() - 1
    }

    /// Decide a stdio chunk that passed the whole-field scan: scan it joined
    /// to its stream's context, then hold it and pass on whatever the stream
    /// no longer needs to keep.
    fn ingest_stdio(
        &mut self,
        record: &TelemetryRecord,
        key: (u32, StdioStream),
        bytes: &[u8],
    ) -> IngestOutcome {
        let Some(carry) = self.scanner.as_ref().map(SecretScanner::carry) else {
            return self.pass_on(record);
        };
        if carry == 0 || bytes.is_empty() {
            return self.pass_on(record);
        }
        let now = Instant::now();
        let at = self.stream_index(key, now);
        let stream = &mut self.streams[at];
        stream.last_seen = now;
        let mut joined = Vec::with_capacity(stream.context.len() + bytes.len());
        joined.extend_from_slice(&stream.context);
        joined.extend_from_slice(bytes);
        // The context advances whatever the verdict: a withheld chunk's bytes
        // still precede the next chunk in the stream the guest wrote.
        stream.remember(bytes, carry);
        let straddles = self
            .scanner
            .as_ref()
            .is_some_and(|scanner| scanner.contains_bound_secret(&joined));
        if straddles {
            let stream = &mut self.streams[at];
            let withheld = std::mem::take(&mut stream.chunks);
            stream.held_bytes = 0;
            for _ in withheld {
                self.losses.record(LossClass::SecretWithheld);
            }
            return IngestOutcome::Shed(LossClass::SecretWithheld);
        }
        let stream = &mut self.streams[at];
        stream.chunks.push_back((record.clone(), now));
        stream.held_bytes += bytes.len();
        // The oldest chunk goes once the chunks after it cover the carry.
        let mut released = Vec::new();
        while let Some((front, _)) = stream.chunks.front() {
            let front_len = stdio_bytes(front).len();
            if stream.held_bytes - front_len < carry {
                break;
            }
            let (front, _) = stream.chunks.pop_front().expect("front exists");
            stream.held_bytes -= front_len;
            released.push(front);
        }
        for record in released {
            self.forward(&record);
        }
        let holding = self.streams.iter().filter(|s| !s.chunks.is_empty()).count();
        if holding > MAX_HELD_STREAMS
            && let Some(longest) = self
                .streams
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != at)
                .filter_map(|(other, s)| s.oldest_held().map(|since| (other, since)))
                .min_by_key(|(_, since)| *since)
                .map(|(other, _)| other)
        {
            self.release_chunks(longest);
        }
        IngestOutcome::Ingested
    }
}

fn stdio_bytes(record: &TelemetryRecord) -> &[u8] {
    match record.body() {
        RecordBody::Stdio { bytes, .. } => bytes.as_slice(),
        _ => &[],
    }
}

impl<S: RecordSink> RecordSink for ScrubbingSink<S> {
    fn try_ingest(&mut self, record: &TelemetryRecord) -> IngestOutcome {
        self.release_expired(Instant::now());
        if self.carries_secret(record) {
            return IngestOutcome::Shed(LossClass::SecretWithheld);
        }
        match record.body() {
            RecordBody::Stdio { stream, bytes } => {
                self.ingest_stdio(record, (record.producer(), *stream), bytes.as_slice())
            }
            _ => self.pass_on(record),
        }
    }

    fn release_held(&mut self) {
        for at in 0..self.streams.len() {
            self.release_chunks(at);
        }
        self.inner.release_held();
    }
}

/// `record` with every guest-authored text and byte field passed through the
/// redaction seam: borrowed when nothing fired, rebuilt when something was
/// masked, and `None` when the seam would not vouch for a field or a masked
/// field no longer fits its bound — fail closed, the record is withheld.
fn redact_record<'a>(
    seam: &StreamRedaction,
    record: &'a TelemetryRecord,
) -> Option<Cow<'a, TelemetryRecord>> {
    let mut fired = false;
    let mut failed = false;
    let mut bytes = |input: &[u8]| -> Option<Vec<u8>> {
        match seam.redact(input) {
            Ok(redacted) if redacted.rules_fired.is_empty() => Some(input.to_vec()),
            Ok(redacted) => {
                fired = true;
                Some(redacted.body)
            }
            Err(_) => {
                failed = true;
                None
            }
        }
    };
    let body = redact_body(record.body(), &mut bytes);
    if failed {
        return None;
    }
    if !fired {
        return Some(Cow::Borrowed(record));
    }
    let body = body?;
    TelemetryRecord::builder()
        .epoch(record.epoch())
        .producer(record.producer())
        .sequence(record.sequence())
        .monotonic_ns(record.monotonic_ns())
        .source(record.source())
        .body(body)
        .build()
        .ok()
        .map(Cow::Owned)
}

/// Rebuild `body` with every guest-authored field mapped through `redact`.
/// `None` when `redact` refused a field or a result does not fit its bound.
fn redact_body(
    body: &RecordBody,
    redact: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<RecordBody> {
    fn text<const N: usize>(
        value: &Text<N>,
        redact: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Option<Text<N>> {
        let masked = String::from_utf8(redact(value.as_str().as_bytes())?).ok()?;
        Text::new(&masked).ok()
    }
    fn attributes(
        attributes: &Attributes,
        redact: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Option<Attributes> {
        let mut out = Vec::with_capacity(attributes.as_slice().len());
        for attribute in attributes.as_slice() {
            let value = match &attribute.value {
                AttributeValue::Text(value) => AttributeValue::Text(text(value, redact)?),
                other => other.clone(),
            };
            out.push(Attribute {
                key: text(&attribute.key, redact)?,
                value,
            });
        }
        Attributes::new(out).ok()
    }
    Some(match body {
        RecordBody::SpanOpen {
            context,
            parent,
            name,
            attributes: a,
            links,
        } => RecordBody::SpanOpen {
            context: *context,
            parent: *parent,
            name: text(name, redact)?,
            attributes: attributes(a, redact)?,
            links: links.clone(),
        },
        RecordBody::SpanUpdate {
            context,
            attributes: a,
        } => RecordBody::SpanUpdate {
            context: *context,
            attributes: attributes(a, redact)?,
        },
        RecordBody::Event {
            context,
            level,
            name,
            attributes: a,
        } => RecordBody::Event {
            context: *context,
            level: *level,
            name: text(name, redact)?,
            attributes: attributes(a, redact)?,
        },
        RecordBody::Log {
            context,
            level,
            message,
            attributes: a,
        } => RecordBody::Log {
            context: *context,
            level: *level,
            message: text(message, redact)?,
            attributes: attributes(a, redact)?,
        },
        RecordBody::Stdio { stream, bytes } => RecordBody::Stdio {
            stream: *stream,
            bytes: BoundedList::new(redact(bytes.as_slice())?).ok()?,
        },
        RecordBody::Coverage { state, code } => RecordBody::Coverage {
            state: *state,
            code: text(code, redact)?,
        },
        RecordBody::SpanClose { .. } | RecordBody::Loss { .. } => body.clone(),
    })
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

/// A size-capped JSONL sink: each record appends as one sealed line — the
/// record inside the served envelope, stamped with the host receive time,
/// encrypted under the records data key — until the cap, then sheds. A line
/// that cannot be sealed is shed, never written in the clear. This file exists so collection is observable
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
    key: aead::Key,
}

impl CappedJsonlSink<std::fs::File> {
    pub fn create(path: &std::path::Path, cap: u64, key: aead::Key) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Owner-only, like every other file under the state dir: the records
        // are guest output, readable by the operator and nobody else.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Self::over(file, cap, key)
    }
}

impl<F: RecordFile> CappedJsonlSink<F> {
    /// Append to an already-open file; its existing length counts against
    /// the cap.
    pub fn over(file: F, cap: u64, key: aead::Key) -> std::io::Result<Self> {
        let written = file.current_len()?;
        Ok(Self {
            file,
            written,
            cap,
            key,
        })
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
        let Ok(line) = ReceivedRecord::seal_line(&self.key, received_at_ms, record) else {
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
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::protocol::telemetry::{CoverageState, Level, ProducerEpoch, SourceKind};
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

    /// The records data key every test sink seals under.
    fn test_key() -> aead::Key {
        aead::Key::from_bytes([9; 32])
    }

    /// The seam production builds, from a launch that set no redaction policy.
    fn seam() -> StreamRedaction {
        StreamRedaction::curated(&RedactionPolicy::default())
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
                    bytes: BoundedList::new(format!("printing {text} to stdout").into_bytes())
                        .unwrap(),
                },
            ),
        ]
    }

    #[test]
    fn a_record_carrying_a_bound_secret_is_withheld_in_every_field_kind() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
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
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        for record in records_carrying("not-the-secret") {
            assert_eq!(sink.try_ingest(&record), IngestOutcome::Ingested);
        }
        // The stdio chunk is held for the straddle check until released.
        assert_eq!(kept.0.lock().unwrap().len(), 2);
        sink.release_held();
        assert_eq!(kept.0.lock().unwrap().len(), 3);

        // A VM with no bound secrets scans nothing at all.
        let mut open = ScrubbingSink::new(Vec::new(), seam(), Keep::default(), Arc::default());
        for record in records_carrying(SECRET) {
            assert_eq!(open.try_ingest(&record), IngestOutcome::Ingested);
        }
    }

    fn stdout(sequence: u64, text: &[u8]) -> TelemetryRecord {
        build(
            sequence,
            RecordBody::Stdio {
                stream: StdioStream::Stdout,
                bytes: BoundedList::new(text.to_vec()).unwrap(),
            },
        )
    }

    /// A chunk as the guest's stdio tap sends it: under the stream's own
    /// producer (2 stdout, 3 stderr) and the stdio source.
    fn tapped(stream: StdioStream, sequence: u64, text: &[u8]) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([5; 16]).unwrap())
            .producer(match stream {
                StdioStream::Stdout => 2,
                StdioStream::Stderr => 3,
            })
            .sequence(sequence)
            .source(SourceKind::Stdio)
            .body(RecordBody::Stdio {
                stream,
                bytes: BoundedList::new(text.to_vec()).unwrap(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn tapped_workload_output_split_across_reads_and_interleaved_with_stderr_is_withheld() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        let third = SECRET.len() / 3;
        let (a, rest) = SECRET.as_bytes().split_at(third);
        let (b, c) = rest.split_at(third);
        sink.try_ingest(&tapped(StdioStream::Stdout, 1, a));
        sink.try_ingest(&tapped(StdioStream::Stderr, 1, &[b'e'; 256]));
        sink.try_ingest(&tapped(StdioStream::Stdout, 2, b));
        sink.try_ingest(&tapped(StdioStream::Stderr, 2, &[b'e'; 256]));
        assert_eq!(
            sink.try_ingest(&tapped(StdioStream::Stdout, 3, c)),
            IngestOutcome::Shed(LossClass::SecretWithheld),
            "each stream is scanned joined to its own tail"
        );
        sink.release_held();
        assert!(never_whole(&kept));
        // The other stream's output is unaffected.
        assert!(
            kept.0
                .lock()
                .unwrap()
                .iter()
                .any(|record| record.producer() == 3)
        );
    }

    fn kept_sequences(kept: &Keep) -> Vec<u64> {
        kept.0
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.sequence())
            .collect()
    }

    #[test]
    fn a_secret_split_across_two_stdio_chunks_withholds_both() {
        let kept = Keep::default();
        let losses = Arc::new(LossCounters::default());
        let mut sink =
            ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::clone(&losses));
        let (head, tail) = SECRET.as_bytes().split_at(SECRET.len() / 2);
        let first = [b"key: ".as_slice(), head].concat();
        let second = [tail, b"\n".as_slice()].concat();

        assert_eq!(sink.try_ingest(&stdout(1, &first)), IngestOutcome::Ingested);
        assert_eq!(
            sink.try_ingest(&stdout(2, &second)),
            IngestOutcome::Shed(LossClass::SecretWithheld)
        );
        sink.release_held();
        assert!(
            kept_sequences(&kept).is_empty(),
            "neither half reached the sink"
        );
        // One counted by the sink for the held half; the caller counts the
        // returned shed.
        assert_eq!(losses.snapshot().secret_withheld, 1);
    }

    #[test]
    fn benign_stdio_chunks_pass_in_order_once_the_stream_covers_the_carry_or_the_hold_ends() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        sink.try_ingest(&stdout(1, b"hello "));
        sink.try_ingest(&stdout(2, b"world\n"));
        assert!(
            kept_sequences(&kept).is_empty(),
            "chunks shorter than the carry stay held"
        );
        sink.try_ingest(&stdout(3, &[b'.'; 64]));
        assert_eq!(
            kept_sequences(&kept),
            vec![1, 2],
            "a chunk longer than the carry clears what came before it"
        );

        // The hold is bounded in time, not only by what follows.
        sink.release_expired(Instant::now() + STDIO_HOLD);
        assert_eq!(kept_sequences(&kept), vec![1, 2, 3]);
    }

    #[test]
    fn a_secret_written_one_byte_per_chunk_is_withheld_with_every_held_piece() {
        let kept = Keep::default();
        let losses = Arc::new(LossCounters::default());
        let mut sink =
            ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::clone(&losses));
        let mut outcomes = Vec::new();
        for (at, byte) in SECRET.bytes().enumerate() {
            outcomes.push(sink.try_ingest(&stdout(at as u64 + 1, &[byte])));
        }
        sink.release_held();
        assert_eq!(
            outcomes.last(),
            Some(&IngestOutcome::Shed(LossClass::SecretWithheld)),
            "the byte completing the secret is refused"
        );
        assert!(
            kept_sequences(&kept).is_empty(),
            "no piece of the secret reached the sink"
        );
        assert_eq!(
            losses.snapshot().secret_withheld,
            SECRET.len() as u64 - 1,
            "every held piece is counted; the caller counts the last"
        );
    }

    #[test]
    fn a_secret_split_three_ways_is_withheld() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        let third = SECRET.len() / 3;
        let (a, rest) = SECRET.as_bytes().split_at(third);
        let (b, c) = rest.split_at(third);
        sink.try_ingest(&stdout(1, a));
        sink.try_ingest(&stdout(2, b));
        assert_eq!(
            sink.try_ingest(&stdout(3, c)),
            IngestOutcome::Shed(LossClass::SecretWithheld)
        );
        sink.release_held();
        assert!(kept_sequences(&kept).is_empty());
    }

    /// The whole secret never reached `kept`, in any concatenation of what
    /// it holds.
    fn never_whole(kept: &Keep) -> bool {
        let mut all = Vec::new();
        for record in kept.0.lock().unwrap().iter() {
            for_each_payload_field(record, |bytes| all.extend_from_slice(bytes));
        }
        !all.windows(SECRET.len()).any(|w| w == SECRET.as_bytes())
    }

    #[test]
    fn a_secret_completed_after_the_hold_expired_still_withholds_its_completion() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        let (head, tail) = SECRET.as_bytes().split_at(SECRET.len() / 2);
        sink.try_ingest(&stdout(1, head));
        // The guest pauses past the hold: the first half is passed on.
        sink.release_expired(Instant::now() + STDIO_HOLD);
        assert_eq!(kept_sequences(&kept), vec![1]);
        assert_eq!(
            sink.try_ingest(&stdout(2, tail)),
            IngestOutcome::Shed(LossClass::SecretWithheld),
            "the release kept the stream's context"
        );
        sink.release_held();
        assert!(never_whole(&kept));
    }

    #[test]
    fn a_session_boundary_does_not_reset_the_scan_context() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        let (head, tail) = SECRET.as_bytes().split_at(SECRET.len() / 2);
        sink.try_ingest(&stdout(1, head));
        // The session ends (a reconnect, a restore) and a new one begins.
        sink.release_held();
        assert_eq!(
            sink.try_ingest(&stdout(2, tail)),
            IngestOutcome::Shed(LossClass::SecretWithheld)
        );
        sink.release_held();
        assert!(never_whole(&kept));
    }

    #[test]
    fn crowding_out_held_streams_does_not_cost_any_stream_its_context() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(fingerprints(), seam(), kept.clone(), Arc::default());
        let (head, tail) = SECRET.as_bytes().split_at(SECRET.len() / 2);
        let producers = MAX_HELD_STREAMS as u32 * 2;
        let chunk = |producer: u32, sequence: u64, bytes: &[u8]| {
            TelemetryRecord::builder()
                .epoch(ProducerEpoch::new([5; 16]).unwrap())
                .producer(producer)
                .sequence(sequence)
                .source(SourceKind::GuestAgent)
                .body(RecordBody::Stdio {
                    stream: StdioStream::Stdout,
                    bytes: BoundedList::new(bytes.to_vec()).unwrap(),
                })
                .build()
                .unwrap()
        };
        for producer in 1..=producers {
            sink.try_ingest(&chunk(producer, 1, head));
        }
        for producer in 1..=producers {
            assert_eq!(
                sink.try_ingest(&chunk(producer, 2, tail)),
                IngestOutcome::Shed(LossClass::SecretWithheld),
                "producer {producer}"
            );
        }
        sink.release_held();
        assert!(never_whole(&kept));
    }

    #[test]
    fn a_field_the_seam_refuses_withholds_the_record() {
        let record = records_carrying("anything").remove(1);
        assert!(redact_body(record.body(), &mut |_| None).is_none());
    }

    #[test]
    fn a_masked_field_that_outgrows_its_bound_withholds_the_record() {
        let record = records_carrying("anything").remove(0);
        let mut grow = |input: &[u8]| Some([input, &[b'x'; 4096]].concat());
        assert!(redact_body(record.body(), &mut grow).is_none());
    }

    #[test]
    fn a_dead_writer_sheds_every_later_record_rather_than_writing_it_elsewhere() {
        struct Dies;
        impl RecordSink for Dies {
            fn try_ingest(&mut self, _record: &TelemetryRecord) -> IngestOutcome {
                panic!("the writer died");
            }
        }
        let losses = Arc::new(LossCounters::default());
        let mut queue = QueuedSink::spawn("dies", 1, Dies, Arc::clone(&losses)).unwrap();
        let _ = queue.try_ingest(&coverage(1));
        // Wait for the writer to take the record and die.
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.writer.as_ref().is_some_and(|w| !w.is_finished()) {
            assert!(Instant::now() < deadline, "writer did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        for sequence in 2..5 {
            assert_eq!(
                queue.try_ingest(&coverage(sequence)),
                IngestOutcome::Shed(LossClass::QueueFull)
            );
        }
    }

    #[test]
    fn pii_the_stream_plane_masks_is_masked_in_every_field_kind_before_the_sink() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(Vec::new(), seam(), kept.clone(), Arc::default());
        let email = "ops.oncall@example.org";
        for record in records_carrying(email) {
            assert_eq!(sink.try_ingest(&record), IngestOutcome::Ingested);
        }
        let kept = kept.0.lock().unwrap();
        assert_eq!(kept.len(), 3);
        for record in kept.iter() {
            // The fields themselves, not the encoding: stdio serializes as a
            // byte array, where neither the address nor the mask is text.
            let mut fields = Vec::new();
            for_each_payload_field(record, |bytes| fields.extend_from_slice(bytes));
            let fields = String::from_utf8_lossy(&fields);
            assert!(
                !fields.contains(email),
                "record {} kept the address",
                record.sequence()
            );
            assert!(
                fields.contains("XXX"),
                "record {} was not masked",
                record.sequence()
            );
        }
        // Identity and order survive the rewrite.
        assert_eq!(
            kept.iter()
                .map(TelemetryRecord::sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn a_record_with_nothing_to_mask_is_passed_on_unchanged() {
        let record = records_carrying("plain words").remove(0);
        assert!(matches!(
            redact_record(&seam(), &record),
            Some(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn a_withheld_record_never_reaches_the_records_file_in_any_encoding() {
        let path = tempfile::tempdir().unwrap();
        let file = path.path().join("records.jsonl");
        let losses = Arc::new(LossCounters::default());
        let mut sink = ScrubbingSink::new(
            fingerprints(),
            seam(),
            CappedJsonlSink::create(&file, 1 << 20, test_key()).unwrap(),
            Arc::clone(&losses),
        );
        for record in records_carrying(SECRET) {
            sink.try_ingest(&record);
        }
        sink.try_ingest(&coverage(9));
        sink.release_held();
        let written = std::fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&written).contains("sink-witness"),
            "lines are sealed, not plaintext"
        );
        // Open every line and look in what it says, not only in the file.
        let opened: Vec<_> = written
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| ReceivedRecord::open_line(&test_key(), line).expect("opens"))
            .collect();
        assert_eq!(opened.len(), 1, "only the coverage record");
        let text = String::from_utf8(opened[0].record.encode().unwrap()).unwrap();
        assert!(!text.contains(SECRET));
        // The stdio chunk is serialized as a byte array: look for that too.
        let as_array = serde_json::to_string(SECRET.as_bytes()).unwrap();
        let inner = &as_array[1..as_array.len() - 1];
        assert!(!text.contains(inner));
    }

    #[test]
    fn a_line_that_cannot_be_opened_under_another_key_is_not_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("records.jsonl");
        let mut sink = CappedJsonlSink::create(&file, 1 << 20, test_key()).unwrap();
        assert_eq!(sink.try_ingest(&coverage(1)), IngestOutcome::Ingested);
        let written = std::fs::read(&file).unwrap();
        assert!(ReceivedRecord::open_line(&test_key(), &written).is_some());
        assert!(ReceivedRecord::open_line(&aead::Key::from_bytes([1; 32]), &written).is_none());
        assert!(ReceivedRecord::decode_line(&written).is_none());
    }

    #[test]
    fn a_vm_without_bound_secrets_holds_no_stdio_back() {
        let kept = Keep::default();
        let mut sink = ScrubbingSink::new(Vec::new(), seam(), kept.clone(), Arc::default());
        sink.try_ingest(&stdout(1, b"no secrets here"));
        assert_eq!(kept_sequences(&kept), vec![1]);
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
        let one_line = ReceivedRecord::seal_line(&test_key(), u64::MAX / 2, &coverage(1))
            .unwrap()
            .len() as u64;
        let inner =
            CappedJsonlSink::create(&dir.path().join("r.jsonl"), one_line, test_key()).unwrap();
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
        let mut sink = CappedJsonlSink::over(FlakyFile::default(), u64::MAX, test_key()).unwrap();
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
            .map(|line| ReceivedRecord::open_line(&test_key(), line).expect("every line decodes"))
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
        let one_line = ReceivedRecord::seal_line(&test_key(), before, &record)
            .unwrap()
            .len() as u64;
        let mut sink = CappedJsonlSink::create(&path, one_line * 2 + 1, test_key()).unwrap();
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
            let served = ReceivedRecord::open_line(&test_key(), line).expect("the served envelope");
            assert_eq!(served.record, record);
            assert!(served.received_at_ms.is_some_and(|at| at >= before));
        }
        // Reopening appends: the cap counts what is already there.
        let mut reopened = CappedJsonlSink::create(&path, one_line * 3, test_key()).unwrap();
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
