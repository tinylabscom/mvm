//! [`StreamBroker`]: one producer in, N followers out, with redaction,
//! hash-chaining, and durable capture in between.
//!
//! Every captured chunk takes the same four steps, in this order:
//!
//! 1. **Redact.** The one seam. See [`super::redact`] for why it runs first
//!    and what that costs.
//! 2. **Stamp and chain.** The broker owns `seq` and `host_unix_nanos`; the
//!    guest never proposes either. Ordering within one source is exact.
//!    Between `Console` and `Entrypoint` it is arrival order and nothing
//!    stronger — those two travel different paths at different latencies, so
//!    a total order is not something the transport can deliver.
//! 3. **Persist.** Append to the AEAD-encrypted transcript.
//! 4. **Fan out.** Push to each follower's bounded ring.
//!
//! Steps 3 and 4 are deliberately not fate-shared. A follower that stops
//! draining loses its own oldest records and nobody else's; a transcript
//! write that fails leaves a hole on disk without silencing the live stream.
//! Neither can reach back and stall ingest, which is the whole point: a
//! workload must not slow down, or die, because logging did.
//!
//! One broker per VM, resident in the per-tenant daemon rather than spawned
//! per VM.

use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use mvm_core::plan::ExecutionPlan;
use mvm_core::transcript::{CaptureBounds, Direction, TranscriptManifest, TranscriptWriter};
use mvm_protocol::stream::{StreamKind, StreamRecord, StreamSource};

use crate::audit::emitter::AuditEmitter;
use crate::stream::fanout::{
    DEFAULT_READER_BOUNDS, ReaderHandle, ReaderQueue, ReaderStart, lock_queue,
};
use crate::stream::redact::{StreamRedactor, redaction_failure_marker};
use crate::supervisor::pii_redactor::PiiRedactor;

/// Default budget for the durable transcript one broker writes into.
///
/// The chunk cap is deliberately modest and it is usually not the binding
/// one: at realistic chunk sizes the byte cap hits first, and the chunk cap
/// only matters for a workload writing a few bytes at a time. It exists
/// because a chunk is a file today, so an unbounded chunk count is an
/// unbounded inode count in one directory.
///
/// Outrunning this budget does not silence anything. Followers are
/// unaffected — only the durable copy stops growing — and the shortfall is
/// visible as [`StreamCounters::persist_failures`] rather than as an absence
/// nobody can distinguish from a quiet workload.
pub const DEFAULT_CAPTURE_BOUNDS: CaptureBounds = CaptureBounds {
    // The transcript is bounded by size and count, not by age.
    max_duration_secs: u64::MAX,
    max_bytes: 8 << 20,
    max_chunks: 4_096,
};

/// What a broker has done since it started. Counters only — nothing here
/// holds a payload byte.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamCounters {
    /// Chunks offered to [`StreamBroker::ingest`]. Equals the number of
    /// records the broker produced: every chunk yields exactly one record,
    /// a redaction failure included.
    pub ingested: u64,
    /// Chunks where at least one redaction rule fired.
    pub redacted: u64,
    /// Chunks the seam refused to vouch for, replaced by a `Trace` marker.
    pub redaction_failures: u64,
    /// Records the durable transcript refused or failed to take. Each one is
    /// a hole on disk that the live stream does not have.
    pub persist_failures: u64,
    /// Followers that have attached over this broker's lifetime.
    pub subscribers: u64,
    /// Subscribe events that could not be written to the chain-signed log.
    pub audit_failures: u64,
}

/// Binds a broker's subscribe events to the chain-signed audit log.
///
/// Carries the admitted plan because every entry in that chain is
/// plan-bound; a stream event that could not name its plan would float free
/// of the admission it belongs to.
pub struct StreamAudit {
    emitter: AuditEmitter,
    plan: ExecutionPlan,
}

impl StreamAudit {
    /// Bind `emitter` to the plan the VM was admitted under.
    pub fn new(emitter: AuditEmitter, plan: ExecutionPlan) -> Self {
        Self { emitter, plan }
    }

    fn emit_subscribed(&self, vm: &str, reader_id: u64, from_seq: u64) -> anyhow::Result<()> {
        self.emitter
            .emit_stream_subscribed(&self.plan, vm, reader_id, from_seq)
    }
}

/// The host-side stream broker for one VM.
pub struct StreamBroker {
    vm: String,
    writer: TranscriptWriter,
    redactor: Box<dyn StreamRedactor>,
    audit: Option<StreamAudit>,
    reader_bounds: CaptureBounds,
    readers: Vec<Weak<Mutex<ReaderQueue>>>,
    next_reader_id: u64,
    next_seq: u64,
    prev_hash: [u8; 32],
    last_stamp_nanos: u64,
    counters: StreamCounters,
}

impl StreamBroker {
    /// Build a broker for `vm` over the curated PII ruleset.
    pub fn new(vm: &str, writer: TranscriptWriter, redactor: PiiRedactor) -> Self {
        Self::with_redactor(vm, writer, Box::new(redactor))
    }

    /// Build a broker over an arbitrary redaction seam — a stricter ruleset,
    /// or a detector that can refuse.
    pub fn with_redactor(
        vm: &str,
        writer: TranscriptWriter,
        redactor: Box<dyn StreamRedactor>,
    ) -> Self {
        Self {
            vm: vm.to_string(),
            writer,
            redactor,
            audit: None,
            reader_bounds: DEFAULT_READER_BOUNDS,
            readers: Vec::new(),
            next_reader_id: 0,
            next_seq: 0,
            prev_hash: [0u8; 32],
            last_stamp_nanos: 0,
            counters: StreamCounters::default(),
        }
    }

    /// Record every subscribe in the chain-signed audit log. Without a
    /// binding the broker still streams; it just leaves no signed trace of
    /// who attached.
    #[must_use]
    pub fn with_audit(mut self, audit: StreamAudit) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Override how far one follower may fall behind before its oldest
    /// records are dropped.
    #[must_use]
    pub fn with_reader_bounds(mut self, bounds: CaptureBounds) -> Self {
        self.reader_bounds = bounds;
        self
    }

    /// The VM this broker captures.
    pub fn vm(&self) -> &str {
        &self.vm
    }

    /// Counters for everything this broker has done.
    pub fn counters(&self) -> StreamCounters {
        self.counters
    }

    /// Chunks accepted so far. Never decreases and never stalls — ingest has
    /// no refusing path.
    pub fn ingested_count(&self) -> u64 {
        self.counters.ingested
    }

    /// The sequence number the next record will carry.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Hash of the newest record, or all-zero before the first one.
    ///
    /// This is the anchor a consumer holding a partial window verifies
    /// against: a follower that attached mid-stream, or one whose oldest
    /// records were pruned, has no genesis to chain back to.
    pub fn head_hash(&self) -> [u8; 32] {
        self.prev_hash
    }

    /// Followers still attached.
    pub fn reader_count(&self) -> usize {
        self.readers.iter().filter(|r| r.strong_count() > 0).count()
    }

    /// Attach a follower. It receives every record ingested from now on;
    /// earlier records live in the transcript, not in its queue.
    pub fn subscribe(&mut self) -> ReaderHandle {
        let id = self.next_reader_id;
        self.next_reader_id = self.next_reader_id.saturating_add(1);
        let start = ReaderStart {
            id,
            from_seq: self.next_seq,
            anchor: self.prev_hash,
        };
        let handle = ReaderHandle::new(start, self.reader_bounds);
        self.readers.push(handle.weak_queue());
        self.counters.subscribers = self.counters.subscribers.saturating_add(1);
        self.audit_subscribe(id);
        handle
    }

    /// Take one captured chunk: redact it, chain it, persist it, deliver it.
    ///
    /// Always accepts. There is no bound, no error, and no backpressure at
    /// this end — a workload silenced or slowed at a cap is unobservable
    /// exactly when it matters most.
    pub fn ingest(&mut self, source: StreamSource, kind: StreamKind, bytes: &[u8]) {
        self.counters.ingested = self.counters.ingested.saturating_add(1);
        let (kind, payload) = self.clear_for_display(source, kind, bytes);
        let record = self.seal_record(source, kind, payload);
        self.persist(&record);
        self.fan_out(Arc::new(record));
    }

    /// Seal the transcript and hand back its manifest. The sealed Merkle
    /// root covers every chunk that reached disk.
    pub fn seal(self) -> TranscriptManifest {
        self.writer.seal()
    }

    /// Run the chunk through the seam, or replace it with a marker.
    ///
    /// Fail closed: a byte nobody could check does not ship. The marker
    /// keeps the gap visible — a reader learns output was suppressed instead
    /// of silently seeing less than the workload wrote.
    fn clear_for_display(
        &mut self,
        source: StreamSource,
        kind: StreamKind,
        bytes: &[u8],
    ) -> (StreamKind, Vec<u8>) {
        match self.redactor.redact(bytes) {
            Ok(redacted) => {
                if !redacted.rules_fired.is_empty() {
                    self.counters.redacted = self.counters.redacted.saturating_add(1);
                    tracing::debug!(
                        vm = %self.vm,
                        rules = ?redacted.rules_fired,
                        "stream chunk redacted"
                    );
                }
                (kind, redacted.body)
            }
            Err(err) => {
                self.counters.redaction_failures =
                    self.counters.redaction_failures.saturating_add(1);
                tracing::warn!(
                    vm = %self.vm,
                    dropped_bytes = bytes.len(),
                    reason = %err,
                    "stream chunk withheld: redaction failed"
                );
                let marker = redaction_failure_marker(source, kind, bytes.len() as u64);
                (StreamKind::Trace, marker)
            }
        }
    }

    /// Stamp the record and link it to its predecessor.
    fn seal_record(
        &mut self,
        source: StreamSource,
        kind: StreamKind,
        payload: Vec<u8>,
    ) -> StreamRecord {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let record = StreamRecord {
            seq,
            source,
            kind,
            host_unix_nanos: self.stamp(),
            prev_hash: self.prev_hash,
            payload,
        };
        self.prev_hash = record.hash();
        record
    }

    /// Host wall-clock, forced non-decreasing.
    ///
    /// `seq` is the ordering authority; the stamp is what a human reads. An
    /// NTP step backwards would otherwise render a later record as earlier,
    /// so the clock is clamped to the last stamp issued rather than allowed
    /// to walk back.
    fn stamp(&mut self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(self.last_stamp_nanos);
        self.last_stamp_nanos = self.last_stamp_nanos.max(now);
        self.last_stamp_nanos
    }

    /// Append to the durable transcript, best-effort.
    ///
    /// The transcript's own budget fails closed, which is right for a
    /// forensic capture and wrong for a live stream: refusing here would
    /// silence followers to protect a disk bound. A failed append is counted
    /// and logged instead, so an absent chunk on disk is distinguishable
    /// from one that was never produced.
    fn persist(&mut self, record: &StreamRecord) {
        let direction = match record.kind {
            StreamKind::Stdout => Direction::Stdout,
            StreamKind::Stderr => Direction::Stderr,
            StreamKind::Trace => Direction::Trace,
        };
        if let Err(err) = self.writer.push(direction, &record.payload) {
            self.counters.persist_failures = self.counters.persist_failures.saturating_add(1);
            tracing::warn!(
                vm = %self.vm,
                seq = record.seq,
                error = %err,
                "stream chunk not persisted"
            );
        }
    }

    /// Hand the record to every live follower.
    ///
    /// `retain` doubles as the reaper: a dropped handle frees its queue, and
    /// the dangling reference goes with it on the next record rather than
    /// accumulating for the life of the VM.
    fn fan_out(&mut self, record: Arc<StreamRecord>) {
        self.readers.retain(|reader| match reader.upgrade() {
            Some(queue) => {
                lock_queue(&queue).push(Arc::clone(&record));
                true
            }
            None => false,
        });
    }

    /// Record the attach in the chain-signed log. Failing to audit degrades
    /// the trace, never the stream — same posture the rest of the emitter
    /// takes.
    fn audit_subscribe(&mut self, reader_id: u64) {
        let from_seq = self.next_seq;
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let result = audit.emit_subscribed(&self.vm, reader_id, from_seq);
        if let Err(err) = result {
            self.counters.audit_failures = self.counters.audit_failures.saturating_add(1);
            tracing::warn!(
                vm = %self.vm,
                reader_id,
                error = %err,
                "stream subscribe not audited"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::fanout::DEFAULT_READER_MAX_RECORDS;
    use crate::stream::redact::{Redacted, RedactionFailed};
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{
        CaptureBinding, TranscriptWriterConfig, export, verify_chunks, verify_sealed_root,
    };
    use mvm_protocol::stream::{verify_chain, verify_chain_from};
    use std::ops::{Deref, DerefMut};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// Holds the transcript tempdir alive for as long as the broker writing
    /// into it, so a test can own one value and still drive the real
    /// persistence path.
    struct TestBroker {
        broker: StreamBroker,
        dir: TempDir,
    }

    impl Deref for TestBroker {
        type Target = StreamBroker;
        fn deref(&self) -> &StreamBroker {
            &self.broker
        }
    }

    impl DerefMut for TestBroker {
        fn deref_mut(&mut self) -> &mut StreamBroker {
            &mut self.broker
        }
    }

    /// Roomy enough that the transcript's own fail-closed budget never binds,
    /// for the tests that assert every record reached disk.
    fn unbounded_capture_bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: 64 << 20,
            max_chunks: 1_000_000,
        }
    }

    /// `aead::Key` is deliberately not `Clone`, so tests that need to read a
    /// capture back rebuild the same key from fixed bytes.
    fn test_key() -> aead::Key {
        aead::Key::from_bytes([0x5a; 32])
    }

    fn writer_at(dir: &Path, vm: &str, bounds: CaptureBounds) -> TranscriptWriter {
        TranscriptWriter::new(
            dir,
            test_key(),
            TranscriptWriterConfig {
                capture_id: format!("capture-{vm}"),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: vm.to_string(),
                    session_id: None,
                },
                bounds,
                created_unix_secs: 0,
                recipient: "host:test".to_string(),
                wrapped_data_key_b64: String::new(),
            },
        )
    }

    /// A broker configured the way production configures one: the shipped
    /// reader ring and the shipped capture budget, writing real encrypted
    /// chunks to a real directory.
    fn broker_for(vm: &str) -> TestBroker {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), vm, DEFAULT_CAPTURE_BOUNDS);
        TestBroker {
            broker: StreamBroker::new(vm, writer, PiiRedactor::with_default_rules()),
            dir,
        }
    }

    fn broker_with_reader_bounds(vm: &str, bounds: CaptureBounds) -> TestBroker {
        let fixture = broker_for(vm);
        TestBroker {
            broker: fixture.broker.with_reader_bounds(bounds),
            dir: fixture.dir,
        }
    }

    /// A seam that refuses to vouch for anything — the shape a detector with
    /// a timeout or a crashed subprocess presents.
    struct FailingRedactor;

    impl StreamRedactor for FailingRedactor {
        fn redact(&self, _body: &[u8]) -> Result<Redacted, RedactionFailed> {
            Err(RedactionFailed::new("detector unavailable"))
        }
    }

    fn broker_with_failing_redactor(vm: &str) -> TestBroker {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), vm, DEFAULT_CAPTURE_BOUNDS);
        TestBroker {
            broker: StreamBroker::with_redactor(vm, writer, Box::new(FailingRedactor)),
            dir,
        }
    }

    // --- the required behaviours -----------------------------------------

    #[test]
    fn every_subscriber_sees_every_record() {
        let mut b = broker_for("vm-a");
        let mut r1 = b.subscribe();
        let mut r2 = b.subscribe();
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"hello");
        assert_eq!(r1.recv().expect("r1 record").payload, b"hello");
        assert_eq!(r2.recv().expect("r2 record").payload, b"hello");
    }

    #[test]
    fn redaction_runs_before_the_chain_so_no_reader_sees_raw_matches() {
        let mut b = broker_for("vm-a");
        let mut r = b.subscribe();
        b.ingest(
            StreamSource::Entrypoint,
            StreamKind::Stdout,
            b"card 4111111111111111 end",
        );
        let got = r.recv().expect("record");
        assert!(!got.payload.windows(16).any(|w| w == b"4111111111111111"));
    }

    #[test]
    fn ingested_records_form_a_verifiable_chain() {
        let mut b = broker_for("vm-a");
        let mut r = b.subscribe();
        for i in 0..5u8 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &[i]);
        }
        let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(5).collect();
        verify_chain(&records).expect("broker output must verify");
    }

    #[test]
    fn a_chunk_that_cannot_be_redacted_is_dropped_not_forwarded() {
        // Fail closed: a byte that cannot be checked does not ship.
        let mut b = broker_with_failing_redactor("vm-a");
        let mut r = b.subscribe();
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"unscannable");
        let got = r.recv().expect("a marker still arrives");
        assert_eq!(got.kind, StreamKind::Trace);
        assert!(!got.payload.windows(11).any(|w| w == b"unscannable"));
    }

    #[test]
    fn a_slow_reader_does_not_stall_ingest() {
        let mut b = broker_for("vm-a");
        let slow = b.subscribe(); // deliberately never drained
        let started = Instant::now();
        for i in 0..10_000u32 {
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                &i.to_le_bytes(),
            );
        }
        // Fail loudly rather than hanging until the harness timeout kills us.
        assert_eq!(b.ingested_count(), 10_000, "every ingest must be accepted");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "ingest must never wait on a reader"
        );
        assert!(
            slow.dropped_count() > 0,
            "the undrained reader must show its gap"
        );
    }

    // --- coverage beyond the required set --------------------------------

    #[test]
    fn the_broker_and_its_readers_cross_thread_boundaries() {
        // A resident per-tenant daemon owns the broker on one thread and
        // hands readers to connection handlers on others; a non-`Send` field
        // would only show up when that wiring lands.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<StreamBroker>();
        assert_send::<ReaderHandle>();
        assert_sync::<ReaderHandle>();
    }

    #[test]
    fn fan_out_cost_does_not_grow_as_a_reader_falls_further_behind() {
        // The property the test above is really about, measured without the
        // transcript's per-chunk disk write dominating the number: eviction
        // must cost O(evicted), not O(queue). A full scan per drop turns one
        // stalled follower into quadratic work on the producer.
        let dir = tempfile::tempdir().expect("tempdir");
        // A capture budget of zero: every append short-circuits before any
        // I/O, so what is timed is redact -> chain -> fan out.
        let writer = writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 0,
                max_chunks: 0,
            },
        );
        let mut b = StreamBroker::new("vm-a", writer, PiiRedactor::with_default_rules());
        let slow = b.subscribe();

        for i in 0..10_000u32 {
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                &i.to_le_bytes(),
            );
        }
        assert_eq!(
            slow.pending() as u64,
            DEFAULT_READER_MAX_RECORDS,
            "the queue must sit at its bound, not grow"
        );

        // Second burst: every single record now evicts, which is the worst
        // case. Measured at ~17ms locally, so a second is a wide margin that
        // still catches a return to per-eviction scanning.
        let started = Instant::now();
        for i in 0..10_000u32 {
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                &i.to_le_bytes(),
            );
        }
        let saturated = started.elapsed();
        assert!(
            saturated < Duration::from_secs(1),
            "eviction must not scale with queue depth (took {saturated:?})"
        );
        assert_eq!(slow.pending() as u64, DEFAULT_READER_MAX_RECORDS);
        assert_eq!(b.counters().persist_failures, 20_000);
    }

    #[test]
    fn a_redaction_failure_is_counted_and_never_persisted_raw() {
        let mut b = broker_with_failing_redactor("vm-a");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"unscannable");
        assert_eq!(b.counters().redaction_failures, 1);

        let TestBroker { broker, dir } = b;
        let manifest = broker.seal();
        // The chunk on disk is the marker, not the payload: ciphertext of
        // the withheld bytes would be a leak deferred, not prevented.
        assert_eq!(manifest.chunks.len(), 1);
        assert_eq!(manifest.chunks[0].direction, Direction::Trace);
        let shown = export(&manifest, dir.path(), &test_key()).expect("export");
        assert!(!shown.windows(11).any(|w| w == b"unscannable"));
        assert!(
            export(&manifest, dir.path(), &aead::Key::from_bytes([0x01; 32])).is_err(),
            "a foreign key must not decrypt the capture"
        );
    }

    #[test]
    fn the_transcript_holds_every_redacted_record_and_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new("vm-a", writer, PiiRedactor::with_default_rules());
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"out");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stderr, b"err");
        b.ingest(
            StreamSource::Console,
            StreamKind::Stdout,
            b"card 4111111111111111",
        );

        let manifest = b.seal();
        verify_sealed_root(&manifest).expect("sealed root");
        verify_chunks(&manifest, dir.path()).expect("chunks");
        assert_eq!(
            manifest
                .chunks
                .iter()
                .map(|c| c.direction)
                .collect::<Vec<_>>(),
            vec![Direction::Stdout, Direction::Stderr, Direction::Stdout]
        );

        let bytes = export(&manifest, dir.path(), &test_key()).expect("export");
        assert!(bytes.starts_with(b"outerr"));
        assert!(
            !bytes.windows(16).any(|w| w == b"4111111111111111"),
            "the transcript stores what was shown, not what was written"
        );
    }

    #[test]
    fn one_sequence_spans_both_sources() {
        let mut b = broker_for("vm-a");
        let mut r = b.subscribe();
        b.ingest(StreamSource::Console, StreamKind::Stdout, b"kernel");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stderr, b"app");
        let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(2).collect();
        assert_eq!(records[0].source, StreamSource::Console);
        assert_eq!(records[1].source, StreamSource::Entrypoint);
        verify_chain(&records).expect("one chain covers both sources");
    }

    #[test]
    fn stamps_never_walk_backwards() {
        let mut b = broker_for("vm-a");
        let mut r = b.subscribe();
        for _ in 0..64 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"x");
        }
        let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(64).collect();
        assert!(
            records
                .windows(2)
                .all(|w| w[1].host_unix_nanos >= w[0].host_unix_nanos),
            "a clock step must not reorder the rendered timeline"
        );
    }

    #[test]
    fn a_late_subscriber_verifies_its_window_against_the_broker_head() {
        let mut b = broker_for("vm-a");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"before");
        let head = b.head_hash();
        let mut late = b.subscribe();
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"after-1");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"after-2");

        // The reader carries its own anchor, so a consumer can verify what it
        // was handed without going back to the broker.
        assert_eq!(late.anchor(), head);
        assert_eq!(late.from_seq(), 1);
        let anchor = late.anchor();

        let window: Vec<_> = std::iter::from_fn(|| late.recv()).take(2).collect();
        assert_eq!(window[0].seq, 1, "a late reader starts where it attached");
        assert!(
            verify_chain(&window).is_err(),
            "a mid-stream window is not a genesis chain"
        );
        verify_chain_from(&window, anchor).expect("anchored at the head it attached to");
    }

    #[test]
    fn a_pruned_window_still_verifies_from_the_record_before_the_gap() {
        let mut b = broker_with_reader_bounds(
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 4,
            },
        );
        let mut keeping_up = b.subscribe();
        let mut falling_behind = b.subscribe();
        let mut full: Vec<StreamRecord> = Vec::new();
        for i in 0..10u8 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &[i]);
            full.extend(std::iter::from_fn(|| keeping_up.recv()));
        }

        assert_eq!(full.len(), 10, "the drained reader misses nothing");
        assert_eq!(keeping_up.gap(), None);
        let gap = falling_behind.gap().expect("the slow reader lost records");
        let survivors: Vec<_> = std::iter::from_fn(|| falling_behind.recv()).collect();

        assert_eq!(survivors.len(), 4, "the window holds its bound, not more");
        assert_eq!(survivors[0].seq, gap.after_seq + 1);
        let anchor = full
            .iter()
            .find(|r| r.seq == gap.after_seq)
            .expect("the record before the gap")
            .hash();
        verify_chain_from(&survivors, anchor).expect("the surviving window is unbroken");
    }

    #[test]
    fn a_dropped_reader_stops_costing_anything() {
        let mut b = broker_for("vm-a");
        let keep = b.subscribe();
        {
            let _transient = b.subscribe();
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                b"seen by both",
            );
            assert_eq!(b.reader_count(), 2);
        }
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"seen by one");
        assert_eq!(b.reader_count(), 1, "the dangling reference is reaped");
        assert_eq!(keep.pending(), 2);
    }

    #[test]
    fn a_persist_failure_never_silences_a_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A budget of one chunk: the second append fails closed.
        let writer = writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 1,
            },
        );
        let mut b = StreamBroker::new("vm-a", writer, PiiRedactor::with_default_rules());
        let mut r = b.subscribe();
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"one");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"two");

        assert_eq!(b.counters().persist_failures, 1);
        let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(2).collect();
        assert_eq!(records.len(), 2, "the live stream outlives the disk bound");
        verify_chain(&records).expect("the chain does not skip an unpersisted record");
    }

    #[test]
    fn subscribing_writes_a_chain_signed_entry_carrying_no_payload_bytes() {
        let audit_dir = tempfile::tempdir().expect("tempdir");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let emitter = AuditEmitter::with_dir(signing_key, audit_dir.path()).expect("emitter");
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-stream")
            .build();

        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", DEFAULT_CAPTURE_BOUNDS);
        let mut b = StreamBroker::new("vm-a", writer, PiiRedactor::with_default_rules())
            .with_audit(StreamAudit::new(emitter, plan));

        let _reader = b.subscribe();
        let secret = b"card 4111111111111111 end";
        for _ in 0..16 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, secret);
        }

        let chain = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&chain).expect("audit chain");
        assert_eq!(
            content.lines().count(),
            1,
            "one entry per attach, never one per record"
        );
        assert!(content.contains("stream.subscribed"));
        assert!(content.contains("vm-a"));
        assert!(
            !content.contains("4111111111111111"),
            "the audit chain must carry no payload bytes"
        );
        assert!(
            !content.contains("XXX"),
            "not even the redacted payload belongs in the chain"
        );
        assert_eq!(b.counters().audit_failures, 0);
        verify_audit_chain(&chain, &verifying_key).expect("the entry is chain-signed");
    }
}
