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
//! Neither can *refuse* a chunk and neither can block on a consumer, so no
//! reader and no full disk can ever silence or wedge a workload.
//!
//! **Step 3 does not run on the caller's thread, and does not wait.** Steps 1,
//! 2 and 4 are a regex pass and some hashing — single-digit microseconds. Step
//! 3 is filesystem syscalls against whatever the host's disk is doing at that
//! moment. For the entrypoint source the caller *is* the RPC read thread, so
//! paying that inline makes the guest's pace a function of the host's disk. It
//! runs on a per-broker writer thread instead, behind a bounded hand-off that
//! **sheds** when the writer falls behind rather than blocking the producer —
//! see [`super::durable`], which also explains why nothing shed is silent.
//!
//! One broker per VM, resident in the per-tenant daemon rather than spawned
//! per VM.

use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use mvm_contract::stream::{StreamKind, StreamRecord, StreamSource};
use mvm_core::plan::ExecutionPlan;
use mvm_core::transcript::{
    CaptureBinding, CaptureBounds, RetentionPolicy, TranscriptManifest, TranscriptWriter,
    TranscriptWriterConfig,
};

use crate::audit::emitter::AuditEmitter;
use crate::stream::durable::DurableSink;
use crate::stream::fanout::{
    DEFAULT_READER_BOUNDS, ReaderHandle, ReaderQueue, ReaderStart, lock_queue,
};
use crate::stream::redact::{self, ClearOutcome, ClearedChunk, StreamRedaction};

/// Default budget for the durable transcript one broker writes into.
///
/// The chunk cap used to be an inode cap in disguise — one chunk was one file,
/// so it had to sit low enough that under a second of log output exhausted it.
/// Chunks now share segments, so file count tracks bytes rather than pushes
/// and the cap is free to sit where it actually belongs: at the point where
/// the sealed manifest's own size starts to matter. One `ChunkRecord`
/// serialises to roughly 250 bytes, so 64 Ki records is a manifest in the tens
/// of megabytes — big, bounded, and written once at seal.
///
/// Reaching either bound does not silence anything and no longer stops the
/// durable copy growing: with [`DEFAULT_STREAM_RETENTION`] the transcript
/// drops its oldest chunks to make room for the newest, so the persisted copy
/// holds the most recent window instead of the first few seconds.
/// [`StreamCounters::persist_failures`] is left to mean what it should — the
/// record never landed, not the budget filled.
pub const DEFAULT_CAPTURE_BOUNDS: CaptureBounds = CaptureBounds {
    // The transcript is bounded by size and count, not by age.
    max_duration_secs: u64::MAX,
    max_bytes: 8 << 20,
    max_chunks: 64 * 1024,
};

/// Retention the durable transcript runs under for a live stream.
///
/// A forensic egress capture of discrete frames is right to refuse at its
/// bound. A workload's output is the opposite case: the moment it stops being
/// observed — a crash loop, a runaway process — is the moment it matters most,
/// and the newest bytes are the ones worth keeping. Ring retention applies to
/// the persisted copy the same decision the reader queues already make.
pub const DEFAULT_STREAM_RETENTION: RetentionPolicy = RetentionPolicy::Ring;

/// Who a stream capture belongs to and how its data key was wrapped —
/// everything a [`TranscriptWriter`] needs that is *not* a policy choice.
///
/// Grouped so [`stream_capture_config`] can own the policy half (bounds plus
/// retention) and leave callers no way to supply their own by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCaptureIdentity {
    pub capture_id: String,
    pub binding: CaptureBinding,
    pub created_unix_secs: u64,
    pub recipient: String,
    pub wrapped_data_key_b64: String,
}

/// Configure the transcript writer a [`StreamBroker`] persists into: the
/// shipped budget and ring retention, over the caller's capture identity.
///
/// One door, so a stream transcript cannot be built fail-closed by omission —
/// which would put back the silent stop this whole path exists to remove.
pub fn stream_capture_config(identity: StreamCaptureIdentity) -> TranscriptWriterConfig {
    TranscriptWriterConfig {
        capture_id: identity.capture_id,
        binding: identity.binding,
        bounds: DEFAULT_CAPTURE_BOUNDS,
        retention: DEFAULT_STREAM_RETENTION,
        created_unix_secs: identity.created_unix_secs,
        recipient: identity.recipient,
        wrapped_data_key_b64: identity.wrapped_data_key_b64,
    }
}

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
    /// Records that never reached the durable transcript: the store refused
    /// them, or the hand-off to the writer thread shed them. Each one is a hole
    /// on disk that the live stream does not have, and the sealed manifest
    /// carries the same total as `refused_chunks`.
    pub persist_failures: u64,
    /// How many times persistence went from working to failing. One long
    /// outage counts once; a flapping disk counts every time. This is what
    /// the broker logs, because a per-record warning turns a bounded-disk
    /// problem into an unbounded-log one at a few thousand chunks a second.
    pub persist_lapses: u64,
    /// The part of `persist_failures` the writer thread never saw, because the
    /// hand-off dropped it rather than pace the workload behind the disk. A
    /// full disk and a slow one are different operator problems, so they are
    /// separable here.
    pub persist_shed: u64,
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
    /// `None` for a capture admitted as ephemeral: nothing is written and
    /// nothing is sealed. Everything else about the broker is identical, so
    /// the mode cannot quietly change what a live follower sees.
    durable: Option<DurableSink>,
    redaction: StreamRedaction,
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
    /// Build a broker for `vm` over a redaction seam.
    ///
    /// The only seam a production caller can supply is
    /// [`StreamRedaction::curated`] — see that type for why the parameter is
    /// not a bare [`StreamRedactor`].
    pub fn new(vm: &str, writer: TranscriptWriter, redaction: StreamRedaction) -> Self {
        Self::over(vm, Some(DurableSink::new(vm, writer)), redaction)
    }

    /// Build a broker that fans out and keeps nothing.
    ///
    /// The shape a plan admitted as ephemeral gets. Only the durable half goes
    /// away: redaction, chaining, sequencing and fan-out are unchanged, so a
    /// live follower sees the same records and verifies them the same way, and
    /// nothing about the workload's observability *while it runs* is reduced.
    /// What ends is the recording — [`seal`](Self::seal) has no manifest to
    /// hand back, and a reader arriving after the VM is gone finds no
    /// transcript of it.
    pub fn live_only(vm: &str, redaction: StreamRedaction) -> Self {
        Self::over(vm, None, redaction)
    }

    /// The one assembly both constructors go through, so the two shapes can
    /// only ever differ in the durable half.
    fn over(vm: &str, durable: Option<DurableSink>, redaction: StreamRedaction) -> Self {
        Self {
            vm: vm.to_string(),
            durable,
            redaction,
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
        // An ephemeral capture has nothing to fail at persisting, so its
        // durable counters are zero rather than absent — "wrote nothing on
        // purpose" must not read as "lost everything".
        let durable = self
            .durable
            .as_ref()
            .map(DurableSink::counts)
            .unwrap_or_default();
        StreamCounters {
            persist_failures: durable.missing(),
            persist_lapses: durable.lapses,
            persist_shed: durable.shed_chunks,
            ..self.counters
        }
    }

    /// Whether this broker keeps a durable transcript.
    pub fn persists(&self) -> bool {
        self.durable.is_some()
    }

    /// Block until every record ingested so far has reached the durable
    /// writer. Test-only: nothing in production waits on the store, which is
    /// the whole point of it being on another thread.
    #[cfg(test)]
    pub(in crate::stream) fn drain_transcript(&self) {
        if let Some(durable) = self.durable.as_ref() {
            durable.drain();
        }
    }

    /// The lock the durable writer takes for every append. Test-only: holding
    /// it is how a test stands in for a disk that stopped answering.
    #[cfg(test)]
    pub(in crate::stream) fn transcript_lock(&self) -> Arc<Mutex<TranscriptWriter>> {
        self.durable
            .as_ref()
            .expect("a persisting broker has a writer")
            .writer_lock()
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
    ///
    /// Hands back what the seam decided, which is what lets a producer that is
    /// *also* showing those bytes to somebody — `mvmctl invoke`, writing the
    /// entrypoint's output to the caller's own fds — say how the copy it
    /// recorded differs from the copy it showed. The recorded bytes themselves
    /// are deliberately not handed back: the fan-out and the transcript get the
    /// masked copy, and a caller printing its own function's return value is
    /// not a third party to mask it from. Ignoring the return is fine and
    /// ordinary: the console follower does.
    pub fn ingest(&mut self, source: StreamSource, kind: StreamKind, bytes: &[u8]) -> ClearOutcome {
        self.counters.ingested = self.counters.ingested.saturating_add(1);
        let cleared = self.clear_for_display(source, kind, bytes);
        let record = Arc::new(self.seal_record(source, cleared.kind, cleared.body));
        if let Some(durable) = self.durable.as_ref() {
            durable.push(&record);
        }
        self.fan_out(record);
        cleared.outcome
    }

    /// Seal the transcript and hand back its manifest.
    ///
    /// The sealed Merkle root covers every chunk still on disk **and** the
    /// counts of those that are not: `refused_chunks` for records that never
    /// landed, whether the store refused them or the hand-off shed them (equal
    /// to this broker's `persist_failures`), and `evicted_chunks` for the older
    /// records ring retention dropped to keep the newest. Without those counts
    /// an incomplete artifact passes every verification with nothing saying so
    /// — worse than a loud refusal, because it looks trustworthy.
    ///
    /// Waits for the writer thread to finish what is queued, so a record it
    /// accepted before the seal is a record the manifest accounts for.
    ///
    /// `None` for an ephemeral capture. Not an empty manifest: a manifest with
    /// no chunks asserts that the workload produced nothing, which is a
    /// different and false claim. The reason this capture has no transcript
    /// lives in the plan's retention mode and in `plan.admitted`, not in a
    /// zero-length artifact.
    pub fn seal(self) -> Option<TranscriptManifest> {
        self.durable.map(DurableSink::seal)
    }

    /// Run the chunk through the seam and count what it decided.
    ///
    /// The decision itself lives in [`redact::clear_for_display`], shared with
    /// the entrypoint sink's unrecorded arm; what belongs here is only this
    /// broker's bookkeeping.
    fn clear_for_display(
        &mut self,
        source: StreamSource,
        kind: StreamKind,
        bytes: &[u8],
    ) -> ClearedChunk {
        let cleared = redact::clear_for_display(&self.redaction, source, kind, bytes);
        match &cleared.outcome {
            ClearOutcome::Clean => {}
            ClearOutcome::Redacted { rules_fired } => {
                self.counters.redacted = self.counters.redacted.saturating_add(1);
                tracing::debug!(
                    vm = %self.vm,
                    rules = ?rules_fired,
                    "stream chunk redacted"
                );
            }
            ClearOutcome::Withheld {
                reason,
                dropped_bytes,
            } => {
                self.counters.redaction_failures =
                    self.counters.redaction_failures.saturating_add(1);
                tracing::warn!(
                    vm = %self.vm,
                    dropped_bytes,
                    reason,
                    "stream chunk withheld: redaction failed"
                );
            }
        }
        cleared
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
    use crate::audit::emitter::stream_audit;
    use crate::stream::durable::DURABLE_QUEUE_DEPTH;
    use crate::stream::fanout::DEFAULT_READER_MAX_RECORDS;
    use crate::stream::redact::{Redacted, RedactionFailed, StreamRedactor};
    use crate::supervisor::verify_audit_chain_entries;
    use ed25519_dalek::SigningKey;
    use mvm_contract::stream::{verify_chain, verify_chain_from};
    use mvm_core::crypto::aead;
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::transcript::{
        Direction, SEGMENT_MAX_CHUNKS, export, verify_chunks, verify_sealed_root,
    };
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

    /// Let the durable writer catch up every so often, for the tests whose
    /// subject is what reached disk rather than how fast ingest returned.
    ///
    /// The hand-off sheds once the writer is a full queue behind, and a
    /// synthetic loop outruns a real disk by orders of magnitude — so a test
    /// that wants all of its records on disk has to stay inside that bound.
    /// Production never does this: the whole point is that ingest does not
    /// wait.
    fn keep_the_writer_close(broker: &StreamBroker, ingested: u64) {
        if ingested.is_multiple_of(DURABLE_QUEUE_DEPTH as u64 / 4) {
            broker.drain_transcript();
        }
    }

    /// Roomy enough that no bound binds, for the tests that assert every
    /// record reached disk.
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

    fn identity(vm: &str) -> StreamCaptureIdentity {
        StreamCaptureIdentity {
            capture_id: format!("capture-{vm}"),
            binding: CaptureBinding {
                tenant_id: "local".to_string(),
                vm_name: vm.to_string(),
                session_id: None,
            },
            created_unix_secs: 0,
            recipient: "host:test".to_string(),
            wrapped_data_key_b64: String::new(),
        }
    }

    /// A writer the way a stream broker gets one: ring retention, with the
    /// budget overridden so a test can reach it in a handful of records.
    fn writer_at(dir: &Path, vm: &str, bounds: CaptureBounds) -> TranscriptWriter {
        let mut config = stream_capture_config(identity(vm));
        config.bounds = bounds;
        TranscriptWriter::new(dir, test_key(), config)
    }

    /// A writer that refuses at its bound — the forensic-capture policy, kept
    /// for the one test that wants persistence to short-circuit before any I/O.
    fn fail_closed_writer_at(dir: &Path, vm: &str, bounds: CaptureBounds) -> TranscriptWriter {
        let mut config = stream_capture_config(identity(vm));
        config.bounds = bounds;
        config.retention = RetentionPolicy::FailClosed;
        TranscriptWriter::new(dir, test_key(), config)
    }

    /// A broker configured the way production configures one: the shipped
    /// reader ring and the shipped capture budget, writing real encrypted
    /// chunks to a real directory.
    fn broker_for(vm: &str) -> TestBroker {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), vm, DEFAULT_CAPTURE_BOUNDS);
        TestBroker {
            broker: StreamBroker::new(
                vm,
                writer,
                StreamRedaction::curated(&RedactionPolicy::default()),
            ),
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
            broker: StreamBroker::new(
                vm,
                writer,
                StreamRedaction::from_seam(Box::new(FailingRedactor)),
            ),
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
        // A fail-closed budget of zero: every append short-circuits before
        // any I/O, so what is timed is redact -> chain -> fan out. (The
        // shipped ring would happily write all 20k chunks and time the disk.)
        let writer = fail_closed_writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 0,
                max_chunks: 0,
            },
        );
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
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
        b.drain_transcript();
        assert_eq!(b.counters().persist_failures, 20_000);
    }

    #[test]
    fn a_redaction_failure_is_counted_and_never_persisted_raw() {
        let mut b = broker_with_failing_redactor("vm-a");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"unscannable");
        assert_eq!(b.counters().redaction_failures, 1);

        let TestBroker { broker, dir } = b;
        let manifest = broker.seal().expect("a persisting broker seals");
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
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"out");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stderr, b"err");
        b.ingest(
            StreamSource::Console,
            StreamKind::Stdout,
            b"card 4111111111111111",
        );

        let manifest = b.seal().expect("a persisting broker seals");
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

    /// An ephemeral broker is the same broker with the disk taken out:
    /// redacted, chained, sequenced, delivered — and sealed to nothing.
    #[test]
    fn a_live_only_broker_fans_out_redacted_records_and_seals_no_manifest() {
        let mut b = StreamBroker::live_only(
            "vm-a",
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        assert!(!b.persists());
        let mut reader = b.subscribe();

        b.ingest(
            StreamSource::Entrypoint,
            StreamKind::Stdout,
            b"card 4111111111111111",
        );
        b.ingest(StreamSource::Console, StreamKind::Stdout, b"second");

        let window = reader.drain_verified();
        assert_eq!(window.records.len(), 2, "the fan-out is unchanged");
        assert_eq!(window.records[0].seq, 0);
        assert_eq!(window.records[1].seq, 1);
        assert_eq!(window.records[1].prev_hash, window.records[0].hash());
        assert!(
            !window.records[0]
                .payload
                .windows(16)
                .any(|w| w == b"4111111111111111"),
            "the redaction seam runs whether or not anything is written down"
        );

        let counters = b.counters();
        assert_eq!(counters.ingested, 2);
        assert_eq!(
            (counters.persist_failures, counters.persist_shed),
            (0, 0),
            "nothing was lost; there was nowhere for it to go"
        );
        assert!(
            b.seal().is_none(),
            "no manifest, rather than one asserting the workload printed nothing"
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
        let falling_behind_anchor = falling_behind.anchor();
        let survivors: Vec<_> = std::iter::from_fn(|| falling_behind.recv()).collect();

        assert_eq!(survivors.len(), 4, "the window holds its bound, not more");
        assert_eq!(survivors[0].seq, gap.after_seq + 1);
        let anchor = full
            .iter()
            .find(|r| r.seq == gap.after_seq)
            .expect("the record before the gap")
            .hash();
        verify_chain_from(&survivors, anchor).expect("the surviving window is unbroken");
        // What the second reader supplied above, the pruned reader already
        // carried: this test only passes because `keeping_up` kept a copy of
        // the record that was evicted, which a real lone follower never has.
        assert_eq!(
            falling_behind_anchor, anchor,
            "the pruned reader's own anchor is that same hash"
        );
    }

    #[test]
    fn a_pruned_reader_verifies_its_own_window_with_no_second_reader() {
        // The normal read once the broker starts pruning, exercised the way a
        // real follower sees it: one reader, no keeping-up sibling handing it
        // the evicted record, no broker call. Before the queue kept the
        // evicted hash this was unverifiable — `verify_chain` rejects a
        // non-genesis first `prev_hash`, and the attach anchor is stale.
        let mut b = broker_with_reader_bounds(
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 4,
            },
        );
        let mut lone = b.subscribe();
        for i in 0..10u8 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &[i]);
        }

        let gap = lone.gap().expect("the lone reader lost records");
        let anchor = lone.anchor();
        let survivors: Vec<_> = std::iter::from_fn(|| lone.recv()).collect();

        assert_eq!(survivors.len(), 4);
        assert_eq!(survivors[0].seq, gap.after_seq + 1);
        assert!(
            verify_chain(&survivors).is_err(),
            "a pruned window is not a genesis chain"
        );
        assert_ne!(
            anchor,
            lone.attach_anchor(),
            "the attach anchor is stale once records were lost"
        );
        verify_chain_from(&survivors, anchor)
            .expect("a pruned follower must be able to verify what it was handed");
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
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        let mut r = b.subscribe();
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"one");
        // Let the first one land before the store goes: the writer is on its
        // own thread, so an undrained ingest would be racing the removal that
        // is meant to break only the *second* append.
        b.drain_transcript();
        // Take the store away: the second append has nowhere to land.
        std::fs::remove_dir_all(dir.path()).expect("remove capture dir");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"two");

        b.drain_transcript();
        assert_eq!(b.counters().persist_failures, 1);
        let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(2).collect();
        assert_eq!(records.len(), 2, "the live stream outlives the store");
        verify_chain(&records).expect("the chain does not skip an unpersisted record");
    }

    #[test]
    fn a_transcript_that_stopped_persisting_seals_as_truncated() {
        // A sealed transcript that quietly stopped at the chunk cap is worse
        // than a loud refusal: it verifies clean and reads as the whole of a
        // quiet workload's output. The manifest must say it is a prefix.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = fail_closed_writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 2,
            },
        );
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        for i in 0..7u8 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &[i, i, i]);
        }
        b.drain_transcript();
        assert_eq!(b.counters().persist_failures, 5);

        let manifest = b.seal().expect("a persisting broker seals");
        verify_sealed_root(&manifest).expect("the truncated manifest still seals");
        verify_chunks(&manifest, dir.path()).expect("the chunks that landed verify");
        assert_eq!(manifest.chunks.len(), 2);
        assert!(
            manifest.is_truncated(),
            "the sealed artifact must declare itself incomplete"
        );
        assert_eq!(
            manifest.refused_chunks, 5,
            "one per record that never landed"
        );
        assert_eq!(manifest.refused_bytes, 15);
    }

    #[test]
    fn a_complete_capture_seals_without_a_truncation_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"all of it");
        b.drain_transcript();
        assert_eq!(b.counters().persist_failures, 0);
        let manifest = b.seal().expect("a persisting broker seals");
        assert!(!manifest.is_truncated());
        assert_eq!(manifest.refused_chunks, 0);
    }

    #[test]
    fn a_persistence_outage_is_reported_once_not_once_per_record() {
        // A 5k-chunk/sec workload against an exhausted budget would otherwise
        // emit 5k warnings a second forever, trading a bounded-disk problem
        // for an unbounded-log one.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = fail_closed_writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 1,
            },
        );
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        for _ in 0..5_000 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"x");
        }
        b.drain_transcript();
        assert_eq!(b.counters().persist_failures, 4_999);
        assert_eq!(
            b.counters().persist_lapses,
            1,
            "one outage is one report, however many records it swallows"
        );
    }

    #[test]
    fn persistence_recovering_and_failing_again_counts_two_lapses() {
        // The counter has to be a transition count, not a latch: a flapping
        // store must stay visible rather than reporting its first outage and
        // going quiet forever.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        // Each step has to land before the next one changes the disk under
        // it: the writer runs on its own thread, so an undrained ingest would
        // be racing the `remove_dir_all` that is supposed to break it.
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"ok");
        b.drain_transcript();

        // Remove the directory out from under the writer, then put it back.
        std::fs::remove_dir_all(dir.path()).expect("remove capture dir");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"lost");
        b.drain_transcript();
        std::fs::create_dir_all(dir.path()).expect("restore capture dir");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"ok again");
        b.drain_transcript();
        std::fs::remove_dir_all(dir.path()).expect("remove capture dir again");
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"lost again");
        b.drain_transcript();

        assert_eq!(b.counters().persist_failures, 2);
        assert_eq!(b.counters().persist_lapses, 2);
    }

    #[test]
    fn the_shipped_stream_capture_rings_rather_than_refusing() {
        // The two halves of the same decision: chunks no longer cost a file
        // each, so the cap can sit where the manifest's own size puts it, and
        // reaching it prunes rather than stopping the durable copy dead.
        let config = stream_capture_config(identity("vm-a"));
        assert_eq!(config.retention, RetentionPolicy::Ring);
        assert_eq!(config.bounds, DEFAULT_CAPTURE_BOUNDS);
        const { assert!(DEFAULT_CAPTURE_BOUNDS.max_chunks >= 64 * 1024) };
    }

    #[test]
    fn a_saturated_durable_store_keeps_the_newest_window_and_reports_no_failure() {
        // The behaviour the raised cap rests on: past the bound the transcript
        // drops its oldest chunks instead of going quiet, so the persisted
        // copy still shows what the workload was doing when it mattered.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(
            dir.path(),
            "vm-a",
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: u64::MAX,
                max_chunks: 2 * SEGMENT_MAX_CHUNKS,
            },
        );
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        let total = SEGMENT_MAX_CHUNKS * 6;
        for i in 0..total {
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                format!("{i}\n").as_bytes(),
            );
            // Keep the writer within a queue's reach. What this test is about
            // is the *budget* pruning, and a record shed at the hand-off would
            // be a second, unrelated reason for one to be missing.
            keep_the_writer_close(&b, i);
        }
        b.drain_transcript();
        assert_eq!(
            b.counters().persist_failures,
            0,
            "a full budget prunes; it is not a store failure"
        );

        let manifest = b.seal().expect("a persisting broker seals");
        assert!(manifest.evicted_chunks > 0);
        assert!(manifest.is_truncated(), "a window declares itself a window");
        assert_eq!(manifest.retention, RetentionPolicy::Ring);
        verify_sealed_root(&manifest).expect("the window seals a valid root");
        verify_chunks(&manifest, dir.path()).expect("the surviving segments verify");
        let out = export(&manifest, dir.path(), &test_key()).expect("export");
        assert!(
            out.ends_with(format!("{}\n", total - 1).as_bytes()),
            "the newest record survives"
        );
    }

    #[test]
    fn a_burst_far_past_the_durable_queue_is_accounted_for_not_silently_lost() {
        // The hand-off is a queue, and a queue is where records go missing.
        // Sixteen times its depth, with nothing pacing the producer: whatever
        // the queue could not take is missing from the transcript, and the
        // sealed artifact has to own every one of them.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        let total = DURABLE_QUEUE_DEPTH * 16;
        for i in 0..total {
            b.ingest(
                StreamSource::Entrypoint,
                StreamKind::Stdout,
                format!("{i}\n").as_bytes(),
            );
        }

        // No drain: `seal` is the production teardown, and it has to be the
        // thing that waits — a manifest missing whatever was still queued
        // would be a hole nothing declares.
        let manifest = b.seal().expect("a persisting broker seals");
        assert!(
            !manifest.chunks.is_empty(),
            "a healthy writer racing an unbounded producer must still land some records — \
             otherwise the accounting check below passes vacuously on a broker that recorded \
             nothing at all"
        );
        assert_eq!(
            manifest.chunks.len() as u64 + manifest.refused_chunks,
            total as u64,
            "every ingested record is either in the transcript or counted as absent from it"
        );
        assert_eq!(
            manifest.is_truncated(),
            manifest.refused_chunks > 0,
            "a transcript declares itself incomplete exactly when it is"
        );
        verify_sealed_root(&manifest).expect("what survived seals a valid root");
        verify_chunks(&manifest, dir.path()).expect("and every surviving chunk verifies");
    }

    #[test]
    fn a_wedged_durable_writer_sheds_rather_than_pacing_the_workload() {
        // The failure a bounded hand-off invites: a queue that waits when it
        // fills is a slow disk stalling ingest, which is the stalled-reader
        // failure with a different door. The producer must come back at its
        // own speed and the shortfall must show up in the sealed manifest.
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-wedged", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-wedged",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        let mut follower = b.subscribe();
        let transcript = b.transcript_lock();
        // The disk, stopped: the writer thread parks on its first append, so
        // the queue behind it fills and stays full.
        let wedged = transcript.lock().expect("the writer lock");

        let total = DURABLE_QUEUE_DEPTH * 8;
        let (finished, ingesting) = std::sync::mpsc::channel();
        let producer = std::thread::spawn(move || {
            for i in 0..total {
                b.ingest(
                    StreamSource::Entrypoint,
                    StreamKind::Stdout,
                    format!("{i}\n").as_bytes(),
                );
            }
            let _ = finished.send(());
            b
        });
        // Unwedging only after the verdict: a producer still blocked here is
        // one the queue held, and it has to be released to join cleanly.
        let returned = ingesting.recv_timeout(Duration::from_secs(5)).is_ok();
        drop(wedged);
        let b = producer.join().expect("the producer thread");

        assert!(returned, "ingest must never wait on the durable writer");
        assert_eq!(
            b.ingested_count(),
            total as u64,
            "every chunk still accepted"
        );
        assert!(
            follower.recv().is_some(),
            "shedding is the durable copy's problem; the live stream is untouched"
        );
        let shed = b.counters().persist_shed;
        assert!(shed > 0, "a wedged writer must actually shed");
        assert_eq!(b.counters().persist_failures, shed);

        let manifest = b.seal().expect("a persisting broker seals");
        assert!(
            manifest.is_truncated(),
            "a transcript that lost records must not seal as complete"
        );
        assert_eq!(manifest.refused_chunks, shed);
        assert!(manifest.refused_bytes > 0, "the lost bytes are counted too");
        assert_eq!(
            manifest.chunks.len() as u64 + manifest.refused_chunks,
            total as u64
        );
        verify_sealed_root(&manifest).expect("the shortfall is inside the sealed root");
    }

    #[test]
    fn a_chatty_workload_does_not_cost_a_file_per_chunk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = writer_at(dir.path(), "vm-a", unbounded_capture_bounds());
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        );
        for i in 0..20_000u64 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"x");
            // What is under test is how many *files* 20k landed chunks cost,
            // so all 20k have to land: keep the writer inside the hand-off's
            // bound instead of letting it shed.
            keep_the_writer_close(&b, i);
        }
        b.drain_transcript();
        let files = std::fs::read_dir(dir.path())
            .expect("read capture dir")
            .filter_map(Result::ok)
            .count();
        let ceiling = 20_000usize.div_ceil(SEGMENT_MAX_CHUNKS as usize) + 1;
        assert!(
            files <= ceiling,
            "20k chunks left {files} files, expected at most {ceiling}"
        );
        assert_eq!(
            b.seal().expect("a persisting broker seals").chunks.len(),
            20_000
        );
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
        let mut b = StreamBroker::new(
            "vm-a",
            writer,
            StreamRedaction::curated(&RedactionPolicy::default()),
        )
        .with_audit(StreamAudit::new(emitter, plan));

        let _reader = b.subscribe();
        let secret = b"card 4111111111111111 end";
        for _ in 0..16 {
            b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, secret);
        }

        let chain = audit_dir.path().join("local.jsonl");
        let entries =
            verify_audit_chain_entries(&chain, &verifying_key).expect("the entry is chain-signed");
        assert_eq!(
            entries.len(),
            1,
            "one entry per attach, never one per record"
        );
        let entry = entries.first().expect("one verified entry");
        assert_eq!(entry.event, stream_audit::SUBSCRIBED_EVENT);
        assert_eq!(
            entry.labels,
            std::collections::BTreeMap::from([
                (stream_audit::LABEL_VM_NAME.to_string(), "vm-a".to_string()),
                (stream_audit::LABEL_READER_ID.to_string(), "0".to_string()),
                (stream_audit::LABEL_FROM_SEQ.to_string(), "0".to_string()),
            ]),
            "the signed entry must contain only attach metadata, never raw or redacted payload bytes"
        );
        assert_eq!(b.counters().audit_failures, 0);
    }
}
