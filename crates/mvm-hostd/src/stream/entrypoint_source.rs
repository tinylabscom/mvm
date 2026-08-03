//! The second of the two sources the capture is built on: the guest agent's
//! entrypoint frames, arriving over the vsock RPC as the workload's child
//! produces them.
//!
//! The console source covers the windows the agent cannot — before it starts
//! and after it dies — but it is one merged byte stream and every record it
//! produces is labelled `Stdout`, because a console genuinely cannot tell the
//! two channels apart. This source is the other half: the guest hands over
//! `stdout` and `stderr` as separate frames, so the capture keeps them
//! separate. Without it `--stream stderr` matches nothing a workload ever
//! wrote.
//!
//! **The broker is the seam for the recorded copy, not for the caller's.**
//! Everything that leaves this host — the transcript on disk, every follower
//! queue, `mvmctl logs` — gets the masked copy, and there is no second path to
//! any of them. What comes back out of [`EntrypointSink::ingest`] is the
//! workload's own bytes, unchanged, because the caller of an entrypoint call
//! is not a third party: they invoked the function and they have code
//! execution inside the workload that produced it. Masking their own return
//! value protects nothing and breaks the function contract — a JSON body comes
//! back as `{"id":XXX}`, which no parser accepts.
//!
//! **The divergence is reported, never silent.** Every chunk comes back
//! carrying [`RecordedCopy`] — identical, masked by these named rules, or
//! withheld — so the caller can say on its own stderr that what an operator
//! reads back differs from what it printed, and why.
//!
//! **Nothing here waits on a follower queue.** Subscribing the caller to its
//! own output would be the other way to reach the recorded bytes, and it would
//! put the answer to a synchronous call behind a bounded ring that evicts under
//! back-pressure. One `ingest` per frame produces one record; nothing is
//! delivered twice and nothing waits on a reader.
//!
//! **A VM with no capture is not a VM with no output.** A call dispatched into
//! a machine some *other* process booted (`machine run -d --name X`, then an
//! attach) finds no broker here. The bytes still reach the caller; what they do
//! not get is a sequence number, a chain link, or a durable copy — and, with no
//! second copy to diverge from, nothing to redact for either.
//!
//! **Hold a sink for one call, not for a VM.** The plane seals a transcript by
//! taking sole ownership of the broker at teardown, so the sink holds only a
//! [`Weak`] reference and upgrades it per frame: a release that lands mid-call
//! seals normally and the frames after it are simply unrecorded.

use std::sync::{Arc, Mutex, Weak};

use mvm_protocol::stream::{StreamKind, StreamSource};

use crate::stream::broker::StreamBroker;
use crate::stream::console_source::{SharedBroker, lock_broker};
use crate::stream::redact::ClearOutcome;

/// One frame's two copies: what the caller was handed, and how the copy that
/// was recorded differs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownChunk {
    /// The channel these bytes go out on — the one the guest sent them on.
    pub kind: StreamKind,
    /// The workload's own bytes, byte for byte.
    pub body: Vec<u8>,
    /// What an operator reading this call back will see instead.
    pub recorded: RecordedCopy,
}

/// How the copy in the transcript and the follower queues differs from the copy
/// the caller was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCopy {
    /// Nothing is capturing this VM in this process, so there is no second
    /// copy — and nothing an operator can read back afterwards.
    NotRecorded,
    /// Recorded as handed over: nothing fired.
    Identical,
    /// Recorded masked, by these rules. Names only — a value that fired a rule
    /// is exactly the value that must not travel.
    Masked { rules_fired: Vec<&'static str> },
    /// The seam would not vouch for the chunk, so a marker was recorded in
    /// place of the bytes.
    Withheld {
        /// Why the detector gave up. Describes the detector, never the bytes.
        reason: String,
    },
}

impl RecordedCopy {
    /// Whether an operator reading this back would see something other than
    /// what the caller was handed.
    pub fn differs(&self) -> bool {
        matches!(self, Self::Masked { .. } | Self::Withheld { .. })
    }
}

impl From<ClearOutcome> for RecordedCopy {
    fn from(outcome: ClearOutcome) -> Self {
        match outcome {
            ClearOutcome::Clean => Self::Identical,
            ClearOutcome::Redacted { rules_fired } => Self::Masked { rules_fired },
            ClearOutcome::Withheld { reason, .. } => Self::Withheld { reason },
        }
    }
}

/// One entrypoint call's ingest into the host's capture of a VM.
///
/// Obtained per call from [`StreamPlane::entrypoint_sink`](crate::stream::StreamPlane::entrypoint_sink)
/// (or [`EntrypointSink::for_vm`] against the process's registered plane) and
/// dropped when the call ends — see the module docs on why it belongs to one
/// dispatch.
pub struct EntrypointSink(Ingest);

/// Where a chunk goes after the caller has been handed it. Private: the two
/// arms are a property of the VM, not a choice a caller makes.
enum Ingest {
    /// Into the VM's broker — redacted, stamped, chained, persisted, fanned
    /// out to every follower. Weak so a teardown that lands mid-call can still
    /// take sole ownership and seal.
    Recorded(Weak<Mutex<StreamBroker>>),
    /// Nowhere. No broker is capturing this VM in this process, so there is
    /// nothing to chain a record onto and no second copy to mask.
    Unrecorded,
}

impl EntrypointSink {
    /// The sink for `vm` against the plane this process registered, or an
    /// unrecorded one when no plane is installed or the VM is not attached to
    /// it.
    ///
    /// Never fails and never refuses: a call whose output cannot be captured
    /// still has to run and still has to print. What the caller loses is the
    /// capture, not the call.
    pub fn for_vm(vm: &str) -> Self {
        super::host_stream_plane().map_or_else(Self::unrecorded, |plane| plane.entrypoint_sink(vm))
    }

    /// A sink over a live broker, held weakly.
    pub(in crate::stream) fn recorded(broker: &SharedBroker) -> Self {
        Self(Ingest::Recorded(Arc::downgrade(broker)))
    }

    /// A sink that records nothing.
    pub fn unrecorded() -> Self {
        Self(Ingest::Unrecorded)
    }

    /// Whether these bytes are reaching a capture, for a caller reporting what
    /// an operator will be able to read back afterwards.
    pub fn is_recorded(&self) -> bool {
        match &self.0 {
            Ingest::Recorded(broker) => broker.strong_count() > 0,
            Ingest::Unrecorded => false,
        }
    }

    /// Take one frame of entrypoint output, record it, and hand the caller
    /// back its own bytes plus what the recorded copy became.
    ///
    /// Never blocks on a consumer and never refuses: a broker's fan-out rings
    /// rather than waiting, and its durable append runs on another thread whose
    /// hand-off sheds rather than waiting too — so a follower that stopped
    /// reading and a disk that stopped answering both leave this call at the
    /// speed it would have returned anyway. Nothing downstream can reach back
    /// and stall the guest's child.
    pub fn ingest(&mut self, kind: StreamKind, bytes: &[u8]) -> ShownChunk {
        ShownChunk {
            kind,
            body: bytes.to_vec(),
            recorded: self.record(kind, bytes),
        }
    }

    fn record(&self, kind: StreamKind, bytes: &[u8]) -> RecordedCopy {
        let Ingest::Recorded(broker) = &self.0 else {
            return RecordedCopy::NotRecorded;
        };
        // Upgraded per frame, not held: the plane seals by taking sole
        // ownership, and a sink that kept a strong reference for the whole
        // dispatch would turn any teardown racing the call into an unsealed
        // transcript.
        broker
            .upgrade()
            .map_or(RecordedCopy::NotRecorded, |broker| {
                lock_broker(&broker)
                    .ingest(StreamSource::Entrypoint, kind, bytes)
                    .into()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::broker::{StreamBroker, StreamCaptureIdentity, stream_capture_config};
    use crate::stream::redact::{Redacted, RedactionFailed, StreamRedaction, StreamRedactor};
    use mvm_core::crypto::aead;
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::transcript::{CaptureBinding, TranscriptWriter};
    use mvm_protocol::stream::verify_chain;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// A broker writing real encrypted chunks into a real directory, held
    /// alive alongside it.
    struct Fixture {
        broker: SharedBroker,
        _dir: TempDir,
    }

    fn fixture_with(vm: &str, seam: StreamRedaction) -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = stream_capture_config(StreamCaptureIdentity {
            capture_id: format!("capture-{vm}"),
            binding: CaptureBinding {
                tenant_id: "local".to_string(),
                vm_name: vm.to_string(),
                session_id: None,
            },
            created_unix_secs: 0,
            recipient: "host:test".to_string(),
            wrapped_data_key_b64: String::new(),
        });
        let writer = TranscriptWriter::new(dir.path(), aead::Key::from_bytes([0x5a; 32]), config);
        Fixture {
            broker: Arc::new(Mutex::new(StreamBroker::new(vm, writer, seam))),
            _dir: dir,
        }
    }

    fn fixture(vm: &str) -> Fixture {
        fixture_with(vm, StreamRedaction::curated(&RedactionPolicy::default()))
    }

    /// A Luhn-valid test card number the curated ruleset masks.
    const TEST_CARD: &[u8] = b"4111111111111111";

    #[test]
    fn each_channel_keeps_its_own_kind_and_names_the_entrypoint_as_its_source() {
        // The whole reason this source exists: a console cannot say which of
        // the two channels a byte came out of, and this one can.
        let fx = fixture("vm-a");
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(&fx.broker);

        sink.ingest(StreamKind::Stdout, b"out");
        sink.ingest(StreamKind::Stderr, b"err");

        let records: Vec<_> = std::iter::from_fn(|| reader.recv()).take(2).collect();
        assert_eq!(records[0].kind, StreamKind::Stdout);
        assert_eq!(records[0].payload, b"out");
        assert_eq!(records[1].kind, StreamKind::Stderr);
        assert_eq!(records[1].payload, b"err");
        assert!(
            records.iter().all(|r| r.source == StreamSource::Entrypoint),
            "entrypoint frames must not be labelled as console output"
        );
        verify_chain(&records).expect("both channels share one chain");
    }

    #[test]
    fn one_frame_produces_exactly_one_record() {
        // The duplication this design has to rule out: the caller both prints
        // the bytes and records them, and a second ingest anywhere on that
        // path shows the operator the same line twice.
        let fx = fixture("vm-once");
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(&fx.broker);

        let shown = sink.ingest(StreamKind::Stdout, b"said once");

        assert_eq!(shown.body, b"said once");
        assert_eq!(shown.recorded, RecordedCopy::Identical);
        assert_eq!(lock_broker(&fx.broker).ingested_count(), 1);
        assert_eq!(reader.recv().expect("the record").payload, b"said once");
        assert!(reader.recv().is_none(), "the frame must not arrive twice");
    }

    #[test]
    fn the_caller_gets_its_own_bytes_and_the_followers_get_the_masked_ones() {
        // The correction this shape exists for: masking a caller's own return
        // value protects nothing — they ran the function — while breaking it
        // for anything that parses the result. The copy that leaves the host
        // is still masked.
        let fx = fixture("vm-same");
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(&fx.broker);

        let shown = sink.ingest(StreamKind::Stdout, b"card 4111111111111111 end");

        assert_eq!(
            shown.body, b"card 4111111111111111 end",
            "the caller asked for its own output and must get it byte for byte"
        );
        assert_eq!(
            shown.recorded,
            RecordedCopy::Masked {
                rules_fired: vec!["credit_card"]
            },
            "and must be told the recorded copy is not the same bytes"
        );
        let recorded = reader.recv().expect("the record").payload.clone();
        assert!(
            !recorded.windows(TEST_CARD.len()).any(|w| w == TEST_CARD),
            "the copy every follower gets must still be masked"
        );
        assert_ne!(recorded, shown.body);
    }

    #[test]
    fn an_unrecorded_vm_hands_its_bytes_straight_back() {
        // A call dispatched into a machine another process booted has no
        // broker here. With no second copy there is nothing to diverge from
        // and nobody to mask for — the caller is the only consumer.
        let mut sink = EntrypointSink::unrecorded();
        assert!(!sink.is_recorded());

        let shown = sink.ingest(StreamKind::Stderr, b"card 4111111111111111 end");

        assert_eq!(shown.kind, StreamKind::Stderr);
        assert_eq!(shown.body, b"card 4111111111111111 end");
        assert_eq!(shown.recorded, RecordedCopy::NotRecorded);
    }

    /// A seam that refuses to vouch for anything — the shape a detector with a
    /// timeout or a crashed subprocess presents.
    struct FailingRedactor;

    impl StreamRedactor for FailingRedactor {
        fn redact(&self, _body: &[u8]) -> Result<Redacted, RedactionFailed> {
            Err(RedactionFailed::new("detector unavailable"))
        }
    }

    #[test]
    fn a_chunk_the_seam_will_not_vouch_for_is_withheld_from_the_record_only() {
        // Fail closed where it matters: the transcript gets a marker instead
        // of bytes nobody checked. The caller still gets its own output, and
        // is told the record is a marker.
        let fx = fixture_with(
            "vm-unscannable",
            StreamRedaction::from_seam(Box::new(FailingRedactor)),
        );
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(&fx.broker);

        let shown = sink.ingest(StreamKind::Stdout, b"unscannable");

        assert_eq!(shown.kind, StreamKind::Stdout);
        assert_eq!(shown.body, b"unscannable");
        assert_eq!(
            shown.recorded,
            RecordedCopy::Withheld {
                reason: "detector unavailable".to_string()
            }
        );
        let record = reader.recv().expect("a marker still lands");
        assert_eq!(record.kind, StreamKind::Trace);
        assert!(!record.payload.windows(11).any(|w| w == b"unscannable"));
    }

    #[test]
    fn every_divergent_outcome_reports_itself_as_divergent() {
        assert!(!RecordedCopy::NotRecorded.differs());
        assert!(!RecordedCopy::Identical.differs());
        assert!(
            RecordedCopy::Masked {
                rules_fired: vec!["credit_card"]
            }
            .differs()
        );
        assert!(
            RecordedCopy::Withheld {
                reason: "gone".to_string()
            }
            .differs()
        );
    }

    #[test]
    fn a_capture_released_mid_call_seals_and_the_rest_of_the_call_is_unrecorded() {
        // The sink holds the broker weakly on purpose: a teardown racing a
        // dispatch has to be able to take sole ownership and seal, and the
        // frames after it must still reach the caller.
        let fx = fixture("vm-released");
        let mut sink = EntrypointSink::recorded(&fx.broker);
        assert!(sink.is_recorded());
        sink.ingest(StreamKind::Stdout, b"before");

        let Fixture { broker, _dir } = fx;
        let broker = Arc::into_inner(broker).expect("the sink must not hold the broker open");
        let manifest = broker
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seal()
            .expect("a persisting broker seals");
        assert_eq!(manifest.chunks.len(), 1, "the released capture still seals");

        assert!(!sink.is_recorded());
        let shown = sink.ingest(StreamKind::Stdout, b"after");
        assert_eq!(shown.body, b"after");
        assert_eq!(shown.recorded, RecordedCopy::NotRecorded);
    }

    #[test]
    fn a_follower_that_stopped_reading_does_not_slow_the_ingest_down() {
        // The guest's child is decoupled from this thread by the pump's
        // bounded hand-off, so the one way a stalled consumer could reach back
        // and pace the workload is if ingest waited on it. It never does: the
        // fan-out rings.
        let fx = fixture("vm-slow");
        let stalled = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(&fx.broker);

        let started = Instant::now();
        for i in 0..10_000u32 {
            sink.ingest(StreamKind::Stdout, &i.to_le_bytes());
        }
        let elapsed = started.elapsed();

        assert_eq!(lock_broker(&fx.broker).ingested_count(), 10_000);
        assert!(
            elapsed < Duration::from_secs(5),
            "ingest waited on a reader ({elapsed:?})"
        );
        assert!(
            stalled.dropped_count() > 0,
            "the undrained follower must show its own gap, not hold the producer"
        );
    }
}
