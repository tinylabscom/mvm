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
//! **The broker is the seam, not a second consumer.** The host process that
//! dispatches the entrypoint call is also the one that prints its output, and
//! that is exactly why the bytes are routed *through* here rather than teed
//! alongside: [`EntrypointSink::ingest`] hands back the bytes the broker
//! cleared, and the caller writes those. `mvmctl invoke` and `mvmctl logs`
//! therefore show the same redacted, hash-chained bytes, and there is no
//! second path by which raw output reaches a terminal.
//!
//! **The record comes back from the ingest, never from a follower queue.**
//! Subscribing the caller to its own output would be the other way to keep the
//! two views identical, and it would put the answer to a synchronous call
//! behind a bounded ring that evicts under back-pressure — losing exactly the
//! bytes an SDK is waiting on. One `ingest` per frame produces one record;
//! nothing is delivered twice and nothing waits on a reader.
//!
//! **A VM with no capture still gets its output cleared.** A call dispatched
//! into a machine some *other* process booted (`machine run -d --name X`, then
//! an attach) finds no broker here. The bytes are still workload output, so
//! they still cross the seam; what they do not get is a sequence number, a
//! chain link, or a durable copy, because there is no capture to put them in.
//!
//! **Hold a sink for one call, not for a VM.** It keeps the broker alive, and
//! the plane seals a transcript by taking sole ownership of that broker at
//! teardown. A sink cached past its dispatch turns a sealed capture into an
//! unsealed one.

use mvm_protocol::stream::{StreamKind, StreamSource};

use crate::stream::console_source::{SharedBroker, lock_broker};
use crate::stream::redact::{self, StreamRedaction};

/// Bytes cleared for display, and the channel they belong on.
///
/// `kind` is not always the one that went in: a chunk the seam refused to
/// vouch for comes back as a [`StreamKind::Trace`] marker, and a caller that
/// wrote it to the channel it asked for would put a diagnostic where a parser
/// expects the workload's own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownChunk {
    /// The channel these bytes go out on.
    pub kind: StreamKind,
    /// What may be shown, in place of what arrived.
    pub body: Vec<u8>,
}

/// One entrypoint call's ingest into the host's capture of a VM.
///
/// Obtained per call from [`StreamPlane::entrypoint_sink`](crate::stream::StreamPlane::entrypoint_sink)
/// (or [`EntrypointSink::for_vm`] against the process's registered plane) and
/// dropped when the call ends — see the module docs on why it must not outlive
/// one dispatch.
pub struct EntrypointSink(Ingest);

/// Where a cleared chunk goes after the seam. Private: the two arms are a
/// property of the VM, not a choice a caller makes.
enum Ingest {
    /// Into the VM's broker — redacted, stamped, chained, persisted, fanned
    /// out to every follower.
    Recorded(SharedBroker),
    /// Through the seam and no further. No broker is capturing this VM in this
    /// process, so there is nothing to chain the record onto.
    Unrecorded(StreamRedaction),
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

    /// A sink over a live broker.
    pub(in crate::stream) fn recorded(broker: SharedBroker) -> Self {
        Self(Ingest::Recorded(broker))
    }

    /// A sink that clears bytes for display and records nothing.
    pub fn unrecorded() -> Self {
        Self(Ingest::Unrecorded(StreamRedaction::curated()))
    }

    /// Whether these bytes are reaching a capture, for a caller reporting what
    /// an operator will be able to read back afterwards.
    pub fn is_recorded(&self) -> bool {
        matches!(self.0, Ingest::Recorded(_))
    }

    /// Take one frame of entrypoint output and hand back what may be shown.
    ///
    /// Never blocks on a consumer and never refuses: a broker's fan-out rings
    /// rather than waiting, so a follower that stopped reading loses its own
    /// oldest records and this call returns at the same speed it would have
    /// otherwise. Nothing here can reach back and stall the guest's child.
    pub fn ingest(&mut self, kind: StreamKind, bytes: &[u8]) -> ShownChunk {
        match &self.0 {
            Ingest::Recorded(broker) => {
                let record = lock_broker(broker).ingest(StreamSource::Entrypoint, kind, bytes);
                ShownChunk {
                    kind: record.kind,
                    body: record.payload.clone(),
                }
            }
            Ingest::Unrecorded(seam) => {
                let cleared =
                    redact::clear_for_display(seam, StreamSource::Entrypoint, kind, bytes);
                ShownChunk {
                    kind: cleared.kind,
                    body: cleared.body,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::broker::{StreamBroker, StreamCaptureIdentity, stream_capture_config};
    use crate::stream::redact::{Redacted, RedactionFailed, StreamRedactor};
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{CaptureBinding, TranscriptWriter};
    use mvm_protocol::stream::verify_chain;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// A broker writing real encrypted chunks into a real directory, held
    /// alive alongside it.
    struct Fixture {
        broker: SharedBroker,
        _dir: TempDir,
    }

    fn fixture(vm: &str) -> Fixture {
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
            broker: Arc::new(Mutex::new(StreamBroker::new(
                vm,
                writer,
                StreamRedaction::curated(),
            ))),
            _dir: dir,
        }
    }

    /// A Luhn-valid test card number the curated ruleset masks.
    const TEST_CARD: &[u8] = b"4111111111111111";

    #[test]
    fn each_channel_keeps_its_own_kind_and_names_the_entrypoint_as_its_source() {
        // The whole reason this source exists: a console cannot say which of
        // the two channels a byte came out of, and this one can.
        let fx = fixture("vm-a");
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(Arc::clone(&fx.broker));

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
        let mut sink = EntrypointSink::recorded(Arc::clone(&fx.broker));

        let shown = sink.ingest(StreamKind::Stdout, b"said once");

        assert_eq!(shown.body, b"said once");
        assert_eq!(lock_broker(&fx.broker).ingested_count(), 1);
        assert_eq!(reader.recv().expect("the record").payload, b"said once");
        assert!(reader.recv().is_none(), "the frame must not arrive twice");
    }

    #[test]
    fn the_bytes_handed_back_are_the_bytes_the_followers_get() {
        // The property that makes routing through the broker worth doing: the
        // caller printing to its own fds cannot become a path around the seam,
        // because it prints what the seam returned.
        let fx = fixture("vm-same");
        let mut reader = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(Arc::clone(&fx.broker));

        let shown = sink.ingest(StreamKind::Stdout, b"card 4111111111111111 end");

        assert!(
            !shown.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD),
            "the caller must not be handed the raw match"
        );
        assert_eq!(reader.recv().expect("the record").payload, shown.body);
    }

    #[test]
    fn an_unrecorded_vm_still_crosses_the_seam() {
        // A call dispatched into a machine another process booted has no
        // broker here. Printing raw would make "no capture" mean "no
        // redaction", which is the one place the two must not be the same
        // switch.
        let mut sink = EntrypointSink::unrecorded();
        assert!(!sink.is_recorded());

        let shown = sink.ingest(StreamKind::Stderr, b"card 4111111111111111 end");

        assert_eq!(shown.kind, StreamKind::Stderr);
        assert!(!shown.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD));
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
    fn a_chunk_the_seam_will_not_vouch_for_comes_back_as_a_trace_marker() {
        // Fail closed on both arms, and retagged: a caller that wrote the
        // marker to stdout would hand a parser a diagnostic where the
        // workload's own bytes belong.
        let mut sink = EntrypointSink(Ingest::Unrecorded(StreamRedaction::from_seam(Box::new(
            FailingRedactor,
        ))));

        let shown = sink.ingest(StreamKind::Stdout, b"unscannable");

        assert_eq!(shown.kind, StreamKind::Trace);
        assert!(!shown.body.windows(11).any(|w| w == b"unscannable"));
    }

    #[test]
    fn a_follower_that_stopped_reading_does_not_slow_the_ingest_down() {
        // The guest's child is decoupled from this thread by the pump's
        // bounded hand-off, so the one way a stalled consumer could reach back
        // and pace the workload is if ingest waited on it. It never does: the
        // fan-out rings.
        let fx = fixture("vm-slow");
        let stalled = lock_broker(&fx.broker).subscribe();
        let mut sink = EntrypointSink::recorded(Arc::clone(&fx.broker));

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
