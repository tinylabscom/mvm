//! Test-only executable reference model, not a capture receiver or credential API.
//!
//! Binding values and connection IDs are fixtures representing independently
//! verified facts. No actual peer, startup permit or HVF call is authenticated.
//! The proof-vector child checks fixture signature math only. Broker tests use
//! the existing real redaction/encrypted transcript seam, not a supervisor or
//! public audited output-reader witness.

use super::tests::{Fixture, fixture};
use super::*;
use std::collections::VecDeque;
use std::sync::{Barrier, Mutex};

#[path = "owned_capture_proof_tests.rs"]
mod proof_vectors;
#[path = "owned_capture_reconciliation_tests.rs"]
mod reconciliation;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixtureBinding {
    run: u64,
    call: u64,
    boot: u64,
    principal: u64,
}

fn binding() -> FixtureBinding {
    FixtureBinding {
        run: 1,
        call: 2,
        boot: 3,
        principal: 4,
    }
}

fn fixture_challenge(connection: u64) -> [u8; 32] {
    let mut challenge = [0; 32];
    challenge[..8].copy_from_slice(&connection.to_be_bytes());
    challenge
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Binding,
    Spent,
    Retired,
    Connection,
    Sequence,
    Frozen,
    Frame,
    Window,
    NotDrained,
    Receipt,
    Overflow,
}

#[derive(Debug)]
enum Slot {
    Bound,
    Spent { connection: u64, next: u64 },
    Retired,
}

struct ModelPermit {
    expected: FixtureBinding,
    slot: Mutex<Slot>,
}

impl ModelPermit {
    fn new(expected: FixtureBinding) -> Arc<Self> {
        Arc::new(Self {
            expected,
            slot: Mutex::new(Slot::Bound),
        })
    }

    // The argument stands for a completed verifier callback, not a wire proof.
    fn spend(
        self: &Arc<Self>,
        verified_fixture: &FixtureBinding,
        connection: u64,
    ) -> Result<ModelConnection, Refusal> {
        let mut slot = self.slot.lock().unwrap();
        if matches!(*slot, Slot::Retired) {
            return Err(Refusal::Retired);
        }
        if verified_fixture != &self.expected {
            return Err(Refusal::Binding);
        }
        if !matches!(*slot, Slot::Bound) {
            return Err(Refusal::Spent);
        }
        *slot = Slot::Spent {
            connection,
            next: 1,
        };
        Ok(ModelConnection {
            permit: Arc::clone(self),
            id: connection,
            challenge: fixture_challenge(connection),
        })
    }

    fn retire(&self) {
        *self.slot.lock().unwrap() = Slot::Retired;
    }
}

struct ModelConnection {
    permit: Arc<ModelPermit>,
    id: u64,
    challenge: [u8; 32],
}

impl ModelConnection {
    fn claim_fragment(&self, sequence: u64) -> Result<(), Refusal> {
        let mut slot = self.permit.slot.lock().unwrap();
        match &mut *slot {
            Slot::Spent { connection, next } => {
                if *connection != self.id {
                    return Err(Refusal::Connection);
                }
                if sequence != *next {
                    *slot = Slot::Retired;
                    return Err(Refusal::Sequence);
                }
                let Some(advanced) = next.checked_add(1) else {
                    *slot = Slot::Retired;
                    return Err(Refusal::Overflow);
                };
                *next = advanced;
                Ok(())
            }
            Slot::Bound => Err(Refusal::Connection),
            Slot::Retired => Err(Refusal::Retired),
        }
    }

    fn close(&self, last: u64) -> Result<(), Refusal> {
        let mut slot = self.permit.slot.lock().unwrap();
        match *slot {
            Slot::Spent { connection, next }
                if connection == self.id && last.checked_add(1) == Some(next) =>
            {
                *slot = Slot::Retired;
                Ok(())
            }
            Slot::Retired => Err(Refusal::Retired),
            Slot::Bound | Slot::Spent { .. } => Err(Refusal::Sequence),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Count {
    frames: u64,
    bytes: u64,
}

impl Count {
    fn one(bytes: usize) -> Result<Self, Refusal> {
        Ok(Self {
            frames: 1,
            bytes: u64::try_from(bytes).map_err(|_| Refusal::Overflow)?,
        })
    }

    fn plus(self, other: Self) -> Result<Self, Refusal> {
        Ok(Self {
            frames: self
                .frames
                .checked_add(other.frames)
                .ok_or(Refusal::Overflow)?,
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(Refusal::Overflow)?,
        })
    }

    fn add(&mut self, bytes: usize) -> Result<(), Refusal> {
        *self = self.plus(Self::one(bytes)?)?;
        Ok(())
    }

    fn sum(counts: impl IntoIterator<Item = Self>) -> Result<Self, Refusal> {
        counts.into_iter().try_fold(Self::default(), Self::plus)
    }
}

struct Fragment {
    sequence: u64,
    kind: StreamKind,
    body: Vec<u8>,
}

struct ModelReceipt {
    connection: u64,
    challenge: [u8; 32],
    sequence: u64,
    broker_sequence: Option<u64>,
    dropped_bytes: Option<u32>,
    copy: RecordedCopy,
}

#[derive(Clone)]
struct ModelFinal {
    binding: FixtureBinding,
    connection: u64,
    challenge: [u8; 32],
    through: u64,
    accepted: Count,
    owner_dropped: Count,
    masked: u64,
    withheld: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProducerPhase {
    Open,
    Frozen,
    FinishSent,
    Aborted,
    Closed,
}

struct ModelProducer {
    connection: ModelConnection,
    queue: VecDeque<Fragment>,
    queued_bytes: usize,
    frame_limit: usize,
    byte_limit: usize,
    next: u64,
    phase: ProducerPhase,
    pending: Option<(u64, usize)>,
    last_broker_sequence: Option<u64>,
    offered: Count,
    local_dropped: Count,
    owner_dropped: Count,
    accepted: Count,
    unconfirmed: Count,
    // Identical, masked, withheld: subcategories, never extra partition terms.
    dispositions: [Count; 3],
    accounting_invalid: bool,
}

impl ModelProducer {
    fn new(connection: ModelConnection, frame_limit: usize, byte_limit: usize) -> Self {
        assert!((1..=64).contains(&frame_limit));
        assert!((1..=1024 * 1024).contains(&byte_limit));
        Self {
            connection,
            queue: VecDeque::new(),
            queued_bytes: 0,
            frame_limit,
            byte_limit,
            next: 1,
            phase: ProducerPhase::Open,
            pending: None,
            last_broker_sequence: None,
            offered: Count::default(),
            local_dropped: Count::default(),
            owner_dropped: Count::default(),
            accepted: Count::default(),
            unconfirmed: Count::default(),
            dispositions: [Count::default(); 3],
            accounting_invalid: false,
        }
    }

    fn offer(&mut self, kind: StreamKind, body: &[u8]) -> Result<Option<u64>, Refusal> {
        if self.phase != ProducerPhase::Open {
            return Err(Refusal::Frozen);
        }
        if !matches!(kind, StreamKind::Stdout | StreamKind::Stderr) || body.len() > 16 * 1024 {
            return Err(Refusal::Frame);
        }
        if body.is_empty() {
            return Ok(None);
        }
        if self.offered.add(body.len()).is_err() {
            return Err(self.accounting_failure());
        }
        let Some(queued_bytes) = self.queued_bytes.checked_add(body.len()) else {
            return Err(self.accounting_failure());
        };
        if self.queue.len() == self.frame_limit || queued_bytes > self.byte_limit {
            if self.local_dropped.add(body.len()).is_err() {
                return Err(self.accounting_failure());
            }
            return Ok(None);
        }
        let sequence = self.next;
        let Some(next) = self.next.checked_add(1) else {
            let _ = self.local_dropped.add(body.len());
            return Err(self.accounting_failure());
        };
        self.next = next;
        self.queued_bytes = queued_bytes;
        self.queue.push_back(Fragment {
            sequence,
            kind,
            body: body.to_vec(),
        });
        Ok(Some(sequence))
    }

    fn take_next(&mut self) -> Result<Option<Fragment>, Refusal> {
        if !matches!(self.phase, ProducerPhase::Open | ProducerPhase::Frozen) {
            return Err(Refusal::Retired);
        }
        if self.pending.is_some() {
            return Err(Refusal::Window);
        }
        let Some(frame) = self.queue.pop_front() else {
            return Ok(None);
        };
        let Some(queued_bytes) = self.queued_bytes.checked_sub(frame.body.len()) else {
            let _ = self.local_dropped.add(frame.body.len());
            return Err(self.accounting_failure());
        };
        self.queued_bytes = queued_bytes;
        if let Err(error) = self.connection.claim_fragment(frame.sequence) {
            if self.local_dropped.add(frame.body.len()).is_err() {
                return Err(self.accounting_failure());
            }
            self.abort();
            return Err(error);
        }
        self.pending = Some((frame.sequence, frame.body.len()));
        Ok(Some(frame))
    }

    fn confirm(&mut self, receipt: ModelReceipt) -> Result<(), Refusal> {
        let Some((sequence, bytes)) = self.pending else {
            self.abort();
            return Err(Refusal::Receipt);
        };
        let recorded = !matches!(receipt.copy, RecordedCopy::NotRecorded);
        if receipt.connection != self.connection.id
            || receipt.challenge != self.connection.challenge
            || receipt.sequence != sequence
            || recorded != receipt.broker_sequence.is_some()
            || (recorded && receipt.dropped_bytes.is_some())
            || (!recorded
                && receipt
                    .dropped_bytes
                    .and_then(|count| usize::try_from(count).ok())
                    != Some(bytes))
            || receipt.broker_sequence.is_some_and(|seq| {
                self.last_broker_sequence
                    .is_some_and(|previous| seq <= previous)
            })
        {
            self.abort();
            return Err(Refusal::Receipt);
        }
        if self.apply_disposition(&receipt.copy, bytes).is_err() {
            return Err(self.accounting_failure());
        }
        self.last_broker_sequence = receipt.broker_sequence.or(self.last_broker_sequence);
        self.pending = None;
        Ok(())
    }

    fn apply_disposition(&mut self, copy: &RecordedCopy, bytes: usize) -> Result<(), Refusal> {
        let index = match copy {
            RecordedCopy::NotRecorded => return self.owner_dropped.add(bytes),
            RecordedCopy::Identical => 0,
            RecordedCopy::Masked { .. } => 1,
            RecordedCopy::Withheld { .. } => 2,
        };
        let accepted = self.accepted.plus(Count::one(bytes)?)?;
        let category = self.dispositions[index].plus(Count::one(bytes)?)?;
        self.accepted = accepted;
        self.dispositions[index] = category;
        Ok(())
    }

    fn accounting_failure(&mut self) -> Refusal {
        self.accounting_invalid = true;
        self.abort();
        Refusal::Overflow
    }

    fn abort(&mut self) {
        if self.phase == ProducerPhase::Closed {
            return;
        }
        self.phase = ProducerPhase::Aborted;
        self.connection.permit.retire();
        if let Some((_, bytes)) = self.pending.take()
            && self.unconfirmed.add(bytes).is_err()
        {
            self.accounting_invalid = true;
        }
        for frame in self.queue.drain(..) {
            if self.local_dropped.add(frame.body.len()).is_err() {
                self.accounting_invalid = true;
            }
        }
        self.queued_bytes = 0;
    }

    fn freeze(&mut self) -> Result<(), Refusal> {
        if self.phase != ProducerPhase::Open {
            return Err(Refusal::Frozen);
        }
        self.phase = ProducerPhase::Frozen;
        Ok(())
    }

    fn finish(&mut self) -> Result<ModelFinal, Refusal> {
        if matches!(
            self.phase,
            ProducerPhase::FinishSent | ProducerPhase::Aborted | ProducerPhase::Closed
        ) {
            return Err(Refusal::Retired);
        }
        if self.phase != ProducerPhase::Frozen || !self.queue.is_empty() || self.pending.is_some() {
            return Err(Refusal::NotDrained);
        }
        let through = self.next.checked_sub(1).ok_or(Refusal::Overflow)?;
        if !self.partition_valid()
            || self.accepted.plus(self.owner_dropped)?.frames != through
            || self.unconfirmed != Count::default()
        {
            self.abort();
            return Err(Refusal::Receipt);
        }
        self.connection.close(through)?;
        self.phase = ProducerPhase::FinishSent;
        Ok(ModelFinal {
            binding: self.connection.permit.expected.clone(),
            connection: self.connection.id,
            challenge: self.connection.challenge,
            through,
            accepted: self.accepted,
            owner_dropped: self.owner_dropped,
            masked: self.dispositions[1].frames,
            withheld: self.dispositions[2].frames,
        })
    }

    fn confirm_final(&mut self, reply: &ModelFinal) -> Result<(), Refusal> {
        if self.phase != ProducerPhase::FinishSent
            || self.pending.is_some()
            || !self.queue.is_empty()
            || reply.binding != self.connection.permit.expected
            || reply.connection != self.connection.id
            || reply.challenge != self.connection.challenge
            || reply.through.checked_add(1) != Some(self.next)
            || reply.accepted != self.accepted
            || reply.owner_dropped != self.owner_dropped
            || reply.masked != self.dispositions[1].frames
            || reply.withheld != self.dispositions[2].frames
            || reply
                .accepted
                .plus(reply.owner_dropped)
                .map(|count| count.frames)
                != Ok(reply.through)
            || reply
                .masked
                .checked_add(reply.withheld)
                .and_then(|count| reply.accepted.frames.checked_sub(count))
                != Some(self.dispositions[0].frames)
            || !self.partition_valid()
            || self.unconfirmed != Count::default()
        {
            self.abort();
            return Err(Refusal::Receipt);
        }
        self.phase = ProducerPhase::Closed;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.phase == ProducerPhase::Closed
            && self.partition_valid()
            && self.accepted == self.offered
            && self.local_dropped == Count::default()
            && self.owner_dropped == Count::default()
            && self.unconfirmed == Count::default()
    }

    fn partition_valid(&self) -> bool {
        !self.accounting_invalid
            && self.accounted() == Ok(self.offered)
            && Count::sum(self.dispositions) == Ok(self.accepted)
    }

    fn accounted(&self) -> Result<Count, Refusal> {
        let pending = self.pending.map_or(Count::default(), |(_, bytes)| Count {
            frames: 1,
            bytes: u64::try_from(bytes).unwrap(),
        });
        Count::sum([
            self.accepted,
            self.local_dropped,
            self.owner_dropped,
            self.unconfirmed,
            Count {
                frames: u64::try_from(self.queue.len()).map_err(|_| Refusal::Overflow)?,
                bytes: u64::try_from(self.queued_bytes).map_err(|_| Refusal::Overflow)?,
            },
            pending,
        ])
    }
}

fn producer() -> ModelProducer {
    let permit = ModelPermit::new(binding());
    ModelProducer::new(permit.spend(&binding(), 10).unwrap(), 2, 5)
}

fn record(
    producer: &mut ModelProducer,
    sink: &mut EntrypointSink,
    reader: &mut crate::stream::ReaderHandle,
) -> (ShownChunk, ModelReceipt) {
    let frame = producer.take_next().unwrap().unwrap();
    let shown = sink.ingest(frame.kind, &frame.body);
    let broker_sequence = if matches!(shown.recorded, RecordedCopy::NotRecorded) {
        None
    } else {
        Some(reader.recv().expect("actual broker record").seq)
    };
    let receipt = ModelReceipt {
        connection: producer.connection.id,
        challenge: producer.connection.challenge,
        sequence: frame.sequence,
        broker_sequence,
        dropped_bytes: broker_sequence
            .is_none()
            .then(|| u32::try_from(frame.body.len()).unwrap()),
        copy: shown.recorded.clone(),
    };
    (shown, receipt)
}

fn sealed_fixture_payload(fx: Fixture) -> Vec<u8> {
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{export, verify_chunks, verify_sealed_root};

    let Fixture { broker, _dir } = fx;
    let broker = Arc::into_inner(broker).unwrap().into_inner().unwrap();
    let manifest = broker.seal().unwrap();
    verify_sealed_root(&manifest).unwrap();
    verify_chunks(&manifest, _dir.path()).unwrap();
    export(&manifest, _dir.path(), &aead::Key::from_bytes([0x5a; 32])).unwrap()
}

#[test]
fn model_wrong_binding_does_not_spend_the_slot() {
    let permit = ModelPermit::new(binding());
    for candidate in [
        FixtureBinding {
            run: 8,
            ..binding()
        },
        FixtureBinding {
            call: 8,
            ..binding()
        },
        FixtureBinding {
            boot: 8,
            ..binding()
        },
        FixtureBinding {
            principal: 8,
            ..binding()
        },
    ] {
        assert!(matches!(
            permit.spend(&candidate, 10),
            Err(Refusal::Binding)
        ));
    }
    assert!(permit.spend(&binding(), 10).is_ok());
}

#[test]
fn model_competing_verifier_callbacks_spend_exactly_once() {
    let permit = ModelPermit::new(binding());
    let barrier = Arc::new(Barrier::new(3));
    let (sent, received) = std::sync::mpsc::channel();
    let mut workers = Vec::new();
    for connection in [10, 11] {
        let (permit, barrier, sent) = (Arc::clone(&permit), Arc::clone(&barrier), sent.clone());
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            sent.send(permit.spend(&binding(), connection)).unwrap();
        }));
    }
    barrier.wait();
    let results: Vec<_> = (0..2)
        .map(|_| {
            received
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Refusal::Spent)))
            .count(),
        1
    );
}

#[test]
fn model_retirement_beats_a_late_valid_verifier_callback() {
    let permit = ModelPermit::new(binding());
    let verified_fixture = binding();
    permit.retire();
    assert!(matches!(
        permit.spend(&verified_fixture, 10),
        Err(Refusal::Retired)
    ));
}

#[test]
fn model_lost_ready_and_empty_output_never_refund_a_spent_permit() {
    let permit = ModelPermit::new(binding());
    let connection = permit.spend(&binding(), 10).unwrap();
    drop(connection);
    assert!(matches!(permit.spend(&binding(), 11), Err(Refusal::Spent)));
    permit.retire();
    assert!(matches!(
        permit.spend(&binding(), 11),
        Err(Refusal::Retired)
    ));
}

#[test]
fn model_foreign_connection_cannot_consume_the_winners_sequence() {
    let permit = ModelPermit::new(binding());
    let winner = permit.spend(&binding(), 10).unwrap();
    let foreign = ModelConnection {
        permit,
        id: 11,
        challenge: winner.challenge,
    };
    assert_eq!(foreign.claim_fragment(1), Err(Refusal::Connection));
    assert_eq!(winner.claim_fragment(1), Ok(()));
    assert_eq!(winner.claim_fragment(1), Err(Refusal::Sequence));
    assert_eq!(winner.claim_fragment(2), Err(Refusal::Retired));
}

#[test]
fn model_pressure_is_accounted_in_frames_and_bytes() {
    let mut producer = producer();
    assert_eq!(producer.offer(StreamKind::Stdout, b"abc"), Ok(Some(1)));
    assert_eq!(producer.offer(StreamKind::Stderr, b"xyz"), Ok(None));
    assert_eq!(producer.offer(StreamKind::Stderr, b"de"), Ok(Some(2)));
    assert_eq!(producer.offer(StreamKind::Stdout, b"f"), Ok(None));
    assert_eq!(producer.queued_bytes, 5);
    assert_eq!(producer.queue.len(), 2);
    assert_eq!(
        producer.local_dropped,
        Count {
            frames: 2,
            bytes: 4
        }
    );
    assert_eq!(producer.accounted(), Ok(producer.offered));
    producer.abort();
    assert_eq!(producer.accounted(), Ok(producer.offered));
    assert!(!producer.complete());
}

#[test]
fn model_invalid_frames_do_not_enter_the_output_count() {
    let mut producer = producer();
    assert_eq!(
        producer.offer(StreamKind::Trace, b"control"),
        Err(Refusal::Frame)
    );
    assert_eq!(
        producer.offer(StreamKind::Stdout, &[0; 16385]),
        Err(Refusal::Frame)
    );
    assert_eq!(producer.offer(StreamKind::Stdout, b""), Ok(None));
    assert_eq!(producer.offered, Count::default());
}

#[test]
fn model_terminal_freezes_the_cut_and_cannot_skip_queued_copies() {
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"abc").unwrap();
    producer.freeze().unwrap();
    let cut = producer.offered;
    assert_eq!(
        producer.offer(StreamKind::Stdout, b"x"),
        Err(Refusal::Frozen)
    );
    assert_eq!(producer.offered, cut);
    assert!(matches!(producer.finish(), Err(Refusal::NotDrained)));
    producer.abort();
    assert_eq!(producer.local_dropped, cut);
    assert!(!producer.complete());
}

#[test]
fn model_abort_distinguishes_unsent_from_possibly_sent() {
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"abc").unwrap();
    producer.offer(StreamKind::Stderr, b"de").unwrap();
    producer.take_next().unwrap().unwrap();
    assert!(matches!(producer.take_next(), Err(Refusal::Window)));
    producer.abort();
    assert_eq!(
        producer.unconfirmed,
        Count {
            frames: 1,
            bytes: 3
        }
    );
    assert_eq!(
        producer.local_dropped,
        Count {
            frames: 1,
            bytes: 2
        }
    );
    assert_eq!(producer.accounted(), Ok(producer.offered));
    assert!(!producer.complete());
}

#[test]
fn model_receipts_use_real_broker_sequences_and_keep_returned_bytes() {
    let fx = fixture("qualification-channels");
    let mut reader = lock_broker(&fx.broker).subscribe();
    let mut sink = EntrypointSink::recorded(&fx.broker);
    let permit = ModelPermit::new(binding());
    let mut producer = ModelProducer::new(permit.spend(&binding(), 10).unwrap(), 2, 64);
    producer.offer(StreamKind::Stdout, b"out").unwrap();
    producer.offer(StreamKind::Stderr, b"err").unwrap();
    for (kind, body) in [
        (StreamKind::Stdout, &b"out"[..]),
        (StreamKind::Stderr, &b"err"[..]),
    ] {
        let (shown, receipt) = record(&mut producer, &mut sink, &mut reader);
        assert_eq!(shown.kind, kind);
        assert_eq!(shown.body, body);
        assert_eq!(receipt.copy, RecordedCopy::Identical);
        producer.confirm(receipt).unwrap();
    }
    producer.freeze().unwrap();
    let final_reply = producer.finish().unwrap();
    assert!(
        !producer.complete(),
        "enqueue and per-frame replies are not final close"
    );
    producer.confirm_final(&final_reply).unwrap();
    assert!(producer.complete());
    assert!(matches!(
        permit.spend(&binding(), 11),
        Err(Refusal::Retired)
    ));
}

#[test]
fn model_real_broker_append_with_lost_reply_remains_unconfirmed() {
    let fx = fixture("qualification-lost-reply");
    let mut reader = lock_broker(&fx.broker).subscribe();
    let mut sink = EntrypointSink::recorded(&fx.broker);
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"out").unwrap();
    let (shown, _lost_reply) = record(&mut producer, &mut sink, &mut reader);
    assert_eq!(shown.body, b"out");
    assert_eq!(lock_broker(&fx.broker).ingested_count(), 1);
    producer.abort();
    assert_eq!(producer.accepted, Count::default());
    assert_eq!(
        producer.unconfirmed,
        Count {
            frames: 1,
            bytes: 3
        }
    );
    assert!(!producer.complete());
    drop(sink);
    assert_eq!(sealed_fixture_payload(fx), b"out");
    assert!(
        !producer.complete(),
        "readback is not the lost call receipt"
    );
}

#[test]
fn model_broker_unavailable_is_not_accepted_output() {
    let fx = fixture("qualification-unavailable");
    let mut reader = lock_broker(&fx.broker).subscribe();
    let mut sink = EntrypointSink::unrecorded();
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"out").unwrap();
    let (shown, receipt) = record(&mut producer, &mut sink, &mut reader);
    assert_eq!(shown.body, b"out");
    assert_eq!(shown.recorded, RecordedCopy::NotRecorded);
    producer.confirm(receipt).unwrap();
    producer.freeze().unwrap();
    let final_reply = producer.finish().unwrap();
    producer.confirm_final(&final_reply).unwrap();
    assert_eq!(
        producer.owner_dropped,
        Count {
            frames: 1,
            bytes: 3
        }
    );
    assert!(!producer.complete());
}

#[test]
fn model_wrong_or_incomplete_receipt_does_not_clear_uncertainty() {
    for (connection, sequence, broker_sequence) in
        [(11, 1, Some(0)), (10, 2, Some(0)), (10, 1, None)]
    {
        let mut producer = producer();
        producer.offer(StreamKind::Stdout, b"out").unwrap();
        producer.take_next().unwrap().unwrap();
        assert_eq!(
            producer.confirm(ModelReceipt {
                connection,
                challenge: producer.connection.challenge,
                sequence,
                broker_sequence,
                dropped_bytes: None,
                copy: RecordedCopy::Identical,
            }),
            Err(Refusal::Receipt)
        );
        assert_eq!(producer.unconfirmed.frames, 1);
        assert!(!producer.complete());
    }
}

#[test]
fn model_lost_or_conflicting_final_cannot_project_success() {
    let mutations: [fn(&mut ModelFinal); 3] = [
        |reply| reply.binding.call += 1,
        |reply| reply.through += 1,
        |reply| reply.accepted.frames += 1,
    ];
    for mutate in mutations {
        let mut producer = producer();
        producer.freeze().unwrap();
        let reply = producer.finish().unwrap();
        let mut wrong = reply.clone();
        mutate(&mut wrong);
        assert_eq!(producer.confirm_final(&wrong), Err(Refusal::Receipt));
        assert_eq!(producer.confirm_final(&reply), Err(Refusal::Receipt));
        assert!(matches!(producer.finish(), Err(Refusal::Retired)));
        assert!(!producer.complete());
    }
}

#[test]
fn model_an_unsolicited_final_cannot_close_an_unfinished_call() {
    let mut producer = producer();
    producer.freeze().unwrap();
    let unsolicited = ModelFinal {
        binding: binding(),
        connection: producer.connection.id,
        challenge: producer.connection.challenge,
        through: 0,
        accepted: Count::default(),
        owner_dropped: Count::default(),
        masked: 0,
        withheld: 0,
    };
    assert_eq!(producer.confirm_final(&unsolicited), Err(Refusal::Receipt));
    assert!(!producer.complete());
    assert!(matches!(producer.finish(), Err(Refusal::Retired)));
}

#[test]
fn model_final_after_deadline_cannot_upgrade_unknown() {
    let mut producer = producer();
    producer.freeze().unwrap();
    let reply = producer.finish().unwrap();
    producer.abort();
    assert_eq!(producer.confirm_final(&reply), Err(Refusal::Receipt));
    assert!(!producer.complete());
}

#[test]
fn model_empty_call_can_close_but_cannot_reactivate_its_permit() {
    let mut producer = producer();
    producer.freeze().unwrap();
    let reply = producer.finish().unwrap();
    producer.confirm_final(&reply).unwrap();
    assert!(
        producer.complete(),
        "an explicitly closed empty call is valid"
    );
    assert_eq!(producer.connection.claim_fragment(1), Err(Refusal::Retired));
}

#[test]
fn model_recorded_redaction_is_real_but_not_a_runtime_publication_receipt() {
    let fx = fixture("qualification-redaction");
    let mut reader = lock_broker(&fx.broker).subscribe();
    let mut sink = EntrypointSink::recorded(&fx.broker);
    let permit = ModelPermit::new(binding());
    let mut producer = ModelProducer::new(permit.spend(&binding(), 10).unwrap(), 2, 64);
    let raw = b"card 4111111111111111 end";
    producer.offer(StreamKind::Stdout, raw).unwrap();
    let (shown, receipt) = record(&mut producer, &mut sink, &mut reader);
    assert_eq!(shown.body, raw);
    assert!(matches!(receipt.copy, RecordedCopy::Masked { .. }));
    producer.confirm(receipt).unwrap();
    drop(sink);
    let protected = sealed_fixture_payload(fx);
    assert!(
        !protected
            .windows(16)
            .any(|bytes| bytes == b"4111111111111111")
    );
    assert!(
        !producer.complete(),
        "record verification is separate from final reply"
    );
}
