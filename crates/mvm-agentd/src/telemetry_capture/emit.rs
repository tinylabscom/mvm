//! One-attempt, non-waiting record emission into the shared outbox.
//!
//! `emit` builds, prepares and offers exactly once. It never waits on the
//! queue, never notifies a worker (the transport worker owns its own draining
//! cadence), and never emits a record about its own shed — a shed only bumps
//! per-producer counters, so saturation cannot recurse into more emission.

use mvm_core::net::telemetry::outbox::{Offer, PreparedRecord};
use mvm_core::protocol::telemetry::{RecordBody, SourceKind, TelemetryRecord};

use super::state::{CaptureState, ProducerId};

/// Result of one emission attempt. A shed is already counted when returned;
/// callers may ignore it (a tracing callback has nothing better to do).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Copied into the bounded queue. Not delivered, not acknowledged.
    Queued,
    /// Dropped after exactly one attempt, with per-producer loss counted.
    Shed(ShedReason),
}

/// Why one attempt shed. Mirrors the outbox's queue-global stages so the
/// per-producer counters can be reconciled against the queue's own evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedReason {
    /// Queue record or byte capacity exhausted.
    Capacity,
    /// Another thread held the queue lock; no wait or retry was attempted.
    Contention,
    /// Closed or poisoned queue, or the epoch was mid-rotation.
    Unavailable,
    /// The record could not be built or encoded within its ceilings.
    Rejected,
}

impl CaptureState {
    /// Make exactly one non-waiting emission attempt for `body`.
    ///
    /// The attempt spends a sequence number before anything can fail, so a
    /// shed leaves a visible gap for the host instead of a silent renumber.
    /// `source` is the declared class stamped into the record; `producer`
    /// selects the fixed producer number and the accounting row.
    pub fn emit(&self, source: SourceKind, producer: ProducerId, body: RecordBody) -> EmitOutcome {
        let sequence = self.next_sequence(producer);
        let Some((epoch, monotonic_ns)) = self.identity_now() else {
            return self.shed(producer, ShedReason::Unavailable, 0);
        };
        let record = TelemetryRecord::builder()
            .epoch(epoch)
            .producer(producer.number())
            .sequence(sequence)
            .monotonic_ns(monotonic_ns)
            .source(source)
            .body(body)
            .build();
        let Ok(record) = record else {
            return self.shed(producer, ShedReason::Rejected, 0);
        };
        let Ok(prepared) = PreparedRecord::new(&record) else {
            return self.shed(producer, ShedReason::Rejected, 0);
        };
        let bytes = prepared.len() as u64;
        match self.outbox().offer(&prepared) {
            Offer::Queued => EmitOutcome::Queued,
            Offer::Full => self.shed(producer, ShedReason::Capacity, bytes),
            Offer::Contended => self.shed(producer, ShedReason::Contention, bytes),
            Offer::Closed | Offer::Unavailable => {
                self.shed(producer, ShedReason::Unavailable, bytes)
            }
        }
    }

    fn shed(&self, producer: ProducerId, reason: ShedReason, bytes: u64) -> EmitOutcome {
        self.count_shed(producer, reason, bytes);
        EmitOutcome::Shed(reason)
    }
}

impl CaptureState {
    /// Build and prepare one record outside the queue, spending a sequence
    /// number like any other attempt. For the session plane's own records —
    /// the coverage announcement and loss summaries — which must reach the
    /// host even when the data queue is saturated, so they ride the
    /// transport's reserved direct path instead of an offer. A record that
    /// cannot be built is counted as a rejected attempt and yields `None`.
    pub fn prepare_direct(
        &self,
        source: SourceKind,
        producer: ProducerId,
        body: RecordBody,
    ) -> Option<PreparedRecord> {
        let sequence = self.next_sequence(producer);
        let Some((epoch, monotonic_ns)) = self.identity_now() else {
            self.shed(producer, ShedReason::Unavailable, 0);
            return None;
        };
        let prepared = TelemetryRecord::builder()
            .epoch(epoch)
            .producer(producer.number())
            .sequence(sequence)
            .monotonic_ns(monotonic_ns)
            .source(source)
            .body(body)
            .build()
            .and_then(|record| PreparedRecord::new(&record));
        match prepared {
            Ok(prepared) => Some(prepared),
            Err(_) => {
                self.shed(producer, ShedReason::Rejected, 0);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use mvm_core::net::telemetry::outbox::Outbox;
    use mvm_core::protocol::telemetry::{
        Attribute, AttributeValue, Attributes, Level, MAX_ATTRIBUTES, MAX_RECORD_BYTES,
    };

    use super::*;

    fn state_over(records: usize) -> (Arc<Outbox>, CaptureState) {
        let outbox = Arc::new(Outbox::new(records, records * MAX_RECORD_BYTES).unwrap());
        let state = CaptureState::new(outbox.clone()).unwrap();
        (outbox, state)
    }

    fn body() -> RecordBody {
        RecordBody::Event {
            context: None,
            level: Level::Info,
            name: "capture-test".try_into().unwrap(),
            attributes: Attributes::default(),
        }
    }

    fn emit(state: &CaptureState) -> EmitOutcome {
        state.emit(SourceKind::GuestAgent, ProducerId::AgentDiagnostics, body())
    }

    fn drain(outbox: &Outbox) -> Vec<TelemetryRecord> {
        let mut records = Vec::new();
        while let Some(prepared) = outbox.take_for_test().unwrap() {
            records.push(TelemetryRecord::decode(prepared.encoded_for_test()).unwrap());
        }
        records
    }

    #[test]
    fn sequences_count_attempts_and_shed_is_accounted_per_producer() {
        let (outbox, state) = state_over(1);
        assert_eq!(emit(&state), EmitOutcome::Queued);
        for _ in 0..4 {
            assert_eq!(emit(&state), EmitOutcome::Shed(ShedReason::Capacity));
        }
        let losses = state.losses(ProducerId::AgentDiagnostics);
        assert_eq!(losses.attempts, 5);
        assert_eq!(losses.capacity.records, 4);
        // One producer feeds the queue, so the per-producer byte evidence
        // must reconcile exactly with the queue-global counters.
        assert_eq!(losses.capacity.bytes, outbox.losses().capacity.bytes);
        assert!(losses.capacity.bytes > 0);

        let queued = drain(&outbox);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].sequence(), 1);
        // The next successful record carries the post-shed sequence, leaving
        // the gap the host detects rather than renumbering over the loss.
        assert_eq!(emit(&state), EmitOutcome::Queued);
        assert_eq!(drain(&outbox)[0].sequence(), 6);
    }

    #[test]
    fn a_locked_queue_sheds_contention_without_blocking() {
        let (outbox, state) = state_over(1);
        assert_eq!(emit(&state), EmitOutcome::Queued);
        let held = outbox.hold_queue_lock_for_test();
        std::thread::scope(|scope| {
            let (done, result) = mpsc::channel();
            let state = &state;
            scope.spawn(move || done.send(emit(state)).unwrap());
            let observed = result.recv_timeout(Duration::from_secs(2));
            // Release even on failure so an accidentally blocking emit fails
            // the test rather than deadlocking its scoped-thread join.
            drop(held);
            assert_eq!(observed.unwrap(), EmitOutcome::Shed(ShedReason::Contention));
        });
        let losses = state.losses(ProducerId::AgentDiagnostics);
        assert_eq!(losses.contention.records, 1);
        assert_eq!(losses.contention.bytes, outbox.losses().contention.bytes);
    }

    #[test]
    fn a_shed_emit_never_emits_a_record_about_its_own_shed() {
        let (outbox, state) = state_over(1);
        assert_eq!(emit(&state), EmitOutcome::Queued);
        assert_eq!(emit(&state), EmitOutcome::Shed(ShedReason::Capacity));
        // Exactly one offer was refused: a synthesized shed record would have
        // spent a second refusal or occupied the drained slot below.
        assert_eq!(outbox.losses().capacity.records, 1);
        let queued = drain(&outbox);
        assert_eq!(queued.len(), 1);
        assert!(matches!(queued[0].body(), RecordBody::Event { .. }));
    }

    #[test]
    fn a_closed_queue_sheds_as_unavailable() {
        let (outbox, state) = state_over(1);
        outbox.close();
        assert_eq!(emit(&state), EmitOutcome::Shed(ShedReason::Unavailable));
        assert_eq!(
            state
                .losses(ProducerId::AgentDiagnostics)
                .unavailable
                .records,
            1
        );
    }

    #[test]
    fn an_oversize_record_is_rejected_before_admission() {
        let (outbox, state) = state_over(1);
        let value = "x".repeat(2048);
        let attributes = (0..MAX_ATTRIBUTES)
            .map(|index| Attribute {
                key: format!("k{index}").as_str().try_into().unwrap(),
                value: AttributeValue::Text(value.as_str().try_into().unwrap()),
            })
            .collect();
        let body = RecordBody::Event {
            context: None,
            level: Level::Info,
            name: "oversize".try_into().unwrap(),
            attributes: Attributes::new(attributes).unwrap(),
        };
        let outcome = state.emit(SourceKind::GuestAgent, ProducerId::AgentDiagnostics, body);
        assert_eq!(outcome, EmitOutcome::Shed(ShedReason::Rejected));
        let losses = state.losses(ProducerId::AgentDiagnostics);
        assert_eq!(losses.rejected.records, 1);
        assert_eq!(losses.attempts, 1);
        assert!(drain(&outbox).is_empty());
    }

    #[test]
    fn epoch_is_stable_across_emits_and_changes_only_on_rotate() {
        let (outbox, state) = state_over(8);
        for _ in 0..4 {
            assert_eq!(emit(&state), EmitOutcome::Queued);
        }
        state.rotate_epoch().unwrap();
        assert_eq!(emit(&state), EmitOutcome::Queued);
        let records = drain(&outbox);
        let first_epoch = records[0].epoch();
        assert!(records[..4].iter().all(|r| r.epoch() == first_epoch));
        assert_ne!(records[4].epoch(), first_epoch);
    }

    #[test]
    fn monotonic_ns_is_nondecreasing_across_sequential_emits() {
        let (outbox, state) = state_over(8);
        for _ in 0..5 {
            assert_eq!(emit(&state), EmitOutcome::Queued);
        }
        let records = drain(&outbox);
        for pair in records.windows(2) {
            assert!(pair[1].monotonic_ns() >= pair[0].monotonic_ns());
        }
    }
}
