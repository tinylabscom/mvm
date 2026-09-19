use super::*;
use crate::protocol::telemetry::{CoverageState, ProducerEpoch, RecordBody, SourceKind};

fn prepared(sequence: u64) -> PreparedRecord {
    PreparedRecord::new(
        &TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([1; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "test-sentinel".try_into().unwrap(),
            })
            .build()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn rejects_invalid_limits_before_allocating() {
    for (records, bytes) in [(0, 1), (257, 1), (1, 0), (1, MAX_RECORD_BYTES + 1)] {
        assert!(matches!(
            Outbox::new(records, bytes),
            Err(RecordError::Capacity)
        ));
    }
}

#[test]
fn count_and_byte_limits_shed_without_replacing_queued_records() {
    let first = prepared(1);
    let second = prepared(2);
    assert!(!first.is_empty());
    for queue in [
        Outbox::new(1, MAX_RECORD_BYTES).unwrap(),
        Outbox::new(2, first.len()).unwrap(),
    ] {
        assert_eq!(queue.offer(&first), Offer::Queued);
        assert_eq!(queue.offer(&second), Offer::Full);
        let losses = queue.losses();
        assert_eq!(losses.capacity.records, 1);
        assert_eq!(losses.capacity.bytes, second.len() as u64);
        assert!(!losses.counts_overflowed);
        assert_eq!(queue.take().unwrap().unwrap().bytes, first.bytes);
        assert!(queue.take().unwrap().is_none());
        assert_eq!(queue.offer(&second), Offer::Queued);
    }
}

#[test]
fn contention_returns_before_the_worker_releases_its_lock() {
    let queue = Outbox::new(1, MAX_RECORD_BYTES).unwrap();
    let record = prepared(1);
    let held = queue.state.lock().unwrap();
    std::thread::scope(|scope| {
        let (done, result) = std::sync::mpsc::channel();
        let queue = &queue;
        let record = &record;
        scope.spawn(move || done.send(queue.offer(record)).unwrap());
        let observed = result.recv_timeout(std::time::Duration::from_secs(2));
        // Release even on failure so an accidentally blocking implementation
        // fails the test rather than deadlocking its scoped-thread join.
        drop(held);
        assert_eq!(observed.unwrap(), Offer::Contended);
    });
    assert_eq!(queue.losses().contention.records, 1);
    assert_eq!(queue.losses().contention.bytes, record.len() as u64);
}

#[test]
fn closed_and_poisoned_queues_fail_without_panicking_or_waiting() {
    let queue = Outbox::new(1, MAX_RECORD_BYTES).unwrap();
    let record = prepared(1);
    assert_eq!(queue.offer(&record), Offer::Queued);
    queue.close();
    assert_eq!(queue.offer(&record), Offer::Closed);
    assert_eq!(queue.take().unwrap().unwrap().bytes, record.bytes);
    assert_eq!(queue.losses().unavailable.records, 1);

    let _ = std::panic::catch_unwind(|| {
        let _held = queue.state.lock().unwrap();
        panic!("deliberately poison queue");
    });
    assert_eq!(queue.offer(&record), Offer::Unavailable);
    assert!(queue.take().is_err());
    assert_eq!(queue.losses().unavailable.records, 2);
    assert!(queue.losses().queue_tail_unknown);
}

#[test]
fn closing_admission_does_not_wait_for_the_worker_lock() {
    let queue = Outbox::new(1, MAX_RECORD_BYTES).unwrap();
    let held = queue.state.lock().unwrap();
    std::thread::scope(|scope| {
        let (done, result) = std::sync::mpsc::channel();
        let queue = &queue;
        scope.spawn(move || {
            queue.close();
            done.send(()).unwrap();
        });
        let observed = result.recv_timeout(std::time::Duration::from_secs(2));
        drop(held);
        observed.unwrap();
    });
    assert_eq!(queue.offer(&prepared(1)), Offer::Closed);
}

#[test]
fn loss_overflow_is_explicit_and_diagnostics_never_include_payload() {
    let queue = Outbox::new(1, MAX_RECORD_BYTES).unwrap();
    let record = prepared(1);
    assert_eq!(queue.offer(&record), Offer::Queued);
    queue.capacity.records.store(u64::MAX, Ordering::Relaxed);
    queue.capacity.bytes.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(queue.offer(&record), Offer::Full);
    assert!(queue.losses().counts_overflowed);
    assert!(!format!("{record:?}").contains("test-sentinel"));
}

#[test]
fn slots_wrap_and_reuse_storage_without_growing() {
    let queue = Outbox::new(2, 2 * MAX_RECORD_BYTES).unwrap();
    let pointer = queue.state.lock().unwrap().slots.as_ptr();
    for sequence in 1..100 {
        let record = prepared(sequence);
        assert_eq!(queue.offer(&record), Offer::Queued);
        assert_eq!(queue.take().unwrap().unwrap().bytes, record.bytes);
    }
    assert_eq!(queue.state.lock().unwrap().slots.as_ptr(), pointer);
    assert_eq!(queue.losses(), LossSnapshot::default());
}
