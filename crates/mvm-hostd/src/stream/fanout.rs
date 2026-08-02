//! Per-reader delivery queues: the bounded ring that keeps a stalled
//! follower from ever reaching back into ingest.
//!
//! One producer, N readers, and the producer must not care how fast any of
//! them are. Each reader gets its own ring: when it fills, that reader's
//! oldest records are dropped and its gap marker grows. Nobody else notices
//! and the producer never waits.
//!
//! Two bounds, not one. Bytes alone leaves the element count unbounded, and
//! a workload emitting single-byte writes then costs two orders of magnitude
//! more resident memory in per-record overhead than the byte bound suggests.
//! [`RingState`] enforces both.
//!
//! Records are shared as `Arc`, so fanning one chunk out to K readers costs
//! K pointers, not K payload copies.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use mvm_core::transcript::{Admission, CaptureBounds, GapMarker, RingState};
use mvm_protocol::stream::StreamRecord;

/// Payload bytes one follower may fall behind by before its oldest records
/// are dropped.
pub const DEFAULT_READER_MAX_BYTES: u64 = 1 << 20;

/// Records one follower may fall behind by. The companion bound to
/// [`DEFAULT_READER_MAX_BYTES`]: it is what caps per-record overhead when a
/// workload writes a byte at a time.
pub const DEFAULT_READER_MAX_RECORDS: u64 = 4_096;

/// Default window one follower is allowed to fall behind by.
pub const DEFAULT_READER_BOUNDS: CaptureBounds = CaptureBounds {
    // A follower's window is bounded by bytes and record count, never by
    // age. `RingState` reads no clock and never looks at this field.
    max_duration_secs: u64::MAX,
    max_bytes: DEFAULT_READER_MAX_BYTES,
    max_chunks: DEFAULT_READER_MAX_RECORDS,
};

/// One follower's bounded delivery queue. Lives behind an `Arc<Mutex<_>>`
/// shared with the broker so ingest and `recv` never borrow each other.
pub(crate) struct ReaderQueue {
    records: VecDeque<Arc<StreamRecord>>,
    ring: RingState,
    gap: Option<GapMarker>,
}

impl ReaderQueue {
    fn new(bounds: CaptureBounds) -> Self {
        Self {
            records: VecDeque::new(),
            ring: RingState::new(bounds),
            gap: None,
        }
    }

    /// Enqueue one record, evicting this reader's oldest if it no longer
    /// fits. Never refuses — the newest write always wins, which is what
    /// keeps a stalled follower from stalling the producer.
    pub(crate) fn push(&mut self, record: Arc<StreamRecord>) {
        let size = record.payload.len() as u64;
        if let Admission::AcceptAfterPruning { pruned_seqs, .. } = self.ring.admit(size) {
            self.evict_oldest(pruned_seqs.len());
        }
        self.records.push_back(record);
    }

    /// Drop the `count` oldest records the ring just evicted and fold them
    /// into this reader's gap.
    ///
    /// Work is proportional to `count`, not to queue length: a full scan per
    /// eviction turns steady-state draining into quadratic work.
    ///
    /// The gap is folded here rather than through `GapTally` because the
    /// tally reports the *ring's* sequence numbers. A reader that subscribed
    /// mid-stream starts its ring at zero while the records it holds carry
    /// much higher stream sequence numbers, so the two disagree — and it is
    /// the stream number a consumer needs to resume from.
    fn evict_oldest(&mut self, count: usize) {
        let mut after_seq = None;
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        for _ in 0..count {
            let Some(evicted) = self.records.pop_front() else {
                break;
            };
            after_seq = Some(evicted.seq);
            chunks = chunks.saturating_add(1);
            bytes = bytes.saturating_add(evicted.payload.len() as u64);
        }
        let Some(after_seq) = after_seq else {
            return;
        };
        self.gap = Some(match self.gap {
            Some(prev) => GapMarker {
                after_seq,
                dropped_chunks: prev.dropped_chunks.saturating_add(chunks),
                dropped_bytes: prev.dropped_bytes.saturating_add(bytes),
            },
            None => GapMarker {
                after_seq,
                dropped_chunks: chunks,
                dropped_bytes: bytes,
            },
        });
    }

    fn pop(&mut self) -> Option<Arc<StreamRecord>> {
        let record = self.records.pop_front()?;
        // Delivered is not evicted: release the bytes so the ring stops
        // charging for a record this reader no longer holds.
        self.ring.release_oldest();
        Some(record)
    }
}

/// Where a follower starts. Two bare `u64`s side by side in a constructor
/// are trivially transposable, so they travel named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderStart {
    /// Broker-assigned reader id, unique within one broker.
    pub id: u64,
    /// Sequence number of the first record this reader will be handed.
    pub from_seq: u64,
    /// Hash of the record immediately before `from_seq`, all-zero when the
    /// reader attached before the stream produced anything.
    pub anchor: [u8; 32],
}

/// A follower's end of the stream. Dropping it releases the queue; the
/// broker reaps the dangling reference on its next record.
pub struct ReaderHandle {
    start: ReaderStart,
    queue: Arc<Mutex<ReaderQueue>>,
}

impl ReaderHandle {
    pub(crate) fn new(start: ReaderStart, bounds: CaptureBounds) -> Self {
        Self {
            start,
            queue: Arc::new(Mutex::new(ReaderQueue::new(bounds))),
        }
    }

    /// The broker's half of the shared queue. Weak so a dropped handle
    /// really does free its buffered records.
    pub(crate) fn weak_queue(&self) -> Weak<Mutex<ReaderQueue>> {
        Arc::downgrade(&self.queue)
    }

    /// This reader's id, as recorded in the chain-signed subscribe entry.
    pub fn id(&self) -> u64 {
        self.start.id
    }

    /// Sequence number of the first record this reader was handed.
    pub fn from_seq(&self) -> u64 {
        self.start.from_seq
    }

    /// The hash a consumer verifies its delivered window against.
    ///
    /// A follower that attached mid-stream holds a window, not a chain from
    /// genesis, so `verify_chain` rejects it by design and
    /// `verify_chain_from` against this anchor is the right check. Once
    /// [`ReaderHandle::gap`] is set the window no longer starts here — it
    /// resumes after the gap, and the anchor for it is the hash of the
    /// record at `after_seq`, which the reader no longer holds.
    pub fn anchor(&self) -> [u8; 32] {
        self.start.anchor
    }

    /// Take the next record, or `None` when this reader is caught up.
    pub fn recv(&mut self) -> Option<StreamRecord> {
        let record = lock_queue(&self.queue).pop()?;
        // The last holder gets the record outright; earlier readers copy.
        Some(Arc::try_unwrap(record).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// What this reader missed, folded into one marker, or `None` when it
    /// has kept up. `after_seq` is the anchor a caller verifies the
    /// surviving window against.
    pub fn gap(&self) -> Option<GapMarker> {
        lock_queue(&self.queue).gap
    }

    /// Records dropped because this reader fell behind.
    pub fn dropped_count(&self) -> u64 {
        self.gap().map_or(0, |g| g.dropped_chunks)
    }

    /// Payload bytes dropped because this reader fell behind.
    pub fn dropped_bytes(&self) -> u64 {
        self.gap().map_or(0, |g| g.dropped_bytes)
    }

    /// Records buffered and not yet taken.
    pub fn pending(&self) -> usize {
        lock_queue(&self.queue).records.len()
    }

    /// Whether this reader is caught up.
    pub fn is_empty(&self) -> bool {
        self.pending() == 0
    }
}

/// Take a queue lock, ignoring poison.
///
/// A reader that panicked mid-`recv` must not silence ingest for everyone
/// else. The queue is plain data and is never left half-updated across a
/// panic point, so the poison flag carries nothing to act on.
pub(crate) fn lock_queue(queue: &Mutex<ReaderQueue>) -> MutexGuard<'_, ReaderQueue> {
    queue.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::stream::{StreamKind, StreamSource};

    fn bounds(max_bytes: u64, max_chunks: u64) -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes,
            max_chunks,
        }
    }

    /// A reader attached at genesis; these tests drive the queue directly, so
    /// the start metadata is not what is under test.
    fn start_at(from_seq: u64) -> ReaderStart {
        ReaderStart {
            id: 0,
            from_seq,
            anchor: [0u8; 32],
        }
    }

    fn record(seq: u64, payload: &[u8]) -> Arc<StreamRecord> {
        Arc::new(StreamRecord {
            seq,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stdout,
            host_unix_nanos: 1_000 + seq,
            prev_hash: [0u8; 32],
            payload: payload.to_vec(),
        })
    }

    #[test]
    fn a_reader_takes_records_in_order() {
        let mut handle = ReaderHandle::new(start_at(0), DEFAULT_READER_BOUNDS);
        {
            let mut q = lock_queue(&handle.queue);
            q.push(record(0, b"a"));
            q.push(record(1, b"b"));
        }
        assert_eq!(handle.recv().expect("first").seq, 0);
        assert_eq!(handle.recv().expect("second").seq, 1);
        assert!(handle.recv().is_none());
    }

    #[test]
    fn the_record_bound_holds_even_when_the_byte_bound_never_would() {
        // The failure this bound exists for: one-byte writes against a
        // bytes-only bound leave the element count — and its per-record
        // overhead — unbounded.
        let handle = ReaderHandle::new(start_at(0), bounds(1 << 20, 8));
        {
            let mut q = lock_queue(&handle.queue);
            for seq in 0..1_000u64 {
                q.push(record(seq, b"x"));
            }
        }
        assert_eq!(handle.pending(), 8, "the record bound must cap the queue");
        assert_eq!(handle.dropped_count(), 992);
    }

    #[test]
    fn the_byte_bound_holds_for_large_records() {
        let handle = ReaderHandle::new(start_at(0), bounds(100, 1_000));
        {
            let mut q = lock_queue(&handle.queue);
            q.push(record(0, &[b'x'; 60]));
            q.push(record(1, &[b'x'; 60]));
        }
        assert_eq!(handle.pending(), 1, "60 + 60 exceeds the 100-byte window");
        assert_eq!(handle.dropped_bytes(), 60);
    }

    #[test]
    fn a_gap_names_the_last_stream_seq_the_reader_lost() {
        let handle = ReaderHandle::new(start_at(0), bounds(1 << 20, 2));
        {
            let mut q = lock_queue(&handle.queue);
            // Start at 500 so a ring-local sequence number would disagree.
            for seq in 500..505u64 {
                q.push(record(seq, b"x"));
            }
        }
        let gap = handle.gap().expect("the reader fell behind");
        assert_eq!(gap.after_seq, 502, "gap must speak in stream sequence");
        assert_eq!(gap.dropped_chunks, 3);
    }

    #[test]
    fn draining_frees_the_window_so_a_keeping_up_reader_never_gaps() {
        let mut handle = ReaderHandle::new(start_at(0), bounds(4, 2));
        for seq in 0..50u64 {
            lock_queue(&handle.queue).push(record(seq, b"xx"));
            assert_eq!(handle.recv().expect("record").seq, seq);
        }
        assert_eq!(handle.gap(), None, "a drained reader misses nothing");
    }

    #[test]
    fn a_record_larger_than_the_whole_window_is_still_delivered() {
        let mut handle = ReaderHandle::new(start_at(0), bounds(10, 4));
        {
            let mut q = lock_queue(&handle.queue);
            q.push(record(0, b"xx"));
            q.push(record(1, &[b'x'; 500]));
        }
        assert_eq!(
            handle.recv().expect("the oversized record").seq,
            1,
            "the newest write always wins"
        );
    }
}
