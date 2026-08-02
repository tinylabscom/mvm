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

use mvm_core::transcript::{CaptureBounds, GapMarker, RingState};
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
///
/// Visible only inside [`crate::stream`]: the broker's `fan_out` is the one
/// writer, and a queue reachable from anywhere else in the crate is a way to
/// hand a reader a record that never crossed the redaction seam.
pub(in crate::stream) struct ReaderQueue {
    records: VecDeque<Arc<StreamRecord>>,
    ring: RingState,
    gap: Option<GapMarker>,
    resume_anchor: Option<[u8; 32]>,
}

impl ReaderQueue {
    fn new(bounds: CaptureBounds) -> Self {
        Self {
            records: VecDeque::new(),
            ring: RingState::new(bounds),
            gap: None,
            resume_anchor: None,
        }
    }

    /// Enqueue one record, evicting this reader's oldest if it no longer
    /// fits. Never refuses — the newest write always wins, which is what
    /// keeps a stalled follower from stalling the producer.
    pub(in crate::stream) fn push(&mut self, record: Arc<StreamRecord>) {
        let size = record.payload.len() as u64;
        let evicted = self.ring.admit_counted(size);
        self.evict_oldest(usize::try_from(evicted.chunks).unwrap_or(usize::MAX));
        self.records.push_back(record);
    }

    /// Drop the `count` oldest records the ring just evicted, fold them into
    /// this reader's gap, and keep the hash of the newest one as the anchor
    /// the surviving window chains from.
    ///
    /// Keeping that hash is what makes a pruned window verifiable at all. A
    /// follower that falls behind is handed survivors whose first `prev_hash`
    /// is a real predecessor's — so `verify_chain` rejects them (not genesis)
    /// and the anchor it attached with is now stale. The hash of the last
    /// record it will never see is the one value that closes the gap, and it
    /// is computed from a record the reader does *not* keep, so the check is
    /// evidence rather than a restatement of the window's own bytes.
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
        let mut last = None;
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        for _ in 0..count {
            let Some(evicted) = self.records.pop_front() else {
                break;
            };
            chunks = chunks.saturating_add(1);
            bytes = bytes.saturating_add(evicted.payload.len() as u64);
            last = Some(evicted);
        }
        let Some(last) = last else {
            return;
        };
        let after_seq = last.seq;
        // One hash per eviction batch, not per evicted record.
        self.resume_anchor = Some(last.hash());
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

/// Everything a follower needs to verify one delivery, sampled together.
///
/// The three values are only meaningful as a set. Read separately —
/// [`ReaderHandle::recv`], then [`ReaderHandle::anchor`], then
/// [`ReaderHandle::gap`] — an eviction landing between two of the calls
/// yields a window that does not chain from the anchor beside it, and the
/// consumer renders that mismatch as tampering. [`ReaderHandle::drain_verified`]
/// takes all three under one lock so the triple is always self-consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedWindow {
    /// Every record this reader had buffered, in sequence order.
    pub records: Vec<StreamRecord>,
    /// The hash `records` chains from: the reader's attach point, or the
    /// hash of the last record it lost if retention has moved it since.
    pub anchor: [u8; 32],
    /// What this reader has lost so far, folded into one marker.
    pub gap: Option<GapMarker>,
}

/// A follower's end of the stream. Dropping it releases the queue; the
/// broker reaps the dangling reference on its next record.
pub struct ReaderHandle {
    start: ReaderStart,
    queue: Arc<Mutex<ReaderQueue>>,
}

impl ReaderHandle {
    pub(in crate::stream) fn new(start: ReaderStart, bounds: CaptureBounds) -> Self {
        Self {
            start,
            queue: Arc::new(Mutex::new(ReaderQueue::new(bounds))),
        }
    }

    /// The broker's half of the shared queue. Weak so a dropped handle
    /// really does free its buffered records.
    pub(in crate::stream) fn weak_queue(&self) -> Weak<Mutex<ReaderQueue>> {
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
    /// `verify_chain_from` against this anchor is the right check.
    ///
    /// After a loss this moves: it becomes the hash of the last record the
    /// reader will never see, which is precisely what the surviving window
    /// chains from. So the anchor covers every record handed to this reader
    /// since it attached, or since its most recent loss, whichever is later
    /// — a consumer that re-verifies as it drains restarts its window
    /// whenever [`ReaderHandle::gap`] changes.
    pub fn anchor(&self) -> [u8; 32] {
        lock_queue(&self.queue)
            .resume_anchor
            .unwrap_or(self.start.anchor)
    }

    /// The anchor this reader attached at, before any loss moved it.
    pub fn attach_anchor(&self) -> [u8; 32] {
        self.start.anchor
    }

    /// Take the next record, or `None` when this reader is caught up.
    pub fn recv(&mut self) -> Option<StreamRecord> {
        let record = lock_queue(&self.queue).pop()?;
        // The last holder gets the record outright; earlier readers copy.
        Some(Arc::try_unwrap(record).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// Take everything buffered together with the anchor and gap that make
    /// it verifiable — one lock, one consistent [`DrainedWindow`].
    ///
    /// This is the delivery path a consumer should use. Draining record by
    /// record and then asking for the anchor separately is a race: retention
    /// can evict between the two calls, and the anchor that comes back then
    /// describes a different window than the one in hand. The consumer has no
    /// way to tell that apart from a tampered chain, so it reports the one
    /// failure this whole subsystem exists to make trustworthy.
    ///
    /// Costs no hashing. The anchor is a value the queue already holds, and
    /// the running anchor for a *subsequent* window is the hash of the last
    /// record here — which the consumer computes itself from a record it has
    /// verified, rather than trusting this side to repeat it.
    pub fn drain_verified(&mut self) -> DrainedWindow {
        let mut queue = lock_queue(&self.queue);
        let anchor = queue.resume_anchor.unwrap_or(self.start.anchor);
        let gap = queue.gap;
        let mut records = Vec::with_capacity(queue.records.len());
        while let Some(record) = queue.pop() {
            // The last holder gets the record outright; earlier readers copy.
            records.push(Arc::try_unwrap(record).unwrap_or_else(|shared| (*shared).clone()));
        }
        DrainedWindow {
            records,
            anchor,
            gap,
        }
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
pub(in crate::stream) fn lock_queue(queue: &Mutex<ReaderQueue>) -> MutexGuard<'_, ReaderQueue> {
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

    /// A real chain: each record's `prev_hash` is its predecessor's hash, so
    /// an anchor is evidence rather than a restatement of the window's bytes.
    fn chained(from: u64, count: u64) -> Vec<Arc<StreamRecord>> {
        let mut out = Vec::new();
        let mut prev = [0u8; 32];
        for seq in from..from + count {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: seq.to_le_bytes().to_vec(),
            };
            prev = record.hash();
            out.push(Arc::new(record));
        }
        out
    }

    #[test]
    fn a_pruned_window_verifies_against_the_anchor_the_queue_kept() {
        // The pruned reader's own path: no second reader, no broker lookup —
        // the survivors must verify from the anchor this queue stashed when it
        // evicted, or a follower that fell behind holds records it cannot check.
        let mut handle = ReaderHandle::new(start_at(0), bounds(1 << 20, 4));
        let records = chained(0, 10);
        {
            let mut q = lock_queue(&handle.queue);
            for record in &records {
                q.push(Arc::clone(record));
            }
        }
        let gap = handle.gap().expect("the reader fell behind");
        let anchor = handle.anchor();
        let survivors: Vec<_> = std::iter::from_fn(|| handle.recv()).collect();

        assert_eq!(survivors.len(), 4);
        assert_eq!(survivors[0].seq, gap.after_seq + 1);
        assert_eq!(
            anchor,
            records[gap.after_seq as usize].hash(),
            "the anchor is the hash of the last record this reader lost"
        );
        assert_ne!(anchor, handle.attach_anchor(), "the anchor moved on loss");
        mvm_protocol::stream::verify_chain_from(&survivors, anchor)
            .expect("the surviving window is unbroken from the anchor the queue kept");
    }

    #[test]
    fn a_reader_that_never_fell_behind_keeps_the_anchor_it_attached_with() {
        let start = ReaderStart {
            id: 3,
            from_seq: 0,
            anchor: [0xab; 32],
        };
        let handle = ReaderHandle::new(start, bounds(1 << 20, 8));
        {
            let mut q = lock_queue(&handle.queue);
            for record in chained(0, 4) {
                q.push(record);
            }
        }
        assert_eq!(handle.gap(), None);
        assert_eq!(handle.anchor(), [0xab; 32]);
        assert_eq!(handle.anchor(), handle.attach_anchor());
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
    fn drain_verified_hands_back_the_window_with_its_own_anchor_and_gap() {
        let mut handle = ReaderHandle::new(start_at(0), bounds(1 << 20, 4));
        let records = chained(0, 10);
        {
            let mut q = lock_queue(&handle.queue);
            for record in &records {
                q.push(Arc::clone(record));
            }
        }

        let window = handle.drain_verified();
        let gap = window.gap.expect("the reader fell behind");
        assert_eq!(window.records.len(), 4);
        assert_eq!(window.records[0].seq, gap.after_seq + 1);
        assert_eq!(
            window.anchor,
            records[gap.after_seq as usize].hash(),
            "the anchor is the hash of the last record this reader lost"
        );
        mvm_protocol::stream::verify_chain_from(&window.records, window.anchor)
            .expect("the triple must verify as a set");
    }

    #[test]
    fn drain_verified_takes_the_anchor_before_a_later_eviction_can_move_it() {
        // The race the separate accessors lose: drain, evict, then read the
        // anchor, and the anchor describes a window the caller does not hold.
        // Reading them as one value is what makes that unrepresentable.
        let mut handle = ReaderHandle::new(start_at(0), bounds(1 << 20, 4));
        let records = chained(0, 12);
        {
            let mut q = lock_queue(&handle.queue);
            for record in &records[..4] {
                q.push(Arc::clone(record));
            }
        }
        let first = handle.drain_verified();
        assert_eq!(first.anchor, [0u8; 32], "attached at genesis");
        assert_eq!(first.gap, None);

        {
            // Overflow the ring so the anchor moves after the first drain.
            let mut q = lock_queue(&handle.queue);
            for record in &records[4..] {
                q.push(Arc::clone(record));
            }
        }
        let second = handle.drain_verified();
        let gap = second.gap.expect("the second window lost records");
        assert_ne!(second.anchor, first.anchor, "loss moved the anchor");
        assert_eq!(second.records[0].seq, gap.after_seq + 1);
        mvm_protocol::stream::verify_chain_from(&second.records, second.anchor)
            .expect("the second window verifies against the anchor it came with");
    }

    #[test]
    fn drain_verified_on_a_caught_up_reader_is_an_empty_window_not_a_stall() {
        let mut handle = ReaderHandle::new(start_at(0), DEFAULT_READER_BOUNDS);
        let window = handle.drain_verified();
        assert!(window.records.is_empty());
        assert_eq!(window.gap, None);
        assert_eq!(window.anchor, [0u8; 32]);
    }

    #[test]
    fn consecutive_drains_of_an_unpruned_reader_report_the_attach_anchor() {
        // The queue's anchor only tracks loss; a consumer that never lost
        // anything chains each window from the hash it computed itself. This
        // pins that contract so the reader side can rely on it.
        let mut handle = ReaderHandle::new(start_at(0), DEFAULT_READER_BOUNDS);
        let records = chained(0, 6);
        {
            let mut q = lock_queue(&handle.queue);
            for record in &records[..3] {
                q.push(Arc::clone(record));
            }
        }
        let first = handle.drain_verified();
        {
            let mut q = lock_queue(&handle.queue);
            for record in &records[3..] {
                q.push(Arc::clone(record));
            }
        }
        let second = handle.drain_verified();
        assert_eq!(first.anchor, second.anchor);
        assert_eq!(second.gap, None, "no loss, so nothing re-anchors");
        assert_eq!(second.records[0].seq, 3);
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
