//! Ring retention: the alternative to `CaptureBudget` for captures that must
//! never go quiet.
//!
//! A forensic egress capture is right to refuse once it hits a bound — that
//! is `CaptureBudget`, unchanged, sitting beside this module. A workload's
//! stdout/stderr needs the opposite policy: the moment it would stop being
//! observed (a crash loop, a runaway process dumping output) is exactly the
//! moment it matters most. `RingState` never refuses; it evicts the oldest
//! admitted chunks to make room for the newest one. It tracks sequence
//! numbers and byte sizes only — no payloads, no file I/O — so the store that
//! actually owns the `{seq}.chunk` files is the one that unlinks what `admit`
//! reports evicted and records a gap for it.

use std::collections::VecDeque;

use super::CaptureBounds;

/// Which admission policy backs a capture: `CaptureBudget`'s fail-closed
/// refusal, or this module's prune-oldest ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    FailClosed,
    Ring,
}

/// Outcome of [`RingState::admit`]. Deliberately has no refusing variant: a
/// stream capture must always accept the newest write, so the type itself
/// makes a silenced workload unrepresentable rather than trusting every
/// caller to remember not to drop one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The chunk fit without evicting anything.
    Accept,
    /// The chunk was admitted only after evicting the oldest live chunks.
    AcceptAfterPruning {
        /// Evicted sequence numbers, oldest first — the caller's cue to
        /// unlink each corresponding `{seq}.chunk` file.
        pruned_seqs: Vec<u64>,
        /// Total bytes freed by the eviction.
        dropped_bytes: u64,
    },
}

/// What one pruning admission dropped. Not produced by `RingState` itself —
/// the caller builds one from an `Admission::AcceptAfterPruning` after it
/// has unlinked the pruned chunk files, as the one gap record for that
/// admission. Shaped so a verifier can use `after_seq` as the anchor point
/// for the surviving window (the same role a `verify_chain_from` anchor
/// plays once the window no longer starts at genesis).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapMarker {
    /// The highest sequence number this admission evicted; the surviving
    /// chain resumes at `after_seq + 1`.
    pub after_seq: u64,
    /// How many chunks were evicted.
    pub dropped_chunks: u64,
    /// Total bytes evicted.
    pub dropped_bytes: u64,
}

/// One chunk still counted against the ring's bounds. No payload, no hash —
/// just enough to know what to evict and how much room it frees.
struct LiveChunk {
    seq: u64,
    size: u64,
}

/// Prune-oldest admission control for a continuous stream capture. A pure
/// state machine — see the module docs for why it does no file I/O.
pub struct RingState {
    bounds: CaptureBounds,
    live: VecDeque<LiveChunk>,
    bytes: u64,
    next_seq: u64,
}

impl RingState {
    pub fn new(bounds: CaptureBounds) -> Self {
        Self {
            bounds,
            live: VecDeque::new(),
            bytes: 0,
            next_seq: 0,
        }
    }

    /// Admit one more chunk of `size` bytes. Evicts the oldest live chunks
    /// until `size` fits both bounds, then always admits it — including the
    /// case where `size` alone exceeds `max_bytes`, which empties the ring
    /// and is still accepted. The newest write always wins.
    pub fn admit(&mut self, size: u64) -> Admission {
        let mut pruned_seqs = Vec::new();
        let mut dropped_bytes = 0u64;
        while self.would_exceed_bounds(size) {
            let Some(oldest) = self.live.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(oldest.size);
            dropped_bytes = dropped_bytes.saturating_add(oldest.size);
            pruned_seqs.push(oldest.seq);
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.live.push_back(LiveChunk { seq, size });
        self.bytes = self.bytes.saturating_add(size);

        if pruned_seqs.is_empty() {
            Admission::Accept
        } else {
            Admission::AcceptAfterPruning {
                pruned_seqs,
                dropped_bytes,
            }
        }
    }

    /// Whether admitting one more `size`-byte chunk on top of the current
    /// live set would breach either bound. An empty ring never exceeds —
    /// there is nothing left to evict, so even an oversized chunk is admitted
    /// on its own.
    fn would_exceed_bounds(&self, size: u64) -> bool {
        !self.live.is_empty()
            && (self.bytes.saturating_add(size) > self.bounds.max_bytes
                || self.live.len() as u64 + 1 > self.bounds.max_chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(max_bytes: u64, max_chunks: u64) -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: 60,
            max_bytes,
            max_chunks,
        }
    }

    #[test]
    fn ring_accepts_until_the_byte_bound_is_reached() {
        let mut r = RingState::new(bounds(/* max_bytes */ 100, /* max_chunks */ 8));
        assert!(matches!(r.admit(60), Admission::Accept));
        assert!(matches!(r.admit(30), Admission::Accept));
    }

    #[test]
    fn ring_prunes_oldest_rather_than_refusing() {
        let mut r = RingState::new(bounds(100, 8));
        r.admit(60);
        r.admit(30);
        match r.admit(50) {
            Admission::AcceptAfterPruning {
                pruned_seqs,
                dropped_bytes,
            } => {
                assert_eq!(pruned_seqs, vec![0]);
                assert_eq!(dropped_bytes, 60);
            }
            other => panic!("expected pruning, got {other:?}"),
        }
    }

    #[test]
    fn a_chatty_workload_stays_observable_forever() {
        // The regression this whole task exists for: the store must never refuse.
        let mut r = RingState::new(bounds(10, 2));
        let mut newest_accepted = 0u64;
        for i in 0..50u64 {
            match r.admit(9) {
                Admission::Accept | Admission::AcceptAfterPruning { .. } => newest_accepted = i,
            }
        }
        assert_eq!(newest_accepted, 49, "the newest write must always win");
    }

    #[test]
    fn a_chunk_larger_than_the_whole_bound_is_still_accepted() {
        let mut r = RingState::new(bounds(100, 8));
        r.admit(60);
        match r.admit(500) {
            Admission::AcceptAfterPruning { pruned_seqs, .. } => assert_eq!(pruned_seqs, vec![0]),
            other => panic!("expected pruning, got {other:?}"),
        }
    }
}
