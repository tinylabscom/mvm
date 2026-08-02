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

/// Running record of what one stream's ring evicted, folded into the single
/// [`GapMarker`] that stream reports.
///
/// A consumer needs to know output was lost and where the surviving window
/// starts, not the eviction history that got it there — so many admissions
/// collapse into one marker rather than a list.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GapTally {
    marker: Option<GapMarker>,
}

impl GapTally {
    /// Fold one admission's evictions in. [`Admission::Accept`] is a no-op, so
    /// every admission can be handed here without the caller branching.
    pub fn record(&mut self, admission: &Admission) {
        let Admission::AcceptAfterPruning {
            pruned_seqs,
            dropped_bytes,
        } = admission
        else {
            return;
        };
        let Some(&after_seq) = pruned_seqs.last() else {
            return;
        };
        let dropped_chunks = pruned_seqs.len() as u64;
        self.marker = Some(match self.marker {
            Some(prev) => GapMarker {
                after_seq,
                dropped_chunks: prev.dropped_chunks.saturating_add(dropped_chunks),
                dropped_bytes: prev.dropped_bytes.saturating_add(*dropped_bytes),
            },
            None => GapMarker {
                after_seq,
                dropped_chunks,
                dropped_bytes: *dropped_bytes,
            },
        });
    }

    /// The one marker for this stream, or `None` when nothing was evicted.
    pub fn marker(&self) -> Option<GapMarker> {
        self.marker
    }
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

    /// Stop counting the oldest live chunk because the store handed it on
    /// rather than evicting it. Returns its sequence number, or `None` when
    /// nothing is live.
    ///
    /// The counterpart to eviction, for a store that drains from the front as
    /// well as pruning from it: without it the ring keeps charging for chunks
    /// the store no longer holds, and evicts live ones to make room that is
    /// already free. A released chunk is not a gap — it was delivered.
    pub fn release_oldest(&mut self) -> Option<u64> {
        let oldest = self.live.pop_front()?;
        self.bytes = self.bytes.saturating_sub(oldest.size);
        Some(oldest.seq)
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
    fn releasing_the_oldest_frees_its_bytes_for_the_next_admission() {
        // A delivered chunk must stop counting, or a queue that drains from
        // the front would evict live chunks to make room that is already free.
        let mut r = RingState::new(bounds(100, 8));
        r.admit(60);
        r.admit(30);
        assert_eq!(r.release_oldest(), Some(0));
        assert!(
            matches!(r.admit(50), Admission::Accept),
            "the released 60 bytes must be available again"
        );
    }

    #[test]
    fn releasing_an_empty_ring_reports_nothing() {
        let mut r = RingState::new(bounds(100, 8));
        assert_eq!(r.release_oldest(), None);
    }

    #[test]
    fn a_tally_folds_many_evictions_into_one_marker() {
        let mut r = RingState::new(bounds(10, 8));
        let mut tally = GapTally::default();
        for _ in 0..4 {
            tally.record(&r.admit(4));
        }
        // 4-byte chunks against a 10-byte bound: two fit, then each new one
        // evicts exactly one. Chunks 0 and 1 go as 2 and 3 arrive, and the
        // two evictions collapse into a single marker.
        assert_eq!(
            tally.marker(),
            Some(GapMarker {
                after_seq: 1,
                dropped_chunks: 2,
                dropped_bytes: 8,
            })
        );
    }

    #[test]
    fn a_tally_that_never_evicted_reports_no_marker() {
        let mut r = RingState::new(bounds(100, 8));
        let mut tally = GapTally::default();
        tally.record(&r.admit(10));
        assert_eq!(tally.marker(), None);
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
