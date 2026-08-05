//! Chain verification for [`StreamRecord`] sequences.

use super::record::StreamRecord;

// `StreamKind`/`StreamSource` and `Vec` are only named by the test helper
// below, which reaches them through `use super::*;` — cfg-gating the
// imports here keeps a non-test build (the wasm-clean lib target) free of
// an unused-import warning.
#[cfg(test)]
use super::record::{StreamKind, StreamSource};
#[cfg(test)]
use alloc::vec::Vec;

/// Why [`verify_chain`] or [`verify_chain_from`] rejected a sequence of
/// [`StreamRecord`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// A record's `seq` was not its predecessor's `seq` plus one.
    #[error("expected seq {expected}, got {got}")]
    SeqGap {
        /// The `seq` the chain required next.
        expected: u64,
        /// The `seq` the offending record actually carried.
        got: u64,
    },
    /// A record's `prev_hash` did not match the expected hash: the
    /// predecessor's [`StreamRecord::hash`], or the anchor for the first
    /// record (all-zero under [`verify_chain`], caller-supplied under
    /// [`verify_chain_from`]).
    #[error("hash mismatch at seq {seq}")]
    HashMismatch {
        /// The `seq` of the record whose `prev_hash` did not match.
        seq: u64,
    },
    /// The chain had no records to verify.
    #[error("stream chain is empty")]
    Empty,
}

/// Verify `records` form one unbroken hash chain anchored at `anchor`.
///
/// Requires the first record's `prev_hash` to equal `anchor`, every later
/// record's `seq` to be exactly one more than its predecessor's, and every
/// later record's `prev_hash` to equal [`StreamRecord::hash`] of its
/// predecessor. A dropped, reordered, or tampered record breaks one of
/// these and is rejected; an empty slice is rejected as
/// [`ChainError::Empty`] rather than vacuously accepted.
///
/// # Scope: self-consistency, not provenance
///
/// A successful result proves only that `records` is unbroken *from*
/// `anchor` onward — the same "half a membership check" posture
/// [`crate::merkle::InclusionProof`] documents for its own embedded root.
/// It does not prove `anchor` itself is authentic, or that `records` is
/// the true start of the underlying stream: a caller holding a pruned or
/// partially-fetched window (the oldest records evicted by retention, or
/// simply not yet fetched) is expected to have obtained `anchor` from a
/// source it already trusts — typically the hash of the last record it
/// verified in an earlier call. Binding that trust is the caller's job;
/// this function only checks the window is unbroken from the anchor it
/// was given. See [`verify_chain`] for the genesis-anchored case, which
/// additionally claims to be the whole stream from its true beginning.
pub fn verify_chain_from(records: &[StreamRecord], anchor: [u8; 32]) -> Result<(), ChainError> {
    let first = records.first().ok_or(ChainError::Empty)?;
    if first.prev_hash != anchor {
        return Err(ChainError::HashMismatch { seq: first.seq });
    }
    for pair in records.windows(2) {
        let (prev, cur) = (&pair[0], &pair[1]);
        // `wrapping_add`, not `+`, to avoid an overflow panic if `prev.seq`
        // were ever `u64::MAX`. That specific wraparound (`u64::MAX` to
        // `0`) would make `expected` collide with a legitimate
        // `cur.seq == 0` and wrongly *pass* rather than reject — this is
        // not cryptographically prevented, only practically unreachable:
        // it requires one chain to grow past 2^64 records, which no real
        // stream ever will.
        let expected = prev.seq.wrapping_add(1);
        if cur.seq != expected {
            return Err(ChainError::SeqGap {
                expected,
                got: cur.seq,
            });
        }
        if cur.prev_hash != prev.hash() {
            return Err(ChainError::HashMismatch { seq: cur.seq });
        }
    }
    Ok(())
}

/// Verify `records` form one unbroken hash chain from genesis.
///
/// Equivalent to [`verify_chain_from`] with an all-zero anchor — this
/// crate's convention for "no predecessor." Because genesis is fixed at
/// all-zero rather than caller-supplied, success here additionally claims
/// `records` is the whole stream from its true beginning, not merely some
/// internally consistent window of it: a pruned or mid-stream slice whose
/// first `prev_hash` is a real predecessor's hash (not zero) is rejected
/// here even though [`verify_chain_from`] would accept that identical
/// slice against that predecessor's hash as the anchor.
pub fn verify_chain(records: &[StreamRecord]) -> Result<(), ChainError> {
    verify_chain_from(records, [0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn chained(n: u64) -> Vec<StreamRecord> {
        let mut out: Vec<StreamRecord> = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: vec![b'a' + seq as u8],
            };
            prev = r.hash();
            out.push(r);
        }
        out
    }

    #[test]
    fn verify_chain_accepts_a_well_formed_chain() {
        assert!(verify_chain(&chained(4)).is_ok());
    }

    #[test]
    fn verify_chain_rejects_a_tampered_payload() {
        let mut rs = chained(4);
        rs[2].payload = vec![b'z'];
        assert!(matches!(
            verify_chain(&rs),
            Err(ChainError::HashMismatch { seq: 3 })
        ));
    }

    #[test]
    fn verify_chain_rejects_a_dropped_record() {
        let mut rs = chained(4);
        rs.remove(2);
        assert!(matches!(verify_chain(&rs), Err(ChainError::SeqGap { .. })));
    }

    #[test]
    fn verify_chain_rejects_reordered_records() {
        let mut rs = chained(4);
        rs.swap(1, 2);
        assert!(verify_chain(&rs).is_err());
    }

    // --- coverage beyond the four required cases above ------------------

    #[test]
    fn verify_chain_rejects_an_empty_chain() {
        let empty: Vec<StreamRecord> = Vec::new();
        assert!(matches!(verify_chain(&empty), Err(ChainError::Empty)));
    }

    #[test]
    fn verify_chain_rejects_a_non_zero_genesis_prev_hash() {
        let mut rs = chained(4);
        rs[0].prev_hash = [7u8; 32];
        assert!(matches!(
            verify_chain(&rs),
            Err(ChainError::HashMismatch { seq: 0 })
        ));
    }

    #[test]
    fn verify_chain_accepts_a_single_record_genesis_chain() {
        assert!(verify_chain(&chained(1)).is_ok());
    }

    // --- anchored verification (verify_chain_from) -----------------------
    //
    // Exercises the ring-retention / resume-from-seq shape: a caller only
    // holds a window of a longer chain (the oldest records were pruned or
    // never fetched) and verifies it against the hash of the record that
    // used to precede it.

    #[test]
    fn verify_chain_from_accepts_a_pruned_window_anchored_at_its_true_predecessor() {
        let full = chained(10);
        let anchor = full[4].hash();
        let window = &full[5..10];
        assert!(verify_chain_from(window, anchor).is_ok());
    }

    #[test]
    fn verify_chain_from_rejects_the_same_window_against_a_wrong_anchor() {
        let full = chained(10);
        let window = &full[5..10];
        assert!(matches!(
            verify_chain_from(window, [9u8; 32]),
            Err(ChainError::HashMismatch { seq: 5 })
        ));
    }

    #[test]
    fn verify_chain_still_rejects_a_pruned_window_even_though_internally_consistent() {
        let full = chained(10);
        let window = &full[5..10];
        assert!(matches!(
            verify_chain(window),
            Err(ChainError::HashMismatch { seq: 5 })
        ));
    }
}
