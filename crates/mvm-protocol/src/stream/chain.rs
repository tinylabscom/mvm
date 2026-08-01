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

/// Why [`verify_chain`] rejected a sequence of [`StreamRecord`]s.
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
    /// predecessor's [`StreamRecord::hash`], or all-zero for the first
    /// record.
    #[error("hash mismatch at seq {seq}")]
    HashMismatch {
        /// The `seq` of the record whose `prev_hash` did not match.
        seq: u64,
    },
    /// The chain had no records to verify.
    #[error("stream chain is empty")]
    Empty,
}

/// Verify `records` form one unbroken hash chain.
///
/// Requires the first record's `prev_hash` to be all-zero (the genesis
/// marker), every later record's `seq` to be exactly one more than its
/// predecessor's, and every later record's `prev_hash` to equal
/// [`StreamRecord::hash`] of its predecessor. A dropped, reordered, or
/// tampered record breaks one of these and is rejected; an empty slice is
/// rejected as [`ChainError::Empty`] rather than vacuously accepted.
pub fn verify_chain(records: &[StreamRecord]) -> Result<(), ChainError> {
    let first = records.first().ok_or(ChainError::Empty)?;
    if first.prev_hash != [0u8; 32] {
        return Err(ChainError::HashMismatch { seq: first.seq });
    }
    for pair in records.windows(2) {
        let (prev, cur) = (&pair[0], &pair[1]);
        // `wrapping_add`, not `+`: a chain can never realistically reach
        // `u64::MAX` records, but wrapping keeps this fail-closed instead
        // of panicking if it somehow did — the wrapped value still cannot
        // equal a real `cur.seq`, so the comparison below still rejects.
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
}
