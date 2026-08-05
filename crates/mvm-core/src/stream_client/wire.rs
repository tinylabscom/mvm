//! The frame a broker sends a follower: one verifiable window of records.
//!
//! Framing is a 4-byte big-endian length prefix followed by JSON, matching
//! the host-services broker's convention so there is one framing to reason
//! about on this host. The length gate is checked *before* the parse, so a
//! bogus prefix cannot provoke an unbounded allocation.

use std::io::{self, Read, Write};

use mvm_contract::stream::StreamRecord;
use serde::{Deserialize, Serialize};

use crate::transcript::GapMarker;

/// Largest payload one [`StreamBatch`] carries. A broker splits a bigger
/// drain into consecutive batches rather than emitting one huge frame, so
/// this bounds a follower's per-frame allocation regardless of how far
/// behind it fell or how the producer's ring was sized.
///
/// A batch is cut *before* the record that would overflow it, so this is a
/// real ceiling and not a threshold the last record may cross. The one
/// exception is a record whose own payload is larger: a record is atomic —
/// the chain covers it whole — so it cannot be split, and it travels alone
/// in a batch of its own.
pub const MAX_BATCH_PAYLOAD_BYTES: usize = 256 * 1024;

/// Records one [`StreamBatch`] carries.
///
/// The companion bound to [`MAX_BATCH_PAYLOAD_BYTES`], and there for the
/// same reason a reader's ring has two: a workload writing a byte at a time
/// reaches the payload cap only after a quarter of a million records, whose
/// per-record JSON metadata would then dwarf the payload the cap is sized
/// for.
pub const MAX_BATCH_RECORDS: usize = 4 * 1024;

/// Largest single record the plane can frame.
///
/// A record cannot be split without breaking the chain, so a bigger one is
/// refused by the length gate in [`read_batch`] rather than truncated —
/// loudly, and with the cap named. Both producers read in 64 KiB chunks, so
/// this is four times the largest record either can emit.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = MAX_BATCH_PAYLOAD_BYTES;

/// Largest frame a reader accepts, checked against the declared length
/// before a body byte is read. Sized from the worst batch the split rules
/// permit, with the headroom asserted at compile time below.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// JSON bytes one record costs beyond its payload: the field names, three
/// integers, and `prev_hash` rendered as 32 decimal numbers. The worst case
/// measures 261; `a_worst_case_record_fits_its_modelled_overhead` pins that
/// against the real encoder rather than trusting this arithmetic.
const RECORD_JSON_OVERHEAD_BYTES: usize = 512;

/// JSON bytes one payload byte costs. `serde_json` renders a `Vec<u8>` as
/// decimal numbers, so `255,` — four characters — is the worst case.
const PAYLOAD_JSON_BYTES_PER_BYTE: usize = 4;

/// JSON bytes a batch costs beyond its records: the anchor array, the gap
/// marker, and the caught-up flag.
const BATCH_JSON_OVERHEAD_BYTES: usize = 512;

/// Largest a batch obeying the split rules can encode to.
///
/// Two payload terms, not one: a batch carries at most
/// [`MAX_BATCH_PAYLOAD_BYTES`] of payload, *or* one oversized record up to
/// [`MAX_RECORD_PAYLOAD_BYTES`] — summing both is the cheap way to bound
/// either without a `max` in const position.
const MAX_ENCODED_BATCH_BYTES: usize = BATCH_JSON_OVERHEAD_BYTES
    + MAX_BATCH_RECORDS * RECORD_JSON_OVERHEAD_BYTES
    + (MAX_BATCH_PAYLOAD_BYTES + MAX_RECORD_PAYLOAD_BYTES) * PAYLOAD_JSON_BYTES_PER_BYTE;

/// A legitimate batch has to fit the cap that guards against a hostile one.
/// If the two ever crossed, a full-size window would be refused as an attack
/// — so the relation is checked at compile time rather than left to whoever
/// next edits one of the numbers.
const _: () = assert!(MAX_ENCODED_BATCH_BYTES < MAX_FRAME_BYTES);

/// One window of a VM's output stream, plus everything needed to verify it.
///
/// `records` are consecutive and unfiltered — the broker never drops records
/// to honour a consumer's filter, because a hole in the middle of a window
/// breaks the hash chain. Filtering is the reader's job, after verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamBatch {
    /// Hash the first record chains from. For the first batch this is the
    /// broker's head when the follower attached; after a loss it is the hash
    /// of the last record the follower will never see.
    pub anchor: [u8; 32],
    /// The window, in sequence order. May be empty — an empty batch is how a
    /// broker says "nothing new" without closing the connection.
    pub records: Vec<StreamRecord>,
    /// What this follower has lost to retention so far, folded into one
    /// marker. Cumulative: a consumer detects new loss by the value changing.
    pub gap: Option<GapMarker>,
    /// Whether the follower's queue was empty after this batch was taken. A
    /// non-following consumer stops here.
    pub caught_up: bool,
}

impl StreamBatch {
    /// Total payload bytes in this batch. What [`MAX_BATCH_PAYLOAD_BYTES`]
    /// bounds; the JSON encoding is a multiple of this, not a different
    /// order of magnitude.
    pub fn payload_bytes(&self) -> usize {
        self.records.iter().map(|r| r.payload.len()).sum()
    }
}

/// Write one length-prefixed JSON batch.
pub fn write_batch<W: Write>(writer: &mut W, batch: &StreamBatch) -> io::Result<()> {
    let body = serde_json::to_vec(batch).map_err(io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(|_| {
        io::Error::other(format!(
            "stream batch of {} bytes is unframeable",
            body.len()
        ))
    })?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// Read one length-prefixed JSON batch, or `None` at a clean end of stream.
///
/// `max_bytes` is enforced against the declared length before a single body
/// byte is read, so a hostile or corrupted prefix costs nothing.
pub fn read_batch<R: Read>(reader: &mut R, max_bytes: usize) -> io::Result<Option<StreamBatch>> {
    let mut prefix = [0u8; 4];
    match reader.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len > max_bytes {
        return Err(io::Error::other(format!(
            "stream frame declares {len} bytes, cap is {max_bytes}"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::{StreamKind, StreamSource};

    fn record(seq: u64, payload: &[u8]) -> StreamRecord {
        StreamRecord {
            seq,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stdout,
            host_unix_nanos: 1_000 + seq,
            prev_hash: [0u8; 32],
            payload: payload.to_vec(),
        }
    }

    fn batch() -> StreamBatch {
        StreamBatch {
            anchor: [7u8; 32],
            records: vec![record(0, b"a"), record(1, b"bb")],
            gap: Some(GapMarker {
                after_seq: 4,
                dropped_chunks: 2,
                dropped_bytes: 30,
            }),
            caught_up: true,
        }
    }

    #[test]
    fn a_batch_round_trips_through_the_frame() {
        let mut buf = Vec::new();
        write_batch(&mut buf, &batch()).expect("write");
        let back = read_batch(&mut buf.as_slice(), 1 << 20)
            .expect("read")
            .expect("a frame");
        assert_eq!(back, batch());
    }

    #[test]
    fn consecutive_batches_read_back_in_order() {
        let mut buf = Vec::new();
        let first = batch();
        let mut second = batch();
        second.records = vec![record(2, b"c")];
        write_batch(&mut buf, &first).expect("write first");
        write_batch(&mut buf, &second).expect("write second");

        let mut cursor = buf.as_slice();
        assert_eq!(
            read_batch(&mut cursor, 1 << 20).expect("read").as_ref(),
            Some(&first)
        );
        assert_eq!(
            read_batch(&mut cursor, 1 << 20).expect("read").as_ref(),
            Some(&second)
        );
        assert_eq!(read_batch(&mut cursor, 1 << 20).expect("read"), None);
    }

    #[test]
    fn a_clean_end_of_stream_is_none_not_an_error() {
        let empty: &[u8] = &[];
        assert_eq!(read_batch(&mut { empty }, 1 << 20).expect("read"), None);
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_the_body_is_read() {
        // Only the 4-byte prefix exists: if the cap were checked after the
        // read this would fail as a short read instead of a cap breach.
        let framed = 1_000_000u32.to_be_bytes();
        let err = read_batch(&mut framed.as_slice(), 64).expect_err("must refuse");
        assert!(err.to_string().contains("cap is 64"), "{err}");
    }

    #[test]
    fn a_truncated_body_is_an_error_not_a_silent_short_batch() {
        let mut buf = Vec::new();
        write_batch(&mut buf, &batch()).expect("write");
        buf.truncate(buf.len() - 5);
        assert!(read_batch(&mut buf.as_slice(), 1 << 20).is_err());
    }

    #[test]
    fn payload_bytes_sums_the_window() {
        assert_eq!(batch().payload_bytes(), 3);
    }

    /// The per-record term in [`MAX_ENCODED_BATCH_BYTES`] is arithmetic about
    /// an encoder, so it is checked against the encoder. Worst case in every
    /// field: the widest integers and an all-`0xff` hash, which is what makes
    /// the number a bound rather than a guess.
    #[test]
    fn a_worst_case_record_fits_its_modelled_overhead() {
        let payload = vec![0xffu8; 1024];
        let record = StreamRecord {
            seq: u64::MAX,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stderr,
            host_unix_nanos: u64::MAX,
            prev_hash: [0xff; 32],
            payload: payload.clone(),
        };
        let encoded = serde_json::to_vec(&record).expect("encode").len();
        let modelled = RECORD_JSON_OVERHEAD_BYTES + payload.len() * PAYLOAD_JSON_BYTES_PER_BYTE;
        assert!(encoded <= modelled, "{encoded} exceeds modelled {modelled}");
    }

    /// The whole relation, against the encoder rather than against the
    /// arithmetic: a batch at both split limits must frame inside the cap the
    /// reading side refuses beyond.
    #[test]
    fn a_batch_at_both_split_limits_frames_inside_the_cap() {
        // Byte-sized writes: the case the record bound exists for, and the
        // one where per-record metadata dominates.
        let mut records: Vec<StreamRecord> = (0..MAX_BATCH_RECORDS as u64)
            .map(|seq| record(seq, &[0xff]))
            .collect();
        // Plus the one record a cut cannot help with, at its own ceiling.
        records.push(record(
            MAX_BATCH_RECORDS as u64,
            &vec![0xffu8; MAX_RECORD_PAYLOAD_BYTES],
        ));
        let oversized = StreamBatch {
            anchor: [0xff; 32],
            records,
            gap: Some(GapMarker {
                after_seq: u64::MAX,
                dropped_chunks: u64::MAX,
                dropped_bytes: u64::MAX,
            }),
            caught_up: true,
        };

        let mut framed = Vec::new();
        write_batch(&mut framed, &oversized).expect("write");
        assert!(
            framed.len() <= MAX_ENCODED_BATCH_BYTES,
            "{} exceeds the modelled {MAX_ENCODED_BATCH_BYTES}",
            framed.len()
        );
        read_batch(&mut framed.as_slice(), MAX_FRAME_BYTES)
            .expect("a batch at the split limits must not read as hostile")
            .expect("a frame");
    }
}
