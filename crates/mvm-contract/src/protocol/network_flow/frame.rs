//! Outer framing for the FlowMux protocol.
//!
//! A frame is a big-endian `u32` byte count followed by that many bytes: a
//! 20-byte fixed header and then the payload. Nothing here is
//! self-describing and nothing allocates before the length has been checked
//! against [`MAX_FRAME_LEN`], which is the whole point — the bytes arrive
//! from a guest that controls all of them.
//!
//! ```text
//! u32 frame_length_be   bytes that follow: header_len + payload_len
//! ├─ magic       [u8;4]  b"MVFM"
//! ├─ version     u8
//! ├─ opcode      u8
//! ├─ flags       u16 be   reserved in v1, must be zero
//! ├─ header_len  u16 be   20 in v1
//! ├─ reserved    u16 be   must be zero
//! ├─ stream_id   u32 be   zero only on a session frame
//! └─ payload_len u32 be   must equal frame_length - header_len
//! payload        [u8; payload_len]
//! ```
//!
//! Decoding is **state-independent**: it answers "is this a well-formed v1
//! frame" and nothing else. Whether the frame is legal *right now* for the
//! stream it names is [`super::state`]'s question. Keeping the two apart is
//! what lets the decoder be fuzzed without a session and lets the state
//! machine be fuzzed without bytes.

use alloc::vec::Vec;

use super::limits::{
    HEADER_LEN, LENGTH_PREFIX_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION,
};
use super::opcode::Opcode;

/// Frame magic. Distinctive enough that a stream desync shows up as a
/// rejection rather than a plausible-looking header.
pub const MAGIC: [u8; 4] = *b"MVFM";

/// The stream ID session frames ride on. No flow may claim it.
pub const SESSION_STREAM_ID: u32 = 0;

/// Which end of the session a frame came from.
///
/// Not carried on the wire — each end knows which socket it read from, and
/// a peer-supplied direction would be a peer-supplied authorization input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Sent by the guest, read by the host.
    GuestToHost,
    /// Sent by the host, read by the guest.
    HostToGuest,
}

impl Direction {
    /// The other side.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::GuestToHost => Self::HostToGuest,
            Self::HostToGuest => Self::GuestToHost,
        }
    }
}

/// Why a frame was refused.
///
/// Every variant except [`FrameError::Incomplete`] is fatal to the
/// connection: the framing is a fixed-layout binary contract, so a
/// disagreement about it means the two ends no longer agree where frames
/// begin, and there is no resynchronization story that is not also an
/// attacker's resynchronization story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Not enough bytes yet for the length prefix or the announced frame.
    /// The only non-fatal variant: the caller reads more and retries.
    #[error("frame incomplete: need {needed} bytes, have {have}")]
    Incomplete { needed: usize, have: usize },
    /// Announced length exceeds [`MAX_FRAME_LEN`]. Rejected before any
    /// allocation is attempted.
    #[error("frame length {len} exceeds maximum {max}")]
    TooLong { len: usize, max: usize },
    /// Announced length cannot even hold a header.
    #[error("frame length {len} is below the {min}-byte header")]
    TooShort { len: usize, min: usize },
    /// Leading four bytes were not [`MAGIC`].
    #[error("bad magic")]
    BadMagic,
    /// Major version mismatch. Never negotiated down.
    #[error("unsupported protocol version {got} (this build speaks {want})")]
    UnsupportedVersion { got: u8, want: u8 },
    /// `opcode` was not a known discriminant.
    #[error("unknown opcode {0:#04x}")]
    UnknownOpcode(u8),
    /// `header_len` was not the version's header size.
    #[error("invalid header length {0}")]
    InvalidHeaderLen(u16),
    /// A field reserved in this version carried a non-zero value. Rejected
    /// so the field can be given a meaning later without ambiguity.
    #[error("reserved field {field} must be zero in version {PROTOCOL_VERSION}")]
    ReservedNonZero { field: &'static str },
    /// `payload_len` disagreed with `frame_length - header_len`.
    #[error("payload length {declared} inconsistent with frame length (expected {expected})")]
    InconsistentLength { declared: u64, expected: usize },
    /// Payload exceeded [`MAX_PAYLOAD_LEN`].
    #[error("payload length {len} exceeds maximum {max}")]
    PayloadTooLong { len: u64, max: usize },
    /// A flow frame named stream 0, which belongs to the session.
    #[error("opcode {opcode:#04x} is a flow frame and may not use stream 0")]
    FlowOnSessionStream { opcode: u8 },
    /// A session frame named a stream other than 0.
    #[error("session opcode {opcode:#04x} may only use stream 0, not {stream_id}")]
    SessionOffStreamZero { opcode: u8, stream_id: u32 },
    /// Encoding was asked to emit a payload larger than the protocol
    /// permits.
    #[error("cannot encode payload of {len} bytes (maximum {max})")]
    EncodeTooLong { len: usize, max: usize },
}

impl FrameError {
    /// Whether the caller should read more bytes and retry, as opposed to
    /// dropping the connection.
    #[must_use]
    pub const fn is_incomplete(self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

/// The fixed header, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol major. Always [`PROTOCOL_VERSION`] on a decoded frame.
    pub version: u8,
    /// What the frame does.
    pub opcode: Opcode,
    /// Reserved in v1; always zero on a decoded frame.
    pub flags: u16,
    /// The stream this frame belongs to. Zero exactly for session frames.
    pub stream_id: u32,
    /// Payload byte count. Always at most [`MAX_PAYLOAD_LEN`].
    pub payload_len: u32,
}

impl FrameHeader {
    /// A v1 header for `opcode` on `stream_id`.
    ///
    /// # Errors
    ///
    /// Refuses a payload past [`MAX_PAYLOAD_LEN`], and refuses a stream ID
    /// that contradicts the opcode's class — the same two checks the decoder
    /// applies, so a header this constructor produces always decodes.
    pub fn new(opcode: Opcode, stream_id: u32, payload_len: usize) -> Result<Self, FrameError> {
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FrameError::EncodeTooLong {
                len: payload_len,
                max: MAX_PAYLOAD_LEN,
            });
        }
        check_stream_id_for(opcode, stream_id)?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            opcode,
            flags: 0,
            stream_id,
            // Checked immediately above.
            payload_len: payload_len as u32,
        })
    }
}

/// Refuse a stream ID that contradicts the opcode's class.
///
/// Stream 0 is the session's and no flow may claim it; conversely a session
/// opcode on a flow stream would make "which state machine owns this frame"
/// ambiguous. Both directions are checked so neither can be used to smuggle
/// a frame into the wrong machine.
fn check_stream_id_for(opcode: Opcode, stream_id: u32) -> Result<(), FrameError> {
    match (opcode.is_session(), stream_id == SESSION_STREAM_ID) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(FrameError::SessionOffStreamZero {
            opcode: opcode.as_u8(),
            stream_id,
        }),
        (false, true) => Err(FrameError::FlowOnSessionStream {
            opcode: opcode.as_u8(),
        }),
    }
}

/// A parsed frame: its header plus the byte range of its payload inside the
/// caller's buffer. Borrowing rather than copying keeps the steady state
/// free of per-frame allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    /// The decoded fixed header.
    pub header: FrameHeader,
    /// The payload, borrowed from the caller's buffer.
    pub payload: &'a [u8],
    /// Total bytes this frame occupied, prefix included. The caller advances
    /// its buffer by exactly this.
    pub consumed: usize,
}

/// Read the announced frame length without consuming it.
///
/// Separated from [`decode`] so a reader can size — or refuse — its read
/// before it has the body. That is the point at which an oversized frame
/// must die: before anything is allocated for it.
///
/// # Errors
///
/// [`FrameError::Incomplete`] when fewer than four bytes are available, and
/// [`FrameError::TooLong`] / [`FrameError::TooShort`] for a length outside
/// the version's bounds.
pub fn peek_frame_len(buf: &[u8]) -> Result<usize, FrameError> {
    let Some(prefix) = buf.get(..LENGTH_PREFIX_LEN) else {
        return Err(FrameError::Incomplete {
            needed: LENGTH_PREFIX_LEN,
            have: buf.len(),
        });
    };
    // A u32 read as usize is lossless on every target we build for, but
    // `try_into` rather than `as` keeps that a compile-time fact rather
    // than an assumption a 16-bit target would silently break.
    let announced = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    let Ok(len) = usize::try_from(announced) else {
        return Err(FrameError::TooLong {
            len: MAX_FRAME_LEN.saturating_add(1),
            max: MAX_FRAME_LEN,
        });
    };
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLong {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    if len < HEADER_LEN {
        return Err(FrameError::TooShort {
            len,
            min: HEADER_LEN,
        });
    }
    Ok(len)
}

/// Decode one frame from the front of `buf`.
///
/// Fails closed on every inconsistency. Returns [`FrameError::Incomplete`] —
/// and only that — when the caller simply needs to read more; every other
/// error means the connection is unusable and must be dropped.
///
/// # Errors
///
/// See [`FrameError`]. Every check runs before the payload is borrowed, so
/// a rejected frame never causes an allocation proportional to its claims.
pub fn decode(buf: &[u8]) -> Result<ParsedFrame<'_>, FrameError> {
    let frame_len = peek_frame_len(buf)?;
    let total = LENGTH_PREFIX_LEN + frame_len;
    let Some(frame) = buf.get(LENGTH_PREFIX_LEN..total) else {
        return Err(FrameError::Incomplete {
            needed: total,
            have: buf.len(),
        });
    };

    if frame[0..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = frame[4];
    if version != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion {
            got: version,
            want: PROTOCOL_VERSION,
        });
    }
    let opcode = Opcode::from_u8(frame[5]).ok_or(FrameError::UnknownOpcode(frame[5]))?;

    let flags = u16::from_be_bytes([frame[6], frame[7]]);
    if flags != 0 {
        return Err(FrameError::ReservedNonZero { field: "flags" });
    }
    let header_len = u16::from_be_bytes([frame[8], frame[9]]);
    if usize::from(header_len) != HEADER_LEN {
        return Err(FrameError::InvalidHeaderLen(header_len));
    }
    let reserved = u16::from_be_bytes([frame[10], frame[11]]);
    if reserved != 0 {
        return Err(FrameError::ReservedNonZero { field: "reserved" });
    }
    let stream_id = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
    let payload_len = u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]);

    // The payload cap is checked against the *declared* field before the
    // consistency check, so an oversized claim is reported as oversized
    // rather than as a length disagreement.
    if u64::from(payload_len) > MAX_PAYLOAD_LEN as u64 {
        return Err(FrameError::PayloadTooLong {
            len: u64::from(payload_len),
            max: MAX_PAYLOAD_LEN,
        });
    }
    let expected = frame_len - HEADER_LEN;
    if !usize::try_from(payload_len).is_ok_and(|n| n == expected) {
        return Err(FrameError::InconsistentLength {
            declared: u64::from(payload_len),
            expected,
        });
    }

    check_stream_id_for(opcode, stream_id)?;

    Ok(ParsedFrame {
        header: FrameHeader {
            version,
            opcode,
            flags,
            stream_id,
            payload_len,
        },
        payload: &frame[HEADER_LEN..],
        consumed: total,
    })
}

/// Serialize a frame into `out`, appending to whatever is already there.
///
/// `out` is a caller-owned buffer so the hot path can reuse one allocation
/// per connection instead of minting a `Vec` per frame.
///
/// # Errors
///
/// [`FrameError::EncodeTooLong`] for an oversized payload, and the stream-ID
/// class errors for an opcode/stream mismatch — the encoder refuses to emit
/// a frame its own decoder would reject.
pub fn encode_into(
    out: &mut Vec<u8>,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), FrameError> {
    let header = FrameHeader::new(opcode, stream_id, payload.len())?;
    let frame_len = HEADER_LEN + payload.len();

    out.reserve(LENGTH_PREFIX_LEN + frame_len);
    // `frame_len` is bounded by MAX_FRAME_LEN, checked in `new` above.
    out.extend_from_slice(&(frame_len as u32).to_be_bytes());
    out.extend_from_slice(&MAGIC);
    out.push(header.version);
    out.push(header.opcode.as_u8());
    out.extend_from_slice(&header.flags.to_be_bytes());
    out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&header.stream_id.to_be_bytes());
    out.extend_from_slice(&header.payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Serialize one frame into a fresh buffer.
///
/// Convenience for tests and cold paths; the hot path uses
/// [`encode_into`] with a reused buffer.
///
/// # Errors
///
/// Same as [`encode_into`].
pub fn encode(opcode: Opcode, stream_id: u32, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + HEADER_LEN + payload.len());
    encode_into(&mut out, opcode, stream_id, payload)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A stream ID legal for `opcode`: 0 for session frames, an odd
    /// guest-initiated ID otherwise.
    fn stream_for(opcode: Opcode) -> u32 {
        if opcode.is_session() { 0 } else { 7 }
    }

    #[test]
    fn every_opcode_round_trips_with_an_empty_payload() {
        for op in Opcode::ALL {
            let bytes = encode(*op, stream_for(*op), &[]).expect("encode");
            let parsed = decode(&bytes).expect("decode");
            assert_eq!(parsed.header.opcode, *op);
            assert_eq!(parsed.header.stream_id, stream_for(*op));
            assert_eq!(parsed.header.payload_len, 0);
            assert!(parsed.payload.is_empty());
            assert_eq!(parsed.consumed, bytes.len());
        }
    }

    #[test]
    fn every_opcode_round_trips_with_a_payload() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for op in Opcode::ALL {
            let bytes = encode(*op, stream_for(*op), &payload).expect("encode");
            let parsed = decode(&bytes).expect("decode");
            assert_eq!(parsed.payload, &payload[..], "{op:?}");
            assert_eq!(parsed.header.payload_len as usize, payload.len());
        }
    }

    #[test]
    fn a_maximal_payload_round_trips() {
        let payload = vec![0xabu8; MAX_PAYLOAD_LEN];
        let bytes = encode(Opcode::Data, 1, &payload).expect("encode");
        assert_eq!(
            bytes.len(),
            LENGTH_PREFIX_LEN + HEADER_LEN + MAX_PAYLOAD_LEN
        );
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed.payload.len(), MAX_PAYLOAD_LEN);
    }

    #[test]
    fn a_header_default_has_zeroed_reserved_fields() {
        let h = FrameHeader::new(Opcode::Data, 1, 0).expect("header");
        assert_eq!(h.version, PROTOCOL_VERSION);
        assert_eq!(h.flags, 0);
        assert_eq!(h.payload_len, 0);
    }

    #[test]
    fn encoding_refuses_a_payload_past_the_cap() {
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            encode(Opcode::Data, 1, &payload),
            Err(FrameError::EncodeTooLong {
                len: MAX_PAYLOAD_LEN + 1,
                max: MAX_PAYLOAD_LEN
            })
        );
    }

    #[test]
    fn a_truncated_prefix_is_incomplete_not_fatal() {
        for n in 0..LENGTH_PREFIX_LEN {
            let err = decode(&vec![0u8; n]).unwrap_err();
            assert!(err.is_incomplete(), "{n} bytes: {err:?}");
        }
    }

    #[test]
    fn a_truncated_body_is_incomplete_not_fatal() {
        let bytes = encode(Opcode::Data, 1, b"hello").expect("encode");
        for n in LENGTH_PREFIX_LEN..bytes.len() {
            let err = decode(&bytes[..n]).unwrap_err();
            assert!(err.is_incomplete(), "{n} bytes: {err:?}");
        }
        assert!(decode(&bytes).is_ok());
    }

    /// The cap is enforced from the length prefix alone, before the body is
    /// read — so an oversized claim never sizes an allocation.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_the_body_arrives() {
        let mut buf = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec();
        assert_eq!(
            peek_frame_len(&buf),
            Err(FrameError::TooLong {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );
        assert_eq!(
            decode(&buf),
            Err(FrameError::TooLong {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );
        // Still refused with a full-looking buffer behind it.
        buf.extend_from_slice(&[0u8; 64]);
        assert!(matches!(decode(&buf), Err(FrameError::TooLong { .. })));
    }

    #[test]
    fn a_u32_max_length_prefix_is_refused() {
        let buf = u32::MAX.to_be_bytes().to_vec();
        assert!(matches!(
            peek_frame_len(&buf),
            Err(FrameError::TooLong { .. })
        ));
    }

    #[test]
    fn a_length_below_the_header_is_refused() {
        for len in 0..HEADER_LEN {
            let buf = (len as u32).to_be_bytes().to_vec();
            assert_eq!(
                peek_frame_len(&buf),
                Err(FrameError::TooShort {
                    len,
                    min: HEADER_LEN
                })
            );
        }
    }

    #[test]
    fn bad_magic_is_refused() {
        let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
        bytes[LENGTH_PREFIX_LEN] ^= 0xff;
        assert_eq!(decode(&bytes), Err(FrameError::BadMagic));
    }

    #[test]
    fn an_unknown_version_is_refused_and_never_negotiated_down() {
        for v in [0u8, 2, 0xff] {
            let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
            bytes[LENGTH_PREFIX_LEN + 4] = v;
            assert_eq!(
                decode(&bytes),
                Err(FrameError::UnsupportedVersion {
                    got: v,
                    want: PROTOCOL_VERSION
                })
            );
        }
    }

    #[test]
    fn an_unknown_opcode_is_refused() {
        for v in [0x00u8, 0x04, 0x18, 0x56, 0xff] {
            let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
            bytes[LENGTH_PREFIX_LEN + 5] = v;
            assert_eq!(decode(&bytes), Err(FrameError::UnknownOpcode(v)));
        }
    }

    #[test]
    fn a_nonzero_reserved_flag_is_refused() {
        for bit in 0..16u32 {
            let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
            let v = (1u16 << bit).to_be_bytes();
            bytes[LENGTH_PREFIX_LEN + 6] = v[0];
            bytes[LENGTH_PREFIX_LEN + 7] = v[1];
            assert_eq!(
                decode(&bytes),
                Err(FrameError::ReservedNonZero { field: "flags" }),
                "flag bit {bit}"
            );
        }
    }

    #[test]
    fn a_nonzero_reserved_word_is_refused() {
        let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
        bytes[LENGTH_PREFIX_LEN + 11] = 1;
        assert_eq!(
            decode(&bytes),
            Err(FrameError::ReservedNonZero { field: "reserved" })
        );
    }

    #[test]
    fn a_wrong_header_length_is_refused() {
        for hl in [0u16, 19, 21, 0xffff] {
            let mut bytes = encode(Opcode::Data, 1, b"x").expect("encode");
            let v = hl.to_be_bytes();
            bytes[LENGTH_PREFIX_LEN + 8] = v[0];
            bytes[LENGTH_PREFIX_LEN + 9] = v[1];
            assert_eq!(decode(&bytes), Err(FrameError::InvalidHeaderLen(hl)));
        }
    }

    /// A payload length that disagrees with the frame length is the classic
    /// smuggling primitive; it has to be a hard failure, not a truncation.
    #[test]
    fn a_payload_length_that_disagrees_with_the_frame_length_is_refused() {
        let mut bytes = encode(Opcode::Data, 1, b"hello").expect("encode");
        let v = 4u32.to_be_bytes();
        bytes[LENGTH_PREFIX_LEN + 16..LENGTH_PREFIX_LEN + 20].copy_from_slice(&v);
        assert_eq!(
            decode(&bytes),
            Err(FrameError::InconsistentLength {
                declared: 4,
                expected: 5
            })
        );
    }

    #[test]
    fn a_declared_payload_length_past_the_cap_is_refused_as_oversized() {
        let mut bytes = encode(Opcode::Data, 1, b"hello").expect("encode");
        let v = (MAX_PAYLOAD_LEN as u32 + 1).to_be_bytes();
        bytes[LENGTH_PREFIX_LEN + 16..LENGTH_PREFIX_LEN + 20].copy_from_slice(&v);
        assert_eq!(
            decode(&bytes),
            Err(FrameError::PayloadTooLong {
                len: MAX_PAYLOAD_LEN as u64 + 1,
                max: MAX_PAYLOAD_LEN
            })
        );
    }

    #[test]
    fn a_flow_frame_may_not_claim_stream_zero() {
        for op in Opcode::ALL.iter().filter(|o| !o.is_session()) {
            assert_eq!(
                FrameHeader::new(*op, 0, 0),
                Err(FrameError::FlowOnSessionStream { opcode: op.as_u8() }),
                "{op:?}"
            );
            // And on the wire, not only through the constructor.
            let mut bytes = encode(*op, 9, b"x").expect("encode");
            bytes[LENGTH_PREFIX_LEN + 12..LENGTH_PREFIX_LEN + 16]
                .copy_from_slice(&0u32.to_be_bytes());
            assert_eq!(
                decode(&bytes),
                Err(FrameError::FlowOnSessionStream { opcode: op.as_u8() }),
                "{op:?}"
            );
        }
    }

    #[test]
    fn a_session_frame_may_not_claim_a_flow_stream() {
        for op in Opcode::ALL.iter().filter(|o| o.is_session()) {
            assert_eq!(
                FrameHeader::new(*op, 1, 0),
                Err(FrameError::SessionOffStreamZero {
                    opcode: op.as_u8(),
                    stream_id: 1
                }),
                "{op:?}"
            );
            let mut bytes = encode(*op, 0, b"x").expect("encode");
            bytes[LENGTH_PREFIX_LEN + 12..LENGTH_PREFIX_LEN + 16]
                .copy_from_slice(&5u32.to_be_bytes());
            assert_eq!(
                decode(&bytes),
                Err(FrameError::SessionOffStreamZero {
                    opcode: op.as_u8(),
                    stream_id: 5
                }),
                "{op:?}"
            );
        }
    }

    #[test]
    fn frames_decode_back_to_back_from_one_buffer() {
        let mut buf = Vec::new();
        encode_into(&mut buf, Opcode::OpenTcp, 1, b"a").expect("encode");
        encode_into(&mut buf, Opcode::Data, 1, b"bb").expect("encode");
        encode_into(&mut buf, Opcode::GoAway, 0, b"ccc").expect("encode");

        let mut rest = &buf[..];
        for (op, payload) in [
            (Opcode::OpenTcp, &b"a"[..]),
            (Opcode::Data, &b"bb"[..]),
            (Opcode::GoAway, &b"ccc"[..]),
        ] {
            let parsed = decode(rest).expect("decode");
            assert_eq!(parsed.header.opcode, op);
            assert_eq!(parsed.payload, payload);
            rest = &rest[parsed.consumed..];
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn direction_peer_is_an_involution() {
        assert_eq!(Direction::GuestToHost.peer(), Direction::HostToGuest);
        assert_eq!(Direction::HostToGuest.peer().peer(), Direction::HostToGuest);
    }

    /// Golden bytes, written out by hand rather than by the encoder.
    ///
    /// The point is to catch a field-order or endianness change that both
    /// the encoder and decoder would agree on — a round-trip test cannot see
    /// that, and a guest built from an older revision would.
    #[test]
    fn the_wire_layout_matches_its_golden_bytes() {
        let golden: [u8; 4 + 20 + 3] = [
            // frame length: 20 header + 3 payload = 23
            0x00, 0x00, 0x00, 0x17, //
            // magic
            b'M', b'V', b'F', b'M', //
            // version, opcode (Data = 0x13)
            0x01, 0x13, //
            // flags
            0x00, 0x00, //
            // header_len = 20
            0x00, 0x14, //
            // reserved
            0x00, 0x00, //
            // stream_id = 0x0102_0304
            0x01, 0x02, 0x03, 0x04, //
            // payload_len = 3
            0x00, 0x00, 0x00, 0x03, //
            // payload
            b'a', b'b', b'c',
        ];

        let encoded = encode(Opcode::Data, 0x0102_0304, b"abc").expect("encode");
        assert_eq!(
            encoded, golden,
            "encoder drifted from the pinned v1 wire layout"
        );

        let parsed = decode(&golden).expect("decode");
        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.header.opcode, Opcode::Data);
        assert_eq!(parsed.header.stream_id, 0x0102_0304);
        assert_eq!(parsed.header.payload_len, 3);
        assert_eq!(parsed.payload, b"abc");
    }

    /// Multi-byte fields are big-endian on every host, so the golden bytes
    /// above are the bytes a little-endian host emits too. Reading the
    /// fields back through native `from_be_bytes` and comparing against
    /// hand-placed byte positions is what makes that a test rather than a
    /// comment.
    #[test]
    fn multibyte_fields_are_big_endian_regardless_of_host_endianness() {
        let bytes = encode(Opcode::HttpResponseBody, 0xdead_beef, b"\x00\x01").expect("encode");
        // frame length, then header_len, stream_id, payload_len at their
        // fixed offsets inside the 20-byte header that starts at byte 4.
        assert_eq!(&bytes[0..4], &(HEADER_LEN as u32 + 2).to_be_bytes());
        assert_eq!(&bytes[12..14], &(HEADER_LEN as u16).to_be_bytes());
        assert_eq!(&bytes[16..20], &0xdead_beefu32.to_be_bytes());
        assert_eq!(&bytes[20..24], &2u32.to_be_bytes());
        // The most significant byte lands first, which is the whole claim.
        assert_eq!(bytes[16], 0xde);
        assert_eq!(bytes[19], 0xef);
    }

    #[test]
    fn every_opcode_has_a_stable_golden_discriminant() {
        // A renumbering would silently break a guest built from an older
        // revision, so the wire values are pinned here explicitly.
        let pinned: &[(Opcode, u8)] = &[
            (Opcode::Hello, 0x01),
            (Opcode::HelloAck, 0x02),
            (Opcode::GoAway, 0x03),
            (Opcode::OpenTcp, 0x10),
            (Opcode::Opened, 0x11),
            (Opcode::Refused, 0x12),
            (Opcode::Data, 0x13),
            (Opcode::WindowUpdate, 0x14),
            (Opcode::HalfClose, 0x15),
            (Opcode::Reset, 0x16),
            (Opcode::ConnectFailed, 0x17),
            (Opcode::OpenUdp, 0x20),
            (Opcode::UdpOpened, 0x21),
            (Opcode::UdpSend, 0x22),
            (Opcode::UdpRecv, 0x23),
            (Opcode::CloseUdp, 0x24),
            (Opcode::Resolve, 0x30),
            (Opcode::Resolved, 0x31),
            (Opcode::ResolveRefused, 0x32),
            (Opcode::InboundOpen, 0x40),
            (Opcode::InboundReady, 0x41),
            (Opcode::InboundRefused, 0x42),
            (Opcode::OpenHttp, 0x50),
            (Opcode::HttpRequestHead, 0x51),
            (Opcode::HttpRequestBody, 0x52),
            (Opcode::HttpResponseHead, 0x53),
            (Opcode::HttpResponseBody, 0x54),
            (Opcode::HttpComplete, 0x55),
            (Opcode::IcmpEcho, 0x60),
            (Opcode::IcmpReply, 0x61),
            (Opcode::IcmpRefused, 0x62),
        ];
        assert_eq!(pinned.len(), Opcode::ALL.len());
        for (op, want) in pinned {
            assert_eq!(op.as_u8(), *want, "{op:?}");
        }
    }
}
