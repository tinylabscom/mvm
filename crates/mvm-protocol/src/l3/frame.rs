//! Outer framing for the L3-over-vsock protocol.
//!
//! A frame is a big-endian `u32` byte count followed by that many bytes: a
//! 24-byte fixed header and then the payload. Nothing here is
//! self-describing and nothing allocates before the length has been
//! checked against [`MAX_FRAME_LEN`], which is the whole point — the bytes
//! arrive from a guest that controls all of them.
//!
//! ```text
//! u32 frame_length_be   bytes that follow: header_len + payload_len
//! ├─ magic       [u8;4]  b"MVL3"
//! ├─ version     u8
//! ├─ msg_type    u8
//! ├─ flags       u16 be   reserved in v1, must be zero
//! ├─ header_len  u16 be   24 in v1
//! ├─ reserved    u16 be   must be zero
//! ├─ session_id  u64 be   host-assigned; zero only on HELLO
//! ├─ queue_id    u16 be
//! └─ payload_len u16 be   must equal frame_length - header_len
//! payload        [u8; payload_len]
//! ```

use alloc::vec::Vec;

use super::limits::{HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION};

/// Frame magic. Distinctive enough that a stream desync shows up as a
/// rejection rather than a plausible-looking header.
pub const MAGIC: [u8; 4] = *b"MVL3";

/// Length of the `u32` big-endian frame-length prefix.
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Message discriminants. Anything not listed is rejected; there is no
/// "unknown, pass through" path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// guest→host: opens the control connection and proposes features.
    Hello = 0x01,
    /// host→guest: the assigned network configuration.
    Config = 0x02,
    /// guest→host: interface configured, packets may flow.
    Ready = 0x03,
    /// both: exactly one complete IP packet.
    Packet = 0x04,
    /// both: liveness.
    Heartbeat = 0x05,
    /// both: orderly teardown with a reason.
    Shutdown = 0x06,
    /// both: bounded error report.
    Error = 0x07,
}

impl MessageType {
    /// Wire discriminant.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire discriminant, or `None` for an unknown type.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Config),
            0x03 => Some(Self::Ready),
            0x04 => Some(Self::Packet),
            0x05 => Some(Self::Heartbeat),
            0x06 => Some(Self::Shutdown),
            0x07 => Some(Self::Error),
            _ => None,
        }
    }

    /// Whether this message belongs on the data connection. Keeping
    /// control and packet traffic on separate connections is a design
    /// constraint, so each end checks arrivals against the connection they
    /// came in on.
    pub fn is_data_plane(self) -> bool {
        matches!(self, Self::Packet)
    }
}

/// Why a frame was refused. Every variant is a fail-closed outcome; there
/// is no "recovered" case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
    /// `msg_type` was not a known discriminant.
    #[error("unknown message type {0:#04x}")]
    UnknownMessageType(u8),
    /// `header_len` was not the version's header size, or did not fit
    /// inside the announced frame.
    #[error("invalid header length {0}")]
    InvalidHeaderLen(u16),
    /// `payload_len` disagreed with `frame_length - header_len`.
    #[error("payload length {declared} inconsistent with frame length (expected {expected})")]
    InconsistentLength { declared: usize, expected: usize },
    /// Payload exceeded [`MAX_PAYLOAD_LEN`].
    #[error("payload length {len} exceeds maximum {max}")]
    PayloadTooLong { len: usize, max: usize },
    /// A field reserved in this version carried a non-zero value. Rejected
    /// so the field can be given a meaning later without ambiguity.
    #[error("reserved field {field} must be zero in version {PROTOCOL_VERSION}")]
    ReservedNonZero { field: &'static str },
    /// Encoding was asked to emit a payload larger than the protocol
    /// permits.
    #[error("cannot encode payload of {len} bytes (maximum {max})")]
    EncodeTooLong { len: usize, max: usize },
}

/// The fixed header, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub msg_type: MessageType,
    pub flags: u16,
    pub session_id: u64,
    pub queue_id: u16,
    pub payload_len: u16,
}

impl FrameHeader {
    /// A v1 header for `msg_type` on `session_id` / `queue_id`.
    pub fn new(msg_type: MessageType, session_id: u64, queue_id: u16, payload_len: u16) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            flags: 0,
            session_id,
            queue_id,
            payload_len,
        }
    }
}

/// A parsed frame: its header plus the byte range of its payload inside
/// the caller's buffer. Borrowing rather than copying keeps the steady
/// state free of per-packet allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
    /// Total bytes this frame occupied, prefix included. The caller
    /// advances its buffer by exactly this.
    pub consumed: usize,
}

/// Read the announced frame length without consuming it.
///
/// Separated from [`decode`] so a reader can size (or refuse) its read
/// before it has the body — the point at which an oversized frame must
/// die, before any allocation.
pub fn peek_frame_len(buf: &[u8]) -> Result<usize, FrameError> {
    if buf.len() < LENGTH_PREFIX_LEN {
        return Err(FrameError::Incomplete {
            needed: LENGTH_PREFIX_LEN,
            have: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
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
/// Fails closed on every inconsistency. Returns [`FrameError::Incomplete`]
/// — and only that — when the caller simply needs to read more; every
/// other error means the connection is unusable and must be dropped.
pub fn decode(buf: &[u8]) -> Result<ParsedFrame<'_>, FrameError> {
    let frame_len = peek_frame_len(buf)?;
    let total = LENGTH_PREFIX_LEN + frame_len;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            have: buf.len(),
        });
    }
    let frame = &buf[LENGTH_PREFIX_LEN..total];

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
    let msg_type =
        MessageType::from_u8(frame[5]).ok_or(FrameError::UnknownMessageType(frame[5]))?;
    let flags = u16::from_be_bytes([frame[6], frame[7]]);
    if flags != 0 {
        return Err(FrameError::ReservedNonZero { field: "flags" });
    }
    let header_len = u16::from_be_bytes([frame[8], frame[9]]);
    if header_len as usize != HEADER_LEN {
        return Err(FrameError::InvalidHeaderLen(header_len));
    }
    let reserved = u16::from_be_bytes([frame[10], frame[11]]);
    if reserved != 0 {
        return Err(FrameError::ReservedNonZero { field: "reserved" });
    }
    let session_id = u64::from_be_bytes([
        frame[12], frame[13], frame[14], frame[15], frame[16], frame[17], frame[18], frame[19],
    ]);
    let queue_id = u16::from_be_bytes([frame[20], frame[21]]);
    let payload_len = u16::from_be_bytes([frame[22], frame[23]]);

    let expected = frame_len - HEADER_LEN;
    if payload_len as usize != expected {
        return Err(FrameError::InconsistentLength {
            declared: payload_len as usize,
            expected,
        });
    }
    if payload_len as usize > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLong {
            len: payload_len as usize,
            max: MAX_PAYLOAD_LEN,
        });
    }

    Ok(ParsedFrame {
        header: FrameHeader {
            version,
            msg_type,
            flags,
            session_id,
            queue_id,
            payload_len,
        },
        payload: &frame[HEADER_LEN..],
        consumed: total,
    })
}

/// Serialize a frame into `out`, appending to whatever is already there.
///
/// `out` is a caller-owned buffer so the hot path can reuse one allocation
/// per connection instead of minting a `Vec` per packet.
pub fn encode_into(
    out: &mut Vec<u8>,
    msg_type: MessageType,
    session_id: u64,
    queue_id: u16,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::EncodeTooLong {
            len: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }
    let frame_len = HEADER_LEN + payload.len();
    out.reserve(LENGTH_PREFIX_LEN + frame_len);
    out.extend_from_slice(&(frame_len as u32).to_be_bytes());
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(msg_type.as_u8());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags
    out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // reserved
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&queue_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Convenience wrapper over [`encode_into`] for call sites that are not on
/// the hot path (handshake, shutdown, tests).
pub fn encode(
    msg_type: MessageType,
    session_id: u64,
    queue_id: u16,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + HEADER_LEN + payload.len());
    encode_into(&mut out, msg_type, session_id, queue_id, payload)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip(msg_type: MessageType, payload: &[u8]) -> ParsedFrame<'static> {
        let bytes = encode(msg_type, 0xDEAD_BEEF_CAFE_F00D, 0, payload).expect("encode");
        let leaked: &'static [u8] = alloc::boxed::Box::leak(bytes.into_boxed_slice());
        decode(leaked).expect("decode")
    }

    #[test]
    fn roundtrips_every_message_type() {
        for ty in [
            MessageType::Hello,
            MessageType::Config,
            MessageType::Ready,
            MessageType::Packet,
            MessageType::Heartbeat,
            MessageType::Shutdown,
            MessageType::Error,
        ] {
            let parsed = roundtrip(ty, b"payload-bytes");
            assert_eq!(parsed.header.msg_type, ty);
            assert_eq!(parsed.payload, b"payload-bytes");
            assert_eq!(parsed.header.session_id, 0xDEAD_BEEF_CAFE_F00D);
            assert_eq!(parsed.header.version, PROTOCOL_VERSION);
        }
    }

    #[test]
    fn roundtrips_an_empty_payload() {
        let parsed = roundtrip(MessageType::Heartbeat, &[]);
        assert_eq!(parsed.header.payload_len, 0);
        assert!(parsed.payload.is_empty());
        assert_eq!(parsed.consumed, LENGTH_PREFIX_LEN + HEADER_LEN);
    }

    #[test]
    fn consumed_covers_prefix_header_and_payload() {
        let parsed = roundtrip(MessageType::Packet, &[7u8; 100]);
        assert_eq!(parsed.consumed, LENGTH_PREFIX_LEN + HEADER_LEN + 100);
    }

    #[test]
    fn a_truncated_length_prefix_is_incomplete_not_fatal() {
        for n in 0..LENGTH_PREFIX_LEN {
            assert!(matches!(
                decode(&vec![0u8; n]),
                Err(FrameError::Incomplete { .. })
            ));
        }
    }

    #[test]
    fn a_truncated_header_is_incomplete_not_fatal() {
        let bytes = encode(MessageType::Hello, 1, 0, b"abc").unwrap();
        for n in LENGTH_PREFIX_LEN..bytes.len() {
            assert!(
                matches!(decode(&bytes[..n]), Err(FrameError::Incomplete { .. })),
                "prefix of {n} bytes should be incomplete, not fatal"
            );
        }
    }

    #[test]
    fn an_oversized_frame_is_rejected_before_the_body_arrives() {
        // Only the four length bytes are present; the rejection must not
        // wait for (or allocate for) the announced body.
        let announced = (MAX_FRAME_LEN + 1) as u32;
        let err = decode(&announced.to_be_bytes()).unwrap_err();
        assert!(matches!(err, FrameError::TooLong { .. }));
        assert!(matches!(
            peek_frame_len(&announced.to_be_bytes()),
            Err(FrameError::TooLong { .. })
        ));
    }

    #[test]
    fn a_frame_too_small_for_a_header_is_rejected() {
        let announced = (HEADER_LEN - 1) as u32;
        assert!(matches!(
            decode(&announced.to_be_bytes()),
            Err(FrameError::TooShort { .. })
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = encode(MessageType::Hello, 1, 0, b"x").unwrap();
        bytes[LENGTH_PREFIX_LEN] = b'X';
        assert!(matches!(decode(&bytes), Err(FrameError::BadMagic)));
    }

    #[test]
    fn an_unknown_major_version_is_rejected_never_negotiated_down() {
        let mut bytes = encode(MessageType::Hello, 1, 0, b"x").unwrap();
        bytes[LENGTH_PREFIX_LEN + 4] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::UnsupportedVersion { got, want })
                if got == PROTOCOL_VERSION + 1 && want == PROTOCOL_VERSION
        ));
    }

    #[test]
    fn an_unknown_message_type_is_rejected() {
        let mut bytes = encode(MessageType::Hello, 1, 0, b"x").unwrap();
        bytes[LENGTH_PREFIX_LEN + 5] = 0x7f;
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::UnknownMessageType(0x7f))
        ));
    }

    #[test]
    fn non_zero_reserved_fields_are_rejected() {
        let mut bytes = encode(MessageType::Hello, 1, 0, b"x").unwrap();
        bytes[LENGTH_PREFIX_LEN + 6] = 0x01; // flags
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::ReservedNonZero { field: "flags" })
        ));

        let mut bytes = encode(MessageType::Hello, 1, 0, b"x").unwrap();
        bytes[LENGTH_PREFIX_LEN + 10] = 0x01; // reserved
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::ReservedNonZero { field: "reserved" })
        ));
    }

    #[test]
    fn a_wrong_header_len_is_rejected() {
        let mut bytes = encode(MessageType::Hello, 1, 0, b"xyz").unwrap();
        bytes[LENGTH_PREFIX_LEN + 8..LENGTH_PREFIX_LEN + 10]
            .copy_from_slice(&(HEADER_LEN as u16 + 4).to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::InvalidHeaderLen(_))
        ));
    }

    #[test]
    fn inner_and_outer_lengths_must_agree() {
        let mut bytes = encode(MessageType::Packet, 1, 0, &[0u8; 64]).unwrap();
        // Claim a shorter payload than the frame length implies.
        bytes[LENGTH_PREFIX_LEN + 22..LENGTH_PREFIX_LEN + 24].copy_from_slice(&32u16.to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::InconsistentLength {
                declared: 32,
                expected: 64
            })
        ));
    }

    #[test]
    fn encoding_refuses_an_oversized_payload() {
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            encode(MessageType::Packet, 1, 0, &payload),
            Err(FrameError::EncodeTooLong { .. })
        ));
    }

    #[test]
    fn a_maximum_sized_payload_roundtrips() {
        let payload = vec![0xABu8; MAX_PAYLOAD_LEN];
        let bytes = encode(MessageType::Packet, 9, 0, &payload).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed.payload.len(), MAX_PAYLOAD_LEN);
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn decode_stops_at_the_frame_boundary_when_two_frames_are_buffered() {
        let mut buf = Vec::new();
        encode_into(&mut buf, MessageType::Packet, 5, 0, b"first").unwrap();
        encode_into(&mut buf, MessageType::Packet, 5, 0, b"second").unwrap();
        let first = decode(&buf).unwrap();
        assert_eq!(first.payload, b"first");
        let second = decode(&buf[first.consumed..]).unwrap();
        assert_eq!(second.payload, b"second");
        assert_eq!(first.consumed + second.consumed, buf.len());
    }

    #[test]
    fn only_packet_is_data_plane() {
        assert!(MessageType::Packet.is_data_plane());
        for ty in [
            MessageType::Hello,
            MessageType::Config,
            MessageType::Ready,
            MessageType::Heartbeat,
            MessageType::Shutdown,
            MessageType::Error,
        ] {
            assert!(!ty.is_data_plane(), "{ty:?} must stay on the control path");
        }
    }

    #[test]
    fn message_type_discriminants_are_pinned() {
        // The wire values are a contract with the guest binary; a
        // reordering of the enum must not silently renumber them.
        assert_eq!(MessageType::Hello.as_u8(), 0x01);
        assert_eq!(MessageType::Config.as_u8(), 0x02);
        assert_eq!(MessageType::Ready.as_u8(), 0x03);
        assert_eq!(MessageType::Packet.as_u8(), 0x04);
        assert_eq!(MessageType::Heartbeat.as_u8(), 0x05);
        assert_eq!(MessageType::Shutdown.as_u8(), 0x06);
        assert_eq!(MessageType::Error.as_u8(), 0x07);
    }

    /// Deterministic sweep over adversarial byte patterns. The property is
    /// only ever "no panic": a decoder that aborts on hostile input is a
    /// denial of service on the host gateway.
    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..600usize {
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = decode(&buf);
            let _ = peek_frame_len(&buf);
            // Also exercise plausible-prefix inputs, which get much deeper
            // into the parser than uniformly random bytes do.
            if len >= LENGTH_PREFIX_LEN + 4 {
                buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + 4].copy_from_slice(&MAGIC);
                let _ = decode(&buf);
            }
        }
    }
}
