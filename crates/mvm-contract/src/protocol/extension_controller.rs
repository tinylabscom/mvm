//! Generic framing for optional out-of-process extension controllers.
//!
//! The frame carries no ambient authority. Message payloads are separately
//! versioned, typed contracts, while this layer supplies a bounded byte count,
//! payload integrity, and monotonic sequence protection. An extension such as
//! an assurance runner uses the same frame as any future optional controller.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Distinguishes extension-controller frames from every guest protocol.
pub const MAGIC: [u8; 4] = *b"MVEX";
/// Exact framing version. Unknown versions are refused rather than negotiated
/// down implicitly.
pub const PROTOCOL_VERSION: u16 = 1;
/// Interoperable ceiling for controllers that do not advertise a narrower
/// admitted payload budget.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Bytes preceding the payload.
pub const HEADER_BYTES: usize = 4 + 2 + 2 + 8 + 4 + 32;

/// Generic controller lifecycle messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionMessageKind {
    Hello = 1,
    Describe = 2,
    ValidateConfig = 3,
    Plan = 4,
    OpenSession = 5,
    Start = 6,
    Progress = 7,
    Observation = 8,
    Finding = 9,
    ArtifactReady = 10,
    Complete = 11,
    Cancel = 12,
    Shutdown = 13,
    Error = 14,
}

impl ExtensionMessageKind {
    /// Decode a v1 wire discriminant.
    pub fn from_u16(value: u16) -> Result<Self, ExtensionFrameError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Describe),
            3 => Ok(Self::ValidateConfig),
            4 => Ok(Self::Plan),
            5 => Ok(Self::OpenSession),
            6 => Ok(Self::Start),
            7 => Ok(Self::Progress),
            8 => Ok(Self::Observation),
            9 => Ok(Self::Finding),
            10 => Ok(Self::ArtifactReady),
            11 => Ok(Self::Complete),
            12 => Ok(Self::Cancel),
            13 => Ok(Self::Shutdown),
            14 => Ok(Self::Error),
            other => Err(ExtensionFrameError::UnknownMessageKind(other)),
        }
    }

    /// Encode a v1 wire discriminant.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// One integrity-protected controller message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionFrame {
    pub kind: ExtensionMessageKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

/// Why an extension-controller frame was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionFrameError {
    #[error("extension frame is incomplete: need {needed} bytes, have {available}")]
    Incomplete { needed: usize, available: usize },
    #[error("invalid extension frame magic")]
    BadMagic,
    #[error("unsupported extension protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("unknown extension message kind: {0}")]
    UnknownMessageKind(u16),
    #[error("extension payload is too large: announced {announced}, maximum {maximum}")]
    PayloadTooLarge { announced: usize, maximum: usize },
    #[error("extension payload digest mismatch")]
    DigestMismatch,
    #[error("extension sequence must increase: previous {previous}, received {received}")]
    SequenceRollback { previous: u64, received: u64 },
}

/// Encode one frame under the caller's admitted payload ceiling.
pub fn encode_extension_frame(
    frame: &ExtensionFrame,
    maximum: usize,
) -> Result<Vec<u8>, ExtensionFrameError> {
    if frame.payload.len() > maximum || u32::try_from(frame.payload.len()).is_err() {
        return Err(ExtensionFrameError::PayloadTooLarge {
            announced: frame.payload.len(),
            maximum: maximum.min(u32::MAX as usize),
        });
    }
    let payload_len = u32::try_from(frame.payload.len()).expect("length checked against u32");
    let mut encoded = Vec::with_capacity(HEADER_BYTES.saturating_add(frame.payload.len()));
    encoded.extend_from_slice(&MAGIC);
    encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    encoded.extend_from_slice(&frame.kind.as_u16().to_be_bytes());
    encoded.extend_from_slice(&frame.sequence.to_be_bytes());
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(&Sha256::digest(&frame.payload));
    encoded.extend_from_slice(&frame.payload);
    Ok(encoded)
}

/// Decode exactly one frame from the front of `bytes` under the admitted
/// payload ceiling. The returned byte count lets stream adapters retain any
/// following frame without reparsing or over-reading.
pub fn decode_extension_frame(
    bytes: &[u8],
    maximum: usize,
) -> Result<(ExtensionFrame, usize), ExtensionFrameError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ExtensionFrameError::Incomplete {
            needed: HEADER_BYTES,
            available: bytes.len(),
        });
    }
    if bytes[..4] != MAGIC {
        return Err(ExtensionFrameError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ExtensionFrameError::UnsupportedVersion(version));
    }
    let kind = ExtensionMessageKind::from_u16(u16::from_be_bytes([bytes[6], bytes[7]]))?;
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed-width sequence slice"));
    let announced = usize::try_from(u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .expect("fixed-width payload length slice"),
    ))
    .expect("u32 fits in usize on supported targets");
    if announced > maximum {
        return Err(ExtensionFrameError::PayloadTooLarge { announced, maximum });
    }
    let total = HEADER_BYTES.saturating_add(announced);
    if bytes.len() < total {
        return Err(ExtensionFrameError::Incomplete {
            needed: total,
            available: bytes.len(),
        });
    }
    let payload = &bytes[HEADER_BYTES..total];
    let actual_digest = Sha256::digest(payload);
    if actual_digest.as_slice() != &bytes[20..HEADER_BYTES] {
        return Err(ExtensionFrameError::DigestMismatch);
    }
    Ok((
        ExtensionFrame {
            kind,
            sequence,
            payload: payload.to_vec(),
        },
        total,
    ))
}

/// Per-direction replay protection for a controller stream.
#[derive(Debug, Clone, Default)]
pub struct ExtensionSequenceValidator {
    previous: Option<u64>,
}

impl ExtensionSequenceValidator {
    /// Accept a strictly increasing sequence number.
    pub fn observe(&mut self, received: u64) -> Result<(), ExtensionFrameError> {
        if let Some(previous) = self.previous
            && received <= previous
        {
            return Err(ExtensionFrameError::SequenceRollback { previous, received });
        }
        self.previous = Some(received);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_v1_golden_frame_decodes_and_reencodes_byte_for_byte() {
        let golden = [
            b'M', b'V', b'E', b'X', 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 5, 0x2c, 0xf2,
            0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
            0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b,
            0x98, 0x24, b'h', b'e', b'l', b'l', b'o',
        ];
        let (decoded, consumed) =
            decode_extension_frame(&golden, DEFAULT_MAX_PAYLOAD_BYTES).expect("golden frame");
        assert_eq!(consumed, golden.len());
        assert_eq!(decoded.kind, ExtensionMessageKind::Finding);
        assert_eq!(decoded.sequence, 4);
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(
            encode_extension_frame(&decoded, DEFAULT_MAX_PAYLOAD_BYTES).expect("encode"),
            golden
        );
    }

    #[test]
    fn refuses_oversize_before_payload_is_required() {
        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header[6..8].copy_from_slice(&ExtensionMessageKind::Start.as_u16().to_be_bytes());
        header[16..20].copy_from_slice(&4096_u32.to_be_bytes());
        assert_eq!(
            decode_extension_frame(&header, 32),
            Err(ExtensionFrameError::PayloadTooLarge {
                announced: 4096,
                maximum: 32
            })
        );
    }

    #[test]
    fn refuses_tampering_unknown_versions_kinds_and_replay() {
        let frame = ExtensionFrame {
            kind: ExtensionMessageKind::Start,
            sequence: 7,
            payload: b"request".to_vec(),
        };
        let encoded = encode_extension_frame(&frame, 64).expect("encode");

        let mut tampered = encoded.clone();
        *tampered.last_mut().expect("payload byte") ^= 1;
        assert_eq!(
            decode_extension_frame(&tampered, 64),
            Err(ExtensionFrameError::DigestMismatch)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[5] = 2;
        assert_eq!(
            decode_extension_frame(&wrong_version, 64),
            Err(ExtensionFrameError::UnsupportedVersion(2))
        );

        let mut wrong_kind = encoded;
        wrong_kind[6..8].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            decode_extension_frame(&wrong_kind, 64),
            Err(ExtensionFrameError::UnknownMessageKind(99))
        );

        let mut sequences = ExtensionSequenceValidator::default();
        sequences.observe(4).expect("first sequence");
        assert_eq!(
            sequences.observe(4),
            Err(ExtensionFrameError::SequenceRollback {
                previous: 4,
                received: 4
            })
        );
    }
}
