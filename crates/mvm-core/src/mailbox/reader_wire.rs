//! Versioned control frames for the on-demand guest reader exchange.
//!
//! The `MVMR` discriminator must be dispatched before the outbox decoder;
//! it is not itself a claim of reader authority.
//! Decoding never supplies authority: the destination must verify the signed
//! Receive capability, current boot, possession proof, lease and ACK against
//! its journal before releasing plaintext or committing an acknowledgement.
//! The discriminator is inspected only after the outer length has been bounded.

use std::io::{Read, Write};

use base64::Engine as _;
use mvm_contract::protocol::mailbox::{
    ContentType, SignedMailboxCapability, SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
    SignedMailboxGuestReaderEnrollment,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::frame::Refusal;

const READER_MAGIC: &[u8; 5] = b"MVMR\x01";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Guest-local socket for explicit application Receive and ACK-after-processing.
pub const GUEST_READER_SOCKET_PATH: &str = "/run/mvm/mailbox/receive.sock";

/// One on-demand guest request. `Possession` answers the immediately preceding
/// destination challenge on the same connection, not an arbitrary old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReaderRequest {
    Receive,
    Possession {
        signature: Vec<u8>,
    },
    Ack {
        signed: Box<SignedMailboxDeliveryAck>,
    },
}

/// The guest application asks for a delivery or explicitly acknowledges one
/// after processing. It never receives the per-boot ACK signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationReaderRequest {
    Receive,
    Ack {
        lease: Box<SignedMailboxDeliveryLease>,
    },
}

/// Destination response; a delivery is never sent before its lease is durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReaderResponse {
    Challenge {
        enrollment: Box<SignedMailboxGuestReaderEnrollment>,
        capability: Box<SignedMailboxCapability>,
        challenge: [u8; 32],
    },
    Delivery {
        lease: Box<SignedMailboxDeliveryLease>,
        content_type: ContentType,
        #[serde(with = "payload_base64")]
        payload: Vec<u8>,
    },
    Empty,
    Acknowledged {
        /// The exact guest-signed operation committed and anchored locally.
        /// This is correlation, not a destination-signed exportable receipt.
        ack: Box<SignedMailboxDeliveryAck>,
    },
    Refused {
        reason: Refusal,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned<T> {
    version: u16,
    value: T,
}

/// Write one request, bounded before a byte is put on the stream.
pub fn write_request(stream: &mut impl Write, request: &ReaderRequest) -> Result<(), Refusal> {
    write_frame(stream, request, MAX_REQUEST_BYTES)
}

/// Read a request only after bounding its complete length.
pub fn read_request(stream: &mut impl Read) -> Result<ReaderRequest, Refusal> {
    read_frame(stream, MAX_REQUEST_BYTES)
}

/// Distinguish the reader plane from an outbox body after bounding the outer frame.
/// The legacy outbox begins with an arbitrary recipient ID, so a four-byte
/// prefix alone would misclassify valid Send operations. Unknown versions with
/// the versioned JSON envelope still fail closed in `decode_request_body`.
#[must_use]
pub fn is_reader_frame(body: &[u8]) -> bool {
    body.starts_with(b"MVMR")
        && body
            .get(READER_MAGIC.len()..)
            .is_some_and(|json| json.starts_with(b"{\"version\":"))
}

/// Decode a request when the shared mailbox listener has already read its length.
pub fn decode_request_body(body: &[u8]) -> Result<ReaderRequest, Refusal> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Refusal::Oversized(MAX_REQUEST_BYTES));
    }
    decode_body(body)
}

/// Read one bounded, explicit application operation from the guest-local socket.
pub fn read_application_request(
    stream: &mut impl Read,
) -> Result<ApplicationReaderRequest, Refusal> {
    read_frame(stream, MAX_REQUEST_BYTES)
}

/// Send an explicit application operation to the guest-local socket.
pub fn write_application_request(
    stream: &mut impl Write,
    request: &ApplicationReaderRequest,
) -> Result<(), Refusal> {
    write_frame(stream, request, MAX_REQUEST_BYTES)
}

/// Write one destination response, including at most a bounded payload.
pub fn write_response(stream: &mut impl Write, response: &ReaderResponse) -> Result<(), Refusal> {
    write_frame(stream, response, MAX_RESPONSE_BYTES)
}

/// Read a response only after bounding its complete length.
pub fn read_response(stream: &mut impl Read) -> Result<ReaderResponse, Refusal> {
    read_frame(stream, MAX_RESPONSE_BYTES)
}

fn write_frame<T: Serialize>(
    stream: &mut impl Write,
    value: &T,
    limit: usize,
) -> Result<(), Refusal> {
    let mut json = BoundedBytes {
        bytes: Vec::new(),
        limit: limit - READER_MAGIC.len(),
    };
    serde_json::to_writer(&mut json, &Versioned { version: 1, value })
        .map_err(|_| Refusal::Oversized(limit))?;
    let len = READER_MAGIC.len() + json.bytes.len();
    stream
        .write_all(&(len as u32).to_be_bytes())
        .and_then(|()| stream.write_all(READER_MAGIC))
        .and_then(|()| stream.write_all(&json.bytes))
        .map_err(|_| Refusal::Unavailable)
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(std::io::Error::other("mailbox reader frame exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

mod payload_base64 {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(D::Error::custom)
    }
}

fn read_frame<T: DeserializeOwned>(stream: &mut impl Read, limit: usize) -> Result<T, Refusal> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|_| Refusal::Malformed)?;
    let len = u32::from_be_bytes(len) as usize;
    if !(READER_MAGIC.len()..=limit).contains(&len) {
        return Err(Refusal::Oversized(limit));
    }
    let mut body = vec![0; len];
    stream
        .read_exact(&mut body)
        .map_err(|_| Refusal::Malformed)?;
    decode_body(&body)
}

fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Refusal> {
    let json = body.strip_prefix(READER_MAGIC).ok_or(Refusal::Malformed)?;
    let frame: Versioned<T> = serde_json::from_slice(json).map_err(|_| Refusal::Malformed)?;
    if frame.version != 1 {
        return Err(Refusal::Malformed);
    }
    Ok(frame.value)
}
