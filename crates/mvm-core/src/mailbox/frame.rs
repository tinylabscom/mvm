//! The one-frame mailbox exchange both ends of the mailbox port share.
//!
//! A peer writes a length-prefixed frame (a capability and a sealed envelope),
//! a guest a length-prefixed plaintext [`OutboxMessage`]; either reads one
//! typed verdict, a serialized `Result<(), Refusal>`. Keeping both directions
//! here means the two ends cannot drift.
//!
//! Frame: `u32 BE length`, then `u32 BE capability length`, the capability as
//! JSON, and the envelope in its canonical `encode_envelope` form.

use std::io::{Read, Write};

use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    DeliveryOutcome, MAX_MAILBOX_PAYLOAD_BYTES, MailboxAddress, MailboxEnvelope,
    MailboxEnvelopeHeader, MessageId, PrincipalId, SignedDestinationReceipt,
    SignedMailboxCapability,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{decode_envelope, encode_envelope, verify_receipt};

// A verdict contains no payload. Bound the response even when a peer never
// closes or sends arbitrarily large error text.
const MAX_VERDICT_BYTES: u64 = 4 * 1024;

/// Why a frame was not queued. Sent back to the peer verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Refusal {
    #[error("frame exceeds the {0}-byte limit")]
    Oversized(usize),
    #[error("mailbox queue is full ({0} messages)")]
    QueueFull(usize),
    #[error("durable mailbox storage quota is full")]
    StorageFull,
    #[error("mailbox retry budget exhausted; reconcile the stable message ID")]
    RetriesExhausted,
    #[error("frame is malformed")]
    Malformed,
    #[error("destination is unavailable")]
    Unavailable,
    /// The mailbox gate refused it; carries the gate's own reason text.
    #[error("{0}")]
    Mailbox(String),
}

/// The frame body (without its outer length prefix).
pub fn encode_frame(
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<Vec<u8>, Refusal> {
    let cap = serde_json::to_vec(capability).map_err(|_| Refusal::Malformed)?;
    let env = encode_envelope(envelope).map_err(|e| Refusal::Mailbox(e.to_string()))?;
    let mut body = (cap.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(&cap);
    body.extend_from_slice(&env);
    Ok(body)
}

/// Split a frame body back into its capability and envelope.
pub fn decode_frame(body: &[u8]) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal> {
    let (len, rest) = body.split_at_checked(4).ok_or(Refusal::Malformed)?;
    let cap_len = u32::from_be_bytes(len.try_into().map_err(|_| Refusal::Malformed)?) as usize;
    let (cap, env) = rest.split_at_checked(cap_len).ok_or(Refusal::Malformed)?;
    Ok((
        serde_json::from_slice(cap).map_err(|_| Refusal::Malformed)?,
        decode_envelope(env).map_err(|_| Refusal::Malformed)?,
    ))
}

/// What a guest asks its host to send: an immutable operation identity,
/// recipient, and plaintext body.
/// Nothing here is sealed or signed; the host does that under keys the guest
/// never holds. Wire form: 32 recipient bytes, 32 message-ID bytes, then body.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxMessage {
    pub recipient: PrincipalId,
    pub message_id: MessageId,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for OutboxMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxMessage")
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl OutboxMessage {
    /// Mint a fresh operation identity once, before the first submission;
    /// retry by retaining this value rather than constructing another one.
    #[must_use]
    pub fn new(recipient: PrincipalId, body: Vec<u8>) -> Self {
        Self {
            recipient,
            message_id: MessageId::from_bytes(rand::random()),
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        [
            self.recipient.as_bytes().as_slice(),
            self.message_id.as_bytes().as_slice(),
            &self.body,
        ]
        .concat()
    }

    /// Refuses a short, oversized or empty-bodied message.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let (recipient, rest) = bytes.split_at_checked(32).ok_or(Refusal::Malformed)?;
        let (message_id, body) = rest.split_at_checked(32).ok_or(Refusal::Malformed)?;
        if body.is_empty() {
            return Err(Refusal::Malformed);
        }
        if body.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES));
        }
        let recipient = <[u8; 32]>::try_from(recipient).map_err(|_| Refusal::Malformed)?;
        let message_id = <[u8; 32]>::try_from(message_id).map_err(|_| Refusal::Malformed)?;
        Ok(Self {
            recipient: PrincipalId::from_bytes(recipient),
            message_id: MessageId::from_bytes(message_id),
            body: body.to_vec(),
        })
    }
}

/// Peer side: write one sealed frame on `stream` and read the service's
/// verdict. The caller sets any timeouts on the stream.
pub fn send_frame<S: Read + Write>(
    stream: &mut S,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<(), Refusal> {
    exchange(stream, &encode_frame(capability, envelope)?)
}

/// A durable destination verdict is useful only after verifying its signer
/// and binding to the exact canonical envelope sent on this connection.
pub fn send_receipted_frame<S: Read + Write>(
    stream: &mut S,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
    expected_header: &MailboxEnvelopeHeader,
    destination_key: &VerifyingKey,
) -> Result<SignedDestinationReceipt, Refusal> {
    let receipt: SignedDestinationReceipt = exchange(stream, &encode_frame(capability, envelope)?)?;
    verify_receipt(&receipt, destination_key).map_err(|_| Refusal::Malformed)?;
    let address = MailboxAddress {
        tenant: expected_header.tenant,
        authorization_domain: expected_header.authorization_domain,
        mailbox: expected_header.mailbox,
        recipient: expected_header.recipient,
    };
    if receipt.receipt.delivery_id != envelope.routing.delivery_id
        || receipt.receipt.ciphertext_commitment != envelope.ciphertext_commitment
        || receipt.receipt.message_id != expected_header.message_id
        || receipt.receipt.address != address
        || receipt.receipt.execution_epoch != expected_header.execution_epoch
        || !matches!(
            receipt.receipt.outcome,
            DeliveryOutcome::AcceptedDurable | DeliveryOutcome::Duplicate
        )
    {
        return Err(Refusal::Malformed);
    }
    Ok(receipt)
}

/// Guest side: write one plaintext message and read the host's verdict.
pub fn send_outbox_message<S: Read + Write>(
    stream: &mut S,
    message: &OutboxMessage,
) -> Result<(), Refusal> {
    if message.body.is_empty() {
        return Err(Refusal::Malformed);
    }
    if message.body.len() > MAX_MAILBOX_PAYLOAD_BYTES {
        return Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES));
    }
    exchange(stream, &message.encode())
}

fn exchange<S: Read + Write, T: DeserializeOwned>(
    stream: &mut S,
    body: &[u8],
) -> Result<T, Refusal> {
    // A service that refuses on length alone closes early; the verdict is
    // still readable, so a failed write is not itself the answer.
    let _ = stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(body));
    let mut reply = Vec::new();
    stream
        .take(MAX_VERDICT_BYTES + 1)
        .read_to_end(&mut reply)
        .map_err(|_| Refusal::Malformed)?;
    if reply.len() as u64 > MAX_VERDICT_BYTES {
        return Err(Refusal::Oversized(MAX_VERDICT_BYTES as usize));
    }
    serde_json::from_slice::<Result<T, Refusal>>(&reply).map_err(|_| Refusal::Malformed)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_outbox_message_round_trips_and_malformed_input_is_refused() {
        let message = OutboxMessage {
            recipient: PrincipalId::from_bytes([3; 32]),
            message_id: MessageId::from_bytes([4; 32]),
            body: b"hello".to_vec(),
        };
        assert_eq!(OutboxMessage::decode(&message.encode()), Ok(message));
        assert_eq!(OutboxMessage::decode(&[0; 63]), Err(Refusal::Malformed));
        assert_eq!(OutboxMessage::decode(&[0; 64]), Err(Refusal::Malformed));
        let big = vec![1; 64 + MAX_MAILBOX_PAYLOAD_BYTES + 1];
        assert_eq!(
            OutboxMessage::decode(&big),
            Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES))
        );
        let first = OutboxMessage::new(PrincipalId::from_bytes([3; 32]), b"hello".to_vec());
        let second = OutboxMessage::new(PrincipalId::from_bytes([3; 32]), b"hello".to_vec());
        assert_ne!(
            first.message_id, second.message_id,
            "each new send has a new identity"
        );
        assert_eq!(
            first.message_id,
            first.clone().message_id,
            "retry retains its identity"
        );
    }

    #[test]
    fn a_peer_cannot_make_the_verdict_reader_grow_without_bound() {
        struct Peer(std::io::Cursor<Vec<u8>>);
        impl Read for Peer {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Write for Peer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut peer = Peer(std::io::Cursor::new(vec![
            b'x';
            MAX_VERDICT_BYTES as usize + 2
        ]));
        assert_eq!(
            send_outbox_message(
                &mut peer,
                &OutboxMessage {
                    recipient: PrincipalId::from_bytes([3; 32]),
                    message_id: MessageId::from_bytes([4; 32]),
                    body: b"hello".to_vec(),
                }
            ),
            Err(Refusal::Oversized(MAX_VERDICT_BYTES as usize))
        );
        assert_eq!(peer.0.position(), MAX_VERDICT_BYTES + 1);
    }

    #[test]
    fn an_oversized_outbox_is_refused_before_a_peer_sees_a_frame() {
        let mut peer = std::io::Cursor::new(Vec::new());
        assert_eq!(
            send_outbox_message(
                &mut peer,
                &OutboxMessage {
                    recipient: PrincipalId::from_bytes([3; 32]),
                    message_id: MessageId::from_bytes([4; 32]),
                    body: vec![0; MAX_MAILBOX_PAYLOAD_BYTES + 1],
                }
            ),
            Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES))
        );
        assert!(peer.into_inner().is_empty());
    }
}
