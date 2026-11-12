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

use mvm_contract::protocol::mailbox::{
    MAX_MAILBOX_PAYLOAD_BYTES, MailboxEnvelope, PrincipalId, SignedMailboxCapability,
};
use serde::{Deserialize, Serialize};

use super::{decode_envelope, encode_envelope};

/// Why a frame was not queued. Sent back to the peer verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Refusal {
    #[error("frame exceeds the {0}-byte limit")]
    Oversized(usize),
    #[error("mailbox queue is full ({0} messages)")]
    QueueFull(usize),
    #[error("frame is malformed")]
    Malformed,
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

/// The recipient a guest writes to address its own granted mailbox without
/// knowing any host-derived value. The mailbox id means the same.
pub const OWN_MAILBOX_RECIPIENT: [u8; 32] = [0; 32];

/// What a guest asks its host to send: a recipient and a plaintext body.
/// Nothing here is sealed or signed; the host does that under keys the guest
/// never holds. The recipient is [`OWN_MAILBOX_RECIPIENT`] or the mailbox id;
/// the host maps either to the recipient its policy names and refuses any
/// other value at admission. Wire form: the 32 recipient bytes, then the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxMessage {
    pub recipient: PrincipalId,
    pub body: Vec<u8>,
}

impl OutboxMessage {
    pub fn encode(&self) -> Vec<u8> {
        [self.recipient.as_bytes().as_slice(), &self.body].concat()
    }

    /// Refuses a short, oversized or empty-bodied message.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let (recipient, body) = bytes.split_at_checked(32).ok_or(Refusal::Malformed)?;
        if body.is_empty() {
            return Err(Refusal::Malformed);
        }
        if body.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES));
        }
        let recipient = <[u8; 32]>::try_from(recipient).map_err(|_| Refusal::Malformed)?;
        Ok(Self {
            recipient: PrincipalId::from_bytes(recipient),
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

/// Guest side: write one plaintext message and read the host's verdict.
pub fn send_outbox_message<S: Read + Write>(
    stream: &mut S,
    message: &OutboxMessage,
) -> Result<(), Refusal> {
    exchange(stream, &message.encode())
}

fn exchange<S: Read + Write>(stream: &mut S, body: &[u8]) -> Result<(), Refusal> {
    // A service that refuses on length alone closes early; the verdict is
    // still readable, so a failed write is not itself the answer.
    let _ = stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(body));
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|_| Refusal::Malformed)?;
    serde_json::from_slice::<Result<(), Refusal>>(&reply).map_err(|_| Refusal::Malformed)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_outbox_message_round_trips_and_malformed_input_is_refused() {
        let message = OutboxMessage {
            recipient: PrincipalId::from_bytes([3; 32]),
            body: b"hello".to_vec(),
        };
        assert_eq!(OutboxMessage::decode(&message.encode()), Ok(message));
        assert_eq!(OutboxMessage::decode(&[0; 31]), Err(Refusal::Malformed));
        assert_eq!(OutboxMessage::decode(&[0; 32]), Err(Refusal::Malformed));
        let big = vec![1; 32 + MAX_MAILBOX_PAYLOAD_BYTES + 1];
        assert_eq!(
            OutboxMessage::decode(&big),
            Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES))
        );
    }
}
