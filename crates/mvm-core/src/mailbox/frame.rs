//! The one-frame mailbox exchange both ends of the mailbox port share.
//!
//! A peer writes a length-prefixed frame (a capability and a sealed envelope),
//! a guest a length-prefixed plaintext [`OutboxMessage`]; a legacy guest reads
//! `Result<(), Refusal>`, while a locally durable sender requires a signed V2
//! receipt. Keeping both directions here means the two ends cannot drift.
//!
//! Frame: `u32 BE length`, then `u32 BE capability length`, the capability as
//! JSON, and the envelope in its canonical `encode_envelope` form.

use std::io::{Read, Write};

use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    DeliveryOutcome, ExecutionEpoch, MAX_MAILBOX_PAYLOAD_BYTES, MailboxAddress, MailboxEnvelope,
    MailboxEnvelopeHeader, MailboxId, MessageId, PrincipalId, SignedDestinationReceipt,
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
    #[error("mailbox message expired before acceptance")]
    Expired,
    #[error("mailbox retry budget exhausted; reconcile the stable message ID")]
    RetriesExhausted,
    #[error("mailbox operation is not authorized")]
    NotAuthorized,
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

/// A guest may name its own granted mailbox without knowing its host-derived
/// recipient principal. The host resolves this alias before admission.
pub const OWN_MAILBOX_RECIPIENT: [u8; 32] = [0; 32];

/// What a guest asks its host to send: an immutable operation identity,
/// recipient, and plaintext body.
/// Nothing here is sealed or signed; the host does that under keys the guest
/// never holds. Recipient may name [`OWN_MAILBOX_RECIPIENT`] or the mailbox
/// ID; the host resolves either to the grant's recipient. Wire form: 32
/// recipient bytes, 32 message-ID bytes, then body.
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
    send_expected_receipt(
        stream,
        capability,
        envelope,
        expected_header,
        destination_key,
        &[DeliveryOutcome::AcceptedDurable, DeliveryOutcome::Duplicate],
    )
}

/// Verify the separate trusted-host local receipt without upgrading it to the
/// stronger independently anchored acceptance tier.
pub fn send_local_receipted_frame<S: Read + Write>(
    stream: &mut S,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
    expected_header: &MailboxEnvelopeHeader,
    destination_key: &VerifyingKey,
) -> Result<SignedDestinationReceipt, Refusal> {
    send_expected_receipt(
        stream,
        capability,
        envelope,
        expected_header,
        destination_key,
        &[DeliveryOutcome::AcceptedLocalDurable],
    )
}

fn send_expected_receipt<S: Read + Write>(
    stream: &mut S,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
    expected_header: &MailboxEnvelopeHeader,
    destination_key: &VerifyingKey,
    allowed: &[DeliveryOutcome],
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
        || !allowed.contains(&receipt.receipt.outcome)
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
    validate_outbox(message)?;
    exchange(stream, &message.encode())
}

/// Require a signed V2 local acceptance for one guest-authored operation.
///
/// The guest cannot independently bind the host-sealed ciphertext commitment
/// to its plaintext. This is a trusted-host receipt, not host-blind delivery.
pub fn send_local_outbox_message<S: Read + Write>(
    stream: &mut S,
    message: &OutboxMessage,
    destination_key: &VerifyingKey,
    mailbox: MailboxId,
    execution_epoch: ExecutionEpoch,
) -> Result<SignedDestinationReceipt, Refusal> {
    validate_outbox(message)?;
    let signed: SignedDestinationReceipt = exchange(stream, &message.encode())?;
    verify_receipt(&signed, destination_key).map_err(|_| Refusal::Malformed)?;
    if signed.receipt.outcome != DeliveryOutcome::AcceptedLocalDurable
        || signed.receipt.message_id != message.message_id
        || signed.receipt.address.mailbox != mailbox
        || signed.receipt.execution_epoch != execution_epoch
        || (message.recipient.as_bytes() != &OWN_MAILBOX_RECIPIENT
            && signed.receipt.address.recipient != message.recipient)
    {
        return Err(Refusal::Malformed);
    }
    Ok(signed)
}

fn validate_outbox(message: &OutboxMessage) -> Result<(), Refusal> {
    if message.body.is_empty() {
        return Err(Refusal::Malformed);
    }
    if message.body.len() > MAX_MAILBOX_PAYLOAD_BYTES {
        return Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES));
    }
    Ok(())
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

    struct ReplyPeer(std::io::Cursor<Vec<u8>>);

    impl Read for ReplyPeer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ReplyPeer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

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
        let mut peer = ReplyPeer(std::io::Cursor::new(vec![
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

    #[test]
    fn guest_local_outbox_needs_a_signed_v2_receipt_for_its_own_identity() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::mailbox::{
            AuthorizationDomainId, DeliveryId, DestinationReceipt, ProtocolVersion,
            SignatureAlgorithm, TenantId,
        };

        let signer = SigningKey::from_bytes(&[9; 32]);
        let mailbox = MailboxId::from_bytes([3; 32]);
        let epoch = ExecutionEpoch::new(7).expect("epoch");
        let message = OutboxMessage {
            recipient: PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
            message_id: MessageId::from_bytes([4; 32]),
            body: b"hello".to_vec(),
        };
        let receipt = DestinationReceipt {
            protocol_version: ProtocolVersion::V2,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: DeliveryId::from_bytes([5; 32]),
            message_id: message.message_id,
            address: MailboxAddress {
                tenant: TenantId::from_bytes([6; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([7; 32]),
                mailbox,
                recipient: PrincipalId::from_bytes([8; 32]),
            },
            execution_epoch: epoch,
            outcome: DeliveryOutcome::AcceptedLocalDurable,
            observed_at_unix_ms: 1_500,
            ciphertext_commitment: [10; 32],
        };
        let signed = super::super::sign_receipt(receipt.clone(), &signer).expect("V2 receipt");
        let wire = serde_json::to_vec(&Ok::<_, Refusal>(signed.clone())).expect("verdict");
        let mut peer = ReplyPeer(std::io::Cursor::new(wire));
        assert_eq!(
            send_local_outbox_message(&mut peer, &message, &signer.verifying_key(), mailbox, epoch),
            Ok(signed)
        );

        let mut unit = ReplyPeer(std::io::Cursor::new(
            serde_json::to_vec(&Ok::<(), Refusal>(())).expect("legacy verdict"),
        ));
        assert_eq!(
            send_local_outbox_message(&mut unit, &message, &signer.verifying_key(), mailbox, epoch),
            Err(Refusal::Malformed),
            "a transport-level success cannot satisfy local acceptance"
        );
        for wrong in [
            DestinationReceipt {
                message_id: MessageId::from_bytes([11; 32]),
                ..receipt.clone()
            },
            DestinationReceipt {
                execution_epoch: ExecutionEpoch::new(8).expect("foreign epoch"),
                ..receipt.clone()
            },
            DestinationReceipt {
                outcome: DeliveryOutcome::AcceptedDurable,
                protocol_version: ProtocolVersion::V1,
                ..receipt.clone()
            },
        ] {
            let signed = super::super::sign_receipt(wrong.clone(), &signer).expect("signed wrong");
            let mut peer = ReplyPeer(std::io::Cursor::new(
                serde_json::to_vec(&Ok::<_, Refusal>(signed)).expect("wrong verdict"),
            ));
            assert_eq!(
                send_local_outbox_message(
                    &mut peer,
                    &message,
                    &signer.verifying_key(),
                    mailbox,
                    epoch,
                ),
                Err(Refusal::Malformed)
            );
        }
        let foreign = super::super::sign_receipt(receipt, &SigningKey::from_bytes(&[12; 32]))
            .expect("foreign authority signs");
        let mut peer = ReplyPeer(std::io::Cursor::new(
            serde_json::to_vec(&Ok::<_, Refusal>(foreign)).expect("foreign verdict"),
        ));
        assert_eq!(
            send_local_outbox_message(&mut peer, &message, &signer.verifying_key(), mailbox, epoch),
            Err(Refusal::Malformed)
        );
    }
}
