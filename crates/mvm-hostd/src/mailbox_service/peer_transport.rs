//! Encrypted fixed-pair holder transport; no mailbox payload crosses the broker.

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    DeliveryOutcome, DestinationRouteToken, MAX_ENCODED_ENVELOPE_BYTES, ProtocolVersion,
    SignedDestinationReceipt,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::net::session::{
    Session, read_json_frame, read_sealed_frame, write_json_frame, write_sealed_frame,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::actor_operations::{ActorDispatch, ActorPeerFrame};
use crate::mailbox_launch::actor_template::{ActorPeerBinding, ActorPeerRole};

const MAGIC: &[u8; 5] = b"MVMP\x01";
const PURPOSE: &str = "mvm.mailbox.peer.v1";
const MAX_REQUEST: usize = MAX_ENCODED_ENVELOPE_BYTES + 64 * 1024;
const MAX_REPLY: usize = 16 * 1024;
const SESSION_OVERHEAD: usize = 4096;
const IO_DEADLINE: Duration = Duration::from_secs(5);
/// Only a discriminator and one canonical opaque route token precede encryption.
pub(super) const PREFACE_BYTES: usize = 37;

/// Decode only the exact opaque selector, never an address or capability.
pub(super) fn route_from_preface(body: &[u8]) -> Result<DestinationRouteToken, Refusal> {
    let token = body.strip_prefix(MAGIC).ok_or(Refusal::Malformed)?;
    Ok(DestinationRouteToken::from_bytes(
        token.try_into().map_err(|_| Refusal::Malformed)?,
    ))
}

fn outgoing_route(peer: &ActorPeerBinding) -> DestinationRouteToken {
    match peer.role {
        ActorPeerRole::Parent => peer.call.routing.destination_route_token,
        ActorPeerRole::Child => peer.reply_routing.destination_route_token,
    }
}

fn incoming_route(peer: &ActorPeerBinding) -> DestinationRouteToken {
    match peer.role {
        ActorPeerRole::Parent => peer.reply_routing.destination_route_token,
        ActorPeerRole::Child => peer.call.routing.destination_route_token,
    }
}

fn local_key(peer: &ActorPeerBinding) -> Result<VerifyingKey, Refusal> {
    VerifyingKey::from_bytes(&match peer.role {
        ActorPeerRole::Parent => peer.parent_authority_key,
        ActorPeerRole::Child => peer.child_authority_key,
    })
    .map_err(|_| Refusal::NotAuthorized)
}

fn remote_key(peer: &ActorPeerBinding) -> Result<VerifyingKey, Refusal> {
    VerifyingKey::from_bytes(&match peer.role {
        ActorPeerRole::Parent => peer.child_authority_key,
        ActorPeerRole::Child => peer.parent_authority_key,
    })
    .map_err(|_| Refusal::NotAuthorized)
}

fn prefix(peer: &ActorPeerBinding, route: DestinationRouteToken) -> Result<String, Refusal> {
    let parent_plan = peer.parent_plan_binding.ok_or(Refusal::NotAuthorized)?;
    let child_plan = peer.child_plan_binding.ok_or(Refusal::NotAuthorized)?;
    if parent_plan == [0; 32] || child_plan == [0; 32] {
        return Err(Refusal::NotAuthorized);
    }
    let context = serde_json::to_vec(&(
        PURPOSE,
        1_u16,
        peer.parent_address,
        peer.child_address,
        peer.epoch,
        peer.call.capability.policy_epoch,
        parent_plan,
        child_plan,
        route,
        peer.parent_authority_key,
        peer.child_authority_key,
    ))
    .map_err(|_| Refusal::Malformed)?;
    Ok(format!(
        "{PURPOSE}:{}:",
        hex::encode(Sha256::digest(context))
    ))
}

fn check_id(prefix: &str, id: &str) -> Result<(), Refusal> {
    let nonce = id.strip_prefix(prefix).ok_or(Refusal::NotAuthorized)?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || nonce.bytes().all(|byte| byte == b'0')
    {
        return Err(Refusal::NotAuthorized);
    }
    Ok(())
}

fn outbound_frame(peer: &ActorPeerBinding, frame: &ActorPeerFrame) -> Result<(), Refusal> {
    if !matches!(
        (peer.role, frame),
        (ActorPeerRole::Parent, ActorPeerFrame::Call { .. })
            | (ActorPeerRole::Child, ActorPeerFrame::Reply { .. })
    ) || frame.envelope().routing.destination_route_token != outgoing_route(peer)
    {
        return Err(Refusal::NotAuthorized);
    }
    frame
        .envelope()
        .validate_bounds()
        .map_err(|_| Refusal::Malformed)
}

/// Send one exact persisted packet, with the local holder's own authority signer.
/// A failure may follow destination acceptance; never reseal or replace message IDs.
pub fn send_peer(
    dispatch: &ActorDispatch,
    signer: SigningKey,
) -> Result<SignedDestinationReceipt, Refusal> {
    outbound_frame(&dispatch.peer, &dispatch.frame)?;
    if signer.verifying_key() != local_key(&dispatch.peer)? {
        return Err(Refusal::NotAuthorized);
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Refusal::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| Refusal::Unavailable)?;
    if now >= dispatch.frame.envelope().routing.expires_at_unix_ms
        || now >= dispatch.peer.send_capability.grant.expires_at_unix_ms
    {
        return Err(Refusal::Expired);
    }
    let deadline = Instant::now() + IO_DEADLINE;
    let mut stream = mvm_agentd::vsock::connect_unix_before(&dispatch.peer.peer_socket, deadline)
        .map_err(|_| Refusal::Unavailable)?;
    mvm_agentd::vsock::run_with_stream_deadline(&mut stream, deadline, |stream| {
        Ok(send_on(stream, dispatch, signer))
    })
    .map_err(|_| Refusal::Unavailable)?
}

fn send_on(
    stream: &mut (impl Read + Write),
    dispatch: &ActorDispatch,
    signer: SigningKey,
) -> Result<SignedDestinationReceipt, Refusal> {
    let route = outgoing_route(&dispatch.peer);
    let scope = prefix(&dispatch.peer, route)?;
    stream
        .write_all(&(PREFACE_BYTES as u32).to_be_bytes())
        .and_then(|()| stream.write_all(MAGIC))
        .and_then(|()| stream.write_all(route.as_bytes()))
        .map_err(|_| Refusal::Unavailable)?;
    let (mut session, id) = Session::guest(stream, signer, &remote_key(&dispatch.peer)?)
        .map_err(|_| Refusal::NotAuthorized)?;
    check_id(&scope, &id)?;
    send(stream, &mut session, &dispatch.frame, MAX_REQUEST)?;
    let receipt: Result<SignedDestinationReceipt, Refusal> =
        receive(stream, &mut session, MAX_REPLY)?;
    let receipt = receipt?;
    mvm_core::mailbox::verify_receipt(&receipt, &remote_key(&dispatch.peer)?)
        .map_err(|_| Refusal::NotAuthorized)?;
    let envelope = dispatch.frame.envelope();
    if receipt.receipt.protocol_version != ProtocolVersion::V2
        || receipt.receipt.message_id != dispatch.message_id
        || receipt.receipt.delivery_id != envelope.routing.delivery_id
        || receipt.receipt.ciphertext_commitment != envelope.ciphertext_commitment
        || receipt.receipt.address != dispatch.peer.peer_address()
        || receipt.receipt.execution_epoch != dispatch.peer.epoch
    {
        return Err(Refusal::NotAuthorized);
    }
    match receipt.receipt.outcome {
        DeliveryOutcome::AcceptedLocalDurable => Ok(receipt),
        DeliveryOutcome::Expired => Err(Refusal::Expired),
        DeliveryOutcome::AcceptedEphemeral
        | DeliveryOutcome::AcceptedDurable
        | DeliveryOutcome::Duplicate
        | DeliveryOutcome::Refused
        | DeliveryOutcome::Full
        | DeliveryOutcome::Unavailable
        | DeliveryOutcome::Late
        | DeliveryOutcome::DeadLettered => Err(Refusal::NotAuthorized),
    }
}

/// Authenticate the exact fixed pair before passing a sealed canonical packet to admission.
pub(super) fn receive_peer(
    stream: &mut (impl Read + Write),
    peer: &ActorPeerBinding,
    signer: SigningKey,
    accept: impl FnOnce(ActorPeerFrame) -> Result<SignedDestinationReceipt, Refusal>,
) -> Result<(), Refusal> {
    if signer.verifying_key() != local_key(peer)? {
        return Err(Refusal::NotAuthorized);
    }
    let route = incoming_route(peer);
    let scope = prefix(peer, route)?;
    let nonce: [u8; 32] = rand::random();
    if nonce == [0; 32] {
        return Err(Refusal::Unavailable);
    }
    let id = format!("{scope}{}", hex::encode(nonce));
    let (mut session, authenticated) =
        Session::host(stream, &id, signer).map_err(|_| Refusal::NotAuthorized)?;
    if authenticated != remote_key(peer)? {
        return Err(Refusal::NotAuthorized);
    }
    let frame: ActorPeerFrame = receive(stream, &mut session, MAX_REQUEST)?;
    let accepted = if matches!(
        (peer.role, &frame),
        (ActorPeerRole::Child, ActorPeerFrame::Call { .. })
            | (ActorPeerRole::Parent, ActorPeerFrame::Reply { .. })
    ) && frame.envelope().routing.destination_route_token == route
    {
        accept(frame)
    } else {
        Err(Refusal::NotAuthorized)
    };
    send(stream, &mut session, &accepted, MAX_REPLY)
}

fn send<T: Serialize>(
    stream: &mut impl Write,
    session: &mut Session,
    value: &T,
    limit: usize,
) -> Result<(), Refusal> {
    let mut plaintext = Zeroizing::new(Vec::new());
    write_json_frame(&mut *plaintext, value, limit).map_err(|_| Refusal::Oversized(limit))?;
    let frame = session
        .seal(&plaintext)
        .map_err(|_| Refusal::NotAuthorized)?;
    if write_sealed_frame(stream, &frame).is_err() {
        session.poison_send(frame.sequence, "peer mailbox write failed");
        return Err(Refusal::Unavailable);
    }
    Ok(())
}

fn receive<T: DeserializeOwned>(
    stream: &mut impl Read,
    session: &mut Session,
    limit: usize,
) -> Result<T, Refusal> {
    let frame =
        read_sealed_frame(stream, limit + SESSION_OVERHEAD).map_err(|_| Refusal::Malformed)?;
    let plaintext = Zeroizing::new(session.open(&frame).map_err(|_| Refusal::NotAuthorized)?);
    let mut input = plaintext.as_slice();
    let value = read_json_frame(&mut input, limit).map_err(|_| Refusal::Malformed)?;
    if !input.is_empty() {
        return Err(Refusal::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{
        CapabilityId, CapabilityOperations, CorrelationId, DestinationReceipt, ExecutionEpoch,
        MailboxAddress, MailboxGrant, MailboxId, MailboxMessageKind, MailboxOperation, MessageId,
        ReplyRoute, SignatureAlgorithm,
    };
    use mvm_core::crypto::aead::Key;
    use mvm_core::mailbox::{SealRequest, seal_envelope, sign_capability, sign_receipt};
    use std::os::unix::net::UnixStream;

    struct Fixture {
        dispatch: ActorDispatch,
        parent: SigningKey,
        child: SigningKey,
    }

    fn fixture() -> Fixture {
        let keys = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let endpoint = |id| {
            let mailbox = MailboxId::from_bytes([id; 32]);
            let epoch = ExecutionEpoch::new(1).unwrap();
            let grant = MailboxGrant {
                mailbox,
                epoch,
                report: None,
                retention: None,
                authority_key: crate::mailbox_launch::authority_key_for(
                    keys.path(),
                    &mailbox,
                    epoch,
                )
                .unwrap()
                .to_bytes(),
            };
            crate::mailbox_launch::host_trust(keys.path(), &grant, &Key::from_bytes([41; 32]))
                .unwrap()
                .1
        };
        let parent = endpoint(1);
        let mut child = endpoint(2);
        let address =
            |header: &mvm_contract::protocol::mailbox::MailboxEnvelopeHeader| MailboxAddress {
                tenant: header.tenant,
                authorization_domain: header.authorization_domain,
                mailbox: header.mailbox,
                recipient: header.recipient,
            };
        let parent_address = address(&parent.header);
        let child_address = address(&child.header);
        child.header.kind = MailboxMessageKind::Call;
        child.header.sender = parent.header.sender;
        child.header.sender_boot = parent.header.sender_boot;
        child.header.message_id = MessageId::from_bytes([42; 32]);
        child.header.correlation_id = CorrelationId::from_bytes([44; 32]);
        child.header.plaintext_len = 5;
        let mut reply = parent.capability.clone();
        reply.capability_id = CapabilityId::from_bytes([43; 32]);
        reply.subject = child_address.recipient;
        reply.operations = CapabilityOperations::from_operations(&[MailboxOperation::Reply]);
        reply.message_kinds = vec![MailboxMessageKind::Reply];
        let reply = sign_capability(reply, &parent.authority_key).unwrap();
        child.header.reply_to = Some(ReplyRoute {
            address: parent_address,
            capability_id: reply.grant.capability_id,
        });
        child.capability.subject = parent.header.sender;
        child.capability.message_kinds = vec![MailboxMessageKind::Call];
        let send = sign_capability(child.capability.clone(), &child.authority_key).unwrap();
        let envelope = seal_envelope(
            SealRequest {
                header: child.header.clone(),
                routing: child.routing.clone(),
                plaintext: b"hello",
            },
            &child.encryption_key,
            &parent.sender_key,
        )
        .unwrap();
        let template = crate::mailbox_launch::MailboxTemplate {
            header: child.header.clone(),
            routing: child.routing.clone(),
            capability: child.capability.clone(),
        };
        // This fixture supplies a pair directly to test transport authentication;
        // provider admission and journal acceptance have separate integration witnesses.
        let peer: ActorPeerBinding = serde_json::from_value(serde_json::json!({
            "role": "Parent", "parent_address": parent_address, "child_address": child_address,
            "parent_plan_binding": vec![11_u8; 32], "child_plan_binding": vec![12_u8; 32],
            "epoch": child.header.execution_epoch, "call": template,
            "reply_header": parent.header, "reply_routing": parent.routing,
            "send_capability": send, "parent_receive": reply, "child_receive": send,
            "parent_authority_key": parent.authority_key.verifying_key().to_bytes(),
            "child_authority_key": child.authority_key.verifying_key().to_bytes(),
            "parent_sender_key": parent.sender_key.verifying_key().to_bytes(),
            "child_sender_key": child.sender_key.verifying_key().to_bytes(),
            "peer_socket": "/unused-transport-fixture",
            "call_key": child.encryption_key.expose_bytes(), "reply_key": parent.encryption_key.expose_bytes()
        })).unwrap();
        Fixture {
            dispatch: ActorDispatch {
                message_id: child.header.message_id,
                peer,
                frame: ActorPeerFrame::Call {
                    envelope,
                    reply_capability: Box::new(reply),
                },
            },
            parent: parent.authority_key,
            child: child.authority_key,
        }
    }

    fn sockets() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        for stream in [&a, &b] {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        (a, b)
    }

    struct Captured {
        stream: UnixStream,
        written: Vec<u8>,
    }
    impl Read for Captured {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.stream.read(bytes)
        }
    }
    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let n = self.stream.write(bytes)?;
            self.written.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.stream.flush()
        }
    }

    #[test]
    fn pair_session_encrypts_packet_and_verifies_exact_receipt() {
        for wrong_id in [false, true] {
            let fixture = fixture();
            let (source, mut destination) = sockets();
            let mut source = Captured {
                stream: source,
                written: Vec::new(),
            };
            let mut peer = fixture.dispatch.peer.clone();
            peer.role = ActorPeerRole::Child;
            let expected = fixture.dispatch.frame.clone();
            let message_id = fixture.dispatch.message_id;
            let child = fixture.child.clone();
            let receiver = std::thread::spawn(move || {
                let body = super::super::read_frame(PREFACE_BYTES, &mut destination).unwrap();
                assert_eq!(route_from_preface(&body).unwrap(), incoming_route(&peer));
                receive_peer(&mut destination, &peer, child.clone(), |frame| {
                    assert_eq!(frame, expected);
                    let envelope = frame.envelope();
                    sign_receipt(
                        DestinationReceipt {
                            protocol_version: ProtocolVersion::V2,
                            signature_algorithm: SignatureAlgorithm::ED25519,
                            delivery_id: envelope.routing.delivery_id,
                            message_id: if wrong_id {
                                MessageId::from_bytes([99; 32])
                            } else {
                                message_id
                            },
                            address: peer.child_address,
                            execution_epoch: peer.epoch,
                            outcome: DeliveryOutcome::AcceptedLocalDurable,
                            observed_at_unix_ms: 1,
                            ciphertext_commitment: envelope.ciphertext_commitment,
                        },
                        &child,
                    )
                    .map_err(|_| Refusal::NotAuthorized)
                })
                .unwrap();
            });
            let result = send_on(&mut source, &fixture.dispatch, fixture.parent);
            assert_eq!(result.is_err(), wrong_id);
            assert!(
                !source
                    .written
                    .windows(b"reply_capability".len())
                    .any(|bytes| bytes == b"reply_capability"),
                "capability metadata is inside the encrypted session"
            );
            receiver.join().unwrap();
        }
    }

    #[test]
    fn peer_scope_and_role_are_exact_and_missing_plan_refuses() {
        let fixture = fixture();
        let peer = fixture.dispatch.peer;
        let route = outgoing_route(&peer);
        let expected = prefix(&peer, route).unwrap();
        let mut other = peer.clone();
        other.child_plan_binding = Some([55; 32]);
        assert_ne!(prefix(&other, route).unwrap(), expected);
        other.child_plan_binding = None;
        assert!(prefix(&other, route).is_err());
        other.role = ActorPeerRole::Child;
        assert!(outbound_frame(&other, &fixture.dispatch.frame).is_err());
        assert!(check_id(&expected, &format!("{expected}{}extra", "a".repeat(64))).is_err());
        assert!(route_from_preface(b"MVMP\x01").is_err());
    }
}
