//! Bounded conversation operations inside a boot-pinned encrypted mailbox session.
//!
//! Session authentication does not grant mailbox operations. The endpoint must
//! independently verify current reader enrollment and capability authority.
//! The guest-local handoff reuses the reader socket; only the empty discriminator
//! travels before the encrypted handshake on the host/guest mailbox connection.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    ContentType, CorrelationId, MAX_MAILBOX_PAYLOAD_BYTES, MailboxAddress, MailboxEnvelopeHeader,
    MessageId, SignedMailboxCapability, SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
    SignedMailboxGuestReaderEnrollment,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use super::frame::Refusal;
use super::reader::MailboxReaderBootBinding;
use super::reader_wire::{self, ApplicationReaderRequest};
use crate::net::session::{Session, SessionRole, read_sealed_frame, write_sealed_frame};

const MAGIC: &[u8; 5] = b"MVMC\x02";
const PURPOSE: &str = "mvm.mailbox.conversation.v2";
/// The existing local mailbox API accepts waits of at most five minutes.
pub const MAX_WAIT_BUDGET: Duration = Duration::from_secs(300);
/// Includes bounded JSON/base64 expansion, canonical headers and sealed framing.
pub const MAX_FRAME_BYTES: usize = 2 * MAX_MAILBOX_PAYLOAD_BYTES + 64 * 1024;
/// Public admitted projection copied from the identity drive before privilege drop.
pub const CONVERSATION_BINDING_FILE: &str = "mailbox-conversation-binding.json";
/// Maximum admitted projection size, bounded before decoding.
pub const MAX_BINDING_BYTES: usize = 4096;

/// Guest operations carry canonical identities, never caller-selected authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConversationRequest {
    Call {
        destination: MailboxAddress,
        message_id: MessageId,
        correlation_id: CorrelationId,
        deadline_unix_ms: i64,
        content_type: ContentType,
        #[serde(with = "payload", rename = "payload_b64")]
        payload: Vec<u8>,
    },
    Receive {},
    Reply {
        request_message_id: MessageId,
        message_id: MessageId,
        content_type: ContentType,
        #[serde(with = "payload", rename = "payload_b64")]
        payload: Vec<u8>,
    },
    ReceiveResult {
        call_message_id: MessageId,
    },
    AckResult {
        call_message_id: MessageId,
        result_message_id: MessageId,
        lease: Box<SignedMailboxDeliveryLease>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed: Option<Box<SignedMailboxDeliveryAck>>,
    },
    AckRequest {
        request_message_id: MessageId,
        lease: Box<SignedMailboxDeliveryLease>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed: Option<Box<SignedMailboxDeliveryAck>>,
    },
    Possession {
        signature: Vec<u8>,
    },
}

impl std::fmt::Debug for ConversationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationRequest")
            .finish_non_exhaustive()
    }
}

/// A queued call is source intent, not destination acceptance or application completion.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConversationResponse {
    Queued {
        call_message_id: MessageId,
    },
    Delivery {
        header: Box<MailboxEnvelopeHeader>,
        lease: Box<SignedMailboxDeliveryLease>,
        #[serde(with = "payload", rename = "payload_b64")]
        payload: Vec<u8>,
    },
    Pending,
    TimedOut,
    Settled,
    Acknowledged,
    Challenge {
        enrollment: Box<SignedMailboxGuestReaderEnrollment>,
        capability: Box<SignedMailboxCapability>,
        challenge: [u8; 32],
    },
    Refused {
        reason: Refusal,
    },
}

impl std::fmt::Debug for ConversationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationResponse")
            .finish_non_exhaustive()
    }
}

/// Trusted current-boot facts supplied independently by guest boot and host admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationTarget {
    pub address: MailboxAddress,
    pub policy_epoch: u64,
}

impl ConversationTarget {
    /// Combine a provider's exact destination with this boot's independently minted reader.
    pub fn bind(&self, reader: &MailboxReaderBootBinding) -> Result<ConversationBinding, Refusal> {
        let binding = ConversationBinding {
            reader: reader.clone(),
            address: self.address,
            policy_epoch: self.policy_epoch,
        };
        binding.check_reader(reader)?;
        Ok(binding)
    }
}

/// Exact provider target and reader credentials projected into the admitted guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationBinding {
    pub reader: MailboxReaderBootBinding,
    pub address: MailboxAddress,
    pub policy_epoch: u64,
}

/// Created only after exact mailbox-purpose scope and peer authentication.
#[derive(Debug)]
pub struct ConversationSession {
    session: Session,
    binding: ConversationBinding,
}

impl ConversationSession {
    /// Verified guest scope, available only to the authenticated host-side holder.
    pub fn authenticated_host_binding(&self) -> Result<&ConversationBinding, Refusal> {
        if self.session.role() != SessionRole::Host {
            return Err(Refusal::NotAuthorized);
        }
        Ok(&self.binding)
    }
}

impl ConversationBinding {
    /// Refuse a projection for another boot, mailbox, epoch, plan, or authority key.
    pub fn check_reader(&self, reader: &MailboxReaderBootBinding) -> Result<(), Refusal> {
        if &self.reader != reader || self.address.mailbox != reader.mailbox {
            return Err(Refusal::NotAuthorized);
        }
        Ok(())
    }

    fn prefix(&self) -> Result<String, Refusal> {
        if self.address.mailbox != self.reader.mailbox {
            return Err(Refusal::NotAuthorized);
        }
        let bytes = serde_json::to_vec(&(PURPOSE, 1_u16, self)).map_err(|_| Refusal::Malformed)?;
        Ok(format!("{PURPOSE}:{}:", hex::encode(Sha256::digest(bytes))))
    }

    fn check_session_id(&self, id: &str) -> Result<(), Refusal> {
        let prefix = self.prefix()?;
        let nonce = id.strip_prefix(&prefix).ok_or(Refusal::NotAuthorized)?;
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
}

/// Start encryption only after the exact empty conversation discriminator.
/// A legacy report or bare application operation never selects this path.
pub fn is_session_request(body: &[u8]) -> bool {
    body == MAGIC
}

/// Establish a mailbox-purpose session and verify the admitted guest ACK identity.
pub fn host_session(
    stream: &mut (impl Read + Write),
    binding: &ConversationBinding,
    signer: SigningKey,
) -> Result<ConversationSession, Refusal> {
    if signer.verifying_key().to_bytes() != binding.reader.authority_key {
        return Err(Refusal::NotAuthorized);
    }
    let nonce: [u8; 32] = rand::random();
    if nonce == [0; 32] {
        return Err(Refusal::Unavailable);
    }
    let id = format!("{}{}", binding.prefix()?, hex::encode(nonce));
    let (session, peer) = Session::host(stream, &id, signer).map_err(|_| Refusal::NotAuthorized)?;
    if peer.to_bytes() != binding.reader.ack_public_key {
        return Err(Refusal::NotAuthorized);
    }
    Ok(ConversationSession {
        session,
        binding: binding.clone(),
    })
}

/// Guest verifies the exact admitted scope and fresh nonce before sending a payload.
pub fn guest_session(
    stream: &mut (impl Read + Write),
    binding: &ConversationBinding,
    signer: SigningKey,
) -> Result<ConversationSession, Refusal> {
    if signer.verifying_key().to_bytes() != binding.reader.ack_public_key {
        return Err(Refusal::NotAuthorized);
    }
    stream
        .write_all(&(MAGIC.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(MAGIC))
        .map_err(|_| Refusal::Unavailable)?;
    let anchor = VerifyingKey::from_bytes(&binding.reader.authority_key)
        .map_err(|_| Refusal::NotAuthorized)?;
    let (session, id) =
        Session::guest(stream, signer, &anchor).map_err(|_| Refusal::NotAuthorized)?;
    binding.check_session_id(&id)?;
    Ok(ConversationSession {
        session,
        binding: binding.clone(),
    })
}

/// One shared local socket dispatches old reader and new conversation operations.
#[derive(Debug)]
pub enum LocalRequest {
    Reader(ApplicationReaderRequest),
    Conversation(Box<ConversationInvocation>),
}

/// Caller-owned patience, not authority; forwarding consumes the original budget.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationInvocation {
    /// The requested operation; it carries no new authority.
    pub request: ConversationRequest,
    /// Remaining patience, bounded by the local API and independently signed expiry.
    pub wait_budget_ms: u64,
}

impl ConversationInvocation {
    /// Project only the unspent duration; sub-millisecond exhaustion is expired.
    pub fn new(request: ConversationRequest, remaining: Duration) -> Result<Self, Refusal> {
        let wait_budget_ms =
            u64::try_from(remaining.as_millis()).map_err(|_| Refusal::Malformed)?;
        if wait_budget_ms == 0 {
            return Err(Refusal::Expired);
        }
        let invocation = Self {
            request,
            wait_budget_ms,
        };
        invocation.deadline(Instant::now())?;
        Ok(invocation)
    }

    /// Validate untrusted duration and anchor it to request receipt, not forwarding.
    pub fn deadline(&self, received: Instant) -> Result<Instant, Refusal> {
        let budget = Duration::from_millis(self.wait_budget_ms);
        if budget.is_zero() || budget > MAX_WAIT_BUDGET {
            return Err(Refusal::Malformed);
        }
        received.checked_add(budget).ok_or(Refusal::Malformed)
    }
}

/// Convert signed wall-clock expiry once, without extending the monotonic caller deadline.
pub fn bounded_wait_deadline(
    caller: Instant,
    expires_unix_ms: i64,
    now_unix_ms: i64,
    now: Instant,
) -> Instant {
    let remaining = u64::try_from(expires_unix_ms.saturating_sub(now_unix_ms)).unwrap_or(0);
    caller.min(
        now.checked_add(Duration::from_millis(remaining))
            .unwrap_or(caller),
    )
}

/// Read bounded local input before deciding which mailbox operation family owns it.
pub fn read_local_request(stream: &mut impl Read) -> Result<LocalRequest, Refusal> {
    let body = reader_wire::read_body(stream, MAX_FRAME_BYTES)?;
    if body.starts_with(b"MVMC") {
        reader_wire::decode_versioned_body(&body, MAGIC)
            .map(|request| LocalRequest::Conversation(Box::new(request)))
    } else {
        reader_wire::decode_application_body(&body).map(LocalRequest::Reader)
    }
}

/// Send a local operation to the existing guest reader socket.
pub fn write_local_request(
    stream: &mut impl Write,
    request: &ConversationInvocation,
) -> Result<(), Refusal> {
    reader_wire::write_versioned_frame(stream, request, MAGIC, MAX_FRAME_BYTES)
}

/// Send the remaining caller budget before the independent possession proof.
pub fn send_invocation(
    stream: &mut impl Write,
    session: &mut ConversationSession,
    invocation: &ConversationInvocation,
) -> Result<(), Refusal> {
    send(stream, session, invocation)
}

/// Receive a versioned caller budget; signed authority still independently bounds it.
pub fn receive_invocation(
    stream: &mut impl Read,
    session: &mut ConversationSession,
) -> Result<ConversationInvocation, Refusal> {
    receive(stream, session)
}

/// Return the typed local result without putting plaintext on the host connection.
pub fn write_local_response(
    stream: &mut impl Write,
    response: &ConversationResponse,
) -> Result<(), Refusal> {
    reader_wire::write_versioned_frame(stream, response, MAGIC, MAX_FRAME_BYTES)
}

/// Receive one typed result from the existing guest-local reader socket.
pub fn read_local_response(stream: &mut impl Read) -> Result<ConversationResponse, Refusal> {
    let body = reader_wire::read_body(stream, MAX_FRAME_BYTES)?;
    reader_wire::decode_versioned_body(&body, MAGIC)
}

/// Encrypt one request in an authenticated mailbox-purpose session.
pub fn send_request(
    stream: &mut impl Write,
    session: &mut ConversationSession,
    request: &ConversationRequest,
) -> Result<(), Refusal> {
    send(stream, session, request)
}

/// Open one request only after exact session scope and peer checks have succeeded.
pub fn receive_request(
    stream: &mut impl Read,
    session: &mut ConversationSession,
) -> Result<ConversationRequest, Refusal> {
    receive(stream, session)
}

/// Encrypt a result; no raw-payload fallback exists.
pub fn send_response(
    stream: &mut impl Write,
    session: &mut ConversationSession,
    response: &ConversationResponse,
) -> Result<(), Refusal> {
    send(stream, session, response)
}

/// Open one result with strict session sequence and authentication checking.
pub fn receive_response(
    stream: &mut impl Read,
    session: &mut ConversationSession,
) -> Result<ConversationResponse, Refusal> {
    receive(stream, session)
}

fn send<T: Serialize>(
    stream: &mut impl Write,
    session: &mut ConversationSession,
    value: &T,
) -> Result<(), Refusal> {
    let mut body = Vec::new();
    reader_wire::write_versioned_frame(&mut body, value, MAGIC, MAX_FRAME_BYTES - 4096)?;
    let frame = session
        .session
        .seal(&body)
        .map_err(|_| Refusal::NotAuthorized)?;
    if write_sealed_frame(stream, &frame).is_err() {
        session
            .session
            .poison_send(frame.sequence, "mailbox transport write failed");
        return Err(Refusal::Unavailable);
    }
    Ok(())
}

fn receive<T: DeserializeOwned>(
    stream: &mut impl Read,
    session: &mut ConversationSession,
) -> Result<T, Refusal> {
    let frame = read_sealed_frame(stream, MAX_FRAME_BYTES).map_err(|error| match error {
        crate::net::session::SessionError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Refusal::Expired
        }
        crate::net::session::SessionError::Io(_) => Refusal::Unavailable,
        _ => Refusal::Malformed,
    })?;
    let plaintext = zeroize::Zeroizing::new(
        session
            .session
            .open(&frame)
            .map_err(|_| Refusal::NotAuthorized)?,
    );
    let mut input = plaintext.as_slice();
    let body = reader_wire::read_body(&mut input, MAX_FRAME_BYTES)?;
    if !input.is_empty() {
        return Err(Refusal::Malformed);
    }
    reader_wire::decode_versioned_body(&body, MAGIC)
}

mod payload {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.len() > super::MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(serde::ser::Error::custom("mailbox payload exceeds limit"));
        }
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > super::MAX_FRAME_BYTES {
            return Err(D::Error::custom("mailbox payload exceeds limit"));
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| D::Error::custom("invalid mailbox payload"))?;
        if bytes.len() > super::MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(D::Error::custom("mailbox payload exceeds limit"));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, BootId, ExecutionEpoch, MailboxId, PrincipalId, TenantId,
    };
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn caller_wait_budget_only_narrows_signed_expiry_and_is_not_restarted() {
        let now = Instant::now();
        let invocation = ConversationInvocation::new(request(), Duration::from_secs(60)).unwrap();
        let caller = invocation.deadline(now).unwrap();
        let forwarded_at = now + Duration::from_secs(10);
        let forwarded =
            ConversationInvocation::new(request(), caller.saturating_duration_since(forwarded_at))
                .unwrap();
        assert_eq!(forwarded.deadline(forwarded_at).unwrap(), caller);
        assert_eq!(
            bounded_wait_deadline(caller, 25_000, 5_000, now),
            now + Duration::from_secs(20)
        );
        assert_eq!(bounded_wait_deadline(caller, 500_000, 5_000, now), caller);
        assert_eq!(bounded_wait_deadline(caller, 4_999, 5_000, now), now);
        for budget in [0, 300_001, u64::MAX] {
            let invalid = ConversationInvocation {
                request: request(),
                wait_budget_ms: budget,
            };
            assert!(invalid.deadline(now).is_err());
        }
        assert!(matches!(
            ConversationInvocation::new(request(), Duration::ZERO),
            Err(Refusal::Expired)
        ));
    }

    #[test]
    fn local_conversation_requires_explicit_v2_budget_and_preserves_operation() {
        let invocation = ConversationInvocation::new(request(), Duration::from_secs(90)).unwrap();
        let mut bytes = Vec::new();
        write_local_request(&mut bytes, &invocation).unwrap();
        let LocalRequest::Conversation(decoded) =
            read_local_request(&mut bytes.as_slice()).unwrap()
        else {
            panic!("conversation family");
        };
        assert_eq!(decoded.request, invocation.request);
        assert_eq!(decoded.wait_budget_ms, 90_000);
        bytes[8] = 1;
        assert!(matches!(
            read_local_request(&mut bytes.as_slice()),
            Err(Refusal::Malformed)
        ));
    }

    fn binding() -> ConversationBinding {
        ConversationBinding {
            reader: MailboxReaderBootBinding {
                plan_id: PlanId("admitted-plan".into()),
                plan_nonce: Nonce::from_bytes([1; 16]),
                mailbox: MailboxId::from_bytes([2; 32]),
                authority_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
                execution_epoch: ExecutionEpoch::new(1).unwrap(),
                boot: BootId::from_bytes([4; 32]),
                guest_identity_key: [5; 32],
                ack_public_key: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            },
            address: MailboxAddress {
                tenant: TenantId::from_bytes([7; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([8; 32]),
                mailbox: MailboxId::from_bytes([2; 32]),
                recipient: PrincipalId::from_bytes([9; 32]),
            },
            policy_epoch: 1,
        }
    }

    fn sockets() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (b, _) = listener.accept().unwrap();
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

    fn request() -> ConversationRequest {
        ConversationRequest::Reply {
            request_message_id: MessageId::from_bytes([10; 32]),
            message_id: MessageId::from_bytes([11; 32]),
            content_type: ContentType::parse("application/octet-stream", 1).unwrap(),
            payload: b"secret application bytes".to_vec(),
        }
    }

    #[test]
    fn invocation_budget_roundtrips_inside_the_authenticated_session() {
        let (mut guest, mut host) = sockets();
        let worker = std::thread::spawn(move || {
            assert!(is_session_request(
                &reader_wire::read_body(&mut host, MAX_FRAME_BYTES).unwrap()
            ));
            let mut session =
                host_session(&mut host, &binding(), SigningKey::from_bytes(&[3; 32])).unwrap();
            let invocation = receive_invocation(&mut host, &mut session).unwrap();
            assert_eq!(invocation.request, request());
            assert_eq!(invocation.wait_budget_ms, 90_000);
            send_response(&mut host, &mut session, &ConversationResponse::Acknowledged).unwrap();
        });
        let mut session =
            guest_session(&mut guest, &binding(), SigningKey::from_bytes(&[6; 32])).unwrap();
        let invocation = ConversationInvocation::new(request(), Duration::from_secs(90)).unwrap();
        send_invocation(&mut guest, &mut session, &invocation).unwrap();
        assert_eq!(
            receive_response(&mut guest, &mut session).unwrap(),
            ConversationResponse::Acknowledged
        );
        worker.join().unwrap();
        assert!(
            matches!(
                receive_response(&mut guest, &mut session),
                Err(Refusal::Unavailable)
            ),
            "transport EOF is not malformed application data"
        );
    }

    #[test]
    fn actual_session_roundtrip_is_sealed_and_replay_checked() {
        let (mut guest, mut host) = sockets();
        let worker = std::thread::spawn(move || {
            assert!(is_session_request(
                &reader_wire::read_body(&mut host, MAX_FRAME_BYTES).unwrap()
            ));
            let mut session =
                host_session(&mut host, &binding(), SigningKey::from_bytes(&[3; 32])).unwrap();
            let frame = read_sealed_frame(&mut host, MAX_FRAME_BYTES).unwrap();
            assert!(
                !frame
                    .ciphertext
                    .windows(24)
                    .any(|bytes| bytes == b"secret application bytes")
            );
            let plaintext = session.session.open(&frame).unwrap();
            let body = reader_wire::read_body(&mut plaintext.as_slice(), MAX_FRAME_BYTES).unwrap();
            let opened: ConversationRequest =
                reader_wire::decode_versioned_body(&body, MAGIC).unwrap();
            assert_eq!(opened, request());
            assert!(
                session.session.open(&frame).is_err(),
                "session replay refused"
            );
        });
        let mut session =
            guest_session(&mut guest, &binding(), SigningKey::from_bytes(&[6; 32])).unwrap();
        send_request(&mut guest, &mut session, &request()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn wrong_complete_binding_never_sends_application_payload() {
        let (mut guest, mut host) = sockets();
        let worker = std::thread::spawn(move || {
            assert!(is_session_request(
                &reader_wire::read_body(&mut host, MAX_FRAME_BYTES).unwrap()
            ));
            let mut session =
                host_session(&mut host, &binding(), SigningKey::from_bytes(&[3; 32])).unwrap();
            assert!(receive_request(&mut host, &mut session).is_err());
        });
        let mut wrong = binding();
        wrong.policy_epoch += 1;
        assert!(guest_session(&mut guest, &wrong, SigningKey::from_bytes(&[6; 32])).is_err());
        drop(guest);
        worker.join().unwrap();
        let expected = binding().prefix().unwrap();
        assert!(
            binding()
                .check_session_id(&format!("{expected}{}", "0".repeat(64)))
                .is_err()
        );
        assert!(
            binding()
                .check_session_id(&format!("{expected}{}suffix", "a".repeat(64)))
                .is_err()
        );
    }

    #[test]
    fn encrypted_request_and_response_helpers_roundtrip() {
        let (mut guest, mut host) = sockets();
        let worker = std::thread::spawn(move || {
            assert!(is_session_request(
                &reader_wire::read_body(&mut host, MAX_FRAME_BYTES).unwrap()
            ));
            let mut session =
                host_session(&mut host, &binding(), SigningKey::from_bytes(&[3; 32])).unwrap();
            assert_eq!(receive_request(&mut host, &mut session).unwrap(), request());
            send_response(&mut host, &mut session, &ConversationResponse::Pending).unwrap();
        });
        let mut session =
            guest_session(&mut guest, &binding(), SigningKey::from_bytes(&[6; 32])).unwrap();
        send_request(&mut guest, &mut session, &request()).unwrap();
        assert_eq!(
            receive_response(&mut guest, &mut session).unwrap(),
            ConversationResponse::Pending
        );
        worker.join().unwrap();
    }

    #[test]
    fn full_boot_plan_and_mailbox_scope_are_bound_not_just_a_prefix() {
        let original = binding();
        let id = format!("{}{}", original.prefix().unwrap(), "a".repeat(64));
        for field in 0..8 {
            let mut other = original.clone();
            match field {
                0 => other.reader.plan_id = PlanId("foreign-plan".into()),
                1 => other.reader.plan_nonce = Nonce::from_bytes([22; 16]),
                2 => other.reader.boot = BootId::from_bytes([22; 32]),
                3 => other.reader.execution_epoch = ExecutionEpoch::new(2).unwrap(),
                4 => other.address.tenant = TenantId::from_bytes([22; 32]),
                5 => {
                    other.address.authorization_domain = AuthorizationDomainId::from_bytes([22; 32])
                }
                6 => other.address.recipient = PrincipalId::from_bytes([22; 32]),
                7 => other.policy_epoch += 1,
                _ => unreachable!(),
            }
            assert!(
                other.check_session_id(&id).is_err(),
                "field {field} must be pinned"
            );
        }
    }

    #[test]
    fn old_local_reader_and_conversation_frames_remain_distinct() {
        let mut bytes = Vec::new();
        reader_wire::write_application_request(&mut bytes, &ApplicationReaderRequest::Receive)
            .unwrap();
        assert!(matches!(
            read_local_request(&mut bytes.as_slice()).unwrap(),
            LocalRequest::Reader(ApplicationReaderRequest::Receive)
        ));
        bytes.clear();
        write_local_request(
            &mut bytes,
            &ConversationInvocation::new(request(), Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            read_local_request(&mut bytes.as_slice()).unwrap(),
            LocalRequest::Conversation(_)
        ));
        assert!(
            !is_session_request(&bytes[4..]),
            "bare application cannot start host exchange"
        );
        assert!(!is_session_request(b"MVMC\x01"));
        assert!(read_local_request(&mut u32::MAX.to_be_bytes().as_slice()).is_err());
    }
}
