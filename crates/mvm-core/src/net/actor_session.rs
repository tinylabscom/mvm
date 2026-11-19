//! Boot-bound lifecycle channels over the shared authenticated session primitive.

use std::io::{Read, Write};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::workload_actor::{
    ActorRequest, ActorResponse, MAX_ACTOR_REQUEST_BYTES, MAX_ACTOR_RESPONSE_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::session::{Session, SessionError, read_sealed_frame, write_sealed_frame};

/// Token-free broker stream selector, distinct from a bounded JSON length prefix.
pub const ACTOR_ROUTE_PREFACE: [u8; 4] = *b"MVAC";
/// Public admitted context on the identity drive and in the guest runtime directory.
pub const ACTOR_BINDING_FILE: &str = "actor-session.json";
/// Independent guest-held actor signing seed.
pub const ACTOR_GUEST_KEY_FILE: &str = "actor-guest-signing-key";
/// Maximum serialized identity binding, bounded before allocation.
pub const MAX_ACTOR_BINDING_BYTES: usize = 4096;

/// A stream whose individual reads and writes share one absolute deadline.
#[cfg(unix)]
pub struct ActorDeadlineStream {
    stream: std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
}

#[cfg(unix)]
impl ActorDeadlineStream {
    /// Apply one absolute deadline to an already owned socket.
    pub fn new(
        stream: std::os::unix::net::UnixStream,
        deadline: std::time::Instant,
    ) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self { stream, deadline })
    }

    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        self.deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "actor deadline"))
    }

    fn ready(&self, events: rustix::event::PollFlags) -> std::io::Result<()> {
        loop {
            let remaining = self.remaining()?;
            let timeout = rustix::event::Timespec::try_from(remaining).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "actor deadline exceeds clock range",
                )
            })?;
            let mut fds = [rustix::event::PollFd::new(&self.stream, events)];
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                Ok(_) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(unix)]
impl Read for ActorDeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.ready(rustix::event::PollFlags::IN)?;
            match self.stream.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

#[cfg(unix)]
impl Write for ActorDeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.ready(rustix::event::PollFlags::OUT)?;
            match self.stream.write(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Public context projected only after the parent workload has been admitted.
///
/// Key possession authenticates this context, not permission to launch a child.
/// The lifecycle authority must independently verify every operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorSessionBinding {
    pub protocol_version: u8,
    pub purpose: String,
    pub tenant: String,
    pub workflow: String,
    pub boot_id: String,
    pub plan_digest: [u8; 32],
    pub epoch: u64,
    pub controller_generation: u64,
    pub key_generation: u64,
    pub guest_public_key: [u8; 32],
    pub host_public_key: [u8; 32],
}

impl ActorSessionBinding {
    /// Validate and bind the complete admitted context into the session transcript.
    pub fn session_id(&self) -> Result<String, SessionError> {
        if self.protocol_version != 1
            || self.purpose != "host.actor.v1"
            || self.epoch == 0
            || self.controller_generation == 0
            || self.key_generation == 0
            || self.guest_public_key == self.host_public_key
            || [&self.guest_public_key, &self.host_public_key]
                .iter()
                .any(|bytes| VerifyingKey::from_bytes(bytes).map_or(true, |key| key.is_weak()))
            || [&self.tenant, &self.workflow, &self.boot_id]
                .iter()
                .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(SessionError::InvalidHandshake(
                "invalid actor binding".into(),
            ));
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|_| SessionError::InvalidHandshake("invalid actor binding".into()))?;
        Ok(format!(
            "host.actor.v1:{}",
            hex::encode(Sha256::digest(bytes))
        ))
    }
}

/// One authenticated channel. Any exchange failure requires discarding the channel.
///
/// Session keys are zeroized by the underlying session when this holder is dropped.
/// This holder has no admission, reservation, signing-authority or backend handle.
#[derive(Debug)]
pub struct ActorSession {
    session: Session,
}

impl ActorSession {
    /// Authenticate the guest against this boot's pinned actor-only identity.
    pub fn host(
        stream: &mut (impl Read + Write),
        binding: &ActorSessionBinding,
        key: SigningKey,
    ) -> Result<Self, SessionError> {
        let id = binding.session_id()?;
        if key.verifying_key().to_bytes() != binding.host_public_key {
            return Err(identity_error());
        }
        let (session, peer) = Session::host(stream, &id, key)?;
        if peer.to_bytes() != binding.guest_public_key {
            return Err(identity_error());
        }
        Ok(Self { session })
    }

    /// Pin the host and reject a different purpose, generation, plan, or boot.
    pub fn guest(
        stream: &mut (impl Read + Write),
        binding: &ActorSessionBinding,
        key: SigningKey,
    ) -> Result<Self, SessionError> {
        let expected = binding.session_id()?;
        if key.verifying_key().to_bytes() != binding.guest_public_key {
            return Err(identity_error());
        }
        let anchor =
            VerifyingKey::from_bytes(&binding.host_public_key).map_err(|_| identity_error())?;
        let (session, id) = Session::guest(stream, key, &anchor)?;
        if id != expected {
            return Err(SessionError::InvalidHandshake(
                "actor context mismatch".into(),
            ));
        }
        Ok(Self { session })
    }

    /// Send the canonical lifecycle request, never a bare broker call.
    pub fn send_request(
        &mut self,
        stream: &mut impl Write,
        request: &ActorRequest,
    ) -> Result<(), SessionError> {
        self.send(stream, request, MAX_ACTOR_REQUEST_BYTES)
    }

    /// Open and strictly decode a bounded lifecycle request.
    pub fn receive_request(
        &mut self,
        stream: &mut impl Read,
    ) -> Result<ActorRequest, SessionError> {
        let plaintext = self.receive(stream, MAX_ACTOR_REQUEST_BYTES)?;
        ActorRequest::decode(&plaintext)
            .map_err(|_| SessionError::InvalidHandshake("invalid actor request".into()))
    }

    /// Send the canonical lifecycle response without exposing tokens to relays.
    pub fn send_response(
        &mut self,
        stream: &mut impl Write,
        response: &ActorResponse,
    ) -> Result<(), SessionError> {
        self.send(stream, response, MAX_ACTOR_RESPONSE_BYTES)
    }

    /// Open and strictly decode a bounded lifecycle response.
    pub fn receive_response(
        &mut self,
        stream: &mut impl Read,
    ) -> Result<ActorResponse, SessionError> {
        let plaintext = self.receive(stream, MAX_ACTOR_RESPONSE_BYTES)?;
        ActorResponse::decode(&plaintext)
            .map_err(|_| SessionError::InvalidHandshake("invalid actor response".into()))
    }

    fn send(
        &mut self,
        stream: &mut impl Write,
        value: &impl Serialize,
        limit: usize,
    ) -> Result<(), SessionError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| SessionError::InvalidHandshake("invalid actor message".into()))?,
        );
        if bytes.len() > limit {
            return Err(SessionError::InvalidHandshake(
                "actor message exceeds bound".into(),
            ));
        }
        let sealed = self.session.seal(&bytes)?;
        if let Err(error) = write_sealed_frame(stream, &sealed) {
            self.session
                .poison_send(sealed.sequence, "actor write failed");
            return Err(error);
        }
        Ok(())
    }

    fn receive(
        &mut self,
        stream: &mut impl Read,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        // The shared binary envelope includes the session ID, signature and AEAD tag.
        let sealed = read_sealed_frame(stream, limit + 1024)?;
        let plaintext = Zeroizing::new(self.session.open(&sealed)?);
        if plaintext.len() > limit {
            return Err(SessionError::InvalidHandshake(
                "actor message exceeds bound".into(),
            ));
        }
        Ok(plaintext)
    }
}

fn identity_error() -> SessionError {
    SessionError::PeerIdentityMismatch("actor identity mismatch".into())
}

/// Read a canonical request from the private, inherited holder/controller socket.
/// This is not a guest transport and must never be bound to a filesystem listener.
pub fn read_actor_request(stream: &mut impl Read) -> anyhow::Result<ActorRequest> {
    Ok(ActorRequest::decode(&read_private_frame(
        stream,
        MAX_ACTOR_REQUEST_BYTES,
    )?)?)
}

/// Write a canonical request to the private, inherited controller socket.
pub fn write_actor_request(stream: &mut impl Write, request: &ActorRequest) -> anyhow::Result<()> {
    write_private_frame(stream, request, MAX_ACTOR_REQUEST_BYTES)
}

/// Read a canonical response from the private, inherited controller socket.
pub fn read_actor_response(stream: &mut impl Read) -> anyhow::Result<ActorResponse> {
    Ok(ActorResponse::decode(&read_private_frame(
        stream,
        MAX_ACTOR_RESPONSE_BYTES,
    )?)?)
}

/// Write a canonical response to the private, inherited holder socket.
pub fn write_actor_response(
    stream: &mut impl Write,
    response: &ActorResponse,
) -> anyhow::Result<()> {
    write_private_frame(stream, response, MAX_ACTOR_RESPONSE_BYTES)
}

fn read_private_frame(stream: &mut impl Read, limit: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    anyhow::ensure!(length <= limit, "actor IPC frame exceeds bound");
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_private_frame(
    stream: &mut impl Write,
    value: &impl Serialize,
    limit: usize,
) -> anyhow::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value)?);
    anyhow::ensure!(bytes.len() <= limit, "actor IPC frame exceeds bound");
    stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use mvm_contract::protocol::workload_actor::{
        ActorOutcome, ActorProtocolVersion, ActorRefusalCode,
    };
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn binding() -> ActorSessionBinding {
        ActorSessionBinding {
            protocol_version: 1,
            purpose: "host.actor.v1".into(),
            tenant: "tenant".into(),
            workflow: "workflow".into(),
            boot_id: "boot".into(),
            plan_digest: [3; 32],
            epoch: 1,
            controller_generation: 1,
            key_generation: 1,
            guest_public_key: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            host_public_key: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
        }
    }

    fn pair() -> (ActorSession, ActorSession) {
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let thread = std::thread::spawn(move || {
            ActorSession::host(&mut host, &binding(), SigningKey::from_bytes(&[2; 32])).unwrap()
        });
        let guest =
            ActorSession::guest(&mut guest, &binding(), SigningKey::from_bytes(&[1; 32])).unwrap();
        (guest, thread.join().unwrap())
    }

    #[test]
    fn actual_sessions_exchange_canonical_request_and_response() {
        let (mut guest, mut host) = pair();
        let request = ActorRequest::decode(
            br#"{"version":1,"operation":{"operation":"launch","grant_id":"grant","template_id":"template","idempotency_key":"request"}}"#
        ).unwrap();
        let mut wire = Vec::new();
        guest.send_request(&mut wire, &request).unwrap();
        assert!(!wire.windows(5).any(|bytes| bytes == b"grant"));
        assert_eq!(host.receive_request(&mut wire.as_slice()).unwrap(), request);
        let response = ActorResponse {
            version: ActorProtocolVersion::V1,
            outcome: ActorOutcome::Refused {
                code: ActorRefusalCode::Capacity,
            },
        };
        wire.clear();
        host.send_response(&mut wire, &response).unwrap();
        assert_eq!(
            guest.receive_response(&mut wire.as_slice()).unwrap(),
            response
        );
    }

    #[test]
    fn actual_frames_reject_replay_tampering_and_bare_json() {
        let (mut guest, mut host) = pair();
        let bytes = br#"{"version":1,"operation":{"operation":"launch","grant_id":"g","template_id":"t","idempotency_key":"i"}}"#;
        let sealed = guest.session.seal(bytes).unwrap();
        let mut wire = Vec::new();
        write_sealed_frame(&mut wire, &sealed).unwrap();
        host.receive_request(&mut wire.as_slice()).unwrap();
        assert!(host.receive_request(&mut wire.as_slice()).is_err());
        let mut tampered = guest.session.seal(bytes).unwrap();
        tampered.ciphertext[0] ^= 1;
        wire.clear();
        write_sealed_frame(&mut wire, &tampered).unwrap();
        assert!(host.receive_request(&mut wire.as_slice()).is_err());
        assert!(
            host.receive_request(&mut br#"{"service":"host.actor.v1"}"#.as_slice())
                .is_err()
        );
    }

    #[test]
    fn changed_boot_context_is_refused_before_guest_sends_tokens() {
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            ActorSession::host(&mut host, &binding(), SigningKey::from_bytes(&[2; 32]))
        });
        let mut different = binding();
        different.epoch += 1;
        assert!(
            ActorSession::guest(&mut guest, &different, SigningKey::from_bytes(&[1; 32])).is_err()
        );
        thread.join().unwrap().unwrap();
    }

    #[test]
    fn binding_rejects_downgrade_and_other_purpose() {
        let mut context = binding();
        context.protocol_version = 0;
        assert!(context.session_id().is_err());
        context.protocol_version = 1;
        context.purpose = "mailbox".into();
        assert!(context.session_id().is_err());
    }

    #[test]
    fn binding_rejects_unversioned_and_shared_keys() {
        let mut context = binding();
        context.epoch = 0;
        assert!(context.session_id().is_err());
        context = binding();
        context.controller_generation = 0;
        assert!(context.session_id().is_err());
        context = binding();
        context.key_generation = 0;
        assert!(context.session_id().is_err());
        context = binding();
        context.host_public_key = context.guest_public_key;
        assert!(context.session_id().is_err());
        context = binding();
        context.host_public_key = [0; 32];
        assert!(context.session_id().is_err());
    }

    #[test]
    fn every_admitted_context_component_changes_session_id() {
        let original = binding();
        let id = original.session_id().unwrap();
        let mut variants = vec![original.clone(); 8];
        variants[0].tenant.push('2');
        variants[1].workflow.push('2');
        variants[2].boot_id.push('2');
        variants[3].plan_digest[0] ^= 1;
        variants[4].epoch += 1;
        variants[5].controller_generation += 1;
        variants[6].key_generation += 1;
        variants[7].guest_public_key = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        for variant in variants {
            assert_ne!(variant.session_id().unwrap(), id);
        }
        assert_eq!(
            serde_json::from_slice::<ActorSessionBinding>(&serde_json::to_vec(&original).unwrap())
                .unwrap(),
            original
        );
    }

    #[test]
    fn deadline_expires_without_reading_or_writing_socket_bytes() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut stream = ActorDeadlineStream::new(stream, std::time::Instant::now()).unwrap();
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write(&[1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn host_rejects_guest_with_a_different_pinned_key() {
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            ActorSession::host(&mut host, &binding(), SigningKey::from_bytes(&[2; 32]))
        });
        let mut different = binding();
        different.guest_public_key = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
        assert!(
            ActorSession::guest(&mut guest, &different, SigningKey::from_bytes(&[4; 32])).is_err()
        );
        assert!(thread.join().unwrap().is_err());
    }
}
