//! Length-prefixed JSON frame I/O and the authenticated, encrypted control
//! session built on top of it.

use rand::TryRng;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use super::*;
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::net::session::{Session, SessionError, read_sealed_frame, write_sealed_frame};
use mvm_core::security::{PROTOCOL_VERSION_AUTHENTICATED, SessionHello, SessionHelloAck};
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};

/// 32 bytes from the OS entropy source, or an error naming `what` when the
/// source is unavailable, so a handshake fails instead of aborting the agent.
fn random_seed(what: &str) -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("OS entropy unavailable for {what}: {e}"))?;
    Ok(seed)
}

/// Read a single length-prefixed JSON frame from a stream.
/// Returns the deserialized value.
pub fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .with_context(|| "Failed to read frame length")?;
    let frame_len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| anyhow::anyhow!("frame length does not fit this platform's usize"))?;

    if frame_len > MAX_FRAME_SIZE {
        bail!(
            "Frame too large: {} bytes (max {})",
            frame_len,
            MAX_FRAME_SIZE
        );
    }

    let mut buf = vec![0u8; frame_len];
    stream
        .read_exact(&mut buf)
        .with_context(|| "Failed to read frame body")?;

    serde_json::from_slice(&buf).with_context(|| "Failed to deserialize frame")
}

/// Write a single length-prefixed JSON frame to a stream.
pub fn write_frame<T: Serialize>(stream: &mut (impl Write + ?Sized), value: &T) -> Result<()> {
    let data = serde_json::to_vec(value).with_context(|| "Failed to serialize frame")?;
    if data.len() > MAX_FRAME_SIZE {
        bail!(
            "Frame too large: {} bytes (max {})",
            data.len(),
            MAX_FRAME_SIZE
        );
    }
    let len = u32::try_from(data.len())
        .context("frame length does not fit the 4-byte prefix")?
        .to_be_bytes();
    stream
        .write_all(&len)
        .with_context(|| "Failed to write frame length")?;
    stream
        .write_all(&data)
        .with_context(|| "Failed to write frame body")?;
    stream.flush()?;
    Ok(())
}

/// Perform the host side of the session handshake.
///
/// After CONNECT/OK, the host sends `SessionHello` with a random challenge
/// and its public key. The guest responds with `SessionHelloAck` containing
/// the signed challenge and its public key.
///
/// Returns the guest's verifying key on success.
pub fn handshake_as_host(
    stream: &mut UnixStream,
    session_id: &str,
    host_signing_key: &SigningKey,
) -> Result<VerifyingKey> {
    let _span = tracing::info_span!("vsock_handshake").entered();
    let t = std::time::Instant::now();
    let challenge: Vec<u8> = random_seed("handshake challenge")?.to_vec();
    let host_pubkey = host_signing_key.verifying_key().to_bytes().to_vec();
    let host_ephemeral_secret = StaticSecret::from(random_seed("host X25519 secret")?);

    let hello = SessionHello {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        session_id: session_id.to_string(),
        challenge: challenge.clone(),
        host_pubkey,
        host_ephemeral_pubkey: PublicKey::from(&host_ephemeral_secret).as_bytes().to_vec(),
    };

    write_frame(stream, &hello)?;

    let ack: SessionHelloAck = read_frame(stream)?;

    // Verify session ID echoed back
    if ack.session_id != session_id {
        bail!(
            "Session ID mismatch in HelloAck: got '{}', expected '{}'",
            ack.session_id,
            session_id
        );
    }

    // Extract guest public key
    if ack.guest_pubkey.len() != 32 {
        bail!(
            "Invalid guest public key length: {} (expected 32)",
            ack.guest_pubkey.len()
        );
    }
    let guest_key_bytes: [u8; 32] = ack
        .guest_pubkey
        .as_slice()
        .try_into()
        .with_context(|| "Guest public key must be 32 bytes")?;

    let guest_verifying_key = VerifyingKey::from_bytes(&guest_key_bytes)
        .with_context(|| "Invalid guest Ed25519 public key")?;

    // Verify guest signed the challenge
    if ack.challenge_response.len() != 64 {
        bail!(
            "Invalid challenge response length: {} (expected 64)",
            ack.challenge_response.len()
        );
    }
    let sig_bytes: [u8; 64] = ack
        .challenge_response
        .as_slice()
        .try_into()
        .with_context(|| "Challenge response must be 64 bytes")?;

    let sig = Signature::from_bytes(&sig_bytes);
    guest_verifying_key
        .verify(&challenge, &sig)
        .map_err(|e| anyhow::anyhow!("Challenge verification failed: {}", e))?;

    mvm_core::observability::metrics::global()
        .vsock_handshake_rtt_ms
        .store(
            t.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    Ok(guest_verifying_key)
}

/// Perform the guest side of the session handshake.
///
/// Reads `SessionHello` from the host, signs the challenge with the guest's
/// key, and sends back `SessionHelloAck`.
///
/// Returns the host's verifying key and session ID on success.
pub fn handshake_as_guest(
    stream: &mut UnixStream,
    guest_signing_key: &SigningKey,
) -> Result<(VerifyingKey, String)> {
    let hello: SessionHello = read_frame(stream)?;

    // Extract host public key
    if hello.host_pubkey.len() != 32 {
        bail!(
            "Invalid host public key length: {} (expected 32)",
            hello.host_pubkey.len()
        );
    }
    let host_key_bytes: [u8; 32] = hello
        .host_pubkey
        .as_slice()
        .try_into()
        .with_context(|| "Host public key must be 32 bytes")?;

    let host_verifying_key = VerifyingKey::from_bytes(&host_key_bytes)
        .with_context(|| "Invalid host Ed25519 public key")?;

    // Sign the challenge to prove we hold the session key
    let challenge_sig = guest_signing_key.sign(&hello.challenge);
    let guest_pubkey = guest_signing_key.verifying_key().to_bytes().to_vec();
    let guest_ephemeral_secret = StaticSecret::from(random_seed("guest X25519 secret")?);

    let ack = SessionHelloAck {
        version: hello.version,
        session_id: hello.session_id.clone(),
        challenge_response: challenge_sig.to_bytes().to_vec(),
        guest_pubkey,
        guest_ephemeral_pubkey: PublicKey::from(&guest_ephemeral_secret).as_bytes().to_vec(),
        guest_challenge: vec![0u8; 32],
        control: None,
    };

    write_frame(stream, &ack)?;

    Ok((host_verifying_key, hello.session_id))
}

/// A per-connection authenticated and confidential control session.
///
/// This is the control-RPC wrapper around [`mvm_core::net::session::Session`].
/// Frames go on the wire through `SealedFrame`'s binary encoding, the same one
/// the FlowMux networking path uses, so both planes share the cryptographic
/// session machinery *and* the envelope rather than only the former.
///
/// This is the guest end of the control plane. The host never holds one: it
/// holds a [`HostControlSession`], whose only request writer checks the guest's
/// advertisement first.
pub struct AuthenticatedSession {
    inner: Session,
}

impl AuthenticatedSession {
    /// Establish a guest session, advertising `offer`, and require the host
    /// identity to match `anchor`.
    ///
    /// A host whose protocol range shares nothing with `offer`, or that sent
    /// no range, is refused here: the host's first request is read and
    /// discarded, answered with a sealed `ProtocolMismatch` naming the remedy,
    /// and the typed refusal is returned so the caller closes the connection.
    /// Nothing the host sent is dispatched.
    ///
    /// The error is returned typed rather than flattened into `anyhow`, because
    /// one of its cases is not a failure to authenticate: a peer that hangs up
    /// mid-handshake produced no bad signature and no wrong identity, and on
    /// the control socket that is the host's readiness poll. Callers separate
    /// the two with [`SessionError::is_peer_hangup`]; flattening the type here
    /// left the agent nothing to branch on but the message text.
    pub fn guest<S: Read + Write>(
        stream: &mut S,
        signing_key: SigningKey,
        anchor: &VerifyingKey,
        offer: &ControlOffer,
    ) -> std::result::Result<Self, SessionError> {
        let (inner, refusal) = Session::guest_control(stream, signing_key, anchor, offer)?;
        let mut session = Self { inner };
        match refusal {
            None => Ok(session),
            Some(mismatch) => {
                session.refuse(stream, &mismatch);
                Err(SessionError::ControlRefused(mismatch))
            }
        }
    }

    /// Consume the first request without interpreting it, answer it with the
    /// typed mismatch, and stop. Best effort: the host may already be gone.
    fn refuse<S: Read + Write>(&mut self, stream: &mut S, mismatch: &ControlMismatch) {
        if self.read::<serde::de::IgnoredAny>(stream).is_err() {
            return;
        }
        let _ = self.write(
            stream,
            &GuestResponse::ProtocolMismatch {
                host_protocol_version: mismatch.host_protocol_version,
                agent_protocol_version: mismatch.agent_protocol_version,
                required_action: mismatch.required_action,
                message: mismatch.message.clone(),
            },
        );
    }

    /// Write one encrypted, signed control frame.
    ///
    /// A write that fails after the frame is sealed ends the session: the
    /// sequence number is already spent, so continuing would put every later
    /// frame one ahead of what the peer expects and surface as an
    /// unexplained sequence mismatch instead of the write failure that
    /// actually happened.
    pub fn write<T: Serialize>(&mut self, stream: &mut impl Write, value: &T) -> Result<()> {
        let plaintext = serde_json::to_vec(value).with_context(|| "serialize control payload")?;
        // Checked before `seal`, not after. Sealing spends a sequence number
        // that cannot be reissued, so a payload already known to be too large
        // has to be refused while the session is still usable — otherwise
        // every oversize frame would also cost the connection.
        if plaintext.len() > MAX_FRAME_SIZE {
            bail!(
                "control payload too large: {} bytes (max {MAX_FRAME_SIZE})",
                plaintext.len()
            );
        }
        let sealed = self
            .inner
            .seal(&plaintext)
            .map_err(|error| anyhow::anyhow!("control frame seal failed: {error}"))?;
        let sequence = sealed.sequence;
        write_sealed_frame(stream, &sealed).map_err(|error| {
            self.inner.poison_send(sequence, error.to_string());
            anyhow::anyhow!("control frame write failed: {error}")
        })
    }

    /// Read, authenticate, decrypt, and deserialize one control frame.
    pub fn read<T: serde::de::DeserializeOwned>(&mut self, stream: &mut impl Read) -> Result<T> {
        let sealed = read_sealed_frame(stream, MAX_SEALED_FRAME_SIZE)
            .map_err(anyhow::Error::new)
            .context("control frame read failed")?;
        let plaintext = self
            .inner
            .open(&sealed)
            .map_err(|error| anyhow::anyhow!("control frame open failed: {error}"))?;
        serde_json::from_slice(&plaintext).with_context(|| "deserialize decrypted control payload")
    }
}

/// The host end of a control session, with the guest's signed advertisement
/// bound to it for the life of the connection.
///
/// This is the single place the host writes a request. It has no generic
/// writer: [`send`](Self::send) takes a [`GuestRequest`] and refuses, before
/// sealing anything, a verb whose capability the guest did not advertise. The
/// advertisement is read once off the authenticated handshake, is never
/// persisted or shared, and dies with the connection, so a restored guest is
/// renegotiated rather than trusted from a cache.
///
/// The check only narrows what the host sends. It is not authorization: the
/// guest's profile gate, signed grants and seccomp tier decide what runs and
/// never read the advertisement.
pub struct HostControlSession {
    inner: AuthenticatedSession,
    offer: ControlOffer,
}

impl HostControlSession {
    /// Establish the host side of a control session using the host's
    /// long-lived signing identity. A guest that advertises nothing, or a
    /// range this host does not speak, is refused before the confirm is
    /// written, with a typed [`SessionError::ControlRefused`] in the chain.
    pub fn host<S: Read + Write>(
        stream: &mut S,
        session_id: &str,
        signing_key: SigningKey,
    ) -> Result<Self> {
        Self::host_retaining_peer(stream, session_id, signing_key).map(|(session, _)| session)
    }

    /// Retain the actual handshake key. This is peer authentication, not a
    /// claim that the transport belongs to a particular native generation.
    pub fn host_retaining_peer<S: Read + Write>(
        stream: &mut S,
        session_id: &str,
        signing_key: SigningKey,
    ) -> Result<(Self, VerifyingKey)> {
        let (inner, peer_key, offer) =
            Session::host_control(stream, session_id, signing_key, &control_range())
                .context("host session handshake failed")?;
        Ok((
            Self {
                inner: AuthenticatedSession { inner },
                offer,
            },
            peer_key,
        ))
    }

    /// What the guest advertised in the signed handshake.
    pub fn offer(&self) -> &ControlOffer {
        &self.offer
    }

    /// Write one request, after checking the guest advertised the capability
    /// its verb needs. A refused verb writes nothing and spends no sequence
    /// number, so the session stays usable.
    pub fn send<S: Write>(
        &mut self,
        stream: &mut S,
        request: &GuestRequest,
    ) -> std::result::Result<(), RpcError> {
        let verb = request.verb();
        if let Some(capability) = verb
            .capability()
            .filter(|capability| !self.offer.advertises(*capability))
        {
            return Err(RpcError::CapabilityNotAdvertised {
                capability,
                verb: verb.name(),
            });
        }
        self.inner.write(stream, request)?;
        Ok(())
    }

    /// Read, authenticate, decrypt, and deserialize one control frame.
    pub fn read<T: serde::de::DeserializeOwned>(&mut self, stream: &mut impl Read) -> Result<T> {
        self.inner.read(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::net::session::paired_sessions_for_test;
    use rand::Rng;
    use std::io::Cursor;

    #[test]
    fn random_seed_yields_distinct_nonzero_seeds() {
        let a = random_seed("test").unwrap();
        let b = random_seed("test").unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn read_frame_rejects_an_oversized_announced_length() {
        let mut wire = Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let err = read_frame::<serde_json::Value>(&mut wire).unwrap_err();
        assert!(err.to_string().contains("Frame too large"), "{err}");
    }

    // ========================================================================
    // Authenticated frame tests
    // ========================================================================

    fn test_keypair() -> SigningKey {
        {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        }
    }

    #[test]
    fn retaining_handshake_returns_the_real_guest_key_and_preserves_counters() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let expected = guest_key.verifying_key();
        let anchor = host_key.verifying_key();
        let peer = std::thread::spawn(move || {
            let mut session =
                AuthenticatedSession::guest(&mut guest, guest_key, &anchor, &control_offer())
                    .unwrap();
            for _ in 0..3 {
                assert!(matches!(
                    session.read::<GuestRequest>(&mut guest).unwrap(),
                    GuestRequest::Ping
                ));
                session.write(&mut guest, &GuestResponse::Pong).unwrap();
            }
        });
        let (mut session, key) =
            HostControlSession::host_retaining_peer(&mut host, "retained-key", host_key).unwrap();
        assert_eq!(key, expected);
        assert_eq!(session.offer(), &control_offer());
        for _ in 0..3 {
            session.send(&mut host, &GuestRequest::Ping).unwrap();
            assert!(matches!(
                session.read::<GuestResponse>(&mut host).unwrap(),
                GuestResponse::Pong
            ));
        }
        peer.join().unwrap();
    }

    fn guest_offering(first: u32, last: u32) -> ControlOffer {
        ControlOffer {
            protocol_version: last,
            min_supported_version: first,
            ..control_offer()
        }
    }

    #[test]
    fn a_legacy_guest_with_no_advertisement_is_refused_with_rebuild_guest_before_the_confirm() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let host_key = test_keypair();
        let anchor = host_key.verifying_key();
        let legacy = std::thread::spawn(move || {
            // The pre-advertisement handshake: no `control` in the ack.
            Session::guest(&mut guest, test_keypair(), &anchor).map(|_| ())
        });
        let Err(error) = HostControlSession::host(&mut host, "legacy-guest", host_key) else {
            panic!("a guest that advertises nothing must be refused");
        };
        let Some(SessionError::ControlRefused(mismatch)) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<SessionError>())
        else {
            panic!("the refusal must stay typed in the error chain: {error:#}");
        };
        assert_eq!(
            mismatch.required_action,
            ProtocolUpgradeAction::RebuildGuest
        );
        assert!(mismatch.message.contains("mvmctl bootstrap"));
        drop(host);
        // No confirm and no request reached the legacy guest.
        assert!(legacy.join().unwrap().unwrap_err().is_peer_hangup());
    }

    #[test]
    fn a_host_range_outside_the_guests_is_refused_at_handshake_and_names_the_remedy() {
        for (first, last, action) in [
            (
                control_range().protocol_version + 1,
                control_range().protocol_version + 2,
                ProtocolUpgradeAction::UpgradeHost,
            ),
            (
                0,
                control_range().min_supported_version - 1,
                ProtocolUpgradeAction::RebuildGuest,
            ),
        ] {
            let (mut host, mut guest) = UnixStream::pair().unwrap();
            host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            guest
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let host_key = test_keypair();
            let anchor = host_key.verifying_key();
            let peer = std::thread::spawn(move || {
                AuthenticatedSession::guest(
                    &mut guest,
                    test_keypair(),
                    &anchor,
                    &guest_offering(first, last),
                )
                .map(|_| ())
            });
            let Err(error) = HostControlSession::host(&mut host, "range", host_key) else {
                panic!("disjoint ranges must be refused");
            };
            let Some(SessionError::ControlRefused(mismatch)) = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<SessionError>())
            else {
                panic!("expected a typed mismatch: {error:#}");
            };
            assert_eq!(mismatch.required_action, action);
            drop(host);
            assert!(peer.join().unwrap().unwrap_err().is_peer_hangup());
        }
    }

    #[test]
    fn a_refused_host_gets_one_typed_mismatch_for_its_first_request_and_nothing_is_dispatched() {
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let (mut host_session, guest_session) = paired_sessions_for_test(
            host_key,
            guest_key,
            rand::random::<[u8; 32]>(),
            "refused-host",
        );
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mismatch = ControlRange {
            protocol_version: control_range().min_supported_version - 1,
            min_supported_version: 1,
        }
        .check(&control_offer())
        .unwrap_err();
        let guest = std::thread::spawn(move || {
            AuthenticatedSession {
                inner: guest_session,
            }
            .refuse(&mut guest_stream, &mismatch);
        });

        // The host's first request is sealed and sent as usual.
        let plaintext = serde_json::to_vec(&GuestRequest::Ping).unwrap();
        let sealed = host_session.seal(&plaintext).unwrap();
        write_sealed_frame(&mut host_stream, &sealed).unwrap();
        let reply = read_sealed_frame(&mut host_stream, MAX_SEALED_FRAME_SIZE).unwrap();
        let reply: GuestResponse =
            serde_json::from_slice(&host_session.open(&reply).unwrap()).unwrap();
        guest.join().unwrap();
        assert!(matches!(
            reply,
            GuestResponse::ProtocolMismatch {
                required_action: ProtocolUpgradeAction::UpgradeHost,
                ..
            }
        ));
    }

    struct WouldBlockReader;

    impl std::io::Read for WouldBlockReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    #[test]
    fn control_frame_read_preserves_would_block_for_bounded_retry() {
        let error = read_sealed_frame(&mut WouldBlockReader, MAX_SEALED_FRAME_SIZE)
            .map_err(anyhow::Error::new)
            .context("control frame read failed")
            .expect_err("a would-block reader has no frame");

        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::WouldBlock)
        }));
    }

    #[test]
    fn control_frame_timeout_after_partial_read_is_not_retryable() {
        struct PartialTimeout {
            bytes: std::io::Cursor<Vec<u8>>,
            kind: std::io::ErrorKind,
        }

        impl Read for PartialTimeout {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.position() < u64::try_from(self.bytes.get_ref().len()).unwrap() {
                    self.bytes.read(buf)
                } else {
                    Err(self.kind.into())
                }
            }
        }

        // Both an incomplete prefix and an incomplete body have consumed wire
        // bytes that a fresh read cannot safely interpret as another prefix.
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            for bytes in [
                vec![0],
                vec![0, 0],
                vec![0, 0, 0, 4],
                vec![0, 0, 0, 4, 1, 2],
            ] {
                let error = read_sealed_frame(
                    &mut PartialTimeout {
                        bytes: std::io::Cursor::new(bytes),
                        kind,
                    },
                    MAX_SEALED_FRAME_SIZE,
                )
                .expect_err("partial frame must fail closed");
                assert!(
                    matches!(error, SessionError::InvalidHandshake(_)),
                    "partial frame must not look like an idle-stream timeout: {error}"
                );
            }
            let error = read_sealed_frame(
                &mut PartialTimeout {
                    bytes: std::io::Cursor::new(Vec::new()),
                    kind,
                },
                MAX_SEALED_FRAME_SIZE,
            )
            .expect_err("idle stream times out");
            assert!(matches!(error, SessionError::Io(ref io) if io.kind() == kind));
        }
        for bytes in [vec![], vec![0], vec![0, 0, 0, 4, 1, 2]] {
            let error = read_sealed_frame(&mut bytes.as_slice(), MAX_SEALED_FRAME_SIZE)
                .expect_err("EOF remains a transport hangup");
            assert!(
                matches!(error, SessionError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
    }

    // ========================================================================
    // Handshake tests
    // ========================================================================

    #[test]
    fn test_handshake_roundtrip() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let guest_key = test_keypair();
        let host_vk_expected = host_key.verifying_key();
        let guest_vk_expected = guest_key.verifying_key();
        let session_id = "handshake-test-001";

        // Run handshake in separate threads since both sides block on I/O
        let host_handle =
            std::thread::spawn(move || handshake_as_host(&mut host_stream, session_id, &host_key));

        let guest_handle =
            std::thread::spawn(move || handshake_as_guest(&mut guest_stream, &guest_key));

        let guest_vk = host_handle.join().unwrap().unwrap();
        let (host_vk, received_session_id) = guest_handle.join().unwrap().unwrap();

        // Host got guest's public key
        assert_eq!(guest_vk.as_bytes(), guest_vk_expected.as_bytes());
        // Guest got host's public key
        assert_eq!(host_vk.as_bytes(), host_vk_expected.as_bytes());
        // Session ID was echoed correctly
        assert_eq!(received_session_id, session_id);
    }

    #[test]
    fn host_handshake_preserves_the_typed_peer_hangup() {
        let (mut host_stream, guest_stream) = UnixStream::pair().unwrap();
        drop(guest_stream);

        let Err(error) = HostControlSession::host(&mut host_stream, "peer-hangup", test_keypair())
        else {
            panic!("a vanished guest must fail the host handshake");
        };
        let session_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<SessionError>())
            .expect("the anyhow context must preserve SessionError");

        assert!(session_error.is_peer_hangup());
    }

    #[test]
    fn oversized_write_is_rejected_before_writing_any_bytes() {
        let payload = vec![0_u8; MAX_FRAME_SIZE + 1];
        let mut output = Cursor::new(Vec::new());

        let err = write_frame(&mut output, &payload).expect_err("oversized frame must fail");

        assert!(err.to_string().contains("Frame too large"));
        assert!(output.into_inner().is_empty());
    }

    /// Build a host/guest session pair over a socketpair, as a completed
    /// handshake would leave them.
    fn confidential_pair() -> (
        (UnixStream, HostControlSession),
        (UnixStream, AuthenticatedSession),
    ) {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let host_anchor = host_key.verifying_key();

        let guest_thread = std::thread::spawn(move || {
            let session = AuthenticatedSession::guest(
                &mut guest_stream,
                guest_key,
                &host_anchor,
                &control_offer(),
            )
            .unwrap();
            (guest_stream, session)
        });
        let host_session =
            HostControlSession::host(&mut host_stream, "chunk-cap-test", host_key).unwrap();
        let guest = guest_thread.join().unwrap();
        ((host_stream, host_session), guest)
    }

    /// The witness the chunk cap was missing: a full-size chunk of the most
    /// expensive bytes there are must still fit the frame cap *after* both JSON
    /// encodings — the response body and the sealed envelope's ciphertext.
    ///
    /// Checking the cap against the response body alone is what let a 48 KiB
    /// chunk pass the handler and then fail on the wire.
    #[test]
    fn sealed_worst_case_chunk_fits_the_frame_cap() {
        let (_host, (guest_stream, mut guest_session)) = confidential_pair();
        drop(guest_stream);

        // 0xFF is the worst case: every byte serializes as the four characters
        // `255,` in both the response body and the sealed ciphertext.
        let response = GuestResponse::ExecEvent(ExecEvent::Stdout {
            chunk: vec![0xFF; MAX_DATA_CHUNK_SIZE],
        });

        let mut wire = Vec::new();
        guest_session
            .write(&mut wire, &response)
            .expect("a full-size chunk must fit the wire");

        let body = wire.len() - 4;
        assert!(
            body <= MAX_FRAME_SIZE,
            "a {MAX_DATA_CHUNK_SIZE}-byte chunk sealed to {body} bytes, over the \
             {MAX_FRAME_SIZE}-byte cap"
        );

        let mut host_session = _host.1;
        let decoded: GuestResponse = host_session
            .read(&mut std::io::Cursor::new(wire))
            .expect("the frame must round-trip");
        assert!(matches!(
            decoded,
            GuestResponse::ExecEvent(ExecEvent::Stdout { .. })
        ));
    }

    /// An oversize payload is refused before it can spend a sequence number,
    /// so the session survives it.
    ///
    /// The old JSON envelope discovered the size only after sealing, which
    /// meant an oversize frame also cost the connection. Checking first is why
    /// the second write below is expected to succeed rather than to report a
    /// poisoned session. The size is taken from the derived cap rather than
    /// written out, so raising the cap moves this test with it instead of
    /// quietly making it vacuous.
    #[test]
    fn a_payload_above_the_cap_is_refused_before_it_spends_a_sequence() {
        let ((mut host_stream, mut host_session), (mut guest_stream, mut guest_session)) =
            confidential_pair();

        let oversize = GuestResponse::ExecEvent(ExecEvent::Stdout {
            chunk: vec![0xFF; MAX_DATA_CHUNK_SIZE * 2],
        });
        let mut wire = Vec::new();
        let err = guest_session
            .write(&mut wire, &oversize)
            .expect_err("twice the chunk cap must not fit the frame cap");
        assert!(
            err.to_string().contains("control payload too large"),
            "expected the payload cap to name itself, got {err}"
        );
        assert!(wire.is_empty(), "nothing may reach the wire on a rejection");

        // The refusal cost no sequence, so the session is still usable and its
        // next frame is still the one the peer is waiting for.
        guest_session
            .write(&mut guest_stream, &GuestResponse::Pong)
            .expect("a refused payload must not end the session");
        let received: GuestResponse = host_session
            .read(&mut host_stream)
            .expect("the peer is still in step");
        assert!(matches!(received, GuestResponse::Pong));
    }

    /// The user-visible failure this fixes: a write that dies after the seal
    /// used to leave the peer permanently one frame behind, reported several
    /// frames later as a sequence mismatch with no mention of the write.
    #[test]
    fn a_transport_failure_after_the_seal_does_not_desync_the_peer() {
        struct DeadTransport;
        impl Write for DeadTransport {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "peer went away",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let ((mut host_stream, mut host_session), (mut guest_stream, mut guest_session)) =
            confidential_pair();

        host_session
            .send(&mut DeadTransport, &GuestRequest::Ping)
            .expect_err("the transport is dead");

        // Without the poison this write would succeed and land as sequence 2
        // against a peer still expecting 1.
        let err = host_session
            .send(&mut host_stream, &GuestRequest::Ping)
            .expect_err("the session must be finished, not one frame ahead");
        assert!(err.to_string().contains("session poisoned"), "got {err}");

        // And the peer sees nothing rather than a frame it must reject.
        drop(host_stream);
        assert!(
            guest_session
                .read::<GuestRequest>(&mut guest_stream)
                .is_err()
        );
    }

    #[test]
    fn confidential_session_round_trip_and_tamper_rejection() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let host_anchor = host_key.verifying_key();

        let guest_thread = std::thread::spawn(move || {
            let session = AuthenticatedSession::guest(
                &mut guest_stream,
                guest_key,
                &host_anchor,
                &control_offer(),
            )
            .unwrap();
            (guest_stream, session)
        });
        let mut host_session =
            HostControlSession::host(&mut host_stream, "confidential-test", host_key).unwrap();
        let (mut guest_stream, mut guest_session) = guest_thread.join().unwrap();

        host_session
            .send(&mut host_stream, &GuestRequest::Ping)
            .unwrap();
        let request: GuestRequest = guest_session.read(&mut guest_stream).unwrap();
        assert!(matches!(request, GuestRequest::Ping));

        guest_session
            .write(&mut guest_stream, &GuestResponse::Pong)
            .unwrap();
        let response: GuestResponse = host_session.read(&mut host_stream).unwrap();
        assert!(matches!(response, GuestResponse::Pong));

        let (mut tamper_writer, mut tamper_reader) = UnixStream::pair().unwrap();
        host_session
            .send(&mut host_stream, &GuestRequest::Ping)
            .unwrap();
        let frame = read_sealed_frame(&mut guest_stream, MAX_SEALED_FRAME_SIZE).unwrap();
        assert!(
            !frame
                .ciphertext
                .windows(b"Ping".len())
                .any(|window| window == b"Ping")
        );
        let (mut valid_writer, mut valid_reader) = UnixStream::pair().unwrap();
        write_sealed_frame(&mut valid_writer, &frame).unwrap();
        let accepted: GuestRequest = guest_session.read(&mut valid_reader).unwrap();
        assert!(matches!(accepted, GuestRequest::Ping));

        let (mut replay_writer, mut replay_reader) = UnixStream::pair().unwrap();
        write_sealed_frame(&mut replay_writer, &frame).unwrap();
        let replay: anyhow::Result<GuestRequest> = guest_session.read(&mut replay_reader);
        assert!(replay.is_err(), "replayed control frame must be rejected");

        host_session
            .send(&mut host_stream, &GuestRequest::Ping)
            .unwrap();
        let next_frame = read_sealed_frame(&mut guest_stream, MAX_SEALED_FRAME_SIZE).unwrap();
        assert_eq!(next_frame.sequence, 3);
        let mut tampered = next_frame;
        tampered.ciphertext[0] ^= 0x01;
        write_sealed_frame(&mut tamper_writer, &tampered).unwrap();
        let err: anyhow::Result<GuestRequest> = guest_session.read(&mut tamper_reader);
        assert!(err.is_err());
    }

    #[test]
    fn test_handshake_with_wrong_challenge_response() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let wrong_key = test_keypair(); // Guest uses wrong key

        let host_handle = std::thread::spawn(move || {
            handshake_as_host(&mut host_stream, "bad-handshake", &host_key)
        });

        // Guest side: read hello, but sign with wrong key
        let hello: SessionHello = read_frame(&mut guest_stream).unwrap();
        let bad_sig = wrong_key.sign(&hello.challenge);
        let ack = SessionHelloAck {
            version: hello.version,
            session_id: hello.session_id,
            challenge_response: bad_sig.to_bytes().to_vec(),
            // Send the correct guest pubkey for the wrong key
            guest_pubkey: wrong_key.verifying_key().to_bytes().to_vec(),
            guest_ephemeral_pubkey: vec![0u8; 32],
            guest_challenge: vec![0u8; 32],
            control: None,
        };
        write_frame(&mut guest_stream, &ack).unwrap();

        // Host should succeed because the guest signed with wrong_key
        // but sent wrong_key's pubkey — the challenge was signed by the
        // key whose pubkey was provided, so verification passes.
        // This is correct: we verify the guest controls the key it claims.
        let result = host_handle.join().unwrap();
        assert!(result.is_ok());
    }

    /// The reported bug, reproduced at the seam it comes from.
    ///
    /// A peer that connects and goes away without sending anything is exactly
    /// what `wait_for_agent` does while the guest boots — it probes on a
    /// backoff and drops each stream. The guest must classify that as a
    /// vanished peer, not as a failed authentication, or every healthy boot
    /// logs a security-relevant failure.
    #[test]
    fn a_peer_that_sends_nothing_is_a_hangup_not_an_auth_failure() {
        use std::io::Cursor;

        let guest_key = SigningKey::from_bytes(&[7u8; 32]);
        let host_anchor = SigningKey::from_bytes(&[9u8; 32]).verifying_key();

        // Reads hit end-of-stream immediately: the peer is gone.
        let mut vanished = Cursor::new(Vec::new());
        // `AuthenticatedSession` holds key material and deliberately has no
        // `Debug`, so unwrap the Result by hand rather than deriving one.
        let err = match AuthenticatedSession::guest(
            &mut vanished,
            guest_key,
            &host_anchor,
            &control_offer(),
        ) {
            Ok(_) => panic!("no handshake can complete against a peer that sent nothing"),
            Err(e) => e,
        };

        assert!(
            err.is_peer_hangup(),
            "an abandoned probe must not read as an authentication failure: {err}"
        );
    }
}
