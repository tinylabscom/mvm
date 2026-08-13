//! Length-prefixed JSON frame I/O and the authenticated, encrypted control
//! session built on top of it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use super::*;
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::net::session::{SealedFrame, Session};
use mvm_core::security::{
    AuthenticatedFrame, PROTOCOL_VERSION_AUTHENTICATED, SIG_ALG_ED25519, SessionHello,
    SessionHelloAck,
};
use mvm_core::signing::SignedPayload;
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};

/// Read a single length-prefixed JSON frame from a stream.
/// Returns the deserialized value.
pub fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .with_context(|| "Failed to read frame length")?;
    let frame_len =
        usize::try_from(u32::from_be_bytes(len_buf)).expect("u32 frame length fits usize");

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
        .expect("bounded frame length fits u32")
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
/// Write a legacy authenticated, Ed25519-signed frame to a stream.
///
/// This helper provides signature-only framing for compatibility with the
/// framing tests and fuzz targets. Live control RPCs use
/// [`AuthenticatedSession`], which also encrypts payloads and enforces a
/// bidirectional handshake.
pub fn write_authenticated_frame<T: Serialize>(
    stream: &mut impl Write,
    value: &T,
    signing_key: &SigningKey,
    signer_id: &str,
    session_id: &str,
    sequence: u64,
) -> Result<()> {
    let payload = serde_json::to_vec(value).with_context(|| "Failed to serialize inner payload")?;

    let signature = signing_key.sign(&payload);
    let signed = SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.to_string(),
    };

    let frame = AuthenticatedFrame {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        sig_alg: SIG_ALG_ED25519,
        session_id: session_id.to_string(),
        sequence,
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed,
    };

    write_frame(stream, &frame)
}

/// Read a legacy authenticated frame from a stream and verify its Ed25519 signature.
///
/// This is the signature-only counterpart to [`write_authenticated_frame`].
/// Live control RPCs use [`AuthenticatedSession`] instead.
pub fn read_authenticated_frame<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    verifying_key: &VerifyingKey,
    expected_session_id: &str,
    expected_min_sequence: u64,
) -> Result<(T, u64)> {
    let frame: AuthenticatedFrame = read_frame(stream)?;
    verify_authenticated_frame(
        &frame,
        verifying_key,
        expected_session_id,
        expected_min_sequence,
    )
}

/// Verify an already-deserialized `AuthenticatedFrame` and extract its
/// inner payload.
///
/// Same checks as [`read_authenticated_frame`] minus the wire read:
/// version → session ID → sequence (replay) → 64-byte signature length
/// → Ed25519 signature over `signed.payload` → deserialize as `T`.
/// Each step short-circuits with `Err`; the inner deserializer is
/// reached only after the signature check passes, which is the
/// load-bearing property the fuzz harness exercises.
///
/// Public so `crates/mvm-agentd/fuzz/fuzz_targets/fuzz_authed_path.rs`
/// can drive the verification path without a real `UnixStream`.
pub fn verify_authenticated_frame<T: serde::de::DeserializeOwned>(
    frame: &AuthenticatedFrame,
    verifying_key: &VerifyingKey,
    expected_session_id: &str,
    expected_min_sequence: u64,
) -> Result<(T, u64)> {
    if frame.version != PROTOCOL_VERSION_AUTHENTICATED {
        bail!(
            "Unexpected protocol version: {} (expected {})",
            frame.version,
            PROTOCOL_VERSION_AUTHENTICATED
        );
    }

    if frame.session_id != expected_session_id {
        bail!(
            "Session ID mismatch: got '{}', expected '{}'",
            frame.session_id,
            expected_session_id
        );
    }

    if frame.sequence < expected_min_sequence {
        bail!(
            "Replay detected: sequence {} < expected minimum {}",
            frame.sequence,
            expected_min_sequence
        );
    }

    let signed = &frame.signed;
    if signed.signature.len() != 64 {
        bail!(
            "Invalid signature length: {} (expected 64)",
            signed.signature.len()
        );
    }

    let sig_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .with_context(|| "Signature must be exactly 64 bytes")?;

    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&signed.payload, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    let value: T = serde_json::from_slice(&signed.payload)
        .with_context(|| "Failed to deserialize verified payload")?;

    Ok((value, frame.sequence))
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
    let challenge: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let host_pubkey = host_signing_key.verifying_key().to_bytes().to_vec();
    let host_ephemeral_secret = StaticSecret::from(rand::random::<[u8; 32]>());

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
    let guest_ephemeral_secret = StaticSecret::from(rand::random::<[u8; 32]>());

    let ack = SessionHelloAck {
        version: hello.version,
        session_id: hello.session_id.clone(),
        challenge_response: challenge_sig.to_bytes().to_vec(),
        guest_pubkey,
        guest_ephemeral_pubkey: PublicKey::from(&guest_ephemeral_secret).as_bytes().to_vec(),
        guest_challenge: vec![0u8; 32],
    };

    write_frame(stream, &ack)?;

    Ok((host_verifying_key, hello.session_id))
}

/// A per-connection authenticated and confidential control session.
///
/// This is the control-RPC wrapper around [`mvm_core::net::session::Session`].
/// It keeps the existing JSON `AuthenticatedFrame` envelope so all current
/// callers continue to interoperate, while the cryptographic session machinery
/// is shared with the FlowMux networking path.
pub struct AuthenticatedSession {
    inner: Session,
}

impl AuthenticatedSession {
    /// Establish a host session using the host's long-lived signing identity.
    pub fn host<S: Read + Write>(
        stream: &mut S,
        session_id: &str,
        signing_key: SigningKey,
    ) -> Result<Self> {
        let (inner, _peer_key) = Session::host(stream, session_id, signing_key)
            .map_err(|error| anyhow::anyhow!("host session handshake failed: {error}"))?;
        Ok(Self { inner })
    }

    /// Establish a guest session and require the host identity to match `anchor`.
    pub fn guest<S: Read + Write>(
        stream: &mut S,
        signing_key: SigningKey,
        anchor: &VerifyingKey,
    ) -> Result<Self> {
        let (inner, _session_id) = Session::guest(stream, signing_key, anchor)
            .map_err(|error| anyhow::anyhow!("guest session handshake failed: {error}"))?;
        Ok(Self { inner })
    }

    /// Write one encrypted, signed control frame.
    pub fn write<T: Serialize>(&mut self, stream: &mut impl Write, value: &T) -> Result<()> {
        let plaintext = serde_json::to_vec(value).with_context(|| "serialize control payload")?;
        let sealed = self
            .inner
            .seal(&plaintext)
            .map_err(|error| anyhow::anyhow!("control frame seal failed: {error}"))?;
        let frame = AuthenticatedFrame {
            version: sealed.version,
            sig_alg: sealed.sig_alg,
            session_id: sealed.session_id,
            sequence: sealed.sequence,
            timestamp: sealed.timestamp,
            signed: SignedPayload {
                payload: sealed.ciphertext,
                signature: sealed.signature,
                signer_id: sealed.signer_id,
            },
        };
        write_frame(stream, &frame)?;
        Ok(())
    }

    /// Read, authenticate, decrypt, and deserialize one control frame.
    pub fn read<T: serde::de::DeserializeOwned>(&mut self, stream: &mut impl Read) -> Result<T> {
        let frame: AuthenticatedFrame = read_frame(stream)?;
        let sealed = SealedFrame {
            version: frame.version,
            sig_alg: frame.sig_alg,
            session_id: frame.session_id,
            sequence: frame.sequence,
            timestamp: frame.timestamp,
            signature: frame.signed.signature,
            signer_id: frame.signed.signer_id,
            ciphertext: frame.signed.payload,
        };
        let plaintext = self
            .inner
            .open(&sealed)
            .map_err(|error| anyhow::anyhow!("control frame open failed: {error}"))?;
        serde_json::from_slice(&plaintext).with_context(|| "deserialize decrypted control payload")
    }
}

impl From<Session> for AuthenticatedSession {
    fn from(inner: Session) -> Self {
        Self { inner }
    }
}

impl From<AuthenticatedSession> for Session {
    fn from(session: AuthenticatedSession) -> Self {
        session.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ========================================================================
    // Authenticated frame tests
    // ========================================================================

    fn test_keypair() -> SigningKey {
        {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        }
    }

    #[test]
    fn test_authenticated_frame_write_read_roundtrip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();
        let session_id = "test-session-001";

        let request = GuestRequest::Ping;

        write_authenticated_frame(&mut writer, &request, &key, "test-key", session_id, 1).unwrap();

        let (parsed, seq): (GuestRequest, u64) =
            read_authenticated_frame(&mut reader, &verifying, session_id, 0).unwrap();

        assert_eq!(seq, 1);
        assert!(matches!(parsed, GuestRequest::Ping));
    }

    #[test]
    fn test_authenticated_frame_complex_payload() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();
        let session_id = "complex-session";

        let response = GuestResponse::WorkerStatus {
            status: "busy".to_string(),
            last_busy_at: Some("2026-02-25T10:00:00Z".to_string()),
        };

        write_authenticated_frame(&mut writer, &response, &key, "guest", session_id, 42).unwrap();

        let (parsed, seq): (GuestResponse, u64) =
            read_authenticated_frame(&mut reader, &verifying, session_id, 0).unwrap();

        assert_eq!(seq, 42);
        match parsed {
            GuestResponse::WorkerStatus {
                status,
                last_busy_at,
            } => {
                assert_eq!(status, "busy");
                assert_eq!(last_busy_at.unwrap(), "2026-02-25T10:00:00Z");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_authenticated_frame_tampered_payload_rejected() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        // Write a valid authenticated frame
        let request = GuestRequest::Ping;
        write_authenticated_frame(&mut writer, &request, &key, "test", "sess", 1).unwrap();

        // Read the raw bytes and tamper with the payload
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).unwrap();
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; frame_len];
        reader.read_exact(&mut buf).unwrap();

        // Tamper: change a byte in the payload
        let mut frame: AuthenticatedFrame = serde_json::from_slice(&buf).unwrap();
        if !frame.signed.payload.is_empty() {
            frame.signed.payload[0] ^= 0xFF;
        }

        // Write tampered frame to a new stream
        let (mut w2, mut r2) = UnixStream::pair().unwrap();
        r2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_frame(&mut w2, &frame).unwrap();

        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut r2, &verifying, "sess", 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Signature verification failed") || err_msg.contains("deserialize"),
            "Unexpected error: {}",
            err_msg
        );
    }

    #[test]
    fn test_authenticated_frame_wrong_key_rejected() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key_a = test_keypair();
        let key_b = test_keypair();

        write_authenticated_frame(&mut writer, &GuestRequest::Ping, &key_a, "a", "sess", 1)
            .unwrap();

        // Try to verify with wrong key
        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &key_b.verifying_key(), "sess", 0);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Signature verification failed")
        );
    }

    #[test]
    fn test_authenticated_frame_replay_detection() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        // Write frame with sequence 5
        write_authenticated_frame(&mut writer, &GuestRequest::Ping, &key, "test", "sess", 5)
            .unwrap();

        // Try to read expecting minimum sequence 10 — should be rejected
        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &verifying, "sess", 10);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));
    }

    #[test]
    fn test_authenticated_frame_session_id_mismatch() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        write_authenticated_frame(
            &mut writer,
            &GuestRequest::Ping,
            &key,
            "test",
            "session-A",
            1,
        )
        .unwrap();

        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &verifying, "session-B", 0);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Session ID mismatch")
        );
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
    fn oversized_write_is_rejected_before_writing_any_bytes() {
        let payload = vec![0_u8; MAX_FRAME_SIZE + 1];
        let mut output = Cursor::new(Vec::new());

        let err = write_frame(&mut output, &payload).expect_err("oversized frame must fail");

        assert!(err.to_string().contains("Frame too large"));
        assert!(output.into_inner().is_empty());
    }

    #[test]
    fn test_handshake_then_authenticated_exchange() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let guest_key = test_keypair();
        let session_id = "full-exchange-test";

        // Handshake
        let host_handle = {
            let hk = SigningKey::from_bytes(&host_key.to_bytes());
            std::thread::spawn(move || {
                handshake_as_host(&mut host_stream, session_id, &hk).map(|gvk| (host_stream, gvk))
            })
        };

        let guest_handle = {
            let gk = SigningKey::from_bytes(&guest_key.to_bytes());
            std::thread::spawn(move || {
                handshake_as_guest(&mut guest_stream, &gk)
                    .map(|(hvk, sid)| (guest_stream, hvk, sid))
            })
        };

        let (mut host_stream, guest_vk) = host_handle.join().unwrap().unwrap();
        let (mut guest_stream, host_vk, _sid) = guest_handle.join().unwrap().unwrap();

        // Host sends authenticated request
        write_authenticated_frame(
            &mut host_stream,
            &GuestRequest::Ping,
            &host_key,
            "host",
            session_id,
            1,
        )
        .unwrap();

        // Guest reads and verifies
        let (req, seq): (GuestRequest, u64) =
            read_authenticated_frame(&mut guest_stream, &host_vk, session_id, 0).unwrap();
        assert!(matches!(req, GuestRequest::Ping));
        assert_eq!(seq, 1);

        // Guest sends authenticated response
        write_authenticated_frame(
            &mut guest_stream,
            &GuestResponse::Pong,
            &guest_key,
            "guest",
            session_id,
            1,
        )
        .unwrap();

        // Host reads and verifies
        let (resp, seq): (GuestResponse, u64) =
            read_authenticated_frame(&mut host_stream, &guest_vk, session_id, 0).unwrap();
        assert!(matches!(resp, GuestResponse::Pong));
        assert_eq!(seq, 1);
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
            let session =
                AuthenticatedSession::guest(&mut guest_stream, guest_key, &host_anchor).unwrap();
            (guest_stream, session)
        });
        let mut host_session =
            AuthenticatedSession::host(&mut host_stream, "confidential-test", host_key).unwrap();
        let (mut guest_stream, mut guest_session) = guest_thread.join().unwrap();

        host_session
            .write(&mut host_stream, &GuestRequest::Ping)
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
            .write(&mut host_stream, &GuestRequest::Ping)
            .unwrap();
        let frame: AuthenticatedFrame = read_frame(&mut guest_stream).unwrap();
        assert!(
            !frame
                .signed
                .payload
                .windows(b"Ping".len())
                .any(|window| window == b"Ping")
        );
        let (mut valid_writer, mut valid_reader) = UnixStream::pair().unwrap();
        write_frame(&mut valid_writer, &frame).unwrap();
        let accepted: GuestRequest = guest_session.read(&mut valid_reader).unwrap();
        assert!(matches!(accepted, GuestRequest::Ping));

        let (mut replay_writer, mut replay_reader) = UnixStream::pair().unwrap();
        write_frame(&mut replay_writer, &frame).unwrap();
        let replay: anyhow::Result<GuestRequest> = guest_session.read(&mut replay_reader);
        assert!(replay.is_err(), "replayed control frame must be rejected");

        host_session
            .write(&mut host_stream, &GuestRequest::Ping)
            .unwrap();
        let next_frame: AuthenticatedFrame = read_frame(&mut guest_stream).unwrap();
        assert_eq!(next_frame.sequence, 3);
        let mut tampered = next_frame;
        tampered.signed.payload[0] ^= 0x01;
        write_frame(&mut tamper_writer, &tampered).unwrap();
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
        };
        write_frame(&mut guest_stream, &ack).unwrap();

        // Host should succeed because the guest signed with wrong_key
        // but sent wrong_key's pubkey — the challenge was signed by the
        // key whose pubkey was provided, so verification passes.
        // This is correct: we verify the guest controls the key it claims.
        let result = host_handle.join().unwrap();
        assert!(result.is_ok());
    }
}
