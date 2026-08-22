//! Transport-independent authenticated session for vsock channels.
//!
//! Both the control-RPC path and the FlowMux networking path need the same
//! thing: an Ed25519-signed challenge, an X25519 key agreement, an AES-256-GCM
//! session key, and per-direction sequence numbers with replay rejection.
//! Keeping that machinery in one place means the security properties are
//! implemented once and the two protocols differ only in what they put inside
//! the sealed frames.
//!
//! The session is deliberately low-level. Callers bring their own framing:
//!
//! - `mvm-agentd::vsock` wraps sealed payloads in length-prefixed JSON
//!   `AuthenticatedFrame`s for control RPC.
//! - `mvm-network-endpoint` will wrap sealed payloads in `MVFM` binary frames
//!   for FlowMux.
//!
//! This module exposes `seal`/`open` on byte buffers; higher-level JSON
//! helpers are thin wrappers in the agentd vsock module.

use std::fmt;
use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::policy::security::{
    PROTOCOL_VERSION_AUTHENTICATED, SIG_ALG_ED25519, SessionHello, SessionHelloAck,
    SessionHelloConfirm,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Why a session operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The peer's identity did not match the pinned trust anchor.
    #[error("peer identity mismatch: {0}")]
    PeerIdentityMismatch(String),
    /// The peer sent an unexpected protocol version.
    #[error("unsupported protocol version {got} (expected {want})")]
    UnsupportedVersion { got: u8, want: u8 },
    /// The session ID in a frame did not match this session.
    #[error("session id mismatch: got '{got}', expected '{expected}'")]
    SessionIdMismatch { got: String, expected: String },
    /// A received sequence number was below the expected minimum.
    #[error("replay detected: sequence {got} < expected {expected}")]
    Replay { got: u64, expected: u64 },
    /// A received sequence number did not match the exact expected value.
    #[error("sequence mismatch: got {got}, expected {expected}")]
    SequenceMismatch { got: u64, expected: u64 },
    /// The peer's signature over a handshake proof or frame did not verify.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    /// The peer presented a public key of the wrong length or format.
    #[error("invalid peer key: {0}")]
    InvalidPeerKey(String),
    /// Decryption failed (tampered ciphertext or wrong key).
    #[error("decryption failed")]
    DecryptionFailed,
    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
    /// The send or receive sequence counter overflowed `u64`.
    #[error("sequence counter exhausted")]
    SequenceExhausted,
    /// A sealed frame was spent without reaching the peer, so the session can
    /// no longer be used in either direction.
    #[error(
        "session poisoned: frame {sequence} was sealed but never reached the peer ({reason}); \
         the sequence is spent and cannot be reissued"
    )]
    Poisoned {
        /// The sequence number the unsent frame consumed.
        sequence: u64,
        /// Why the frame did not reach the peer.
        reason: String,
    },
    /// A handshake message was malformed or inconsistent.
    #[error("invalid handshake: {0}")]
    InvalidHandshake(String),
    /// I/O error reading or writing the handshake or frame.
    #[error("session i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl SessionError {
    /// Whether the peer went away rather than failed to authenticate.
    ///
    /// These are different events and only one of them is security-relevant. A
    /// peer that disconnects part-way through the handshake produced no bad
    /// signature, no wrong identity and no replayed sequence — it produced
    /// nothing, and the read hit end-of-stream. On the guest's control socket
    /// that is the ordinary shape of the host's readiness poll, which connects
    /// on a backoff while the guest boots and drops each probe it has finished
    /// with.
    ///
    /// Callers use this to keep "someone tried to authenticate and failed"
    /// meaning what it says. A failure that fires on every healthy boot trains
    /// its audience to skip the line, and the next real one arrives to an
    /// audience that already knows to.
    pub fn is_peer_hangup(&self) -> bool {
        let Self::Io(e) = self else {
            return false;
        };
        matches!(
            e.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
        )
    }
}

impl From<anyhow::Error> for SessionError {
    fn from(value: anyhow::Error) -> Self {
        // Preserve the most common case as a generic variant; callers that
        // need the original message can log it before conversion.
        SessionError::InvalidHandshake(value.to_string())
    }
}

/// Which side of a session an instance plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// The host initiated the session and holds the guest's trust anchor.
    Host,
    /// The guest accepted the session and pins the host's identity.
    Guest,
}

impl SessionRole {
    const fn signer_id(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Guest => "guest",
        }
    }

    const fn peer_signer_id(self) -> &'static str {
        match self {
            Self::Host => "guest",
            Self::Guest => "host",
        }
    }

    const fn opposite(self) -> Self {
        match self {
            Self::Host => Self::Guest,
            Self::Guest => Self::Host,
        }
    }
}

impl fmt::Display for SessionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.signer_id())
    }
}

/// Material produced by a successful handshake, before the session key is
/// derived.
struct HandshakeMaterial {
    peer_verifying_key: VerifyingKey,
    session_id: String,
    shared_secret: [u8; 32],
}

impl Zeroize for HandshakeMaterial {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.shared_secret.zeroize();
        // VerifyingKey has no Zeroize impl; it is public material.
    }
}

/// A sealed payload ready to be placed inside a caller-defined frame.
///
/// The ciphertext includes the AES-GCM authentication tag. The signature
/// covers the frame context plus the ciphertext, so tampering with either is
/// detected before decryption is attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFrame {
    /// Protocol version. Currently always [`PROTOCOL_VERSION_AUTHENTICATED`].
    pub version: u8,
    /// Signature algorithm. Currently always [`SIG_ALG_ED25519`].
    pub sig_alg: u8,
    /// Session identifier this frame belongs to.
    pub session_id: String,
    /// Monotonic sequence number for replay rejection.
    pub sequence: u64,
    /// ISO 8601 timestamp of sealing.
    pub timestamp: String,
    /// Ed25519 signature over the frame context and ciphertext.
    pub signature: Vec<u8>,
    /// Signer label ("host" or "guest").
    pub signer_id: String,
    /// AES-256-GCM ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// A transport-independent authenticated session.
///
/// Created by [`Session::host`] or [`Session::guest`], then used to
/// [`seal`](Self::seal) outbound plaintext and [`open`](Self::open) inbound
/// sealed frames. Sequence numbers are enforced exactly in both directions.
pub struct Session {
    signing_key: SigningKey,
    peer_verifying_key: VerifyingKey,
    session_id: String,
    key: Zeroizing<[u8; 32]>,
    role: SessionRole,
    next_send_sequence: u64,
    next_receive_sequence: u64,
    poison: Option<Poison>,
}

/// A sealed frame that was spent without reaching the peer.
///
/// Recorded rather than rolled back: the AES-GCM nonce derives from
/// `(session_id, role, sequence)`, so re-sealing different plaintext under a
/// spent sequence would reuse a nonce. A session that kept going instead would
/// leave the peer one frame behind for the rest of its life, surfacing as an
/// unexplained sequence mismatch several frames later rather than as the write
/// failure that actually happened.
#[derive(Debug, Clone)]
struct Poison {
    sequence: u64,
    reason: String,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .field("next_send_sequence", &self.next_send_sequence)
            .field("next_receive_sequence", &self.next_receive_sequence)
            .field("poison", &self.poison)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Establish a host session using the host's long-lived signing identity.
    ///
    /// `session_id` must be unique per VM boot; reusing one across boots would
    /// let an old guest replay frames against a new instance.
    ///
    /// Returns the session and the guest's verifying key, so the host can log
    /// or audit the peer identity.
    pub fn host<S: Read + Write>(
        stream: &mut S,
        session_id: &str,
        signing_key: SigningKey,
    ) -> Result<(Self, VerifyingKey), SessionError> {
        let material = secure_host_handshake(stream, session_id, &signing_key)?;
        let peer_key = material.peer_verifying_key;
        let session = Self::from_material(signing_key, material, SessionRole::Host);
        Ok((session, peer_key))
    }

    /// Establish a guest session and require the host identity to match `anchor`.
    ///
    /// Returns the session and the session id assigned by the host.
    pub fn guest<S: Read + Write>(
        stream: &mut S,
        signing_key: SigningKey,
        anchor: &VerifyingKey,
    ) -> Result<(Self, String), SessionError> {
        let material = secure_guest_handshake(stream, &signing_key, anchor)?;
        let session_id = material.session_id.clone();
        let session = Self::from_material(signing_key, material, SessionRole::Guest);
        Ok((session, session_id))
    }

    fn from_material(
        signing_key: SigningKey,
        material: HandshakeMaterial,
        role: SessionRole,
    ) -> Self {
        Self {
            peer_verifying_key: material.peer_verifying_key,
            session_id: material.session_id.clone(),
            key: Zeroizing::new(derive_session_key(
                material.shared_secret,
                &material.session_id,
            )),
            signing_key,
            role,
            next_send_sequence: 1,
            next_receive_sequence: 1,
            poison: None,
        }
    }

    /// Record that `sequence` was sealed but never reached the peer, ending
    /// this session.
    ///
    /// Callers that own the transport must call this when writing a sealed
    /// frame fails. The sequence is spent either way — [`seal`](Self::seal)
    /// advances the counter before the frame can be handed to a transport, and
    /// it cannot be rewound without reusing an AES-GCM nonce. Every later
    /// [`seal`](Self::seal) and [`open`](Self::open) then refuses and names
    /// this cause, so the failure is reported where it happened instead of as
    /// a sequence mismatch on the peer.
    ///
    /// The first poison wins; a later one does not overwrite the original
    /// cause.
    pub fn poison_send(&mut self, sequence: u64, reason: impl Into<String>) {
        if self.poison.is_none() {
            self.poison = Some(Poison {
                sequence,
                reason: reason.into(),
            });
        }
    }

    /// Whether an unsent sealed frame has ended this session.
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    fn check_poison(&self) -> Result<(), SessionError> {
        match &self.poison {
            Some(poison) => Err(SessionError::Poisoned {
                sequence: poison.sequence,
                reason: poison.reason.clone(),
            }),
            None => Ok(()),
        }
    }

    /// The session identifier.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Which role this side plays.
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// The peer's verified Ed25519 public key.
    pub fn peer_verifying_key(&self) -> &VerifyingKey {
        &self.peer_verifying_key
    }

    /// Seal `plaintext` into an authenticated, encrypted frame.
    ///
    /// Advances the outbound sequence counter. The returned [`SealedFrame`]
    /// is owned; the caller frames it for transport.
    ///
    /// The sequence is spent the moment this returns, whether or not the frame
    /// reaches the peer, so a caller whose transport write fails must call
    /// [`poison_send`](Self::poison_send) with the frame's sequence. Dropping
    /// the frame silently leaves the peer permanently one frame behind.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<SealedFrame, SessionError> {
        self.check_poison()?;
        let sequence = self.next_send_sequence;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let context = frame_context(
            &self.session_id,
            sequence,
            &timestamp,
            self.role.signer_id(),
        )
        .map_err(|e| SessionError::InvalidHandshake(e.to_string()))?;
        let nonce = session_nonce(&self.session_id, self.role, sequence);
        let cipher = new_cipher(self.key.as_ref())?;
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| SessionError::EncryptionFailed)?;

        let mut signed_bytes = context;
        signed_bytes.extend_from_slice(&ciphertext);
        let signature = self.signing_key.sign(&signed_bytes).to_bytes().to_vec();

        self.next_send_sequence = sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceExhausted)?;

        Ok(SealedFrame {
            version: PROTOCOL_VERSION_AUTHENTICATED,
            sig_alg: SIG_ALG_ED25519,
            session_id: self.session_id.clone(),
            sequence,
            timestamp,
            signature,
            signer_id: self.role.signer_id().to_string(),
            ciphertext,
        })
    }

    /// Verify and decrypt a sealed frame from the peer.
    ///
    /// Rejects replay, wrong session, wrong signer, bad signature, and
    /// tampered ciphertext. Advances the inbound sequence counter on success.
    pub fn open(&mut self, frame: &SealedFrame) -> Result<Vec<u8>, SessionError> {
        self.check_poison()?;
        if frame.version != PROTOCOL_VERSION_AUTHENTICATED || frame.sig_alg != SIG_ALG_ED25519 {
            return Err(SessionError::UnsupportedVersion {
                got: frame.version,
                want: PROTOCOL_VERSION_AUTHENTICATED,
            });
        }
        if frame.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                got: frame.session_id.clone(),
                expected: self.session_id.clone(),
            });
        }
        if frame.sequence != self.next_receive_sequence {
            return Err(if frame.sequence < self.next_receive_sequence {
                SessionError::Replay {
                    got: frame.sequence,
                    expected: self.next_receive_sequence,
                }
            } else {
                SessionError::SequenceMismatch {
                    got: frame.sequence,
                    expected: self.next_receive_sequence,
                }
            });
        }
        if frame.signer_id != self.role.peer_signer_id() {
            return Err(SessionError::PeerIdentityMismatch(format!(
                "signer '{0}' is not the expected '{1}'",
                frame.signer_id,
                self.role.peer_signer_id()
            )));
        }
        let context = frame_context(
            &frame.session_id,
            frame.sequence,
            &frame.timestamp,
            &frame.signer_id,
        )
        .map_err(|e| SessionError::InvalidHandshake(e.to_string()))?;
        let mut signed_bytes = context;
        signed_bytes.extend_from_slice(&frame.ciphertext);
        verify_signature(
            &frame.signature,
            &signed_bytes,
            &self.peer_verifying_key,
            "frame",
        )?;

        let nonce = session_nonce(&self.session_id, self.role.opposite(), frame.sequence);
        let cipher = new_cipher(self.key.as_ref())?;
        let plaintext = cipher
            .decrypt(&Nonce::from(nonce), frame.ciphertext.as_ref())
            .map_err(|_| SessionError::DecryptionFailed)?;

        self.next_receive_sequence = frame
            .sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceExhausted)?;

        Ok(plaintext)
    }
}

impl SealedFrame {
    /// Encode this sealed frame into a compact binary representation.
    ///
    /// Layout:
    ///   version (u8), sig_alg (u8),
    ///   session_id_len (u8), session_id (bytes),
    ///   sequence (u64 BE),
    ///   timestamp_len (u8), timestamp (bytes),
    ///   signer_id_len (u8), signer_id (bytes),
    ///   signature_len (u16 BE), signature (bytes),
    ///   ciphertext_len (u32 BE), ciphertext (bytes).
    pub fn encode(&self, dst: &mut Vec<u8>) -> Result<(), SessionError> {
        let session_id_len = u8::try_from(self.session_id.len())
            .map_err(|_| SessionError::InvalidHandshake("session_id too long".into()))?;
        let timestamp_len = u8::try_from(self.timestamp.len())
            .map_err(|_| SessionError::InvalidHandshake("timestamp too long".into()))?;
        let signer_id_len = u8::try_from(self.signer_id.len())
            .map_err(|_| SessionError::InvalidHandshake("signer_id too long".into()))?;
        let signature_len = u16::try_from(self.signature.len())
            .map_err(|_| SessionError::InvalidHandshake("signature too long".into()))?;
        let ciphertext_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| SessionError::InvalidHandshake("ciphertext too long".into()))?;

        dst.reserve(
            1 + 1
                + 1
                + self.session_id.len()
                + 8
                + 1
                + self.timestamp.len()
                + 1
                + self.signer_id.len()
                + 2
                + self.signature.len()
                + 4
                + self.ciphertext.len(),
        );

        dst.push(self.version);
        dst.push(self.sig_alg);
        dst.push(session_id_len);
        dst.extend_from_slice(self.session_id.as_bytes());
        dst.extend_from_slice(&self.sequence.to_be_bytes());
        dst.push(timestamp_len);
        dst.extend_from_slice(self.timestamp.as_bytes());
        dst.push(signer_id_len);
        dst.extend_from_slice(self.signer_id.as_bytes());
        dst.extend_from_slice(&signature_len.to_be_bytes());
        dst.extend_from_slice(&self.signature);
        dst.extend_from_slice(&ciphertext_len.to_be_bytes());
        dst.extend_from_slice(&self.ciphertext);
        Ok(())
    }

    /// Decode a sealed frame from its compact binary representation.
    pub fn decode(src: &[u8]) -> Result<Self, SessionError> {
        if src.len() < 1 + 1 + 1 + 8 + 1 + 1 + 1 + 2 + 4 {
            return Err(SessionError::InvalidHandshake(
                "sealed frame too short".into(),
            ));
        }
        let mut pos = 0_usize;

        let version = src[pos];
        pos += 1;
        let sig_alg = src[pos];
        pos += 1;

        let session_id_len = src[pos] as usize;
        pos += 1;
        if src.len() < pos + session_id_len {
            return Err(SessionError::InvalidHandshake(
                "session_id truncated".into(),
            ));
        }
        let session_id = String::from_utf8(src[pos..pos + session_id_len].to_vec())
            .map_err(|_| SessionError::InvalidHandshake("session_id not utf-8".into()))?;
        pos += session_id_len;

        if src.len() < pos + 8 {
            return Err(SessionError::InvalidHandshake("sequence truncated".into()));
        }
        let sequence = u64::from_be_bytes([
            src[pos],
            src[pos + 1],
            src[pos + 2],
            src[pos + 3],
            src[pos + 4],
            src[pos + 5],
            src[pos + 6],
            src[pos + 7],
        ]);
        pos += 8;

        if src.len() < pos + 1 {
            return Err(SessionError::InvalidHandshake(
                "timestamp length truncated".into(),
            ));
        }
        let timestamp_len = src[pos] as usize;
        pos += 1;
        if src.len() < pos + timestamp_len {
            return Err(SessionError::InvalidHandshake("timestamp truncated".into()));
        }
        let timestamp = String::from_utf8(src[pos..pos + timestamp_len].to_vec())
            .map_err(|_| SessionError::InvalidHandshake("timestamp not utf-8".into()))?;
        pos += timestamp_len;

        if src.len() < pos + 1 {
            return Err(SessionError::InvalidHandshake(
                "signer_id length truncated".into(),
            ));
        }
        let signer_id_len = src[pos] as usize;
        pos += 1;
        if src.len() < pos + signer_id_len {
            return Err(SessionError::InvalidHandshake("signer_id truncated".into()));
        }
        let signer_id = String::from_utf8(src[pos..pos + signer_id_len].to_vec())
            .map_err(|_| SessionError::InvalidHandshake("signer_id not utf-8".into()))?;
        pos += signer_id_len;

        if src.len() < pos + 2 {
            return Err(SessionError::InvalidHandshake(
                "signature length truncated".into(),
            ));
        }
        let signature_len = u16::from_be_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        if src.len() < pos + signature_len {
            return Err(SessionError::InvalidHandshake("signature truncated".into()));
        }
        let signature = src[pos..pos + signature_len].to_vec();
        pos += signature_len;

        if src.len() < pos + 4 {
            return Err(SessionError::InvalidHandshake(
                "ciphertext length truncated".into(),
            ));
        }
        let ciphertext_len =
            u32::from_be_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]) as usize;
        pos += 4;
        if src.len() < pos + ciphertext_len {
            return Err(SessionError::InvalidHandshake(
                "ciphertext truncated".into(),
            ));
        }
        let ciphertext = src[pos..pos + ciphertext_len].to_vec();
        pos += ciphertext_len;

        if pos != src.len() {
            return Err(SessionError::InvalidHandshake(
                "trailing bytes after sealed frame".into(),
            ));
        }

        Ok(Self {
            version,
            sig_alg,
            session_id,
            sequence,
            timestamp,
            signature,
            signer_id,
            ciphertext,
        })
    }
}

/// Read a length-prefixed sealed frame from a stream.
///
/// The length prefix is a 4-byte big-endian integer. `max_len` bounds the
/// accepted sealed frame size.
pub fn read_sealed_frame<R: Read>(
    stream: &mut R,
    max_len: usize,
) -> Result<SealedFrame, SessionError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let frame_len =
        usize::try_from(u32::from_be_bytes(len_buf)).expect("u32 frame length fits usize");
    if frame_len > max_len {
        return Err(SessionError::InvalidHandshake(format!(
            "sealed frame length {frame_len} exceeds maximum {max_len}"
        )));
    }
    let mut buf = vec![0u8; frame_len];
    stream.read_exact(&mut buf)?;
    SealedFrame::decode(&buf)
}

/// Write a sealed frame to a stream with a 4-byte big-endian length prefix.
pub fn write_sealed_frame<W: Write>(
    stream: &mut W,
    frame: &SealedFrame,
) -> Result<(), SessionError> {
    let mut buf = Vec::new();
    frame.encode(&mut buf)?;
    let len = u32::try_from(buf.len())
        .expect("bounded sealed frame length fits u32")
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&buf)?;
    stream.flush()?;
    Ok(())
}

fn new_cipher(key: &[u8]) -> Result<Aes256Gcm, SessionError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| SessionError::EncryptionFailed)
}

fn random_bytes() -> Vec<u8> {
    (0..32).map(|_| rand::random::<u8>()).collect()
}

fn session_transcript(
    hello: &SessionHello,
    ack: &SessionHelloAck,
) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&(hello, ack)).map_err(|e| SessionError::InvalidHandshake(e.to_string()))
}

fn guest_challenge_message(
    hello: &SessionHello,
    ack: &SessionHelloAck,
) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&(
        "mvm-vsock-guest-auth-v1",
        &hello.version,
        &hello.session_id,
        &hello.challenge,
        &hello.host_pubkey,
        &hello.host_ephemeral_pubkey,
        &ack.guest_pubkey,
        &ack.guest_ephemeral_pubkey,
        &ack.guest_challenge,
    ))
    .map_err(|e| SessionError::InvalidHandshake(e.to_string()))
}

fn parse_verifying_key(bytes: &[u8], label: &str) -> Result<VerifyingKey, SessionError> {
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        SessionError::InvalidPeerKey(format!("{label} Ed25519 key must be 32 bytes"))
    })?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| SessionError::InvalidPeerKey(format!("invalid {label} Ed25519 key")))
}

fn parse_public_key(bytes: &[u8], label: &str) -> Result<PublicKey, SessionError> {
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        SessionError::InvalidPeerKey(format!("{label} X25519 key must be 32 bytes"))
    })?;
    Ok(PublicKey::from(key_bytes))
}

fn verify_signature(
    bytes: &[u8],
    message: &[u8],
    key: &VerifyingKey,
    label: &str,
) -> Result<(), SessionError> {
    let signature_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        SessionError::SignatureVerificationFailed(format!("{label} signature must be 64 bytes"))
    })?;
    key.verify(message, &Signature::from_bytes(&signature_bytes))
        .map_err(|error| {
            SessionError::SignatureVerificationFailed(format!(
                "{label} signature verification failed: {error}"
            ))
        })
}

fn derive_session_key(shared_secret: [u8; 32], session_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-vsock-control-key-v1");
    hasher.update(shared_secret);
    hasher.update(session_id.as_bytes());
    hasher.finalize().into()
}

fn frame_context(
    session_id: &str,
    sequence: u64,
    timestamp: &str,
    signer_id: &str,
) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&(
        "mvm-vsock-control-frame-v1",
        session_id,
        sequence,
        timestamp,
        signer_id,
    ))
    .map_err(|e| SessionError::InvalidHandshake(e.to_string()))
}

fn session_nonce(session_id: &str, role: SessionRole, sequence: u64) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-vsock-control-nonce-v1");
    hasher.update(session_id.as_bytes());
    hasher.update(role.signer_id().as_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    digest[..12]
        .try_into()
        .expect("SHA-256 digest has at least 12 bytes")
}

/// Read a single length-prefixed JSON frame from a stream.
///
/// This helper exists so the handshake messages (which are still JSON) can be
/// shared between the control-RPC path and any future caller without each
/// caller reimplementing the length prefix.
pub fn read_json_frame<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    max_len: usize,
) -> Result<T, SessionError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let frame_len =
        usize::try_from(u32::from_be_bytes(len_buf)).expect("u32 frame length fits usize");
    if frame_len > max_len {
        return Err(SessionError::InvalidHandshake(format!(
            "frame length {frame_len} exceeds maximum {max_len}"
        )));
    }
    let mut buf = vec![0u8; frame_len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| SessionError::InvalidHandshake(e.to_string()))
}

/// Write a single length-prefixed JSON frame to a stream.
///
/// Pair of [`read_json_frame`].
pub fn write_json_frame<T: Serialize>(
    stream: &mut impl Write,
    value: &T,
    max_len: usize,
) -> Result<(), SessionError> {
    let data =
        serde_json::to_vec(value).map_err(|e| SessionError::InvalidHandshake(e.to_string()))?;
    if data.len() > max_len {
        return Err(SessionError::InvalidHandshake(format!(
            "frame length {} exceeds maximum {max_len}",
            data.len()
        )));
    }
    let len = u32::try_from(data.len())
        .expect("bounded frame length fits u32")
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn secure_host_handshake<S: Read + Write>(
    stream: &mut S,
    session_id: &str,
    host_signing_key: &SigningKey,
) -> Result<HandshakeMaterial, SessionError> {
    let host_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let hello = SessionHello {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        session_id: session_id.to_string(),
        challenge: random_bytes(),
        host_pubkey: host_signing_key.verifying_key().to_bytes().to_vec(),
        host_ephemeral_pubkey: PublicKey::from(&host_secret).as_bytes().to_vec(),
    };
    write_json_frame(stream, &hello, 1 << 16)?;

    let ack: SessionHelloAck = read_json_frame(stream, 1 << 16)?;
    if ack.version != hello.version || ack.session_id != hello.session_id {
        return Err(SessionError::InvalidHandshake(
            "invalid or mismatched HelloAck session".to_string(),
        ));
    }
    if ack.guest_challenge.len() != 32 {
        return Err(SessionError::InvalidHandshake(
            "guest handshake challenge must be 32 bytes".to_string(),
        ));
    }
    let guest_key = parse_verifying_key(&ack.guest_pubkey, "guest")?;
    let proof = guest_challenge_message(&hello, &ack)?;
    verify_signature(
        &ack.challenge_response,
        &proof,
        &guest_key,
        "guest handshake",
    )?;
    let transcript = session_transcript(&hello, &ack)?;
    write_json_frame(
        stream,
        &SessionHelloConfirm {
            version: hello.version,
            session_id: hello.session_id.clone(),
            transcript_signature: host_signing_key.sign(&transcript).to_bytes().to_vec(),
        },
        1 << 16,
    )?;
    let guest_public = parse_public_key(&ack.guest_ephemeral_pubkey, "guest")?;
    Ok(HandshakeMaterial {
        peer_verifying_key: guest_key,
        session_id: hello.session_id,
        shared_secret: host_secret.diffie_hellman(&guest_public).to_bytes(),
    })
}

fn secure_guest_handshake<S: Read + Write>(
    stream: &mut S,
    guest_signing_key: &SigningKey,
    expected_host_key: &VerifyingKey,
) -> Result<HandshakeMaterial, SessionError> {
    let hello: SessionHello = read_json_frame(stream, 1 << 16)?;
    if hello.version != PROTOCOL_VERSION_AUTHENTICATED
        || hello.challenge.len() != 32
        || hello.session_id.is_empty()
    {
        return Err(SessionError::InvalidHandshake(
            "invalid SessionHello".to_string(),
        ));
    }
    let host_key = parse_verifying_key(&hello.host_pubkey, "host")?;
    if &host_key != expected_host_key {
        return Err(SessionError::PeerIdentityMismatch(
            "host key does not match pinned trust anchor".to_string(),
        ));
    }
    let guest_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let mut ack = SessionHelloAck {
        version: hello.version,
        session_id: hello.session_id.clone(),
        challenge_response: Vec::new(),
        guest_pubkey: guest_signing_key.verifying_key().to_bytes().to_vec(),
        guest_ephemeral_pubkey: PublicKey::from(&guest_secret).as_bytes().to_vec(),
        guest_challenge: random_bytes(),
    };
    let proof = guest_challenge_message(&hello, &ack)?;
    ack.challenge_response = guest_signing_key.sign(&proof).to_bytes().to_vec();
    write_json_frame(stream, &ack, 1 << 16)?;

    let confirm: SessionHelloConfirm = read_json_frame(stream, 1 << 16)?;
    if confirm.version != hello.version || confirm.session_id != hello.session_id {
        return Err(SessionError::InvalidHandshake(
            "invalid or mismatched HelloConfirm".to_string(),
        ));
    }
    let transcript = session_transcript(&hello, &ack)?;
    verify_signature(
        &confirm.transcript_signature,
        &transcript,
        &host_key,
        "host handshake",
    )?;
    let host_public = parse_public_key(&hello.host_ephemeral_pubkey, "host")?;
    Ok(HandshakeMaterial {
        peer_verifying_key: host_key,
        session_id: hello.session_id,
        shared_secret: guest_secret.diffie_hellman(&host_public).to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use serde::Deserialize;
    use std::io::Cursor;
    use std::time::Duration;

    fn test_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn pair() -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (a, b)
    }

    /// Two sessions that share the same key material, as if a handshake had
    /// just completed. The host uses `host_key`, the guest uses `guest_key`,
    /// and each knows the other's verifying key.
    fn paired_sessions() -> (Session, Session) {
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let shared_secret = rand::random::<[u8; 32]>();
        let session_id = "paired-test-session";

        let host = Session::from_material(
            host_key.clone(),
            HandshakeMaterial {
                peer_verifying_key: guest_key.verifying_key(),
                session_id: session_id.to_string(),
                shared_secret,
            },
            SessionRole::Host,
        );
        let guest = Session::from_material(
            guest_key,
            HandshakeMaterial {
                peer_verifying_key: host_key.verifying_key(),
                session_id: session_id.to_string(),
                shared_secret,
            },
            SessionRole::Guest,
        );
        (host, guest)
    }

    #[test]
    fn handshake_host_and_guest_succeed() {
        let (mut host_stream, mut guest_stream) = pair();
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let session_id = "test-session-001";

        std::thread::scope(|scope| {
            let host_key_clone = host_key.clone();
            let guest_verify = guest_key.verifying_key();
            let host_verify = host_key.verifying_key();
            scope.spawn(move || {
                let (session, peer_key) =
                    Session::host(&mut host_stream, session_id, host_key_clone).unwrap();
                assert_eq!(peer_key, guest_verify);
                assert_eq!(session.session_id(), session_id);
            });
            let (session, received_session_id) =
                Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
            assert_eq!(received_session_id, session_id);
            assert_eq!(session.peer_verifying_key(), &host_verify);
        });
    }

    #[test]
    fn poisoning_ends_the_session_in_both_directions() {
        let (mut host, mut guest) = paired_sessions();

        // A frame the transport accepted, to prove the poison is what stops
        // the session rather than it never having worked.
        let good = host.seal(b"first").unwrap();
        assert_eq!(guest.open(&good).unwrap(), b"first");

        // Sequence 2 is now spent on a frame the peer will never see.
        let spent = host.seal(b"lost to the transport").unwrap();
        assert_eq!(spent.sequence, 2);
        host.poison_send(spent.sequence, "Frame too large: 700000 bytes (max 262144)");

        assert!(host.is_poisoned());
        let err = host.seal(b"third").unwrap_err();
        let SessionError::Poisoned { sequence, reason } = err else {
            panic!("expected Poisoned, got {err}");
        };
        assert_eq!(sequence, 2);
        assert!(
            reason.contains("Frame too large"),
            "the poison must carry the original cause, got {reason}"
        );

        // Inbound too: a poisoned session is finished, not half usable.
        let from_guest = guest.seal(b"reply").unwrap();
        assert!(matches!(
            host.open(&from_guest),
            Err(SessionError::Poisoned { .. })
        ));
    }

    #[test]
    fn the_first_poison_cause_survives_a_later_one() {
        let (mut host, _guest) = paired_sessions();
        host.poison_send(1, "original cause");
        host.poison_send(2, "downstream noise");
        let SessionError::Poisoned { sequence, reason } = host.seal(b"x").unwrap_err() else {
            panic!("expected Poisoned");
        };
        assert_eq!(sequence, 1);
        assert_eq!(reason, "original cause");
    }

    /// The failure this replaces: without the poison the session kept sealing,
    /// so the peer's very next `open` rejected a sequence gap it could not
    /// explain. Pinned so a regression reads as the confusing error again.
    #[test]
    fn without_poisoning_a_dropped_frame_would_desync_the_peer() {
        let (mut host, mut guest) = paired_sessions();
        let _dropped = host.seal(b"never written").unwrap();
        let next = host.seal(b"written").unwrap();
        assert!(matches!(
            guest.open(&next),
            Err(SessionError::SequenceMismatch {
                got: 2,
                expected: 1
            })
        ));
    }

    #[test]
    fn seal_open_roundtrip_between_peers() {
        let (mut host, mut guest) = paired_sessions();

        let plaintext = b"hello flowmux";
        let sealed = host.seal(plaintext).unwrap();
        let opened = guest.open(&sealed).unwrap();
        assert_eq!(opened, plaintext);

        // Guest can respond.
        let response = b"ack";
        let sealed2 = guest.seal(response).unwrap();
        let opened2 = host.open(&sealed2).unwrap();
        assert_eq!(opened2, response);
    }

    #[test]
    fn sealed_frame_encode_decode_roundtrip() {
        let (mut host, _guest) = paired_sessions();
        let sealed = host.seal(b"hello flowmux").unwrap();

        let mut buf = Vec::new();
        sealed.encode(&mut buf).unwrap();
        let decoded = SealedFrame::decode(&buf).unwrap();

        assert_eq!(decoded.version, sealed.version);
        assert_eq!(decoded.sig_alg, sealed.sig_alg);
        assert_eq!(decoded.session_id, sealed.session_id);
        assert_eq!(decoded.sequence, sealed.sequence);
        assert_eq!(decoded.timestamp, sealed.timestamp);
        assert_eq!(decoded.signer_id, sealed.signer_id);
        assert_eq!(decoded.signature, sealed.signature);
        assert_eq!(decoded.ciphertext, sealed.ciphertext);
    }

    #[test]
    fn sealed_frame_length_prefixed_roundtrip() {
        let (mut host, mut guest) = paired_sessions();
        let plaintext = b"length-prefixed secret";
        let sealed = host.seal(plaintext).unwrap();

        let mut buf = Vec::new();
        write_sealed_frame(&mut buf, &sealed).unwrap();
        let decoded = read_sealed_frame(&mut buf.as_slice(), 1 << 20).unwrap();
        let opened = guest.open(&decoded).unwrap();
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn replay_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let frame = host.seal(b"first").unwrap();
        guest.open(&frame).unwrap();

        let replay_err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(replay_err, SessionError::Replay { .. }),
            "expected replay error, got {replay_err}"
        );
    }

    #[test]
    fn out_of_order_frame_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let first = host.seal(b"first").unwrap();
        let second = host.seal(b"second").unwrap();

        let err = guest.open(&second).unwrap_err();
        assert!(
            matches!(err, SessionError::SequenceMismatch { .. }),
            "expected sequence mismatch, got {err}"
        );

        // First frame still works once order is restored.
        guest.open(&first).unwrap();
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let mut frame = host.seal(b"secret").unwrap();
        if !frame.ciphertext.is_empty() {
            frame.ciphertext[0] ^= 0xFF;
        }
        let err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(err, SessionError::SignatureVerificationFailed(_))
                || matches!(err, SessionError::DecryptionFailed),
            "expected auth/decrypt failure, got {err}"
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let mut frame = host.seal(b"secret").unwrap();
        if !frame.signature.is_empty() {
            frame.signature[0] ^= 0xFF;
        }
        let err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(err, SessionError::SignatureVerificationFailed(_)),
            "expected signature failure, got {err}"
        );
    }

    #[test]
    fn wrong_session_id_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let mut frame = host.seal(b"secret").unwrap();
        frame.session_id = "wrong-session".to_string();
        let err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(err, SessionError::SessionIdMismatch { .. }),
            "expected session id mismatch, got {err}"
        );
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let (mut host, mut guest) = paired_sessions();

        let mut frame = host.seal(b"secret").unwrap();
        frame.signer_id = "guest".to_string();
        // Re-sign with the host key under the wrong signer label context.
        let context = frame_context(
            &frame.session_id,
            frame.sequence,
            &frame.timestamp,
            &frame.signer_id,
        )
        .unwrap();
        let mut signed_bytes = context;
        signed_bytes.extend_from_slice(&frame.ciphertext);
        frame.signature = host.signing_key.sign(&signed_bytes).to_bytes().to_vec();
        let err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(err, SessionError::PeerIdentityMismatch(_)),
            "expected signer mismatch, got {err}"
        );
    }

    #[test]
    fn sequence_exhaustion_is_rejected_on_send() {
        let mut host = make_host_session();
        host.next_send_sequence = u64::MAX;
        let err = host.seal(b"last").unwrap_err();
        assert!(
            matches!(err, SessionError::SequenceExhausted),
            "expected sequence exhausted on send, got {err}"
        );
    }

    #[test]
    fn sequence_exhaustion_is_rejected_on_receive() {
        let (host, mut guest) = paired_sessions();
        let session_id = host.session_id.clone();

        // Manually build a valid host frame at sequence u64::MAX using the
        // shared session key, then verify the guest rejects it because the
        // receive counter cannot advance past u64::MAX.
        let plaintext = b"last";
        let sequence = u64::MAX;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let context = frame_context(&session_id, sequence, &timestamp, "host").unwrap();
        let nonce = session_nonce(&session_id, SessionRole::Host, sequence);
        let cipher = Aes256Gcm::new_from_slice(host.key.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plaintext.as_ref())
            .unwrap();
        let mut signed_bytes = context;
        signed_bytes.extend_from_slice(&ciphertext);
        let signature = host.signing_key.sign(&signed_bytes).to_bytes().to_vec();
        let frame = SealedFrame {
            version: PROTOCOL_VERSION_AUTHENTICATED,
            sig_alg: SIG_ALG_ED25519,
            session_id,
            sequence,
            timestamp,
            signature,
            signer_id: "host".to_string(),
            ciphertext,
        };

        guest.next_receive_sequence = u64::MAX;
        let err = guest.open(&frame).unwrap_err();
        assert!(
            matches!(err, SessionError::SequenceExhausted),
            "expected sequence exhausted on receive, got {err}"
        );
    }

    #[test]
    fn handshake_with_wrong_anchor_fails() {
        let (mut host_stream, mut guest_stream) = pair();
        let host_key = test_keypair();
        let guest_key = test_keypair();
        let wrong_key = test_keypair();

        std::thread::scope(|scope| {
            let host_key_clone = host_key.clone();
            scope.spawn(move || {
                let _ = Session::host(&mut host_stream, "s", host_key_clone);
            });
            let err = Session::guest(&mut guest_stream, guest_key, &wrong_key.verifying_key())
                .unwrap_err();
            assert!(
                matches!(err, SessionError::PeerIdentityMismatch(_)),
                "expected peer identity mismatch, got {err}"
            );
        });
    }

    #[test]
    fn json_frame_helpers_roundtrip() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Ping {
            n: u32,
        }
        let mut buf = Cursor::new(Vec::new());
        write_json_frame(&mut buf, &Ping { n: 42 }, 1 << 16).unwrap();
        buf.set_position(0);
        let decoded: Ping = read_json_frame(&mut buf, 1 << 16).unwrap();
        assert_eq!(decoded, Ping { n: 42 });
    }

    fn make_host_session() -> Session {
        let key = test_keypair();
        Session::from_material(
            key,
            HandshakeMaterial {
                peer_verifying_key: test_keypair().verifying_key(),
                session_id: "local-test".to_string(),
                shared_secret: rand::random::<[u8; 32]>(),
            },
            SessionRole::Host,
        )
    }

    /// The whole point of the predicate is what it refuses to classify. A
    /// signature that did not verify, an identity that did not match, a
    /// replayed sequence — those are the events the log line exists for, and
    /// none of them may be quietly reclassified as "the peer went away".
    #[test]
    fn only_a_vanished_peer_counts_as_a_hangup() {
        use std::io::ErrorKind;

        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
        ] {
            assert!(
                SessionError::Io(std::io::Error::from(kind)).is_peer_hangup(),
                "{kind:?} is a peer that went away"
            );
        }

        // Other I/O failures are real failures: the peer is still there and
        // something else broke.
        for kind in [ErrorKind::PermissionDenied, ErrorKind::InvalidData] {
            assert!(
                !SessionError::Io(std::io::Error::from(kind)).is_peer_hangup(),
                "{kind:?} is not a hangup"
            );
        }

        // Every authentication failure stays an authentication failure.
        for err in [
            SessionError::PeerIdentityMismatch("wrong key".into()),
            SessionError::SignatureVerificationFailed("bad sig".into()),
            SessionError::Replay {
                got: 1,
                expected: 9,
            },
            SessionError::UnsupportedVersion { got: 9, want: 1 },
            SessionError::InvalidHandshake("truncated".into()),
        ] {
            assert!(
                !err.is_peer_hangup(),
                "{err} must not be reclassified as a hangup"
            );
        }
    }
}
