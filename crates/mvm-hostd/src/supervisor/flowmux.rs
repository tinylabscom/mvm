//! FlowMux session acceptor for the single workload networking endpoint.
//!
//! This module owns the host side of one authenticated FlowMux session:
//! handshake, frame I/O, and dispatch to the per-flow handlers. The current
//! implementation accepts one session, completes the handshake, and then
//! rejects every flow frame with `GoAway`. That is enough to prove the session
//! plumbing and gives the next changes a stable place to add `OpenTcp`,
//! `OpenUdp`, `Resolve`, and typed-HTTP dispatch.

use std::io::{Read, Write};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, Opcode, SessionValidator, decode,
};
use mvm_core::net::session::Session;
use tracing::{info, warn};

/// Why the FlowMux session ended.
#[derive(Debug, thiserror::Error)]
pub enum FlowMuxError {
    /// Handshake with the guest failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame from the guest violated the protocol or session state.
    #[error("frame refused: {0}")]
    FrameRefused(String),
    /// An I/O error occurred on the transport.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}

/// Host-owned context for one FlowMux session.
impl<S: Read + Write> std::fmt::Debug for FlowMuxSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowMuxSession")
            .field("session_id", &self.session_id())
            .finish_non_exhaustive()
    }
}

pub struct FlowMuxSession<S> {
    stream: S,
    session: Session,
    validator: SessionValidator,
    read_buf: Vec<u8>,
}

impl<S: Read + Write> FlowMuxSession<S> {
    /// Return the session identifier for logging and correlation.
    pub fn session_id(&self) -> &str {
        self.session.session_id()
    }

    /// Accept one authenticated FlowMux session on `stream`.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept(
        mut stream: S,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
    ) -> Result<Self, FlowMuxError> {
        let (session, _peer_key) = Session::host(&mut stream, session_id, host_key)
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        if session.peer_verifying_key() != guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }

        info!(session_id, "FlowMux handshake complete");

        Ok(Self {
            stream,
            session,
            validator: SessionValidator::default(),
            read_buf: Vec::with_capacity(4096),
        })
    }

    /// Serve the session until it closes or errors.
    ///
    /// The skeleton accepts the handshake, acknowledges with `HelloAck`, and
    /// then sends `GoAway` for any flow frame. Future work fills in the
    /// per-opcode dispatch table.
    pub fn serve(&mut self) -> Result<(), FlowMuxError> {
        // Wait for the guest's Hello, then acknowledge. The authenticated
        // session is already established; this is the FlowMux session opening.
        match self.read_frame()? {
            Some((Opcode::Hello, 0, 0)) => {}
            Some((opcode, _, _)) => {
                return Err(FlowMuxError::FrameRefused(format!(
                    "expected Hello as first FlowMux frame, got {opcode:?}"
                )));
            }
            None => {
                return Err(FlowMuxError::FrameRefused(
                    "peer closed before Hello".to_string(),
                ));
            }
        }

        self.validator
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
            ))
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        self.send_hello_ack()?;
        self.validator
            .mark_hello_ack_sent()
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        loop {
            let (opcode, stream_id, payload_len) = match self.read_frame()? {
                Some(facts) => facts,
                None => {
                    info!("FlowMux peer closed session");
                    return Ok(());
                }
            };

            if let Err(e) = self.validator.admit(
                &mvm_contract::protocol::network_flow::FrameFacts::new(
                    Direction::GuestToHost,
                    opcode,
                    stream_id,
                )
                .with_payload(payload_len),
            ) {
                warn!(error = %e, "FlowMux frame refused by session validator");
                self.send_goaway(&e.to_string())?;
                return Ok(());
            }

            match opcode {
                Opcode::Hello => {
                    // A second Hello is illegal after the session is established;
                    // the validator already refuses it.
                }
                _ => {
                    warn!(?opcode, "FlowMux skeleton rejects flow frame");
                    self.send_goaway("flow frames not yet implemented")?;
                    return Ok(());
                }
            }
        }
    }

    fn send_hello_ack(&mut self) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HelloAck, 0, b"")
    }

    fn send_goaway(&mut self, reason: &str) -> Result<(), FlowMuxError> {
        warn!(%reason, "FlowMux sending GoAway");
        self.write_frame(Opcode::GoAway, 0, reason.as_bytes())
    }

    fn write_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let mut wire = Vec::new();
        mvm_contract::protocol::network_flow::encode_into(&mut wire, opcode, stream_id, payload)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.stream.write_all(&wire)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read one decrypted FlowMux frame from the peer, returning the opcode,
    /// stream id, and payload length, or `None` on clean close.
    ///
    /// The session layer encrypts each frame; this helper reads the encrypted
    /// envelope, opens it, and decodes the inner FlowMux header. The skeleton
    /// currently sends plaintext FlowMux frames, so this reads the length
    /// prefix that `encode_into` produces and decodes the frame directly.
    fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32)>, FlowMuxError> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 {
            return Ok(None);
        }
        if frame_len > 1 << 20 {
            return Err(FlowMuxError::FrameRefused(format!(
                "FlowMux frame length {frame_len} exceeds 1 MiB"
            )));
        }
        self.read_buf.resize(4 + frame_len, 0);
        self.read_buf[..4].copy_from_slice(&len_buf);
        self.stream.read_exact(&mut self.read_buf[4..])?;

        // TODO: decrypt `self.read_buf` with `self.session.open(...)` once
        // the encrypted wire format for `SealedFrame` is defined.

        let frame = match decode(&self.read_buf) {
            Ok(frame) => frame,
            Err(FrameError::Incomplete { have: 0, .. }) => return Ok(None),
            Err(e) => return Err(FlowMuxError::FrameRefused(e.to_string())),
        };

        Ok(Some((
            frame.header.opcode,
            frame.header.stream_id,
            frame.header.payload_len,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::network_flow::{Opcode, encode_into};
    use mvm_core::net::session::Session;
    use rand::RngCore;

    use super::*;

    fn fresh_keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let key = SigningKey::from_bytes(&seed);
        let verify = key.verifying_key();
        (key, verify)
    }

    #[test]
    fn accept_rejects_wrong_guest_anchor() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, _guest_verify) = fresh_keys();
        let (_wrong_key, wrong_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(host_stream, "test-session", host_key, &wrong_verify).map(|_| ())
        });

        // Drive the guest side of the handshake with the *correct* guest key;
        // the host must still reject because the anchor does not match.
        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let result = host_handle.join().unwrap();
        assert!(
            matches!(result, Err(FlowMuxError::Handshake(_))),
            "expected handshake failure due to anchor mismatch, got {result:?}"
        );
    }

    fn read_flowmux_frame(stream: &mut UnixStream) -> (Opcode, Vec<u8>) {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) => panic!("read len failed: {e:?}"),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&len_buf);
        buf.resize(4 + len, 0);
        stream.read_exact(&mut buf[4..]).unwrap();
        let parsed = mvm_contract::protocol::network_flow::decode(&buf).unwrap();
        (parsed.header.opcode, parsed.payload.to_vec())
    }

    #[test]
    fn accept_succeeds_and_sends_hello_ack() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let host_handle = thread::spawn(move || {
            let mut session =
                FlowMuxSession::accept(host_stream, "test-session", host_key, &guest_verify)
                    .unwrap();
            session.serve()
        });

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        // The guest must send Hello to open the FlowMux session.
        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        // Read the HelloAck from the host.
        let (opcode, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        // Send a flow frame and expect a GoAway, because flow frames are not
        // implemented yet.
        let mut payload = Vec::new();
        encode_into(&mut payload, Opcode::OpenTcp, 1, b"example.com:443").unwrap();
        guest_stream.write_all(&payload).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, goaway_payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::GoAway);
        assert!(!goaway_payload.is_empty());

        // Close the guest side; the host serve loop should end cleanly.
        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }
}
