//! Guest side of the dedicated telemetry service: serve one authenticated
//! session per host connection on the reserved telemetry port.
//!
//! The host dials; the guest listens, gates the peer, and then plays the
//! cryptographic guest role over the accepted stream — the same pinned-key
//! handshake the transport contract defines, no second implementation. This
//! module is deliberately capture-free: the only record it sends is the
//! producer's own coverage announcement, so the host learns the service is
//! live. Wiring real sources into the session is separate capture work, and
//! nothing here claims it.
//!
//! One session per connection, one fresh producer epoch per session: a
//! restore or reconnect dials again and gets a new epoch, so replayed or
//! donor state can never continue an old sequence.

use std::io::{Read, Write};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::net::telemetry::{TelemetryError, TelemetrySender};
use mvm_core::protocol::telemetry::{
    CoverageState, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
};
use rand::TryRng as _;

/// Coverage code the agent announces itself under.
pub const AGENT_COVERAGE_CODE: &str = "guest-agent";

/// Why a telemetry session ended; payload-free by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The host closed the connection; normal teardown.
    PeerClosed,
    /// Authentication or transport failed; the connection is unusable.
    Failed,
}

fn fresh_epoch() -> Result<ProducerEpoch, TelemetryError> {
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| TelemetryError::Transport)?;
    ProducerEpoch::new(bytes).map_err(|_| TelemetryError::Transport)
}

fn coverage_started(epoch: ProducerEpoch) -> Result<TelemetryRecord, TelemetryError> {
    TelemetryRecord::builder()
        .epoch(epoch)
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: AGENT_COVERAGE_CODE
                .try_into()
                .map_err(|_| TelemetryError::Transport)?,
        })
        .build()
        .map_err(|_| TelemetryError::Transport)
}

/// Serve one telemetry session over an accepted, peer-gated stream.
///
/// Authenticates as the guest under `signing_key` against the pinned host
/// anchor, announces coverage started, then blocks until the host closes the
/// connection. Returns how the session ended; every failure is payload-free.
/// The caller owns peer authorization and key acquisition — this function
/// assumes both, so it stays testable over any byte stream.
pub fn serve_telemetry_connection<S: Read + Write>(
    stream: &mut S,
    signing_key: SigningKey,
    host_anchor: &VerifyingKey,
) -> SessionEnd {
    let mut sender = match TelemetrySender::connect(stream, signing_key, host_anchor) {
        Ok(sender) => sender,
        Err(_) => return SessionEnd::Failed,
    };
    let announced = fresh_epoch()
        .and_then(coverage_started)
        .and_then(|record| sender.send(stream, &record));
    if announced.is_err() {
        return SessionEnd::Failed;
    }
    // The session is one-way and the host never writes after its handshake
    // ack, so a read can only return EOF (host teardown) or an error. Either
    // way the session is over; drain nothing and never write again.
    let mut sink = [0u8; 64];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => return SessionEnd::PeerClosed,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return SessionEnd::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
    use mvm_core::protocol::telemetry::RecordBody;
    use std::os::unix::net::UnixStream;

    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[11; 32]),
            SigningKey::from_bytes(&[12; 32]),
        )
    }

    fn host_side(
        mut stream: UnixStream,
        anchor_key: SigningKey,
        expected_guest: VerifyingKey,
    ) -> std::thread::JoinHandle<Option<TelemetryRecord>> {
        std::thread::spawn(move || {
            let anchor = anchor_key.verifying_key();
            let mut receiver =
                TelemetryReceiver::connect_with_signer(&mut stream, &anchor, &expected_guest, {
                    let signer = anchor_key.clone();
                    move |hello, ack| {
                        let bytes = handshake_signing_bytes(hello, ack, &signer.verifying_key())
                            .map_err(|_| {
                                mvm_core::net::session::SessionError::InvalidHandshake(
                                    "bad handshake".into(),
                                )
                            })?;
                        Ok(signer.sign(&bytes))
                    }
                })
                .ok()?;
            let record = receiver.receive(&mut stream).ok();
            drop(stream);
            record
        })
    }

    #[test]
    fn a_session_authenticates_announces_coverage_and_ends_on_host_close() {
        let (guest_key, anchor_key) = keys();
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_side(host, anchor_key.clone(), guest_key.verifying_key());
        let end = serve_telemetry_connection(&mut guest, guest_key, &anchor_key.verifying_key());
        assert_eq!(end, SessionEnd::PeerClosed);
        let record = collector.join().unwrap().expect("coverage record");
        match *record.body() {
            RecordBody::Coverage { state, ref code } => {
                assert_eq!(state, CoverageState::Started);
                assert_eq!(code.as_str(), AGENT_COVERAGE_CODE);
            }
            ref other => panic!("expected coverage, got {other:?}"),
        }
        assert_eq!(record.source(), SourceKind::GuestAgent);
    }

    #[test]
    fn two_sessions_never_share_a_producer_epoch() {
        let (guest_key, anchor_key) = keys();
        let mut epochs = Vec::new();
        for _ in 0..2 {
            let (mut guest, host) = UnixStream::pair().unwrap();
            let collector = host_side(host, anchor_key.clone(), guest_key.verifying_key());
            serve_telemetry_connection(&mut guest, guest_key.clone(), &anchor_key.verifying_key());
            epochs.push(collector.join().unwrap().expect("record").epoch());
        }
        assert_ne!(epochs[0], epochs[1], "restore/reconnect mints a new epoch");
    }

    #[test]
    fn a_host_expecting_a_different_guest_key_fails_the_session() {
        let (guest_key, anchor_key) = keys();
        let stranger = SigningKey::from_bytes(&[13; 32]);
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_side(host, anchor_key.clone(), stranger.verifying_key());
        let end = serve_telemetry_connection(&mut guest, guest_key, &anchor_key.verifying_key());
        assert_eq!(end, SessionEnd::Failed);
        assert!(collector.join().unwrap().is_none());
    }

    #[test]
    fn a_wrong_host_anchor_fails_before_any_record_is_sent() {
        let (guest_key, anchor_key) = keys();
        let wrong_anchor = SigningKey::from_bytes(&[14; 32]).verifying_key();
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_side(host, anchor_key, guest_key.verifying_key());
        let end = serve_telemetry_connection(&mut guest, guest_key, &wrong_anchor);
        assert_eq!(end, SessionEnd::Failed);
        // The guest wrote nothing after refusing the anchor, so the host is
        // still blocked in its handshake read; close the guest's socket
        // before joining or the join deadlocks.
        drop(guest);
        assert!(collector.join().unwrap().is_none());
    }

    #[test]
    fn a_dead_peer_is_a_failed_session_not_a_hang() {
        let (guest_key, anchor_key) = keys();
        let (mut guest, host) = UnixStream::pair().unwrap();
        drop(host);
        let end = serve_telemetry_connection(&mut guest, guest_key, &anchor_key.verifying_key());
        assert_eq!(end, SessionEnd::Failed);
    }
}
