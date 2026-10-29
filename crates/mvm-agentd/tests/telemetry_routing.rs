//! Telemetry leaves the guest only as sealed frames on its own authenticated
//! session. These witnesses run the guest's real capture session against a
//! host that records every byte the guest put on the wire:
//!
//! - an authenticated host decodes the record, and the raw wire bytes never
//!   contained its plaintext;
//! - a host holding the wrong anchor key, and a peer that never speaks the
//!   protocol at all, receive no record plaintext either — there is no
//!   unauthenticated or raw fallback that hands records to whoever connects.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use mvm_agentd::telemetry_capture::session::{SessionDeadlines, serve_capture_session};
use mvm_agentd::telemetry_capture::{CaptureState, ProducerId};
use mvm_agentd::telemetry_service::SessionEnd;
use mvm_core::net::telemetry::outbox::Outbox;
use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
use mvm_core::protocol::telemetry::{Attributes, Level, MAX_RECORD_BYTES, RecordBody, SourceKind};

/// A value no handshake or framing byte sequence could contain by accident.
const MARKER: &str = "routing-witness-plaintext-7f3c91";

/// Host-side stream that keeps a copy of every byte it reads.
struct Tee {
    inner: UnixStream,
    seen: Vec<u8>,
}

impl Read for Tee {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn capture_with_marker() -> CaptureState {
    let outbox = Arc::new(Outbox::new(8, 8 * MAX_RECORD_BYTES).unwrap());
    let capture = CaptureState::new(outbox).unwrap();
    let _ = capture.emit(
        SourceKind::GuestAgent,
        ProducerId::AgentDiagnostics,
        RecordBody::Log {
            context: None,
            level: Level::Info,
            message: MARKER.try_into().unwrap(),
            attributes: Attributes::default(),
        },
    );
    capture
}

/// Short idle probes so a session notices its peer leave promptly; the
/// handshake and frame writes keep the agent's own limits.
const BOUNDS: SessionDeadlines = SessionDeadlines {
    probe: Duration::from_millis(10),
    ..SessionDeadlines::AGENT
};

fn serve_guest(
    mut guest: UnixStream,
    guest_key: SigningKey,
    anchor: VerifyingKey,
    capture: CaptureState,
) -> std::thread::JoinHandle<SessionEnd> {
    std::thread::spawn(move || {
        let stop = AtomicBool::new(false);
        serve_capture_session(&mut guest, guest_key, &anchor, &capture, &stop, BOUNDS)
    })
}

fn authenticate(
    stream: &mut Tee,
    signer: SigningKey,
    expected_guest: &VerifyingKey,
) -> Option<TelemetryReceiver> {
    let anchor = signer.verifying_key();
    TelemetryReceiver::connect_authenticated(stream, &anchor, expected_guest, move |hello, ack| {
        let bytes = handshake_signing_bytes(hello, ack, &signer.verifying_key()).map_err(|_| {
            mvm_core::net::session::SessionError::InvalidHandshake("bad handshake".into())
        })?;
        Ok(signer.sign(&bytes))
    })
    .ok()
}

#[test]
fn an_authenticated_host_decodes_the_record_the_wire_never_carried_in_plaintext() {
    let guest_key = SigningKey::from_bytes(&[71; 32]);
    let anchor_key = SigningKey::from_bytes(&[72; 32]);
    let (guest, host) = UnixStream::pair().unwrap();
    let serving = serve_guest(
        guest,
        guest_key.clone(),
        anchor_key.verifying_key(),
        capture_with_marker(),
    );
    let mut tee = Tee {
        inner: host,
        seen: Vec::new(),
    };
    let mut receiver =
        authenticate(&mut tee, anchor_key, &guest_key.verifying_key()).expect("host authenticates");
    let mut decoded = false;
    // Announcement first, then the queued log record.
    for _ in 0..2 {
        let record = receiver.receive(&mut tee).expect("record");
        if let RecordBody::Log { message, .. } = record.body() {
            decoded = message.as_str() == MARKER;
        }
    }
    let seen = std::mem::take(&mut tee.seen);
    drop(tee);
    assert_eq!(serving.join().unwrap(), SessionEnd::PeerClosed);
    assert!(decoded, "the authenticated host decoded the marker record");
    assert!(!seen.is_empty());
    assert!(
        !contains(&seen, MARKER.as_bytes()),
        "record plaintext crossed the wire"
    );
}

#[test]
fn a_host_with_the_wrong_anchor_receives_no_record_plaintext() {
    let guest_key = SigningKey::from_bytes(&[73; 32]);
    let anchor_key = SigningKey::from_bytes(&[74; 32]);
    let imposter = SigningKey::from_bytes(&[75; 32]);
    let (guest, host) = UnixStream::pair().unwrap();
    let serving = serve_guest(
        guest,
        guest_key.clone(),
        anchor_key.verifying_key(),
        capture_with_marker(),
    );
    let mut tee = Tee {
        inner: host,
        seen: Vec::new(),
    };
    // Set before the handshake: once the guest refuses and closes, macOS
    // rejects a timeout change on the dead socket. The guest closing ends the
    // drain below; the timeout only guards against a guest that never does.
    tee.inner
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert!(authenticate(&mut tee, imposter, &guest_key.verifying_key()).is_none());
    // Whatever the guest still sends before closing is recorded too.
    let mut rest = [0u8; 4096];
    while let Ok(n) = tee.read(&mut rest) {
        if n == 0 {
            break;
        }
    }
    assert_eq!(serving.join().unwrap(), SessionEnd::Failed);
    assert!(!contains(&tee.seen, MARKER.as_bytes()));
}

#[test]
fn a_peer_that_never_speaks_the_protocol_receives_no_record_plaintext() {
    let guest_key = SigningKey::from_bytes(&[76; 32]);
    let anchor_key = SigningKey::from_bytes(&[77; 32]);
    let (guest, mut raw) = UnixStream::pair().unwrap();
    let serving = serve_guest(
        guest,
        guest_key,
        anchor_key.verifying_key(),
        capture_with_marker(),
    );
    raw.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = raw.read(&mut buf) {
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
    }
    // A raw reader that hangs up gets nothing more; the guest ends the session.
    drop(raw);
    assert_eq!(serving.join().unwrap(), SessionEnd::Failed);
    assert!(!contains(&seen, MARKER.as_bytes()));
}
