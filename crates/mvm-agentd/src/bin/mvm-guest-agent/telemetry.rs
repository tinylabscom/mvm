//! Telemetry listener glue: bind the reserved vsock telemetry port and serve
//! one authenticated session per accepted host connection.
//!
//! Vsock-only by design. The shared-kernel container tier has no vsock, and
//! its AF_UNIX boundary is weaker than the peer-CID gate (see `transport.rs`);
//! that tier gets no telemetry listener in this slice, and nothing here
//! claims host-mediated telemetry for it.
//!
//! Boot readiness never gates on this module: the listener is spawned after
//! PID-1 activation, a bind failure is logged and abandoned rather than
//! surfaced, and the control plane is already serving before this thread
//! exists. Keys are loaded lazily per connection because the identity drive's
//! material lands in `/run/mvm` during boot — a host that dials before the
//! keys exist gets a dropped connection and dials again.

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::Ordering;

use mvm_agentd::flowmux_sync::{load_guest_signing_key, load_host_anchor};
use mvm_agentd::telemetry_service::{SessionEnd, serve_telemetry_connection};
use mvm_core::protocol::telemetry::TELEMETRY_PORT;

use crate::globals::SHUTDOWN_REQUESTED;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

/// Where the guest inits leave this boot's identity material.
const KEY_DIR: &str = "/run/mvm";

/// Spawn the telemetry accept thread. Must be called only after PID-1
/// activation: the thread is created here, and activation's credential
/// transition is per-thread at the kernel boundary.
pub(crate) fn spawn_telemetry_listener() {
    if unix_transport_selected() {
        // Container tier: no vsock, no telemetry listener (module docs).
        return;
    }
    std::thread::spawn(|| {
        let fd = match bind_vsock_listener(TELEMETRY_PORT) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!(
                    "mvm-guest-agent: telemetry listener bind failed (port {TELEMETRY_PORT}): {e}"
                );
                return;
            }
        };
        accept_loop(fd);
    });
}

/// Accept host connections and serve them inline, one session at a time.
/// A second dial while a session is live waits in the listen backlog; the
/// host ends the old session by closing it, which returns the loop here.
/// Serving inline bounds this plane to one thread and one connection by
/// construction.
fn accept_loop(listener_fd: RawFd) {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            return;
        }
        let Some(cfd) = accept_vsock(listener_fd, "telemetry") else {
            continue;
        };
        // SAFETY: `cfd` is the just-accepted connection fd, owned here for
        // the session's lifetime and closed on drop.
        let mut stream = unsafe { std::fs::File::from_raw_fd(cfd) };
        if serve_accepted(&mut stream, Path::new(KEY_DIR)) == Some(SessionEnd::Failed) {
            eprintln!("mvm-guest-agent: telemetry session failed");
        }
    }
}

/// Load this boot's identity and serve one telemetry session over an
/// accepted, peer-gated stream. `None` means the keys were unavailable and
/// the connection was dropped before any handshake byte; the listener keeps
/// serving either way. Split from [`accept_loop`] so a test can drive it
/// over a socket pair with keys in a temp directory.
fn serve_accepted<S: Read + Write>(stream: &mut S, key_dir: &Path) -> Option<SessionEnd> {
    let signing_key = match load_guest_signing_key(key_dir) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("mvm-guest-agent: telemetry session refused, no guest signing key: {e}");
            return None;
        }
    };
    let anchor = match load_host_anchor(key_dir) {
        Ok(anchor) => anchor,
        Err(e) => {
            eprintln!("mvm-guest-agent: telemetry session refused, no host anchor: {e}");
            return None;
        }
    };
    Some(serve_telemetry_connection(stream, signing_key, &anchor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use mvm_agentd::flowmux_drive::{GUEST_SIGNING_KEY_FILE, HOST_SIGNER_PUB_FILE};
    use mvm_agentd::telemetry_service::AGENT_COVERAGE_CODE;
    use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
    use mvm_core::protocol::telemetry::{CoverageState, RecordBody, TelemetryRecord};
    use std::os::unix::net::UnixStream;

    fn provision_keys(dir: &Path) -> (SigningKey, SigningKey) {
        let guest_key = SigningKey::from_bytes(&[21; 32]);
        let anchor_key = SigningKey::from_bytes(&[22; 32]);
        std::fs::write(dir.join(GUEST_SIGNING_KEY_FILE), guest_key.to_bytes()).unwrap();
        std::fs::write(
            dir.join(HOST_SIGNER_PUB_FILE),
            anchor_key.verifying_key().to_bytes(),
        )
        .unwrap();
        (guest_key, anchor_key)
    }

    fn host_side(
        mut stream: UnixStream,
        anchor_key: SigningKey,
        expected_guest: ed25519_dalek::VerifyingKey,
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
    fn a_connection_with_provisioned_keys_serves_a_full_session() {
        let dir = tempfile::tempdir().unwrap();
        let (guest_key, anchor_key) = provision_keys(dir.path());
        let (mut guest, host) = UnixStream::pair().unwrap();
        let collector = host_side(host, anchor_key, guest_key.verifying_key());
        let end = serve_accepted(&mut guest, dir.path());
        assert_eq!(end, Some(SessionEnd::PeerClosed));
        let record = collector.join().unwrap().expect("coverage record");
        match *record.body() {
            RecordBody::Coverage { state, ref code } => {
                assert_eq!(state, CoverageState::Started);
                assert_eq!(code.as_str(), AGENT_COVERAGE_CODE);
            }
            ref other => panic!("expected coverage, got {other:?}"),
        }
    }

    #[test]
    fn a_connection_before_keys_exist_is_dropped_without_a_handshake_byte() {
        let dir = tempfile::tempdir().unwrap();
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        assert_eq!(serve_accepted(&mut guest, dir.path()), None);
        drop(guest);
        // The guest side wrote nothing before dropping: the host's first
        // read is clean EOF, not a partial handshake.
        let mut buf = [0u8; 1];
        assert_eq!(host.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_missing_host_anchor_drops_the_connection_before_any_byte() {
        let dir = tempfile::tempdir().unwrap();
        let guest_key = SigningKey::from_bytes(&[23; 32]);
        std::fs::write(
            dir.path().join(GUEST_SIGNING_KEY_FILE),
            guest_key.to_bytes(),
        )
        .unwrap();
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        assert_eq!(serve_accepted(&mut guest, dir.path()), None);
        drop(guest);
        let mut buf = [0u8; 1];
        assert_eq!(host.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_malformed_guest_key_is_a_refusal_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(GUEST_SIGNING_KEY_FILE), b"short").unwrap();
        std::fs::write(dir.path().join(HOST_SIGNER_PUB_FILE), [22u8; 32]).unwrap();
        let (mut guest, _host) = UnixStream::pair().unwrap();
        assert_eq!(serve_accepted(&mut guest, dir.path()), None);
    }
}
