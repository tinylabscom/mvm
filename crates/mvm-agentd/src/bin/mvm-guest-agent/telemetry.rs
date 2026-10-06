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
//!
//! The listener is opt-in, launch-asserted: it binds and spawns only when the
//! kernel cmdline carries `mvm.telemetry=1` — the same host→guest assertion
//! channel the grant requirement rides. A host that provisions no telemetry
//! endpoint asserts nothing, and the guest launches no thread and holds no
//! port for it.

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use mvm_agentd::flowmux_sync::{load_guest_signing_key, load_host_anchor};
use mvm_agentd::telemetry_capture::session::serve_capture_session;
use mvm_agentd::telemetry_capture::{AgentSubscriber, CaptureState, ProducerId};
use mvm_agentd::telemetry_service::SessionEnd;
use mvm_core::net::telemetry::outbox::Outbox;
use mvm_core::protocol::telemetry::{
    CoverageState, MAX_RECORD_BYTES, RecordBody, SourceKind, TELEMETRY_PORT,
};

use crate::globals::SHUTDOWN_REQUESTED;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

/// Where the guest inits leave this boot's identity material.
const KEY_DIR: &str = "/run/mvm";

/// The launch assertion that turns the telemetry listener on. Set by the
/// host when it provisions a telemetry endpoint for this boot; absent means
/// no listener thread and no bound port.
const TELEMETRY_CMDLINE_TOKEN: &str = "mvm.telemetry=1";

/// Whether `cmdline` asserts a telemetry endpoint for this boot.
fn telemetry_asserted(cmdline: &str) -> bool {
    cmdline
        .split_ascii_whitespace()
        .any(|tok| tok == TELEMETRY_CMDLINE_TOKEN)
}

/// The agent's capture queue: slots × the record ceiling. 128 slots (4 MiB,
/// paid at construction) — half the contract's 256-slot ceiling, sized for
/// diagnostics rather than stdio floods.
const CAPTURE_RECORDS: usize = 128;

/// The process capture state, present only on telemetry-asserted boots.
static CAPTURE: OnceLock<Arc<CaptureState>> = OnceLock::new();

/// One agent-diagnostics coverage emission; the record is queued and rides
/// the next session. A shed is already counted by the capture state.
fn emit_coverage(state: &CaptureState, coverage: CoverageState, code: &str) {
    let Ok(code) = code.try_into() else { return };
    let _ = state.emit(
        SourceKind::GuestAgent,
        ProducerId::AgentDiagnostics,
        RecordBody::Coverage {
            state: coverage,
            code,
        },
    );
}

/// Emit the clean-stop coverage mark, if capture is live. Called from the
/// shutdown path: one non-waiting offer, never a join or flush.
pub(crate) fn emit_stopped() {
    if let Some(state) = CAPTURE.get() {
        emit_coverage(state, CoverageState::Stopped, "guest-agent");
    }
}

/// Initialize guest telemetry: install the capture subscriber and spawn the
/// accept thread. Must be called only after PID-1 activation — a thread is
/// created here, and activation's credential transition is per-thread at the
/// kernel boundary. The subscriber installs before the listener spawns, so
/// no session can observe a half-initialized capture path.
pub(crate) fn init_telemetry() {
    // Opt-in: an unreadable cmdline asserts nothing, so nothing installs
    // and nothing spawns — a non-provisioned boot runs byte-identically.
    let asserted = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| telemetry_asserted(&cmdline))
        .unwrap_or(false);
    if !asserted {
        return;
    }
    if unix_transport_selected() {
        // Container tier: no vsock, no telemetry listener (module docs).
        return;
    }
    let Ok(outbox) = Outbox::new(CAPTURE_RECORDS, CAPTURE_RECORDS * MAX_RECORD_BYTES) else {
        eprintln!("mvm-guest-agent: telemetry capture queue construction failed");
        return;
    };
    let Ok(state) = CaptureState::new(Arc::new(outbox)) else {
        eprintln!("mvm-guest-agent: telemetry capture state construction failed");
        return;
    };
    let state = Arc::new(state);
    if CAPTURE.set(Arc::clone(&state)).is_err() {
        return;
    }
    // Diagnostics emitted from here on are captured; the tracing-core-only
    // subscriber keeps the sealed closure unchanged. An install failure
    // (another global subscriber — impossible in this bin) leaves the agent
    // exactly as before: emitting into the void, listener still serving.
    if tracing::subscriber::set_global_default(AgentSubscriber::new(Arc::clone(&state))).is_err() {
        eprintln!("mvm-guest-agent: telemetry subscriber install failed");
    }
    emit_coverage(&state, CoverageState::Started, "guest-agent");
    std::thread::spawn(move || {
        let fd = match bind_vsock_listener(TELEMETRY_PORT) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!(
                    "mvm-guest-agent: telemetry listener bind failed (port {TELEMETRY_PORT}): {e}"
                );
                emit_coverage(&state, CoverageState::Degraded, "listener-bind-failed");
                return;
            }
        };
        accept_loop(fd, &state);
    });
}

/// Accept host connections and serve them inline, one session at a time.
/// A second dial while a session is live waits in the listen backlog; the
/// host ends the old session by closing it, which returns the loop here.
/// Serving inline bounds this plane to one thread and one connection by
/// construction.
fn accept_loop(listener_fd: RawFd, capture: &CaptureState) {
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
        // The liveness probe needs bounded reads, but only after the
        // handshake — installed earlier the timeout races a slow dialer
        // and fails the session spuriously (session module docs). The
        // serve hook runs it at exactly the right moment.
        let bound = |stream: &mut std::fs::File| {
            use std::os::fd::AsRawFd as _;
            set_read_timeout(stream.as_raw_fd());
        };
        if serve_accepted(&mut stream, Path::new(KEY_DIR), capture, bound)
            == Some(SessionEnd::Failed)
        {
            eprintln!("mvm-guest-agent: telemetry session failed");
        }
    }
}

/// Bound reads on the accepted connection so the session's peer probe can
/// distinguish an idle live host from a dead one. Best-effort: a socket that
/// refuses the option still serves, with peer death observed at the next
/// write instead.
fn set_read_timeout(fd: RawFd) {
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 25_000,
    };
    // SAFETY: fd is the just-accepted connection; the timeval is a local,
    // correctly-sized value read once by the kernel.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

/// Load this boot's identity and serve one telemetry session over an
/// accepted, peer-gated stream. `None` means the keys were unavailable and
/// the connection was dropped before any handshake byte; the listener keeps
/// serving either way. Split from [`accept_loop`] so a test can drive it
/// over a socket pair with keys in a temp directory.
fn serve_accepted<S: Read + Write>(
    stream: &mut S,
    key_dir: &Path,
    capture: &CaptureState,
    bound_reads: impl FnOnce(&mut S),
) -> Option<SessionEnd> {
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
    Some(serve_capture_session(
        stream,
        signing_key,
        &anchor,
        capture,
        &SHUTDOWN_REQUESTED,
        bound_reads,
    ))
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

    #[test]
    fn the_listener_is_asserted_only_by_the_exact_cmdline_token() {
        assert!(telemetry_asserted(
            "console=ttyS0 mvm.telemetry=1 root=/dev/vda"
        ));
        assert!(!telemetry_asserted("console=ttyS0 root=/dev/vda"));
        assert!(!telemetry_asserted(""));
        // Lookalikes assert nothing: prefixes, other values, substrings.
        assert!(!telemetry_asserted("mvm.telemetry=0"));
        assert!(!telemetry_asserted("mvm.telemetry=11"));
        assert!(!telemetry_asserted("xmvm.telemetry=1"));
    }

    fn test_capture() -> CaptureState {
        let outbox = Arc::new(Outbox::new(8, 8 * MAX_RECORD_BYTES).unwrap());
        CaptureState::new(outbox).unwrap()
    }

    /// The probe contract: reads become bounded after the handshake, via
    /// the serve hook.
    fn bound(stream: &mut UnixStream) {
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();
    }

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
        let capture = test_capture();
        let end = serve_accepted(&mut guest, dir.path(), &capture, bound);
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
        assert_eq!(
            serve_accepted(&mut guest, dir.path(), &test_capture(), bound),
            None
        );
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
        assert_eq!(
            serve_accepted(&mut guest, dir.path(), &test_capture(), bound),
            None
        );
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
        assert_eq!(
            serve_accepted(&mut guest, dir.path(), &test_capture(), bound),
            None
        );
    }
}
