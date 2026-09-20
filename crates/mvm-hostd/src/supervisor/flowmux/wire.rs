//! Shared synchronization and frame-writing helpers for a FlowMux session.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use mvm_contract::protocol::network_flow::{Opcode, SessionValidator};
use mvm_core::net::session::Session;

use super::FlowMuxError;
use super::registry::StreamRegistry;

/// Returns true for the common "peer closed the connection" I/O errors that
/// can race with an in-flight read when the guest drops its socket.
pub(super) fn is_peer_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Lock the shared writer, recovering from poison so a crashed relay thread
/// does not silence the whole session.
pub(super) fn lock_writer(writer: &Mutex<UnixStream>) -> MutexGuard<'_, UnixStream> {
    writer.lock().unwrap_or_else(|error| error.into_inner())
}

/// Lock the shared session, recovering from poison.
pub(super) fn lock_session(session: &Mutex<Session>) -> MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(|error| error.into_inner())
}

/// Lock the shared validator, recovering from poison.
pub(super) fn lock_validator(
    validator: &Mutex<SessionValidator>,
) -> MutexGuard<'_, SessionValidator> {
    validator.lock().unwrap_or_else(|error| error.into_inner())
}

/// Lock the shared registry, recovering from poison.
pub(super) fn lock_registry(registry: &Mutex<StreamRegistry>) -> MutexGuard<'_, StreamRegistry> {
    registry.lock().unwrap_or_else(|error| error.into_inner())
}

/// Serialize and send one encrypted frame through a shared writer.
///
/// Locks the session first, then the writer, so sequence numbers are assigned
/// in the same order the bytes are emitted. The paired locks are released
/// once the frame is flushed.
pub(super) fn write_frame_to(
    session: &Mutex<Session>,
    writer: &Mutex<UnixStream>,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), FlowMuxError> {
    write_frame_unless(session, writer, None, opcode, stream_id, payload).map(|_| ())
}

/// Send a relay thread's frame for a stream the session thread may retire at
/// any moment, unless it already has. Returns whether the frame was sent.
///
/// The session thread marks a stream retired before it writes the `Reset`
/// that ends it. Checking the mark while holding the session lock, which every
/// frame write takes, orders the two: either this frame goes out ahead of the
/// `Reset`, or it is not sent at all. A check made before taking the lock left
/// a window in which a relay's `HalfClose` or `Data` followed the `Reset` onto
/// the wire, and the guest, rightly, ended the session over a frame naming a
/// stream it had already closed — every other flow on it with it.
pub(super) fn write_stream_frame_to(
    session: &Mutex<Session>,
    writer: &Mutex<UnixStream>,
    retired: &AtomicBool,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<bool, FlowMuxError> {
    write_frame_unless(session, writer, Some(retired), opcode, stream_id, payload)
}

fn write_frame_unless(
    session: &Mutex<Session>,
    writer: &Mutex<UnixStream>,
    retired: Option<&AtomicBool>,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<bool, FlowMuxError> {
    let mut frame = Vec::new();
    mvm_contract::protocol::network_flow::encode_into(&mut frame, opcode, stream_id, payload)
        .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;

    let mut session = lock_session(session);
    if retired.is_some_and(|retired| retired.load(Ordering::Acquire)) {
        return Ok(false);
    }
    let sealed = session
        .seal(&frame)
        .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
    let mut sealed_bytes = Vec::new();
    sealed
        .encode(&mut sealed_bytes)
        .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
    let len = u32::try_from(sealed_bytes.len())
        .map_err(|_| FlowMuxError::FrameRefused("sealed frame too large".into()))?;

    let mut writer = lock_writer(writer);
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&sealed_bytes)?;
    writer.flush()?;
    Ok(true)
}

/// Split `host:port`, rejecting an empty host or an unparseable port.
pub(super) fn parse_host_port(target: &str) -> Result<(&str, u16), String> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| "target must be host:port".to_string())?;
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("port must be a 16-bit integer: {port_str}"))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn session_pair() -> (Mutex<Session>, Session) {
        let (host_stream, guest_stream) = UnixStream::pair().unwrap();
        let (host_key, host_anchor) = super::super::tests::fresh_keys();
        let (guest_key, _) = super::super::tests::fresh_keys();
        let host = std::thread::spawn(move || {
            let mut host_stream = host_stream;
            Session::host(&mut host_stream, "wire-test", host_key)
                .unwrap()
                .0
        });
        let mut guest_stream = guest_stream;
        let guest = Session::guest(&mut guest_stream, guest_key, &host_anchor)
            .unwrap()
            .0;
        (Mutex::new(host.join().unwrap()), guest)
    }

    #[test]
    fn a_retired_stream_gets_no_further_relay_frames() {
        let (session, _guest) = session_pair();
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let writer = Mutex::new(ours);
        let retired = AtomicBool::new(true);

        let sent =
            write_stream_frame_to(&session, &writer, &retired, Opcode::HalfClose, 1, &[]).unwrap();

        assert!(!sent);
        theirs.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        assert!(
            theirs.read(&mut buf).is_err(),
            "nothing may reach the wire for a retired stream"
        );
    }

    #[test]
    fn a_live_stream_gets_its_relay_frame() {
        let (session, _guest) = session_pair();
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let writer = Mutex::new(ours);
        let retired = AtomicBool::new(false);

        let sent =
            write_stream_frame_to(&session, &writer, &retired, Opcode::HalfClose, 1, &[]).unwrap();

        assert!(sent);
        let mut len = [0u8; 4];
        theirs.read_exact(&mut len).unwrap();
        assert!(u32::from_be_bytes(len) > 0);
    }
}
