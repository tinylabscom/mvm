//! Shared synchronization and frame-writing helpers for a FlowMux session.

use std::io::Write;
use std::os::unix::net::UnixStream;
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
    let mut frame = Vec::new();
    mvm_contract::protocol::network_flow::encode_into(&mut frame, opcode, stream_id, payload)
        .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;

    let mut session = lock_session(session);
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
    Ok(())
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
