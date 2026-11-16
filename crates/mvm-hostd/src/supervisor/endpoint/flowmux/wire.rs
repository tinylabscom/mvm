//! Shared synchronization and frame-writing helpers for a FlowMux session.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mio::Interest;
use mvm_contract::protocol::network_flow::{Opcode, SessionValidator};
use mvm_core::net::session::Session;

use super::FlowMuxError;
use super::registry::StreamRegistry;
use super::transport::Readiness;

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

/// Validate the configured budget without overflowing the monotonic clock.
pub(super) fn write_deadline(budget: Duration) -> io::Result<Instant> {
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FlowMux write budget must be positive",
        ));
    }
    Instant::now().checked_add(budget).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "FlowMux write budget overflows the monotonic clock",
        )
    })
}

/// Serialize and send one encrypted frame through a shared writer.
///
/// Serializes sealing and bytes under the writer lock. The session lock is
/// released before I/O so an unread response cannot block inbound cancellation.
/// The socket's configured timeout supplies the budget; nonblocking I/O and
/// readiness enforce one deadline for the complete frame, not SO_SNDTIMEO.
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
/// that ends it. Checking the mark while holding the writer lock, which every
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

    let mut writer = lock_writer(writer);
    let result = (|| {
        if retired.is_some_and(|retired| retired.load(Ordering::Acquire)) {
            return Ok(false);
        }
        let budget = writer.write_timeout()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "FlowMux writer has no deadline",
            )
        })?;
        let deadline = write_deadline(budget)?;
        let mut readiness = Readiness::new(&writer, Interest::WRITABLE)?;
        let sealed = {
            let mut session = lock_session(session);
            session
                .seal(&frame)
                .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?
        };
        let mut sealed_bytes = Vec::new();
        sealed
            .encode(&mut sealed_bytes)
            .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
        let len = u32::try_from(sealed_bytes.len())
            .map_err(|_| FlowMuxError::FrameRefused("sealed frame too large".into()))?;
        write_before(&mut writer, &mut readiness, &len.to_be_bytes(), deadline)?;
        write_before(&mut writer, &mut readiness, &sealed_bytes, deadline)?;
        writer.flush()?;
        Ok(true)
    })();
    if result.is_err()
        && let Err(error) = writer.shutdown(std::net::Shutdown::Both)
    {
        tracing::debug!(%error, "failed FlowMux writer was already closed");
    }
    result
}

fn write_before(
    writer: &mut UnixStream,
    readiness: &mut Readiness,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "FlowMux frame write deadline expired",
            ));
        }
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "FlowMux frame write stopped",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                readiness.wait_until(Some(deadline))?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "FlowMux frame write deadline expired",
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    fn bounded_writer() -> (Mutex<UnixStream>, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let capacity: libc::c_int = 4096;
        // SAFETY: setsockopt reads a correctly sized live integer and socket descriptor.
        let configured = unsafe {
            libc::setsockopt(
                ours.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&capacity).cast(),
                std::mem::size_of_val(&capacity).try_into().unwrap(),
            )
        };
        assert_eq!(configured, 0);
        ours.set_nonblocking(true).unwrap();
        ours.set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        (Mutex::new(ours), theirs)
    }

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
        ours.set_nonblocking(true).unwrap();
        ours.set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let writer = Mutex::new(ours);
        let retired = AtomicBool::new(false);

        let sent =
            write_stream_frame_to(&session, &writer, &retired, Opcode::HalfClose, 1, &[]).unwrap();

        assert!(sent);
        let mut len = [0u8; 4];
        theirs.read_exact(&mut len).unwrap();
        assert!(u32::from_be_bytes(len) > 0);
    }

    #[test]
    fn a_partial_frame_timeout_closes_the_transport_before_another_frame() {
        let (session, _guest) = session_pair();
        let (writer, mut peer) = bounded_writer();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let payload = vec![0; mvm_contract::protocol::network_flow::MAX_PAYLOAD_LEN];
        assert!(write_frame_to(&session, &writer, Opcode::Data, 1, &payload).is_err());
        assert!(write_frame_to(&session, &writer, Opcode::HalfClose, 1, &[]).is_err());
        let mut received = Vec::new();
        peer.read_to_end(&mut received)
            .expect("failed frame closes the peer-facing transport");
        assert!(
            received.len() > 4,
            "the witness must include a partial encrypted frame"
        );
        let expected = u32::from_be_bytes(received[..4].try_into().unwrap()) as usize + 4;
        assert!(
            received.len() < expected,
            "the witness must stall before the complete frame"
        );
    }

    #[test]
    fn a_slow_drip_peer_cannot_extend_the_whole_frame_deadline() {
        let (session, _guest) = session_pair();
        let (writer, mut peer) = bounded_writer();
        let writer = Arc::new(writer);
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (stop, pacing) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            // Timer-paced bandwidth, not polling for completion: each tick permits
            // only one small read; stop is an explicit channel notification.
            while matches!(
                pacing.recv_timeout(Duration::from_millis(10)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                match peer.read(&mut [0; 256]) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let (finished, done) = mpsc::sync_channel(1);
        let worker_writer = Arc::clone(&writer);
        let worker = std::thread::spawn(move || {
            let payload = vec![0; mvm_contract::protocol::network_flow::MAX_PAYLOAD_LEN];
            let result = write_frame_to(&session, &worker_writer, Opcode::Data, 1, &payload);
            let _ = finished.send(result);
        });
        let result = done.recv_timeout(Duration::from_secs(1));
        let _ = stop.send(());
        reader.join().unwrap();
        worker.join().unwrap();
        assert!(
            result
                .expect("partial progress must not restart a full timeout")
                .is_err()
        );
    }

    #[test]
    fn a_missing_write_budget_refuses_and_closes_the_transport() {
        let (session, _guest) = session_pair();
        let (ours, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert!(write_frame_to(&session, &Mutex::new(ours), Opcode::Data, 1, b"x").is_err());
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
}
