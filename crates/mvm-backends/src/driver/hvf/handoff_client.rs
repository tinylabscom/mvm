//! The claimant's side of a live standby handoff: ask the paused parent to
//! become the child, read its one-line reply, and link the child's state files
//! to the parent's.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use mvm_core::vm_backend::StandbyError;
use mvm_vmm::hvf_handoff::{HANDOFF_RESPONSE_MAX_BYTES, HandoffReply, HvfHandoffRequest};

use super::PID_FILE_NAME;

/// How many times one claim asks a parent that answers `RETRY`. The parent
/// says that only when no request reached it, so it is untouched and asking
/// again is cheap; a parent that keeps saying it will not be won by asking more.
pub(super) const LIVE_HANDOFF_ATTEMPTS: usize = 2;

/// Ask the paused parent listening at `socket` to become the child `request`
/// names. A refusal is final; a `RETRY` is asked again, up to
/// [`LIVE_HANDOFF_ATTEMPTS`] in all.
pub(super) fn request_live_handoff(
    socket: &Path,
    request: &HvfHandoffRequest,
) -> Result<(), StandbyError> {
    // Serialized before connecting, so nothing stands between `connect` and
    // the write the parent is waiting on.
    let mut payload = serde_json::to_vec(request)
        .map_err(|e| StandbyError::ClaimFailed(format!("serialize HVF handoff request: {e}")))?;
    payload.push(b'\n');
    let mut unread = String::new();
    for _ in 0..LIVE_HANDOFF_ATTEMPTS {
        match send_live_handoff(socket, &payload)? {
            HandoffReply::Accepted => return Ok(()),
            HandoffReply::Retry(reason) => unread = reason,
            HandoffReply::Refused(reply) => {
                return Err(StandbyError::ClaimFailed(format!(
                    "HVF parent rejected live handoff: {reply}"
                )));
            }
        }
    }
    Err(StandbyError::ClaimFailed(format!(
        "HVF parent did not receive the live handoff request in \
         {LIVE_HANDOFF_ATTEMPTS} attempts: {unread}"
    )))
}

/// One connection to the parent's handoff socket: send the request, read the
/// reply.
fn send_live_handoff(socket: &Path, payload: &[u8]) -> Result<HandoffReply, StandbyError> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
        StandbyError::ClaimFailed(format!(
            "connect to HVF parent handoff socket {}: {e}",
            socket.display()
        ))
    })?;
    stream
        .write_all(payload)
        .map_err(|e| StandbyError::ClaimFailed(format!("send HVF handoff request: {e}")))?;
    let response = read_handoff_response(&mut stream)
        .map_err(|e| StandbyError::ClaimFailed(format!("read HVF handoff response: {e}")))?;
    Ok(HandoffReply::parse(&response))
}

/// How much longer than the parent's own capture handoff bound the claimant
/// waits for a reply.
pub(super) const HANDOFF_RESPONSE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// When the claimant stops waiting for the parent's handoff reply.
///
/// The parent may spend up to [`mvm_vmm::hvf_handoff::CAPTURE_HANDOFF_TIMEOUT`]
/// preparing protected capture before it answers, and then answers with its
/// reason. Giving up at or before that bound would replace the parent's
/// account of a refusal with a bare local timeout.
pub(super) fn handoff_response_deadline(now: Instant) -> Instant {
    now + mvm_vmm::hvf_handoff::CAPTURE_HANDOFF_TIMEOUT + HANDOFF_RESPONSE_GRACE
}

/// Read the parent's one-line handoff reply: `OK`, `RETRY <reason>`, or
/// `ERR <reason>`.
///
/// Reads through the newline rather than a fixed length. A fixed three bytes
/// fit `OK\n` and truncated every refusal to `ERR`, which left a failed claim
/// with no account of what the parent had refused.
pub(super) fn read_handoff_response(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<Vec<u8>> {
    stream.set_nonblocking(true)?;
    let deadline = handoff_response_deadline(Instant::now());
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < HANDOFF_RESPONSE_MAX_BYTES && response.last() != Some(&b'\n') {
        match stream.read(&mut byte) {
            Ok(0) if response.is_empty() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HVF handoff peer closed before its response was complete",
                ));
            }
            // A reply cut off by the peer closing is still the parent's account
            // of the refusal; the caller only admits an exact `OK`.
            Ok(0) => break,
            Ok(_) => response.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HVF handoff response timed out",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(response)
}

/// Point a restored child's state files at the parent supervisor's, which is
/// the process actually running the child's guest.
///
/// The captured usage record is deliberately not in this list. It is written
/// once, at the owning process's teardown, describing the whole life of that
/// process — so a symlink would hand the child the parent's CPU and resident
/// numbers and let its exit report sign them as its own measurement. A child
/// with no usage sidecar reads as unobserved, which is the honest answer:
/// attributing a warm-forked child's consumption is an open question this
/// version does not answer.
pub(super) fn link_child_state(child_dir: &Path, parent_dir: &Path) -> std::io::Result<()> {
    for name in [PID_FILE_NAME, "console.log", "workload.exit", "pause.state"] {
        let child_path = child_dir.join(name);
        let parent_path = parent_dir.join(name);
        if let Ok(metadata) = std::fs::symlink_metadata(&child_path) {
            if metadata.file_type().is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("child state path {} is a directory", child_path.display()),
                ));
            }
            std::fs::remove_file(&child_path)?;
        }
        std::os::unix::fs::symlink(&parent_path, &child_path)?;
    }
    Ok(())
}
