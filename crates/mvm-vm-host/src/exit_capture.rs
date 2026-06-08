//! Supervisor-side workload exit-code capture (Plan 152 WS-A).
//!
//! Binds nothing itself — the caller passes a bound `UnixListener` for
//! the control vsock port. Reads the guest's 4-byte LE i32 and persists
//! it via `mvm_core::exit_capture::exit_file_path`. The file convention +
//! reader live in `mvm-core` so `mvm-backend` can read without depending
//! on this (supervisor) crate.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::Path;

pub use mvm_core::exit_capture::{WORKLOAD_EXIT_FILE, exit_file_path, read_captured};

/// Block on `listener` for one guest connection, read the 4-byte LE i32,
/// and persist it to `<vm_state_dir>/workload.exit`. Returns the code.
/// Best-effort: called on a background thread; an `Err` simply leaves no
/// file, which the backend reads downstream as `UNKNOWN`.
pub fn capture_once(listener: &UnixListener, vm_state_dir: &Path) -> std::io::Result<i32> {
    let (mut stream, _addr) = listener.accept()?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    let code = i32::from_le_bytes(buf);
    std::fs::write(exit_file_path(vm_state_dir), code.to_string())?;
    // Ack AFTER the file is durably written: the guest waits for this
    // before powering off, so the supervisor's start_enter->exit() can't
    // race the file write. Best-effort — a failed ack just means the
    // guest times out and powers off (file already written). Plan 152 WS-A.
    use std::io::Write as _;
    let _ = stream.write_all(&[1u8]);
    let _ = stream.flush();
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn capture_persists_le_i32_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock-5251.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || {
                let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
                c.write_all(&(-7i32).to_le_bytes()).unwrap();
                let mut ack = [0u8; 1];
                use std::io::Read as _;
                let _ = c.read_exact(&mut ack);
            }
        });

        let code = capture_once(&listener, dir.path()).unwrap();
        handle.join().unwrap();
        assert_eq!(code, -7);
        assert_eq!(read_captured(dir.path()), Some(-7));
    }
}
