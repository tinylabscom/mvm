//! Workload exit-code file convention + capture.
//!
//! A finished one-shot workload's exit code (written by the guest `/init`
//! over the control vsock port) is persisted to `<vm_state_dir>/workload.exit`.
//! This module is the shared home for the file name + path + reader **and** the
//! `capture_once` writer, so every host-side capture site — the libkrun
//! supervisor subprocess and the in-process Firecracker driver alike — reads a
//! guest exit report the same way, and the backends that only read the file
//! (`mvm-runtime`) depend on nothing above them in the graph.

use std::path::{Path, PathBuf};

/// File name under `vm_state_dir` holding the captured exit code (decimal).
pub const WORKLOAD_EXIT_FILE: &str = "workload.exit";

pub fn exit_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_EXIT_FILE)
}

/// Read a previously-captured exit code, if present.
pub fn read_captured(vm_state_dir: &Path) -> Option<i32> {
    std::fs::read_to_string(exit_file_path(vm_state_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Block on `listener` for one guest connection, read the 4-byte LE i32, and
/// persist it to `<vm_state_dir>/workload.exit`. Returns the code.
///
/// The caller passes a bound `UnixListener` for the control vsock port; this
/// function binds nothing itself. Best-effort by design: it runs on a
/// background thread, and an `Err` simply leaves no file, which readers treat
/// downstream as `UNKNOWN`.
#[cfg(unix)]
pub fn capture_once(
    listener: &std::os::unix::net::UnixListener,
    vm_state_dir: &Path,
) -> std::io::Result<i32> {
    let (stream, _addr) = listener.accept()?;
    capture_stream(stream, vm_state_dir)
}

/// Read one guest exit report (4-byte LE i32) from an already-connected
/// stream, persist it to `<vm_state_dir>/workload.exit`, and ack. Returns
/// the code. The stream half of [`capture_once`], split out so a capture
/// site whose control channel is not a `UnixListener` (e.g. an accepted
/// AF_VSOCK connection) persists and acks with the identical protocol and
/// file-then-ack ordering.
pub fn capture_stream(
    mut stream: impl std::io::Read + std::io::Write,
    vm_state_dir: &Path,
) -> std::io::Result<i32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    let code = i32::from_le_bytes(buf);
    std::fs::write(exit_file_path(vm_state_dir), code.to_string())?;
    // Ack AFTER the file is durably written: the guest waits for this before
    // powering off, so a supervisor's start_enter->exit() can't race the file
    // write. Best-effort — a failed ack just means the guest times out and
    // powers off (file already written).
    let _ = stream.write_all(&[1u8]);
    let _ = stream.flush();
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_captured_roundtrips_decimal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(exit_file_path(dir.path()), "-7").unwrap();
        assert_eq!(read_captured(dir.path()), Some(-7));
    }

    #[test]
    fn read_captured_is_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_captured(dir.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn capture_persists_le_i32_and_reads_back() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;

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

    #[cfg(unix)]
    #[test]
    fn capture_stream_persists_le_i32_from_any_connected_stream() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let (mut guest, host) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            guest.write_all(&42i32.to_le_bytes()).unwrap();
        });

        let code = capture_stream(host, dir.path()).unwrap();
        handle.join().unwrap();
        assert_eq!(code, 42);
        assert_eq!(read_captured(dir.path()), Some(42));
    }
}
