//! Backend-agnostic workload exit-code capture (Plan 152 WS-A).
//!
//! The guest `/init` writes a 4-byte little-endian `i32` to the control
//! vsock port before `poweroff -f`. The supervisor binds a host
//! `UnixListener` at the control socket (libkrun `add_vsock_port2(
//! listen=false)`), accepts one connection, reads the code, and persists
//! it to `<vm_state_dir>/workload.exit`. The backend reads that file
//! after the VM stops. WS-B's Vz supervisor reuses this module.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// File name under `vm_state_dir` holding the captured exit code (decimal).
pub const WORKLOAD_EXIT_FILE: &str = "workload.exit";

pub fn exit_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_EXIT_FILE)
}

/// Block on `listener` for one guest connection, read the 4-byte LE i32,
/// and persist it to `<vm_state_dir>/workload.exit`. Returns the code.
/// Best-effort: any error leaves no file (read as "unknown" downstream).
pub fn capture_once(listener: &UnixListener, vm_state_dir: &Path) -> std::io::Result<i32> {
    let (mut stream, _addr) = listener.accept()?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    let code = i32::from_le_bytes(buf);
    std::fs::write(exit_file_path(vm_state_dir), code.to_string())?;
    Ok(code)
}

/// Read a previously-captured exit code, if present.
pub fn read_captured(vm_state_dir: &Path) -> Option<i32> {
    std::fs::read_to_string(exit_file_path(vm_state_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
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
            }
        });

        let code = capture_once(&listener, dir.path()).unwrap();
        handle.join().unwrap();
        assert_eq!(code, -7);
        assert_eq!(read_captured(dir.path()), Some(-7));
    }

    #[test]
    fn read_captured_is_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_captured(dir.path()), None);
    }
}
