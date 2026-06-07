//! `mvm-exit-report <code>` — in-guest one-shot helper. Connects to the
//! host over AF_VSOCK (CID=host, WORKLOAD_EXIT_PORT) and writes the exit
//! code as a 4-byte little-endian i32, then exits. Called by mkGuest's
//! `/init` after a one-shot workload finishes, before `poweroff -f`.
//! Plan 152 WS-A. Linux-only (AF_VSOCK); a no-op stub off Linux so the
//! workspace builds on macOS dev hosts.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code: i32 = match std::env::args().nth(1).and_then(|s| s.parse().ok()) {
        Some(c) => c,
        None => {
            eprintln!("usage: mvm-exit-report <exit-code>");
            return ExitCode::from(2);
        }
    };
    match report(code) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvm-exit-report: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn report(code: i32) -> std::io::Result<()> {
    use std::io::Write;
    use std::net::TcpStream;
    use std::os::fd::FromRawFd;

    // Must match mvm_guest::vsock::WORKLOAD_EXIT_PORT (Plan 152 WS-A).
    // mvm-guest is not a dep of this crate — keep in sync manually.
    const WORKLOAD_EXIT_PORT: u32 = 5251;
    const VMADDR_CID_HOST: u32 = 2;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: WORKLOAD_EXIT_PORT,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: fd is a valid connected AF_VSOCK stream we own.
    let mut stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream.write_all(&code.to_le_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn report(_code: i32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "mvm-exit-report is Linux-only (AF_VSOCK)",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn exit_code_wire_is_4_byte_le() {
        let code: i32 = -7;
        let bytes = code.to_le_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(i32::from_le_bytes(bytes), -7);
    }
}
