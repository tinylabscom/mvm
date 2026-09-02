//! `mvm-exit-report <code>` — in-guest one-shot helper. Connects to the
//! host over AF_VSOCK (CID=host, WORKLOAD_EXIT_PORT) and writes the exit
//! code as a 4-byte little-endian i32, then exits. Called by mkGuest's
//! `/init` after a one-shot workload finishes, before `poweroff -f`.
//! Linux-only (AF_VSOCK); a no-op stub off Linux so the workspace builds
//! on macOS dev hosts.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code: i32 = match std::env::args().nth(1).and_then(|s| s.parse().ok()) {
        Some(c) => c,
        None => {
            eprintln!("usage: mvm-exit-report <exit-code>");
            return ExitCode::from(2);
        }
    };
    // Flush before the host is told we are done, and before `/init` runs
    // `poweroff -f`. The `-f` is a *forced* poweroff: no shutdown scripts, no
    // unmount, no implicit sync — so anything still in the page cache for a
    // writable block volume dies with the VM.
    //
    // Measured, which is why this is here rather than assumed: a guest wrote a
    // file to a `--mount HOST:/GUEST:SIZE:rw` disk and the file was absent when
    // the same image was re-attached to a fresh VM. The identical write with an
    // explicit `sync` survived. Without this, "writable" silently means
    // "writable if the workload remembers to sync", and losing data quietly is
    // worse than refusing to write at all.
    //
    // Ordered before `report` so the bytes are on their way to the disk while
    // the exit round-trip is in flight, and unconditional: the guest cannot
    // know which of its mounts the host cares about.
    flush_filesystems();
    match report(code) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvm-exit-report: {e}");
            ExitCode::from(1)
        }
    }
}

/// `sync(2)` — schedule every dirty page for writeback.
///
/// Best-effort and infallible by design: `sync` cannot fail in a way this
/// helper could act on, and a guest must never block or abort its exit path
/// over a flush.
#[cfg(target_os = "linux")]
fn flush_filesystems() {
    // SAFETY: `sync` takes no arguments, returns nothing, and has no failure
    // mode to check.
    unsafe { libc::sync() };
}

#[cfg(not(target_os = "linux"))]
fn flush_filesystems() {}

#[cfg(target_os = "linux")]
fn report(code: i32) -> std::io::Result<()> {
    use std::io::Write;
    use std::net::TcpStream;

    use mvm_agentd::vsock::{HOST_CID, WORKLOAD_EXIT_PORT, sys};

    let fd = sys::dial(HOST_CID, WORKLOAD_EXIT_PORT)?;
    // A vsock SOCK_STREAM fd wrapped as a `TcpStream` for its `Read`/`Write`;
    // read/write hit the same syscalls regardless of the wrapper type.
    let mut stream = TcpStream::from(fd);
    stream.write_all(&code.to_le_bytes())?;
    stream.flush()?;
    // Wait (bounded) for the host's ack so /init doesn't poweroff until
    // the supervisor has durably written workload.exit (avoids the
    // start_enter->exit() race). Best-effort: a timeout/EOF is fine — we
    // return Ok and /init powers off regardless.
    // Only wait for the ack if we could arm a timeout — otherwise skip
    // the read entirely so the guest can never block before poweroff.
    use std::io::Read as _;
    let mut ack = [0u8; 1];
    if stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .is_ok()
    {
        let _ = stream.read_exact(&mut ack);
    }
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
