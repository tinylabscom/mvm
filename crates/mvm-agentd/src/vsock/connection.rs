//! Low-level vsock UDS connection management: the Firecracker
//! CONNECT/OK handshake, reconnect backoff, and the guest-facing
//! AF_VSOCK dial path used by the substitution forward proxy.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::*;

/// Path to the Firecracker vsock UDS for an instance.
pub fn vsock_uds_path(instance_dir: &str) -> String {
    format!("{}/runtime/v.sock", instance_dir)
}

/// Check if an IO error is a timeout (EAGAIN/EWOULDBLOCK or TimedOut).
fn is_timeout_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn connect_retry_delay(attempt: u32) -> Duration {
    let scaled = CONNECT_RETRY_BASE_DELAY_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(scaled.min(CONNECT_RETRY_CAP_DELAY_MS))
}

fn is_transient_connect_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotFound
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::UnexpectedEof
    )
}

fn should_retry_connect_error(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(is_transient_connect_error)
}

/// Single attempt to connect and perform the Firecracker CONNECT handshake.
fn try_connect_once(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
    let timeout = Duration::from_secs(timeout_secs);

    // Pre-flight: verify the socket file exists and is actually a socket.
    // Follow symlinks (`metadata`, not `symlink_metadata`): both the
    // Firecracker default-image and template launch paths expose the vsock
    // UDS at `<dir>/runtime/v.sock` as a symlink to the socket Firecracker
    // actually binds, so the pre-flight must resolve through it — otherwise
    // it sees the symlink's own file type and wrongly rejects a connectable
    // socket.
    match std::fs::metadata(uds_path) {
        Err(e) => bail!("Vsock socket not found at {}: {}", uds_path, e),
        Ok(m) if !m.file_type().is_socket() => {
            bail!(
                "Path {} exists but is not a socket (type: {:?})",
                uds_path,
                m.file_type()
            )
        }
        Ok(_) => {}
    }

    let stream = UnixStream::connect(uds_path)
        .with_context(|| format!("Failed to connect to vsock UDS at {}", uds_path))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut stream = stream;
    writeln!(stream, "CONNECT {}", port).with_context(|| "Failed to send CONNECT")?;
    stream.flush()?;

    // Read response line: "OK <port>\n"
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    let bytes = reader.read_line(&mut response_line).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!(
                "Guest agent did not respond within {}s \
                 (the agent may not be running or the microVM may be unhealthy)",
                timeout_secs
            )
        } else {
            anyhow::anyhow!("Failed to read CONNECT response: {}", e)
        }
    })?;
    if bytes == 0 {
        return Err(anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "guest agent closed the CONNECT handshake before replying",
        ))
        .context("Failed to read CONNECT response"));
    }

    if !response_line.starts_with("OK ") {
        bail!(
            "Vsock CONNECT failed: expected 'OK {}', got '{}'",
            GUEST_AGENT_PORT,
            response_line.trim()
        );
    }

    Ok(stream)
}

/// Connect to a specific vsock port via the Firecracker UDS multiplexer.
///
/// The Firecracker vsock device exposes a single host-side UDS for
/// host→guest connections; the destination port is selected by the
/// `CONNECT <port>\n` handshake line, not by the UDS path. This entry
/// point lets the caller pick that port — needed for things like the
/// console data port, which is allocated by the agent at runtime.
///
/// Connect protocol:
/// 1. Open Unix stream to the given UDS path.
/// 2. Write `CONNECT <port>\n`.
/// 3. Read `OK <port>\n`.
/// 4. Then exchange length-prefixed JSON frames.
///
/// Retries up to `CONNECT_RETRIES` times on timeout errors, skipping retries
/// for definitive failures (connection refused, socket not found).
pub fn connect_to_port(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
    let mut last_err = None;

    for attempt in 0..CONNECT_RETRIES {
        match try_connect_once(uds_path, port, timeout_secs) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                if !should_retry_connect_error(e.root_cause()) {
                    return Err(e);
                }

                last_err = Some(e);

                if attempt + 1 < CONNECT_RETRIES {
                    std::thread::sleep(connect_retry_delay(attempt));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect to guest agent on port {} after {} attempts",
            port,
            CONNECT_RETRIES
        )
    }))
}

/// Connect to the guest agent control port ([`GUEST_AGENT_PORT`]) via
/// a direct UDS path. Backward-compatible thin wrapper over
/// [`connect_to_port`] that all existing callers (control-plane RPCs,
/// health probes, integration queries) target.
pub fn connect_to(uds_path: &str, timeout_secs: u64) -> Result<UnixStream> {
    connect_to_port(uds_path, GUEST_AGENT_PORT, timeout_secs)
}

/// The vsock CID of the host, from the guest's perspective (`VMADDR_CID_HOST`).
pub const HOST_CID: u32 = 2;

/// Open a **guest→host** vsock stream to the host on `port` (AF_VSOCK to
/// [`HOST_CID`]). This is the direction the substitution forward proxy needs —
/// the opposite of [`connect_to_port`], which is the host→guest Firecracker
/// UDS-multiplexer path. Backend-agnostic on the guest side: both QEMU
/// (`vhost-vsock`) and Firecracker forward a guest AF_VSOCK connect to CID 2 to
/// the host's listener (real AF_VSOCK for QEMU, a per-port UDS for Firecracker).
///
/// The returned fd is a `SOCK_STREAM` socket wrapped as a [`UnixStream`] — a
/// thin SOCK_STREAM wrapper whose read/write are the same syscalls — so the
/// length-prefixed frame helpers ([`read_frame`]/[`write_frame`]) work over it
/// unchanged.
pub fn connect_host_vsock(port: u32, timeout_secs: u64) -> Result<UnixStream> {
    use std::os::fd::FromRawFd;

    const AF_VSOCK: libc::c_int = 40;
    // Kernel uapi `struct sockaddr_vm`: family u16 + reserved u16 + port u32 +
    // cid u32 + 4-byte pad = 16 (== sizeof(struct sockaddr)).
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

    let mut last_err = None;
    let mut stream = None;
    for attempt in 0..CONNECT_RETRIES {
        // SAFETY: standard socket(2)/connect(2) on AF_VSOCK; `addr` is fully
        // initialized and sized exactly. The fd is adopted by `UnixStream` on
        // success (closed on its drop) or closed explicitly on the error path.
        let connect_result = unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                Err(anyhow::Error::from(std::io::Error::last_os_error())
                    .context("AF_VSOCK socket()"))
            } else {
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: HOST_CID,
                    svm_zero: [0; 4],
                };
                let rc = libc::connect(
                    fd,
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                );
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    Err(anyhow::Error::from(err).context(format!(
                        "AF_VSOCK connect to host CID {HOST_CID} port {port}"
                    )))
                } else {
                    Ok(UnixStream::from_raw_fd(fd))
                }
            }
        };

        match connect_result {
            Ok(open_stream) => {
                stream = Some(open_stream);
                break;
            }
            Err(e) => {
                if !should_retry_connect_error(e.root_cause()) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt + 1 < CONNECT_RETRIES {
                    std::thread::sleep(connect_retry_delay(attempt));
                }
            }
        }
    }
    let stream = match stream {
        Some(stream) => stream,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                anyhow::anyhow!(
                    "Failed to connect to host CID {HOST_CID} port {port} after {CONNECT_RETRIES} attempts"
                )
            }));
        }
    };
    let timeout = Duration::from_secs(timeout_secs);
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    Ok(stream)
}

/// Connect to the guest vsock agent via the fleet-mode instance directory convention.
///
/// Resolves the UDS path as `<instance_dir>/runtime/v.sock`.
pub(super) fn connect(instance_dir: &str, timeout_secs: u64) -> Result<UnixStream> {
    connect_to(&vsock_uds_path(instance_dir), timeout_secs)
}

/// Send a request and receive a response over a vsock connection.
///
/// Uses 4-byte big-endian length prefix + JSON body (same pattern as hostd).
pub fn send_request(stream: &mut UnixStream, req: &GuestRequest) -> Result<GuestResponse> {
    let data = serde_json::to_vec(req).with_context(|| "Failed to serialize request")?;

    // Write length-prefixed frame
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .with_context(|| "Failed to write frame length")?;
    stream
        .write_all(&data)
        .with_context(|| "Failed to write frame body")?;
    stream.flush()?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!("Guest agent timed out while waiting for response")
        } else {
            anyhow::anyhow!("Failed to read response length: {}", e)
        }
    })?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > MAX_FRAME_SIZE {
        bail!(
            "Response frame too large: {} bytes (max {})",
            resp_len,
            MAX_FRAME_SIZE
        );
    }

    // Read response body
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!("Guest agent timed out while reading response body")
        } else {
            anyhow::anyhow!("Failed to read response body: {}", e)
        }
    })?;

    serde_json::from_slice(&buf).with_context(|| "Failed to deserialize response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_uds_path() {
        assert_eq!(
            vsock_uds_path("/var/lib/mvm/tenants/acme/pools/workers/instances/i-abc"),
            "/var/lib/mvm/tenants/acme/pools/workers/instances/i-abc/runtime/v.sock"
        );
    }

    #[test]
    fn test_is_timeout_error_would_block() {
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn test_is_timeout_error_timed_out() {
        let err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn test_is_timeout_error_other() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(!is_timeout_error(&err));
    }

    #[test]
    fn test_connect_retry_delay_grows_then_caps() {
        assert_eq!(connect_retry_delay(0), Duration::from_millis(100));
        assert_eq!(connect_retry_delay(1), Duration::from_millis(200));
        assert_eq!(connect_retry_delay(2), Duration::from_millis(400));
        assert_eq!(connect_retry_delay(3), Duration::from_millis(500));
        assert_eq!(connect_retry_delay(32), Duration::from_millis(500));
    }

    #[test]
    fn test_transient_connect_errors_include_restart_races() {
        assert!(is_transient_connect_error(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "socket missing during restart"
        )));
        assert!(is_transient_connect_error(&std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "listener not ready"
        )));
        assert!(is_transient_connect_error(&std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "worker restarted"
        )));
        assert!(is_transient_connect_error(&std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "listener died before CONNECT ack"
        )));
        assert!(!is_transient_connect_error(&std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "caller bug"
        )));
    }

    #[test]
    fn test_try_connect_once_nonexistent_path() {
        let result = try_connect_once("/nonexistent/v.sock", GUEST_AGENT_PORT, 1);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Vsock socket not found at"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_connect_to_nonexistent_retries_are_bounded() {
        // A missing socket can be transient during restart. We retry briefly,
        // but the bounded exponential backoff must still fail quickly.
        let start = std::time::Instant::now();
        let result = connect_to("/nonexistent/v.sock", 1);
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < 3,
            "connect_to took {:?}, suggesting an unbounded reconnect loop",
            elapsed
        );
    }

    #[test]
    fn test_connect_to_port_retries_across_listener_restart_before_connect_ack() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("v.sock");
        let socket_path = socket.to_string_lossy().into_owned();
        let port = 4242;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn({
            let socket = socket.clone();
            move || {
                let listener = match UnixListener::bind(&socket) {
                    Ok(listener) => listener,
                    Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                        ready_tx.send(Err(err)).unwrap();
                        return;
                    }
                    Err(err) => panic!("initial unix listener bind failed: {err}"),
                };
                ready_tx.send(Ok(())).unwrap();
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim(), format!("CONNECT {port}"));
                drop(reader);
                drop(listener);

                std::fs::remove_file(&socket).unwrap();
                let listener = match UnixListener::bind(&socket) {
                    Ok(listener) => listener,
                    Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                        panic!(
                            "restart unix listener bind unexpectedly denied after initial success: {err}"
                        );
                    }
                    Err(err) => panic!("restart unix listener bind failed: {err}"),
                };
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                line.clear();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim(), format!("CONNECT {port}"));
                writeln!(stream, "OK {port}").unwrap();
                stream.flush().unwrap();
            }
        });

        match ready_rx.recv().unwrap() {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping listener restart retry test: {err}");
                worker.join().unwrap();
                return;
            }
            Err(err) => panic!("worker setup failed before connect: {err}"),
        }
        let stream =
            connect_to_port(&socket_path, port, 1).expect("connect succeeds after restart");
        drop(stream);
        worker.join().unwrap();
    }
}
