//! Low-level vsock UDS connection management: the Firecracker
//! CONNECT/OK handshake, reconnect backoff, and the guest-facing
//! AF_VSOCK dial path used by the substitution forward proxy.

use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;

use super::*;

/// Path to the Firecracker vsock UDS for an instance.
pub fn vsock_uds_path(instance_dir: &str) -> String {
    format!("{}/runtime/v.sock", instance_dir)
}

/// Check if an IO error is a timeout (EAGAIN/EWOULDBLOCK or TimedOut).
pub(crate) fn is_timeout_error(err: &std::io::Error) -> bool {
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
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotFound
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod transient_connect_error_tests {
    use super::is_transient_connect_error;
    use std::io::{Error, ErrorKind};

    #[test]
    fn broken_pipe_during_connect_handshake_is_transient() {
        assert!(is_transient_connect_error(&Error::from(
            ErrorKind::BrokenPipe
        )));
    }

    #[test]
    fn malformed_connect_ack_is_not_an_io_retry_candidate() {
        assert!(!is_transient_connect_error(&Error::from(
            ErrorKind::InvalidData
        )));
    }
}

fn should_retry_connect_error(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(is_transient_connect_error)
}

/// Hard cap on the Firecracker `CONNECT` acknowledgement line, including its
/// terminating newline. A well-formed `OK <port>\n` is a handful of bytes; a
/// response that never terminates within this bound is treated as hostile or
/// broken and refused rather than read unboundedly.
const MAX_CONNECT_RESPONSE_LEN: usize = 128;

fn read_connect_response_line<R: Read>(stream: &mut R) -> std::io::Result<String> {
    let mut response = Vec::with_capacity(16);
    let mut byte = [0_u8; 1];

    loop {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
        if byte[0] == b'\n' {
            return String::from_utf8(response)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
        }
        if response.len() >= MAX_CONNECT_RESPONSE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CONNECT response line is too long",
            ));
        }
    }
}

/// Why a Firecracker hybrid-vsock `CONNECT` acknowledgement line was rejected.
///
/// A malformed acknowledgement is a definitive protocol violation, never a
/// transient establishment hiccup, so it must fail closed with no retry — the
/// bytes already read cannot be safely replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum ConnectAckError {
    #[error("acknowledgement line was not newline-terminated")]
    MissingNewline,
    #[error("acknowledgement did not start with the 'OK ' prefix")]
    MissingOkPrefix,
    #[error("acknowledgement carried no port number")]
    EmptyPort,
    #[error("port field was not a bare decimal number")]
    PortNotDecimal,
    #[error("port number did not fit in a u32")]
    PortOverflow,
}

/// Parse and validate the multiplexer's `CONNECT` acknowledgement line.
///
/// The Firecracker vsock device answers a successful host→guest `CONNECT` with
/// exactly `OK <port>\n`, where `<port>` is the decimal port the device
/// assigns to the *host* end of the tunnel. That number is deliberately not
/// the guest port we requested, so equality is not — and must not be —
/// enforced; requiring it would reject every real acknowledgement. The
/// returned value is the host-assigned port.
///
/// Every other shape is refused so a malformed or adversarial line can never
/// be mistaken for a live tunnel: a missing `OK ` prefix, an absent port, a
/// signed or non-decimal or overflowing number, a trailing extra token, any
/// embedded control byte or NUL, or a line with no terminating newline. The
/// digit scan runs before the numeric parse precisely because the standard
/// unsigned parser would otherwise accept a leading `+` and a `-0`.
fn parse_connect_ack(line: &str) -> Result<u32, ConnectAckError> {
    let body = line
        .strip_suffix('\n')
        .ok_or(ConnectAckError::MissingNewline)?;
    let port_field = body
        .strip_prefix("OK ")
        .ok_or(ConnectAckError::MissingOkPrefix)?;
    if port_field.is_empty() {
        return Err(ConnectAckError::EmptyPort);
    }
    if !port_field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConnectAckError::PortNotDecimal);
    }
    port_field
        .parse::<u32>()
        .map_err(|_| ConnectAckError::PortOverflow)
}

/// Make one connection attempt and perform the Firecracker CONNECT handshake.
///
/// Callers that already own a bounded readiness loop use this entry point so
/// they do not nest the general reconnect cadence inside their own backoff.
/// Ordinary RPC callers should use [`connect_to_port`], which retries transient
/// transport races for them.
pub fn connect_to_port_once(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
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
    let response_line = read_connect_response_line(&mut stream).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::Error::from(e).context(format!(
                "Guest agent did not respond within {}s \
                 (the agent may not be running or the microVM may be unhealthy)",
                timeout_secs
            ))
        } else {
            anyhow::Error::from(e).context("Failed to read CONNECT response")
        }
    })?;

    // A malformed acknowledgement means we have already exchanged application
    // bytes with something that is not the multiplexer; fail closed here rather
    // than admit the stream. `ConnectAckError` is not an `io::Error`, so
    // `should_retry_connect_error` classifies it as non-transient and the
    // caller does not retry (which would replay the CONNECT after those bytes).
    parse_connect_ack(&response_line).map_err(|reason| {
        anyhow::Error::new(reason).context(format!(
            "Vsock CONNECT to port {port} was refused by the multiplexer: {response_line:?}"
        ))
    })?;

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
/// 4. Then establish the authenticated, encrypted session that carries
///    length-prefixed control envelopes.
///
/// Retries up to `CONNECT_RETRIES` times on timeout errors, skipping retries
/// for definitive failures (connection refused, socket not found).
pub fn connect_to_port(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
    let mut last_err = None;

    for attempt in 0..CONNECT_RETRIES {
        match connect_to_port_once(uds_path, port, timeout_secs) {
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
    let mut last_err = None;
    let mut stream = None;
    for attempt in 0..CONNECT_RETRIES {
        match dial_host_once(port) {
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

/// One guest→host AF_VSOCK dial attempt, wrapping the leaf's owned fd as a
/// [`UnixStream`]. The `anyhow` context carries the io::Error as its root
/// cause so [`connect_host_vsock`]'s transient-error classifier keys on it.
#[cfg(target_os = "linux")]
fn dial_host_once(port: u32) -> Result<UnixStream> {
    let fd = crate::vsock::sys::dial(HOST_CID, port)
        .with_context(|| format!("AF_VSOCK connect to host CID {HOST_CID} port {port}"))?;
    Ok(UnixStream::from(fd))
}

/// The guest→host vsock path is Linux-only; the workspace still compiles on
/// macOS dev hosts, where this direction is never dialed.
#[cfg(not(target_os = "linux"))]
fn dial_host_once(port: u32) -> Result<UnixStream> {
    bail!("guest→host AF_VSOCK dial to port {port} is Linux-only")
}

/// Connect to the guest vsock agent via the fleet-mode instance directory convention.
///
/// Resolves the UDS path as `<instance_dir>/runtime/v.sock`.
pub(super) fn connect(instance_dir: &str, timeout_secs: u64) -> Result<UnixStream> {
    connect_to(&vsock_uds_path(instance_dir), timeout_secs)
}

/// Send a request and receive a response over a vsock connection.
///
/// Establishes the authenticated, encrypted control session and sends one
/// length-prefixed JSON request envelope.
pub fn send_request(stream: &mut UnixStream, req: &GuestRequest) -> Result<GuestResponse> {
    send_request_stream(stream, req)
}

/// Send a request over any synchronous duplex stream.
///
/// Mirrors [`send_request`] but accepts any `Read + Write + Send` type so
/// callers that obtain a stream through the `RunningVm::vsock_connect` seam
/// (which returns a boxed [`std::io::Read`] + [`std::io::Write`]) can use it
/// directly without re-resolving the backend-specific socket path.
pub fn send_request_stream<S: std::io::Read + std::io::Write + Send>(
    stream: &mut S,
    req: &GuestRequest,
) -> Result<GuestResponse> {
    let mut session = open_authenticated_session_stream(stream)?;
    session.write(stream, req)?;
    session.read(stream)
}

/// Establish the authenticated and encrypted host side of a fresh control
/// connection. The host signer is the same identity pinned in the guest's
/// `/run/mvm/host-signer.pub` trust anchor.
pub(crate) fn open_authenticated_session(
    stream: &mut UnixStream,
) -> Result<crate::vsock::AuthenticatedSession> {
    open_authenticated_session_stream(stream)
}

pub(crate) fn open_authenticated_session_stream<S: std::io::Read + std::io::Write + Send>(
    stream: &mut S,
) -> Result<crate::vsock::AuthenticatedSession> {
    let key_path = mvm_core::config::mvm_keys_dir().join("host-signer.ed25519");
    let key_bytes: [u8; 32] = std::fs::read(&key_path)
        .with_context(|| format!("read host signer key {}", key_path.display()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("host signer key must be exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let session_id = format!("vsock-{:032x}", rand::random::<u128>());
    crate::vsock::AuthenticatedSession::host(stream, &session_id, signing_key)
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
    fn test_connect_to_port_once_nonexistent_path() {
        let result = connect_to_port_once("/nonexistent/v.sock", GUEST_AGENT_PORT, 1);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Vsock socket not found at"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_single_connect_attempt_surfaces_the_first_failure() {
        let error = connect_to_port_once("/nonexistent/v.sock", GUEST_AGENT_PORT, 1)
            .expect_err("a missing mux socket must fail without an internal retry loop");
        assert!(
            error.to_string().contains("Vsock socket not found"),
            "{error:#}"
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
    fn single_connect_attempt_does_not_charge_the_reconnect_backoff() {
        let started = std::time::Instant::now();
        let result = connect_to_port_once("/nonexistent/v.sock", GUEST_AGENT_PORT, 1);

        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(CONNECT_RETRY_BASE_DELAY_MS),
            "one readiness probe must not sleep for the multi-attempt reconnect cadence"
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

    #[test]
    fn test_connect_response_preserves_bytes_after_ack() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("v.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), format!("CONNECT {}", GUEST_AGENT_PORT));
            stream
                .write_all(format!("OK {}\nsentinel", GUEST_AGENT_PORT).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let mut stream =
            connect_to_port_once(socket.to_str().unwrap(), GUEST_AGENT_PORT, 1).unwrap();
        let mut sentinel = [0_u8; 8];
        stream.read_exact(&mut sentinel).unwrap();
        assert_eq!(&sentinel, b"sentinel");
        worker.join().unwrap();
    }

    /// A `Read` that hands back preconfigured chunks, then reports EOF once
    /// drained. Lets the CONNECT read helper be exercised across arbitrary
    /// fragmentation without a live socket.
    struct ChunkReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
    }

    impl ChunkReader {
        fn new<I>(chunks: I) -> Self
        where
            I: IntoIterator<Item = Vec<u8>>,
        {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Ok(0);
            };
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks.push_front(chunk.split_off(n));
            }
            Ok(n)
        }
    }

    #[test]
    fn parse_connect_ack_accepts_host_assigned_port() {
        // The device answers with a *host*-assigned port, not the guest port we
        // asked for, so any well-formed decimal is accepted on its own terms.
        assert_eq!(parse_connect_ack("OK 12345\n"), Ok(12345));
        assert_eq!(parse_connect_ack("OK 5252\n"), Ok(5252));
    }

    #[test]
    fn parse_connect_ack_accepts_port_boundaries() {
        assert_eq!(parse_connect_ack("OK 0\n"), Ok(0));
        assert_eq!(
            parse_connect_ack("OK 4294967295\n"),
            Ok(u32::MAX),
            "u32::MAX must parse"
        );
    }

    #[test]
    fn parse_connect_ack_rejects_missing_newline() {
        assert_eq!(
            parse_connect_ack("OK 5252"),
            Err(ConnectAckError::MissingNewline)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_missing_prefix() {
        assert_eq!(
            parse_connect_ack("NO 5252\n"),
            Err(ConnectAckError::MissingOkPrefix)
        );
        // Case- and spacing-strict: neither variant is the literal `OK ` prefix.
        assert_eq!(
            parse_connect_ack("ok 5252\n"),
            Err(ConnectAckError::MissingOkPrefix)
        );
        assert_eq!(
            parse_connect_ack("OK5252\n"),
            Err(ConnectAckError::MissingOkPrefix)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_empty_port() {
        assert_eq!(parse_connect_ack("OK \n"), Err(ConnectAckError::EmptyPort));
    }

    #[test]
    fn parse_connect_ack_rejects_signed_values() {
        // The standard unsigned parser tolerates a leading `+` and a `-0`; the
        // digit scan must reject both before we ever reach it.
        assert_eq!(
            parse_connect_ack("OK -1\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
        assert_eq!(
            parse_connect_ack("OK +5\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
        assert_eq!(
            parse_connect_ack("OK -0\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_overflow() {
        // u32::MAX + 1, and a value far beyond any integer width.
        assert_eq!(
            parse_connect_ack("OK 4294967296\n"),
            Err(ConnectAckError::PortOverflow)
        );
        assert_eq!(
            parse_connect_ack("OK 99999999999999999999\n"),
            Err(ConnectAckError::PortOverflow)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_non_decimal() {
        assert_eq!(
            parse_connect_ack("OK abc\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
        assert_eq!(
            parse_connect_ack("OK 0x10\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_trailing_garbage() {
        assert_eq!(
            parse_connect_ack("OK 5252 6\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
        assert_eq!(
            parse_connect_ack("OK 5252x\n"),
            Err(ConnectAckError::PortNotDecimal)
        );
    }

    #[test]
    fn parse_connect_ack_rejects_embedded_control_bytes() {
        assert_eq!(
            parse_connect_ack("OK 52\u{0}4\n"),
            Err(ConnectAckError::PortNotDecimal),
            "embedded NUL"
        );
        assert_eq!(
            parse_connect_ack("OK 52\t4\n"),
            Err(ConnectAckError::PortNotDecimal),
            "embedded tab"
        );
        assert_eq!(
            parse_connect_ack("OK 5\r\n"),
            Err(ConnectAckError::PortNotDecimal),
            "carriage return before newline"
        );
    }

    #[test]
    fn read_connect_response_line_reassembles_across_reads() {
        let mut reader = ChunkReader::new([b"OK ".to_vec(), b"525".to_vec(), b"2\n".to_vec()]);
        let line = read_connect_response_line(&mut reader).unwrap();
        assert_eq!(line, "OK 5252\n");
        assert_eq!(parse_connect_ack(&line), Ok(5252));
    }

    #[test]
    fn read_connect_response_line_reassembles_one_byte_at_a_time() {
        let chunks = b"OK 5252\n".iter().map(|b| vec![*b]);
        let mut reader = ChunkReader::new(chunks);
        let line = read_connect_response_line(&mut reader).unwrap();
        assert_eq!(line, "OK 5252\n");
        assert_eq!(parse_connect_ack(&line), Ok(5252));
    }

    #[test]
    fn read_connect_response_line_errors_on_eof_before_newline() {
        let mut reader = ChunkReader::new([b"OK 52".to_vec()]);
        let err = read_connect_response_line(&mut reader).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_connect_response_line_accepts_line_at_length_limit() {
        // A line whose terminating newline lands exactly on the cap is admitted.
        let mut line = vec![b'x'; MAX_CONNECT_RESPONSE_LEN - 1];
        line.push(b'\n');
        assert_eq!(line.len(), MAX_CONNECT_RESPONSE_LEN);
        let mut reader = ChunkReader::new([line.clone()]);
        let got = read_connect_response_line(&mut reader).unwrap();
        assert_eq!(got.len(), MAX_CONNECT_RESPONSE_LEN);
    }

    #[test]
    fn read_connect_response_line_rejects_line_over_length_limit() {
        // The cap is reached by non-newline bytes before any terminator.
        let over = vec![b'x'; MAX_CONNECT_RESPONSE_LEN];
        let mut reader = ChunkReader::new([over]);
        let err = read_connect_response_line(&mut reader).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
