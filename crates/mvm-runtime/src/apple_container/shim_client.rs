//! Host-side client for the container shim's control protocol.
//!
//! The shim (`swift/mvm-container-shim`) is spawned detached per VM with a
//! `--spec` JSON file, then spoken to over its control Unix socket using
//! newline-delimited JSON: one request line in (`{"id":N,"op":…}`), one
//! response line out (`{"id":N,"ok":true}` or `{"id":N,"ok":false,
//! "error":…}`). The only op that transfers more than JSON is
//! `dial_vsock`: after the ok response line, the shim sends one sendmsg
//! carrying a single dummy payload byte plus the connected vsock fd in an
//! SCM_RIGHTS control message — this module implements the symmetric
//! recvmsg. The framing codec is pure and unit-tested against an
//! in-process mock server; no Swift is needed to test it.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::apple_container_backend::AppleContainerError;

/// How long `connect` waits for the shim to bind its control socket before
/// declaring the boot failed.
const CONTROL_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-request I/O deadline on the control socket. `wait`-family ops can
/// legitimately block for the life of the workload; they run with no
/// deadline instead.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn the shim detached for `spec_path`, record its pid in `pid_file`,
/// and connect to its control socket once bound. Rolling back is the
/// caller's job on any later failure (the shim stops its VM on exit, so
/// killing the shim is sufficient).
pub fn spawn_shim(
    shim_bin: &Path,
    spec_path: &Path,
    control_socket: &Path,
    pid_file: &Path,
) -> Result<ShimClient, AppleContainerError> {
    let shim = |reason: String| AppleContainerError::Shim {
        op: "spawn",
        reason,
    };
    let mut cmd = Command::new(shim_bin);
    cmd.arg("--spec")
        .arg(spec_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Detach into its own session so it survives this process, exactly as
    // the other per-VM supervisors do.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| shim(format!("spawn {}: {e}", shim_bin.display())))?;
    std::fs::write(pid_file, child.id().to_string())
        .map_err(|e| shim(format!("write {}: {e}", pid_file.display())))?;
    ShimClient::connect(control_socket, CONTROL_SOCKET_TIMEOUT)
}

/// A live control connection to a shim.
pub struct ShimClient {
    stream: UnixStream,
    next_id: u64,
}

impl ShimClient {
    /// Connect to an already-running shim, waiting for the control socket
    /// to appear (the shim binds it a beat after its VM starts).
    pub fn connect(control_socket: &Path, timeout: Duration) -> Result<Self, AppleContainerError> {
        let deadline = Instant::now() + timeout;
        loop {
            match UnixStream::connect(control_socket) {
                Ok(stream) => {
                    return Ok(Self { stream, next_id: 1 });
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(AppleContainerError::Shim {
                            op: "connect",
                            reason: format!(
                                "shim did not bind {} within {timeout:?}: {e}",
                                control_socket.display()
                            ),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// One request/response round trip. Returns the response's result
    /// fields (empty for ack-only ops).
    fn request(
        &mut self,
        op: serde_json::Value,
        deadline: Option<Duration>,
    ) -> Result<serde_json::Value, AppleContainerError> {
        self.request_impl(op, deadline)
            .map_err(|e| AppleContainerError::Shim {
                op: "request",
                reason: e.to_string(),
            })
    }

    fn request_impl(
        &mut self,
        op: serde_json::Value,
        deadline: Option<Duration>,
    ) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = encode_request_line(id, &op)?;
        self.stream
            .set_read_timeout(deadline)
            .context("set read timeout on shim control socket")?;
        self.stream
            .set_write_timeout(deadline)
            .context("set write timeout on shim control socket")?;
        self.stream.write_all(&line).context("write shim request")?;
        let resp_line = read_line(&mut self.stream).context("read shim response")?;
        let resp = parse_response_line(&resp_line).context("parse shim response")?;
        if resp.id != id {
            bail!(
                "shim response id {} does not match request id {id}",
                resp.id
            );
        }
        match resp.error {
            Some(error) => bail!("shim: {error}"),
            None => Ok(resp.result.unwrap_or_else(|| json!({}))),
        }
    }

    /// Liveness probe.
    pub fn ping(&mut self) -> Result<(), AppleContainerError> {
        self.request(json!({"op": "ping"}), Some(REQUEST_TIMEOUT))?;
        Ok(())
    }

    /// Stop the container VM and let the shim exit.
    pub fn stop(&mut self) -> Result<(), AppleContainerError> {
        self.request(json!({"op": "stop"}), Some(REQUEST_TIMEOUT))?;
        Ok(())
    }

    /// SIGKILL the container VM.
    pub fn kill(&mut self) -> Result<(), AppleContainerError> {
        self.request(json!({"op": "kill"}), Some(REQUEST_TIMEOUT))?;
        Ok(())
    }

    /// Wait for the container VM to exit and return its exit code. Runs
    /// with no deadline — a workload's life is unbounded.
    pub fn wait(&mut self) -> Result<i64, AppleContainerError> {
        let result = self.request(json!({"op": "wait"}), None)?;
        Ok(result
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1))
    }

    /// Inject a file into the guest (whole-file write; the shim streams it
    /// via the container's copy channel, so no chunking is needed).
    pub fn write_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<(), AppleContainerError> {
        use base64::Engine;
        self.request(
            json!({
                "op": "vminitd_write_file",
                "path": path,
                "data_b64": base64::engine::general_purpose::STANDARD.encode(data),
                "mode": mode,
            }),
            Some(REQUEST_TIMEOUT),
        )?;
        Ok(())
    }

    /// Create a directory in the guest (optionally with parents).
    pub fn mkdir(&mut self, path: &str, all: bool, perms: u32) -> Result<(), AppleContainerError> {
        self.request(
            json!({"op": "vminitd_mkdir", "path": path, "all": all, "perms": perms}),
            Some(REQUEST_TIMEOUT),
        )?;
        Ok(())
    }

    /// Create (not start) a guest process.
    pub fn create_process(&mut self, proc: &ProcessSpec<'_>) -> Result<(), AppleContainerError> {
        self.request(
            json!({
                "op": "vminitd_create_process",
                "proc_id": proc.id,
                "path": proc.path,
                "args": proc.args,
                "env": proc.env,
                "cwd": proc.cwd,
            }),
            Some(REQUEST_TIMEOUT),
        )?;
        Ok(())
    }

    /// Start a created guest process, returning its pid.
    pub fn start_process(&mut self, proc_id: &str) -> Result<i32, AppleContainerError> {
        let result = self.request(
            json!({"op": "vminitd_start_process", "proc_id": proc_id}),
            Some(REQUEST_TIMEOUT),
        )?;
        Ok(result
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1) as i32)
    }

    /// Wait for a guest process to exit, returning its exit code.
    pub fn wait_process(&mut self, proc_id: &str) -> Result<i64, AppleContainerError> {
        let result = self.request(
            json!({"op": "vminitd_wait_process", "proc_id": proc_id}),
            None,
        )?;
        Ok(result
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1))
    }

    /// Signal a guest process.
    pub fn signal_process(
        &mut self,
        proc_id: &str,
        signal: i32,
    ) -> Result<(), AppleContainerError> {
        self.request(
            json!({"op": "vminitd_signal", "proc_id": proc_id, "signal": signal}),
            Some(REQUEST_TIMEOUT),
        )?;
        Ok(())
    }

    /// Dial a guest vsock port, returning the connected socket. After the
    /// ok response line, the shim hands the fd over SCM_RIGHTS (see the
    /// module docs for the wire convention).
    pub fn dial_vsock(&mut self, port: u32) -> Result<UnixStream, AppleContainerError> {
        self.request(
            json!({"op": "dial_vsock", "port": port}),
            Some(REQUEST_TIMEOUT),
        )?;
        self.stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| AppleContainerError::Shim {
                op: "dial_vsock",
                reason: format!("set read timeout: {e}"),
            })?;
        recv_fd(self.stream.as_raw_fd()).map_err(|e| AppleContainerError::Shim {
            op: "dial_vsock",
            reason: format!("receive vsock fd: {e}"),
        })
    }
}

/// The process description `create_process` takes. Borrows so a caller
/// assembling it inline pays no copies.
pub struct ProcessSpec<'a> {
    pub id: &'a str,
    pub path: &'a str,
    pub args: &'a [String],
    pub env: &'a [String],
    pub cwd: &'a str,
}

// ---------------------------------------------------------------------------
// Framing (pure, unit-tested)
// ---------------------------------------------------------------------------

/// Encode one request line (with trailing newline).
pub fn encode_request_line(id: u64, op: &serde_json::Value) -> Result<Vec<u8>> {
    let mut value = op.clone();
    value["id"] = json!(id);
    let mut bytes = serde_json::to_vec(&value).context("encode shim request")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// A decoded response line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub result: Option<serde_json::Value>,
}

/// Decode one response line.
pub fn parse_response_line(line: &[u8]) -> Result<RawResponse> {
    serde_json::from_slice(line).context("shim response is not valid JSON")
}

/// Read one newline-terminated line (without the newline).
fn read_line(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .context("read from shim control socket")?;
        if n == 0 {
            bail!("shim closed the control socket");
        }
        if byte[0] == b'\n' {
            return Ok(out);
        }
        out.push(byte[0]);
    }
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS receive (the dial_vsock fd handoff)
// ---------------------------------------------------------------------------

/// CMSG helpers mirroring CMSG_ALIGN/CMSG_SPACE from <sys/socket.h>.
const fn cmsg_align(n: usize) -> usize {
    n.next_multiple_of(std::mem::size_of::<libc::size_t>())
}

const fn cmsg_space(payload: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(payload)
}

const fn cmsg_len(payload: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + payload
}

/// Aligned control-message buffer: a bare `[u8; N]` stack array has no
/// alignment guarantee, and an unaligned `cmsghdr` is EINVAL on both
/// sendmsg and recvmsg.
#[repr(align(8))]
struct AlignedControl([u8; cmsg_space(std::mem::size_of::<RawFd>())]);

impl AlignedControl {
    fn new() -> Self {
        Self([0u8; cmsg_space(std::mem::size_of::<RawFd>())])
    }

    fn as_ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Receive one message of exactly one dummy payload byte plus one fd in an
/// SCM_RIGHTS control message — the symmetric half of the shim's sendFd.
fn recv_fd(socket: RawFd) -> Result<UnixStream> {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = AlignedControl::new();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_ptr();
    msg.msg_controllen = control.len() as _;

    // SAFETY: recvmsg(2) on a valid socket fd; `msg` points at valid,
    // fully-sized buffers for the duration of the call.
    let n = unsafe { libc::recvmsg(socket, &mut msg, 0) };
    if n < 0 {
        return Err(anyhow!("recvmsg: {}", std::io::Error::last_os_error()));
    }
    if n == 0 {
        bail!("shim closed the control socket instead of passing an fd");
    }

    // SAFETY: CMSG_FIRSTHDR equivalent — the control buffer is
    // cmsg_space-sized and the kernel filled the header.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        bail!("no control message in shim fd handoff");
    }
    let (level, ty, len) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len) };
    if level != libc::SOL_SOCKET
        || ty != libc::SCM_RIGHTS
        || (len as usize) < cmsg_len(std::mem::size_of::<RawFd>())
    {
        bail!(
            "unexpected control message in shim fd handoff (level={level}, type={ty}, len={len})"
        );
    }
    // SAFETY: the header checks above prove one fd-sized payload follows
    // the aligned header.
    let fd = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned() };
    // SAFETY: `fd` is a fresh, owned descriptor received via SCM_RIGHTS.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// A stub shim: answer requests from canned responses, one per line.
    fn spawn_stub(answers: Vec<serde_json::Value>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("shim.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for answer in answers {
                let _line = read_line(&mut stream).unwrap();
                let mut bytes = serde_json::to_vec(&answer).unwrap();
                bytes.push(b'\n');
                stream.write_all(&bytes).unwrap();
            }
        });
        let path = sock;
        (dir, path)
    }

    #[test]
    fn request_line_carries_id_and_op() {
        let line = encode_request_line(7, &json!({"op": "ping"})).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(parsed["id"], 7);
        assert_eq!(parsed["op"], "ping");
        assert_eq!(*line.last().unwrap(), b'\n');
    }

    #[test]
    fn response_line_decodes_ok_error_and_result() {
        let ok = parse_response_line(br#"{"id":1,"ok":true,"pid":42}"#).unwrap();
        assert!(ok.ok);
        assert_eq!(ok.error, None);
        assert_eq!(ok.result.unwrap()["pid"], 42);

        let err = parse_response_line(br#"{"id":2,"ok":false,"error":"boom"}"#).unwrap();
        assert!(!err.ok);
        assert_eq!(err.error.as_deref(), Some("boom"));
    }

    #[test]
    fn round_trip_ok_error_and_id_mismatch() {
        let (_dir, sock) = spawn_stub(vec![
            json!({"id": 1, "ok": true}),
            json!({"id": 2, "ok": false, "error": "nope"}),
            json!({"id": 99, "ok": true}),
        ]);
        let mut client = ShimClient::connect(&sock, Duration::from_secs(2)).unwrap();
        client.ping().unwrap();
        let err = client.ping().unwrap_err();
        assert!(
            matches!(err, AppleContainerError::Shim { .. }),
            "error responses surface as typed Shim errors: {err}"
        );
        let err = client.ping().unwrap_err();
        assert!(
            matches!(err, AppleContainerError::Shim { .. }),
            "id mismatch: {err}"
        );
    }

    #[test]
    fn dial_vsock_receives_the_passed_fd() {
        // Stub shim: answer the request line, then pass one end of a
        // socketpair over SCM_RIGHTS (the symmetric half of the client's
        // recv_fd).
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("shim.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _line = read_line(&mut stream).unwrap();
            stream.write_all(br#"{"id":1,"ok":true}"#.as_ref()).unwrap();
            stream.write_all(b"\n").unwrap();
            let (mut a, b) = UnixStream::pair().unwrap();
            send_fd(stream.as_raw_fd(), b.as_raw_fd()).unwrap();
            drop(b);
            // Echo one byte back through the passed fd's other end.
            let mut byte = [0u8; 1];
            a.read_exact(&mut byte).unwrap();
            a.write_all(&byte).unwrap();
        });

        let mut client = ShimClient::connect(&sock, Duration::from_secs(2)).unwrap();
        let mut conn = client.dial_vsock(5252).unwrap();
        conn.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        conn.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x", "the passed fd is a live duplex channel");
    }

    /// Test-side mirror of the shim's sendFd: one dummy payload byte + one
    /// fd in an SCM_RIGHTS cmsg.
    fn send_fd(socket: RawFd, fd: RawFd) -> Result<()> {
        let mut dummy = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = AlignedControl::new();
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_ptr();
        // macOS rejects CMSG_SPACE here (EINVAL): msg_controllen must be
        // the single header's CMSG_LEN, not the padded buffer size.
        msg.msg_controllen = cmsg_len(std::mem::size_of::<RawFd>()) as _;

        // SAFETY: one cmsg at the head of a cmsg_space-sized buffer.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null());
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<RawFd>()) as _;
            libc::CMSG_DATA(cmsg).cast::<RawFd>().write_unaligned(fd);
        }
        // SAFETY: sendmsg(2) on a valid socket; buffers are valid for the call.
        let rc = unsafe { libc::sendmsg(socket, &msg, 0) };
        if rc < 0 {
            return Err(anyhow!("sendmsg: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}
