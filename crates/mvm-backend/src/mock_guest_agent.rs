//! In-process mock of the in-guest `mvm-guest-agent` vsock surface.
//!
//! Pairs with [`crate::mock::MockBackend`]: every mock VM
//! gets its own `MockGuestAgent` listening on `<vm_dir>/runtime/v.sock`,
//! the same Unix-domain socket path Firecracker exposes for the
//! vsock UDS multiplexer. The host-side fs/proc helpers in
//! `mvm_guest::vsock` connect to that path, send the
//! `CONNECT <port>\n` line, then exchange length-prefixed JSON
//! `GuestRequest` / `GuestResponse` frames. The mock implements that
//! protocol faithfully enough for the audit-emit live tests in
//! `tests/audit_emissions_live.rs` to exercise `mvmctl fs *` and
//! `mvmctl proc *` end-to-end without a real microVM.
//!
//! ## What the mock answers
//!
//! - **Fs verbs** (`FsWrite`, `FsMkdir`, `FsRemove`, `FsMove`) return
//!   the matching success variant of [`FsResult`]. Byte counts and
//!   entry counts reflect the input so audit-detail strings (`bytes=N`,
//!   `entries=N`) line up with what a real agent would emit.
//! - **Proc verbs** (`ProcStart`, `ProcSignal`, `ProcSendInput`,
//!   `ProcKill`) return the matching success variant of [`ProcResult`].
//!   `ProcStart` mints a deterministic `proc-<N>` token from an atomic
//!   counter.
//! - **Read-only verbs** (`FsRead`, `FsStat`, `FsList`, `FsDiff`,
//!   `ProcList`, `ProcWait`) return empty / zero-state responses — they exist to
//!   keep the wire surface complete for the pinned no-emit tests,
//!   not to model real filesystem / proc state.
//! - **Everything else** comes back as `GuestResponse::Error` so a
//!   future verb that lands without a matching mock arm fails loud
//!   instead of hanging.
//!
//! ## Security profile
//!
//! Tier 3 / test-only. The mock accepts every request, never
//! validates signatures, and never enforces policy. It mirrors
//! [`MockBackend`]'s posture — never selectable from
//! `AnyBackend::auto_select`, only via `--hypervisor mock`.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_guest::vsock::{
    FsErrorKind, FsResult, GuestRequest, GuestResponse, ProcResult, ProcWaitEvent,
    protocol_hello_response,
};

/// Maximum frame size accepted by the mock agent — matches the
/// host-side `MAX_FRAME_SIZE` (256 KiB) so the mock breaks loud
/// rather than silent if a caller exceeds the production cap.
const MAX_FRAME_SIZE: usize = 256 * 1024;

/// How long the accept loop waits between shutdown-flag checks.
/// Short enough that `MockGuestAgent::stop()` returns promptly,
/// long enough to keep idle CPU near zero.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Per-VM mock agent. Owns the listener thread and shuts it down
/// when dropped or when [`stop`](Self::stop) is called.
pub struct MockGuestAgent {
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for MockGuestAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockGuestAgent")
            .field("socket_path", &self.socket_path)
            .field("running", &!self.shutdown.load(Ordering::Relaxed))
            .finish()
    }
}

impl MockGuestAgent {
    /// Start a new mock agent listening on `<vm_dir>/runtime/v.sock`.
    ///
    /// Creates the `runtime` subdirectory if missing and removes any
    /// stale socket file at the target path. The accept loop runs
    /// on a background thread; callers must hold the returned handle
    /// for the agent's lifetime.
    pub fn start(vm_dir: &Path) -> Result<Self> {
        let runtime_dir = vm_dir.join("runtime");
        std::fs::create_dir_all(&runtime_dir)
            .with_context(|| format!("creating runtime dir at {}", runtime_dir.display()))?;
        let socket_path = runtime_dir.join("v.sock");
        // Stale socket from a previous run would make `bind` fail
        // with EADDRINUSE. Best-effort removal.
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("binding mock agent at {}", socket_path.display()))?;
        listener
            .set_nonblocking(true)
            .with_context(|| "setting listener non-blocking")?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let next_token = Arc::new(AtomicU64::new(1));
        let next_token_clone = Arc::clone(&next_token);

        let thread = std::thread::Builder::new()
            .name(format!(
                "mock-guest-agent-{}",
                vm_dir.file_name().and_then(|s| s.to_str()).unwrap_or("vm")
            ))
            .spawn(move || run_accept_loop(listener, shutdown_clone, next_token_clone))
            .with_context(|| "spawning mock guest-agent thread")?;

        Ok(Self {
            socket_path,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Path of the Unix socket the agent is listening on.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Signal the accept loop to exit, join the thread, and remove
    /// the socket file. Idempotent — subsequent calls are no-ops.
    pub fn stop(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for MockGuestAgent {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

fn run_accept_loop(listener: UnixListener, shutdown: Arc<AtomicBool>, next_token: Arc<AtomicU64>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // The listener is non-blocking (so accept can return
                // WouldBlock for the shutdown poll). On some
                // platforms the accepted socket inherits non-blocking
                // mode; force it back to blocking + a generous read
                // timeout so a misbehaving client can't wedge the
                // worker forever.
                if let Err(e) = stream.set_nonblocking(false) {
                    tracing::warn!("mock-guest-agent: set_nonblocking(false) failed: {e}");
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                let token_counter = Arc::clone(&next_token);
                // One worker per connection. Tests bring up at most
                // a handful of VMs with one in-flight call each;
                // unbounded spawn is fine at this scale.
                let _ = std::thread::Builder::new()
                    .name("mock-guest-agent-worker".to_string())
                    .spawn(move || handle_connection(stream, token_counter));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                // Listener dropped (socket file removed during stop)
                // or other unrecoverable error — exit cleanly.
                break;
            }
        }
    }
}

/// Handle one client connection: CONNECT handshake, then one
/// request/response cycle, then close. Matches the host-side
/// `connect_to_port` + `send_request` shape.
fn handle_connection(mut stream: UnixStream, next_token: Arc<AtomicU64>) {
    // Read the CONNECT line one byte at a time. A `BufReader` would
    // be more idiomatic but it pre-buffers from the underlying
    // stream, which means it can swallow the length-prefix bytes
    // the client immediately writes after `CONNECT <port>\n`. The
    // byte-by-byte loop guarantees the next read on `stream`
    // starts exactly at the length-prefix.
    let connect_line = match read_line_byte_by_byte(&mut stream) {
        Some(line) => line,
        None => return,
    };
    let port = parse_connect_line(&connect_line).unwrap_or(0);

    if writeln!(stream, "OK {}", port).is_err() {
        return;
    }
    if stream.flush().is_err() {
        return;
    }

    // Read length-prefixed JSON requests until the client closes the
    // stream or an error occurs. The host-side helpers let a single
    // session issue `ProtocolHello` then the operational request on
    // the same connection — a one-shot mock would close after the
    // hello and strand the follow-up request. The real agent
    // (`handle_client` in `mvm-guest-agent`) also reads multiple
    // frames per session, so this matches production semantics.
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            return;
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_FRAME_SIZE {
            return;
        }
        let mut body = vec![0u8; frame_len];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let req: GuestRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => {
                let _ = write_error(&mut stream, "mock: failed to deserialize GuestRequest");
                return;
            }
        };

        let resp = dispatch(req, &next_token);
        if write_frame(&mut stream, &resp).is_err() {
            return;
        }
    }
}

fn parse_connect_line(line: &str) -> Option<u32> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("CONNECT ")?;
    rest.parse().ok()
}

/// Read a single line (terminated by `\n`) from `stream` one byte at
/// a time. Used in place of `BufReader::read_line` so the worker
/// can switch to length-prefixed framing on the next read without
/// any pre-buffered bytes left over. Caps at 128 bytes — the line
/// the client sends is `"CONNECT <decimal-u32>\n"`, comfortably
/// shorter than that.
fn read_line_byte_by_byte(stream: &mut UnixStream) -> Option<String> {
    let mut out = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    while out.len() < 128 {
        match stream.read_exact(&mut byte) {
            Ok(()) => {
                out.push(byte[0]);
                if byte[0] == b'\n' {
                    return String::from_utf8(out).ok();
                }
            }
            Err(_) => return None,
        }
    }
    None
}

fn write_frame(stream: &mut UnixStream, resp: &GuestResponse) -> Result<()> {
    let data = serde_json::to_vec(resp).context("serialize GuestResponse")?;
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn write_error(stream: &mut UnixStream, message: &str) -> Result<()> {
    write_frame(
        stream,
        &GuestResponse::Error {
            message: message.to_string(),
        },
    )
}

/// Translate one `GuestRequest` into the matching success-shaped
/// `GuestResponse`. Centralised so the protocol surface is auditable
/// in one place.
fn dispatch(req: GuestRequest, next_token: &AtomicU64) -> GuestResponse {
    match req {
        // ── Protocol negotiation ────────────────────────────────────
        // Every call site hellos before the first operational request.
        // The mock answers with whatever the
        // real `protocol_hello_response` would produce so the host
        // helpers (`negotiate_protocol` / `require_capabilities`) see
        // the same ack shape they expect from a real agent.
        GuestRequest::ProtocolHello {
            host_protocol_version,
            min_supported_version,
            host_version,
            requested_capabilities,
        } => protocol_hello_response(
            host_protocol_version,
            min_supported_version,
            &host_version,
            &requested_capabilities,
        ),

        // ── Integration status ──────────────────────────────────────
        // Mock VMs have no integrations to report. Returning an empty
        // list lets the host's services-ready poll transition straight
        // to `ServicesReady` rather than timing out on a "verb not
        // implemented" error from the catch-all arm below.
        GuestRequest::IntegrationStatus => GuestResponse::IntegrationStatusReport {
            integrations: Vec::new(),
        },

        // ── Filesystem verbs ────────────────────────────────────────
        GuestRequest::FsWrite { content, .. } => GuestResponse::FsResult(FsResult::Write {
            bytes_written: content.len() as u64,
        }),
        GuestRequest::FsMkdir { .. } => GuestResponse::FsResult(FsResult::Mkdir),
        GuestRequest::FsRemove { .. } => {
            // Real agent reports actual entry count; the mock has no
            // tree to walk, so always report a single entry removed.
            // The audit emit only asserts `entries=<N>` exists, not
            // the value.
            GuestResponse::FsResult(FsResult::Remove { entries_removed: 1 })
        }
        GuestRequest::FsMove { .. } => GuestResponse::FsResult(FsResult::Move),
        GuestRequest::FsList { .. } => GuestResponse::FsResult(FsResult::List {
            entries: Vec::new(),
            truncated: false,
        }),
        GuestRequest::FsRead { .. } | GuestRequest::FsStat { .. } => {
            GuestResponse::FsResult(FsResult::Error {
                kind: FsErrorKind::Other,
                message: "mock guest-agent: read/stat not implemented".to_string(),
            })
        }

        // ── Process verbs ───────────────────────────────────────────
        GuestRequest::ProcStart { .. } => {
            let n = next_token.fetch_add(1, Ordering::Relaxed);
            GuestResponse::ProcResult(ProcResult::Started {
                pid_token: format!("proc-{n}"),
            })
        }
        GuestRequest::ProcSignal { .. } => GuestResponse::ProcResult(ProcResult::Signaled),
        GuestRequest::ProcSendInput { bytes, .. } => {
            GuestResponse::ProcResult(ProcResult::InputAccepted {
                bytes_accepted: bytes.len() as u64,
            })
        }
        GuestRequest::ProcKill { .. } => GuestResponse::ProcResult(ProcResult::Killed),
        GuestRequest::ProcList => GuestResponse::ProcResult(ProcResult::List {
            processes: Vec::new(),
        }),
        GuestRequest::ProcWait { .. } => {
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Exit { code: 0 })
        }

        // ── Filesystem diff ─────────────────────────────────────────
        // Mock VMs have no overlay to walk; report no changes so
        // `mvmctl diff --hypervisor mock` succeeds rather than hitting
        // the loud catch-all.
        GuestRequest::FsDiff => GuestResponse::FsDiffResult {
            changes: Vec::new(),
        },

        // ── Catch-all: every other verb fails loud ──────────────────
        other => GuestResponse::Error {
            message: format!(
                "mock guest-agent: verb {:?} is not implemented",
                std::mem::discriminant(&other)
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::vsock::{
        connect_to, query_fs_diff_on, send_fs_request, send_proc_request, send_proc_request_on,
        send_proc_wait_on, vsock_uds_path,
    };
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    /// Connect a CONNECT-handshaked stream to a running mock agent —
    /// the same shape `mvm::vsock_transport::for_vm(...).connect(...)`
    /// hands the backend-agnostic `*_on` helpers.
    fn connect_stream(dir: &TempDir) -> std::os::unix::net::UnixStream {
        connect_to(&vsock_uds_path(&dir.path().to_string_lossy()), 5).expect("connect mock stream")
    }

    fn make_vm_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn write_file_round_trip() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent; // keep alive

        let req = GuestRequest::FsWrite {
            path: "/tmp/hello".to_string(),
            content: b"hi there".to_vec(),
            mode: 0o644,
            create_parents: false,
            follow_symlinks: false,
        };
        let result = send_fs_request(&dir.path().to_string_lossy(), req).expect("send_fs_request");
        match result {
            FsResult::Write { bytes_written } => assert_eq!(bytes_written, 8),
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn mkdir_and_remove_round_trip() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let mk = send_fs_request(
            &dir.path().to_string_lossy(),
            GuestRequest::FsMkdir {
                path: "/tmp/x".to_string(),
                mode: 0o755,
                parents: false,
            },
        )
        .expect("mkdir");
        assert!(matches!(mk, FsResult::Mkdir));
        let rm = send_fs_request(
            &dir.path().to_string_lossy(),
            GuestRequest::FsRemove {
                path: "/tmp/x".to_string(),
                recursive: false,
                follow_symlinks: false,
            },
        )
        .expect("remove");
        assert!(matches!(rm, FsResult::Remove { entries_removed: 1 }));
    }

    #[test]
    fn proc_start_assigns_deterministic_tokens() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;

        let req = || GuestRequest::ProcStart {
            argv: vec!["/bin/true".to_string()],
            env: BTreeMap::new(),
            cwd: None,
            stdin: Vec::new(),
            timeout_secs: None,
        };
        let path = dir.path().to_string_lossy();
        let r1 = send_proc_request(&path, req()).expect("start 1");
        let r2 = send_proc_request(&path, req()).expect("start 2");
        match (r1, r2) {
            (ProcResult::Started { pid_token: t1 }, ProcResult::Started { pid_token: t2 }) => {
                assert_eq!(t1, "proc-1");
                assert_eq!(t2, "proc-2");
            }
            other => panic!("expected Started + Started, got {other:?}"),
        }
    }

    #[test]
    fn proc_signal_and_kill_return_success_variants() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let path = dir.path().to_string_lossy();
        let sig = send_proc_request(
            &path,
            GuestRequest::ProcSignal {
                pid_token: "proc-anything".to_string(),
                signum: 15,
            },
        )
        .expect("signal");
        assert!(matches!(sig, ProcResult::Signaled));
        let kill = send_proc_request(
            &path,
            GuestRequest::ProcKill {
                pid_token: "proc-anything".to_string(),
            },
        )
        .expect("kill");
        assert!(matches!(kill, ProcResult::Killed));
    }

    #[test]
    fn proc_send_input_reports_accepted_bytes() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let result = send_proc_request(
            &dir.path().to_string_lossy(),
            GuestRequest::ProcSendInput {
                pid_token: "proc-1".to_string(),
                bytes: vec![1, 2, 3, 4, 5],
            },
        )
        .expect("send input");
        match result {
            ProcResult::InputAccepted { bytes_accepted } => assert_eq!(bytes_accepted, 5),
            other => panic!("expected InputAccepted, got {other:?}"),
        }
    }

    #[test]
    fn stop_removes_socket() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let socket = agent.socket_path().to_path_buf();
        assert!(socket.exists(), "socket must exist while agent is up");
        agent.stop();
        assert!(
            !socket.exists(),
            "socket must be removed by MockGuestAgent::stop"
        );
    }

    #[test]
    fn two_agents_on_separate_vm_dirs_do_not_collide() {
        let dir_a = make_vm_dir();
        let dir_b = make_vm_dir();
        let agent_a = MockGuestAgent::start(dir_a.path()).expect("start a");
        let agent_b = MockGuestAgent::start(dir_b.path()).expect("start b");
        let _ = (&agent_a, &agent_b);

        let write_a = send_fs_request(
            &dir_a.path().to_string_lossy(),
            GuestRequest::FsWrite {
                path: "/tmp/a".to_string(),
                content: b"a".to_vec(),
                mode: 0o644,
                create_parents: false,
                follow_symlinks: false,
            },
        )
        .expect("write a");
        let write_b = send_fs_request(
            &dir_b.path().to_string_lossy(),
            GuestRequest::FsWrite {
                path: "/tmp/b".to_string(),
                content: b"bb".to_vec(),
                mode: 0o644,
                create_parents: false,
                follow_symlinks: false,
            },
        )
        .expect("write b");
        match (write_a, write_b) {
            (FsResult::Write { bytes_written: 1 }, FsResult::Write { bytes_written: 2 }) => {}
            other => panic!("expected 1-byte / 2-byte writes, got {other:?}"),
        }
    }

    // ── Stream-based `*_on` entry points round-trip ──────────────────
    // These drive the backend-agnostic helpers directly on a
    // CONNECT-handshaked stream (what `vsock_transport::for_vm` yields
    // for QEMU/libkrun), instead of the dir-based wrappers.

    #[test]
    fn send_proc_request_on_round_trips_proc_list() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let mut stream = connect_stream(&dir);
        let result = send_proc_request_on(&mut stream, GuestRequest::ProcList).expect("proc list");
        match result {
            ProcResult::List { processes } => assert!(processes.is_empty()),
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[test]
    fn send_proc_wait_on_streams_to_terminal_event() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let mut stream = connect_stream(&dir);
        let terminal =
            send_proc_wait_on(&mut stream, "proc-1", None, |_| {}).expect("proc wait stream");
        assert!(matches!(terminal, ProcWaitEvent::Exit { code: 0 }));
    }

    #[test]
    fn query_fs_diff_on_round_trips_empty_changes() {
        let dir = make_vm_dir();
        let agent = MockGuestAgent::start(dir.path()).expect("start agent");
        let _ = &agent;
        let mut stream = connect_stream(&dir);
        let changes = query_fs_diff_on(&mut stream).expect("fs diff");
        assert!(changes.is_empty());
    }
}
