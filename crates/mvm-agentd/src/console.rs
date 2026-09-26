//! PTY-over-vsock console for interactive guest access.
//!
//! The guest agent allocates a PTY, forks a shell, and relays I/O over a
//! dedicated vsock data port. The host connects to the data port for raw
//! byte streaming — no JSON framing, no Ed25519 signing on the data channel.
//!
//! A session outlives its client. When the host disconnects — deliberately or
//! not — the shell keeps running and its output collects in a bounded
//! scrollback ring ([`scrollback`]), replayed to the next client that attaches.
//! Only an explicit close ends the shell, besides the shell exiting on its own,
//! an optional detach timeout, and the VM stopping. One client is attached at a
//! time ([`registry`]).
//!
//! Security: console sessions are dev-mode only. Opening, attaching, detaching,
//! listing and closing are all control-channel requests, so every one passes
//! the same profile and signed-grant gates before it reaches this module, and
//! the data port accepts only the host CID.

pub mod registry;
pub mod scrollback;

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub use registry::{AttachRefusal, AttachTicket, SessionSummary};
pub use scrollback::SCROLLBACK_CAP_BYTES;

use crate::vsock::HOST_CID;
use registry::{AttachOutcome, ConsoleSink, Registry, SpawnedSession};

/// How long an explicit close waits for the shell to go after each signal.
pub const CLOSE_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an attach waits for the host to dial its data port before the
/// reservation lapses and the session counts as detached again.
pub const ATTACH_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one write to an attached client may block. A client that cannot
/// take output for this long is detached, so a stalled host can never stall
/// the shell behind it — its output goes to scrollback instead.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the output pump wakes with nothing to read, to notice an exited
/// shell and an expired detach timeout.
const PUMP_TICK: Duration = Duration::from_millis(250);

/// Every console session on this agent.
static SESSIONS: Mutex<Registry> = Mutex::new(Registry::new(SCROLLBACK_CAP_BYTES));

fn lock(registry: &Mutex<Registry>) -> MutexGuard<'_, Registry> {
    // The registry holds no invariant a panicking holder could half-apply
    // that is worse than refusing every console request for the VM's life.
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What a new session runs and how it behaves while detached.
#[derive(Debug, Clone, Default)]
pub struct OpenRequest {
    pub cols: u16,
    pub rows: u16,
    pub env: Vec<(String, String)>,
    /// Empty runs the default interactive shell.
    pub argv: Vec<String>,
    /// End the shell once it has had no client for this long. `None` keeps it
    /// until it exits, is closed, or the VM stops.
    pub detach_timeout: Option<Duration>,
}

/// Errors from console operations.
#[derive(Debug)]
pub enum ConsoleError {
    AlreadyActive(u32),
    InvalidCommand(String),
    OpenPtyFailed,
    ForkFailed,
    BindFailed(u32),
    NoSuchSession(u32),
    Busy(u32),
    DidNotTerminate(u32),
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyActive(id) => write!(
                f,
                "console session {id} is already running; attach to it or close it first"
            ),
            Self::InvalidCommand(message) => write!(f, "invalid console command: {message}"),
            Self::OpenPtyFailed => write!(f, "openpty() failed"),
            Self::ForkFailed => write!(f, "fork() failed"),
            Self::BindFailed(port) => write!(f, "failed to bind vsock port {port}"),
            Self::NoSuchSession(id) => write!(f, "no console session {id}"),
            Self::Busy(id) => write!(f, "console session {id} already has an attached client"),
            Self::DidNotTerminate(id) => write!(f, "console session {id} did not terminate"),
        }
    }
}

impl std::error::Error for ConsoleError {}

impl From<AttachRefusal> for ConsoleError {
    fn from(refusal: AttachRefusal) -> Self {
        match refusal {
            AttachRefusal::NoSuchSession(id) => Self::NoSuchSession(id),
            AttachRefusal::Busy(id) => Self::Busy(id),
        }
    }
}

// FFI declarations for PTY operations
unsafe extern "C" {
    fn openpty(
        amaster: *mut i32,
        aslave: *mut i32,
        name: *mut u8,
        termp: *const core::ffi::c_void,
        winp: *const Winsize,
    ) -> i32;
    fn setsid() -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn fork() -> i32;
    fn close(fd: i32) -> i32;
    fn chdir(path: *const u8) -> i32;
    #[cfg(all(test, target_os = "linux"))]
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;

    // Vsock
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
    fn listen(sockfd: i32, backlog: i32) -> i32;
    fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
}

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;
/// Sent to end a session: a hangup is what a terminal going away looks like,
/// so job-control shells clean up their children.
const SIGHUP: i32 = 1;

fn console_peer_is_authorized(cid: u32) -> bool {
    cid == HOST_CID
}
/// ioctl request for setting window size (Linux).
#[cfg(target_os = "linux")]
const TIOCSWINSZ: u64 = 0x5414;
#[cfg(not(target_os = "linux"))]
const TIOCSWINSZ: u64 = 0x80087467;

/// ioctl request to set the controlling terminal.
#[cfg(target_os = "linux")]
const TIOCSCTTY: u64 = 0x540E;
#[cfg(not(target_os = "linux"))]
const TIOCSCTTY: u64 = 0x2000_7461;

#[repr(C)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
    /// builds; carried so the mirror matches the header field-for-field.
    svm_flags: u8,
    svm_zero: [u8; 3],
}

// Layout contract with the kernel's `struct sockaddr_vm`
// (linux/vm_sockets.h), derived on Linux 6.8 with cc
// sizeof/offsetof/_Alignof rather than read off the Rust definition.
// Bytes 12..16: the header gained `svm_flags` at offset 12 in Linux 6.0,
// shrinking `svm_zero` to three bytes. The total is 16 either way, which
// is why the pre-6.0 shape went unnoticed here.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<SockAddrVm>() == 16);
    assert!(align_of::<SockAddrVm>() == 4);
    assert!(offset_of!(SockAddrVm, svm_family) == 0);
    assert!(offset_of!(SockAddrVm, svm_reserved1) == 2);
    assert!(offset_of!(SockAddrVm, svm_port) == 4);
    assert!(offset_of!(SockAddrVm, svm_cid) == 8);
    assert!(offset_of!(SockAddrVm, svm_flags) == 12);
    assert!(offset_of!(SockAddrVm, svm_zero) == 13);
};

/// Terminal window size (matches struct winsize in sys/ioctl.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

// Layout contract with `struct winsize` (sys/ioctl.h). Passed by pointer
// to the TIOCSWINSZ/TIOCGWINSZ ioctls, which read the four fields by
// offset. Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof; the
// same four-u16 layout holds on macOS.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<Winsize>() == 8);
    assert!(align_of::<Winsize>() == 2);
    assert!(offset_of!(Winsize, ws_row) == 0);
    assert!(offset_of!(Winsize, ws_col) == 2);
    assert!(offset_of!(Winsize, ws_xpixel) == 4);
    assert!(offset_of!(Winsize, ws_ypixel) == 6);
};

/// Start a new session and reserve its first attach.
///
/// The data listener is bound before the shell is forked and before this
/// returns, so the host can dial the port the moment it has the ticket.
pub fn open_session(request: &OpenRequest) -> Result<AttachTicket, ConsoleError> {
    open_session_in(&SESSIONS, request)
}

fn open_session_in(
    sessions: &'static Mutex<Registry>,
    request: &OpenRequest,
) -> Result<AttachTicket, ConsoleError> {
    let command_argv = build_console_argv(&request.argv)?;
    let command = command_argv[0].to_string_lossy().into_owned();

    let mut registry = lock(sessions);
    registry.ensure_can_open()?;
    let (attach_id, data_port) = registry.allocate_attach();
    let listener = bind_data_listener(data_port)?;
    let (child_pid, master) = spawn_shell(request, &command_argv)?;
    // Registered before anything waits on it, so the PID-1 orphan reaper
    // publishes this shell's status instead of discarding it.
    let owned = crate::child_wait::OwnedChild::new(child_pid as u32);
    let master = Arc::new(master);
    let ticket = registry.insert(
        SpawnedSession {
            child_pid,
            master: Some(Arc::clone(&master)),
            command,
            detach_timeout: request.detach_timeout,
        },
        attach_id,
    );
    drop(registry);

    let pump_master = Arc::clone(&master);
    std::thread::spawn(move || {
        let _owned = owned;
        pump_output(sessions, ticket.session_id, child_pid, &pump_master);
    });
    std::thread::spawn(move || serve_attach(sessions, ticket, listener, Some(master)));
    Ok(ticket)
}

/// Attach a new client to `session_id`, replaying its scrollback first.
///
/// Refused as [`ConsoleError::Busy`] when a client is attached, unless
/// `take_over` is set, in which case that client is hung up and the shell is
/// left exactly as it was. The window size is applied immediately, so a
/// full-screen program redraws for the new terminal.
pub fn attach_session(
    session_id: u32,
    cols: u16,
    rows: u16,
    take_over: bool,
) -> Result<AttachTicket, ConsoleError> {
    attach_session_in(&SESSIONS, session_id, (cols, rows), take_over)
}

fn attach_session_in(
    sessions: &'static Mutex<Registry>,
    session_id: u32,
    (cols, rows): (u16, u16),
    take_over: bool,
) -> Result<AttachTicket, ConsoleError> {
    let mut registry = lock(sessions);
    let ticket = registry.attach(session_id, take_over)?;
    let listener = match bind_data_listener(ticket.data_port) {
        Ok(listener) => listener,
        Err(error) => {
            registry.release(ticket.attach_id, Instant::now());
            return Err(error);
        }
    };
    if let Some(fd) = registry.master_fd(session_id) {
        resize_pty(fd, cols, rows);
    }
    let master = registry.master(session_id);
    drop(registry);
    std::thread::spawn(move || serve_attach(sessions, ticket, listener, master));
    Ok(ticket)
}

/// Hang up the client attached to `session_id`, leaving the shell running.
/// Returns whether a client was attached.
pub fn detach_session(session_id: u32) -> Result<bool, ConsoleError> {
    Ok(lock(&SESSIONS).detach(session_id, Instant::now())?)
}

/// The sessions this agent holds: the running one, or the last to exit.
pub fn list_sessions() -> Vec<SessionSummary> {
    lock(&SESSIONS).summaries(Instant::now())
}

/// Resize `session_id`'s PTY window. Returns whether the session is running.
pub fn resize_session(session_id: u32, cols: u16, rows: u16) -> bool {
    match lock(&SESSIONS).master_fd(session_id) {
        Some(fd) => {
            resize_pty(fd, cols, rows);
            true
        }
        None => false,
    }
}

/// End `session_id` and return the shell's exit code.
///
/// A session that already exited answers from its recorded code. A running one
/// is hung up — foreground job and shell both — and, if it ignores that, killed.
/// Each signal gets `timeout` to take effect.
pub fn terminate_session(session_id: u32, timeout: Duration) -> Result<i32, ConsoleError> {
    terminate_session_in(&SESSIONS, session_id, timeout)
}

fn terminate_session_in(
    sessions: &Mutex<Registry>,
    session_id: u32,
    timeout: Duration,
) -> Result<i32, ConsoleError> {
    let (child_pid, master) = {
        let registry = lock(sessions);
        if let Some(exit_code) = registry.exit_code(session_id) {
            return Ok(exit_code);
        }
        match registry.running_child(session_id) {
            Some(pid) => (pid, registry.master(session_id)),
            None => return Err(ConsoleError::NoSuchSession(session_id)),
        }
    };
    signal_session(child_pid, master.as_deref(), SIGHUP);
    drop(master);
    if let Some(exit_code) = wait_for_recorded_exit(sessions, session_id, timeout) {
        return Ok(exit_code);
    }
    // SAFETY: `kill` takes no pointers; `child_pid` is this session's shell.
    unsafe {
        kill(child_pid, SIGKILL);
    }
    wait_for_recorded_exit(sessions, session_id, timeout)
        .ok_or(ConsoleError::DidNotTerminate(session_id))
}

fn wait_for_recorded_exit(
    sessions: &Mutex<Registry>,
    session_id: u32,
    timeout: Duration,
) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(exit_code) = lock(sessions).exit_code(session_id) {
            return Some(exit_code);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Fork `argv` onto a new PTY. Returns the child pid and the PTY master.
fn spawn_shell(
    request: &OpenRequest,
    argv: &[std::ffi::CString],
) -> Result<(i32, File), ConsoleError> {
    let command_path = argv[0].as_ptr().cast::<u8>();
    let mut argv_ptrs: Vec<*const u8> = argv.iter().map(|c| c.as_ptr().cast::<u8>()).collect();
    argv_ptrs.push(std::ptr::null());

    let ws = Winsize {
        ws_row: request.rows,
        ws_col: request.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let mut master_fd: i32 = -1;
    let mut slave_fd: i32 = -1;

    // SAFETY: `master_fd`/`slave_fd` are live `i32` out-params openpty fills;
    // `name`/`termp` may be NULL (we want defaults), and `&ws` is a valid
    // `Winsize` read for the initial window size.
    let rc = unsafe {
        openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            &ws,
        )
    };
    if rc != 0 {
        return Err(ConsoleError::OpenPtyFailed);
    }

    // Assemble the child's environment block *before* forking. The guest
    // agent is multithreaded by the time it serves a ConsoleOpen request
    // (monitoring, probe, and integration threads are all
    // live), so the post-fork child may call only async-signal-safe
    // functions. `putenv`/`execvp` can `malloc` — if another thread held the
    // allocator lock at fork time the child would deadlock — so we build a
    // fixed `envp` here and hand it to `execve` (async-signal-safe) instead.
    let resolved = build_shell_env_with(&request.env);
    let shell_env = resolved.to_envp();
    let mut envp: Vec<*const u8> = shell_env.iter().map(|c| c.as_ptr().cast::<u8>()).collect();
    envp.push(std::ptr::null());
    // Same reason as `envp`: the child's `chdir` target has to be a NUL string
    // allocated before the fork. The resolver already picked it — the image's
    // own `WorkingDir` when it declares one, and otherwise the workload's
    // writable home rather than root's, which the workload uid can neither
    // write nor, on most images, read.
    let start_dir = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(resolved.working_dir().as_bytes())
            .unwrap_or_else(|_| c"/".to_owned())
    };
    // SAFETY: fork() takes no arguments and has no preconditions; it returns
    // twice (0 in the child, the child pid in the parent).
    let pid = unsafe { fork() };
    if pid < 0 {
        // SAFETY: both fds were just returned valid by openpty.
        unsafe {
            close(master_fd);
            close(slave_fd);
        }
        return Err(ConsoleError::ForkFailed);
    }

    if pid == 0 {
        // Child process — attach to the PTY slave and exec the shell. Only
        // async-signal-safe calls are permitted here (see the env note
        // above): close/setsid/dup2/chdir/execve all qualify; the prior
        // putenv/execvp path did not.
        //
        // SAFETY: `slave_fd`/`master_fd` are valid fds from openpty; dup2's
        // target fds 0/1/2 are always valid; `argv` and `envp` are
        // NUL-/NULL-terminated arrays whose backing storage was allocated in
        // the parent before the fork and is unmodified in the child's
        // copy-on-write image. `execve` replaces the process image and only
        // returns on error.
        unsafe {
            close(master_fd);
            setsid();
            set_controlling_tty(slave_fd);
            // Redirect stdin/stdout/stderr to the PTY slave.
            dup2(slave_fd, 0);
            dup2(slave_fd, 1);
            dup2(slave_fd, 2);
            if slave_fd > 2 {
                close(slave_fd);
            }

            // Start in $HOME.
            let _ = chdir(start_dir.as_ptr().cast());

            // Exec the prepared absolute command path. There is no PATH search
            // here because the post-fork child must avoid allocation.
            execve(command_path, argv_ptrs.as_ptr(), envp.as_ptr());

            libc::_exit(127);
        }
    }

    // SAFETY: `slave_fd` is the valid fd from openpty; the child has its own
    // copy, so closing the parent's does not affect it. `master_fd` is the
    // PTY master openpty returned, and this File becomes its only owner.
    let master = unsafe {
        close(slave_fd);
        File::from_raw_fd(master_fd)
    };
    Ok((pid, master))
}

/// Bind and listen on the vsock data port for one attach.
fn bind_data_listener(port: u32) -> Result<OwnedFd, ConsoleError> {
    // SAFETY: socket takes only integer arguments and returns a fd or -1.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(ConsoleError::BindFailed(port));
    }
    // SAFETY: `fd` is the socket just created and nothing else owns it.
    let listener = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_flags: 0,
        svm_zero: [0; 3],
    };
    // SAFETY: `listener` is an open socket; `addr` points to the live
    // `SockAddrVm` and the length matches its size.
    let bound = unsafe {
        bind(
            listener.as_raw_fd(),
            (&raw const addr).cast::<core::ffi::c_void>(),
            std::mem::size_of::<SockAddrVm>() as u32,
        )
    };
    // SAFETY: `listener` is the bound socket fd; listen takes no pointers.
    if bound != 0 || unsafe { listen(listener.as_raw_fd(), 1) } != 0 {
        return Err(ConsoleError::BindFailed(port));
    }
    Ok(listener)
}

/// Wait up to `timeout` for the host to dial `listener`, and accept it only if
/// it really is the host. A guest-local process must not be able to win the
/// race for this raw PTY channel after the authenticated control request
/// allocated it.
fn accept_host(listener: OwnedFd, timeout: Duration) -> std::io::Result<UnixStream> {
    let mut ready = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `ready` is one live pollfd and the count says one.
    let polled = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
    if polled == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
    }
    if polled < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut peer = SockAddrVm {
        svm_family: 0,
        svm_reserved1: 0,
        svm_port: 0,
        svm_cid: 0,
        svm_flags: 0,
        svm_zero: [0; 3],
    };
    let expected_peer_len =
        u32::try_from(std::mem::size_of::<SockAddrVm>()).expect("vsock address size fits u32");
    let mut peer_len = expected_peer_len;
    // SAFETY: `peer` is correctly sized for AF_VSOCK and `peer_len` bounds the
    // kernel write into it.
    let conn_fd = unsafe {
        accept(
            listener.as_raw_fd(),
            (&raw mut peer).cast::<core::ffi::c_void>(),
            &raw mut peer_len,
        )
    };
    // Closing the listener stops further connections on this port.
    drop(listener);
    if conn_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `conn_fd` is the connected socket accept just returned, owned by
    // nothing else.
    let conn = unsafe { OwnedFd::from_raw_fd(conn_fd) };
    let peer_known = peer_len >= expected_peer_len && peer.svm_family == AF_VSOCK as u16;
    if !peer_known || !console_peer_is_authorized(peer.svm_cid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "rejected non-host data peer (cid={}, family={})",
                peer.svm_cid, peer.svm_family
            ),
        ));
    }
    Ok(UnixStream::from(conn))
}

/// The vsock data stream as a [`ConsoleSink`].
struct StreamSink {
    stream: UnixStream,
}

impl StreamSink {
    fn new(conn: &UnixStream) -> std::io::Result<Self> {
        let stream = conn.try_clone()?;
        stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT))?;
        Ok(Self { stream })
    }
}

impl ConsoleSink for StreamSink {
    fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    fn hang_up(&mut self) {
        // Shutting down (rather than just dropping this clone) also wakes the
        // input thread blocked reading the same socket.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Serve one attach: take the host's connection, replay, then forward its
/// keystrokes to the shell until it goes away.
fn serve_attach(
    sessions: &'static Mutex<Registry>,
    ticket: AttachTicket,
    listener: OwnedFd,
    master: Option<Arc<File>>,
) {
    let conn = match accept_host(listener, ATTACH_ACCEPT_TIMEOUT) {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!(
                "console: attach {} to session {} on port {} failed: {error}",
                ticket.attach_id, ticket.session_id, ticket.data_port
            );
            lock(sessions).release(ticket.attach_id, Instant::now());
            return;
        }
    };
    let sink = match StreamSink::new(&conn).and_then(|sink| {
        configure_console_input(&conn)?;
        Ok(sink)
    }) {
        Ok(sink) => sink,
        Err(error) => {
            eprintln!("console: failed to configure the data stream: {error}");
            lock(sessions).release(ticket.attach_id, Instant::now());
            return;
        }
    };
    let outcome = lock(sessions).complete_attach(ticket.attach_id, Box::new(sink), Instant::now());
    eprintln!(
        "console: attach {} to session {}: {outcome:?}",
        ticket.attach_id, ticket.session_id
    );
    if outcome != AttachOutcome::Live {
        return;
    }
    if let Some(master) = master {
        forward_input(conn, &master);
    }
    // The client is gone; the shell is not.
    lock(sessions).release(ticket.attach_id, Instant::now());
}

/// Host keystrokes → shell, until the host stops sending.
fn forward_input(mut conn: UnixStream, master: &File) {
    let mut buf = [0u8; 4096];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
            Ok(n) => {
                let mut pty = master;
                if pty.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// Shell output → scrollback and the attached client, for the whole life of
/// the session, whether or not anyone is attached. Records the exit code when
/// the shell goes.
fn pump_output(sessions: &Mutex<Registry>, session_id: u32, child_pid: i32, master: &File) {
    let mut buf = [0u8; 4096];
    let mut idle_hangup_sent = false;
    let exit_code = loop {
        if pty_readable(master, PUMP_TICK) {
            let mut pty = master;
            match pty.read(&mut buf) {
                Ok(n) if n > 0 => {
                    lock(sessions).record_output(session_id, &buf[..n], Instant::now());
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                // EOF, or EIO once every holder of the slave side has closed
                // it: the terminal is gone, so the session is over.
                _ => break reap_after_hangup(child_pid),
            }
        }
        if !idle_hangup_sent && lock(sessions).expired_child(Instant::now()) == Some(child_pid) {
            eprintln!("console: session {session_id} passed its detach timeout; hanging up");
            signal_session(child_pid, Some(master), SIGHUP);
            idle_hangup_sent = true;
        }
        // The shell can exit while a background job still holds the terminal
        // open, so the pty never reports EOF; the exit is what ends a session.
        match crate::child_wait::try_wait_pid(child_pid) {
            Ok(None) => {}
            Ok(Some(raw)) => {
                drain_output(sessions, session_id, master, &mut buf);
                break decode_wait_status(raw);
            }
            Err(error) => {
                eprintln!("console: lost track of session {session_id}'s shell: {error}");
                drain_output(sessions, session_id, master, &mut buf);
                break -1;
            }
        }
    };
    lock(sessions).record_exit(session_id, exit_code);
    eprintln!("console: session {session_id} ended, exit code {exit_code}");
}

/// Collect whatever the shell wrote before it exited.
fn drain_output(sessions: &Mutex<Registry>, session_id: u32, master: &File, buf: &mut [u8]) {
    while pty_readable(master, Duration::ZERO) {
        let mut pty = master;
        match pty.read(buf) {
            Ok(n) if n > 0 => lock(sessions).record_output(session_id, &buf[..n], Instant::now()),
            _ => return,
        }
    }
}

fn pty_readable(master: &File, timeout: Duration) -> bool {
    let mut ready = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `ready` is one live pollfd and the count says one.
    let polled = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
    polled > 0 && ready.revents != 0
}

/// The terminal is gone: make sure the shell is too, then collect its status.
fn reap_after_hangup(child_pid: i32) -> i32 {
    let mut signalled = false;
    let deadline = Instant::now() + CLOSE_SETTLE_TIMEOUT;
    loop {
        match crate::child_wait::try_wait_pid(child_pid) {
            Ok(Some(raw)) => return decode_wait_status(raw),
            Ok(None) => {}
            Err(_) => return -1,
        }
        let signal = if !signalled {
            Some(SIGTERM)
        } else if Instant::now() >= deadline {
            Some(SIGKILL)
        } else {
            None
        };
        if let Some(signal) = signal {
            // SAFETY: `kill` takes no pointers; `child_pid` is this session's
            // shell, not yet reaped (the wait above just said so).
            unsafe {
                kill(child_pid, signal);
            }
            signalled = true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A raw `waitpid` status as a shell-style exit code.
fn decode_wait_status(status: i32) -> i32 {
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

/// Make `slave_fd` the controlling terminal of the calling session, so an
/// interactive shell can do job control (Ctrl-Z/fg/bg, Ctrl-C process-group
/// signaling). `setsid()` alone leaves the new session leader with no
/// controlling tty.
///
/// # Safety
/// Must run in the forked child after `setsid()`: `slave_fd` must be a valid
/// open PTY slave and the caller a fresh session leader with no controlling
/// terminal yet. Async-signal-safe (a single `ioctl`).
unsafe fn set_controlling_tty(slave_fd: i32) {
    // SAFETY: TIOCSCTTY takes an int arg; 0 = do not steal the tty from an
    // existing session. `slave_fd` is a live PTY slave fd.
    unsafe {
        ioctl(slave_fd, TIOCSCTTY, 0i32);
    }
}

/// Resize the PTY window.
pub fn resize_pty(master_fd: RawFd, cols: u16, rows: u16) {
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `master_fd` is a PTY master fd; TIOCSWINSZ reads one `Winsize`
    // through the `&ws` pointer, which is a live, aligned `Winsize`.
    unsafe {
        ioctl(master_fd, TIOCSWINSZ, &ws);
    }
}

fn configure_console_input(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(None)
}

/// Deliver `signal` to the session: its foreground job first, then the shell.
fn signal_session(child_pid: i32, master: Option<&File>, signal: i32) {
    // The interactive shell may have placed its current job in a distinct
    // foreground process group. Signal that group first, then the shell/session
    // leader itself. ESRCH is expected when either already exited.
    let foreground = master.map_or(-1, |master| {
        // SAFETY: `tcgetpgrp` takes a fd and no pointers; `master` is a live
        // PTY master borrowed for the duration of the call.
        unsafe { libc::tcgetpgrp(master.as_raw_fd()) }
    });
    for target in console_signal_targets(child_pid, foreground)
        .into_iter()
        .flatten()
    {
        // SAFETY: a negative target addresses the PTY foreground process group;
        // a positive target is the child created for this console session.
        unsafe {
            kill(target, signal);
        }
    }
}

fn console_signal_targets(child_pid: i32, foreground: i32) -> [Option<i32>; 2] {
    [
        (foreground > 0).then(|| -foreground),
        (foreground != child_pid).then_some(child_pid),
    ]
}

/// The console session's environment, resolved through the one shared
/// resolver so an interactive shell lands in exactly the environment the
/// image's own entrypoint would have run in.
fn build_shell_env_with(
    extra_env: &[(String, String)],
) -> crate::workload_env::WorkloadEnvironment {
    let image = crate::workload_env::ImageRuntimeConfig::load().unwrap_or_else(|error| {
        // A malformed config must not cost the operator their shell; it costs
        // them the image's declared vars, and says so.
        eprintln!("mvm-guest-agent: ignoring unreadable image runtime config: {error}");
        crate::workload_env::ImageRuntimeConfig::default()
    });
    build_shell_env_from(std::env::vars_os(), &image, extra_env)
}

fn build_console_argv(argv: &[String]) -> Result<Vec<std::ffi::CString>, ConsoleError> {
    let effective = if argv.is_empty() {
        vec!["/bin/sh".to_string(), "-i".to_string()]
    } else {
        argv.to_vec()
    };
    if effective[0].is_empty() {
        return Err(ConsoleError::InvalidCommand(
            "argv[0] must not be empty".to_string(),
        ));
    }
    if !effective[0].starts_with('/') {
        return Err(ConsoleError::InvalidCommand(format!(
            "argv[0] must be an absolute path, got {:?}",
            effective[0]
        )));
    }
    effective
        .into_iter()
        .map(|arg| {
            std::ffi::CString::new(arg).map_err(|_| {
                ConsoleError::InvalidCommand("argv must not contain NUL bytes".to_string())
            })
        })
        .collect()
}

/// Pure core of the shell environment builder, parameterized over the source
/// vars so it is testable without mutating process-global state.
fn build_shell_env_from<I>(
    vars: I,
    image: &crate::workload_env::ImageRuntimeConfig,
    extra_env: &[(String, String)],
) -> crate::workload_env::WorkloadEnvironment
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    crate::workload_env::WorkloadEnvironment::builder()
        .inherit(vars)
        .image(image)
        .overrides(
            extra_env
                .iter()
                .map(|(key, val)| (key.as_str(), val.as_str())),
        )
        .interactive()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Winsize`'s layout is pinned by the `const _` contract next to the
    // struct: a compile-time assertion that also covers alignment and every
    // field offset, and that holds for cross-compiled targets which never
    // run this host test suite. The runtime size check that used to live
    // here was strictly weaker and is gone.

    #[test]
    fn test_console_error_display() {
        assert_eq!(
            ConsoleError::AlreadyActive(2).to_string(),
            "console session 2 is already running; attach to it or close it first"
        );
        assert_eq!(ConsoleError::OpenPtyFailed.to_string(), "openpty() failed");
        assert_eq!(ConsoleError::ForkFailed.to_string(), "fork() failed");
        assert_eq!(
            ConsoleError::InvalidCommand("argv must not contain NUL bytes".to_string()).to_string(),
            "invalid console command: argv must not contain NUL bytes"
        );
        assert_eq!(
            ConsoleError::BindFailed(20001).to_string(),
            "failed to bind vsock port 20001"
        );
        assert_eq!(
            ConsoleError::from(AttachRefusal::Busy(4)).to_string(),
            "console session 4 already has an attached client"
        );
        assert_eq!(
            ConsoleError::from(AttachRefusal::NoSuchSession(9)).to_string(),
            "no console session 9"
        );
    }

    fn oss(s: &str) -> std::ffi::OsString {
        std::ffi::OsString::from(s)
    }

    fn no_image() -> crate::workload_env::ImageRuntimeConfig {
        crate::workload_env::ImageRuntimeConfig::default()
    }

    fn strings(env: &crate::workload_env::WorkloadEnvironment) -> Vec<String> {
        env.to_envp()
            .iter()
            .filter_map(|c| c.to_str().ok().map(str::to_string))
            .collect()
    }

    #[test]
    fn build_shell_env_overrides_home_and_term() {
        // Inherited HOME/TERM are dropped; the forced values are appended once.
        let out = build_shell_env_from(
            [
                (oss("HOME"), oss("/somewhere/else")),
                (oss("TERM"), oss("dumb")),
                (oss("PATH"), oss("/usr/bin")),
            ],
            &no_image(),
            &[],
        );
        let strs = strings(&out);
        assert!(
            strs.iter().any(|s| s == "PATH=/usr/bin"),
            "inherited PATH kept: {strs:?}"
        );
        assert_eq!(strs.iter().filter(|s| s.starts_with("HOME=")).count(), 1);
        assert_eq!(strs.iter().filter(|s| s.starts_with("TERM=")).count(), 1);
        let expected_home = format!("HOME={}", crate::guest_mount::workload_home());
        assert!(strs.contains(&expected_home), "{strs:?}");
        assert!(strs.iter().any(|s| s == "TERM=xterm-256color"), "{strs:?}");
        assert!(!strs.iter().any(|s| s == "HOME=/somewhere/else"));
    }

    #[test]
    fn build_shell_env_skips_interior_nul_vars() {
        use std::os::unix::ffi::OsStringExt;
        // A value with an embedded NUL can't cross the C ABI — it's dropped,
        // but the forced HOME/TERM still come through.
        let bad = std::ffi::OsString::from_vec(b"a\0b".to_vec());
        let out = build_shell_env_from([(oss("WEIRD"), bad)], &no_image(), &[]);
        let strs = strings(&out);
        assert!(!strs.iter().any(|s| s.starts_with("WEIRD=")), "{strs:?}");
        let expected_home = format!("HOME={}", crate::guest_mount::workload_home());
        assert!(strs.contains(&expected_home));
        assert!(strs.iter().any(|s| s == "TERM=xterm-256color"));
    }

    #[test]
    fn build_shell_env_adds_valid_extra_env() {
        let out = build_shell_env_from(
            [(oss("PATH"), oss("/usr/bin"))],
            &no_image(),
            &[("MVM_SESSION_TAG".to_string(), "abc123".to_string())],
        );
        assert!(strings(&out).iter().any(|s| s == "MVM_SESSION_TAG=abc123"));
    }

    /// The reported bug: `machine run --image rust:latest -it -- /bin/bash`
    /// landed in a shell where `which rustc` found nothing. `rust:latest`
    /// keeps its toolchain in `/usr/local/cargo/bin` and puts it on `PATH`
    /// through the image config alone, which the console never read.
    #[test]
    fn console_takes_path_from_the_image_over_the_agents_own() {
        let image = crate::workload_env::ImageRuntimeConfig {
            argv: vec!["bash".to_string()],
            env: vec![
                "PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin".to_string(),
                "CARGO_HOME=/usr/local/cargo".to_string(),
                "RUSTUP_HOME=/usr/local/rustup".to_string(),
            ],
            working_dir: None,
        };
        let out = build_shell_env_from([(oss("PATH"), oss("/usr/bin:/bin"))], &image, &[]);
        let strs = strings(&out);
        assert!(
            strs.iter()
                .any(|s| s == "PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin"),
            "image PATH must beat the agent's inherited one: {strs:?}"
        );
        assert_eq!(
            strs.iter().filter(|s| s.starts_with("PATH=")).count(),
            1,
            "a repeated PATH resolves to the first entry, so the override must \
             replace rather than append: {strs:?}"
        );
        assert!(strs.iter().any(|s| s == "CARGO_HOME=/usr/local/cargo"));
        assert!(strs.iter().any(|s| s == "RUSTUP_HOME=/usr/local/rustup"));
    }

    /// `--env` is the operator's correction, so it outranks the image.
    #[test]
    fn explicit_env_flags_outrank_the_image_declaration() {
        let image = crate::workload_env::ImageRuntimeConfig {
            argv: Vec::new(),
            env: vec!["NAME=from-image".to_string(), "PATH=/image/bin".to_string()],
            working_dir: None,
        };
        let out = build_shell_env_from(
            [(oss("NAME"), oss("from-agent"))],
            &image,
            &[("NAME".to_string(), "ari".to_string())],
        );
        let strs = strings(&out);
        assert!(strs.iter().any(|s| s == "NAME=ari"), "{strs:?}");
        assert_eq!(strs.iter().filter(|s| s.starts_with("NAME=")).count(), 1);
    }

    /// An image that declares a `WorkingDir` gets it, matching where its own
    /// entrypoint would have started.
    #[test]
    fn console_starts_in_the_images_working_dir_when_it_declares_one() {
        let image = crate::workload_env::ImageRuntimeConfig {
            argv: Vec::new(),
            env: Vec::new(),
            working_dir: Some("/usr/src/app".to_string()),
        };
        let out = build_shell_env_from(std::iter::empty(), &image, &[]);
        assert_eq!(out.working_dir(), std::ffi::OsStr::new("/usr/src/app"));

        // ...and falls back to the writable home when it declares none, which
        // is where an interactive session has always started.
        let out = build_shell_env_from(std::iter::empty(), &no_image(), &[]);
        assert_eq!(
            out.working_dir(),
            std::ffi::OsStr::new(crate::guest_mount::workload_home())
        );
    }

    /// A test registry with one running session whose shell is `child_pid`.
    fn registry_with_running_session(child_pid: i32) -> (&'static Mutex<Registry>, AttachTicket) {
        let sessions: &'static Mutex<Registry> = Box::leak(Box::new(Mutex::new(Registry::new(64))));
        let ticket = {
            let mut registry = lock(sessions);
            let (attach_id, _) = registry.allocate_attach();
            registry.insert(
                SpawnedSession {
                    child_pid,
                    master: None,
                    command: "/bin/sh".to_string(),
                    detach_timeout: None,
                },
                attach_id,
            )
        };
        (sessions, ticket)
    }

    /// A close that arrives after the shell exited answers from the record and
    /// signals nothing — the pid may already belong to someone else.
    #[test]
    fn closing_an_exited_session_returns_its_recorded_code() {
        let (sessions, AttachTicket { session_id: id, .. }) = registry_with_running_session(-1);
        lock(sessions).record_exit(id, 42);
        assert_eq!(
            terminate_session_in(sessions, id, Duration::from_millis(10)).unwrap(),
            42
        );
    }

    /// The close waits for the pump to record the exit its signal caused.
    #[test]
    fn close_waits_for_the_exit_to_be_recorded() {
        // A pid that cannot exist: the signals land nowhere, and the exit is
        // recorded by this thread standing in for the pump.
        let (sessions, AttachTicket { session_id: id, .. }) =
            registry_with_running_session(i32::MAX);
        let pump = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            lock(sessions).record_exit(id, 129);
        });
        let result = terminate_session_in(sessions, id, Duration::from_secs(5));
        pump.join().expect("stand-in pump");
        assert_eq!(result.unwrap(), 129);
    }

    /// A session that never goes is reported, not waited on forever.
    #[test]
    fn close_reports_a_session_that_never_terminates() {
        let (sessions, AttachTicket { session_id: id, .. }) =
            registry_with_running_session(i32::MAX);
        assert!(matches!(
            terminate_session_in(sessions, id, Duration::from_millis(20)),
            Err(ConsoleError::DidNotTerminate(got)) if got == id
        ));
    }

    #[test]
    fn closing_an_unknown_session_is_refused() {
        let (sessions, AttachTicket { session_id: id, .. }) =
            registry_with_running_session(i32::MAX);
        assert!(matches!(
            terminate_session_in(sessions, id + 1, Duration::from_millis(10)),
            Err(ConsoleError::NoSuchSession(_))
        ));
    }

    #[test]
    fn wait_statuses_decode_to_shell_exit_codes() {
        assert_eq!(decode_wait_status(3 << 8), 3);
        assert_eq!(decode_wait_status(0), 0);
        assert_eq!(decode_wait_status(SIGHUP), 128 + SIGHUP);
        assert_eq!(decode_wait_status(SIGKILL), 128 + SIGKILL);
    }

    #[test]
    fn build_console_argv_defaults_to_interactive_shell() {
        let argv = build_console_argv(&[]).expect("default shell argv");
        let got: Vec<&str> = argv.iter().filter_map(|c| c.to_str().ok()).collect();
        assert_eq!(got, ["/bin/sh", "-i"]);
    }

    #[test]
    fn build_console_argv_accepts_absolute_explicit_command() {
        let argv = build_console_argv(&["/bin/sh".to_string()]).expect("explicit shell argv");
        let got: Vec<&str> = argv.iter().filter_map(|c| c.to_str().ok()).collect();
        assert_eq!(got, ["/bin/sh"]);
    }

    #[test]
    fn build_console_argv_rejects_relative_command() {
        let err = build_console_argv(&["sh".to_string()]).expect_err("relative command is unsafe");
        assert!(
            err.to_string().contains("absolute path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_session_rejects_invalid_argv_before_reserving_anything() {
        let sessions: &'static Mutex<Registry> = Box::leak(Box::new(Mutex::new(Registry::new(64))));
        let request = OpenRequest {
            argv: vec!["sh".to_string()],
            ..OpenRequest::default()
        };
        let err = open_session_in(sessions, &request)
            .expect_err("relative command should be rejected before PTY allocation");
        assert!(
            err.to_string().contains("absolute path"),
            "unexpected error: {err}"
        );
        let mut registry = lock(sessions);
        assert!(registry.summaries(Instant::now()).is_empty());
        assert_eq!(
            registry.allocate_attach().0,
            1,
            "a refused open must not consume a data port"
        );
    }

    #[test]
    fn test_data_port_calculation() {
        assert_eq!(crate::vsock::CONSOLE_PORT_BASE + 1, 20001);
        assert_eq!(crate::vsock::CONSOLE_PORT_BASE + 42, 20042);
    }

    #[test]
    fn console_data_peer_authorizes_only_the_host_cid() {
        assert!(console_peer_is_authorized(crate::vsock::HOST_CID));
        for cid in [0, 1, crate::vsock::GUEST_CID, VMADDR_CID_ANY] {
            assert!(
                !console_peer_is_authorized(cid),
                "CID {cid} must be rejected"
            );
        }
    }

    // This exercises Linux guest controlling-terminal semantics. macOS host
    // test sandboxes do not consistently permit a forked child to acquire a
    // controlling tty, while the guest runtime is Linux-only.
    #[cfg(target_os = "linux")]
    #[test]
    fn child_acquires_controlling_tty() {
        let ws = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: i32 = -1;
        let mut slave_fd: i32 = -1;
        // SAFETY: out-params are live i32s; name/termp NULL = defaults.
        let rc = unsafe {
            openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &ws,
            )
        };
        assert_eq!(rc, 0, "openpty failed");

        // SAFETY: fork has no preconditions; returns 0 in child.
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: become a session leader, claim the slave as our
            // controlling terminal, then prove it by opening /dev/tty
            // (only a process WITH a controlling tty can). Async-signal-safe
            // calls only: setsid/ioctl/open/_exit.
            // SAFETY: slave_fd is a valid PTY slave; we are post-fork.
            unsafe {
                setsid();
                set_controlling_tty(slave_fd);
                let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR);
                libc::_exit(if fd >= 0 { 0 } else { 1 });
            }
        }

        // SAFETY: slave_fd valid; the child holds its own copy.
        unsafe {
            close(slave_fd);
        }
        let mut status: i32 = 0;
        // SAFETY: pid is the just-forked child; status is a live i32.
        unsafe {
            waitpid(pid, &mut status, 0);
            close(master_fd);
        }
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child could not open /dev/tty — no controlling terminal acquired"
        );
    }

    #[test]
    fn console_input_has_no_one_way_idle_timeout() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(1)))
            .expect("install test timeout");

        configure_console_input(&stream).expect("configure console input");

        assert_eq!(
            stream.read_timeout().expect("read timeout"),
            None,
            "guest output may keep a console useful indefinitely, so host input must not expire"
        );
    }

    #[test]
    fn console_disconnect_targets_the_foreground_job_and_session_leader() {
        assert_eq!(
            console_signal_targets(42, 77),
            [Some(-77), Some(42)],
            "an interactive foreground job may be in a different process group"
        );
        assert_eq!(
            console_signal_targets(42, 42),
            [Some(-42), None],
            "the process group signal already includes its leader"
        );
        assert_eq!(
            console_signal_targets(42, -1),
            [None, Some(42)],
            "fall back to the session child when the PTY has no foreground group"
        );
    }

    /// End to end on a real PTY: output written while nobody is attached is
    /// kept, the exit is recorded, and a client attaching afterwards receives
    /// the whole transcript and then a clean end.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_session_nobody_attached_to_keeps_its_output_and_exit_code() {
        #[derive(Clone, Default)]
        struct Collect(Arc<Mutex<(Vec<u8>, bool)>>);
        impl ConsoleSink for Collect {
            fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
                self.0.lock().unwrap().0.extend_from_slice(bytes);
                Ok(())
            }
            fn hang_up(&mut self) {
                self.0.lock().unwrap().1 = true;
            }
        }

        let request = OpenRequest {
            cols: 80,
            rows: 24,
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'while-detached'; exit 3".to_string(),
            ],
            ..OpenRequest::default()
        };
        let argv = build_console_argv(&request.argv).expect("argv");
        let (child_pid, master) = spawn_shell(&request, &argv).expect("spawn shell on a pty");
        let (sessions, ticket) = registry_with_running_session(child_pid);
        let id = ticket.session_id;

        pump_output(sessions, id, child_pid, &master);

        // The first attach's reservation was taken at open; its client is only
        // now connecting, after the shell has already gone.
        let client = Collect::default();
        let mut registry = lock(sessions);
        assert_eq!(registry.exit_code(id), Some(3));
        assert_eq!(
            registry.complete_attach(ticket.attach_id, Box::new(client.clone()), Instant::now()),
            AttachOutcome::Ended
        );
        let (received, hung_up) = client.0.lock().unwrap().clone();
        assert!(
            String::from_utf8_lossy(&received).contains("while-detached"),
            "replay: {received:?}"
        );
        assert!(hung_up);
    }
}
