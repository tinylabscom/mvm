//! PTY-over-vsock console for interactive guest access.
//!
//! The guest agent allocates a PTY, forks a shell, and relays I/O over a
//! dedicated vsock data port. The host connects to the data port for raw
//! byte streaming — no JSON framing, no Ed25519 signing on the data channel.
//!
//! Security: Console sessions are dev-mode only and authenticated via the
//! control channel (the `ConsoleOpen` request goes through the normal
//! authenticated vsock protocol).

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::vsock::{CONSOLE_PORT_BASE, HOST_CID};

/// Tracks the active console session. Only one session at a time.
static CONSOLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CONSOLE_SESSION_ID: AtomicU32 = AtomicU32::new(0);
static COMPLETED_SESSION_ID: AtomicU32 = AtomicU32::new(0);
static COMPLETED_EXIT_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// Active PTY master fd for resize support. -1 when no session is active.
static CONSOLE_MASTER_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
/// Active session's shell pid, so an explicit close can end it. -1 when idle.
static CONSOLE_CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// How long an explicit close waits for the session to finish winding down.
///
/// The host sends `ConsoleClose` the instant its relay sees EOF, which the
/// guest produces *before* it reaps the shell and joins its relay threads — so
/// the request routinely arrives while the session is still tearing itself
/// down. Waiting is what turns that race into the exit code the host asked for.
pub const CLOSE_SETTLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Result of opening a console session.
pub struct ConsoleSession {
    pub session_id: u32,
    pub data_port: u32,
    pub master_fd: RawFd,
    pub child_pid: i32,
}

/// Errors from console operations.
#[derive(Debug)]
pub enum ConsoleError {
    AlreadyActive,
    InvalidCommand(String),
    OpenPtyFailed,
    ForkFailed,
    BindFailed(u32),
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyActive => write!(f, "a console session is already active"),
            Self::InvalidCommand(message) => write!(f, "invalid console command: {message}"),
            Self::OpenPtyFailed => write!(f, "openpty() failed"),
            Self::ForkFailed => write!(f, "fork() failed"),
            Self::BindFailed(port) => write!(f, "failed to bind vsock port {port}"),
        }
    }
}

impl std::error::Error for ConsoleError {}

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
const SIGTERM: i32 = 15;
/// Sent to an interactive shell on explicit close: a hangup is what a terminal
/// going away looks like, so job-control shells clean up their children.
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

/// Open a PTY console session.
///
/// Allocates a PTY pair, forks a shell process attached to the slave,
/// and returns the master fd + session info. The caller is responsible
/// for starting the vsock data relay.
pub fn open_session(
    cols: u16,
    rows: u16,
    extra_env: &[(String, String)],
    argv: &[String],
) -> Result<ConsoleSession, ConsoleError> {
    let command_argv = build_console_argv(argv)?;
    let command_path = command_argv[0].as_ptr().cast::<u8>();
    let mut command_argv_ptrs: Vec<*const u8> = command_argv
        .iter()
        .map(|c| c.as_ptr().cast::<u8>())
        .collect();
    command_argv_ptrs.push(std::ptr::null());

    // Only one session at a time
    if CONSOLE_ACTIVE.swap(true, Ordering::SeqCst) {
        return Err(ConsoleError::AlreadyActive);
    }

    let session_id = CONSOLE_SESSION_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let data_port = CONSOLE_PORT_BASE + session_id;
    COMPLETED_SESSION_ID.store(0, Ordering::SeqCst);
    COMPLETED_EXIT_CODE.store(0, Ordering::SeqCst);

    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
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
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        return Err(ConsoleError::OpenPtyFailed);
    }

    // Assemble the child's environment block *before* forking. The guest
    // agent is multithreaded by the time it serves a ConsoleOpen request
    // (monitoring, probe, integration, and forward-proxy threads are all
    // live), so the post-fork child may call only async-signal-safe
    // functions. `putenv`/`execvp` can `malloc` — if another thread held the
    // allocator lock at fork time the child would deadlock — so we build a
    // fixed `envp` here and hand it to `execve` (async-signal-safe) instead.
    let resolved = build_shell_env_with(extra_env);
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
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
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
            execve(command_path, command_argv_ptrs.as_ptr(), envp.as_ptr());

            std::process::exit(127);
        }
    }

    // Parent — close slave fd, store master fd for resize.
    // SAFETY: `slave_fd` is the valid fd from openpty; the child has its own
    // copy, so closing the parent's does not affect it.
    unsafe {
        close(slave_fd);
    }
    CONSOLE_MASTER_FD.store(master_fd, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_CHILD_PID.store(pid, std::sync::atomic::Ordering::SeqCst);

    Ok(ConsoleSession {
        session_id,
        data_port,
        master_fd,
        child_pid: pid,
    })
}

/// Resize the active console session's PTY window.
///
/// Called from the guest agent when it receives a `ConsoleResize` request.
/// Uses the globally tracked master fd.
pub fn resize_active_session(cols: u16, rows: u16) -> bool {
    let fd = CONSOLE_MASTER_FD.load(std::sync::atomic::Ordering::SeqCst);
    if fd < 0 {
        return false;
    }
    resize_pty(fd, cols, rows);
    true
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

/// Close a console session — kill the shell and clean up.
pub fn close_session(session: &ConsoleSession) -> i32 {
    // Kill the shell process.
    // SAFETY: `child_pid` is the pid open_session forked; kill takes no
    // pointers. A stale pid at worst returns ESRCH, which we ignore.
    unsafe {
        kill(session.child_pid, SIGTERM);
    }

    // Wait for it to exit.
    let mut status: i32 = 0;
    // SAFETY: `status` is a live `i32` out-param waitpid writes the exit
    // status into; `child_pid` is the forked child.
    let _ = unsafe { waitpid(session.child_pid, &mut status, 0) };

    // Close the master fd.
    // SAFETY: `master_fd` is the PTY master openpty returned and that no
    // owning `File` has taken over in this path.
    unsafe {
        close(session.master_fd);
    }

    // Extract exit code
    let exit_code = if status & 0x7f == 0 {
        (status >> 8) & 0xff // normal exit
    } else {
        128 + (status & 0x7f) // signal
    };
    // Recorded before the active flag clears, for the reason given in
    // `run_console_relay`'s teardown.
    record_completed_session(session.session_id, exit_code);
    CONSOLE_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_CHILD_PID.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
    exit_code
}

/// Start the vsock data relay for a console session.
///
/// Binds a vsock listener on `session.data_port`, accepts one connection,
/// and relays raw bytes between the vsock socket and the PTY master fd.
/// Blocks until the session ends (shell exits or connection drops).
///
/// Returns the shell exit code.
pub fn run_console_relay(session: &ConsoleSession) -> i32 {
    // Bind vsock listener on data_port.
    // SAFETY: socket takes only integer arguments and returns a fd or -1.
    let listen_fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if listen_fd < 0 {
        eprintln!("console: failed to create vsock socket");
        return close_session(session);
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: session.data_port,
        svm_cid: VMADDR_CID_ANY,
        svm_flags: 0,
        svm_zero: [0; 3],
    };

    // SAFETY: `listen_fd` is the socket just created; `addr` points to the
    // live `SockAddrVm` and the length matches its size.
    let rc = unsafe {
        bind(
            listen_fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            std::mem::size_of::<SockAddrVm>() as u32,
        )
    };
    if rc != 0 {
        eprintln!("console: failed to bind vsock port {}", session.data_port);
        // SAFETY: `listen_fd` is the open socket; no owning wrapper holds it.
        unsafe {
            close(listen_fd);
        }
        return close_session(session);
    }

    // SAFETY: `listen_fd` is the bound socket fd; listen takes no pointers.
    if unsafe { listen(listen_fd, 1) } != 0 {
        eprintln!(
            "console: failed to listen on vsock port {}",
            session.data_port
        );
        // SAFETY: `listen_fd` is the open socket; no owning wrapper holds it.
        unsafe {
            close(listen_fd);
        }
        return close_session(session);
    }

    eprintln!(
        "console: waiting for host connection on vsock port {}",
        session.data_port
    );

    // Accept one host connection and capture its CID. A guest-local process
    // must not be able to win the race for this raw PTY channel after the
    // authenticated control request allocates it.
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
            listen_fd,
            (&raw mut peer).cast::<core::ffi::c_void>(),
            &raw mut peer_len,
        )
    };
    // SAFETY: `listen_fd` is the open listening socket; no owning wrapper
    // holds it. Closing it stops further connections.
    unsafe {
        close(listen_fd);
    }
    if conn_fd < 0 {
        eprintln!("console: accept failed");
        return close_session(session);
    }
    let peer_known = peer_len >= expected_peer_len && peer.svm_family == AF_VSOCK as u16;
    if !peer_known || !console_peer_is_authorized(peer.svm_cid) {
        eprintln!(
            "console: rejected non-host data peer (cid={}, family={})",
            peer.svm_cid, peer.svm_family
        );
        // SAFETY: `conn_fd` is the accepted socket and no owner wraps it yet.
        unsafe {
            close(conn_fd);
        }
        return close_session(session);
    }

    eprintln!("console: host connected, starting PTY relay");

    // Relay: PTY master ↔ vsock connection using raw byte I/O
    // Two threads: vsock→pty and pty→vsock
    let master_fd = session.master_fd;
    let child_pid = session.child_pid;

    // SAFETY: `conn_fd` is the connected socket accept just returned; we
    // transfer sole ownership of it to this UnixStream.
    let mut vsock_read = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_fd as RawFd) };
    let Ok(mut vsock_write) = vsock_read.try_clone() else {
        eprintln!("console: failed to clone vsock stream");
        return close_session(session);
    };

    // Output-only programs remain interactive: a lack of keyboard input must
    // never silently retire the only thread capable of forwarding Ctrl-C.
    if let Err(error) = configure_console_input(&vsock_read) {
        eprintln!("console: failed to configure input stream: {error}");
        return close_session(session);
    }

    // SAFETY: `master_fd` is the PTY master from openpty; we transfer sole
    // ownership of it to this File.
    let mut pty_read = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let Ok(mut pty_write) = pty_read.try_clone() else {
        eprintln!("console: failed to clone PTY fd");
        std::mem::forget(pty_read);
        return close_session(session);
    };

    // vsock → PTY (host input → shell)
    let h1 = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match vsock_read.read(&mut buf) {
                Ok(0) => break,
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
                Ok(n) => {
                    if pty_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }

        // A host disconnect or local escape ends the console session. Terminate
        // the PTY foreground process group so the output pump cannot remain
        // blocked forever on a command such as `top`.
        terminate_console_processes(child_pid, pty_write.as_raw_fd());
        // SAFETY: `conn_fd` is the socket underlying `vsock_read`; shutdown
        // wakes the cloned writer without taking ownership from either thread.
        unsafe {
            shutdown(conn_fd, SHUT_RDWR);
        }
    });

    // PTY → vsock (shell output → host)
    let h2 = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if vsock_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = vsock_write.flush();
                }
            }
        }
    });

    // Wait for PTY output to end (shell exited), then shut down the vsock
    // so the host sees EOF and h1 stops waiting for input.
    let _ = h2.join();
    // SAFETY: `conn_fd` is still open — the UnixStream that owns it lives in
    // the `h1` thread, which has not yet returned. shutdown only wakes its
    // blocked read; closing remains the stream's job on drop.
    unsafe {
        shutdown(conn_fd, SHUT_RDWR);
    }
    let _ = h1.join();

    // Wait for child and get exit code.
    let mut status: i32 = 0;
    // SAFETY: `child_pid` is the forked shell; `status` is a live `i32`
    // out-param waitpid writes into. kill takes no pointers.
    unsafe {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, &mut status, 0);
    }

    // Don't call close_session — we already waited and the fds are owned
    // by the File/UnixStream objects which will drop.
    let exit_code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    };
    // Record before clearing the active flag, never after: a close waiting on
    // that flag would otherwise read the previous session's exit code.
    record_completed_session(session.session_id, exit_code);
    CONSOLE_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_CHILD_PID.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
    exit_code
}

fn configure_console_input(stream: &std::os::unix::net::UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(None)
}

fn terminate_console_processes(child_pid: i32, pty_fd: RawFd) {
    // The interactive shell may have placed its current job in a distinct
    // foreground process group. Signal that group first, then the shell/session
    // leader itself. ESRCH is expected when either already exited.
    let foreground = unsafe { libc::tcgetpgrp(pty_fd) };
    for target in console_signal_targets(child_pid, foreground)
        .into_iter()
        .flatten()
    {
        // SAFETY: a negative target addresses the PTY foreground process group;
        // a positive target is the child created for this console session.
        unsafe {
            kill(target, SIGTERM);
        }
    }
}

fn console_signal_targets(child_pid: i32, foreground: i32) -> [Option<i32>; 2] {
    [
        (foreground > 0).then(|| -foreground),
        (foreground != child_pid).then_some(child_pid),
    ]
}

/// Check if a console session is currently active.
pub fn is_active() -> bool {
    CONSOLE_ACTIVE.load(Ordering::SeqCst)
}

/// Block until no session is active, or `timeout` elapses. Returns whether the
/// session settled.
fn wait_until_idle(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while is_active() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    true
}

/// End the active console session and return the shell's exit code.
///
/// Two callers arrive here and both must be served. The common one is a host
/// that already saw its relay EOF and only wants the exit code — its session is
/// mid-teardown, so the first wait is all it needs. The other is a host that
/// wants a still-running session gone, which takes a `SIGHUP` to the shell:
/// that closes the PTY, ends the relay, and the same teardown path records the
/// exit code.
///
/// Returns `None` only if the session outlives both waits (`timeout` each),
/// which means the relay is wedged rather than merely slow.
pub fn close_active_session(timeout: std::time::Duration) -> Option<i32> {
    if !wait_until_idle(timeout) {
        let pid = CONSOLE_CHILD_PID.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: `kill` takes no pointers. `pid` is the shell forked by
            // `open_session`; if it has already been reaped this returns ESRCH,
            // which is exactly the case the wait below then observes.
            unsafe {
                kill(pid, SIGHUP);
            }
        }
        if !wait_until_idle(timeout) {
            return None;
        }
    }
    Some(COMPLETED_EXIT_CODE.load(Ordering::SeqCst))
}

fn record_completed_session(session_id: u32, exit_code: i32) {
    COMPLETED_EXIT_CODE.store(exit_code, Ordering::SeqCst);
    COMPLETED_SESSION_ID.store(session_id, Ordering::SeqCst);
}

pub fn completed_exit_code(session_id: u32) -> Option<i32> {
    if COMPLETED_SESSION_ID.load(Ordering::SeqCst) == session_id {
        Some(COMPLETED_EXIT_CODE.load(Ordering::SeqCst))
    } else {
        None
    }
}

// FFI for chdir / shutdown
unsafe extern "C" {
    fn chdir(path: *const u8) -> i32;
    fn shutdown(sockfd: i32, how: i32) -> i32;
}

const SHUT_RDWR: i32 = 2;

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

    static CONSOLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn console_test_lock() -> std::sync::MutexGuard<'static, ()> {
        CONSOLE_TEST_LOCK
            .lock()
            .expect("console-test mutex not poisoned")
    }

    // `Winsize`'s layout is pinned by the `const _` contract next to the
    // struct: a compile-time assertion that also covers alignment and every
    // field offset, and that holds for cross-compiled targets which never
    // run this host test suite. The runtime size check that used to live
    // here was strictly weaker and is gone.

    #[test]
    fn test_console_error_display() {
        assert_eq!(
            ConsoleError::AlreadyActive.to_string(),
            "a console session is already active"
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

    /// The reported bug: `mvmctl machine run -it` printed
    /// "explicit close not yet supported" on every clean logout. The host
    /// sends its close as soon as the relay EOFs, which the guest emits
    /// before it reaps the shell — so the close lands on a session that is
    /// still active and must wait for it, not refuse it.
    #[test]
    fn close_waits_out_a_session_that_is_still_tearing_down() {
        let _guard = console_test_lock();
        CONSOLE_ACTIVE.store(true, Ordering::SeqCst);
        let completion = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(120));
            record_completed_session(7, 42);
            CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        });

        let result = close_active_session(std::time::Duration::from_secs(5));
        completion.join().expect("completion thread");
        assert_eq!(result, Some(42));
    }

    /// A wedged relay is the one case that still fails, and it fails as a
    /// refusal rather than by blocking the agent forever.
    #[test]
    fn close_reports_a_session_that_never_terminates() {
        let _guard = console_test_lock();
        CONSOLE_ACTIVE.store(true, Ordering::SeqCst);
        // No shell pid is recorded, so the SIGHUP escalation has nothing to
        // signal and both waits lapse.
        CONSOLE_CHILD_PID.store(-1, Ordering::SeqCst);

        assert_eq!(
            close_active_session(std::time::Duration::from_millis(50)),
            None
        );

        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
    }

    /// An idle agent answers immediately from the recorded exit code.
    #[test]
    fn close_returns_the_recorded_code_when_no_session_is_active() {
        let _guard = console_test_lock();
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        record_completed_session(3, 130);

        assert_eq!(close_active_session(CLOSE_SETTLE_TIMEOUT), Some(130));
        assert_eq!(completed_exit_code(3), Some(130));
        assert_eq!(
            completed_exit_code(4),
            None,
            "other sessions must not match"
        );
    }

    /// The exit code has to be on record before the active flag clears, or a
    /// close released by that flag reads whatever the previous session left.
    #[test]
    fn the_exit_code_is_recorded_before_the_active_flag_clears() {
        let _guard = console_test_lock();
        record_completed_session(1, 9);
        CONSOLE_ACTIVE.store(true, Ordering::SeqCst);
        let observer = std::thread::spawn(|| {
            while is_active() {
                std::hint::spin_loop();
            }
            COMPLETED_EXIT_CODE.load(Ordering::SeqCst)
        });

        record_completed_session(2, 55);
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);

        assert_eq!(observer.join().unwrap(), 55);
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
    fn open_session_rejects_invalid_argv_before_marking_active() {
        let _guard = console_test_lock();
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        let err = match open_session(80, 24, &[], &["sh".to_string()]) {
            Ok(_) => panic!("relative command should be rejected before PTY allocation"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("absolute path"),
            "unexpected error: {err}"
        );
        assert!(
            !is_active(),
            "invalid argv must not leave the console marked active"
        );
    }

    #[test]
    fn test_data_port_calculation() {
        assert_eq!(CONSOLE_PORT_BASE + 1, 20001);
        assert_eq!(CONSOLE_PORT_BASE + 42, 20042);
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

    #[test]
    fn test_is_active_default() {
        let _guard = console_test_lock();
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        assert!(!is_active());
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
}
