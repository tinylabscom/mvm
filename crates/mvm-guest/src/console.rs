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
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::vsock::CONSOLE_PORT_BASE;

/// Tracks the active console session. Only one session at a time.
static CONSOLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CONSOLE_SESSION_ID: AtomicU32 = AtomicU32::new(0);
/// Active PTY master fd for resize support. -1 when no session is active.
static CONSOLE_MASTER_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

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
    OpenPtyFailed,
    ForkFailed,
    BindFailed(u32),
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyActive => write!(f, "a console session is already active"),
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
    svm_zero: [u8; 4],
}

/// Terminal window size (matches struct winsize in sys/ioctl.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

/// Open a PTY console session.
///
/// Allocates a PTY pair, forks a shell process attached to the slave,
/// and returns the master fd + session info. The caller is responsible
/// for starting the vsock data relay.
pub fn open_session(
    cols: u16,
    rows: u16,
    extra_env: &[(String, String)],
) -> Result<ConsoleSession, ConsoleError> {
    // Only one session at a time
    if CONSOLE_ACTIVE.swap(true, Ordering::SeqCst) {
        return Err(ConsoleError::AlreadyActive);
    }

    let session_id = CONSOLE_SESSION_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let data_port = CONSOLE_PORT_BASE + session_id;

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
    let shell_env = build_shell_env_with(extra_env);
    let mut envp: Vec<*const u8> = shell_env.iter().map(|c| c.as_ptr().cast::<u8>()).collect();
    envp.push(std::ptr::null());

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
        // NUL-/NULL-terminated arrays whose backing storage (`shell_env`,
        // the byte literals) was allocated in the parent before the fork and
        // is unmodified in the child's copy-on-write image. `execve` replaces
        // the process image and only returns on error.
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
            let _ = chdir(c"/root".as_ptr().cast());

            // Exec /bin/sh with the prepared environment. The path is
            // absolute, so there is no PATH search (and thus no execvp
            // allocation) to perform.
            let shell = b"/bin/sh\0";
            let dash_i = b"-i\0";
            let argv: [*const u8; 3] = [shell.as_ptr(), dash_i.as_ptr(), std::ptr::null()];
            execve(shell.as_ptr(), argv.as_ptr(), envp.as_ptr());

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

    CONSOLE_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_ACTIVE.store(false, Ordering::SeqCst);

    // Extract exit code
    if status & 0x7f == 0 {
        (status >> 8) & 0xff // normal exit
    } else {
        128 + (status & 0x7f) // signal
    }
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
        svm_zero: [0; 4],
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

    // Accept one connection.
    // SAFETY: `listen_fd` is the listening socket; NULL addr/len out-params
    // are allowed when the peer address is not needed.
    let conn_fd = unsafe { accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    // SAFETY: `listen_fd` is the open listening socket; no owning wrapper
    // holds it. Closing it stops further connections.
    unsafe {
        close(listen_fd);
    }
    if conn_fd < 0 {
        eprintln!("console: accept failed");
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

    // Set read timeout for idle detection (15 minutes)
    let idle_timeout = std::time::Duration::from_secs(15 * 60);
    let _ = vsock_read.set_read_timeout(Some(idle_timeout));

    // SAFETY: `master_fd` is the PTY master from openpty; we transfer sole
    // ownership of it to this File.
    let mut pty_read = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let Ok(mut pty_write) = pty_read.try_clone() else {
        eprintln!("console: failed to clone PTY fd");
        std::mem::forget(pty_read);
        return close_session(session);
    };

    let done = std::sync::Arc::new(AtomicBool::new(false));
    let done2 = done.clone();

    // vsock → PTY (host input → shell)
    // Idle timeout: if no input for 15 minutes, the read times out and we close.
    let h1 = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match vsock_read.read(&mut buf) {
                Ok(0) => {
                    done2.store(true, Ordering::SeqCst);
                    break;
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    eprintln!("console: idle timeout reached, closing session");
                    done2.store(true, Ordering::SeqCst);
                    break;
                }
                Err(_) => {
                    done2.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(n) => {
                    if pty_write.write_all(&buf[..n]).is_err() {
                        done2.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
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

    CONSOLE_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    CONSOLE_ACTIVE.store(false, Ordering::SeqCst);

    // Don't call close_session — we already waited and the fds are owned
    // by the File/UnixStream objects which will drop.
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

/// Check if a console session is currently active.
pub fn is_active() -> bool {
    CONSOLE_ACTIVE.load(Ordering::SeqCst)
}

// FFI for chdir / shutdown
unsafe extern "C" {
    fn chdir(path: *const u8) -> i32;
    fn shutdown(sockfd: i32, how: i32) -> i32;
}

const SHUT_RDWR: i32 = 2;

/// Build the shell's environment block as owned NUL-terminated C strings,
/// inheriting the agent's current environment but overriding `HOME` and
/// `TERM`. Constructed in the parent before `fork()` so the post-fork child
/// can `execve` a fixed array without any allocation (see the async-signal
/// safety note in `open_session`).
fn build_shell_env() -> Vec<std::ffi::CString> {
    build_shell_env_with(&[])
}

fn build_shell_env_with(extra_env: &[(String, String)]) -> Vec<std::ffi::CString> {
    build_shell_env_from(std::env::vars_os(), extra_env)
}

/// Pure core of [`build_shell_env`], parameterized over the source vars so it
/// is testable without mutating process-global state.
fn build_shell_env_from<I>(vars: I, extra_env: &[(String, String)]) -> Vec<std::ffi::CString>
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    use std::os::unix::ffi::OsStrExt;
    let mut env: Vec<std::ffi::CString> = Vec::new();
    for (key, val) in vars {
        // HOME/TERM are forced below; drop any inherited copy so the shell
        // sees exactly one of each.
        if key == "HOME" || key == "TERM" {
            continue;
        }
        let mut kv = key.as_bytes().to_vec();
        kv.push(b'=');
        kv.extend_from_slice(val.as_bytes());
        // Skip any var carrying an interior NUL — it can't cross the C ABI.
        if let Ok(c) = std::ffi::CString::new(kv) {
            env.push(c);
        }
    }
    for (key, val) in extra_env {
        if key.contains('\0') || key.contains('=') || val.contains('\0') {
            continue;
        }
        if let Ok(c) = std::ffi::CString::new(format!("{key}={val}")) {
            env.push(c);
        }
    }
    env.push(std::ffi::CString::new("HOME=/root").expect("no interior NUL"));
    env.push(std::ffi::CString::new("TERM=xterm-256color").expect("no interior NUL"));
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winsize_layout() {
        assert_eq!(std::mem::size_of::<Winsize>(), 8);
    }

    #[test]
    fn test_console_error_display() {
        assert_eq!(
            ConsoleError::AlreadyActive.to_string(),
            "a console session is already active"
        );
        assert_eq!(ConsoleError::OpenPtyFailed.to_string(), "openpty() failed");
        assert_eq!(ConsoleError::ForkFailed.to_string(), "fork() failed");
        assert_eq!(
            ConsoleError::BindFailed(20001).to_string(),
            "failed to bind vsock port 20001"
        );
    }

    fn oss(s: &str) -> std::ffi::OsString {
        std::ffi::OsString::from(s)
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
            &[],
        );
        let strs: Vec<&str> = out.iter().filter_map(|c| c.to_str().ok()).collect();
        assert!(
            strs.contains(&"PATH=/usr/bin"),
            "inherited PATH kept: {strs:?}"
        );
        assert_eq!(strs.iter().filter(|s| s.starts_with("HOME=")).count(), 1);
        assert_eq!(strs.iter().filter(|s| s.starts_with("TERM=")).count(), 1);
        assert!(strs.contains(&"HOME=/root"), "{strs:?}");
        assert!(strs.contains(&"TERM=xterm-256color"), "{strs:?}");
        assert!(!strs.contains(&"HOME=/somewhere/else"));
    }

    #[test]
    fn build_shell_env_skips_interior_nul_vars() {
        use std::os::unix::ffi::OsStringExt;
        // A value with an embedded NUL can't cross the C ABI — it's dropped,
        // but the forced HOME/TERM still come through.
        let bad = std::ffi::OsString::from_vec(b"a\0b".to_vec());
        let out = build_shell_env_from([(oss("WEIRD"), bad)], &[]);
        let strs: Vec<&str> = out.iter().filter_map(|c| c.to_str().ok()).collect();
        assert!(!strs.iter().any(|s| s.starts_with("WEIRD=")), "{strs:?}");
        assert!(strs.contains(&"HOME=/root"));
        assert!(strs.contains(&"TERM=xterm-256color"));
    }

    #[test]
    fn build_shell_env_adds_valid_extra_env() {
        let out = build_shell_env_from(
            [(oss("PATH"), oss("/usr/bin"))],
            &[(
                "SSH_AUTH_SOCK".to_string(),
                "/run/mvm/ssh-agent.sock".to_string(),
            )],
        );
        let strs: Vec<&str> = out.iter().filter_map(|c| c.to_str().ok()).collect();
        assert!(strs.contains(&"SSH_AUTH_SOCK=/run/mvm/ssh-agent.sock"));
    }

    #[test]
    fn test_data_port_calculation() {
        assert_eq!(CONSOLE_PORT_BASE + 1, 20001);
        assert_eq!(CONSOLE_PORT_BASE + 42, 20042);
    }

    #[test]
    fn test_is_active_default() {
        // Reset state for test (note: tests run in parallel, so this
        // tests the initial value only in isolation)
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
        assert!(!is_active());
    }

    // Portable: openpty + TIOCSCTTY + /dev/tty controlling-terminal semantics
    // work on both Linux (the guest) and macOS (dev hosts), so this runs on
    // both — the `TIOCSCTTY` const already carries per-OS values.
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
}
