//! `mvmctl console` — interactive console (PTY-over-vsock) and one-shot exec
//! via the guest agent.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm::vsock_transport::{
    AppleContainerTransport, FirecrackerTransport, LibkrunTransport, VsockProxyTransport,
    VsockTransport,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::super::env::apple_container::dev_vsock_proxy_path;
use super::Cli;
use super::shared::{IN_CONSOLE_MODE, clap_vm_name};
use crate::ui;

/// Pick the right vsock transport for `name`. Priority:
/// 1. In-process Apple Container (zero-copy `VZVirtioSocketDevice` stream).
/// 2. Dev-mode mode-0700 proxy socket (cross-process daemon dispatch).
/// 3. libkrun per-port Unix socket.
/// 4. Firecracker UDS multiplexer (fleet/production path).
///
/// The Apple Container probe consumes one stream and drops it; the
/// returned `Arc<dyn VsockTransport>` is then used for every real
/// connection (control + data + resize). Cloning the Arc lets the
/// SIGWINCH handler thread reuse the same dispatch.
fn pick_console_transport(name: &str) -> Result<Arc<dyn VsockTransport>> {
    if mvm_backend::providers::apple_container::vsock_connect(
        name,
        mvm_guest::vsock::GUEST_AGENT_PORT,
    )
    .is_ok()
    {
        return Ok(Arc::new(AppleContainerTransport::new(name)));
    }
    let proxy = dev_vsock_proxy_path();
    if std::path::Path::new(&proxy).exists() {
        return Ok(Arc::new(VsockProxyTransport::new(proxy)));
    }
    let libkrun = LibkrunTransport::for_vm(name);
    if libkrun.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Arc::new(libkrun));
    }
    Ok(Arc::new(FirecrackerTransport::for_vm(name)?))
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Run a single command instead of an interactive shell
    #[arg(long)]
    pub command: Option<String>,
    /// Bypass the sealed-image check (use with care: the image was
    /// built without dev surface, so the in-VM agent may refuse
    /// `Exec`/`ConsoleOpen` regardless).
    #[arg(long)]
    pub force: bool,
}

/// Refuse to attach if the VM's image was built sealed (dev = false /
/// `passthru.mvm.accessible = false`). The state file is best-effort:
/// missing or pre-W6.2 files are treated as accessible.
fn enforce_accessible_gate(name: &str, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    match mvm::vm::runtime_meta::read(name) {
        Ok(Some(meta)) if !meta.accessible => anyhow::bail!(
            "console refused: VM {name:?} was built from a sealed image (passthru.mvm.accessible = false). \
             Sealed images don't ship the dev agent surface. \
             Rebuild with `dev = true` or pass `--force` to attempt the attach anyway."
        ),
        _ => Ok(()),
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let name = &args.name;
    let command = args.command.as_deref();
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    enforce_accessible_gate(name, args.force)?;

    if let Some(cmd) = command {
        let transport = pick_console_transport(name)?;
        let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
        // ADR-053 / plan 74 W1: hard cutover requires hello before any
        // operational request. One-shot `Exec` is a dev-shell request
        // not covered by the closed `GuestCapability` enum, so request
        // no specific capability — the hello alone unblocks dispatch.
        let _ = mvm_guest::vsock::negotiate_protocol(&mut stream, Vec::new())?;
        let req = mvm_guest::vsock::GuestRequest::Exec {
            command: cmd.to_string(),
            stdin: None,
            timeout_secs: Some(30),
        };
        // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
        super::shared::emit_vsock_rpc_audit(name, &req);
        let resp = mvm_guest::vsock::send_request(&mut stream, &req)?;
        match resp {
            mvm_guest::vsock::GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                if !stdout.is_empty() {
                    print!("{stdout}");
                }
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                }
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
                Ok(())
            }
            mvm_guest::vsock::GuestResponse::Error { message } => {
                anyhow::bail!("Console exec error: {message}")
            }
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    } else {
        // Interactive PTY session
        console_interactive(name)
    }
}

/// Open an interactive PTY console to a running VM.
///
/// Supports Firecracker (via UDS vsock), libkrun (via per-port Unix
/// sockets), Apple Container (via direct vsock), and vsock proxy (via
/// daemon Unix socket for cross-process access).
pub(in crate::commands) fn console_interactive(name: &str) -> Result<()> {
    let (cols, rows) = get_terminal_size();

    ui::info(&format!(
        "Opening console to VM {:?} ({}x{})...",
        name, cols, rows
    ));

    let transport = pick_console_transport(name)?;

    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::require_capabilities(
        &mut stream,
        &[mvm_guest::vsock::GuestCapability::Console],
    )?;
    let req = mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let resp = mvm_guest::vsock::send_request(&mut stream, &req)?;

    let (session_id, data_port) = match resp {
        mvm_guest::vsock::GuestResponse::ConsoleOpened {
            session_id,
            data_port,
        } => (session_id, data_port),
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("Console open failed: {message}");
        }
        other => {
            anyhow::bail!("Unexpected response: {other:?}");
        }
    };

    ui::info(&format!(
        "Console session {} opened, connecting to data port {}...",
        session_id, data_port
    ));

    // Small delay to let the guest agent bind the data port.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let data_stream = transport
        .connect(data_port)
        .context("Failed to connect to console data port")?;

    mvm_core::audit_emit!(ConsoleSessionStart, vm: name, "session_id={session_id}");

    // Set up SIGWINCH handler to forward terminal resizes
    let resize_sender = setup_sigwinch_handler(transport.clone(), session_id);

    // Enter raw terminal mode and suppress the Ctrl-C handler so that
    // Ctrl+C is forwarded as a raw byte (\x03) to the guest shell
    // instead of killing mvmctl.
    IN_CONSOLE_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
    let orig_termios = enter_raw_mode()?;
    let result = run_console_relay(data_stream);

    // Restore terminal and clean up
    restore_terminal(&orig_termios);
    IN_CONSOLE_MODE.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(resize_sender);

    mvm_core::audit_emit!(ConsoleSessionEnd, vm: name, "session_id={session_id}");

    println!("\nConsole session ended.");
    result.map(|_| ())
}

/// Flag set by the SIGWINCH signal handler.
static SIGWINCH_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Set up a SIGWINCH signal handler that forwards terminal resizes to the guest.
///
/// Returns a sender that keeps the background thread alive. Drop it to stop.
fn setup_sigwinch_handler(
    transport: Arc<dyn VsockTransport>,
    session_id: u32,
) -> Option<std::sync::mpsc::Sender<()>> {
    use std::sync::atomic::Ordering;

    let (tx, rx) = std::sync::mpsc::channel::<()>();

    // Install SIGWINCH handler
    unsafe {
        libc::signal(
            libc::SIGWINCH,
            sigwinch_handler as *const () as libc::sighandler_t,
        );
    }

    // Background thread polls for resize signals
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));

            // Stop if session ended (sender dropped)
            if let Err(std::sync::mpsc::TryRecvError::Disconnected) = rx.try_recv() {
                break;
            }

            if !SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) {
                continue;
            }

            let (cols, rows) = get_terminal_size();

            // Send ConsoleResize via the control channel (best-effort).
            let _ = transport
                .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
                .ok()
                .and_then(|mut stream| {
                    mvm_guest::vsock::require_capabilities(
                        &mut stream,
                        &[mvm_guest::vsock::GuestCapability::Console],
                    )
                    .ok()?;
                    mvm_guest::vsock::send_request(
                        &mut stream,
                        &mvm_guest::vsock::GuestRequest::ConsoleResize {
                            session_id,
                            cols,
                            rows,
                        },
                    )
                    .ok()
                });
        }
    });

    Some(tx)
}

/// Get the current terminal size.
fn get_terminal_size() -> (u16, u16) {
    // SAFETY: ioctl with valid fd (stdout)
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

/// Put the terminal in raw mode and return the original termios for restoration.
fn enter_raw_mode() -> Result<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut orig) != 0 {
            anyhow::bail!("Failed to get terminal attributes");
        }

        let mut raw = orig;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
            anyhow::bail!("Failed to set raw terminal mode");
        }

        Ok(orig)
    }
}

/// Restore the terminal to its original mode.
fn restore_terminal(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, orig);
    }
}

/// Relay raw bytes between stdin/stdout and a vsock data stream.
///
/// Exits when the guest closes the connection (e.g. `exit` or Ctrl+D
/// in the shell) or when the user types the `~.` escape sequence
/// (Enter, then `~.`, same as SSH).
///
fn run_console_relay(data_stream: std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    let read_stream = data_stream
        .try_clone()
        .context("Failed to clone data stream")?;
    let write_stream = data_stream;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let vsock_fd = read_stream.as_raw_fd();

    // Save original flags so we can restore stdin after the relay exits.
    let orig_stdin_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    unsafe {
        libc::fcntl(stdin_fd, libc::F_SETFL, orig_stdin_flags | libc::O_NONBLOCK);
        libc::fcntl(vsock_fd, libc::F_SETFL, libc::O_NONBLOCK);
    }

    let mut stdout = std::io::stdout();
    let mut writer = write_stream;
    let mut buf = [0u8; 4096];

    loop {
        let mut fds = [
            libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: vsock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if ret < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // vsock → stdout (guest output)
        if fds[1].revents & libc::POLLIN != 0 {
            match (&read_stream).read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[1].revents & libc::POLLIN == 0
        {
            break;
        }

        // stdin → vsock (host input)
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut inbuf = [0u8; 1024];
            match std::io::stdin().read(&mut inbuf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_all(&inbuf[..n]).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    }

    // Restore stdin to its original blocking mode
    unsafe {
        libc::fcntl(stdin_fd, libc::F_SETFL, orig_stdin_flags);
    }

    Ok(())
}

#[cfg(test)]
mod accessible_gate_tests {
    use super::*;
    use mvm::vm::runtime_meta::{StartModeKind, VmRuntimeMeta, write as write_meta};
    use std::sync::Mutex;

    // Tests in this module mutate the process-global HOME env var to
    // point at a temp dir; serialize them with a local mutex so they
    // don't race when cargo runs the test binary with multiple threads.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn with_home<F: FnOnce(&std::path::Path)>(f: F) {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let prev = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        f(tmp.path());
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn gate_allows_when_meta_missing() {
        with_home(|_| {
            assert!(enforce_accessible_gate("never-started", false).is_ok());
        });
    }

    #[test]
    fn gate_allows_when_meta_says_accessible() {
        with_home(|_| {
            let name = "accessible-vm";
            write_meta(
                name,
                &VmRuntimeMeta {
                    mode: StartModeKind::Attached,
                    accessible: true,
                },
            )
            .expect("write");
            assert!(enforce_accessible_gate(name, false).is_ok());
        });
    }

    #[test]
    fn gate_refuses_when_sealed() {
        with_home(|_| {
            let name = "sealed-vm";
            write_meta(
                name,
                &VmRuntimeMeta {
                    mode: StartModeKind::Detached,
                    accessible: false,
                },
            )
            .expect("write");
            let err = enforce_accessible_gate(name, false).expect_err("must refuse");
            let msg = err.to_string();
            assert!(msg.contains("sealed image"), "msg: {msg}");
            assert!(msg.contains("--force"), "msg should hint at --force: {msg}");
        });
    }

    #[test]
    fn gate_force_bypasses_sealed_refusal() {
        with_home(|_| {
            let name = "sealed-but-forced";
            write_meta(
                name,
                &VmRuntimeMeta {
                    mode: StartModeKind::Attached,
                    accessible: false,
                },
            )
            .expect("write");
            assert!(enforce_accessible_gate(name, true).is_ok());
        });
    }
}
