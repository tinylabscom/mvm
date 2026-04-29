//! Interactive console (PTY-over-vsock) and one-shot exec via the guest agent.

use anyhow::{Context, Result};

use mvm_core::naming::validate_vm_name;
use mvm_runtime::vm::microvm;

use super::apple_container::dev_vsock_proxy_path;
use super::shared::IN_CONSOLE_MODE;
use crate::ui;

pub(super) fn cmd_console(name: &str, command: Option<&str>) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;

    if let Some(cmd) = command {
        // One-shot command execution — detect backend for both Firecracker and Apple Container
        let resp = if let Ok(mut stream) =
            mvm_apple_container::vsock_connect(name, mvm_guest::vsock::GUEST_AGENT_PORT)
        {
            mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::Exec {
                    command: cmd.to_string(),
                    stdin: None,
                    timeout_secs: Some(30),
                },
            )?
        } else {
            let instance_dir = microvm::resolve_running_vm_dir(name)?;
            mvm_guest::vsock::exec_at(
                &mvm_guest::vsock::vsock_uds_path(&instance_dir),
                cmd,
                None,
                30,
            )?
        };
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
/// Backend type for console connections.
enum ConsoleBackend {
    AppleContainer(String),
    /// Connect via the daemon's vsock proxy Unix socket.
    VsockProxy(String),
    Firecracker(String),
}

/// Connect to a vsock port via the daemon's Unix socket proxy.
pub(super) fn vsock_proxy_connect(
    proxy_path: &str,
    port: u32,
) -> Result<std::os::unix::net::UnixStream> {
    use std::io::Write;
    let mut stream = std::os::unix::net::UnixStream::connect(proxy_path)
        .with_context(|| format!("Failed to connect to vsock proxy at {proxy_path}"))?;
    stream.write_all(&port.to_le_bytes())?;
    Ok(stream)
}

/// Open an interactive PTY console to a running VM.
///
/// Supports Firecracker (via UDS vsock), Apple Container (via direct vsock),
/// and vsock proxy (via daemon Unix socket for cross-process access).
pub(super) fn console_interactive(name: &str) -> Result<()> {
    // Get terminal size
    let (cols, rows) = get_terminal_size();

    // Send ConsoleOpen request via the control channel
    ui::info(&format!(
        "Opening console to VM {:?} ({}x{})...",
        name, cols, rows
    ));

    // Determine backend: try in-process Apple Container, then vsock proxy, then Firecracker UDS
    let backend =
        if mvm_apple_container::vsock_connect(name, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
            ConsoleBackend::AppleContainer(name.to_string())
        } else if std::path::Path::new(&dev_vsock_proxy_path()).exists() {
            ConsoleBackend::VsockProxy(dev_vsock_proxy_path())
        } else {
            let instance_dir = microvm::resolve_running_vm_dir(name)?;
            ConsoleBackend::Firecracker(instance_dir)
        };

    // Send ConsoleOpen on the control channel
    let (resp, connect_data) = match &backend {
        ConsoleBackend::AppleContainer(vm_id) => {
            let mut stream =
                mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            let resp = mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows },
            )?;
            (resp, backend)
        }
        ConsoleBackend::VsockProxy(proxy_path) => {
            let mut stream = vsock_proxy_connect(proxy_path, mvm_guest::vsock::GUEST_AGENT_PORT)?;
            let resp = mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows },
            )?;
            (resp, backend)
        }
        ConsoleBackend::Firecracker(instance_dir) => {
            let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
            let mut stream = mvm_guest::vsock::connect_to(&uds, 10)?;
            let resp = mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows },
            )?;
            (resp, backend)
        }
    };

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

    // Small delay to let the guest agent bind the data port
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Connect to the data port for raw I/O
    let data_stream = match &connect_data {
        ConsoleBackend::AppleContainer(vm_id) => {
            mvm_apple_container::vsock_connect(vm_id, data_port)
                .map_err(|e| anyhow::anyhow!("Failed to connect to console data port: {e}"))?
        }
        ConsoleBackend::VsockProxy(proxy_path) => vsock_proxy_connect(proxy_path, data_port)?,
        ConsoleBackend::Firecracker(instance_dir) => {
            // Firecracker vsock multiplexes all ports on the same UDS
            let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
            mvm_guest::vsock::connect_to(&uds, 10)
                .context("Failed to connect to console data port")?
        }
    };

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::ConsoleSessionStart,
        Some(name),
        Some(&format!("session_id={session_id}")),
    );

    // Set up SIGWINCH handler to forward terminal resizes
    let resize_sender = setup_sigwinch_handler(&connect_data, session_id);

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

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::ConsoleSessionEnd,
        Some(name),
        Some(&format!("session_id={session_id}")),
    );

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
    backend: &ConsoleBackend,
    session_id: u32,
) -> Option<std::sync::mpsc::Sender<()>> {
    use std::sync::atomic::Ordering;

    // Clone backend info for the resize thread
    let backend_info = match backend {
        ConsoleBackend::AppleContainer(vm_id) => ConsoleBackend::AppleContainer(vm_id.clone()),
        ConsoleBackend::VsockProxy(path) => ConsoleBackend::VsockProxy(path.clone()),
        ConsoleBackend::Firecracker(dir) => ConsoleBackend::Firecracker(dir.clone()),
    };

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

            // Send ConsoleResize via the control channel (best-effort)
            let _ = match &backend_info {
                ConsoleBackend::AppleContainer(vm_id) => {
                    mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
                        .ok()
                        .and_then(|mut stream| {
                            mvm_guest::vsock::send_request(
                                &mut stream,
                                &mvm_guest::vsock::GuestRequest::ConsoleResize {
                                    session_id,
                                    cols,
                                    rows,
                                },
                            )
                            .ok()
                        })
                }
                ConsoleBackend::VsockProxy(proxy_path) => {
                    vsock_proxy_connect(proxy_path, mvm_guest::vsock::GUEST_AGENT_PORT)
                        .ok()
                        .and_then(|mut stream| {
                            mvm_guest::vsock::send_request(
                                &mut stream,
                                &mvm_guest::vsock::GuestRequest::ConsoleResize {
                                    session_id,
                                    cols,
                                    rows,
                                },
                            )
                            .ok()
                        })
                }
                ConsoleBackend::Firecracker(instance_dir) => {
                    let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
                    mvm_guest::vsock::connect_to(&uds, 5)
                        .ok()
                        .and_then(|mut stream| {
                            mvm_guest::vsock::send_request(
                                &mut stream,
                                &mvm_guest::vsock::GuestRequest::ConsoleResize {
                                    session_id,
                                    cols,
                                    rows,
                                },
                            )
                            .ok()
                        })
                }
            };
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
