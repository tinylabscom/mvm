//! `mvmctl console` — interactive console (PTY-over-vsock) and one-shot exec
//! via the guest agent.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm::vsock_transport::{
    DevConsoleTransport, FirecrackerTransport, LibkrunTransport, VsockTransport, VzTransport,
    firecracker_transport_supported,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::super::env::dev_vz::{DEV_VM_NAME, dev_vsock_proxy_path};
use super::Cli;
use super::shared::{IN_CONSOLE_MODE, clap_vm_name};
use crate::ui;

/// Pick the right vsock transport for `name`. Priority:
/// 1. The dev VM's Vz guest-agent socket, when this is the dev VM and
///    its socket is present (the dev VM lives in the builder cache, a
///    different path than `VzTransport::for_vm` resolves).
/// 2. libkrun per-port Unix socket.
/// 3. HVF runner (`WorkloadRunner` / HVF) agent socket at
///    `<vm_state_dir>/hvf-agent.sock`. This is workload-local; the
///    pre-opened console sockets exist only when the VM was booted with
///    `dev_console=true`.
/// 4. Vz per-port Unix socket (`<vm_state_dir>/vsock/vsock-<port>.sock`) —
///    the macOS AVF path.
/// 5. Firecracker UDS multiplexer (fleet/production path), only on native
///    Linux where resolving the Firecracker runtime dir is side-effect-free.
///
/// Each probe consumes one stream and drops it; the returned
/// `Arc<dyn VsockTransport>` is then used for every real connection
/// (control + data + resize). Cloning the Arc lets the SIGWINCH handler
/// thread reuse the same dispatch.
fn pick_console_transport(name: &str) -> Result<Arc<dyn VsockTransport>> {
    // The dev VM's guest-agent socket sits in the builder cache, not the
    // data-dir path `VzTransport::for_vm` resolves. The Vz supervisor
    // exposes it as a direct per-port socket (no proxy port prefix), so
    // dial it through `VzTransport` rooted at the socket's parent dir.
    //
    // Gate this on the requested name being the dev VM. The dev socket is
    // present whenever the persistent dev/builder VM is up (e.g. after an
    // image-ensure step), so an unconditional check would route every
    // workload's console onto the builder — which must stay free to build
    // other microVMs, and whose per-port data socket the workload's session
    // never created anyway. A workload falls through to its own transport.
    if name == DEV_VM_NAME {
        let dev_sock = std::path::PathBuf::from(dev_vsock_proxy_path());
        if dev_sock.exists()
            && let Some(dir) = dev_sock.parent()
        {
            return Ok(Arc::new(VzTransport::new(dir)));
        }
    }
    let libkrun = LibkrunTransport::for_vm(name);
    if libkrun.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Arc::new(libkrun));
    }
    // HVF runner (WorkloadRunner / HVF) exposes the agent at
    // `<vm_state_dir>/hvf-agent.sock` and console data ports at
    // `<vm_state_dir>/vsock/vsock-<port>.sock`. Gate on the workload being
    // accessible (non-sealed), not on an ambient
    // `MVM_ENV=dev`, so `machine run -it` reaches its own console without an
    // env dance. A sealed prod runner is `accessible = false` here and its
    // agent carries no Console capability regardless.
    if hvf_console_arm_enabled(name) {
        let hvf = DevConsoleTransport::for_vm(name);
        if hvf.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
            return Ok(Arc::new(hvf));
        }
    }
    // Vz workloads expose the agent at `<vm_state_dir>/vsock/vsock-<port>.sock`
    // (one subdir deeper than libkrun); without this probe `console` fell
    // through to the firecracker fallback and mis-resolved to `mvm-dev`.
    let vz = VzTransport::for_vm(name);
    if vz.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Arc::new(vz));
    }
    if firecracker_transport_supported(mvm_core::platform::current()) {
        return Ok(Arc::new(FirecrackerTransport::for_vm(name)?));
    }
    anyhow::bail!("no host-side console transport found for VM {name:?}")
}

/// Whether the HVF interactive console-data arm may fire for `name`. Enabled for
/// an accessible (non-sealed) workload; a sealed prod runner's
/// `runtime_meta.accessible` is `false` so it never routes to the console
/// (`enforce_accessible_gate` refuses the attach up front, and the sealed agent
/// links no Console capability). Missing/legacy metadata reads as accessible —
/// the same backward-compat default `enforce_accessible_gate` uses.
fn hvf_console_arm_enabled(name: &str) -> bool {
    !matches!(mvm::vm::runtime_meta::read(name), Ok(Some(meta)) if !meta.accessible)
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Run a single command instead of an interactive shell
    #[arg(long)]
    pub command: Option<String>,
    /// Attempt the attach even when legacy metadata is incomplete. This never
    /// bypasses a sealed-image refusal.
    #[arg(long)]
    pub force: bool,
    /// Extra KEY=VALUE environment entries for the guest dev shell/session.
    #[arg(skip)]
    pub env: Vec<(String, String)>,
    /// Explicit PTY argv. Empty uses the guest agent default shell.
    #[arg(skip)]
    pub pty_argv: Vec<String>,
}

/// Refuse to attach if the VM's image was built sealed (dev = false /
/// `passthru.mvm.accessible = false`). The state file is best-effort:
/// missing or legacy files without the field are treated as accessible.
///
/// Reused by `machine run -t` (claim 15: no interactive access to a sealed
/// production microVM).
pub(in crate::commands) fn enforce_accessible_gate(name: &str, force: bool) -> Result<()> {
    let _ = force;
    match mvm::vm::runtime_meta::read(name) {
        Ok(Some(meta)) if !meta.accessible => anyhow::bail!(
            "console refused: VM {name:?} was built from a sealed image (passthru.mvm.accessible = false). \
             Sealed images don't ship the dev agent surface. \
             Rebuild with `dev = true` for interactive development."
        ),
        _ => Ok(()),
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let name = &args.name;
    let command = args.command.as_deref();
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    enforce_accessible_gate(name, args.force)?;
    // A console attach (one-shot exec or interactive PTY) is guest activity;
    // refresh idle tracking so an in-use session isn't idle-slept underneath
    // the user. Best-effort.
    touch_activity(name);

    if let Some(cmd) = command {
        let transport = pick_console_transport(name)?;
        let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
        // Inbound vsock RPC audit (verb=exec).
        super::shared::emit_vsock_rpc_audit(
            name,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: cmd.to_string(),
                stdin: None,
                timeout_secs: None,
            },
        );
        // send_exec_streaming does the protocol hello internally.
        use std::io::Write as _;
        let command = command_with_env(cmd, &args.env);
        let terminal =
            mvm_guest::vsock::send_exec_streaming(&mut stream, &command, None, None, |event| {
                match event {
                    mvm_guest::vsock::ExecEvent::Stdout { chunk } => {
                        let mut so = std::io::stdout();
                        let _ = so.write_all(chunk);
                        let _ = so.flush();
                    }
                    mvm_guest::vsock::ExecEvent::Stderr { chunk } => {
                        let mut se = std::io::stderr();
                        let _ = se.write_all(chunk);
                        let _ = se.flush();
                    }
                    _ => {}
                }
            })?;
        match terminal {
            mvm_guest::vsock::ExecEvent::Exit { code } => {
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
            mvm_guest::vsock::ExecEvent::TimedOut => {
                eprintln!("{}", crate::exec::timeout_exit_message(None));
                std::process::exit(crate::exec::EXEC_TIMEOUT_EXIT_CODE);
            }
            other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
        }
    } else {
        // Interactive PTY session
        console_interactive_with_env_and_argv(name, args.env, args.pty_argv)
    }
}

fn command_with_env(cmd: &str, env: &[(String, String)]) -> String {
    if env.is_empty() {
        return cmd.to_string();
    }
    let exports = env
        .iter()
        .map(|(key, value)| format!("{key}={}", crate::exec::shell_quote(value)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{exports} {cmd}")
}

/// Record a coarse guest-activity touch on the named VM.
/// Best-effort: only rewrites the registry when the name is registered;
/// any load/save hiccup is swallowed so console attach never blocks.
fn touch_activity(name: &str) {
    let path = mvm::vm::name_registry::registry_path();
    if let Ok(mut reg) = mvm::vm::name_registry::VmNameRegistry::load(&path)
        && reg
            .touch_last_active(name, mvm_core::time::utc_now())
            .unwrap_or(false)
    {
        let _ = reg.save(&path);
    }
}

/// Open an interactive PTY console to a running VM.
///
/// Supports Firecracker (via UDS vsock), libkrun (via per-port Unix
/// sockets), Apple Container (via direct vsock), and vsock proxy (via
/// daemon Unix socket for cross-process access).
pub(in crate::commands) fn console_interactive(name: &str) -> Result<()> {
    console_interactive_with_env(name, Vec::new()).map(|_| ())
}

pub(in crate::commands) fn console_interactive_with_env(
    name: &str,
    env: Vec<(String, String)>,
) -> Result<i32> {
    console_pty_with_argv(name, env, Vec::new())
}

pub(crate) fn console_pty_command(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<()> {
    let exit_code = run_pty_command_for_exit(name, command, env)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub(in crate::commands) fn console_interactive_with_env_and_argv(
    name: &str,
    env: Vec<(String, String)>,
    argv: Vec<String>,
) -> Result<()> {
    let exit_code = console_pty_with_argv(name, env, argv)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub(crate) fn run_pty_command_for_exit(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<i32> {
    console_pty_with_argv(name, env, shell_command_argv(command))
}

fn shell_command_argv(command: String) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-lc".to_string(), command]
}

fn console_pty_with_argv(name: &str, env: Vec<(String, String)>, argv: Vec<String>) -> Result<i32> {
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
    let req = mvm_guest::vsock::GuestRequest::ConsoleOpen {
        cols,
        rows,
        env,
        argv,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let (session_id, data_port) = match mvm_guest::vsock::call_unary(&mut stream, &req)? {
        mvm_guest::vsock::GuestResponse::ConsoleOpened {
            session_id,
            data_port,
        } => (session_id, data_port),
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

    let exit_code = console_exit_code(&transport, session_id)?;
    println!("\nConsole session ended.");
    result.map(|_| exit_code)
}

fn console_exit_code(transport: &Arc<dyn VsockTransport>, session_id: u32) -> Result<i32> {
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::require_capabilities(
        &mut stream,
        &[mvm_guest::vsock::GuestCapability::Console],
    )?;
    let req = mvm_guest::vsock::GuestRequest::ConsoleClose { session_id };
    match mvm_guest::vsock::call_unary(&mut stream, &req)? {
        mvm_guest::vsock::GuestResponse::ConsoleExited { exit_code, .. } => Ok(exit_code),
        mvm_guest::vsock::GuestResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
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

    fn with_home<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = mvm::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("HOME", tmp.path());
        env.set("MVM_DATA_DIR", tmp.path().join(".mvm"));
        f(tmp.path());
    }

    #[test]
    fn pick_console_transport_selects_vz_when_only_vz_socket_present() {
        use std::os::unix::net::UnixListener;
        // Regression for the "console can't reach a Vz workload" gap: with a
        // Vz workload's vsock socket present (and no dev-proxy / libkrun /
        // firecracker surface), the picker must select the Vz
        // transport instead of erroring out on the firecracker fallback.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_DATA_DIR", tmp.path());

        let name = "vz-console-probe";
        let sock =
            mvm_core::config::vm_vz_vsock_port_socket(name, mvm_guest::vsock::GUEST_AGENT_PORT);
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&sock).unwrap();

        let transport = pick_console_transport(name).expect("picker should find the vz transport");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport should connect to the vz socket");
    }

    // The dev VM's vsock socket is present whenever the persistent
    // dev/builder VM is up. A workload's console request must NOT be
    // routed onto it (the builder must stay free to build other microVMs,
    // and its session never created the workload's per-port data socket).
    #[cfg(feature = "builder-vm")]
    #[test]
    fn pick_console_transport_does_not_route_workload_to_dev_socket() {
        use mvm_backend::base::shell_mock;
        use std::os::unix::net::UnixListener;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        // Root under /tmp: the dev socket path includes a long
        // `mvm-persistent-builder-vz-dev` component that overruns the
        // ~104-char AF_UNIX SUN_LEN limit when rooted in the default $TMPDIR.
        let cache = tempfile::tempdir_in("/tmp").expect("cache tempdir");
        let data = tempfile::tempdir_in("/tmp").expect("data tempdir");
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        // Intercept any shell commands (e.g. the `echo $VMS_DIR` in the
        // Firecracker fallback) so the test completes fast whether or not
        // the dev VM happens to be running.
        let fake_vms = data.path().join("vms");
        let fake_vms_str = fake_vms.display().to_string();
        let _mock = shell_mock::install_handler(move |_script: &str| shell_mock::MockResponse {
            exit_code: 0,
            stdout: fake_vms_str.clone(),
        });

        // Dev VM socket present and live, but the requested name is a workload.
        let dev_sock = std::path::PathBuf::from(dev_vsock_proxy_path());
        std::fs::create_dir_all(dev_sock.parent().unwrap()).unwrap();
        let _dev_listener = UnixListener::bind(&dev_sock).unwrap();

        // No socket for the workload, so the only way to "succeed" is the
        // buggy short-circuit onto the dev socket. An Err (no transport
        // resolved) is fine too — just not the dev VM.
        if let Ok(transport) = pick_console_transport("workload-1") {
            assert!(
                transport
                    .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
                    .is_err(),
                "a workload console must not be routed onto the dev/builder VM socket"
            );
        }
    }

    // The dev shell path (`console_interactive(DEV_VM_NAME)`) must still
    // resolve to the dev VM's builder-cache socket.
    #[cfg(feature = "builder-vm")]
    #[test]
    fn pick_console_transport_selects_dev_socket_for_dev_vm() {
        use std::os::unix::net::UnixListener;
        let mut env = mvm_core::util::test_env::TestEnv::new();
        // /tmp root — see SUN_LEN note in the sibling test above.
        let cache = tempfile::tempdir_in("/tmp").expect("cache tempdir");
        env.set("MVM_CACHE_DIR", cache.path());

        let dev_sock = std::path::PathBuf::from(dev_vsock_proxy_path());
        std::fs::create_dir_all(dev_sock.parent().unwrap()).unwrap();
        let _dev_listener = UnixListener::bind(&dev_sock).unwrap();

        let transport =
            pick_console_transport(DEV_VM_NAME).expect("picker should find the dev VM transport");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("dev VM console must connect to the builder-cache socket");
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
                    rootfs_path: None,
                },
            )
            .expect("write");
            assert!(enforce_accessible_gate(name, false).is_ok());
        });
    }

    #[test]
    fn touch_activity_refreshes_last_active_for_registered_vm() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_SHARE_DIR", tmp.path());

        let path = mvm::vm::name_registry::registry_path();
        let mut reg = mvm::vm::name_registry::VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        reg.save(&path).unwrap();
        assert!(reg.lookup("vm1").unwrap().last_active.is_none());

        touch_activity("vm1");
        let reloaded = mvm::vm::name_registry::VmNameRegistry::load(&path).unwrap();
        assert!(
            reloaded.lookup("vm1").unwrap().last_active.is_some(),
            "console attach must refresh last_active"
        );

        // Unknown name is a clean no-op — no panic, registry untouched.
        touch_activity("ghost");
        let reloaded = mvm::vm::name_registry::VmNameRegistry::load(&path).unwrap();
        assert!(reloaded.lookup("ghost").is_none());
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
                    rootfs_path: None,
                },
            )
            .expect("write");
            let err = enforce_accessible_gate(name, false).expect_err("must refuse");
            let msg = err.to_string();
            assert!(msg.contains("sealed image"), "msg: {msg}");
            assert!(
                !msg.contains("--force"),
                "msg must not suggest bypass: {msg}"
            );
        });
    }

    // claim 15 witness: `mvmctl console` refuses to attach to a VM built
    // from a sealed (accessible == false) production image.
    #[test]
    fn console_refused_on_sealed_image() {
        with_home(|_| {
            let name = "sealed-prod-image";
            write_meta(
                name,
                &VmRuntimeMeta {
                    mode: StartModeKind::Detached,
                    accessible: false,
                    rootfs_path: None,
                },
            )
            .expect("write");
            let err = enforce_accessible_gate(name, false).expect_err("must refuse");
            assert!(err.to_string().contains("sealed image"), "msg: {err}");
        });
    }

    #[test]
    fn gate_force_does_not_bypass_sealed_refusal() {
        with_home(|_| {
            let name = "sealed-but-forced";
            write_meta(
                name,
                &VmRuntimeMeta {
                    mode: StartModeKind::Attached,
                    accessible: false,
                    rootfs_path: None,
                },
            )
            .expect("write");
            let err =
                enforce_accessible_gate(name, true).expect_err("force must not bypass sealed");
            assert!(err.to_string().contains("sealed image"), "msg: {err}");
        });
    }
}

#[cfg(test)]
mod picker_hvf_tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    /// Bind `hvf-agent.sock` under a fresh temp state-dir and set
    /// `MVM_DATA_DIR` so `vm_state_dir` resolves there. Returns the guard
    /// objects that keep the socket and env alive for the test.
    fn setup_hvf_agent(
        name: &str,
    ) -> (
        tempfile::TempDir,
        mvm_core::util::test_env::TestEnv,
        UnixListener,
    ) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").expect("state tempdir");
        env.set("MVM_DATA_DIR", tmp.path());
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let listener = UnixListener::bind(&agent).unwrap();
        (tmp, env, listener)
    }

    #[test]
    fn pick_console_transport_selects_hvf_for_workload() {
        let name = "hvf-dev-workload";
        let (_tmp, _env, _listener) = setup_hvf_agent(name);

        let transport = pick_console_transport(name).expect("picker must resolve hvf transport");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport must connect to hvf-agent.sock");
    }

    // A sealed workload must not route to the hvf console even with
    // `hvf-agent.sock` present. It falls through to Vz/Firecracker, so a sealed
    // prod runner never receives an interactive attach.
    #[test]
    fn pick_console_transport_skips_hvf_for_sealed_workload() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").expect("state tempdir");
        env.set("MVM_DATA_DIR", tmp.path());

        let name = "hvf-sealed-workload";
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let _listener = UnixListener::bind(&agent).unwrap();

        // Mark the image sealed.
        mvm::vm::runtime_meta::write(
            name,
            &mvm::vm::runtime_meta::VmRuntimeMeta {
                mode: mvm::vm::runtime_meta::StartModeKind::Attached,
                accessible: false,
                rootfs_path: None,
            },
        )
        .unwrap();

        match pick_console_transport(name) {
            Err(_) => {
                // Expected: picker fell through to FC which failed — fine.
            }
            Ok(transport) => {
                assert!(
                    transport
                        .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
                        .is_err(),
                    "a sealed workload must not route to the hvf agent socket"
                );
            }
        }
    }

    // The fix: an accessible workload's console is reachable WITHOUT MVM_ENV=dev,
    // so `machine run -it` attaches its own PTY with no env dance.
    #[test]
    fn pick_console_transport_selects_hvf_for_accessible_workload_without_dev_env() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").expect("state tempdir");
        env.set("MVM_DATA_DIR", tmp.path());
        // Deliberately NOT dev mode.
        env.set("MVM_ENV", "prod");

        let name = "hvf-accessible-workload";
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let _listener = UnixListener::bind(&agent).unwrap();
        // No runtime_meta written → accessible by the backward-compat default.

        let transport = pick_console_transport(name)
            .expect("accessible workload must resolve the hvf transport");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport must connect to the workload agent socket");
    }

    // Extend the boundary test: even with MVM_ENV=dev (which enables the
    // hvf arm), the picker selects the workload's OWN hvf socket — not
    // the dev/builder VM socket — when both are present. The hvf arm probes
    // `hvf-agent.sock` under the workload's own state dir, which is disjoint
    // from the builder cache, so it can never cross-route.
    #[cfg(feature = "builder-vm")]
    #[test]
    fn pick_console_transport_hvf_uses_workload_not_dev_socket() {
        // /tmp root — see SUN_LEN note in the original boundary test.
        let cache = tempfile::tempdir_in("/tmp").expect("cache tempdir");
        let data = tempfile::tempdir_in("/tmp").expect("data tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());
        env.set("MVM_ENV", "dev");

        // Dev VM socket present and live.
        let dev_sock = std::path::PathBuf::from(dev_vsock_proxy_path());
        std::fs::create_dir_all(dev_sock.parent().unwrap()).unwrap();
        let _dev_listener = UnixListener::bind(&dev_sock).unwrap();

        // Workload's hvf agent.sock also present.
        let name = "hvf-with-dev-present";
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let workload_agent = mvm_core::config::vm_hvf_agent_socket(name);
        let _workload_listener = UnixListener::bind(&workload_agent).unwrap();

        // The picker must select the workload's own hvf socket, not the
        // dev/builder socket. Connection to agent.sock must succeed.
        let transport = pick_console_transport(name)
            .expect("picker must find the hvf transport for the workload");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport must connect to the workload's agent.sock");
    }

    // Extend the boundary test: the dev VM path must still work even when
    // MVM_ENV=dev is set (which enables the hvf arm for workloads).
    #[cfg(feature = "builder-vm")]
    #[test]
    fn pick_console_transport_selects_dev_socket_for_dev_vm_with_dev_mode() {
        // /tmp root — see SUN_LEN note in the original boundary test.
        let cache = tempfile::tempdir_in("/tmp").expect("cache tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_ENV", "dev");

        let dev_sock = std::path::PathBuf::from(dev_vsock_proxy_path());
        std::fs::create_dir_all(dev_sock.parent().unwrap()).unwrap();
        let _dev_listener = UnixListener::bind(&dev_sock).unwrap();

        let transport =
            pick_console_transport(DEV_VM_NAME).expect("picker must find the dev VM transport");
        transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("dev VM console must connect to the builder-cache socket");
    }
}
