//! Console terminal presentation; policy and guest operations live in the client.
use super::Cli;
use super::shared::{IN_CONSOLE_MODE, clap_vm_name};
use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_client::console::{
    self as service, ConsoleData, ConsoleRelayExit, ConsoleResize, SessionEnding,
};
pub(in crate::commands) use mvm_client::console::{ConsoleSessionOptions, enforce_accessible_gate};
use mvm_core::user_config::MvmConfig;
use std::io::Write as _;

pub(in crate::commands) const CONSOLE_SESSION_HELP: &str = "\
SESSIONS:
    A console session outlives its client. `machine attach <name>` attaches to
    the VM's running session, replaying its recent output, or starts one if
    there is none. One client is attached at a time.

    Escapes (press Enter first; handled by mvmctl, never sent to the guest):
        ~d   detach: the shell keeps running; run `machine attach <name>`
             again to reattach
        ~.   end the session: the shell is hung up and the console exits

    Closing the terminal or losing the connection also detaches. A session ends
    when its shell exits, when it is ended with `~.`, after --detach-timeout
    with no client attached, or when the VM stops.

    `machine attach <name> --list` shows the session. `machine detach <name>`
    disconnects whoever is attached, and `--force` takes the session over
    from them. `machine console` remains a compatibility spelling.";

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Run a single command instead of an interactive shell
    #[arg(long, conflicts_with_all = ["list", "detach_timeout"])]
    pub command: Option<String>,
    /// Take the session over when another client is attached: that client is
    /// detached and the shell keeps running. Never bypasses a sealed-image
    /// refusal.
    #[arg(long)]
    pub force: bool,
    /// List the VM's console sessions instead of attaching
    #[arg(long, conflicts_with = "force")]
    pub list: bool,
    /// When this attach starts a new session, end it after it has had no
    /// client attached for this many seconds. Without it a detached session
    /// runs until its shell exits or the VM stops
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..), conflicts_with = "list")]
    pub detach_timeout: Option<u64>,
    /// Extra KEY=VALUE environment entries for the guest dev shell/session.
    #[arg(skip)]
    pub env: Vec<(String, String)>,
    /// Explicit PTY argv. Empty uses the guest agent default shell.
    #[arg(skip)]
    pub pty_argv: Vec<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct DetachArgs {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let code = run_for_exit(cli, args, cfg)?;
    if code != 0 {
        mvm_observability::exit(code);
    }
    Ok(())
}

pub(in crate::commands) fn run_for_exit(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<i32> {
    if args.list {
        return list_console_sessions(&args.name).map(|()| 0);
    }
    if let Some(command) = args.command {
        return service::exec(&args.name, &command, &args.env, emit_exec_event)
            .map(render_completion);
    }
    console_interactive(
        &args.name,
        ConsoleSessionOptions::builder()
            .env(args.env)
            .argv(args.pty_argv)
            .take_over(args.force)
            .detach_timeout_secs(args.detach_timeout)
            .build(),
    )
}

pub(in crate::commands) fn run_declared_command(
    name: &str,
    tool: &str,
    argv: Vec<String>,
    force: bool,
) -> Result<()> {
    enforce_accessible_gate(name, force)?;
    let code = render_completion(service::exec_declared(name, tool, argv, emit_exec_event)?);
    if code != 0 {
        mvm_observability::exit(code);
    }
    Ok(())
}

fn emit_exec_event(event: service::ExecOutput) {
    match event {
        service::ExecOutput::Stdout(chunk) => {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(&chunk);
            let _ = stdout.flush();
        }
        service::ExecOutput::Stderr(chunk) => {
            let mut stderr = std::io::stderr();
            let _ = stderr.write_all(&chunk);
            let _ = stderr.flush();
        }
    }
}

fn render_completion(completion: service::ExecCompletion) -> i32 {
    if completion.timed_out {
        eprintln!("{}", crate::exec::timeout_exit_message(None));
    }
    if completion.binding_release_failed {
        crate::ui::warn(
            "could not release the tool invocation's binding; the endpoint retires it later",
        );
    }
    completion.exit_code
}

pub(crate) fn console_pty_command(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<()> {
    let code = run_pty_command_for_exit(name, command, env)?;
    if code != 0 {
        mvm_observability::exit(code);
    }
    Ok(())
}

pub(crate) fn run_pty_command_for_exit(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<i32> {
    run_pty_argv_for_exit(name, vec!["/bin/sh".into(), "-lc".into(), command], env)
}

pub(crate) fn run_pty_argv_for_exit(
    name: &str,
    argv: Vec<String>,
    env: Vec<(String, String)>,
) -> Result<i32> {
    console_interactive(
        name,
        ConsoleSessionOptions::builder().env(env).argv(argv).build(),
    )
}

pub(in crate::commands) fn console_interactive(
    name: &str,
    options: ConsoleSessionOptions,
) -> Result<i32> {
    let size = get_terminal_size();
    let mut session = service::open(name, options, size)?;
    let session_id = session.session_id();
    crate::ui::info(&format!(
        "Connected to console session {session_id} on VM {name:?}."
    ));
    let resize_sender = setup_sigwinch_handler(session.resize_handle());
    let raw_terminal = RawTerminalGuard::enter()?;
    let result = run_console_relay(session.take_data()?);
    drop(raw_terminal);
    drop(resize_sender);
    match session.finish(result?)? {
        SessionEnding::Exited(code) => {
            println!("\nConsole session ended.");
            Ok(code)
        }
        SessionEnding::Terminated => {
            println!("\nConsole session ended.");
            Ok(0)
        }
        SessionEnding::Detached => {
            println!(
                "\nDetached from console session {session_id}; it keeps running. \
                 Reattach with `mvmctl machine console {name}`."
            );
            Ok(0)
        }
        SessionEnding::Displaced => {
            println!(
                "\nDisconnected from console session {session_id}: another client took it over \
                 or it was detached. The session keeps running."
            );
            Ok(0)
        }
    }
}

fn list_console_sessions(name: &str) -> Result<()> {
    let sessions = service::list_sessions(name)?;
    if sessions.is_empty() {
        println!("No console sessions on VM {name:?}.");
        return Ok(());
    }
    println!(
        "{:<8} {:<20} {:<32} SCROLLBACK",
        "SESSION", "COMMAND", "STATE"
    );
    for session in &sessions {
        println!(
            "{:<8} {:<20} {:<32} {}",
            session.session_id,
            session.command,
            session_state_label(session),
            format_bytes(session.scrollback_bytes)
        );
    }
    Ok(())
}

fn session_state_label(session: &service::ConsoleSessionInfo) -> String {
    if let Some(exit_code) = session.exit_code {
        return format!("exited ({exit_code})");
    }
    if session.attached {
        return "attached".to_string();
    }
    let detached = match session.detached_secs {
        Some(secs) => format!("detached {secs}s"),
        None => "detached".to_string(),
    };
    match session.detach_timeout_secs {
        Some(timeout) => format!("{detached}, ends at {timeout}s"),
        None => detached,
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

pub(in crate::commands) fn run_detach(args: DetachArgs) -> Result<()> {
    let name = &args.name;
    let service::DetachResult {
        session_id,
        was_attached,
    } = service::detach(name)?;
    if was_attached {
        println!(
            "Detached the client from console session {session_id} on VM {name:?}; \
             the session keeps running."
        );
    } else {
        println!("Console session {session_id} on VM {name:?} has no client attached.");
    }
    Ok(())
}

static SIGWINCH_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Drop the sender to stop forwarding terminal resize signals.
fn setup_sigwinch_handler(resize: ConsoleResize) -> Option<std::sync::mpsc::Sender<()>> {
    use std::sync::atomic::Ordering;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    // SAFETY: the handler only stores to an atomic flag.
    unsafe {
        libc::signal(
            libc::SIGWINCH,
            sigwinch_handler as *const () as libc::sighandler_t,
        );
    }
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if let Err(std::sync::mpsc::TryRecvError::Disconnected) = rx.try_recv() {
                break;
            }
            if !SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) {
                continue;
            }
            let (cols, rows) = get_terminal_size();
            let _ = resize.resize(cols, rows);
        }
    });
    Some(tx)
}

fn get_terminal_size() -> (u16, u16) {
    // SAFETY: ioctl with valid fd (stdout).
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

fn enter_raw_mode() -> Result<libc::termios> {
    // SAFETY: termios pointers are initialized and valid for these calls.
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

fn restore_terminal(orig: &libc::termios) {
    // SAFETY: orig holds attributes obtained from tcgetattr.
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, orig);
    }
}

struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    fn enter() -> Result<Self> {
        let original = enter_raw_mode()?;
        IN_CONSOLE_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(Self { original })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        restore_terminal(&self.original);
        IN_CONSOLE_MODE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleEscape {
    Detach,
    Terminate,
}

/// Hold a leading tilde across reads; local escapes never reach the guest.
struct ConsoleEscapeFilter {
    at_line_start: bool,
    pending_tilde: bool,
}

impl ConsoleEscapeFilter {
    fn new() -> Self {
        Self {
            at_line_start: true,
            pending_tilde: false,
        }
    }

    fn filter(&mut self, input: &[u8], forwarded: &mut Vec<u8>) -> Option<ConsoleEscape> {
        for &byte in input {
            if self.pending_tilde {
                self.pending_tilde = false;
                match byte {
                    b'.' => return Some(ConsoleEscape::Terminate),
                    b'd' => return Some(ConsoleEscape::Detach),
                    _ => {}
                }
                forwarded.push(b'~');
                self.at_line_start = false;
            } else if self.at_line_start && byte == b'~' {
                self.pending_tilde = true;
                continue;
            }
            forwarded.push(byte);
            self.at_line_start = matches!(byte, b'\r' | b'\n');
        }
        None
    }
}

fn run_console_relay(data_stream: ConsoleData) -> Result<ConsoleRelayExit> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    let read_stream = data_stream
        .try_clone()
        .context("Failed to clone data stream")?;
    let write_stream = data_stream;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let vsock_fd = read_stream.as_raw_fd();
    // SAFETY: both descriptors are live for the duration of the relay.
    let orig_stdin_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    unsafe {
        libc::fcntl(stdin_fd, libc::F_SETFL, orig_stdin_flags | libc::O_NONBLOCK);
        libc::fcntl(vsock_fd, libc::F_SETFL, libc::O_NONBLOCK);
    }
    let mut stdout = std::io::stdout();
    let mut writer = write_stream;
    let mut buf = [0u8; 4096];
    let mut escape = ConsoleEscapeFilter::new();
    let outcome = loop {
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
        // SAFETY: fds is a live array of two poll descriptors.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if ret < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break ConsoleRelayExit::GuestClosed;
        }
        // Input goes first so sustained output cannot defer a local escape.
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut inbuf = [0u8; 1024];
            match std::io::stdin().read(&mut inbuf) {
                Ok(0) => break ConsoleRelayExit::InputClosed,
                Ok(n) => {
                    let mut forwarded = Vec::with_capacity(n);
                    let typed = escape.filter(&inbuf[..n], &mut forwarded);
                    if !forwarded.is_empty() && writer.write_all(&forwarded).is_err() {
                        break ConsoleRelayExit::GuestClosed;
                    }
                    let _ = writer.flush();
                    if let Some(typed) = typed {
                        let _ = writer.shutdown(std::net::Shutdown::Both);
                        break match typed {
                            ConsoleEscape::Detach => ConsoleRelayExit::Detach,
                            ConsoleEscape::Terminate => ConsoleRelayExit::Terminate,
                        };
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break ConsoleRelayExit::GuestClosed,
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            match (&read_stream).read(&mut buf) {
                Ok(0) => break ConsoleRelayExit::GuestClosed,
                Ok(n) => {
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break ConsoleRelayExit::GuestClosed,
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[1].revents & libc::POLLIN == 0
        {
            break ConsoleRelayExit::GuestClosed;
        }
    };
    // SAFETY: restore the live stdin descriptor's original status flags.
    unsafe {
        libc::fcntl(stdin_fd, libc::F_SETFL, orig_stdin_flags);
    }
    Ok(outcome)
}

#[cfg(test)]
mod console_relay_tests {
    use super::*;

    #[test]
    fn local_escape_is_recognized_across_input_chunks() {
        let mut escape = ConsoleEscapeFilter::new();
        let mut forwarded = Vec::new();
        assert_eq!(escape.filter(b"echo ready\r~", &mut forwarded), None);
        assert_eq!(
            escape.filter(b".", &mut forwarded),
            Some(ConsoleEscape::Terminate)
        );
        assert_eq!(forwarded, b"echo ready\r");
    }

    #[test]
    fn tilde_d_detaches_and_tilde_dot_terminates() {
        let mut forwarded = Vec::new();
        assert_eq!(
            ConsoleEscapeFilter::new().filter(b"~d", &mut forwarded),
            Some(ConsoleEscape::Detach)
        );
        assert_eq!(
            ConsoleEscapeFilter::new().filter(b"ls\n~.", &mut forwarded),
            Some(ConsoleEscape::Terminate)
        );
        assert_eq!(forwarded, b"ls\n", "neither escape reaches the guest");
    }

    #[test]
    fn escape_like_text_away_from_a_line_boundary_is_forwarded_verbatim() {
        let mut escape = ConsoleEscapeFilter::new();
        let mut forwarded = Vec::new();
        assert_eq!(escape.filter(b"printf '~.' ~d\r", &mut forwarded), None);
        assert_eq!(forwarded, b"printf '~.' ~d\r");
    }

    #[test]
    fn an_unrecognized_line_escape_is_forwarded_without_losing_bytes() {
        let mut escape = ConsoleEscapeFilter::new();
        let mut forwarded = Vec::new();
        assert_eq!(escape.filter(b"\r~x", &mut forwarded), None);
        assert_eq!(forwarded, b"\r~x");
    }

    #[test]
    fn session_states_read_as_the_operator_needs_them() {
        let mut info = service::ConsoleSessionInfo {
            session_id: 1,
            command: "/bin/sh".into(),
            attached: true,
            shareable: true,
            exit_code: None,
            scrollback_bytes: 2048,
            detached_secs: None,
            detach_timeout_secs: None,
        };
        assert_eq!(session_state_label(&info), "attached");
        info.attached = false;
        info.detached_secs = Some(40);
        info.detach_timeout_secs = Some(600);
        assert_eq!(session_state_label(&info), "detached 40s, ends at 600s");
        info.exit_code = Some(0);
        assert_eq!(session_state_label(&info), "exited (0)");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(12), "12 B");
    }

    #[test]
    fn client_completion_preserves_the_status_for_host_cleanup() {
        assert_eq!(
            render_completion(service::ExecCompletion {
                exit_code: 23,
                timed_out: false,
                binding_release_failed: false,
            }),
            23
        );
    }
}
