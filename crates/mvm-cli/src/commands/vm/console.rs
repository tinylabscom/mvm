//! `mvmctl console` — interactive console (PTY-over-vsock) and one-shot exec
//! via the guest agent.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vsock_transport::{
    DevConsoleTransport, FirecrackerTransport, LibkrunTransport, VsockTransport,
    firecracker_transport_supported,
};

use super::Cli;
use super::shared::{IN_CONSOLE_MODE, clap_vm_name};
use crate::ui;

/// Pick the right vsock transport for `name`. Priority:
/// 1. libkrun per-port Unix socket (also serves the libkrun dev VM).
/// 2. HVF runner (`WorkloadRunner` / HVF) agent socket at
///    `<vm_state_dir>/hvf-agent.sock`. This is workload-local; the
///    pre-opened console sockets exist only when the VM was booted with
///    `dev_console=true`.
/// 3. Firecracker UDS multiplexer (fleet/production path), only on native
///    Linux where resolving the Firecracker runtime dir is side-effect-free.
///
/// Each probe consumes one stream and drops it; the returned
/// `Arc<dyn VsockTransport>` is then used for every real connection
/// (control + data + resize). Cloning the Arc lets the SIGWINCH handler
/// thread reuse the same dispatch.
fn pick_console_transport(name: &str) -> Result<Arc<dyn VsockTransport>> {
    let libkrun = LibkrunTransport::for_vm(name);
    if libkrun.connect(mvm_agentd::vsock::GUEST_AGENT_PORT).is_ok() {
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
        if hvf.connect(mvm_agentd::vsock::GUEST_AGENT_PORT).is_ok() {
            return Ok(Arc::new(hvf));
        }
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
    !matches!(mvm_runtime::vm::runtime_meta::read(name), Ok(Some(meta)) if !meta.accessible)
}

/// How the interactive console's local escapes and disconnects behave. Shown
/// under `machine console --help` so the difference between ending a session
/// and leaving it is stated where the flag is.
pub(in crate::commands) const CONSOLE_SESSION_HELP: &str = "\
SESSIONS:
    A console session outlives its client. `machine console <name>` attaches to
    the VM's running session, replaying its recent output, or starts one if
    there is none. One client is attached at a time.

    Escapes (press Enter first; handled by mvmctl, never sent to the guest):
        ~d   detach: the shell keeps running; run `machine console <name>`
             again to reattach
        ~.   end the session: the shell is hung up and the console exits

    Closing the terminal or losing the connection also detaches. A session ends
    when its shell exits, when it is ended with `~.`, after --detach-timeout
    with no client attached, or when the VM stops.

    `machine console <name> --list` shows the session. `machine detach <name>`
    disconnects whoever is attached, and `--force` takes the session over
    from them.";

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

/// `machine detach <name>`: disconnect the client attached to a VM's console.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct DetachArgs {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
}

/// Composable inputs for one interactive console session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::commands) struct ConsoleSessionOptions {
    env: Vec<(String, String)>,
    argv: Vec<String>,
    take_over: bool,
    detach_timeout_secs: Option<u64>,
}

impl ConsoleSessionOptions {
    pub(in crate::commands) fn builder() -> ConsoleSessionOptionsBuilder {
        ConsoleSessionOptionsBuilder::default()
    }

    /// A session with its own program or environment is started for this
    /// caller alone; only the default shell is shared and reattached to.
    fn needs_dedicated_session(&self) -> bool {
        !self.argv.is_empty() || !self.env.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub(in crate::commands) struct ConsoleSessionOptionsBuilder {
    env: Vec<(String, String)>,
    argv: Vec<String>,
    take_over: bool,
    detach_timeout_secs: Option<u64>,
}

impl ConsoleSessionOptionsBuilder {
    #[must_use]
    pub(in crate::commands) fn env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    #[must_use]
    pub(in crate::commands) fn argv(mut self, argv: Vec<String>) -> Self {
        self.argv = argv;
        self
    }

    /// Hang up a client already attached to the shared session and attach in
    /// its place.
    #[must_use]
    pub(in crate::commands) fn take_over(mut self, take_over: bool) -> Self {
        self.take_over = take_over;
        self
    }

    /// End a session this attach creates once it has had no client for this
    /// many seconds.
    #[must_use]
    pub(in crate::commands) fn detach_timeout_secs(mut self, secs: Option<u64>) -> Self {
        self.detach_timeout_secs = secs;
        self
    }

    pub(in crate::commands) fn build(self) -> ConsoleSessionOptions {
        ConsoleSessionOptions {
            env: self.env,
            argv: self.argv,
            take_over: self.take_over,
            detach_timeout_secs: self.detach_timeout_secs,
        }
    }
}

/// Refuse to attach if the VM's image was built sealed (dev = false /
/// `passthru.mvm.accessible = false`). The state file is best-effort:
/// missing or legacy files without the field are treated as accessible.
///
/// Reused by `machine run -t` (claim 15: no interactive access to a sealed
/// production microVM).
pub(in crate::commands) fn enforce_accessible_gate(name: &str, force: bool) -> Result<()> {
    let _ = force;
    match mvm_runtime::vm::runtime_meta::read(name) {
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
    if args.list {
        return list_console_sessions(name);
    }
    // A console attach (one-shot exec or interactive PTY) is guest activity;
    // refresh idle tracking so an in-use session isn't idle-slept underneath
    // the user. Best-effort.
    touch_activity(name);

    if let Some(cmd) = command {
        let transport = pick_console_transport(name)?;
        let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
        // Inbound vsock RPC audit (verb=exec).
        super::shared::emit_vsock_rpc_audit(
            name,
            &mvm_agentd::vsock::GuestRequest::Exec {
                command: cmd.to_string(),
                stdin: None,
                timeout_secs: None,
            },
        );
        // send_exec_streaming does the protocol hello internally.
        use std::io::Write as _;
        let command = command_with_env(cmd, &args.env);
        let terminal =
            mvm_agentd::vsock::send_exec_streaming(&mut stream, &command, None, None, |event| {
                match event {
                    mvm_agentd::vsock::ExecEvent::Stdout { chunk } => {
                        let mut so = std::io::stdout();
                        let _ = so.write_all(chunk);
                        let _ = so.flush();
                    }
                    mvm_agentd::vsock::ExecEvent::Stderr { chunk } => {
                        let mut se = std::io::stderr();
                        let _ = se.write_all(chunk);
                        let _ = se.flush();
                    }
                    _ => {}
                }
            })?;
        match terminal {
            mvm_agentd::vsock::ExecEvent::Exit { code } => {
                if code != 0 {
                    mvm_observability::exit(code);
                }
                Ok(())
            }
            mvm_agentd::vsock::ExecEvent::TimedOut => {
                eprintln!("{}", crate::exec::timeout_exit_message(None));
                mvm_observability::exit(crate::exec::EXEC_TIMEOUT_EXIT_CODE);
            }
            other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
        }
    } else {
        // Interactive PTY session
        let options = ConsoleSessionOptions::builder()
            .env(args.env)
            .argv(args.pty_argv)
            .take_over(args.force)
            .detach_timeout_secs(args.detach_timeout)
            .build();
        let exit_code = console_interactive(name, options)?;
        if exit_code != 0 {
            mvm_observability::exit(exit_code);
        }
        Ok(())
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

/// Record a coarse guest-activity touch on the named VM, through the client
/// boundary (mvm-client owns the host-registry reach). Best-effort — a hiccup
/// never blocks console attach.
fn touch_activity(name: &str) {
    mvm_client::touch_activity(name);
}

/// Open an interactive PTY console to a running VM.
///
/// Supports Firecracker (via UDS vsock), libkrun (via per-port Unix
/// sockets), Apple Container (via direct vsock), and vsock proxy (via
/// daemon Unix socket for cross-process access).
pub(crate) fn console_pty_command(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<()> {
    let exit_code = run_pty_command_for_exit(name, command, env)?;
    if exit_code != 0 {
        mvm_observability::exit(exit_code);
    }
    Ok(())
}

pub(crate) fn run_pty_command_for_exit(
    name: &str,
    command: String,
    env: Vec<(String, String)>,
) -> Result<i32> {
    console_interactive(
        name,
        ConsoleSessionOptions::builder()
            .env(env)
            .argv(shell_command_argv(command))
            .build(),
    )
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

fn shell_command_argv(command: String) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-lc".to_string(), command]
}

pub(in crate::commands) fn console_interactive(
    name: &str,
    options: ConsoleSessionOptions,
) -> Result<i32> {
    let (cols, rows) = get_terminal_size();
    let transport = pick_console_transport(name)?;

    let attached = if options.needs_dedicated_session() {
        ui::info(&format!(
            "Opening console to VM {name:?} ({cols}x{rows})..."
        ));
        open_session(&transport, name, &options, (cols, rows))?
    } else {
        attach_or_open(&transport, name, &options, (cols, rows))?
    };
    let session_id = attached.session_id;

    // Small delay to let the guest agent bind the data port.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let data_stream = transport
        .connect(attached.data_port)
        .context("Failed to connect to console data port")?;

    mvm_core::audit_emit!(
        ConsoleSessionStart,
        vm: name,
        "session_id={session_id} attach={}",
        attached.kind.audit_label()
    );

    // Set up SIGWINCH handler to forward terminal resizes
    let resize_sender = setup_sigwinch_handler(transport.clone(), session_id);

    // Enter raw terminal mode and suppress the Ctrl-C handler so that Ctrl+C
    // is forwarded as a raw byte (\x03) to the guest shell instead of killing
    // mvmctl. The guard restores both pieces of process state on every return.
    let raw_terminal = RawTerminalGuard::enter()?;
    let result = run_console_relay(data_stream);

    // Restore terminal and clean up
    drop(raw_terminal);
    drop(resize_sender);

    let ending = finish_session(&transport, name, session_id, result?);
    let outcome = match &ending {
        Ok(ending) => ending.audit_label(),
        Err(_) => "error",
    };
    mvm_core::audit_emit!(
        ConsoleSessionEnd,
        vm: name,
        "session_id={session_id} outcome={outcome}"
    );
    match ending? {
        SessionEnding::Exited(exit_code) => {
            println!("\nConsole session ended.");
            Ok(exit_code)
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

/// How this client came to be attached, recorded in the audit entry that
/// opens its console span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachKind {
    Opened,
    Reattached,
    TookOver,
}

impl AttachKind {
    fn audit_label(self) -> &'static str {
        match self {
            Self::Opened => "open",
            Self::Reattached => "reattach",
            Self::TookOver => "take-over",
        }
    }
}

/// A session this client holds the attach reservation for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttachedSession {
    session_id: u32,
    data_port: u32,
    kind: AttachKind,
}

/// How an interactive console span finished, from this client's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnding {
    /// The shell exited with this code.
    Exited(i32),
    /// This client ended the session with `~.`.
    Terminated,
    /// This client detached with `~d`; the shell runs on.
    Detached,
    /// The guest hung this client up while the shell ran on: another client
    /// took over, or `machine detach` was used.
    Displaced,
}

impl SessionEnding {
    fn audit_label(self) -> &'static str {
        match self {
            Self::Exited(_) => "exited",
            Self::Terminated => "terminated",
            Self::Detached => "detached",
            Self::Displaced => "displaced",
        }
    }
}

/// A control-channel connection that has confirmed the agent serves consoles.
fn console_control(transport: &Arc<dyn VsockTransport>) -> Result<std::os::unix::net::UnixStream> {
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    mvm_agentd::vsock::require_capabilities(
        &mut stream,
        &[mvm_agentd::vsock::GuestCapability::Console],
    )?;
    Ok(stream)
}

/// Send one console request, audited through the same inbound-RPC record every
/// host→guest verb gets.
fn console_call(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    req: &mvm_agentd::vsock::GuestRequest,
) -> Result<mvm_agentd::vsock::GuestResponse> {
    let mut stream = console_control(transport)?;
    super::shared::emit_vsock_rpc_audit(name, req);
    match mvm_agentd::vsock::call_unary(&mut stream, req)? {
        mvm_agentd::vsock::GuestResponse::Error { message } => anyhow::bail!("{message}"),
        other => Ok(other),
    }
}

fn open_session(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    options: &ConsoleSessionOptions,
    (cols, rows): (u16, u16),
) -> Result<AttachedSession> {
    let req = mvm_agentd::vsock::GuestRequest::ConsoleOpen {
        cols,
        rows,
        env: options.env.clone(),
        argv: options.argv.clone(),
        detach_timeout_secs: options.detach_timeout_secs,
    };
    match console_call(transport, name, &req)? {
        mvm_agentd::vsock::GuestResponse::ConsoleOpened {
            session_id,
            data_port,
        } => {
            ui::info(&format!(
                "Console session {session_id} opened, connecting to data port {data_port}..."
            ));
            Ok(AttachedSession {
                session_id,
                data_port,
                kind: AttachKind::Opened,
            })
        }
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
}

/// Attach to the VM's running console session, or start one when it has none.
fn attach_or_open(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    options: &ConsoleSessionOptions,
    size: (u16, u16),
) -> Result<AttachedSession> {
    let running = fetch_sessions(transport, name)?
        .into_iter()
        .find(|session| session.exit_code.is_none());
    let Some(session) = running else {
        ui::info(&format!(
            "Opening console to VM {name:?} ({}x{})...",
            size.0, size.1
        ));
        return open_session(transport, name, options, size);
    };
    let req = mvm_agentd::vsock::GuestRequest::ConsoleAttach {
        session_id: session.session_id,
        cols: size.0,
        rows: size.1,
        take_over: options.take_over,
    };
    match console_call(transport, name, &req)? {
        mvm_agentd::vsock::GuestResponse::ConsoleAttached {
            session_id,
            data_port,
            replay_bytes,
        } => {
            ui::info(&format!(
                "Reattaching to console session {session_id} on VM {name:?} \
                 (replaying {replay_bytes} bytes of scrollback)..."
            ));
            Ok(AttachedSession {
                session_id,
                data_port,
                kind: if session.attached {
                    AttachKind::TookOver
                } else {
                    AttachKind::Reattached
                },
            })
        }
        mvm_agentd::vsock::GuestResponse::ConsoleBusy { session_id } => {
            Err(busy_refusal(name, session_id))
        }
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
}

fn busy_refusal(name: &str, session_id: u32) -> anyhow::Error {
    anyhow::anyhow!(
        "console session {session_id} on VM {name:?} already has a client attached. \
         Pass --force to take it over (that client is detached; the shell keeps running), \
         or disconnect it with `mvmctl machine detach {name}`."
    )
}

fn fetch_sessions(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
) -> Result<Vec<mvm_agentd::vsock::ConsoleSessionInfo>> {
    match console_call(
        transport,
        name,
        &mvm_agentd::vsock::GuestRequest::ConsoleList,
    )? {
        mvm_agentd::vsock::GuestResponse::ConsoleSessions { sessions } => Ok(sessions),
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
}

/// Settle what the relay's exit means for the session.
fn finish_session(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    session_id: u32,
    exit: ConsoleRelayExit,
) -> Result<SessionEnding> {
    match exit {
        ConsoleRelayExit::Detach => Ok(SessionEnding::Detached),
        ConsoleRelayExit::Terminate => {
            terminate_console(transport, name, session_id)?;
            Ok(SessionEnding::Terminated)
        }
        ConsoleRelayExit::InputClosed => {
            let exit_code = terminate_console(transport, name, session_id)?;
            Ok(SessionEnding::Exited(exit_code))
        }
        ConsoleRelayExit::GuestClosed => {
            let status = session_status(transport, name, session_id);
            let machine_stopped = status.is_err() && wait_for_console_machine_stop(name);
            classify_guest_close(status, machine_stopped)
        }
    }
}

/// End the session and return the shell's exit code. A VM that stopped
/// underneath the request has ended the session just as surely.
fn terminate_console(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    session_id: u32,
) -> Result<i32> {
    let req = mvm_agentd::vsock::GuestRequest::ConsoleClose { session_id };
    let completion = console_call(transport, name, &req).and_then(|response| match response {
        mvm_agentd::vsock::GuestResponse::ConsoleExited { exit_code, .. } => Ok(exit_code),
        other => anyhow::bail!("Unexpected response: {other:?}"),
    });
    let machine_stopped = completion.is_err() && wait_for_console_machine_stop(name);
    classify_console_completion(completion, machine_stopped)
}

/// What the guest says about `session_id` after it closed this client's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionStatus {
    Exited(i32),
    Running,
    Gone,
}

fn session_status(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    session_id: u32,
) -> Result<SessionStatus> {
    let sessions = fetch_sessions(transport, name)?;
    Ok(match sessions.iter().find(|s| s.session_id == session_id) {
        Some(session) => session
            .exit_code
            .map_or(SessionStatus::Running, SessionStatus::Exited),
        None => SessionStatus::Gone,
    })
}

/// The guest closed this client's stream. Either the shell exited — the guest
/// records its code before hanging up, so it is there to read — or the
/// session is still running and this client was displaced.
fn classify_guest_close(
    status: Result<SessionStatus>,
    machine_stopped: bool,
) -> Result<SessionEnding> {
    match status {
        Ok(SessionStatus::Exited(exit_code)) => Ok(SessionEnding::Exited(exit_code)),
        Ok(SessionStatus::Running) => Ok(SessionEnding::Displaced),
        Ok(SessionStatus::Gone) => {
            anyhow::bail!("the console session disappeared from the guest agent")
        }
        Err(error) => {
            classify_console_completion(Err(error), machine_stopped).map(SessionEnding::Exited)
        }
    }
}

/// `machine console <name> --list`.
fn list_console_sessions(name: &str) -> Result<()> {
    let transport = pick_console_transport(name)?;
    let sessions = fetch_sessions(&transport, name)?;
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

fn session_state_label(session: &mvm_agentd::vsock::ConsoleSessionInfo) -> String {
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

/// `machine detach <name>`: hang up whichever client is attached to the VM's
/// running console session. Authorized exactly like an attach.
pub(in crate::commands) fn run_detach(args: DetachArgs) -> Result<()> {
    let name = &args.name;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {name:?}"))?;
    enforce_accessible_gate(name, false)?;
    let transport = pick_console_transport(name)?;
    let Some(session) = fetch_sessions(&transport, name)?
        .into_iter()
        .find(|session| session.exit_code.is_none())
    else {
        anyhow::bail!("VM {name:?} has no running console session");
    };
    let req = mvm_agentd::vsock::GuestRequest::ConsoleDetach {
        session_id: session.session_id,
    };
    match console_call(&transport, name, &req)? {
        mvm_agentd::vsock::GuestResponse::ConsoleDetached {
            session_id,
            was_attached: true,
        } => {
            mvm_core::audit_emit!(
                ConsoleSessionEnd,
                vm: name,
                "session_id={session_id} outcome=detached-remotely"
            );
            println!(
                "Detached the client from console session {session_id} on VM {name:?}; \
                 the session keeps running."
            );
            Ok(())
        }
        mvm_agentd::vsock::GuestResponse::ConsoleDetached {
            session_id,
            was_attached: false,
        } => {
            println!("Console session {session_id} on VM {name:?} has no client attached.");
            Ok(())
        }
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
}

fn wait_for_console_machine_stop(name: &str) -> bool {
    const ATTEMPTS: usize = 40;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);

    for attempt in 0..ATTEMPTS {
        let still_present = mvm_client::LocalBackend::new()
            .list_stop_targets()
            .iter()
            .any(|machine| machine.id.0 == name);
        if !still_present {
            return true;
        }
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(RETRY_DELAY);
        }
    }
    false
}

fn classify_console_completion(completion: Result<i32>, machine_stopped: bool) -> Result<i32> {
    match completion {
        Ok(exit_code) => Ok(exit_code),
        Err(error) if machine_stopped => {
            tracing::debug!(
                error = %error,
                "console exit-code channel closed after the machine stopped"
            );
            Ok(0)
        }
        Err(error) => Err(error),
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
            let _ = console_control(&transport).ok().and_then(|mut stream| {
                mvm_agentd::vsock::send_request(
                    &mut stream,
                    &mvm_agentd::vsock::GuestRequest::ConsoleResize {
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

/// Restores the caller's terminal and Ctrl-C disposition on every return path.
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
enum ConsoleRelayExit {
    /// The guest closed the data stream.
    GuestClosed,
    /// Local stdin reached end of file.
    InputClosed,
    /// The operator typed `~d`.
    Detach,
    /// The operator typed `~.`.
    Terminate,
}

/// A local escape the operator typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleEscape {
    /// `~d`: leave the session running.
    Detach,
    /// `~.`: end the session.
    Terminate,
}

/// Recognizes the documented SSH-style local escapes without sending them
/// through the guest channel. A leading `~` is held until the next byte so an
/// escape can span terminal reads; every other sequence is forwarded
/// byte-for-byte.
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

    /// Append bytes for the guest to `forwarded`; return the escape, if one
    /// was typed. Bytes after an escape in the same read are not forwarded.
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

/// Relay raw bytes between stdin/stdout and a vsock data stream.
///
/// Exits when the guest closes the connection (e.g. `exit` or Ctrl+D
/// in the shell), when stdin ends, or when the user types an escape after
/// Enter: `~d` to detach, `~.` to end the session (same shape as SSH's).
///
fn run_console_relay(data_stream: std::os::unix::net::UnixStream) -> Result<ConsoleRelayExit> {
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
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if ret < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break ConsoleRelayExit::GuestClosed;
        }

        // Check input first so sustained guest output cannot defer a local
        // escape or an interrupt byte behind terminal rendering.
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
                        // Either way this client leaves the data stream; the
                        // guest treats that as a detach, and `~.` then ends
                        // the session explicitly over the control channel.
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

        // vsock → stdout (guest output)
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

    // Restore stdin's original file-status flags before returning to the shell.
    unsafe {
        libc::fcntl(stdin_fd, libc::F_SETFL, orig_stdin_flags);
    }

    Ok(outcome)
}

#[cfg(test)]
mod console_relay_tests {
    use super::*;

    #[test]
    fn session_options_compose_environment_and_argv() {
        let options = ConsoleSessionOptions::builder()
            .env(vec![("TERM".to_string(), "xterm-256color".to_string())])
            .argv(vec!["/bin/sh".to_string(), "-l".to_string()])
            .build();

        assert_eq!(
            options.env,
            vec![("TERM".to_string(), "xterm-256color".to_string())]
        );
        assert_eq!(options.argv, vec!["/bin/sh".to_string(), "-l".to_string()]);
    }

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
    fn a_guest_close_after_the_shell_exited_reports_its_code() {
        let ending = classify_guest_close(Ok(SessionStatus::Exited(7)), false).unwrap();
        assert_eq!(ending, SessionEnding::Exited(7));
    }

    #[test]
    fn a_guest_close_while_the_shell_runs_is_a_displacement_not_an_exit() {
        // Another client took over, or `machine detach` ran. This client must
        // not end the session it was displaced from.
        let ending = classify_guest_close(Ok(SessionStatus::Running), false).unwrap();
        assert_eq!(ending, SessionEnding::Displaced);
    }

    #[test]
    fn a_guest_close_with_the_session_gone_is_an_error() {
        assert!(classify_guest_close(Ok(SessionStatus::Gone), false).is_err());
    }

    #[test]
    fn a_guest_close_on_a_stopped_machine_is_a_clean_end() {
        let ending =
            classify_guest_close(Err(anyhow::anyhow!("Failed to read frame length")), true)
                .unwrap();
        assert_eq!(ending, SessionEnding::Exited(0));
    }

    #[test]
    fn every_ending_has_a_distinct_audit_outcome() {
        let labels: std::collections::BTreeSet<_> = [
            SessionEnding::Exited(0),
            SessionEnding::Terminated,
            SessionEnding::Detached,
            SessionEnding::Displaced,
        ]
        .into_iter()
        .map(SessionEnding::audit_label)
        .collect();
        assert_eq!(labels.len(), 4);
        assert_eq!(AttachKind::Reattached.audit_label(), "reattach");
        assert_eq!(AttachKind::TookOver.audit_label(), "take-over");
        assert_eq!(AttachKind::Opened.audit_label(), "open");
    }

    #[test]
    fn only_the_default_shell_is_shared_between_clients() {
        assert!(!ConsoleSessionOptions::default().needs_dedicated_session());
        assert!(
            ConsoleSessionOptions::builder()
                .argv(vec![
                    "/bin/sh".to_string(),
                    "-lc".to_string(),
                    "make".to_string()
                ])
                .build()
                .needs_dedicated_session()
        );
        assert!(
            ConsoleSessionOptions::builder()
                .env(vec![("K".to_string(), "v".to_string())])
                .build()
                .needs_dedicated_session()
        );
        assert!(
            !ConsoleSessionOptions::builder()
                .take_over(true)
                .detach_timeout_secs(Some(60))
                .build()
                .needs_dedicated_session()
        );
    }

    #[test]
    fn session_states_read_as_the_operator_needs_them() {
        let mut info = mvm_agentd::vsock::ConsoleSessionInfo {
            session_id: 1,
            command: "/bin/sh".to_string(),
            attached: true,
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
    fn a_busy_refusal_names_both_ways_out() {
        let message = busy_refusal("dev", 3).to_string();
        assert!(message.contains("--force"), "{message}");
        assert!(message.contains("mvmctl machine detach dev"), "{message}");
    }

    #[test]
    fn stopped_machine_turns_a_lost_exit_code_reply_into_a_clean_console_end() {
        let result =
            classify_console_completion(Err(anyhow::anyhow!("Failed to read frame length")), true);

        assert_eq!(result.expect("stopped VM is a clean console end"), 0);
    }

    #[test]
    fn running_machine_preserves_a_lost_exit_code_reply_as_an_error() {
        let result =
            classify_console_completion(Err(anyhow::anyhow!("Failed to read frame length")), false);

        let error = result.expect_err("a live VM must not hide a control-plane failure");
        assert!(error.to_string().contains("Failed to read frame length"));
    }

    #[test]
    fn an_absent_machine_is_confirmed_as_stopped() {
        assert!(wait_for_console_machine_stop(
            "console-completion-machine-that-does-not-exist"
        ));
    }
}

#[cfg(test)]
mod accessible_gate_tests {
    use super::*;
    use mvm_runtime::vm::runtime_meta::{StartModeKind, VmRuntimeMeta, write as write_meta};

    fn with_home<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("HOME", tmp.path());
        env.set("MVM_HOME", tmp.path());
        f(tmp.path());
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
                    runtime_overlay_version: None,
                    observability_target: None,
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
        env.set("MVM_HOME", tmp.path());

        let path = mvm_runtime::vm::name_registry::registry_path();
        let mut reg = mvm_runtime::vm::name_registry::VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        reg.save(&path).unwrap();
        assert!(reg.lookup("vm1").unwrap().last_active.is_none());

        touch_activity("vm1");
        let reloaded = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).unwrap();
        assert!(
            reloaded.lookup("vm1").unwrap().last_active.is_some(),
            "console attach must refresh last_active"
        );

        // Unknown name is a clean no-op — no panic, registry untouched.
        touch_activity("ghost");
        let reloaded = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).unwrap();
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
                    runtime_overlay_version: None,
                    observability_target: None,
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
                    runtime_overlay_version: None,
                    observability_target: None,
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
                    runtime_overlay_version: None,
                    observability_target: None,
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
    /// `MVM_HOME` so `vm_state_dir` resolves there. Returns the guard
    /// objects that keep the socket and env alive for the test.
    fn setup_hvf_agent(
        name: &str,
    ) -> (
        tempfile::TempDir,
        mvm_core::util::test_env::TestEnv,
        Option<UnixListener>,
    ) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").expect("state tempdir");
        env.set("MVM_HOME", tmp.path());
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let listener = match UnixListener::bind(&agent) {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping hvf console picker unix listener test: {err}");
                None
            }
            Err(err) => panic!("bind hvf agent socket: {err}"),
        };
        (tmp, env, listener)
    }

    #[test]
    fn pick_console_transport_selects_hvf_for_workload() {
        let name = "hvf-dev-workload";
        let (_tmp, _env, listener) = setup_hvf_agent(name);
        if listener.is_none() {
            return;
        }

        let transport = pick_console_transport(name).expect("picker must resolve hvf transport");
        transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .expect("selected transport must connect to hvf-agent.sock");
    }

    // A sealed workload must not route to the hvf console even with
    // `hvf-agent.sock` present. It falls through to the HVF per-port vsock
    // transport / Firecracker, so a sealed prod runner never receives an
    // interactive attach.
    #[test]
    fn pick_console_transport_skips_hvf_for_sealed_workload() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").expect("state tempdir");
        env.set("MVM_HOME", tmp.path());

        let name = "hvf-sealed-workload";
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let _listener = match UnixListener::bind(&agent) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping hvf console picker unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind hvf agent socket: {err}"),
        };

        // Mark the image sealed.
        mvm_runtime::vm::runtime_meta::write(
            name,
            &mvm_runtime::vm::runtime_meta::VmRuntimeMeta {
                mode: mvm_runtime::vm::runtime_meta::StartModeKind::Attached,
                accessible: false,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
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
                        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
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
        env.set("MVM_HOME", tmp.path());
        // Deliberately NOT dev mode.
        env.set("MVM_ENV", "prod");

        let name = "hvf-accessible-workload";
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).unwrap();
        let agent = mvm_core::config::vm_hvf_agent_socket(name);
        let _listener = match UnixListener::bind(&agent) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping hvf console picker unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind hvf agent socket: {err}"),
        };
        // No runtime_meta written → accessible by the backward-compat default.

        let transport = pick_console_transport(name)
            .expect("accessible workload must resolve the hvf transport");
        transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .expect("selected transport must connect to the workload agent socket");
    }
}
