//! Console access policy and host-side console service.
use anyhow::{Context, Result};
use mvm_core::naming::validate_vm_name;
use mvm_runtime::vsock_transport::{
    DevConsoleTransport, FirecrackerTransport, LibkrunTransport, VsockTransport,
    firecracker_transport_supported,
};
use std::sync::Arc;

/// Check console access without connecting, touching activity, or emitting a
/// success audit. Force only permits taking over an attached client; it never
/// overrides a sealed image. Missing legacy metadata remains accessible.
pub fn enforce_accessible_gate(name: &str, force: bool) -> Result<()> {
    let _ = force;
    validate_vm_name(name).context("invalid VM name for console")?;
    match mvm_runtime::vm::runtime_meta::read(name) {
        Ok(Some(meta)) if !meta.accessible => anyhow::bail!(
            "console refused: VM {name:?} was built from a sealed image (passthru.mvm.accessible = false). \
             Sealed images don't ship the dev agent surface. \
             Rebuild with `dev = true` for interactive development."
        ),
        _ => Ok(()),
    }
}

fn hvf_console_arm_enabled(name: &str) -> bool {
    !matches!(mvm_runtime::vm::runtime_meta::read(name), Ok(Some(meta)) if !meta.accessible)
}

fn pick_console_transport(name: &str) -> Result<Arc<dyn VsockTransport>> {
    let libkrun = LibkrunTransport::for_vm(name);
    if libkrun.connect(mvm_agentd::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Arc::new(libkrun));
    }
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

/// Inputs for an interactive console. Only an uncustomized shell is shared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsoleSessionOptions {
    env: Vec<(String, String)>,
    argv: Vec<String>,
    take_over: bool,
    detach_timeout_secs: Option<u64>,
}

impl ConsoleSessionOptions {
    pub fn builder() -> ConsoleSessionOptionsBuilder {
        ConsoleSessionOptionsBuilder::default()
    }

    fn needs_dedicated_session(&self) -> bool {
        !self.argv.is_empty() || !self.env.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConsoleSessionOptionsBuilder(ConsoleSessionOptions);

impl ConsoleSessionOptionsBuilder {
    #[must_use]
    pub fn env(mut self, env: Vec<(String, String)>) -> Self {
        self.0.env = env;
        self
    }

    #[must_use]
    pub fn argv(mut self, argv: Vec<String>) -> Self {
        self.0.argv = argv;
        self
    }

    #[must_use]
    pub fn take_over(mut self, take_over: bool) -> Self {
        self.0.take_over = take_over;
        self
    }

    #[must_use]
    pub fn detach_timeout_secs(mut self, secs: Option<u64>) -> Self {
        self.0.detach_timeout_secs = secs;
        self
    }

    pub fn build(self) -> ConsoleSessionOptions {
        self.0
    }
}

/// Owned view of a guest console, independent of the wire schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSessionInfo {
    pub session_id: u32,
    pub command: String,
    pub attached: bool,
    pub shareable: bool,
    pub exit_code: Option<i32>,
    pub scrollback_bytes: u64,
    pub detached_secs: Option<u64>,
    pub detach_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleRelayExit {
    Detach,
    Terminate,
    InputClosed,
    GuestClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnding {
    Exited(i32),
    Terminated,
    Detached,
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

fn console_control(transport: &Arc<dyn VsockTransport>) -> Result<std::os::unix::net::UnixStream> {
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    mvm_agentd::vsock::require_capabilities(
        &mut stream,
        &[mvm_agentd::vsock::GuestCapability::Console],
    )?;
    Ok(stream)
}

fn console_call(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    req: &mvm_agentd::vsock::GuestRequest,
) -> Result<mvm_agentd::vsock::GuestResponse> {
    let mut stream = console_control(transport)?;
    crate::guest::emit_vsock_rpc_audit(name, req);
    match mvm_agentd::vsock::call_unary(&mut stream, req)? {
        mvm_agentd::vsock::GuestResponse::Error { .. } => {
            anyhow::bail!("guest refused console request")
        }
        other => Ok(other),
    }
}

fn fetch_sessions(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
) -> Result<Vec<ConsoleSessionInfo>> {
    match console_call(
        transport,
        name,
        &mvm_agentd::vsock::GuestRequest::ConsoleList,
    )? {
        mvm_agentd::vsock::GuestResponse::ConsoleSessions { sessions } => Ok(sessions
            .into_iter()
            .map(|s| ConsoleSessionInfo {
                session_id: s.session_id,
                command: s.command,
                attached: s.attached,
                shareable: s.shareable,
                exit_code: s.exit_code,
                scrollback_bytes: s.scrollback_bytes,
                detached_secs: s.detached_secs,
                detach_timeout_secs: s.detach_timeout_secs,
            })
            .collect()),
        _ => anyhow::bail!("unexpected console list response"),
    }
}

pub fn list_sessions(name: &str) -> Result<Vec<ConsoleSessionInfo>> {
    enforce_accessible_gate(name, false)?;
    fetch_sessions(&pick_console_transport(name)?, name)
}

/// A cloneable resize capability scoped to this session, not a raw transport.
#[derive(Clone)]
pub struct ConsoleResize {
    transport: Arc<dyn VsockTransport>,
    session_id: u32,
}

impl ConsoleResize {
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let mut stream = console_control(&self.transport)?;
        mvm_agentd::vsock::send_request(
            &mut stream,
            &mvm_agentd::vsock::GuestRequest::ConsoleResize {
                session_id: self.session_id,
                cols,
                rows,
            },
        )?;
        Ok(())
    }
}

/// Opaque, session-scoped byte channel. The CLI may poll and render bytes but
/// cannot select a transport, connect arbitrary ports, or issue control RPCs.
pub struct ConsoleData(std::os::unix::net::UnixStream);

impl ConsoleData {
    pub fn try_clone(&self) -> std::io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.0.shutdown(how)
    }
}

impl std::os::fd::AsRawFd for ConsoleData {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.0)
    }
}

impl std::io::Read for &ConsoleData {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut &self.0, buf)
    }
}

impl std::io::Write for ConsoleData {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)
    }
}

/// An attached console. Dropping the data channel detaches; only explicit
/// termination closes the guest shell.
pub struct ConsoleSession {
    name: String,
    resize: ConsoleResize,
    data: Option<ConsoleData>,
    finished: bool,
}

impl ConsoleSession {
    pub fn session_id(&self) -> u32 {
        self.resize.session_id
    }

    pub fn resize_handle(&self) -> ConsoleResize {
        self.resize.clone()
    }

    pub fn take_data(&mut self) -> Result<ConsoleData> {
        self.data
            .take()
            .context("console data channel already taken")
    }

    pub fn finish(mut self, exit: ConsoleRelayExit) -> Result<SessionEnding> {
        let ending = finish_session(&self.resize.transport, &self.name, self.session_id(), exit);
        self.finished = true;
        let outcome = ending
            .as_ref()
            .map_or("error", |ending| ending.audit_label());
        let session_id = self.session_id();
        mvm_core::audit_emit!(
            ConsoleSessionEnd,
            vm: &self.name,
            "session_id={session_id} outcome={outcome}"
        );
        ending
    }
}

impl Drop for ConsoleSession {
    fn drop(&mut self) {
        if !self.finished {
            let session_id = self.session_id();
            mvm_core::audit_emit!(
                ConsoleSessionEnd,
                vm: &self.name,
                "session_id={session_id} outcome=error"
            );
        }
    }
}

/// Hold a console to the application terminal the machine's plan admits, if
/// it admits one: the granted argv and the host-provisioned environment
/// replace the defaults, and another program or caller variables are refused
/// before anything reaches the guest.
fn with_application_terminal(
    name: &str,
    mut options: ConsoleSessionOptions,
) -> Result<ConsoleSessionOptions> {
    let resolved = crate::application_terminal::resolve_terminal_request(
        name,
        crate::application_terminal::TerminalRequest {
            argv: std::mem::take(&mut options.argv),
            env: std::mem::take(&mut options.env),
        },
    )?;
    options.argv = resolved.argv;
    options.env = resolved.env;
    Ok(options)
}

pub fn open(
    name: &str,
    options: ConsoleSessionOptions,
    (cols, rows): (u16, u16),
) -> Result<ConsoleSession> {
    enforce_accessible_gate(name, options.take_over)?;
    let options = with_application_terminal(name, options)?;
    crate::touch_activity(name);
    let transport = pick_console_transport(name)?;
    let running = if options.needs_dedicated_session() {
        None
    } else {
        fetch_sessions(&transport, name)?
            .into_iter()
            .find(|session| session.exit_code.is_none() && session.shareable)
    };
    let req = match running {
        Some(session) => mvm_agentd::vsock::GuestRequest::ConsoleAttach {
            session_id: session.session_id,
            cols,
            rows,
            take_over: options.take_over,
        },
        None => mvm_agentd::vsock::GuestRequest::ConsoleOpen {
            cols,
            rows,
            env: options.env,
            argv: options.argv,
            detach_timeout_secs: options.detach_timeout_secs,
        },
    };
    let (session_id, data_port, kind) = match console_call(&transport, name, &req)? {
        mvm_agentd::vsock::GuestResponse::ConsoleOpened {
            session_id,
            data_port,
        } => (session_id, data_port, AttachKind::Opened),
        mvm_agentd::vsock::GuestResponse::ConsoleAttached {
            session_id,
            data_port,
            displaced_existing,
            ..
        } => (
            session_id,
            data_port,
            if displaced_existing {
                AttachKind::TookOver
            } else {
                AttachKind::Reattached
            },
        ),
        mvm_agentd::vsock::GuestResponse::ConsoleBusy { session_id } => {
            return Err(busy_refusal(name, session_id));
        }
        _ => anyhow::bail!("unexpected console attach response"),
    };
    // Compatibility delay: the guest owns the data listener and starts it
    // after sending the open response.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let data = match transport.connect(data_port) {
        Ok(stream) => ConsoleData(stream),
        Err(error) => {
            // An open reservation must not strand a dedicated shell if the
            // data connection fails. Reattached shells must remain alive.
            if kind == AttachKind::Opened {
                let _ = terminate_console(&transport, name, session_id);
            }
            return Err(error).context("Failed to connect to console data port");
        }
    };
    mvm_core::audit_emit!(
        ConsoleSessionStart,
        vm: name,
        "session_id={session_id} attach={}",
        kind.audit_label()
    );
    Ok(ConsoleSession {
        name: name.to_owned(),
        resize: ConsoleResize {
            transport,
            session_id,
        },
        data: Some(data),
        finished: false,
    })
}

fn busy_refusal(name: &str, session_id: u32) -> anyhow::Error {
    anyhow::anyhow!(
        "console session {session_id} on VM {name:?} already has a client attached. \
         Pass --force to take it over (that client is detached; the shell keeps running), \
         or disconnect it with `mvmctl machine detach {name}`."
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachResult {
    pub session_id: u32,
    pub was_attached: bool,
}

pub fn detach(name: &str) -> Result<DetachResult> {
    enforce_accessible_gate(name, false)?;
    let transport = pick_console_transport(name)?;
    let session = fetch_sessions(&transport, name)?
        .into_iter()
        .find(|session| session.exit_code.is_none())
        .with_context(|| format!("VM {name:?} has no running console session"))?;
    let req = mvm_agentd::vsock::GuestRequest::ConsoleDetach {
        session_id: session.session_id,
    };
    match console_call(&transport, name, &req)? {
        mvm_agentd::vsock::GuestResponse::ConsoleDetached {
            session_id,
            was_attached,
        } => {
            if was_attached {
                mvm_core::audit_emit!(
                    ConsoleSessionEnd,
                    vm: name,
                    "session_id={session_id} outcome=detached-remotely"
                );
            }
            Ok(DetachResult {
                session_id,
                was_attached,
            })
        }
        _ => anyhow::bail!("unexpected console detach response"),
    }
}

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
            terminate_console(transport, name, session_id).map(SessionEnding::Exited)
        }
        ConsoleRelayExit::GuestClosed => {
            let status = session_status(transport, name, session_id);
            let machine_stopped = status.is_err() && wait_for_console_machine_stop(name);
            classify_guest_close(status, machine_stopped)
        }
    }
}

fn terminate_console(
    transport: &Arc<dyn VsockTransport>,
    name: &str,
    session_id: u32,
) -> Result<i32> {
    let req = mvm_agentd::vsock::GuestRequest::ConsoleClose { session_id };
    let completion = console_call(transport, name, &req).and_then(|response| match response {
        mvm_agentd::vsock::GuestResponse::ConsoleExited { exit_code, .. } => Ok(exit_code),
        _ => anyhow::bail!("unexpected console close response"),
    });
    let machine_stopped = completion.is_err() && wait_for_console_machine_stop(name);
    classify_console_completion(completion, machine_stopped)
}

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

fn classify_guest_close(
    status: Result<SessionStatus>,
    machine_stopped: bool,
) -> Result<SessionEnding> {
    match status {
        Ok(SessionStatus::Exited(code)) => Ok(SessionEnding::Exited(code)),
        Ok(SessionStatus::Running) => Ok(SessionEnding::Displaced),
        Ok(SessionStatus::Gone) => {
            anyhow::bail!("the console session disappeared from the guest agent")
        }
        Err(error) => {
            classify_console_completion(Err(error), machine_stopped).map(SessionEnding::Exited)
        }
    }
}

fn wait_for_console_machine_stop(name: &str) -> bool {
    const ATTEMPTS: usize = 40;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
    for attempt in 0..ATTEMPTS {
        let still_present = crate::LocalBackend::new()
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
            tracing::debug!(error = %error, "console exit-code channel closed after the machine stopped");
            Ok(0)
        }
        Err(error) => Err(error),
    }
}

/// Output chunks are delivered as they arrive; the service does not accumulate
/// unbounded guest output. Protocol errors never format guest payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecCompletion {
    pub exit_code: i32,
    pub timed_out: bool,
    pub binding_release_failed: bool,
}

fn emit_exec_event(event: &mvm_agentd::vsock::ExecEvent, emit: &mut impl FnMut(ExecOutput)) {
    match event {
        mvm_agentd::vsock::ExecEvent::Stdout { chunk } => emit(ExecOutput::Stdout(chunk.clone())),
        mvm_agentd::vsock::ExecEvent::Stderr { chunk } => emit(ExecOutput::Stderr(chunk.clone())),
        _ => {}
    }
}

fn terminal_completion(terminal: mvm_agentd::vsock::ExecEvent) -> Result<ExecCompletion> {
    let (exit_code, timed_out) = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => (code, false),
        mvm_agentd::vsock::ExecEvent::TimedOut => (124, true),
        _ => anyhow::bail!("unexpected terminal exec event"),
    };
    Ok(ExecCompletion {
        exit_code,
        timed_out,
        binding_release_failed: false,
    })
}

pub fn exec(
    name: &str,
    command: &str,
    env: &[(String, String)],
    mut emit: impl FnMut(ExecOutput),
) -> Result<ExecCompletion> {
    enforce_accessible_gate(name, false)?;
    crate::touch_activity(name);
    let transport = pick_console_transport(name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    crate::guest::emit_vsock_rpc_audit(
        name,
        &mvm_agentd::vsock::GuestRequest::Exec {
            command: command.to_owned(),
            stdin: None,
            timeout_secs: None,
        },
    );
    let command = command_with_env(command, env);
    terminal_completion(mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &command,
        None,
        None,
        |event| emit_exec_event(event, &mut emit),
    )?)
}

fn command_with_env(cmd: &str, env: &[(String, String)]) -> String {
    if env.is_empty() {
        return cmd.to_owned();
    }
    let exports = env
        .iter()
        .map(|(key, value)| format!("{key}='{}'", value.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{exports} {cmd}")
}

fn guest_tool_reply(
    reply: mvm_contract::protocol::network_flow::tool::ToolDecisionReply,
) -> mvm_agentd::vsock::ToolCheckReply {
    use mvm_agentd::vsock::ToolCheckReply;
    use mvm_contract::protocol::network_flow::tool::ToolDecisionReply;
    match reply {
        ToolDecisionReply::Allow => ToolCheckReply::Allow,
        ToolDecisionReply::AllowBound { binding } => ToolCheckReply::AllowBound { binding },
        ToolDecisionReply::Deny => ToolCheckReply::Deny,
    }
}

/// Execute a declared tool only after the guest and admitted endpoint agree on
/// the invocation; release an acquired binding on success and failure alike.
pub fn exec_declared(
    name: &str,
    tool: &str,
    argv: Vec<String>,
    mut emit: impl FnMut(ExecOutput),
) -> Result<ExecCompletion> {
    enforce_accessible_gate(name, false)?;
    let call = mvm_agentd::vsock::MediatedExecCall {
        tool: tool.to_owned(),
        argv,
        stdin: None,
        timeout_secs: None,
        env: crate::entrypoint::dispatch::workload_egress_env(name),
    };
    anyhow::ensure!(
        call.tool_check().is_some(),
        "invalid declared tool invocation"
    );
    crate::touch_activity(name);
    let transport = pick_console_transport(name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    crate::guest::emit_vsock_rpc_audit(
        name,
        &mvm_agentd::vsock::GuestRequest::MediatedExec(call.clone()),
    );
    let mut bound = None;
    let terminal = mvm_agentd::vsock::send_attributed_mediated_exec_streaming(
        &mut stream,
        call,
        |question| {
            let reply =
                guest_tool_reply(crate::tool_mediation::decide_declared_tool(name, question)?);
            if let mvm_agentd::vsock::ToolCheckReply::AllowBound { binding } = &reply {
                bound = Some(binding.clone());
            }
            Ok(reply)
        },
        |event| emit_exec_event(event, &mut emit),
    );
    let binding_release_failed = bound.as_ref().is_some_and(|binding| {
        crate::tool_mediation::release_declared_tool(name, binding).is_err()
    });
    if binding_release_failed && terminal.is_err() {
        tracing::warn!(
            "could not release the failed tool invocation's binding; the endpoint retires it later"
        );
    }
    let mut completion = terminal_completion(terminal?)?;
    completion.binding_release_failed = binding_release_failed;
    Ok(completion)
}

#[cfg(test)]
mod console_relay_tests {
    use super::*;

    #[test]
    fn the_guest_gets_the_endpoints_decision_and_binding_unchanged() {
        use mvm_agentd::vsock::ToolCheckReply;
        use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;
        use mvm_contract::protocol::network_flow::tool::ToolDecisionReply;
        let binding = ToolInvocationBinding::from_random([2; 16]);
        assert_eq!(
            guest_tool_reply(ToolDecisionReply::Allow),
            ToolCheckReply::Allow
        );
        assert_eq!(
            guest_tool_reply(ToolDecisionReply::AllowBound {
                binding: binding.clone()
            }),
            ToolCheckReply::AllowBound { binding }
        );
        assert_eq!(
            guest_tool_reply(ToolDecisionReply::Deny),
            ToolCheckReply::Deny
        );
    }

    #[test]
    fn command_exit_status_survives_for_host_cleanup() {
        for code in [0, 23] {
            assert_eq!(
                terminal_completion(mvm_agentd::vsock::ExecEvent::Exit { code })
                    .unwrap()
                    .exit_code,
                code
            );
        }
        let completion = terminal_completion(mvm_agentd::vsock::ExecEvent::TimedOut).unwrap();
        assert_eq!(completion.exit_code, 124);
        assert!(completion.timed_out);
    }

    #[test]
    fn unexpected_terminal_event_fails_closed() {
        let error = terminal_completion(mvm_agentd::vsock::ExecEvent::Stdout {
            chunk: b"private guest output".to_vec(),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("unexpected terminal exec event"));
        assert!(!format!("{error:#}").contains("private guest output"));
    }

    #[test]
    fn session_options_compose_environment_and_argv() {
        let options = ConsoleSessionOptions::builder()
            .env(vec![("TERM".into(), "xterm-256color".into())])
            .argv(vec!["/bin/sh".into(), "-l".into()])
            .build();
        assert_eq!(
            options.env,
            vec![("TERM".to_owned(), "xterm-256color".to_owned())]
        );
        assert_eq!(options.argv, vec!["/bin/sh".to_owned(), "-l".to_owned()]);
    }

    #[test]
    fn a_guest_close_after_the_shell_exited_reports_its_code() {
        assert_eq!(
            classify_guest_close(Ok(SessionStatus::Exited(7)), false).unwrap(),
            SessionEnding::Exited(7)
        );
    }

    #[test]
    fn a_guest_close_while_the_shell_runs_is_a_displacement_not_an_exit() {
        assert_eq!(
            classify_guest_close(Ok(SessionStatus::Running), false).unwrap(),
            SessionEnding::Displaced
        );
    }

    #[test]
    fn a_guest_close_with_the_session_gone_is_an_error() {
        assert!(classify_guest_close(Ok(SessionStatus::Gone), false).is_err());
    }

    #[test]
    fn a_guest_close_on_a_stopped_machine_is_a_clean_end() {
        assert_eq!(
            classify_guest_close(Err(anyhow::anyhow!("Failed to read frame length")), true)
                .unwrap(),
            SessionEnding::Exited(0)
        );
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
                .argv(vec!["/bin/sh".into(), "-lc".into(), "make".into()])
                .build()
                .needs_dedicated_session()
        );
        assert!(
            ConsoleSessionOptions::builder()
                .env(vec![("K".into(), "v".into())])
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
    fn a_busy_refusal_names_both_ways_out() {
        let message = busy_refusal("dev", 3).to_string();
        assert!(message.contains("--force"), "{message}");
        assert!(message.contains("mvmctl machine detach dev"), "{message}");
    }

    #[test]
    fn stopped_machine_turns_a_lost_exit_code_reply_into_a_clean_console_end() {
        assert_eq!(
            classify_console_completion(Err(anyhow::anyhow!("Failed to read frame length")), true)
                .unwrap(),
            0
        );
    }

    #[test]
    fn running_machine_preserves_a_lost_exit_code_reply_as_an_error() {
        let error =
            classify_console_completion(Err(anyhow::anyhow!("Failed to read frame length")), false)
                .unwrap_err();
        assert!(error.to_string().contains("Failed to read frame length"));
    }

    #[test]
    fn an_absent_machine_is_confirmed_as_stopped() {
        assert!(wait_for_console_machine_stop(
            "console-completion-machine-that-does-not-exist"
        ));
    }

    #[test]
    fn opaque_data_channel_preserves_bytes_and_shutdown() {
        use std::io::{Read, Write};
        let (socket, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut data = ConsoleData(socket);
        data.write_all(b"input").unwrap();
        let mut input = [0; 5];
        guest.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"input");
        guest.write_all(b"output").unwrap();
        let reader = data.try_clone().unwrap();
        let mut output = [0; 6];
        (&reader).read_exact(&mut output).unwrap();
        assert_eq!(&output, b"output");
        data.shutdown(std::net::Shutdown::Both).unwrap();
        assert_eq!(guest.read(&mut input).unwrap(), 0);
    }

    #[test]
    fn environment_values_are_shell_quoted() {
        assert_eq!(command_with_env("true", &[]), "true");
        assert_eq!(
            command_with_env("true", &[("K".into(), "a'b $HOME".into())]),
            "K='a'\\''b $HOME' true"
        );
    }
}

#[cfg(test)]
mod accessible_gate_tests {
    use super::*;
    use mvm_runtime::vm::runtime_meta::{StartModeKind, VmRuntimeMeta, write as write_meta};

    fn with_home(f: impl FnOnce()) {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("HOME", tmp.path());
        env.set("MVM_HOME", tmp.path());
        f();
    }

    fn metadata(name: &str, accessible: bool) {
        write_meta(
            name,
            &VmRuntimeMeta {
                mode: StartModeKind::Detached,
                accessible,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn gate_allows_when_meta_missing() {
        with_home(|| assert!(enforce_accessible_gate("never-started", false).is_ok()));
    }

    #[test]
    fn gate_allows_when_meta_says_accessible() {
        with_home(|| {
            metadata("accessible-vm", true);
            assert!(enforce_accessible_gate("accessible-vm", false).is_ok());
        });
    }

    #[test]
    fn touch_activity_refreshes_last_active_for_registered_vm() {
        with_home(|| {
            let path = mvm_runtime::vm::name_registry::registry_path();
            let mut reg = mvm_runtime::vm::name_registry::VmNameRegistry::default();
            reg.register(mvm_runtime::vm::name_registry::RegisterParams::minimal(
                "vm1", "/tmp/vm1", "default",
            ))
            .unwrap();
            reg.save(&path).unwrap();
            assert!(reg.lookup("vm1").unwrap().last_active.is_none());
            crate::touch_activity("vm1");
            let reloaded = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).unwrap();
            assert!(reloaded.lookup("vm1").unwrap().last_active.is_some());
            crate::touch_activity("ghost");
            let reloaded = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).unwrap();
            assert!(reloaded.lookup("ghost").is_none());
        });
    }

    #[test]
    fn gate_refuses_when_sealed() {
        with_home(|| {
            metadata("sealed-vm", false);
            let message = enforce_accessible_gate("sealed-vm", false)
                .unwrap_err()
                .to_string();
            assert!(message.contains("sealed image"));
            assert!(!message.contains("--force"));
        });
    }

    #[test]
    fn console_refused_on_sealed_image() {
        with_home(|| {
            metadata("sealed-prod-image", false);
            let error = enforce_accessible_gate("sealed-prod-image", false).unwrap_err();
            assert!(error.to_string().contains("sealed image"));
        });
    }

    #[test]
    fn gate_force_does_not_bypass_sealed_refusal() {
        with_home(|| {
            metadata("sealed-but-forced", false);
            assert!(
                enforce_accessible_gate("sealed-but-forced", true)
                    .unwrap_err()
                    .to_string()
                    .contains("sealed image")
            );
        });
    }

    #[test]
    fn every_service_entry_refuses_sealed_before_transport_or_activity() {
        with_home(|| {
            let name = "sealed";
            metadata(name, false);
            let path = mvm_runtime::vm::name_registry::registry_path();
            let mut reg = mvm_runtime::vm::name_registry::VmNameRegistry::default();
            reg.register(mvm_runtime::vm::name_registry::RegisterParams::minimal(
                name,
                "/tmp/sealed",
                "default",
            ))
            .unwrap();
            reg.save(&path).unwrap();
            assert!(
                list_sessions(name)
                    .unwrap_err()
                    .to_string()
                    .contains("sealed image")
            );
            assert!(
                detach(name)
                    .unwrap_err()
                    .to_string()
                    .contains("sealed image")
            );
            let error = open(
                name,
                ConsoleSessionOptions::builder().take_over(true).build(),
                (80, 24),
            )
            .err()
            .expect("sealed open");
            assert!(error.to_string().contains("sealed image"));
            assert!(
                exec(name, "true", &[], |_| panic!("no output"))
                    .unwrap_err()
                    .to_string()
                    .contains("sealed image")
            );
            assert!(
                exec_declared(name, "tool", vec![], |_| panic!("no output"))
                    .unwrap_err()
                    .to_string()
                    .contains("sealed image")
            );
            let reloaded = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).unwrap();
            assert!(reloaded.lookup(name).unwrap().last_active.is_none());
        });
    }
}

#[cfg(test)]
mod picker_hvf_tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn setup_hvf_agent(
        name: &str,
    ) -> (
        tempfile::TempDir,
        mvm_core::util::test_env::TestEnv,
        Option<UnixListener>,
    ) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        env.set("MVM_HOME", tmp.path());
        std::fs::create_dir_all(mvm_core::config::vm_state_dir(name)).unwrap();
        let listener = match UnixListener::bind(mvm_core::config::vm_hvf_agent_socket(name)) {
            Ok(listener) => Some(listener),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping hvf console picker unix listener test: {error}");
                None
            }
            Err(error) => panic!("bind hvf agent socket: {error}"),
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
        pick_console_transport(name)
            .unwrap()
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .unwrap();
    }

    #[test]
    fn pick_console_transport_skips_hvf_for_sealed_workload() {
        let name = "hvf-sealed-workload";
        let (_tmp, _env, listener) = setup_hvf_agent(name);
        if listener.is_none() {
            return;
        }
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
        if let Ok(transport) = pick_console_transport(name) {
            assert!(
                transport
                    .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
                    .is_err()
            );
        }
    }

    #[test]
    fn pick_console_transport_selects_hvf_for_accessible_workload_without_dev_env() {
        let name = "hvf-accessible-workload";
        let (_tmp, mut env, listener) = setup_hvf_agent(name);
        if listener.is_none() {
            return;
        }
        env.set("MVM_ENV", "prod");
        pick_console_transport(name)
            .unwrap()
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .unwrap();
    }
}
