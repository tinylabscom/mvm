//! Run one command inside a booted guest, and say why when it cannot.
//!
//! The dispatch half of a transient run: hand the wrapper to the guest agent
//! over vsock (or run it on the host `wasmtime` engine for the wasm tier), and
//! on an agent that never became reachable, surface the guest console tail
//! rather than a bare timeout — the panic that explains it is in that tail.

use super::*;

/// Wait for a wasm-backend run to complete.
///
/// The wasm backend runs the module synchronously inside `start`, so by the
/// time control reaches here the guest code has already executed. We just
/// wait for the recorded exit status and surface its code. Stdio is
/// inherited by the host `wasmtime` engine, so streaming/capture are not
/// handled here.
pub(super) fn run_wasm_module(
    backend: &mvm_runtime::backend::AnyBackend,
    vm_name: &str,
) -> anyhow::Result<i32> {
    let status = backend
        .wait(&mvm_core::vm_backend::VmId(vm_name.to_string()))
        .with_context(|| format!("waiting for wasm module '{vm_name}' to finish"))?;
    Ok(status.code.unwrap_or(1))
}

/// Send the wrapped command to the guest agent and either stream
/// stdout/stderr (default) or capture them (when `capture=true`).
///
/// `capture=true` is used by [`run_captured`] to return the output as
/// data; the streaming path keeps the existing `mvmctl exec` ergonomics.
pub(super) fn run_in_guest(
    vm_name: &str,
    req: &ExecRequest,
    capture: bool,
    timing: bool,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<(Either<i32, ExecOutput>, Option<std::time::Instant>)> {
    use crate::commands::vm::phase_timing::SubPhase;
    use std::io::Write as _;

    // Ended before any output or console attach below: an interactive
    // console puts the terminal in raw mode, and no live line may outlast that.
    let phase = mvm_runtime::ui::activity::start("Waiting for the guest agent (up to 30s)");
    if !wait_for_agent_timed(vm_name, 30, sub) {
        drop(phase);
        emit_guest_console_diagnostic(vm_name);
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    // The guest is up, so a session on its endpoint is now possible — and its
    // absence means something. Checked here rather than at spawn time on
    // purpose: the endpoint binds and reports ready before the guest boots, so
    // waiting for a session there would block on an event the wait itself
    // prevents.
    mvm_runtime::network_endpoint_spawn::wait_for_endpoint_session(
        vm_name,
        &mvm_core::config::vm_state_dir(vm_name),
    )?;
    phase.finish();
    // Agent reachable over vsock: the command is about to be dispatched.
    let vsock_ready = timing.then(std::time::Instant::now);
    let req = &with_provisioned_egress_env(req, vm_name);
    let wrapper = build_guest_wrapper(req);

    let dispatch = command_dispatch(
        mvm_runtime::microvm::read_verb_grant_envelope(vm_name)
            .context("reading the run's signed verb grant")?
            .as_ref(),
    );

    if req.pty {
        refuse_mediated_pty(dispatch)?;
        let pty = pty_console_request(req, wrapper);
        let exit_code =
            crate::commands::vm::console::run_pty_argv_for_exit(vm_name, pty.argv, pty.env)?;
        return Ok((Either::Left(exit_code), vsock_ready));
    }

    // Establishing the channel the command goes out on — the dispatch cost,
    // distinct from how long the command itself then runs in the guest.
    sub.start(SubPhase::FirstDispatch);
    let transport = vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    sub.finish(SubPhase::FirstDispatch);
    // Inbound vsock RPC audit. exec.rs is a top-level module that can't
    // reach the private `commands::shared` re-export, so inline the audit
    // emit here. The detail format matches
    // `commands::shared::vsock::emit_vsock_rpc_audit`:
    // `scope=rpc,direction=in,kind=vsock,verb=<kebab-name>`.
    let verb = dispatch.verb();
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );

    let mut out = Vec::<u8>::new();
    let mut err = Vec::<u8>::new();
    let stdin_str = if req.stdin.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&req.stdin).into_owned())
    };
    let on_event = |event: &mvm_agentd::vsock::ExecEvent| match event {
        mvm_agentd::vsock::ExecEvent::Stdout { chunk } => {
            if capture {
                out.extend_from_slice(chunk);
            } else {
                let mut so = std::io::stdout();
                let _ = so.write_all(chunk);
                let _ = so.flush();
            }
        }
        mvm_agentd::vsock::ExecEvent::Stderr { chunk } => {
            if capture {
                err.extend_from_slice(chunk);
            } else {
                let mut se = std::io::stderr();
                let _ = se.write_all(chunk);
                let _ = se.flush();
            }
        }
        _ => {}
    };
    let terminal = match dispatch {
        CommandDispatch::Exec => mvm_agentd::vsock::send_exec_streaming(
            &mut stream,
            &wrapper,
            stdin_str,
            req.timeout_secs,
            on_event,
        )?,
        CommandDispatch::Mediated => mvm_agentd::vsock::send_mediated_exec_streaming(
            &mut stream,
            run_command_call(wrapper, stdin_str, req.timeout_secs)?,
            // The helper has already refused a question that differs from the
            // call; what is left is the run's own command, which the operator
            // supplied with the admitted plan. It is not a tool call, so the
            // tool rules do not decide it.
            |_question| Ok(true),
            on_event,
        )?,
    };
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            let msg = timeout_exit_message(req.timeout_secs);
            if capture {
                err.extend_from_slice(format!("{msg}\n").as_bytes());
            } else {
                eprintln!("{msg}");
            }
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };

    let either = if capture {
        Either::Right(ExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
            phase_timing: None,
        })
    } else {
        Either::Left(exit_code)
    };
    Ok((either, vsock_ready))
}

/// Tool name the run's own command is reported under when the guest mediates
/// commands. The guest echoes it back in its pre-spawn question; no tool rule
/// is consulted for it.
const RUN_COMMAND_TOOL: &str = "mvmctl-run";

/// How the run's own command reaches the guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandDispatch {
    /// A plain `Exec`: nothing in the signed grant mediates guest commands.
    Exec,
    /// The signed grant carries tool mediation, so the guest refuses every
    /// command RPC that does not pause before spawn. The run's command goes
    /// out as a `MediatedExec` that this runner answers itself.
    Mediated,
}

impl CommandDispatch {
    /// The verb recorded in the inbound vsock RPC audit line.
    fn verb(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Mediated => "mediated-exec",
        }
    }
}

/// Pick the dispatch from the grant the host minted for this boot — the same
/// envelope the guest pinned, so the choice matches what the guest enforces.
fn command_dispatch(
    grant: Option<&mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> CommandDispatch {
    if grant.is_some_and(|envelope| envelope.grant.tool_mediation.is_some()) {
        CommandDispatch::Mediated
    } else {
        CommandDispatch::Exec
    }
}

/// An interactive console is an unmediated command channel, and a guest under
/// tool mediation refuses it. Say so before boot work is wasted on a refusal
/// that would otherwise read as an authorization failure.
fn refuse_mediated_pty(dispatch: CommandDispatch) -> Result<()> {
    anyhow::ensure!(
        dispatch == CommandDispatch::Exec,
        "this run's policy has a [tools] section, so the guest mediates every command and \
         refuses an interactive console; run without --pty, or drop the [tools] section"
    );
    Ok(())
}

/// The run's wrapper as a mediated call. `/bin/sh -c <wrapper>` is exactly
/// what the guest runs for a plain `Exec`, so the command behaves the same
/// under either dispatch.
fn run_command_call(
    wrapper: String,
    stdin: Option<String>,
    timeout_secs: Option<u64>,
) -> Result<mvm_agentd::vsock::MediatedExecCall> {
    let call = mvm_agentd::vsock::MediatedExecCall {
        tool: RUN_COMMAND_TOOL.to_string(),
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), wrapper],
        stdin,
        timeout_secs,
        env: Vec::new(),
    };
    anyhow::ensure!(
        call.tool_check().is_some(),
        "the run's command is longer than the {} bytes a mediated guest command may carry",
        mvm_contract::protocol::network_flow::tool::MAX_TOOL_ARGV_BYTES
    );
    Ok(call)
}

const AGENT_FAILURE_CONSOLE_LINES: usize = 80;

pub(super) fn emit_guest_console_diagnostic(vm_name: &str) {
    let path = mvm_core::config::vm_console_log(vm_name);
    let Ok(contents) = std::fs::read(&path) else {
        eprintln!(
            "[mvm] Guest console was unavailable at {} before transient cleanup.",
            path.display()
        );
        return;
    };
    let diagnostic = redacted_console_tail(&contents, AGENT_FAILURE_CONSOLE_LINES);
    if diagnostic.is_empty() {
        eprintln!(
            "[mvm] Guest console at {} was empty before transient cleanup.",
            path.display()
        );
        return;
    }
    eprintln!(
        "[mvm] Guest console tail before transient cleanup ({}):\n{}",
        path.display(),
        diagnostic
    );
}

fn redacted_console_tail(contents: &[u8], line_count: usize) -> String {
    let redactor = mvm_core::pii::PiiRedactor::with_default_rules();
    let (redacted, _) = redactor.redact(contents);
    let text = String::from_utf8_lossy(&redacted);
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(line_count);
    lines[start..].join("\n")
}

struct PtyConsoleRequest {
    argv: Vec<String>,
    env: Vec<(String, String)>,
}

fn pty_console_request(req: &ExecRequest, wrapper: String) -> PtyConsoleRequest {
    match &req.target {
        ExecTarget::Inline { argv } if direct_pty_inline_argv(argv) => PtyConsoleRequest {
            argv: argv.clone(),
            env: req.env.clone(),
        },
        _ => PtyConsoleRequest {
            argv: vec!["/bin/sh".to_string(), "-lc".to_string(), wrapper],
            env: Vec::new(),
        },
    }
}

/// `req` with the environment the host provisioned for this VM's egress in
/// front of the caller's own: the proxy variables, the placeholder minted for
/// each secret the plan binds, and — when the endpoint terminates for a bound
/// destination — the variables pointing TLS clients at the trust bundle that
/// carries this VM's egress certificate.
///
/// Read here, after the endpoint has a session, because that is when the
/// placeholders exist: they are minted at boot, so no request built before
/// boot can carry them. The caller's explicit `--env` comes last and wins.
fn with_provisioned_egress_env(req: &ExecRequest, vm_name: &str) -> ExecRequest {
    let mut provisioned = req.clone();
    provisioned.env = compose_egress_env(
        mvm_hostd::workload_env::workload_egress_env(vm_name),
        &req.env,
    );
    provisioned
}

/// The provisioned egress variables, then the caller's.
fn compose_egress_env(
    provisioned: Vec<(String, String)>,
    caller: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = provisioned;
    env.extend(caller.iter().cloned());
    env
}

fn direct_pty_inline_argv(req_argv: &[String]) -> bool {
    req_argv.first().is_some_and(|argv0| argv0.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant_envelope(
        tool_mediation: Option<mvm_core::plan::ToolMediationGrant>,
    ) -> mvm_core::protocol::vm_backend::VerbGrantEnvelope {
        mvm_core::protocol::vm_backend::VerbGrantEnvelope {
            pubkey_hex: "ab".repeat(32),
            plan_nonce_hex: "00".repeat(16),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: mvm_core::plan::VerbGrant {
                session_id: "vm".to_string(),
                plan_nonce: mvm_core::plan::Nonce::from_bytes([0u8; 16]),
                not_after: chrono::Utc::now() + chrono::Duration::minutes(5),
                verbs: Vec::new(),
                drive: None,
                tool_mediation,
                sig: vec![0u8; 64],
            },
        }
    }

    fn mediation() -> Option<mvm_core::plan::ToolMediationGrant> {
        Some(mvm_core::plan::ToolMediationGrant {
            class_gate_only: true,
        })
    }

    #[test]
    fn a_run_without_tool_mediation_keeps_plain_exec() {
        assert_eq!(command_dispatch(None), CommandDispatch::Exec);
        assert_eq!(
            command_dispatch(Some(&grant_envelope(None))),
            CommandDispatch::Exec
        );
        assert_eq!(CommandDispatch::Exec.verb(), "exec");
        assert!(refuse_mediated_pty(CommandDispatch::Exec).is_ok());
    }

    #[test]
    fn a_tool_mediated_run_dispatches_its_own_command_as_mediated_exec() {
        let dispatch = command_dispatch(Some(&grant_envelope(mediation())));
        assert_eq!(dispatch, CommandDispatch::Mediated);
        assert_eq!(dispatch.verb(), "mediated-exec");
    }

    #[test]
    fn the_guest_admits_the_mediated_run_command_and_refuses_plain_exec() {
        let envelope = grant_envelope(mediation());
        let wrapper = "set -e\necho hello\n".to_string();
        let call = run_command_call(wrapper.clone(), Some("in".into()), Some(9)).expect("call");
        assert_eq!(call.argv, ["/bin/sh", "-c", wrapper.as_str()]);
        assert_eq!(call.stdin.as_deref(), Some("in"));
        assert_eq!(call.timeout_secs, Some(9));

        let mediated = mvm_agentd::vsock::GuestRequest::MediatedExec(call);
        assert!(
            mvm_agentd::vsock::enforce_verb_grant(&mediated, Some(&envelope.grant)).is_none(),
            "the run's own command must pass the signed tool-mediation gate"
        );
        let plain = mvm_agentd::vsock::GuestRequest::Exec {
            command: wrapper,
            stdin: None,
            timeout_secs: None,
        };
        assert!(matches!(
            mvm_agentd::vsock::enforce_verb_grant(&plain, Some(&envelope.grant)),
            Some(mvm_agentd::vsock::GuestResponse::VerbNotAuthorized { .. })
        ));
    }

    #[test]
    fn an_oversized_run_command_is_refused_with_the_limit() {
        let wrapper = "x".repeat(mvm_contract::protocol::network_flow::tool::MAX_TOOL_ARGV_BYTES);
        let error = run_command_call(wrapper, None, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("bytes a mediated guest command may carry"),
            "{error}"
        );
    }

    #[test]
    fn a_tool_mediated_pty_run_is_refused_before_dispatch() {
        let error = refuse_mediated_pty(CommandDispatch::Mediated)
            .unwrap_err()
            .to_string();
        assert!(error.contains("[tools]"), "{error}");
        assert!(error.contains("--pty"), "{error}");
    }

    #[test]
    fn pty_console_request_passes_inline_argv_directly() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("TERM".into(), "xterm-256color".into())],
            target: ExecTarget::Inline {
                argv: vec!["/bin/sh".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };

        let pty = pty_console_request(&req, "set -e\nexec '/bin/sh'\n".to_string());

        assert_eq!(pty.argv, vec!["/bin/sh"]);
        assert_eq!(pty.env, vec![("TERM".into(), "xterm-256color".into())]);
    }

    #[test]
    fn pty_console_request_with_mount_passes_absolute_argv_directly() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: vec![DirShareSpec {
                host_dir: "/host/src".into(),
                guest_mount: "/work/src".into(),
                read_only: true,
            }],
            disk_volumes: Vec::new(),
            env: vec![("NAME".into(), "ari".into())],
            target: ExecTarget::Inline {
                argv: vec!["/bin/bash".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };

        let pty = pty_console_request(&req, "unused wrapper".to_string());

        assert_eq!(pty.argv, vec!["/bin/bash"]);
        assert_eq!(pty.env, vec![("NAME".into(), "ari".into())]);
    }

    #[test]
    fn pty_console_request_keeps_relative_commands_on_shell_path_lookup() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["htop".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let wrapper = build_guest_wrapper(&req);

        let pty = pty_console_request(&req, wrapper.clone());

        assert_eq!(pty.argv, vec!["/bin/sh", "-lc", wrapper.as_str()]);
        assert!(pty.env.is_empty());
    }

    #[test]
    fn a_secret_bearing_run_exports_its_placeholder_before_the_command() {
        let placeholder = format!("mvm-secret-{}", "ab".repeat(24));
        let env = compose_egress_env(
            vec![
                ("HTTPS_PROXY".into(), "http://127.0.0.1:1080".into()),
                ("API_TOKEN".into(), placeholder.clone()),
            ],
            &[("TERM".into(), "xterm-256color".into())],
        );
        assert_eq!(env.len(), 3);
        assert_eq!(env[1], ("API_TOKEN".to_string(), placeholder));
        assert_eq!(
            env.last().map(|(k, _)| k.as_str()),
            Some("TERM"),
            "the caller's explicit env comes last"
        );
    }

    #[test]
    fn a_vm_with_no_provisioned_egress_keeps_the_callers_env() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("TERM".into(), "xterm-256color".into())],
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: None,
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let provisioned = with_provisioned_egress_env(&req, "no-egress-vm");
        assert_eq!(provisioned.env, req.env);
    }

    #[test]
    fn agent_failure_console_tail_is_bounded_and_redacted() {
        let diagnostic = redacted_console_tail(
            b"discarded\nbooting\nmvm-guest-init: failed for dev@example.com\nkernel panic\n",
            3,
        );
        assert!(!diagnostic.contains("discarded"));
        assert!(diagnostic.contains("booting"));
        assert!(diagnostic.contains("mvm-guest-init: failed"));
        assert!(!diagnostic.contains("dev@example.com"));
        assert!(diagnostic.contains("XXX"));
        assert!(diagnostic.contains("kernel panic"));
    }
}
