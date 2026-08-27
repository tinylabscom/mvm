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

    if !wait_for_agent_timed(vm_name, 30, sub) {
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
    // Agent reachable over vsock: the command is about to be dispatched.
    let vsock_ready = timing.then(std::time::Instant::now);
    let wrapper = build_guest_wrapper(req);

    if req.pty {
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
    let verb = "exec";
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
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        stdin_str,
        req.timeout_secs,
        |event| match event {
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
        },
    )?;
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
        ExecTarget::Inline { argv } if direct_pty_inline_argv(argv, req) => PtyConsoleRequest {
            argv: argv.clone(),
            env: req.env.clone(),
        },
        _ => PtyConsoleRequest {
            argv: vec!["/bin/sh".to_string(), "-lc".to_string(), wrapper],
            env: Vec::new(),
        },
    }
}

fn direct_pty_inline_argv(req_argv: &[String], req: &ExecRequest) -> bool {
    req.dir_shares.is_empty() && req_argv.first().is_some_and(|argv0| argv0.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_console_request_passes_inline_argv_directly() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: Some(1),
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            env: vec![("TERM".into(), "xterm-256color".into())],
            target: ExecTarget::Inline {
                argv: vec!["/bin/sh".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_sidecar: None,
        };

        let pty = pty_console_request(&req, "set -e\nexec '/bin/sh'\n".to_string());

        assert_eq!(pty.argv, vec!["/bin/sh"]);
        assert_eq!(pty.env, vec![("TERM".into(), "xterm-256color".into())]);
    }

    #[test]
    fn pty_console_request_keeps_relative_commands_on_shell_path_lookup() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: Some(1),
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["htop".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_sidecar: None,
        };
        let wrapper = build_guest_wrapper(&req);

        let pty = pty_console_request(&req, wrapper.clone());

        assert_eq!(pty.argv, vec!["/bin/sh", "-lc", wrapper.as_str()]);
        assert!(pty.env.is_empty());
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
