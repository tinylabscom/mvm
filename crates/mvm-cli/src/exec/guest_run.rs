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
    startup: &super::StartupClock,
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
    let vsock_ready = std::time::Instant::now();
    let req = &with_provisioned_egress_env(req, vm_name)?;
    let wrapper = build_guest_wrapper(req);

    if req.pty {
        let pty = pty_console_request(req, wrapper);
        startup.gate_dispatch(vsock_ready, sub)?;
        let exit_code =
            crate::commands::vm::console::run_pty_argv_for_exit(vm_name, pty.argv, pty.env)?;
        return Ok((Either::Left(exit_code), Some(vsock_ready)));
    }

    // Establishing the channel the command goes out on — the dispatch cost,
    // distinct from how long the command itself then runs in the guest.
    sub.start(SubPhase::FirstDispatch);
    let mut stream = vsock_transport::for_vm(vm_name)
        .and_then(|transport| transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT))
        .with_context(|| format!("opening the first dispatch channel to guest '{vm_name}'"))
        .inspect_err(|_| emit_guest_console_diagnostic(vm_name))?;
    sub.finish(SubPhase::FirstDispatch);
    // The last host-side point before the command is written to the guest:
    // a launch already over its startup ceiling is refused here, with the
    // channel open but nothing sent, so the workload never starts.
    startup.gate_dispatch(vsock_ready, sub)?;
    // Inbound vsock RPC audit. exec.rs is a top-level module that can't
    // reach the private `commands::shared` re-export, so inline the audit
    // emit here. The detail format matches
    // `mvm_client::guest::emit_vsock_rpc_audit`:
    // `scope=rpc,direction=in,kind=vsock,verb=<kebab-name>`.
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_name,
        "scope=rpc,direction=in,kind=vsock,verb=exec",
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
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        stdin_str,
        req.timeout_secs,
        on_event,
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
    Ok((either, Some(vsock_ready)))
}

const AGENT_FAILURE_CONSOLE_LINES: usize = 80;

const HYPERVISOR_LOG_LINES: usize = 40;

/// The last `line_count` redacted lines of the VMM log that mention vsock.
fn vsock_log_tail(contents: &[u8], line_count: usize) -> String {
    let text = String::from_utf8_lossy(contents);
    let matching = text
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("vsock"))
        .collect::<Vec<_>>()
        .join("\n");
    redacted_console_tail(matching.as_bytes(), line_count)
}

fn emit_hypervisor_vsock_diagnostic(vm_name: &str) {
    let path = mvm_core::config::vm_hypervisor_log(vm_name);
    if let Ok(contents) = std::fs::read(&path) {
        let tail = vsock_log_tail(&contents, HYPERVISOR_LOG_LINES);
        if !tail.is_empty() {
            eprintln!(
                "[mvm] Hypervisor vsock log tail ({}):\n{tail}",
                path.display()
            );
        }
    }
}

pub(super) fn emit_guest_console_diagnostic(vm_name: &str) {
    emit_hypervisor_vsock_diagnostic(vm_name);
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
/// boot can carry them. An explicit `--env` cannot replace a provisioned value.
fn with_provisioned_egress_env(req: &ExecRequest, vm_name: &str) -> Result<ExecRequest> {
    let mut provisioned = req.clone();
    provisioned.env = compose_egress_env(
        mvm_hostd::workload_env::workload_egress_env(vm_name),
        &req.env,
    )?;
    Ok(provisioned)
}

/// The provisioned egress variables, then the caller's own.
///
/// A caller variable that repeats a provisioned name with the very same value
/// replaces nothing: the CLI puts the OCI proxy variables on the request before
/// boot, and the host provisions the same ones after it. That repeat is dropped
/// so the variable appears once. A different value is a replacement and is
/// refused, without echoing the value.
fn compose_egress_env(
    provisioned: Vec<(String, String)>,
    caller: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let mut env = provisioned;
    for (name, value) in caller {
        match env.iter().find(|(bound, _)| bound == name) {
            Some((_, bound)) if bound == value => {}
            Some(_) => anyhow::bail!(
                "cannot override host-provisioned egress variable {name:?} with --env"
            ),
            None => env.push((name.clone(), value.clone())),
        }
    }
    Ok(env)
}

fn direct_pty_inline_argv(req_argv: &[String]) -> bool {
    req_argv.first().is_some_and(|argv0| argv0.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_console_request_passes_inline_argv_directly() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
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
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: vec![DirShareSpec {
                host_dir: "/host/src".into(),
                guest_mount: "/work/src".into(),
                read_only: true,
                include: Vec::new(),
                exclude: Vec::new(),
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
            standby_refill: None,
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
        )
        .unwrap();
        assert_eq!(env.len(), 3);
        assert_eq!(env[1], ("API_TOKEN".to_string(), placeholder));
        assert_eq!(
            env.last().map(|(k, _)| k.as_str()),
            Some("TERM"),
            "non-conflicting caller env follows the host-provisioned values"
        );
    }

    #[test]
    fn a_caller_cannot_override_a_secret_placeholder_or_egress_proxy() {
        for name in ["API_TOKEN", "HTTPS_PROXY"] {
            let error = compose_egress_env(
                vec![
                    ("API_TOKEN".into(), "mvm-secret-placeholder".into()),
                    ("HTTPS_PROXY".into(), "http://127.0.0.1:1080".into()),
                ],
                &[(name.into(), "raw-private-value".into())],
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(name),
                "the collision must name the variable: {error}"
            );
            assert!(
                !error.to_string().contains("raw-private-value"),
                "the refusal must not echo the caller's value: {error}"
            );
        }
    }

    #[test]
    fn the_clis_own_oci_proxy_variables_are_not_an_override() {
        // Both sides come from the same producer the real paths use: the CLI
        // injects it on an OCI boot, the host provisions it after boot.
        let proxy =
            mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN);
        let mut provisioned = proxy.clone();
        provisioned.push(("API_TOKEN".into(), "mvm-secret-placeholder".into()));

        let mut caller = proxy.clone();
        caller.push(("TERM".into(), "xterm-256color".into()));

        let env = compose_egress_env(provisioned.clone(), &caller).unwrap();
        for (name, _) in &proxy {
            assert_eq!(
                env.iter().filter(|(bound, _)| bound == name).count(),
                1,
                "{name} must appear exactly once"
            );
        }
        assert_eq!(env.len(), provisioned.len() + 1, "only TERM is added");
        assert!(env.contains(&("TERM".to_string(), "xterm-256color".to_string())));
    }

    #[test]
    fn a_caller_value_that_differs_from_the_provisioned_one_is_still_refused() {
        let proxy =
            mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN);
        let (name, _) = proxy[0].clone();
        let error =
            compose_egress_env(proxy, &[(name.clone(), "http://evil.example".into())]).unwrap_err();
        assert!(error.to_string().contains(&name), "{error}");
        assert!(!error.to_string().contains("evil.example"), "{error}");
    }

    #[test]
    fn a_vm_with_no_provisioned_egress_keeps_the_callers_env() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
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
        let provisioned = with_provisioned_egress_env(&req, "no-egress-vm").unwrap();
        assert_eq!(provisioned.env, req.env);
    }

    #[test]
    fn vsock_log_tail_keeps_only_the_last_vsock_lines() {
        let tail = vsock_log_tail(
            b"api request\nVsock muxer: a\nnet thing\nvsock conn reset\nvsock last\n",
            2,
        );
        assert_eq!(tail, "vsock conn reset\nvsock last");
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
