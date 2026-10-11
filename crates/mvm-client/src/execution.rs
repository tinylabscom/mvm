//! Execution against an already admitted session, without host console gates.

use anyhow::Result;

pub const EXEC_TIMEOUT_EXIT_CODE: i32 = 124;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn timeout_exit_message(timeout_secs: Option<u64>) -> String {
    let suffix = timeout_secs
        .map(|s| format!(" after {s}s"))
        .unwrap_or_default();
    format!("error: command timed out{suffix}")
}

/// Portable POSIX quoting, shared by transient and session command wrappers.
pub fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Compose the guest command after caller exports, keeping mediated tools first.
pub fn guest_wrapper(
    argv: &[String],
    env: &[(String, String)],
    working_dir: Option<&str>,
) -> String {
    let mut script = String::from("set -e\n");
    for (key, value) in env {
        script.push_str(&format!("export {key}={}\n", shell_quote(value)));
    }
    script.push_str(&format!(
        "export PATH={}:\"$PATH\"\n",
        shell_quote(mvm_core::guest_netd::MEDIATED_TOOLS_BIN),
    ));
    if let Some(wd) = working_dir {
        script.push_str(&format!("cd {}\n", shell_quote(wd)));
    }
    script.push_str("exec ");
    script.push_str(
        &argv
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" "),
    );
    script.push('\n');
    script
}

/// Execute shell code on an admitted session. The authenticated guest RPC
/// enforces its execution grants; interactive-console accessibility is unrelated.
pub fn dispatch_in_session(
    vm: &crate::entrypoint::SessionVm,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<SessionExecOutput> {
    mvm_core::naming::validate_vm_name(&vm.vm_name)?;
    if !crate::readiness::wait_for_guest_agent(&vm.vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    let wrapper = guest_wrapper(&["bash".to_string(), "-c".to_string(), code], &[], None);
    let transport = mvm_runtime::vsock_transport::for_vm(&vm.vm_name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: &vm.vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = "exec",
    );
    let mut out = Vec::new();
    let mut err = Vec::new();
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        None,
        timeout_secs,
        |event| match event {
            mvm_agentd::vsock::ExecEvent::Stdout { chunk } => out.extend_from_slice(chunk),
            mvm_agentd::vsock::ExecEvent::Stderr { chunk } => err.extend_from_slice(chunk),
            _ => {}
        },
    )?;
    finish_session_exec(terminal, out, err, timeout_secs)
}

fn finish_session_exec(
    terminal: mvm_agentd::vsock::ExecEvent,
    out: Vec<u8>,
    mut err: Vec<u8>,
    timeout_secs: Option<u64>,
) -> Result<SessionExecOutput> {
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            err.extend_from_slice(format!("{}\n", timeout_exit_message(timeout_secs)).as_bytes());
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };
    Ok(SessionExecOutput {
        exit_code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::ExecEvent;

    #[test]
    fn invalid_session_identity_is_refused_before_agent_wait() {
        let vm = crate::entrypoint::SessionVm {
            vm_name: "../other".to_string(),
        };
        assert!(dispatch_in_session(&vm, "true".to_string(), None).is_err());
    }

    #[test]
    fn session_wrapper_quotes_code_and_keeps_mediated_tools_first() {
        let script = guest_wrapper(
            &["bash".into(), "-c".into(), "echo 'quoted'".into()],
            &[("PATH".into(), "/caller".into())],
            None,
        );
        assert!(script.starts_with("set -e\nexport PATH='/caller'\nexport PATH="));
        assert!(script.ends_with("exec 'bash' '-c' 'echo '\\''quoted'\\'''\n"));
    }

    #[test]
    fn captured_exit_preserves_lossy_output_and_status() {
        let output = finish_session_exec(
            ExecEvent::Exit { code: 17 },
            vec![255],
            b"err".to_vec(),
            None,
        )
        .unwrap();
        assert_eq!(output.exit_code, 17);
        assert_eq!(output.stdout, "\u{fffd}");
        assert_eq!(output.stderr, "err");
    }

    #[test]
    fn timed_out_exec_appends_diagnostic_and_returns_124() {
        let output =
            finish_session_exec(ExecEvent::TimedOut, vec![], b"before\n".to_vec(), Some(4))
                .unwrap();
        assert_eq!(output.exit_code, 124);
        assert_eq!(output.stderr, "before\nerror: command timed out after 4s\n");
    }

    #[test]
    fn nonterminal_exec_frame_is_refused() {
        assert!(
            finish_session_exec(
                ExecEvent::Stdout {
                    chunk: b"not exit".to_vec()
                },
                vec![],
                vec![],
                None
            )
            .is_err()
        );
    }
}
