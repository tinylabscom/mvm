//! Host->guest healthcheck probe primitive.
//!
//! Runs a workload's declared healthcheck command in the guest via the
//! agent's exec protocol and folds the result into a `ProbeResult`. The
//! guest exec leg is factored behind the [`GuestExec`] trait so
//! [`probe_with`] is unit-testable without a live VM; [`probe_once`] wires
//! it to the real vsock transport.

use mvm_core::health::ProbeResult;
use mvm_guest::vsock::{ExecEvent, GUEST_AGENT_PORT, send_exec_streaming};
use mvm_sdk::ir::HealthCheck;

/// Outcome of running a command in the guest, independent of how it was
/// decided pass/fail.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecOutcome {
    /// The command ran to completion with this exit code.
    Exited(i32),
    /// The agent killed the command after the timeout elapsed.
    TimedOut,
    /// The guest agent could not be reached (connect/protocol failure), or
    /// the exec otherwise failed to produce a terminal result.
    Unreachable,
}

/// Seam over "run this command in the named VM's guest and report how it
/// ended." Exists so tests can substitute a fake without a live VM.
pub trait GuestExec {
    fn exec(&self, vm_name: &str, cmd: &str, timeout_secs: u64) -> ExecOutcome;
}

/// Real [`GuestExec`] impl: connects to the guest agent over vsock and runs
/// the command via `send_exec_streaming`.
pub struct AgentExec;

impl GuestExec for AgentExec {
    fn exec(&self, vm_name: &str, cmd: &str, timeout_secs: u64) -> ExecOutcome {
        let transport = match mvm::vsock_transport::for_vm(vm_name) {
            Ok(t) => t,
            Err(_) => return ExecOutcome::Unreachable,
        };
        let mut stream = match transport.connect(GUEST_AGENT_PORT) {
            Ok(s) => s,
            Err(_) => return ExecOutcome::Unreachable,
        };
        match send_exec_streaming(&mut stream, cmd, None, Some(timeout_secs), |_ev| {}) {
            Ok(ExecEvent::Exit { code }) => ExecOutcome::Exited(code),
            Ok(ExecEvent::TimedOut) => ExecOutcome::TimedOut,
            // send_exec_streaming only ever returns a terminal event
            // (Exit or TimedOut); any other shape or transport error means
            // the probe couldn't get a verdict out of the guest.
            Ok(_) | Err(_) => ExecOutcome::Unreachable,
        }
    }
}

/// Unwrap the phase-A stored shape (`["/bin/sh", "-lc", "<cmd>"]`) back to
/// the raw shell command string. The agent's `Exec` already runs its
/// command through `/bin/sh -c`, so handing it the raw command avoids a
/// redundant nested shell; any other shape is quoted argv-wise so it
/// survives verbatim through that same `/bin/sh -c`.
fn command_string(hc: &HealthCheck) -> String {
    if let [shell, flag, cmd] = hc.command.as_slice()
        && shell == "/bin/sh"
        && flag == "-lc"
    {
        return cmd.clone();
    }
    hc.command
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quote wrap, escaping embedded single quotes the portable POSIX
/// way (`'` -> `'\''`). Mirrors the mvm-cli exec-target quoting convention.
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Testable core: run `hc.command` in `vm_name` via `exec` and decide
/// pass/fail. Exit code 0 is the only passing outcome — non-zero exit,
/// timeout, and an unreachable guest all fail the probe.
pub fn probe_with<E: GuestExec>(exec: &E, vm_name: &str, hc: &HealthCheck) -> ProbeResult {
    let cmd = command_string(hc);
    match exec.exec(vm_name, &cmd, hc.timeout_secs.into()) {
        ExecOutcome::Exited(0) => ProbeResult::Pass,
        ExecOutcome::Exited(_) | ExecOutcome::TimedOut | ExecOutcome::Unreachable => {
            ProbeResult::Fail
        }
    }
}

/// Run `hc`'s command in `vm_name`'s guest over the real vsock transport
/// and decide pass/fail.
pub fn probe_once(vm_name: &str, hc: &HealthCheck) -> ProbeResult {
    probe_with(&AgentExec, vm_name, hc)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake(ExecOutcome);
    impl GuestExec for Fake {
        fn exec(&self, _: &str, _: &str, _: u64) -> ExecOutcome {
            self.0.clone()
        }
    }
    fn hc() -> HealthCheck {
        HealthCheck {
            command: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
            interval_secs: 30,
            timeout_secs: 5,
            retries: 3,
            start_period_secs: 0,
        }
    }
    #[test]
    fn exit_zero_is_pass() {
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Exited(0)), "vm", &hc()),
            ProbeResult::Pass
        );
    }
    #[test]
    fn nonzero_timeout_unreachable_are_fail() {
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Exited(1)), "vm", &hc()),
            ProbeResult::Fail
        );
        assert_eq!(
            probe_with(&Fake(ExecOutcome::TimedOut), "vm", &hc()),
            ProbeResult::Fail
        );
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Unreachable), "vm", &hc()),
            ProbeResult::Fail
        );
    }

    #[test]
    fn command_string_unwraps_phase_a_shape() {
        assert_eq!(command_string(&hc()), "true");
    }

    #[test]
    fn command_string_quotes_unknown_shape() {
        let mut h = hc();
        h.command = vec!["curl".into(), "-f".into(), "http://x/health".into()];
        assert_eq!(command_string(&h), "'curl' '-f' 'http://x/health'");
    }
}
