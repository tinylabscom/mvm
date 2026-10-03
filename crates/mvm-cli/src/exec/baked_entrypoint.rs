//! Baked-entrypoint dispatch for a transient image.

use super::guest_run::emit_guest_console_diagnostic;
use super::session::wait_for_agent_timed;
use super::*;

pub(super) fn boots_baked_entrypoint(req: &ExecRequest) -> bool {
    matches!(&req.target, ExecTarget::Inline { argv } if argv.is_empty())
}

/// Run the image's baked entrypoint and return the status it exited with.
/// The agent validates the entrypoint at boot but does not autostart it, so
/// the host must dispatch `RunEntrypoint` rather than wait for an exit file.
pub(super) fn dispatch_baked_entrypoint(
    vm_name: &str,
    req: &ExecRequest,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<mvm_core::vm_backend::VmExitStatus> {
    if !wait_for_agent_timed(vm_name, 30, sub) {
        emit_guest_console_diagnostic(vm_name);
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    use crate::commands::vm::invoke::{DispatchStdin, EntrypointDispatch, dispatch};
    let code = dispatch(EntrypointDispatch {
        vm_name,
        stdin: DispatchStdin::OneShot(req.stdin.clone()),
        timeout_secs: baked_entrypoint_timeout_secs(req.timeout_secs),
        session_id: None,
    })
    .with_context(|| format!("running the baked entrypoint in {vm_name}"))?;
    Ok(dispatched_exit_status(code))
}

/// The entrypoint verb interprets zero as an already-expired deadline, not
/// an unbounded one. Match its own 30-second default when no timeout is set.
pub(super) fn baked_entrypoint_timeout_secs(requested: Option<u64>) -> u64 {
    requested.unwrap_or(30)
}

/// A successful dispatch always returns an observed code, including nonzero.
pub(super) fn dispatched_exit_status(code: i32) -> mvm_core::vm_backend::VmExitStatus {
    mvm_core::vm_backend::VmExitStatus {
        code: Some(code),
        success: code == 0,
    }
}

pub(super) fn baked_entrypoint_result(
    status: mvm_core::vm_backend::VmExitStatus,
    capture: bool,
    vm_name: &str,
) -> Result<Either<i32, ExecOutput>> {
    let code = status.code.with_context(|| {
        format!("baked workload in {vm_name} stopped without reporting its exit code")
    })?;
    if capture {
        Ok(Either::Right(ExecOutput {
            exit_code: code,
            stdout: String::new(),
            stderr: String::new(),
            phase_timing: None,
        }))
    } else {
        Ok(Either::Left(code))
    }
}
