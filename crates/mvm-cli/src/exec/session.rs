//! Dispatching into an already-booted session VM, and waiting for its agent.
//!
//! Booting and tearing down a session VM are `mvm_client::entrypoint`'s; what
//! stays here is the dev-only shell dispatch (`session exec`, a machine's
//! `dev.init`) and the agent wait the transient runner times.

use super::*;

pub use mvm_client::entrypoint::SessionVm;

/// Dispatch a single command into an already-booted session VM,
/// capturing stdout/stderr. Equivalent to the dispatch step of
/// [`run_captured`] without any boot/teardown.
pub fn dispatch_in_session(
    vm: &SessionVm,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<ExecOutput> {
    let output = mvm_client::execution::dispatch_in_session(vm, code, timeout_secs)?;
    Ok(ExecOutput {
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
        phase_timing: None,
    })
}

pub fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let mut untimed = crate::commands::vm::phase_timing::LaunchSubMarks::new(false);
    wait_for_agent_timed(vm_name, timeout_secs, &mut untimed)
}

/// [`wait_for_agent`], recording where the readiness wait went.
///
/// Two spans come out of it. `GuestKernelEntry` — opened when the VMM started
/// its vCPUs — closes at the start of the attempt that succeeded, so it is the
/// guest-boot window bounded below by the poll interval, not an exact mark.
/// `AgentAuth` covers only that successful attempt's connect and authenticated
/// ping, which is exact.
pub(super) fn wait_for_agent_timed(
    vm_name: &str,
    timeout_secs: u64,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> bool {
    use crate::commands::vm::phase_timing::SubPhase;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0u32;
    while std::time::Instant::now() < deadline {
        // Each attempt re-opens the handshake span, so a failed probe leaves
        // no partial span behind and the reported cost is the one that worked.
        sub.finish(SubPhase::GuestKernelEntry);
        sub.start(SubPhase::AgentAuth);
        // Re-pick the transport on each iteration: a Firecracker VM
        // that's still booting may not show up in
        // resolve_running_vm_dir until the daemon registers it.
        // "agent reachable" means it answered on the wire, not just that the
        // socket is open — the VMM binds the agent port before the guest kernel
        // starts, so a connect alone also succeeds against a guest that is still
        // booting or that panicked before userspace. `probe_agent_ready`
        // handshakes and pings, so returning true here means the caller's next
        // RPC reaches a live agent instead of reading EOF.
        if let Ok(transport) = vsock_transport::for_vm(vm_name)
            && let Ok(mut stream) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            && {
                // Bound each probe: a transport whose socket is bound but whose
                // guest agent hasn't replied yet (e.g. still booting, or an
                // hvf VMM whose relay isn't answering) must not block the
                // whole handshake read forever — otherwise this loop never gets
                // back to the deadline check and hangs instead of timing out. A
                // short per-attempt read timeout lets the probe fail fast so
                // the outer loop retries and ultimately honours `timeout_secs`.
                // The stream is a throwaway probe (dropped below), so the timeout
                // never touches a real agent-RPC data stream.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                mvm_agentd::vsock::probe_agent_ready(&mut stream).is_ok()
            }
        {
            sub.finish(SubPhase::AgentAuth);
            return true;
        }
        // Adaptive, not fixed: readiness is only observed on a tick, so the
        // cadence is a floor under the reported wait. A flat 50ms tick put
        // guest-ready at 53.8ms p50 on a backend whose VM creation takes
        // 53.8ms — the number was reporting the tick, not the guest. Starting
        // fine and backing off keeps a fast guest cheap to notice while a slow
        // one still costs few attempts. The probes are connect+hello and fail
        // fast while the guest is still booting.
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
    false
}
