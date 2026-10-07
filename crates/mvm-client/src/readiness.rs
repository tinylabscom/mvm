//! Host-observed readiness milestones.
//!
//! Recording a readiness milestone is best-effort local observability, not a
//! machine-lifecycle operation: a remote fleet's daemon records its own
//! milestones, so this is a sync free function on the client boundary rather
//! than an `MvmClient` trait method (whose async, remote-capable shape would be
//! an impedance mismatch for a purely-local registry write). It lives here so
//! the CLI reaches the host name registry through the client crate instead of
//! naming `mvm-runtime` internals directly.

use mvm_core::domain::instance::InstanceReadiness;

/// Persist a host-observed readiness milestone on the VM's name-registry entry.
///
/// Best-effort: an unregistered VM or a registry I/O error degrades to a log
/// line inside the registry helper, never an error here — readiness is a
/// display signal for `mvmctl ls/ps --json`, never a control-flow gate.
pub fn record_readiness(vm_name: &str, readiness: InstanceReadiness) {
    mvm_runtime::vm::name_registry::record_readiness(vm_name, readiness);
}

/// Read a machine's last-recorded readiness milestone from the name registry —
/// the read counterpart to [`record_readiness`]. `None` if the machine has no
/// registry entry or no recorded milestone. Best-effort: a registry that can't
/// be loaded reads as `None`.
pub fn readiness_of(vm_name: &str) -> Option<InstanceReadiness> {
    let path = mvm_runtime::vm::name_registry::registry_path();
    let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).ok()?;
    registry
        .lookup(vm_name)
        .and_then(|reg| reg.readiness.clone())
}

/// Record a coarse guest-activity touch (`last_active`) on a machine's registry
/// entry. Best-effort like [`record_readiness`]: only rewrites when the name is
/// registered, and swallows any load/save hiccup so a console attach never
/// blocks on registry I/O.
pub fn touch_activity(vm_name: &str) {
    let path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut reg) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path)
        && reg
            .touch_last_active(vm_name, mvm_core::time::utc_now())
            .unwrap_or(false)
    {
        let _ = reg.save(&path);
    }
}

/// A live `ReadinessReport` from a running machine's guest agent — the
/// read counterpart to the registry milestones above. Drives the
/// protocol-hello prelude and a single `ReadinessStatus` request through
/// the machine's vsock transport, so Firecracker, libkrun, HVF, and the
/// other backends all answer without per-backend code in the caller. It
/// lives here so `mvmctl wait`/`boot-report` and the host library poll
/// the guest through one implementation.
pub use mvm_agentd::vsock::ReadinessReport;

/// Fetch one live readiness report. Typed `RpcError`s cover agent
/// `Error`, profile refusal, and off-contract frames, so the only `Ok`
/// variant is the contracted report.
pub fn fetch_live_readiness(vm_name: &str) -> anyhow::Result<ReadinessReport> {
    use mvm_agentd::vsock::{
        GUEST_AGENT_PORT, GuestCapability, GuestRequest, GuestResponse, call_unary,
        negotiate_protocol,
    };
    let transport: Box<dyn mvm_runtime::vsock_transport::VsockTransport> =
        mvm_runtime::vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(GUEST_AGENT_PORT)?;
    let _ = negotiate_protocol(&mut stream, vec![GuestCapability::Readiness])?;
    match call_unary(&mut stream, &GuestRequest::ReadinessStatus)? {
        GuestResponse::ReadinessStatusReport(report) => Ok(report),
        other => anyhow::bail!("unexpected response to ReadinessStatus: {other:?}"),
    }
}

/// Wait for the guest agent to answer an authenticated RPC over vsock. Returns
/// true once a handshake-and-ping round trip completes within `timeout_secs`; a
/// transport error (EOF from a guest that is still booting, a timeout, an
/// undecodable frame) counts as "not ready yet" and the probe keeps polling
/// until the deadline.
///
/// The round trip is the point. The VMM binds the agent port before the guest
/// kernel starts, so a `connect()` that succeeds says nothing about whether an
/// agent exists behind it.
pub fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    wait_for_guest_agent_for(vm_id, std::time::Duration::from_secs(timeout_secs))
}

/// Duration-based form used by launch policy and tests.
pub fn wait_for_guest_agent_for(vm_id: &str, timeout: std::time::Duration) -> bool {
    wait_with_probe(timeout, |remaining| {
        let Ok(transport) = mvm_runtime::vsock_transport::for_vm(vm_id) else {
            return false;
        };
        let Ok(mut stream) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT) else {
            return false;
        };
        // Never let a bound-but-silent socket park this probe past the launch
        // deadline. Authentication and Ping/Pong must both complete.
        let io_timeout = remaining.min(std::time::Duration::from_secs(3));
        let _ = stream.set_read_timeout(Some(io_timeout));
        let _ = stream.set_write_timeout(Some(io_timeout));
        mvm_agentd::vsock::probe_agent_ready(&mut stream).is_ok()
    })
}

fn wait_with_probe(
    timeout: std::time::Duration,
    mut probe: impl FnMut(std::time::Duration) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;

    // Adaptive backoff instead of a fixed 500 ms poll. A guest that
    // binds in ~80 ms used to wait up to a
    // full 500 ms before the next probe noticed; the backoff starts at
    // 20 ms and grows to the same 500 ms cap, so the common fast-boot
    // case is detected far sooner while a slow guest still polls at the
    // old steady cadence.
    //
    // Resolve the transport each iteration via `for_vm`: it selects the
    // live backend by connecting to the agent port, so a still-booting
    // guest simply fails this attempt and we retry on the next tick.
    let mut attempt: u32 = 0;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if probe(remaining) && std::time::Instant::now() < deadline {
            return true;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(mvm_agentd::vsock::adaptive_backoff(attempt).min(remaining));
        attempt = attempt.saturating_add(1);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_accepts_only_a_successful_authenticated_probe() {
        let mut attempts = 0;
        assert!(wait_with_probe(
            std::time::Duration::from_millis(100),
            |_| {
                attempts += 1;
                attempts == 2
            }
        ));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn readiness_times_out_when_a_bound_peer_never_serves() {
        let started = std::time::Instant::now();
        assert!(!wait_with_probe(
            std::time::Duration::from_millis(35),
            |_| false
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn readiness_rejects_a_probe_that_finishes_after_the_deadline() {
        assert!(!wait_with_probe(
            std::time::Duration::from_millis(10),
            |_| {
                std::thread::sleep(std::time::Duration::from_millis(30));
                true
            }
        ));
    }
}
