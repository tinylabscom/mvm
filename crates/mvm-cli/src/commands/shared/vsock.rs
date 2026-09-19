//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through the canonical `mvm_runtime::vsock_transport::for_vm`
//! dispatcher — the same selector `invoke`/`exec`/`readiness` use. It
//! probes the live backend (hvf agent bridge → libkrun → hvf per-port vsock →
//! firecracker) per VM, so a VM started under any backend reaches its agent
//! on the right transport.

use mvm_runtime::vsock_transport;

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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

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
        if let Ok(transport) = vsock_transport::for_vm(vm_id)
            && let Ok(mut s) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            && {
                // Bound the probe so a bound-but-silent socket can't park the
                // loop past its deadline.
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                mvm_agentd::vsock::probe_agent_ready(&mut s).is_ok()
            }
        {
            return true;
        }
        std::thread::sleep(mvm_agentd::vsock::adaptive_backoff(attempt));
        attempt = attempt.saturating_add(1);
    }
    false
}

pub use mvm_client::guest::emit_vsock_rpc_audit;
