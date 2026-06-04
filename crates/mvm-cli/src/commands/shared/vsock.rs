//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through the canonical `mvm::vsock_transport::for_vm`
//! dispatcher — the same selector `invoke`/`exec`/`readiness` use. It
//! probes the live backend (apple-container → libkrun → firecracker)
//! per VM. The previous hardcoded `AppleContainerTransport` left the
//! libkrun `up` path unable to ever reach its agent.

use anyhow::Result;

use mvm::vsock_transport;

/// Wait for the guest agent to complete the ADR-053 / plan 74 W1
/// protocol hello over vsock. Returns true once the agent has
/// answered `ProtocolHelloAck` (with at least the `Ping` capability)
/// within `timeout_secs`. A `ProtocolMismatch` answer, a transport
/// error, or an unexpected response counts as "not ready yet" and the
/// probe keeps polling until the deadline.
pub fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Plan 93 Phase 2 Lever 2: adaptive backoff instead of a fixed
    // 500 ms poll. A guest that binds in ~80 ms used to wait up to a
    // full 500 ms before the next probe noticed; the backoff starts at
    // 20 ms and grows to the same 500 ms cap, so the common fast-boot
    // case is detected far sooner while a slow guest still polls at the
    // old steady cadence. This is a timing change only — the
    // connect→`negotiate_protocol` ordering (and the
    // ProtocolHello/Ack contract) is untouched; no RPC is issued before
    // negotiation succeeds.
    //
    // Resolve the transport each iteration via `for_vm`: it selects the
    // live backend by connecting to the agent port, so a still-booting
    // guest simply fails this attempt and we retry on the next tick.
    let mut attempt: u32 = 0;
    while std::time::Instant::now() < deadline {
        if let Ok(transport) = vsock_transport::for_vm(vm_id)
            && let Ok(mut s) = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            && mvm_guest::vsock::negotiate_protocol(
                &mut s,
                vec![mvm_guest::vsock::GuestCapability::Ping],
            )
            .is_ok()
        {
            return true;
        }
        std::thread::sleep(mvm_guest::vsock::adaptive_backoff(attempt));
        attempt = attempt.saturating_add(1);
    }
    false
}

/// Tell the guest agent to start a vsock→TCP forwarder for the given port.
pub fn request_port_forward(vm_id: &str, guest_port: u16) -> Result<u32> {
    let transport = vsock_transport::for_vm(vm_id)?;
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::start_port_forward_on(&mut stream, guest_port)
}

/// Post-boot mount of user directory-share volumes on a workload VM
/// (path b). The backend already attached each as virtio-fs tag
/// `uvol{idx}`; this issues the in-guest `mount` via the agent's
/// `MountVolume` RPC. `shares` is `(tag, guest_path, read_only)` for
/// the dir-share volumes only (disk images mount differently / later).
///
/// Best-effort + warned per share: the VM is already running, so one
/// failed mount must not abort the boot. The guest enforces its
/// `MountPathPolicy` (allow-roots `/mnt`, `/data`, `/work`), so a guest
/// path outside those surfaces as a per-share warning here.
pub fn mount_user_dir_shares(vm_id: &str, shares: &[(String, String, bool)]) {
    if shares.is_empty() {
        return;
    }
    let transport = match vsock_transport::for_vm(vm_id) {
        Ok(t) => t,
        Err(e) => {
            crate::ui::warn(&format!(
                "Could not reach guest agent to mount {} volume(s): {e}",
                shares.len()
            ));
            return;
        }
    };
    for (tag, guest_path, read_only) in shares {
        let result = transport
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .and_then(|mut s| {
                mvm_guest::vsock::mount_volume_on(&mut s, tag, guest_path, *read_only)
            });
        match result {
            Ok(path) => crate::ui::info(&format!("Mounted volume at {path} in guest.")),
            Err(e) => crate::ui::warn(&format!("Volume mount {guest_path} failed: {e}")),
        }
    }
}

/// Plan 74 W2 / Plan 51 W6 — emit a `LocalAuditKind::NetworkPolicyAllow`
/// audit record for one host→guest vsock RPC. Pairs with
/// `GuestRequest::kind_name()`; the verb name lands in the audit
/// detail as `verb=<kebab-name>`.
///
/// Detail format (mvmd ADR 0022 §"Audit-first principle"):
///
/// ```text
/// scope=rpc,direction=in,kind=vsock,verb=<name>
/// ```
///
/// The `vm` field carries the target VM name. mvmd ADR 0022 §item 2
/// names this as part of the inbound audit story — Plan 37 §6
/// invariant "every state-changing CLI verb emits ≥1 audit" extends
/// to the underlying vsock messages each verb dispatches.
///
/// Pure host-side helper — does not touch the network or the guest;
/// just records the intent. The audit_emit! macro writes to the
/// default audit log path.
///
/// Verbs to migrate (each in a follow-up slice) include `Exec`,
/// `RunEntrypoint`, `RunCode`, `FsRead`/`FsWrite`/`FsList`,
/// `ProcStart`/`ProcSignal`, `MountVolume`/`UnmountVolume`,
/// `ConsoleOpen`. The Ping poll loop in `wait_for_guest_agent`
/// deliberately *doesn't* migrate — every poll iteration would
/// audit-spam (mostly while waiting for the agent to bind), so
/// readiness probes get a separate `AgentReady` LocalAudit event
/// in the `mvmctl up` flow already.
pub fn emit_vsock_rpc_audit(vm_id: &str, request: &mvm_guest::vsock::GuestRequest) {
    let verb = request.kind_name();
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_id,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The detail format string follows the convention pinned
    /// in mvm PR #275 + mvmd ADR 0022. The audit-emit macro
    /// writes to the default audit log path so we can't observe
    /// the record's content directly without log-pointer
    /// plumbing — the contract here is that the function
    /// composes cleanly with every variant.
    #[test]
    fn emit_vsock_rpc_audit_does_not_panic_on_common_verbs() {
        let cases = [
            mvm_guest::vsock::GuestRequest::Ping,
            mvm_guest::vsock::GuestRequest::ReadinessStatus,
            mvm_guest::vsock::GuestRequest::EntrypointStatus,
            mvm_guest::vsock::GuestRequest::FsDiff,
            mvm_guest::vsock::GuestRequest::Exec {
                command: "echo hello".to_string(),
                stdin: None,
                timeout_secs: Some(30),
            },
        ];
        for req in cases {
            emit_vsock_rpc_audit("vm-test", &req);
        }
    }
}
