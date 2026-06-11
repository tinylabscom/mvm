//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through the canonical `mvm::vsock_transport::for_vm`
//! dispatcher — the same selector `invoke`/`exec`/`readiness` use. It
//! probes the live backend (libkrun → vz → firecracker) per VM, so a
//! VM started under any backend reaches its agent on the right transport.

use anyhow::Result;

use mvm::vsock_transport;

/// Wait for the guest agent to complete the protocol hello over
/// vsock. Returns true once the agent has
/// answered `ProtocolHelloAck` (with at least the `Ping` capability)
/// within `timeout_secs`. A `ProtocolMismatch` answer, a transport
/// error, or an unexpected response counts as "not ready yet" and the
/// probe keeps polling until the deadline.
pub fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Adaptive backoff instead of a fixed 500 ms poll. A guest that
    // binds in ~80 ms used to wait up to a
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

/// Host-side half of a port forward: bind `localhost:host_port`, and for
/// each accepted connection splice it to the guest's TCP port over vsock
/// (the guest agent runs the vsock→TCP forwarder at `PORT_FORWARD_BASE +
/// guest_port`, set up by [`request_port_forward`]). Backend-agnostic —
/// the guest vsock is resolved via `vsock_transport::for_vm`. Runs in a
/// detached background thread; bind/connect failures warn and drop that
/// forward rather than failing the launch.
pub fn start_port_proxy(vm_id: &str, host_port: u16, guest_port: u16) {
    use std::net::TcpListener;

    let bind = format!("127.0.0.1:{host_port}");
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Port proxy bind {bind} failed: {e}");
            return;
        }
    };
    // Must match mvm_guest::vsock::PORT_FORWARD_BASE.
    let vsock_port = 10000u32 + guest_port as u32;
    tracing::info!(
        "Port forwarding: localhost:{host_port} → vsock:{vsock_port} → guest tcp/{guest_port}"
    );

    let vm_id = vm_id.to_string();
    std::thread::Builder::new()
        .name(format!("proxy-{host_port}"))
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let vm_id = vm_id.clone();
                std::thread::spawn(move || {
                    let upstream =
                        match vsock_transport::for_vm(&vm_id).and_then(|t| t.connect(vsock_port)) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    "Port proxy: vsock connect to {vm_id} port {vsock_port} failed: {e}"
                                );
                                return;
                            }
                        };
                    let downstream = stream;
                    let Ok(mut up_read) = upstream.try_clone() else {
                        tracing::warn!("Port proxy: upstream clone failed");
                        return;
                    };
                    let Ok(mut down_write) = downstream.try_clone() else {
                        tracing::warn!("Port proxy: downstream clone failed");
                        return;
                    };
                    let mut up_write = upstream;
                    let mut down_read = downstream;
                    let h1 = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut down_read, &mut up_write);
                    });
                    let h2 = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut up_read, &mut down_write);
                    });
                    let _ = h1.join();
                    let _ = h2.join();
                });
            }
        })
        .ok();
}

/// Emit a `LocalAuditKind::NetworkPolicyAllow` audit record for one
/// host→guest vsock RPC. Pairs with `GuestRequest::kind_name()`; the
/// verb name lands in the audit detail as `verb=<kebab-name>`.
///
/// Detail format:
///
/// ```text
/// scope=rpc,direction=in,kind=vsock,verb=<name>
/// ```
///
/// The `vm` field carries the target VM name. The "every state-changing
/// CLI verb emits ≥1 audit" invariant extends to the underlying vsock
/// messages each verb dispatches.
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

    /// The detail format string follows the established convention.
    /// The audit-emit macro
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
