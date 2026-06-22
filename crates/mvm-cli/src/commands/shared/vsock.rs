//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through the canonical `mvm::vsock_transport::for_vm`
//! dispatcher — the same selector `invoke`/`exec`/`readiness` use. It
//! probes the live backend (libkrun → vz → firecracker) per VM, so a
//! VM started under any backend reaches its agent on the right transport.

use anyhow::{Context, Result};

use mvm::vsock_transport;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

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

/// Host-side SSH-agent socket proxy for dev-tier machines.
///
/// This lives with the existing per-VM port/vsock substrate because it binds a
/// local listener and splices it to a guest-visible vsock path. The only
/// upstream it may dial is the already validated host `SSH_AUTH_SOCK` Unix
/// socket; callers are responsible for policy admission before spawning it.
pub(crate) fn run_ssh_agent_proxy_uds(listen_uds: &Path, host_sock: &Path) -> Result<()> {
    if let Some(parent) = listen_uds.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(listen_uds);
    let listener = UnixListener::bind(listen_uds)
        .with_context(|| format!("binding ssh-agent proxy {}", listen_uds.display()))?;
    std::fs::set_permissions(listen_uds, std::fs::Permissions::from_mode(0o600))?;
    println!("READY");
    std::io::stdout().flush().ok();
    serve_ssh_agent_unix_listener(listener, host_sock)
}

fn serve_ssh_agent_unix_listener(listener: UnixListener, host_sock: &Path) -> Result<()> {
    for inbound in listener.incoming() {
        let inbound = inbound?;
        let host_sock = host_sock.to_path_buf();
        std::thread::spawn(move || {
            if let Ok(agent) = UnixStream::connect(&host_sock) {
                splice_unix_streams(inbound, agent);
            }
        });
    }
    Ok(())
}

pub(crate) fn run_ssh_agent_proxy_vsock(port: u32, host_sock: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use mvm_hostd::supervisor::substitution_proxy::vsock::{VsockListener, accept};
        use std::os::fd::FromRawFd;
        let listener = VsockListener::bind(port)
            .with_context(|| format!("binding AF_VSOCK ssh-agent proxy port {port}"))?;
        println!("READY");
        std::io::stdout().flush().ok();
        loop {
            let fd = accept(listener.raw_fd())?;
            let inbound = unsafe {
                // SAFETY: `accept` returned a fresh connected socket fd owned by
                // this process; UnixStream is an fd wrapper suitable for splice.
                UnixStream::from_raw_fd(fd)
            };
            let host_sock = host_sock.to_path_buf();
            std::thread::spawn(move || {
                if let Ok(agent) = UnixStream::connect(&host_sock) {
                    splice_unix_streams(inbound, agent);
                }
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (port, host_sock);
        anyhow::bail!("AF_VSOCK ssh-agent proxy listener is linux-only")
    }
}

fn splice_unix_streams(left: UnixStream, right: UnixStream) {
    let Ok(mut left_read) = left.try_clone() else {
        return;
    };
    let Ok(mut right_write) = right.try_clone() else {
        return;
    };
    let mut left_write = left;
    let mut right_read = right;
    let h1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut left_read, &mut right_write);
    });
    let h2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut right_read, &mut left_write);
    });
    let _ = h1.join();
    let _ = h2.join();
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
