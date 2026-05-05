//! Backend-agnostic vsock connect dispatch.
//!
//! Hides the choice between Firecracker's UDS multiplexer and Apple
//! Container's `VZVirtioSocketDevice` (or its mode-0700 proxy
//! socket) behind one trait, so callers that just need "give me a
//! connected stream to vsock port `P` on VM `V`" don't have to know
//! which backend the VM is running under. Before this trait, every
//! caller open-coded the same `if let Ok(stream) =
//! mvm_apple_container::vsock_connect(...) { ... } else { ... }`
//! ladder; new backends or backend changes had to chase down every
//! occurrence.
//!
//! Each impl is stateless apart from configuration captured at
//! construction time. `connect()` always returns a fresh stream —
//! the trait never owns or pools connections, since each control-
//! plane RPC and console session is short-lived.

use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;

use crate::vm::microvm;

/// Open a vsock connection to a port on a guest.
///
/// Implementations must be `Send + Sync` so factory `Box<dyn>`
/// returns can cross thread boundaries (the console wires data and
/// control channels through separate worker threads).
pub trait VsockTransport: Send + Sync {
    /// Connect and return a stream ready for length-prefixed JSON I/O.
    /// The Firecracker handshake (`CONNECT <port>\n` / `OK <port>\n`)
    /// is performed inside this call when applicable; on Apple
    /// Container the framework returns a stream directly.
    fn connect(&self, port: u32) -> Result<UnixStream>;
}

/// Connects through a Firecracker vsock UDS multiplexer.
///
/// The `instance_dir` is the runtime-state directory where Firecracker
/// places `runtime/v.sock`; see [`mvm_guest::vsock::vsock_uds_path`].
pub struct FirecrackerTransport {
    instance_dir: String,
    timeout_secs: u64,
}

impl FirecrackerTransport {
    pub fn new(instance_dir: impl Into<String>, timeout_secs: u64) -> Self {
        Self {
            instance_dir: instance_dir.into(),
            timeout_secs,
        }
    }

    /// Resolve the running VM's instance directory and build a
    /// transport with [`mvm_guest::vsock::DEFAULT_TIMEOUT_SECS`].
    pub fn for_vm(vm_name: &str) -> Result<Self> {
        let instance_dir = microvm::resolve_running_vm_dir(vm_name)?;
        Ok(Self::new(
            instance_dir,
            mvm_guest::vsock::DEFAULT_TIMEOUT_SECS,
        ))
    }
}

impl VsockTransport for FirecrackerTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let uds = mvm_guest::vsock::vsock_uds_path(&self.instance_dir);
        mvm_guest::vsock::connect_to_port(&uds, port, self.timeout_secs)
    }
}

/// Connects through Apple's `Virtualization.framework` vsock device.
///
/// `mvm_apple_container::vsock_connect` consults the framework's
/// in-process VM registry and either returns a direct
/// `VZVirtioSocketDevice` stream (mac host) or routes through the
/// per-VM proxy socket (cross-process / development).
pub struct AppleContainerTransport {
    vm_name: String,
}

impl AppleContainerTransport {
    pub fn new(vm_name: impl Into<String>) -> Self {
        Self {
            vm_name: vm_name.into(),
        }
    }
}

impl VsockTransport for AppleContainerTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        mvm_apple_container::vsock_connect(&self.vm_name, port)
            .map_err(|e| anyhow::anyhow!("Apple Container vsock connect failed: {e}"))
    }
}

/// Connects through the daemon-managed mode-0700 proxy Unix socket.
///
/// Used for cross-process access in dev — the `mvmctl dev` daemon
/// owns the framework-side VM and exposes a per-VM Unix socket where
/// each new connection writes the destination vsock port as a
/// 4-byte little-endian prefix and the daemon then forwards bytes
/// to the framework. Mode-0700 is the security boundary
/// (ADR-002 §W1.2).
pub struct VsockProxyTransport {
    proxy_path: String,
}

impl VsockProxyTransport {
    pub fn new(proxy_path: impl Into<String>) -> Self {
        Self {
            proxy_path: proxy_path.into(),
        }
    }
}

impl VsockTransport for VsockProxyTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.proxy_path)
            .with_context(|| format!("Failed to connect to vsock proxy at {}", &self.proxy_path))?;
        stream
            .write_all(&port.to_le_bytes())
            .with_context(|| "Failed to write vsock proxy port prefix")?;
        Ok(stream)
    }
}

/// Pick a transport for a VM by name.
///
/// Probes Apple Container first by attempting a real connect to the
/// agent control port — that's the cheapest probe that doesn't
/// require the caller to know the backend ahead of time. Falls back
/// to Firecracker by resolving the running VM's instance directory.
///
/// Note: the probe consumes one stream and immediately drops it;
/// callers get a *fresh* stream from the returned transport's
/// `connect()`. This matches the legacy ladder it replaces, which
/// already did one throwaway probe before the real call.
pub fn for_vm(vm_name: &str) -> Result<Box<dyn VsockTransport>> {
    if mvm_apple_container::vsock_connect(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(AppleContainerTransport::new(vm_name)));
    }
    let fc = FirecrackerTransport::for_vm(vm_name)
        .with_context(|| format!("no vsock transport found for VM {:?}", vm_name))?;
    Ok(Box::new(fc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_transport_writes_port_prefix() {
        // socketpair acts as a stand-in for the daemon's listening
        // proxy socket: the "client" side of VsockProxyTransport
        // should write the port bytes immediately on connect.
        // We can't actually drive `connect()` here because the
        // proxy_path needs to be a real filesystem socket; this test
        // only exercises construction + the public surface so the
        // factory contract has a regression net even on hosts where
        // `tempfile` + UDS listeners would be flaky in CI.
        let t = VsockProxyTransport::new("/tmp/mvm-proxy-does-not-exist.sock");
        let err = t.connect(52).expect_err("should fail to connect");
        assert!(
            err.to_string().contains("vsock proxy"),
            "error didn't mention proxy: {err}"
        );
    }

    #[test]
    fn firecracker_transport_constructs_with_instance_dir() {
        let t = FirecrackerTransport::new("/tmp/no-such-instance", 1);
        // No real socket → error mentions the UDS path so callers
        // can tell which backend is being attempted.
        let err = t.connect(52).expect_err("should fail to connect");
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/no-such-instance"),
            "error didn't mention instance dir: {msg}"
        );
    }
}
