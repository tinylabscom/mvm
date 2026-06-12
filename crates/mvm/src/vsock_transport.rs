//! Backend-agnostic vsock connect dispatch.
//!
//! Hides the choice between Firecracker's UDS multiplexer, libkrun's
//! per-port Unix sockets, and the vz supervisor's per-port socket
//! behind one trait, so callers that just need "give me a connected
//! stream to vsock port `P` on VM `V`" don't have to know which backend
//! the VM is running under. Before this trait, every caller open-coded
//! the same per-backend connect ladder; new backends or backend changes
//! had to chase down every occurrence.
//!
//! Each impl is stateless apart from configuration captured at
//! construction time. `connect()` always returns a fresh stream —
//! the trait never owns or pools connections, since each control-
//! plane RPC and console session is short-lived.

use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use mvm_backend::microvm;

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

/// Connects through libkrun's per-port Unix socket.
///
/// `LibkrunBackend` starts each VM with `vsock_socket_dir` set to
/// `~/.mvm/vms/<name>`, and mvm-libkrun exposes each registered vsock
/// port as `<dir>/vsock-<port>.sock`.
pub struct LibkrunTransport {
    socket_dir: PathBuf,
}

impl LibkrunTransport {
    pub fn new(socket_dir: impl Into<PathBuf>) -> Self {
        Self {
            socket_dir: socket_dir.into(),
        }
    }

    pub fn for_vm(vm_name: &str) -> Self {
        // Single source of truth for the per-VM dir (honors MVM_DATA_DIR).
        // for_vm(name).socket_path(port) now equals
        // mvm_core::config::vm_vsock_port_socket(name, port) — the same path
        // the dev-VM connect resolver uses, so they can't drift.
        Self::new(mvm_core::config::vm_state_dir(vm_name))
    }

    fn socket_path(&self, port: u32) -> PathBuf {
        self.socket_dir
            .join(mvm_core::config::vsock_socket_filename(port))
    }
}

impl VsockTransport for LibkrunTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let path = self.socket_path(port);
        UnixStream::connect(&path)
            .with_context(|| format!("Failed to connect to libkrun vsock at {}", path.display()))
    }
}

/// Connects through the Vz supervisor's per-port vsock listener.
///
/// `VzBackend` starts the Swift supervisor with a `VsockProxy` that
/// listens under `<vm_state_dir>/vsock/` and forwards each connection to
/// the guest's vsock port, so a host client connects directly with no
/// port handshake — the libkrun shape, one subdir deeper. The path is the
/// single-source-of-truth [`mvm_core::config::vm_vz_vsock_port_socket`].
pub struct VzTransport {
    socket_dir: PathBuf,
}

impl VzTransport {
    pub fn new(socket_dir: impl Into<PathBuf>) -> Self {
        Self {
            socket_dir: socket_dir.into(),
        }
    }

    pub fn for_vm(vm_name: &str) -> Self {
        Self::new(mvm_core::config::vm_vz_vsock_dir(vm_name))
    }

    fn socket_path(&self, port: u32) -> PathBuf {
        self.socket_dir
            .join(mvm_core::config::vsock_socket_filename(port))
    }
}

impl VsockTransport for VzTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let path = self.socket_path(port);
        UnixStream::connect(&path)
            .with_context(|| format!("Failed to connect to Vz vsock at {}", path.display()))
    }
}

/// Connects through the nesting hop: the outer host
/// reaches a workload microVM's vsock *via* the long-lived libkrun
/// host VM. The hop socket is the host VM's libkrun UDS for
/// [`mvm_guest::builder_agent::WORKLOAD_FORWARD_PORT`]
/// (`<vm_state_dir>/vsock-21472.sock`). On connect, the host writes a
/// `<workload_id> <port>` handshake and the in-host-VM forwarder
/// (`mvm_host_vm_init::workload_proxy`) multiplexes the stream to that
/// workload's Firecracker `v.sock`. The workload guest agent is
/// unchanged — it still sees vsock CID 3, just one nesting level in.
pub struct NestingHopTransport {
    hop_socket_path: PathBuf,
    workload_id: String,
}

impl NestingHopTransport {
    pub fn new(hop_socket_path: impl Into<PathBuf>, workload_id: impl Into<String>) -> Self {
        Self {
            hop_socket_path: hop_socket_path.into(),
            workload_id: workload_id.into(),
        }
    }

    /// Build the hop transport for a host VM whose libkrun vsock
    /// sockets live under `vm_state_dir`, targeting `workload_id`. The
    /// forward-port socket name mirrors libkrun's `vsock-<port>.sock`
    /// convention.
    pub fn for_host_vm(vm_state_dir: impl Into<PathBuf>, workload_id: impl Into<String>) -> Self {
        let dir: PathBuf = vm_state_dir.into();
        let hop = dir.join(format!(
            "vsock-{}.sock",
            mvm_guest::builder_agent::WORKLOAD_FORWARD_PORT
        ));
        Self::new(hop, workload_id)
    }
}

impl VsockTransport for NestingHopTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.hop_socket_path).with_context(|| {
            format!(
                "Failed to connect to nesting hop at {}",
                self.hop_socket_path.display()
            )
        })?;
        let handshake =
            mvm_guest::builder_agent::encode_workload_forward_handshake(&self.workload_id, port);
        stream
            .write_all(&handshake)
            .with_context(|| "Failed to write nesting-hop handshake")?;
        Ok(stream)
    }
}

/// Pick a transport for a VM by name.
///
/// Probes libkrun's per-port Unix socket first, then the vz supervisor's
/// per-port socket, then Firecracker by resolving the running VM's
/// instance directory — the cheapest probe that doesn't require the
/// caller to know the backend ahead of time.
///
/// Note: the probe consumes one stream and immediately drops it;
/// callers get a *fresh* stream from the returned transport's
/// `connect()`. This matches the legacy ladder it replaces, which
/// already did one throwaway probe before the real call.
pub fn for_vm(vm_name: &str) -> Result<Box<dyn VsockTransport>> {
    let libkrun = LibkrunTransport::for_vm(vm_name);
    if libkrun.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(libkrun));
    }
    let vz = VzTransport::for_vm(vm_name);
    if vz.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(vz));
    }
    let fc = FirecrackerTransport::for_vm(vm_name)
        .with_context(|| format!("no vsock transport found for VM {:?}", vm_name))?;
    Ok(Box::new(fc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_transport_constructs_with_instance_dir() {
        let t = FirecrackerTransport::new("/tmp/no-such-instance", 1);
        // No real socket → error mentions the UDS path so callers
        // can tell which backend is being attempted.
        let err = t
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect_err("should fail to connect");
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/no-such-instance"),
            "error didn't mention instance dir: {msg}"
        );
    }

    #[test]
    fn libkrun_transport_constructs_with_socket_dir() {
        let t = LibkrunTransport::new("/tmp/no-such-libkrun-vm");
        let err = t
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect_err("should fail to connect");
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/no-such-libkrun-vm"),
            "error didn't mention socket dir: {msg}"
        );
    }

    #[test]
    fn vz_transport_connects_to_socket_in_its_dir() {
        use std::os::unix::net::UnixListener;
        // Vz's supervisor listens on `<vsock_dir>/vsock-<port>.sock`; a host
        // client connects directly (no port handshake), same shape as libkrun.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir
            .path()
            .join(mvm_core::config::vsock_socket_filename(5252));
        let _listener = UnixListener::bind(&sock).unwrap();
        let t = VzTransport::new(dir.path());
        t.connect(5252).expect("vz transport should connect");
    }

    #[test]
    fn vz_transport_for_vm_targets_vsock_subdir() {
        // for_vm must point at `<vm_state_dir>/vsock/` (Vz nests one subdir
        // deeper than libkrun's `<vm_state_dir>/`), and the error names the
        // backend so console failures are diagnosable.
        let t = VzTransport::for_vm("no-such-vz-vm");
        let err = t
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect_err("should fail to connect")
            .to_string();
        assert!(
            err.contains("Vz vsock") && err.contains("/vsock/vsock-5252.sock"),
            "error didn't show the vz vsock-subdir path: {err}"
        );
    }

    #[test]
    fn for_vm_selects_vz_when_only_vz_socket_present() {
        use std::os::unix::net::UnixListener;
        // With a Vz workload's socket present (and no apple-container/libkrun/
        // firecracker surface), the picker must select the Vz transport rather
        // than falling through to the firecracker error. Regression for the
        // "console can't reach a Vz workload" gap.
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MVM_DATA_DIR", dir.path()) };
        let name = "vz-picker-probe";
        let sock =
            mvm_core::config::vm_vz_vsock_port_socket(name, mvm_guest::vsock::GUEST_AGENT_PORT);
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&sock).unwrap();

        let t = for_vm(name).expect("picker should find the vz transport");
        t.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport should connect to the vz socket");

        unsafe { std::env::remove_var("MVM_DATA_DIR") };
    }

    #[test]
    fn nesting_hop_for_host_vm_derives_forward_socket_path() {
        let t = NestingHopTransport::for_host_vm("/tmp/vm-state", "wl-1");
        assert_eq!(
            t.hop_socket_path,
            PathBuf::from("/tmp/vm-state/vsock-21472.sock")
        );
        assert_eq!(t.workload_id, "wl-1");
    }

    #[test]
    fn nesting_hop_connect_error_mentions_hop_path() {
        let t = NestingHopTransport::new("/tmp/no-such-hop-21472.sock", "wl-1");
        let err = t
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect_err("should fail to connect");
        let msg = err.to_string();
        assert!(
            msg.contains("nesting hop") && msg.contains("/tmp/no-such-hop-21472.sock"),
            "error didn't mention hop path: {msg}"
        );
    }

    #[test]
    fn nesting_hop_writes_handshake_on_connect() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let hop = dir.path().join("vsock-21472.sock");
        let listener = UnixListener::bind(&hop).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            conn.read_exact(&mut len).unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut body = vec![0u8; n];
            conn.read_exact(&mut body).unwrap();
            (len.to_vec(), body)
        });

        let t = NestingHopTransport::new(&hop, "wl-abc");
        let _stream = t.connect(5252).expect("connect + handshake");

        let (len, body) = server.join().unwrap();
        // The bytes on the wire must be exactly what the shared
        // host-side encoder produces (which the guest forwarder
        // parses) — pins the hop wire shape end-to-end.
        let mut expected =
            mvm_guest::builder_agent::encode_workload_forward_handshake("wl-abc", 5252);
        let expected_body = expected.split_off(4);
        assert_eq!(len, expected, "length prefix mismatch");
        assert_eq!(body, expected_body, "handshake body mismatch");
        assert_eq!(String::from_utf8(body).unwrap(), "wl-abc 5252");
    }
}
