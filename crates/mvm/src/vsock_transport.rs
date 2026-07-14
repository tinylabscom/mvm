//! Backend-agnostic vsock connect dispatch.
//!
//! Hides the choice between Firecracker's UDS multiplexer, libkrun's
//! per-port Unix sockets, and Apple Container's `VZVirtioSocketDevice`
//! (or its mode-0700 proxy socket) behind one trait, so callers that
//! just need "give me a connected stream to vsock port `P` on VM `V`"
//! don't have to know which backend the VM is running under. Before
//! this trait, every caller open-coded the same per-backend
//! `vsock_connect(...)` if-ladder; new backends or backend changes had
//! to chase down every occurrence.
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
use mvm_core::platform::Platform;

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

/// Whether unresolved socket probes may fall back to Firecracker's in-Linux
/// runtime directory lookup. On macOS that lookup shells through the dev Linux
/// environment, so it must not run while probing a normal host-side HVF/Vz
/// workload.
pub fn firecracker_transport_supported(platform: Platform) -> bool {
    platform.supports_native_runner()
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

/// Connects through a per-VM supervisor's per-port vsock listener.
///
/// The supervisor listens under `<vm_state_dir>/vsock/` and forwards each
/// connection to the guest's vsock port, so a host client connects directly
/// with no
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

/// Connects to an hvf (`WorkloadRunner` / HVF) VM's vsock channels.
///
/// The hvf runner binds two distinct socket layouts under the per-VM
/// socket dir:
/// - Agent RPC (`GUEST_AGENT_PORT`): `<socket-dir>/hvf-agent.sock` — the
///   standing agent bridge the device binds at boot (see
///   [`mvm_core::config::vm_hvf_agent_socket`]).
/// - Console data (ports in `dev_console_data_ports()`): `<socket-dir>/vsock/vsock-<port>.sock`
///   — same `vsock/` subdir convention the Vz supervisor uses, populated
///   only when `VmStartConfig.dev_console` is true.
///
/// The **agent-RPC** use (via [`for_vm`]) is not gated — every
/// `machine run -- <cmd>` / `machine exec` / `invoke` reaches the agent this
/// way, on prod runners too. The **console-data** use is gated:
/// `pick_console_transport` selects it for console ports only for an accessible
/// (non-sealed) workload, so a sealed production runner cannot receive an
/// interactive attach over this path.
pub struct DevConsoleTransport {
    agent_socket: PathBuf,
    vsock_dir: PathBuf,
}

impl DevConsoleTransport {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        let socket_dir = mvm_core::config::vm_socket_dir_at(&state_dir);
        let agent_socket = socket_dir.join("hvf-agent.sock");
        let vsock_dir = mvm_core::config::vm_vz_vsock_dir_at(&state_dir);
        Self {
            agent_socket,
            vsock_dir,
        }
    }

    pub fn for_vm(vm_name: &str) -> Self {
        let agent_socket = mvm_core::config::vm_hvf_agent_socket(vm_name);
        let vsock_dir = mvm_core::config::vm_vz_vsock_dir(vm_name);
        Self {
            agent_socket,
            vsock_dir,
        }
    }

    /// Resolve the host UDS for a port.
    ///
    /// - `GUEST_AGENT_PORT` → `<socket-dir>/hvf-agent.sock` (the standing agent
    ///   bridge the hvf device binds — see
    ///   [`mvm_core::config::vm_hvf_agent_socket`]).
    /// - Any other port → `<socket-dir>/vsock/vsock-<port>.sock` (the
    ///   pre-opened console data socket, same convention as Vz).
    pub(crate) fn socket_path(&self, port: u32) -> PathBuf {
        if port == mvm_guest::vsock::GUEST_AGENT_PORT {
            self.agent_socket.clone()
        } else {
            self.vsock_dir
                .join(mvm_core::config::vsock_socket_filename(port))
        }
    }
}

impl VsockTransport for DevConsoleTransport {
    fn connect(&self, port: u32) -> Result<UnixStream> {
        let path = self.socket_path(port);
        UnixStream::connect(&path)
            .with_context(|| format!("Failed to connect to hvf vsock at {}", path.display()))
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
/// Probes host-side sockets first, then Firecracker only on native Linux where
/// its runtime directory lookup is local and side-effect-free. macOS must not
/// fall back to Firecracker here: that path shells through the dev Linux
/// environment and can auto-start the builder/dev VM while waiting for a normal
/// HVF/Vz workload socket to appear.
///
/// Note: the probe consumes one stream and immediately drops it;
/// callers get a *fresh* stream from the returned transport's
/// `connect()`. This matches the legacy ladder it replaces, which
/// already did one throwaway probe before the real call.
pub fn for_vm(vm_name: &str) -> Result<Box<dyn VsockTransport>> {
    // (HVF / WorkloadRunner) VMs bind the agent bridge at
    // `<state_dir>/hvf-agent.sock`. Probe it first — it's the macOS-26 default
    // backend, and the socket name is distinct from the libkrun/vz layouts so a
    // hit here is unambiguous. Without this branch the agent-RPC path (every
    // non-interactive `machine run -- <cmd>`, `machine exec`, `invoke`) could
    // never reach an hvf guest and timed out after 30s.
    let hvf = DevConsoleTransport::for_vm(vm_name);
    if hvf.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(hvf));
    }
    let libkrun = LibkrunTransport::for_vm(vm_name);
    if libkrun.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(libkrun));
    }
    let vz = VzTransport::for_vm(vm_name);
    if vz.connect(mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
        return Ok(Box::new(vz));
    }
    if firecracker_transport_supported(mvm_core::platform::current()) {
        let fc = FirecrackerTransport::for_vm(vm_name)
            .with_context(|| format!("no vsock transport found for VM {:?}", vm_name))?;
        return Ok(Box::new(fc));
    }
    anyhow::bail!("no host-side vsock transport found for VM {:?}", vm_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn bind_unix_listener(path: &std::path::Path) -> Option<std::os::unix::net::UnixListener> {
        use std::os::unix::net::UnixListener;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "test skipped: sandbox refused unix socket bind at {}: {err}",
                    path.display()
                );
                None
            }
            Err(err) => panic!("bind unix listener at {}: {err}", path.display()),
        }
    }

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
        // Vz's supervisor listens on `<vsock_dir>/vsock-<port>.sock`; a host
        // client connects directly (no port handshake), same shape as libkrun.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir
            .path()
            .join(mvm_core::config::vsock_socket_filename(5252));
        let Some(_listener) = bind_unix_listener(&sock) else {
            return;
        };
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
        // With a Vz workload's socket present (and no libkrun/firecracker
        // surface), the picker must select the Vz transport rather
        // than falling through to the firecracker error. Regression for the
        // "console can't reach a Vz workload" gap.
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", dir.path());
        let name = "vz-picker-probe";
        let sock =
            mvm_core::config::vm_vz_vsock_port_socket(name, mvm_guest::vsock::GUEST_AGENT_PORT);
        let Some(_listener) = bind_unix_listener(&sock) else {
            unsafe { std::env::remove_var("MVM_DATA_DIR") };
            return;
        };

        let t = for_vm(name).expect("picker should find the vz transport");
        t.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport should connect to the vz socket");
    }

    #[test]
    fn for_vm_selects_hvf_when_hvf_agent_socket_present() {
        // The hvf (HVF / WorkloadRunner) agent bridge binds
        // `<state_dir>/hvf-agent.sock`. With only that socket present the picker
        // must select the hvf transport — the regression for the
        // non-interactive `machine run` reachability gap (the picker previously
        // knew only libkrun/vz/firecracker, so it fell through to the
        // firecracker error and the agent-RPC path timed out after 30s).
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", dir.path());
        let name = "hvf-picker-probe";
        let sock = mvm_core::config::vm_hvf_agent_socket(name);
        let Some(_listener) = bind_unix_listener(&sock) else {
            unsafe { std::env::remove_var("MVM_DATA_DIR") };
            return;
        };

        let t = for_vm(name).expect("picker should find the hvf transport");
        t.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport should connect to the hvf-agent socket");
    }

    #[test]
    fn for_vm_selects_hvf_when_agent_socket_uses_short_socket_dir_fallback() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = TestEnv::new();
        env.set(
            "MVM_DATA_DIR",
            "/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-interactive-oci-dev-console/.mvm-test",
        );
        let name = "hvf-picker-long-path";
        let sock = mvm_core::config::vm_hvf_agent_socket(name);
        let Some(_listener) = bind_unix_listener(&sock) else {
            unsafe { std::env::remove_var("MVM_DATA_DIR") };
            return;
        };

        let t = for_vm(name).expect("picker should find the hvf transport");
        t.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("selected transport should connect to the short hvf-agent socket");
    }

    #[test]
    fn firecracker_transport_supported_only_for_native_linux() {
        assert!(firecracker_transport_supported(
            mvm_core::platform::Platform::LinuxNative
        ));
        assert!(!firecracker_transport_supported(
            mvm_core::platform::Platform::MacOS
        ));
        assert!(!firecracker_transport_supported(
            mvm_core::platform::Platform::LinuxNoKvm
        ));
        assert!(!firecracker_transport_supported(
            mvm_core::platform::Platform::Wsl2
        ));
        assert!(!firecracker_transport_supported(
            mvm_core::platform::Platform::Windows
        ));
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

        let dir = tempfile::tempdir().unwrap();
        let hop = dir.path().join("vsock-21472.sock");
        let Some(listener) = bind_unix_listener(&hop) else {
            return;
        };
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

    // --- DevConsoleTransport ---

    #[test]
    fn dev_console_transport_agent_port_resolves_to_hvf_agent_sock() {
        // GUEST_AGENT_PORT → `<state_dir>/hvf-agent.sock` (what the hvf
        // device's AgentBridge actually binds), not the vsock/ subdir. The old
        // `agent.sock` name never matched the backend, so the host agent-RPC
        // path could not reach an hvf guest.
        let t = DevConsoleTransport::new("/tmp/no-such-hvf-vm");
        let path = t.socket_path(mvm_guest::vsock::GUEST_AGENT_PORT);
        assert_eq!(
            path,
            PathBuf::from("/tmp/no-such-hvf-vm/hvf-agent.sock"),
            "agent port must resolve to hvf-agent.sock at state-dir root"
        );
    }

    #[test]
    fn dev_console_transport_console_port_resolves_to_vsock_subdir() {
        // Console data ports → `<state_dir>/vsock/vsock-<port>.sock`.
        let t = DevConsoleTransport::new("/tmp/no-such-hvf-vm");
        let port = *mvm_guest::vsock::dev_console_data_ports()
            .collect::<Vec<_>>()
            .first()
            .expect("at least one console data port");
        let path = t.socket_path(port);
        let expected = PathBuf::from(format!("/tmp/no-such-hvf-vm/vsock/vsock-{port}.sock"));
        assert_eq!(
            path, expected,
            "console data port must resolve to vsock/ subdir"
        );
    }

    #[test]
    fn dev_console_transport_for_vm_error_mentions_backend() {
        // Error text must identify the backend so console failures are diagnosable.
        let t = DevConsoleTransport::for_vm("no-such-hvf-vm");
        let err = t
            .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect_err("should fail — no real socket")
            .to_string();
        assert!(
            err.contains("hvf vsock"),
            "error must name the backend: {err}"
        );
    }

    #[test]
    fn dev_console_transport_connects_via_hvf_agent_sock() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("hvf-agent.sock");
        let Some(_listener) = bind_unix_listener(&agent) else {
            return;
        };
        let t = DevConsoleTransport::new(dir.path());
        t.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            .expect("should connect to hvf-agent.sock");
    }

    #[test]
    fn dev_console_transport_connects_via_console_data_sock() {
        let dir = tempfile::tempdir().unwrap();
        let vsock_dir = dir.path().join("vsock");
        std::fs::create_dir_all(&vsock_dir).unwrap();
        let port = *mvm_guest::vsock::dev_console_data_ports()
            .collect::<Vec<_>>()
            .first()
            .expect("at least one console data port");
        let sock = vsock_dir.join(mvm_core::config::vsock_socket_filename(port));
        let Some(_listener) = bind_unix_listener(&sock) else {
            return;
        };
        let t = DevConsoleTransport::new(dir.path());
        t.connect(port)
            .expect("should connect to console data sock");
    }
}
