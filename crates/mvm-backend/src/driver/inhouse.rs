//! `InHouseDriver` — the `VmmDriver` for the first-party VMM (HVF on macOS, KVM
//! on Linux via the shared `vmm` device model). Identity and capabilities
//! delegate to the proven `HvfBackend`. `boot` maps a policy-free `VmmSpec` to a
//! relay supervisor config, spawns `mvm-hvf-supervisor`, and returns a live
//! handle. The claim-10 egress gate and secret substitution live in the
//! host-side endpoint the caller binds to the spec's `EGRESS_PORT` socket; the
//! driver only wires that socket through as the supervisor's egress relay — it
//! carries no policy and never sees a `NetworkPolicy`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use mvm_build::hvf_supervisor::{HvfDisk, HvfSupervisorConfig};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{
    SnapshotCapability, VmBackend, VmCapabilities, VmExitStatus, VmId, VmStatus,
};
use mvm_guest::vsock::{EGRESS_PORT, GUEST_AGENT_PORT};

use crate::driver::spec::KernelImage;
use crate::driver::{DuplexStream, RunningVm, VmmDriver, VmmSpec};
use crate::hvf_backend::{
    self, HvfBackend, PID_FILE_NAME, PID_FILE_TIMEOUT, resolve_supervisor_path,
};

/// The first-party VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge, not
/// here.
pub struct InHouseDriver {
    backend: HvfBackend,
}

impl InHouseDriver {
    pub fn new() -> Self {
        Self {
            backend: HvfBackend,
        }
    }
}

impl Default for InHouseDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The per-VM host paths the supervisor writes and reads, resolved from the VM's
/// state dir. Grouped so the pure config mapping takes one struct rather than a
/// fistful of positional paths.
struct SupervisorPaths {
    state_dir: PathBuf,
    pid_file: PathBuf,
    console_log: PathBuf,
    workload_exit: PathBuf,
    timeout_secs: u64,
}

impl SupervisorPaths {
    /// Resolve the standard per-VM paths under the VM's state dir. `timeout_secs`
    /// is a backstop cap (0 = none) against a guest that never reports its exit.
    fn resolve(state_dir: PathBuf, timeout_secs: u64) -> Self {
        let pid_file = state_dir.join(PID_FILE_NAME);
        let console_log = state_dir.join("console.log");
        let workload_exit = state_dir.join("workload.exit");
        Self {
            state_dir,
            pid_file,
            console_log,
            workload_exit,
            timeout_secs,
        }
    }
}

/// Find the host socket for a standing vsock port by its guest-port number.
fn vsock_socket(spec: &VmmSpec, guest_port: u32) -> Option<PathBuf> {
    spec.vsock
        .iter()
        .find(|p| p.guest_port == guest_port)
        .map(|p| p.host_uds.clone())
}

/// Map a policy-free `VmmSpec` to a relay `HvfSupervisorConfig`: the supervisor
/// wires the guest's `EGRESS_PORT` straight to the host-side endpoint bound at
/// `egress_relay_socket`, which owns the claim-10 gate and substitution. The
/// spec MUST carry that egress socket — an in-house workload has no other path
/// off the box, so a spec without it fails closed rather than booting ungated.
fn relay_supervisor_config(spec: &VmmSpec, paths: &SupervisorPaths) -> Result<HvfSupervisorConfig> {
    let kernel = match &spec.kernel {
        KernelImage::Path(p) => p.clone(),
        KernelImage::Bundled => {
            bail!("the in-house VMM requires an explicit kernel Image; VmmSpec.kernel is Bundled")
        }
    };

    // Every block in slot order becomes a virtio-blk device (`/dev/vda`…). Each
    // block carries its own read-only + ephemeral policy: a read-only block is
    // file-served with hypervisor-enforced RO; an ephemeral block is RAM-backed
    // (writes dropped on exit); a writable non-ephemeral block persists to the
    // host file (the builder's nix-store / output disks).
    let mut ordered: Vec<&crate::driver::BlockDev> = spec.blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    let disks = ordered
        .iter()
        .map(|b| HvfDisk {
            path: b.source.clone(),
            read_only: b.read_only,
            ephemeral: b.ephemeral,
        })
        .collect();

    // A workload MUST route egress through the gated endpoint — a missing relay
    // fails closed. A trusted builder carries no untrusted workload and boots with
    // no egress gate, so it has no relay socket.
    let egress_relay_socket = if spec.trusted_builder {
        None
    } else {
        Some(vsock_socket(spec, EGRESS_PORT).ok_or_else(|| {
            anyhow!("in-house workload spec is missing the EGRESS_PORT vsock relay socket")
        })?)
    };

    // An empty spec cmdline means "use the supervisor's workload default"
    // (`init=/init`); a non-empty one (e.g. the builder rootfs's
    // `init=/sbin/mvm-host-vm-init`) is threaded through verbatim.
    let cmdline = {
        let c = spec.cmdline.trim();
        (!c.is_empty()).then(|| c.to_string())
    };

    Ok(HvfSupervisorConfig {
        kernel,
        cmdline,
        memory_mib: spec.memory_mib,
        initramfs: spec.initramfs.clone(),
        disks,
        vsock: true,
        console_log: paths.console_log.clone(),
        pid_file: paths.pid_file.clone(),
        workload_exit: paths.workload_exit.clone(),
        timeout_secs: paths.timeout_secs,
        agent_socket: vsock_socket(spec, GUEST_AGENT_PORT),
        substitution_socket: None,
        egress_relay_socket,
    })
}

impl VmmDriver for InHouseDriver {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn is_available(&self) -> Result<bool> {
        self.backend.is_available()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.backend.capabilities()
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        self.backend.snapshot_capability()
    }

    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        // Create/truncate the console capture up front.
        let _ = crate::libkrun::open_console_capture(&state_dir.join("console.log"));

        // MVM_HVF_TIMEOUT is only a backstop cap (0 = none) — matches HvfBackend.
        let timeout_secs = std::env::var("MVM_HVF_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let paths = SupervisorPaths::resolve(state_dir, timeout_secs);

        // Clear any prior run's exit code so `wait` reads only this launch's.
        let _ = std::fs::remove_file(&paths.workload_exit);

        let cfg = relay_supervisor_config(spec, &paths)?;
        let json = serde_json::to_string(&cfg)
            .map_err(|e| anyhow!("serialize HvfSupervisorConfig: {e}"))?;

        let supervisor = resolve_supervisor_path()?;
        let mut child = Command::new(&supervisor)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file (boot confirmed). If the supervisor exits first,
        // surface that — its inherited stderr carries the actionable detail.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if paths.pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "hvf supervisor exited before writing its PID file (status: {status}); see {}",
                    paths.console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                    paths.console_log.display()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Detach: dropping the `Child` does not kill it, so the supervisor
        // outlives this call (reaped via its PID file by `kill`).
        drop(child);

        // The agent RPC socket the supervisor binds for this VM (host→guest agent
        // bridge on GUEST_AGENT_PORT). Prefer the spec's own port; fall back to the
        // standing convention so a later `attach` re-derives the same path.
        let agent_socket = vsock_socket(spec, GUEST_AGENT_PORT)
            .unwrap_or_else(|| in_house_agent_socket(&paths.state_dir));
        Ok(Box::new(InHouseRunningVm {
            id: VmId(spec.name.clone()),
            state_dir: paths.state_dir,
            pid_file: paths.pid_file,
            agent_socket,
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the supervisor's pid file + the
        // persisted workload-exit code under the VM's state dir), so reattaching is
        // just re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(InHouseRunningVm {
            pid_file: state_dir.join(PID_FILE_NAME),
            agent_socket: in_house_agent_socket(&state_dir),
            state_dir,
            id: id.clone(),
        }))
    }
}

/// The per-VM agent RPC socket path (host→guest agent bridge). Matches the
/// standing socket a `WorkloadRunner` binds so `attach` re-derives it.
fn in_house_agent_socket(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("agent.sock")
}

/// A live in-house VM: the detached `mvm-hvf-supervisor` tracked by its PID file,
/// with the workload's exit code persisted under its state dir.
struct InHouseRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
    /// Host→guest agent RPC socket the supervisor bound for this VM.
    agent_socket: PathBuf,
}

impl RunningVm for InHouseRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(crate::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        if let Some(pid) = hvf_backend::read_pid(&self.pid_file) {
            hvf_backend::terminate_pid(pid);
        }
        let _ = std::fs::remove_file(&self.pid_file);
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        bail!("in-house pause/resume is not yet implemented")
    }

    fn resume(&self) -> Result<()> {
        bail!("in-house pause/resume is not yet implemented")
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(match hvf_backend::read_pid(&self.pid_file) {
            Some(pid) if hvf_backend::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        // The in-house VMM bridges exactly one host→guest channel: the agent RPC
        // port, exposed as the per-VM agent socket the supervisor binds. A connect
        // to that UDS is a stream to the guest agent (the bridge opens the vsock
        // leg). Other ports are not host-dialable on this backend.
        if guest_port != GUEST_AGENT_PORT {
            bail!(
                "in-house driver vsock_connect supports only the agent port ({GUEST_AGENT_PORT}); \
                 got {guest_port}"
            );
        }
        let stream =
            std::os::unix::net::UnixStream::connect(&self.agent_socket).with_context(|| {
                format!(
                    "connect to in-house agent socket {}",
                    self.agent_socket.display()
                )
            })?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BlockDev, ConsoleCapture, VsockDirection, VsockPort};

    fn egress_port(uds: &str) -> VsockPort {
        VsockPort {
            guest_port: EGRESS_PORT,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn agent_port(uds: &str) -> VsockPort {
        VsockPort {
            guest_port: GUEST_AGENT_PORT,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    fn spec_with(kernel: KernelImage, vsock: Vec<VsockPort>, blocks: Vec<BlockDev>) -> VmmSpec {
        VmmSpec {
            name: "w".into(),
            kernel,
            initramfs: Some("/img/initrd.cpio".into()),
            cmdline: String::new(),
            vcpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks,
            vsock,
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
        }
    }

    fn sample_paths() -> SupervisorPaths {
        SupervisorPaths::resolve(PathBuf::from("/state/w"), 0)
    }

    #[test]
    fn identity_and_capabilities_delegate_to_the_hvf_backend() {
        let d = InHouseDriver::new();
        assert_eq!(d.name(), "hvf");
        assert!(d.capabilities().vsock);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // Reattaching needs no boot state — it re-derives the state dir. A VM that
        // never ran (or has exited) reports Stopped rather than erroring.
        let vm = InHouseDriver::new()
            .attach(&VmId("hvf-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "hvf-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn relay_config_wires_egress_relay_and_agent_leaves_substitution_none() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();

        assert_eq!(cfg.kernel, PathBuf::from("/img/Image"));
        assert_eq!(cfg.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
        assert_eq!(cfg.agent_socket, Some(PathBuf::from("/run/agent.sock")));
        assert_eq!(cfg.substitution_socket, None);
        assert!(cfg.vsock);
        // No blocks → no disks.
        assert!(cfg.disks.is_empty());
        // Empty spec cmdline ⇒ None (supervisor uses its workload default).
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn relay_config_threads_a_non_empty_cmdline_and_drops_an_empty_one() {
        // The builder rootfs boots a different PID 1 than the mkGuest workload
        // default, so its cmdline must reach the supervisor verbatim.
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        spec.cmdline = "  console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init  ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        // Trimmed, threaded verbatim.
        assert_eq!(
            cfg.cmdline.as_deref(),
            Some("console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init")
        );

        // A whitespace-only cmdline collapses to None (default applies).
        spec.cmdline = "   ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn relay_config_maps_blocks_to_disks_in_slot_order_carrying_ro_and_ephemeral() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![
                // Out of slot order, mixed flags — proves sorting + per-disk policy
                // pass through verbatim (a builder's persistent nix-store is
                // writable AND non-ephemeral).
                BlockDev {
                    source: "/img/nix-store.img".into(),
                    read_only: false,
                    ephemeral: false,
                    slot: 1,
                },
                BlockDev {
                    source: "/img/rootfs.ext4".into(),
                    read_only: true,
                    ephemeral: false,
                    slot: 0,
                },
            ],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.disks.len(), 2);
        // vda = slot 0: read-only rootfs, file-served.
        assert_eq!(cfg.disks[0].path, PathBuf::from("/img/rootfs.ext4"));
        assert!(cfg.disks[0].read_only);
        assert!(!cfg.disks[0].ephemeral);
        // vdb = slot 1: writable + persistent (not ephemeral) — writes hit the file.
        assert_eq!(cfg.disks[1].path, PathBuf::from("/img/nix-store.img"));
        assert!(!cfg.disks[1].read_only);
        assert!(!cfg.disks[1].ephemeral);
    }

    #[test]
    fn relay_config_trusted_builder_needs_no_egress_relay() {
        // A trusted builder boots with no egress gate — no EGRESS_PORT required,
        // and no relay socket is wired. (A workload without one still fails closed;
        // see relay_config_missing_egress_port_fails_closed.)
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![agent_port("/run/agent.sock")],
            vec![],
        );
        spec.trusted_builder = true;
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.egress_relay_socket, None);
    }

    #[test]
    fn relay_config_missing_egress_port_fails_closed() {
        // No EGRESS_PORT: the in-house VMM has no other path off the box, so this
        // must not boot an ungated guest.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![agent_port("/run/agent.sock")],
            vec![],
        );
        let err = relay_supervisor_config(&spec, &sample_paths())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("EGRESS_PORT"), "unexpected error: {err}");
    }

    #[test]
    fn relay_config_rejects_a_bundled_kernel() {
        // HVF has no bundled kernel; the spec must name an explicit Image.
        let spec = spec_with(
            KernelImage::Bundled,
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        assert!(relay_supervisor_config(&spec, &sample_paths()).is_err());
    }

    #[test]
    fn vsock_connect_reaches_the_agent_socket_and_rejects_other_ports() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        // Stand-in for the supervisor's agent bridge: echo one byte back.
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut b = [0u8; 1];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });

        let vm = InHouseRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(PID_FILE_NAME),
            agent_socket: sock,
        };

        // The agent port connects + round-trips through the socket.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // Any other guest port is not host-dialable on this backend.
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
    }
}
