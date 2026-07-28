//! `MockDriver` — a hypervisor-free `VmmDriver` test double. It records the
//! `VmmSpec` it is handed and returns a `MockRunningVm` with a scripted exit
//! status and an in-process loopback vsock, so the role runners can be unit
//! tested with no real VM. Test infrastructure; never a production backend.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    SnapshotCapability, StandbyError, StandbyHandle, StandbySpec, StandbyState, VmCapabilities,
    VmExitStatus, VmId, VmStatus,
};

use mvm_core::crypto::vmgenid::GenerationToken;

use crate::driver::spec::{ConsoleCapture, KernelImage, VmmSpec};
use crate::driver::traits::{ChildForkRequest, DuplexStream, RunningVm, VmmDriver};
use crate::standby_pool::now_unix_secs;

type GuestEnds = Arc<Mutex<HashMap<(String, u32), UnixStream>>>;

/// A recorded `fork_standby_child` call: the child's fresh name plus the
/// generation token the fork delivered, so a test can prove a claim delivered a
/// fresh, content-bound token to the fork (and thus before the child's workload
/// ran).
#[derive(Clone)]
pub struct MockChildFork {
    pub child_vm_name: String,
    pub genid: GenerationToken,
}

/// Hypervisor-free `VmmDriver` test double.
#[derive(Clone)]
pub struct MockDriver {
    exit: VmExitStatus,
    status: VmStatus,
    booted: Arc<Mutex<Vec<VmmSpec>>>,
    forked: Arc<Mutex<Vec<MockChildFork>>>,
    guest_ends: GuestEnds,
}

impl Default for MockDriver {
    fn default() -> Self {
        Self::with_exit(VmExitStatus::SUCCESS)
    }
}

impl MockDriver {
    /// A mock whose VMs return `exit` from `wait()` and report `Running`.
    pub fn with_exit(exit: VmExitStatus) -> Self {
        Self {
            exit,
            status: VmStatus::Running,
            booted: Arc::new(Mutex::new(Vec::new())),
            forked: Arc::new(Mutex::new(Vec::new())),
            guest_ends: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the `status()` the mock's VMs report — e.g. `Stopped` to model a
    /// run-to-completion (builder) VM that has already powered off.
    pub fn reporting_status(mut self, status: VmStatus) -> Self {
        self.status = status;
        self
    }

    /// The specs this driver has booted, in order.
    pub fn booted_specs(&self) -> Vec<VmmSpec> {
        self.booted.lock().unwrap().clone()
    }

    /// The standby-child forks this driver has performed, in order — each with
    /// the fresh generation token the fork delivered.
    pub fn forked_children(&self) -> Vec<MockChildFork> {
        self.forked.lock().unwrap().clone()
    }

    /// Take the guest end of the loopback a prior `vsock_connect` opened, to
    /// script the guest side in a test.
    pub fn take_guest_end(&self, vm: &VmId, guest_port: u32) -> Option<UnixStream> {
        self.guest_ends
            .lock()
            .unwrap()
            .remove(&(vm.0.clone(), guest_port))
    }
}

impl VmmDriver for MockDriver {
    fn name(&self) -> &str {
        "mock"
    }
    fn kind(&self) -> BackendKind {
        BackendKind::Mock
    }
    fn is_available(&self) -> Result<bool> {
        Ok(true)
    }
    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            vsock: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            ..Default::default()
        }
    }
    fn security_profile(&self) -> BackendSecurityProfile {
        // Mirrors `MockBackend::security_profile` — the mock runs no guest and
        // holds none of the seven CI-enforced claims.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 3 (test-only)",
            notes: &[
                "MockDriver is in-process test infrastructure.",
                "No guest, no rootfs, no isolation; never use in production.",
            ],
        }
    }
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        self.booted.lock().unwrap().push(spec.clone());
        Ok(Box::new(MockRunningVm {
            id: VmId(spec.name.clone()),
            exit: self.exit,
            status: self.status.clone(),
            guest_ends: Arc::clone(&self.guest_ends),
        }))
    }

    fn spawn_standby_parent(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        // A clean parent boot: no cmdline, no volumes, no vsock channels — the
        // recipe itself has no field that could carry a plan, a secret, or an
        // egress/broker endpoint. Routed through `boot()` (not pushed directly)
        // so a test can observe it the same way it observes a real workload
        // boot, via `booted_specs()`.
        let parent = VmmSpec {
            name: spec.id.clone(),
            kernel: KernelImage::Bundled,
            initramfs: None,
            cmdline: String::new(),
            vcpus: u32::from(spec.vcpus),
            memory_mib: spec.mem_mib,
            mem_initial_mib: None,
            blocks: Vec::new(),
            vsock: Vec::new(),
            console: ConsoleCapture {
                log_path: std::path::PathBuf::from(&spec.vm_state_dir).join("console.log"),
            },
            trusted_builder: false,
        };
        self.boot(&parent)
            .map_err(|e| StandbyError::SpawnFailed(e.to_string()))?;
        // No live process backs a mocked capture — pid=0 mirrors the saved-state
        // convention (`StandbyHandle::is_saved_state`) already used for a
        // captured-not-running standby.
        Ok(StandbyHandle {
            id: spec.id.clone(),
            template_id: spec.template_id.clone(),
            control_socket: spec.control_socket.clone(),
            pid: 0,
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
        })
    }

    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        // A hypervisor-free fork: record the child's fresh name + the delivered
        // generation token so a test can prove the claim scrubbed identity and
        // delivered a fresh, content-bound token to the fork (i.e. at boot,
        // before the child's workload ran). The runner has already materialized
        // the CoW clone into `req.child_dir`; the mock needs nothing on disk.
        if !req.child_dir.exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': child dir {} was never materialized",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }
        self.forked.lock().unwrap().push(MockChildFork {
            child_vm_name: req.child_vm_name.to_string(),
            genid: req.genid.clone(),
        });
        Ok(())
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        Ok(Box::new(MockRunningVm {
            id: id.clone(),
            exit: self.exit,
            status: self.status.clone(),
            guest_ends: Arc::clone(&self.guest_ends),
        }))
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        bail!("mock driver does not provide guest channel info")
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        // A deterministic stand-in for a non-HVF console base — `hvc0` rather
        // than HVF's `ttyAMA0` — so runner-level tests can prove the base
        // comes from the driver rather than a hardcoded HVF default.
        let mut args = "console=hvc0 panic=-1 nokaslr loglevel=8".to_string();
        if virtiofs_root {
            args.push_str(" rootfstype=virtiofs root=mvmroot rw init=/init");
        } else if has_disk {
            args.push_str(" root=/dev/vda rw init=/init");
        }
        args
    }
}

/// A `MockDriver`'s live VM: a scripted exit + a per-port loopback vsock whose
/// guest end the owning `MockDriver` hands back via `take_guest_end`.
pub struct MockRunningVm {
    id: VmId,
    exit: VmExitStatus,
    status: VmStatus,
    guest_ends: GuestEnds,
}

impl RunningVm for MockRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }
    fn wait(&self) -> Result<VmExitStatus> {
        Ok(self.exit)
    }
    fn kill(&self) -> Result<()> {
        Ok(())
    }
    fn pause(&self) -> Result<()> {
        Ok(())
    }
    fn resume(&self) -> Result<()> {
        Ok(())
    }
    fn status(&self) -> Result<VmStatus> {
        Ok(self.status.clone())
    }
    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        let (host, guest) = UnixStream::pair().map_err(|e| anyhow!("socketpair: {e}"))?;
        self.guest_ends
            .lock()
            .unwrap()
            .insert((self.id.0.clone(), guest_port), guest);
        Ok(Box::new(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec(name: &str) -> VmmSpec {
        VmmSpec {
            name: name.to_string(),
            kernel: KernelImage::Bundled,
            initramfs: None,
            cmdline: String::new(),
            vcpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks: vec![],
            vsock: vec![],
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
        }
    }

    #[test]
    fn mock_driver_records_booted_spec_and_scripts_exit() {
        let driver = MockDriver::with_exit(VmExitStatus {
            code: Some(2),
            success: false,
        });
        let spec = sample_spec("probe");
        let vm = driver.boot(&spec).unwrap();
        assert_eq!(driver.booted_specs(), vec![spec]);
        assert_eq!(
            vm.wait().unwrap(),
            VmExitStatus {
                code: Some(2),
                success: false
            }
        );
        assert_eq!(vm.id(), &VmId("probe".into()));
        assert_eq!(driver.name(), "mock");
    }

    #[test]
    fn mock_driver_reports_mock_identity_and_test_only_security_profile() {
        let driver = MockDriver::default();
        assert_eq!(driver.kind(), BackendKind::Mock);
        let profile = driver.security_profile();
        assert_eq!(profile.tier, "Tier 3 (test-only)");
        assert!(
            profile
                .claims
                .iter()
                .all(|c| *c == ClaimStatus::DoesNotHold)
        );
    }

    #[test]
    fn mock_driver_workload_base_bootargs_uses_hvc0_console_by_root_shape() {
        let driver = MockDriver::default();
        let disk_base = driver.workload_base_bootargs(false, true);
        assert!(disk_base.contains("console=hvc0"));
        assert!(disk_base.contains("root=/dev/vda"));
        assert!(!disk_base.contains("ttyAMA0"));

        let virtiofs_base = driver.workload_base_bootargs(true, false);
        assert!(virtiofs_base.contains("rootfstype=virtiofs"));

        let bare_base = driver.workload_base_bootargs(false, false);
        assert!(!bare_base.contains("root="));
    }

    #[test]
    fn mock_driver_guest_channel_info_fails_closed() {
        let driver = MockDriver::default();
        assert!(
            driver
                .guest_channel_info(&VmId("no-such-vm".into()))
                .is_err()
        );
    }

    #[test]
    fn attach_returns_a_handle_for_the_id_without_booting() {
        let driver = MockDriver::with_exit(VmExitStatus {
            code: Some(7),
            success: false,
        });
        let vm = driver.attach(&VmId("already-running".into())).unwrap();
        assert_eq!(vm.id(), &VmId("already-running".into()));
        assert_eq!(vm.wait().unwrap().code, Some(7));
        // attach records no boot — only boot() pushes a spec.
        assert!(driver.booted_specs().is_empty());
    }

    #[test]
    fn mock_vsock_connect_loops_host_and_guest_both_ways() {
        use std::io::{Read, Write};

        let driver = MockDriver::default();
        let vm = driver.boot(&sample_spec("v")).unwrap();

        let mut host = vm.vsock_connect(5253).unwrap();
        let mut guest = driver
            .take_guest_end(vm.id(), 5253)
            .expect("guest end registered by vsock_connect");

        host.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        guest.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");

        guest.write_all(b"pong").unwrap();
        let mut back = [0u8; 4];
        host.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");
    }
}
