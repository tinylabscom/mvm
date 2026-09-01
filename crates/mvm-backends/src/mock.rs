//! `MockDriver` — a hypervisor-free `VmmDriver` test double. It records the
//! `VmmSpec` it is handed and returns a `MockRunningVm` with a scripted exit
//! status and an in-process loopback vsock, so the role runners can be unit
//! tested with no real VM. Test infrastructure; never a production backend.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    SnapshotCapability, StandbyError, StandbyHandle, StandbyState, VmCapabilities, VmExitStatus,
    VmId, VmStatus,
};

use mvm_core::crypto::vmgenid::{GENID_BYTES, GenerationToken};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

use mvm_vmm::driver::spec::{VmmSpec, VsockPort};
use mvm_vmm::driver::{ChildForkRequest, DuplexStream, RunningVm, StandbyParentSpawn, VmmDriver};
use mvm_vmm::post_restore::PostRestoreOutcome;

type GuestEnds = Arc<Mutex<HashMap<(String, u32), UnixStream>>>;

/// What a `MockDriver` reports from `deliver_child_identity`. `None` scripts a
/// guest that never answered inside the RPC deadline (the shape a real
/// transport error takes); `Some` scripts the flags a live agent would report.
type ScriptedChildIdentity = Option<PostRestoreOutcome>;

/// One post-restore child identity delivery recorded by the mock driver.
#[derive(Clone, Debug)]
pub struct DeliveredChildIdentity {
    /// Final runner-minted identity of the restored child.
    pub child_vm_name: String,
    /// Fresh VMGenID token delivered to the child.
    pub token: [u8; GENID_BYTES],
    /// Optional signed agent authority delivered in the same handshake.
    pub grant_envelope: Option<VerbGrantEnvelope>,
}

/// A clean post-restore answer: the guest acknowledged, rotated its generation
/// identity off the delivered token, and took the host's wall clock. The
/// `MockDriver` default, so an ordinary claim test needs no extra setup.
fn rotated_child_identity() -> PostRestoreOutcome {
    PostRestoreOutcome {
        acknowledged: true,
        detail: None,
        reseeded: true,
        clock_resynced: true,
    }
}

/// A recorded `fork_standby_child` call: the child's fresh name, the generation
/// token the fork delivered, and the host channel set the fork was asked to wire
/// — so a test can prove a claim delivered a fresh, content-bound token to the
/// fork (and thus before the child's workload ran) and handed it the same
/// channels a cold boot wires.
#[derive(Clone)]
pub struct MockChildFork {
    pub child_vm_name: String,
    pub genid: GenerationToken,
    pub channels: Vec<VsockPort>,
}

/// Hypervisor-free `VmmDriver` test double.
#[derive(Clone)]
pub struct MockDriver {
    exit: VmExitStatus,
    status: VmStatus,
    booted: Arc<Mutex<Vec<VmmSpec>>>,
    forked: Arc<Mutex<Vec<MockChildFork>>>,
    guest_ends: GuestEnds,
    /// The rootfs path `vm_full_control`'s returned control reports from
    /// `rootfs_path()` — a test seeds this to a file it already wrote so the
    /// capture orchestration has something real to clone.
    vm_full_rootfs: PathBuf,
    /// Shared with every `MockVmFullControl` this driver hands out, so a test
    /// can read back the pause/save_memory/resume call order via
    /// `vm_full_calls()` regardless of which `vm_full_control()` call produced
    /// the control that was driven.
    vm_full_calls: Arc<Mutex<Vec<&'static str>>>,
    /// The post-restore answer `deliver_child_identity` reports for a forked
    /// child, so a test can drive the claim's fresh-identity gate — including
    /// the refusal arms — with no live guest.
    child_identity: ScriptedChildIdentity,
    /// Every identity and grant this driver was asked to deliver, so a test can
    /// prove the claim handed the guest the same values it minted.
    delivered_identities: Arc<Mutex<Vec<DeliveredChildIdentity>>>,
    /// Names of the VMs killed through any handle this driver produced, so a
    /// test can prove a refused claim actually tore its child down instead of
    /// leaving it resumed.
    killed: Arc<Mutex<Vec<String>>>,
    /// Bytes a killed VM appends to its own console capture before it goes,
    /// modelling the guest's last words: a shutdown trace, a panic, whatever
    /// the kernel prints on the way down. Empty by default, because most
    /// tests have no use for it; a test asserting that teardown does not
    /// throw those bytes away sets it.
    dying_console_output: Vec<u8>,
    /// Whether `attach` refuses. Models the ordinary teardown race — a VM
    /// whose supervisor is already gone by the time a `stop` reaches it — so
    /// a test can prove the teardown steps that must run regardless still do.
    refuse_attach: bool,
    /// Whether claims should use the resident-handoff path instead of the
    /// saved-state materialization path.
    resident_handoff: bool,
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
            vm_full_rootfs: PathBuf::from("/mock/rootfs.ext4"),
            vm_full_calls: Arc::new(Mutex::new(Vec::new())),
            child_identity: Some(rotated_child_identity()),
            delivered_identities: Arc::new(Mutex::new(Vec::new())),
            killed: Arc::new(Mutex::new(Vec::new())),
            dying_console_output: Vec::new(),
            refuse_attach: false,
            resident_handoff: false,
        }
    }

    /// Make `attach` refuse, as it does for a VM that is no longer there.
    #[must_use]
    pub fn refusing_attach(mut self) -> Self {
        self.refuse_attach = true;
        self
    }

    /// Make claims use the resident-handoff path without requiring a
    /// hypervisor, so the runner's no-materialization contract can be tested.
    pub fn with_resident_handoff(mut self) -> Self {
        self.resident_handoff = true;
        self
    }

    /// Make this driver's VMs append `bytes` to their console capture when
    /// they are killed, so a test can tell a teardown that keeps a dying
    /// guest's output from one that drops it.
    #[must_use]
    pub fn printing_on_kill(mut self, bytes: &[u8]) -> Self {
        self.dying_console_output = bytes.to_vec();
        self
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

    /// Seed the rootfs path a subsequent `vm_full_control()` call's control
    /// reports via `rootfs_path()`.
    pub fn with_vm_full_rootfs(mut self, rootfs: impl Into<PathBuf>) -> Self {
        self.vm_full_rootfs = rootfs.into();
        self
    }

    /// The `pause`/`save_memory`/`resume` calls recorded so far against any
    /// control this driver's `vm_full_control()` has handed out, in order.
    pub fn vm_full_calls(&self) -> Vec<&'static str> {
        self.vm_full_calls.lock().unwrap().clone()
    }

    /// Script the flags a forked child's guest agent reports back — e.g. an
    /// acknowledgement that did not rotate the generation identity.
    pub fn with_child_identity(mut self, outcome: PostRestoreOutcome) -> Self {
        self.child_identity = Some(outcome);
        self
    }

    /// Script a forked child whose guest agent never answers, the shape a real
    /// transport failure or a blown RPC deadline takes.
    pub fn with_unreachable_child_agent(mut self) -> Self {
        self.child_identity = None;
        self
    }

    /// Every identity and grant handed to `deliver_child_identity`, in order.
    pub fn delivered_child_identities(&self) -> Vec<DeliveredChildIdentity> {
        self.delivered_identities.lock().unwrap().clone()
    }

    /// Names of the VMs killed through any handle this driver produced, in
    /// order.
    pub fn killed_vms(&self) -> Vec<String> {
        self.killed.lock().unwrap().clone()
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

    fn supports_resident_handoff(&self) -> bool {
        self.resident_handoff
    }
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        self.booted.lock().unwrap().push(spec.clone());
        Ok(Box::new(MockRunningVm {
            id: VmId(spec.name.clone()),
            exit: self.exit,
            status: self.status.clone(),
            guest_ends: Arc::clone(&self.guest_ends),
            killed: Arc::clone(&self.killed),
            dying_console_output: self.dying_console_output.clone(),
        }))
    }

    fn spawn_standby_parent(
        &self,
        req: &StandbyParentSpawn<'_>,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let spec = req.spec;
        // The role layer assembled the parent's boot inputs from the launch it
        // will serve; the mock boots them verbatim, exactly as a real driver
        // does. Routed through `boot()` (not pushed directly) so a test can
        // observe the parent's shape the same way it observes a real workload
        // boot, via `booted_specs()` — which is what lets a test compare them.
        self.boot(req.boot)
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
            spawned_unix_secs: mvm_core::time::now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
            root_strategy: spec.root_strategy,
            vsock_egress: spec.vsock_egress,
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
        })
    }

    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        // A hypervisor-free fork: record the child's fresh name, the delivered
        // generation token, and the host channel set the fork was asked to wire,
        // so a test can prove the claim scrubbed identity, delivered a fresh
        // content-bound token to the fork (i.e. at boot, before the child's
        // workload ran), and handed down the channels a cold boot wires. The
        // runner has already materialized the CoW clone into `req.child_dir`;
        // the mock needs nothing on disk.
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
            channels: req.channels.to_vec(),
        });
        Ok(())
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        if self.refuse_attach {
            bail!("no such vm {}", id.0);
        }
        Ok(Box::new(MockRunningVm {
            id: id.clone(),
            exit: self.exit,
            status: self.status.clone(),
            guest_ends: Arc::clone(&self.guest_ends),
            killed: Arc::clone(&self.killed),
            dying_console_output: self.dying_console_output.clone(),
        }))
    }

    fn deliver_child_identity(
        &self,
        child_vm_name: &str,
        token: [u8; GENID_BYTES],
        grant_envelope: Option<VerbGrantEnvelope>,
    ) -> Result<PostRestoreOutcome> {
        self.delivered_identities
            .lock()
            .unwrap()
            .push(DeliveredChildIdentity {
                child_vm_name: child_vm_name.to_string(),
                token,
                grant_envelope,
            });
        self.child_identity.clone().ok_or_else(|| {
            anyhow!("mock guest agent for '{child_vm_name}' did not answer the post-restore signal")
        })
    }

    fn vm_full_control(
        &self,
        vm_name: &str,
    ) -> Option<Box<dyn mvm_vmm::checkpoint::VmFullControl>> {
        let _ = vm_name;
        Some(Box::new(MockVmFullControl {
            rootfs: self.vm_full_rootfs.clone(),
            calls: Arc::clone(&self.vm_full_calls),
        }))
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        bail!("mock driver does not provide guest channel info")
    }

    fn workload_base_bootargs(&self, has_disk: bool) -> String {
        // A deterministic stand-in for a non-HVF console base — `hvc0` rather
        // than HVF's `ttyAMA0` — so runner-level tests can prove the base
        // comes from the driver rather than a hardcoded HVF default.
        let mut args = "console=hvc0 panic=-1 nokaslr loglevel=8".to_string();
        if has_disk {
            args.push_str(" root=/dev/vda ro init=/init");
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
    killed: Arc<Mutex<Vec<String>>>,
    dying_console_output: Vec<u8>,
}

impl MockRunningVm {
    /// Append the scripted last words to this VM's console capture, at the
    /// same path a real backend's write-only capture lives.
    fn print_dying_words(&self) {
        if self.dying_console_output.is_empty() {
            return;
        }
        let path = mvm_core::config::vm_console_log(&self.id.0);
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, &self.dying_console_output));
        if let Err(error) = appended {
            tracing::warn!(
                path = %path.display(),
                %error,
                "mock guest could not write its dying words"
            );
        }
    }
}

impl RunningVm for MockRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }
    fn wait(&self) -> Result<VmExitStatus> {
        Ok(self.exit)
    }
    fn kill(&self) -> Result<()> {
        self.killed.lock().unwrap().push(self.id.0.clone());
        self.print_dying_words();
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

/// Hypervisor-free [`mvm_vmm::checkpoint::VmFullControl`] test double: no real
/// pause/resume happens, `save_memory` writes a small deterministic file
/// instead of a real machine-memory image, and `rootfs_path`/`device_anchors`
/// report the path a test seeded on the owning `MockDriver`. Every call is
/// recorded (shared with the driver via `calls`) so a capture test can assert
/// the pause-then-save-then-resume ordering without a live hypervisor.
struct MockVmFullControl {
    rootfs: PathBuf,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl mvm_vmm::checkpoint::VmFullControl for MockVmFullControl {
    fn pause(&self) -> Result<()> {
        self.calls.lock().unwrap().push("pause");
        Ok(())
    }

    fn resume(&self) -> Result<()> {
        self.calls.lock().unwrap().push("resume");
        Ok(())
    }

    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        self.calls.lock().unwrap().push("save_memory");
        std::fs::write(memory_path, b"mock-memory-state")
            .map_err(|e| anyhow!("writing mock memory file {}: {e}", memory_path.display()))
    }

    fn rootfs_path(&self) -> Result<PathBuf> {
        Ok(self.rootfs.clone())
    }

    fn device_anchors(&self) -> Result<mvm_core::checkpoint::DeviceAnchors> {
        Ok(mvm_core::checkpoint::DeviceAnchors {
            rootfs: self.rootfs.clone(),
            rootfs_verity: None,
            config: None,
            secrets: None,
            vsock: PathBuf::from("/mock/vsock"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_vmm::driver::spec::{ConsoleCapture, KernelImage};

    fn sample_spec(name: &str) -> VmmSpec {
        VmmSpec {
            name: name.to_string(),
            kernel: KernelImage::Bundled,
            initramfs: None,
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks: vec![],
            shares: vec![],
            vsock: vec![],
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
            plan_binding: None,
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
        let disk_base = driver.workload_base_bootargs(true);
        assert!(disk_base.contains("console=hvc0"));
        assert!(disk_base.contains("root=/dev/vda"));
        assert!(!disk_base.contains("ttyAMA0"));

        let bare_base = driver.workload_base_bootargs(false);
        assert!(!bare_base.contains("root="));
        assert!(!bare_base.contains("virtiofs"));
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

    #[test]
    fn mock_driver_offers_a_vm_full_capture_control() {
        assert!(MockDriver::default().vm_full_control("any-vm").is_some());
    }

    #[test]
    fn mock_vm_full_control_records_calls_and_reports_seeded_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();

        let driver = MockDriver::default().with_vm_full_rootfs(&rootfs);
        let control = driver.vm_full_control("standby-1").unwrap();

        control.pause().unwrap();
        let memory_path = tmp.path().join("memory.bin");
        control.save_memory(&memory_path).unwrap();
        control.resume().unwrap();

        assert_eq!(control.rootfs_path().unwrap(), rootfs);
        assert!(
            std::fs::read(&memory_path)
                .unwrap()
                .starts_with(b"mock-memory")
        );
        assert_eq!(
            driver.vm_full_calls(),
            vec!["pause", "save_memory", "resume"]
        );

        let anchors = control.device_anchors().unwrap();
        assert_eq!(anchors.rootfs, rootfs);
        assert!(anchors.rootfs_verity.is_none());
    }
}
