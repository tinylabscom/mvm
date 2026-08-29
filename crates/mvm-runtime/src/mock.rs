//! Test-only in-memory backend.
//!
//! `MockBackend` records `start` / `stop` / `pause` / `resume` calls
//! against a `Mutex<HashMap>` and never touches the host. It exists so
//! the VM-lifecycle CLI verbs (`mvmctl up`, `down`, `pause`, `resume`,
//! `set-ttl`, `fs`, `proc`, `volume mount`, `snapshot`) can be exercised
//! end-to-end in hermetic tests — `cargo test` on a CI runner with no
//! KVM, no VMM, and no Nix builder VM.
//!
//! Selected via `mvmctl up --hypervisor mock` (matches the
//! `AnyBackend::from_hypervisor` selector). Production callers don't
//! pick it explicitly — `AnyBackend::auto_select` never falls through
//! to it. Treat as test infrastructure; never trust it for anything
//! state-changing.
//!
//! ## Security profile
//!
//! Tier 3 / claims unknown. The mock satisfies none of the
//! seven CI-enforced security claims because it doesn't run a guest
//! at all — there's no isolation, no rootfs, no vsock. A loud
//! `--hypervisor mock` banner is expected (the CLI surfaces backend
//! tier on every `up`).

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, bail};
use mvm_core::checkpoint::CheckpointId;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    SnapshotCapability, StandbyClaim, StandbyError, StandbyHandle, StandbySpec, StandbyState,
    StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmNetworkInfo, VmStartConfig,
    VmStatus,
};

use crate::checkpoint::{CaptureFsQuickParams, capture_fs_quick};
use crate::mock_guest_agent::MockGuestAgent;

/// Per-VM state held by [`MockBackend`].
#[derive(Debug, Clone)]
struct MockVm {
    name: String,
    cpus: u32,
    memory_mib: u32,
    profile: Option<String>,
    flake_ref: Option<String>,
    revision: Option<String>,
    paused: bool,
}

/// In-memory test backend. See module docs.
///
/// The interior `Mutex<HashMap>` is wrapped in an `Arc` so cloning the
/// backend (e.g. across an `AnyBackend::Mock(MockBackend)` enum copy)
/// shares state. The `Default` impl returns an empty registry.
///
/// `agents` holds one [`MockGuestAgent`] per VM — the agent listens
/// on `<vm_dir>/runtime/v.sock` so host-side `fs` and `proc` callers
/// find a working endpoint at the same path Firecracker exposes for
/// the real vsock UDS.
#[derive(Debug, Default, Clone)]
pub struct MockBackend {
    state: std::sync::Arc<Mutex<HashMap<String, MockVm>>>,
    agents: std::sync::Arc<Mutex<HashMap<String, MockGuestAgent>>>,
    /// Opt-in: report `supports_standby_pool()` and honor `claim_standby`.
    /// Off by default so existing tests keep the fail-closed `Unsupported`.
    supports_standby: bool,
    /// Test knob: make `stop` fail, to exercise error-surfacing paths
    /// (e.g. `WarmLease::release` vs the swallowing `Drop`).
    fail_stop: bool,
    /// Test knob: make `spawn_standby` fail even when `supports_standby` is
    /// set, so a warm-pool caller's failure-counting path is exercisable
    /// against the same hermetic double the success path uses.
    fail_spawn_standby: bool,
}

impl MockBackend {
    /// Construct a fresh empty mock backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test builder: opt this mock into the standby-pool surface so
    /// `claim_standby` boots (records) the standby instead of failing closed.
    pub fn with_standby(mut self) -> Self {
        self.supports_standby = true;
        self
    }

    /// Test builder: make every `stop` return an error.
    pub fn with_failing_stop(mut self) -> Self {
        self.fail_stop = true;
        self
    }

    /// Test builder: make every `spawn_standby` return a `SpawnFailed` error
    /// (requires [`with_standby`](Self::with_standby) — otherwise
    /// `spawn_standby` already fails closed with `Unsupported`).
    pub fn with_failing_spawn_standby(mut self) -> Self {
        self.fail_spawn_standby = true;
        self
    }

    /// Test-only counterpart of the runner-backed spawn-and-capture path.
    ///
    /// The mock has no VMM process, but pool bookkeeping still needs the same
    /// captured checkpoint that a real runner returns so audit and claim tests
    /// exercise the production contract rather than a bare, unclaimable handle.
    pub(crate) fn spawn_standby_captured(
        &self,
        ctx: &crate::workload_runner::SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let mut handle = self.spawn_standby(spec)?;
        let rootfs = spec.image_path.as_deref().ok_or_else(|| {
            StandbyError::SpawnFailed(
                "mock standby capture requires a launch rootfs image".to_string(),
            )
        })?;
        let checkpoint_id = CheckpointId::new(format!("standby-parent-{}", spec.id));
        capture_fs_quick(
            ctx.checkpoints,
            CaptureFsQuickParams {
                id: checkpoint_id.clone(),
                vm_name: spec.id.clone(),
                rootfs: rootfs.into(),
                supervisor_config_digest: String::new(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: mvm_core::time::now_unix_secs(),
                quiesced: true,
                grants: None,
            },
        )
        .map_err(|e| StandbyError::SpawnFailed(format!("capture mock standby parent: {e}")))?;
        handle.parent_checkpoint = Some(checkpoint_id.to_string());
        Ok(handle)
    }

    /// Test helper: count VMs currently recorded.
    pub fn count(&self) -> usize {
        self.state.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Host-side per-VM directory for a mock VM. Lives under
    /// `<mvm_home>/mock-vms/<name>/` so it never collides with
    /// the real per-VM `<mvm_home>/vms/<name>` workspace that
    /// `resolve_running_vm_dir` expects for real Firecracker VMs.
    /// `pause.rs` and `resume.rs` read the snapshot directory through
    /// here when `--hypervisor mock` is set.
    pub fn vm_dir(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(mvm_core::config::mvm_home())
            .join("mock-vms")
            .join(name)
    }
}

impl VmBackend for MockBackend {
    fn name(&self) -> &str {
        "mock"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Mock
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            pause_resume: true,
            snapshots: true,
            snapshot_capability: SnapshotCapability::LiveMemory,
            standby_pool: self.supports_standby,
            vsock: false,
            tap_networking: false,
            balloon: false,
            fs_quick_checkpoint: false,
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        if state.contains_key(&config.name) {
            bail!("mock: VM '{}' already running", config.name);
        }
        // Create a host-side per-VM directory so the verbs that probe
        // `<vm_dir>/...` paths (pause/resume's snapshot dir; future
        // fs/proc/volume work) find something real. Best-effort — a
        // failure here doesn't abort start because not every consumer
        // needs the directory.
        let vm_dir = Self::vm_dir(&config.name);
        let _ = std::fs::create_dir_all(&vm_dir);
        // Spawn the mock vsock guest-agent on
        // `<vm_dir>/runtime/v.sock`. Failure to start the agent is
        // *not* fatal — the audit-emit tests that don't touch
        // fs/proc still want the VM to come up. The fs/proc tests
        // will see a clearer "connect failed" error than they
        // would from a missing agent.
        match MockGuestAgent::start(&vm_dir) {
            Ok(agent) => {
                if let Ok(mut agents) = self.agents.lock() {
                    agents.insert(config.name.clone(), agent);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "mock: failed to start MockGuestAgent for '{}': {e}",
                    config.name
                );
            }
        }
        state.insert(
            config.name.clone(),
            MockVm {
                name: config.name.clone(),
                cpus: config.cpus,
                memory_mib: config.memory_mib,
                profile: config.profile.clone(),
                flake_ref: Some(config.flake_ref.clone()),
                revision: Some(config.revision_hash.clone()),
                paused: false,
            },
        );
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, _id: &VmId) -> Result<VmExitStatus> {
        // Mock VMs run forever and never exit. Wait would block
        // indefinitely; bailing matches the behavior of other
        // backends that don't support wait.
        bail!("mock: wait is not supported (mock VMs do not exit)")
    }

    fn supports_standby_pool(&self) -> bool {
        self.supports_standby
    }

    fn spawn_standby(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        if !self.supports_standby {
            return Err(StandbyError::Unsupported {
                backend: "mock".to_string(),
            });
        }
        if self.fail_spawn_standby {
            return Err(StandbyError::SpawnFailed(
                "injected spawn failure (mock test knob)".to_string(),
            ));
        }
        // Echo the spec's compat fields into a handle — no live process backs
        // it, so the pool's later idle/compat bookkeeping (recorded by the
        // caller, not here) sees exactly what it asked to spawn.
        Ok(StandbyHandle {
            id: spec.id.clone(),
            template_id: spec.template_id.clone(),
            control_socket: spec.control_socket.clone(),
            pid: std::process::id(),
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
            root_strategy: spec.root_strategy,
            vsock_egress: spec.vsock_egress,
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
        })
    }

    fn claim_standby(
        &self,
        handle: &StandbyHandle,
        _claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        if !self.supports_standby {
            return Err(StandbyError::Unsupported {
                backend: "mock".to_string(),
            });
        }
        // A claimed standby becomes a running VM; record it under the
        // standby id so `count()` / `stop` behave like a normal boot.
        let mut state = self
            .state
            .lock()
            .map_err(|_| StandbyError::ClaimFailed("mock state mutex poisoned".to_string()))?;
        state.insert(
            handle.id.clone(),
            MockVm {
                name: handle.id.clone(),
                cpus: u32::from(handle.vcpus),
                memory_mib: handle.mem_mib,
                profile: None,
                flake_ref: None,
                revision: None,
                paused: false,
            },
        );
        Ok(VmId(handle.id.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        if self.fail_stop {
            bail!("mock: forced stop failure (test knob) for '{}'", id.0);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        state.remove(&id.0);
        // Drop the agent (which joins its thread + removes the socket)
        // and the on-disk VM dir.
        if let Ok(mut agents) = self.agents.lock()
            && let Some(agent) = agents.remove(&id.0)
        {
            agent.stop();
        }
        let vm_dir = Self::vm_dir(&id.0);
        if vm_dir.exists() {
            let _ = std::fs::remove_dir_all(&vm_dir);
        }
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        let names: Vec<String> = state.keys().cloned().collect();
        state.clear();
        if let Ok(mut agents) = self.agents.lock() {
            for (_, agent) in agents.drain() {
                agent.stop();
            }
        }
        for name in names {
            let vm_dir = Self::vm_dir(&name);
            if vm_dir.exists() {
                let _ = std::fs::remove_dir_all(&vm_dir);
            }
        }
        Ok(())
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        match state.get_mut(&id.0) {
            Some(vm) => {
                vm.paused = true;
                Ok(())
            }
            None => bail!("mock: VM '{}' is not running", id.0),
        }
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        match state.get_mut(&id.0) {
            Some(vm) => {
                vm.paused = false;
                Ok(())
            }
            None => bail!("mock: VM '{}' is not running", id.0),
        }
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        match state.get(&id.0) {
            Some(vm) if vm.paused => Ok(VmStatus::Paused),
            Some(_) => Ok(VmStatus::Running),
            None => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        Ok(state
            .values()
            .map(|vm| VmInfo {
                id: VmId(vm.name.clone()),
                name: vm.name.clone(),
                status: if vm.paused {
                    VmStatus::Paused
                } else {
                    VmStatus::Running
                },
                guest_ip: None,
                cpus: vm.cpus,
                memory_mib: vm.memory_mib,
                profile: vm.profile.clone(),
                revision: vm.revision.clone(),
                flake_ref: vm.flake_ref.clone(),
                ports: Vec::new(),
            })
            .collect())
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock backend state mutex poisoned"))?;
        if state.contains_key(&id.0) {
            Ok(format!("[mock] no logs for '{}' (mock backend)", id.0))
        } else {
            bail!("mock: VM '{}' is not running", id.0)
        }
    }

    fn is_available(&self) -> Result<bool> {
        Ok(true)
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn network_info(&self, _id: &VmId) -> Result<VmNetworkInfo> {
        bail!("mock backend does not provide network info")
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        bail!("mock backend does not provide guest channel info")
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // The mock satisfies none of the seven security claims because
        // it doesn't run a guest at all. Operators selecting it via
        // `--hypervisor mock` get a loud Tier-3 banner so they
        // can't accidentally land production traffic on it.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 3 (test-only)",
            notes: &[
                "MockBackend is in-process test infrastructure.",
                "No guest, no rootfs, no isolation; never use in production.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::VmStartConfig;

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            template_id: None,
            kernel_path: None,
            initrd_path: None,
            rootfs_path: "/tmp/stub.ext4".to_string(),
            virtiofs_root: None,
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_overlay_version: None,
            revision_hash: "abc".to_string(),
            flake_ref: ".".to_string(),
            profile: Some("default".to_string()),
            cpus: 2,
            cpu_grant: None,
            memory_mib: 512,
            mem_initial_mib: None,
            volumes: Vec::new(),
            extensions: Vec::new(),
            extension_plan_id: None,
            service_proxies: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
            runner_dir: None,
            tenant_id: None,
            plan_json: None,
            bundle_json: None,
            warm_pool_size: 0,
            network_policy: Default::default(),
            dev_console: false,
        }
    }

    #[test]
    fn start_records_vm_and_returns_id() {
        let b = MockBackend::new();
        let id = b.start(&cfg("vm-a")).unwrap();
        assert_eq!(id.0, "vm-a");
        assert_eq!(b.count(), 1);
    }

    #[test]
    fn double_start_fails() {
        let b = MockBackend::new();
        b.start(&cfg("vm-a")).unwrap();
        let err = b.start(&cfg("vm-a")).unwrap_err();
        assert!(err.to_string().contains("already running"));
    }

    #[test]
    fn stop_removes_from_registry() {
        let b = MockBackend::new();
        b.start(&cfg("vm-a")).unwrap();
        b.stop(&VmId("vm-a".to_string())).unwrap();
        assert_eq!(b.count(), 0);
    }

    #[test]
    fn pause_resume_round_trip() {
        let b = MockBackend::new();
        b.start(&cfg("vm-a")).unwrap();
        let id = VmId("vm-a".to_string());
        assert_eq!(b.status(&id).unwrap(), VmStatus::Running);
        b.pause(&id).unwrap();
        assert_eq!(b.status(&id).unwrap(), VmStatus::Paused);
        b.resume(&id).unwrap();
        assert_eq!(b.status(&id).unwrap(), VmStatus::Running);
    }

    #[test]
    fn list_returns_recorded_vms() {
        let b = MockBackend::new();
        b.start(&cfg("vm-a")).unwrap();
        b.start(&cfg("vm-b")).unwrap();
        let listed = b.list().unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn status_of_unknown_vm_is_stopped() {
        let b = MockBackend::new();
        let status = b.status(&VmId("nonexistent".to_string())).unwrap();
        assert_eq!(status, VmStatus::Stopped);
    }

    #[test]
    fn capabilities_advertises_pause_resume_and_snapshots() {
        let b = MockBackend::new();
        let caps = b.capabilities();
        assert!(caps.pause_resume);
        assert!(caps.snapshots);
        // No vsock / tap-networking — mock has no guest channel.
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn security_profile_is_tier_3_test_only() {
        let b = MockBackend::new();
        let profile = b.security_profile();
        assert_eq!(profile.tier, "Tier 3 (test-only)");
        assert!(
            profile
                .claims
                .iter()
                .all(|c| matches!(c, ClaimStatus::DoesNotHold)),
            "mock backend must not claim any ADR-002 guarantees"
        );
    }

    #[test]
    fn stop_all_clears_the_registry() {
        let b = MockBackend::new();
        b.start(&cfg("vm-a")).unwrap();
        b.start(&cfg("vm-b")).unwrap();
        b.start(&cfg("vm-c")).unwrap();
        b.stop_all().unwrap();
        assert_eq!(b.count(), 0);
    }

    #[test]
    fn shared_state_across_clones() {
        // The `Arc` lets `AnyBackend::Mock(MockBackend)` clone the
        // outer wrapper without losing track of in-flight VMs.
        let b1 = MockBackend::new();
        let b2 = b1.clone();
        b1.start(&cfg("vm-a")).unwrap();
        assert_eq!(b2.count(), 1, "cloned mock must see vm-a started via b1");
    }

    fn sample_standby_spec() -> StandbySpec {
        StandbySpec {
            id: "standby-a".into(),
            template_id: None,
            kernel_path: "/img/kernel".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: "/tmp/does-not-exist.sock".into(),
            vm_state_dir: "/tmp/does-not-exist".into(),
            image_path: None,
            image_sha256: None,
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    #[test]
    fn spawn_standby_fails_closed_without_standby_support() {
        let b = MockBackend::new();
        let err = b.spawn_standby(&sample_standby_spec()).unwrap_err();
        assert!(matches!(err, StandbyError::Unsupported { .. }));
    }

    #[test]
    fn spawn_standby_echoes_spec_into_the_handle_when_enabled() {
        let b = MockBackend::new().with_standby();
        let spec = sample_standby_spec();
        let handle = b.spawn_standby(&spec).unwrap();
        assert_eq!(handle.id, spec.id);
        assert_eq!(handle.kernel_sha256, spec.kernel_sha256);
        assert_eq!(handle.vcpus, spec.vcpus);
        assert_eq!(handle.mem_mib, spec.mem_mib);
        assert_eq!(
            handle.parent_checkpoint, None,
            "a bare spawn (no capture) carries no checkpoint yet"
        );
    }

    #[test]
    fn spawn_standby_honors_the_failing_test_knob() {
        let b = MockBackend::new()
            .with_standby()
            .with_failing_spawn_standby();
        let err = b.spawn_standby(&sample_standby_spec()).unwrap_err();
        assert!(matches!(err, StandbyError::SpawnFailed(_)));
    }
}
