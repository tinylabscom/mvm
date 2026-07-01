//! The driver-generic workload start mechanics. `WorkloadRunner` spawns the
//! per-VM host-side gating endpoint, maps the admitted config onto a `VmmSpec`,
//! and boots it through the `VmmDriver` seam — once, over the seam, instead of
//! copied into each backend's `start`. The endpoint spawn is itself behind the
//! `EndpointSpawner` trait so the runner is unit-testable with no real VM and no
//! real endpoint process.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mvm_core::config::{mvm_data_dir, vm_state_dir, vm_substitution_endpoint_socket};
use mvm_core::plan::SecretBinding;
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::driver::{RunningVm, VmmDriver};
use crate::egress_shared::decode_plan_secrets_from_state;
use crate::substitution_spawn::{
    EndpointTransport, SubstitutionSpawnParams, reap_substitution_endpoint,
    spawn_substitution_endpoint,
};
use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use crate::workload_runner::spec_map::{WorkloadSockets, WorkloadSpecInputs, workload_spec};

/// What the workload runner needs to stand up the per-VM gating endpoint.
pub struct EndpointSpawnRequest<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Raw TCP egress (no secrets) vs the WireRequest substitution protocol.
    pub raw_egress: bool,
}

/// Stand up the per-VM gating endpoint; return the host UDS the guest's
/// EGRESS_PORT relays to. The one host-side egress bridge (claim-10 gate +
/// claims 12/13 substitution).
pub trait EndpointSpawner: Send + Sync {
    fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf>;
}

/// The production `EndpointSpawner`: spawns the real `mvm-substitution-endpoint`
/// over the in-process-VMM UDS transport.
pub struct RealEndpointSpawner;

impl EndpointSpawner for RealEndpointSpawner {
    fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
        let uds = vm_substitution_endpoint_socket(req.vm_name);
        spawn_substitution_endpoint(SubstitutionSpawnParams {
            vm_name: req.vm_name,
            state_dir: req.state_dir,
            tenant: req.tenant,
            secrets: req.secrets,
            redaction: req.redaction,
            transport: EndpointTransport::Uds { path: uds.clone() },
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: Some(req.network_policy),
            raw_egress: req.raw_egress,
        })?;
        Ok(uds)
    }
}

/// Everything the runner needs to start a workload: the admitted launch config,
/// its tenant/secrets/redaction/policy, and the kernel cmdline the role above
/// assembled.
pub struct WorkloadLaunchInputs<'a> {
    pub config: &'a VmStartConfig,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    pub cmdline: String,
}

/// The standing host sockets a workload's vsock channels bind to, resolved
/// under its per-VM state dir. The egress gateway is the endpoint UDS the
/// spawner returns, not a state-dir path — it is the one gate off the box.
struct StandingSockets {
    agent: PathBuf,
    exit: PathBuf,
    console_log: PathBuf,
}

fn standing_sockets(state_dir: &Path) -> StandingSockets {
    StandingSockets {
        agent: state_dir.join("agent.sock"),
        exit: state_dir.join("workload.exit"),
        console_log: state_dir.join("console.log"),
    }
}

/// Starts workloads over the `VmmDriver` seam: spawn the per-VM gating endpoint,
/// map the config to a `VmmSpec`, boot via the driver.
pub struct WorkloadRunner<D: VmmDriver, S: EndpointSpawner> {
    driver: D,
    spawner: S,
}

impl<D: VmmDriver, S: EndpointSpawner> WorkloadRunner<D, S> {
    pub fn new(driver: D, spawner: S) -> Self {
        Self { driver, spawner }
    }

    /// Spawn the gating endpoint, compose the spec, and boot. The endpoint is
    /// ALWAYS spawned — it is the sole egress gate now, even for the no-secret
    /// raw path.
    pub fn start_workload(&self, inputs: &WorkloadLaunchInputs<'_>) -> Result<Box<dyn RunningVm>> {
        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // A secret-free workload speaks raw TCP; a secret-bearing one speaks the
        // WireRequest substitution protocol so the real secret never enters the guest.
        let raw_egress = inputs.secrets.is_empty();

        let egress_uds = self.spawner.spawn(&EndpointSpawnRequest {
            vm_name: &inputs.config.name,
            state_dir: &state_dir,
            tenant: inputs.tenant,
            secrets: inputs.secrets,
            redaction: inputs.redaction,
            network_policy: inputs.network_policy,
            raw_egress,
        })?;

        let socks = standing_sockets(&state_dir);
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            sockets: WorkloadSockets {
                agent: &socks.agent,
                egress_gateway: &egress_uds,
                exit: &socks.exit,
            },
            cmdline: inputs.cmdline.clone(),
            console_log: socks.console_log,
        });

        self.driver.boot(&spec)
    }
}

/// The runner IS the workload backend: the lifecycle runs through the `VmmDriver`
/// seam (`boot` on start, `attach` for stop/status/wait/pause/resume) instead of
/// per-backend code. State is disk-backed under the per-VM `vm_state_dir`, so a
/// stateless CLI invocation reconstructs a handle by id.
impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static> VmBackend for WorkloadRunner<D, S> {
    fn name(&self) -> &str {
        self.driver.name()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.driver.capabilities()
    }

    fn is_available(&self) -> Result<bool> {
        self.driver.is_available()
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Owned decode + defaults must outlive the `WorkloadLaunchInputs` borrows
        // below, so bind them here rather than inline.
        let default_redaction = RedactionPolicy::default();
        let decoded = decode_plan_secrets_from_state(&state_dir)?;
        let (secrets, redaction, tenant): (&[SecretBinding], &RedactionPolicy, &str) =
            match &decoded {
                Some((s, r, t)) => (s.as_slice(), r, t.as_str()),
                None => (
                    &[],
                    &default_redaction,
                    config.tenant_id.as_deref().unwrap_or("local"),
                ),
            };

        let inputs = WorkloadLaunchInputs {
            config,
            tenant,
            secrets,
            redaction,
            network_policy: &config.network_policy,
            cmdline: String::new(),
        };
        // The supervisor + endpoint are detached/disk-backed; the live handle is
        // reconstructed by id via `attach`, so the boot handle is dropped here.
        let _vm = self.start_workload(&inputs)?;
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        self.driver.attach(id)?.wait()
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        // Reap the per-VM secrets endpoint first, so a crashed VM's
        // decrypted-secret process can't outlive the guest. Idempotent + a no-op
        // when the VM spawned none.
        reap_substitution_endpoint(&vm_state_dir(&id.0), &id.0);
        self.driver.attach(id)?.kill()
    }

    fn stop_all(&self) -> Result<()> {
        for vm in self.list()? {
            let _ = self.stop(&vm.id);
        }
        Ok(())
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        self.driver.attach(id)?.pause()
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        self.driver.attach(id)?.resume()
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.driver.attach(id)?.status()
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        // Capture-only console; one log (no separate hypervisor stream).
        let log = vm_state_dir(&id.0).join("console.log");
        std::fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = PathBuf::from(mvm_data_dir()).join("vms");
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            // console.log is the generic marker that a workload booted in this
            // state dir (every backend captures it). A driver-provided marker
            // could replace this later.
            if !entry.path().join("console.log").exists() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let id = VmId(name.clone());
            let status = self.status(&id).unwrap_or(VmStatus::Stopped);
            vms.push(VmInfo {
                id,
                name,
                status,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            });
        }
        Ok(vms)
    }

    fn install(&self) -> Result<()> {
        // The in-house VMM needs no host install.
        Ok(())
    }
}

impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static> WorkloadBackend
    for WorkloadRunner<D, S>
{
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        // The runner always routes egress through the per-VM vsock UDS endpoint —
        // the sole gate off the box. No transparent :80/:443 terminator.
        EgressSubstitutionTransport::VsockUdsChannel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use mvm_core::plan::{SecretBinding, SecretSource};
    use mvm_guest::vsock::EGRESS_PORT;

    use crate::driver::mock::MockDriver;

    /// An `EndpointSpawner` test double: records the request it was handed and
    /// returns a canned UDS without spawning any process. `Mutex` (not `RefCell`)
    /// so it satisfies the `Send + Sync` a `VmBackend` spawner must be.
    struct RecordingSpawner {
        uds: PathBuf,
        seen: Mutex<Option<Recorded>>,
    }

    struct Recorded {
        raw_egress: bool,
        tenant: String,
        secrets_len: usize,
        policy: NetworkPolicy,
    }

    impl RecordingSpawner {
        fn new(uds: &str) -> Self {
            Self {
                uds: PathBuf::from(uds),
                seen: Mutex::new(None),
            }
        }
    }

    impl EndpointSpawner for RecordingSpawner {
        fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
            *self.seen.lock().unwrap() = Some(Recorded {
                raw_egress: req.raw_egress,
                tenant: req.tenant.to_string(),
                secrets_len: req.secrets.len(),
                policy: req.network_policy.clone(),
            });
            Ok(self.uds.clone())
        }
    }

    fn config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn static_secret() -> SecretBinding {
        SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Static {
                value: "s3cr3t".into(),
            },
        }
    }

    fn egress_host_uds(spec: &crate::driver::VmmSpec) -> &Path {
        spec.vsock
            .iter()
            .find(|p| p.guest_port == EGRESS_PORT)
            .map(|p| p.host_uds.as_path())
            .expect("spec carries an EGRESS_PORT vsock channel")
    }

    #[test]
    fn start_workload_threads_endpoint_uds_into_egress_port() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner =
            WorkloadRunner::new(MockDriver::default(), RecordingSpawner::new("/run/ep.sock"));

        let cfg = config("w-egress");
        let vm = runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: "root=/dev/vda".into(),
            })
            .expect("start_workload succeeds against the mock driver");

        assert_eq!(vm.id().0, "w-egress");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];

        // The endpoint UDS the spawner returned is wired to EGRESS_PORT.
        assert_eq!(egress_host_uds(spec), Path::new("/run/ep.sock"));
        // The sealed rootfs lands at /dev/vda.
        assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
        assert_eq!(spec.blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
        // The write-only console capture path is set under the state dir.
        assert!(spec.console.log_path.ends_with("console.log"));
    }

    #[test]
    fn start_workload_uses_raw_egress_when_no_secrets_and_wire_when_secrets() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();

        // No secrets ⇒ raw TCP egress.
        let raw_runner =
            WorkloadRunner::new(MockDriver::default(), RecordingSpawner::new("/run/ep.sock"));
        let cfg = config("w-raw");
        raw_runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();
        assert!(
            raw_runner
                .spawner
                .seen
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .raw_egress
        );

        // One secret ⇒ WireRequest substitution (raw_egress false).
        let wire_runner =
            WorkloadRunner::new(MockDriver::default(), RecordingSpawner::new("/run/ep.sock"));
        let cfg = config("w-wire");
        let secrets = [static_secret()];
        wire_runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &secrets,
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();
        let recorded = wire_runner.spawner.seen.lock().unwrap();
        let recorded = recorded.as_ref().unwrap();
        assert!(!recorded.raw_egress);
        assert_eq!(recorded.secrets_len, 1);
    }

    #[test]
    fn start_workload_passes_the_network_policy_and_tenant_to_the_spawner() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner =
            WorkloadRunner::new(MockDriver::default(), RecordingSpawner::new("/run/ep.sock"));

        let cfg = config("w-policy");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "acme",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();

        let recorded = runner.spawner.seen.lock().unwrap();
        let recorded = recorded.as_ref().unwrap();
        assert_eq!(recorded.tenant, "acme");
        assert_eq!(recorded.policy, NetworkPolicy::deny_all());
    }

    #[test]
    fn vmbackend_start_then_status_wait_stop_via_the_driver() {
        let exit = VmExitStatus {
            code: Some(0),
            success: true,
        };
        let runner = WorkloadRunner::new(
            MockDriver::with_exit(exit),
            RecordingSpawner::new("/run/ep.sock"),
        );

        let id = runner.start(&config("w")).expect("start succeeds");
        assert_eq!(id.0, "w");

        // attach hands back a MockRunningVm, so the lifecycle works with no real VM.
        assert_eq!(runner.status(&id).unwrap(), VmStatus::Running);
        assert_eq!(runner.wait(&id).unwrap(), exit);
        // stop reaps a nonexistent endpoint (no-op) then kills the attached handle.
        assert!(runner.stop(&VmId("w".into())).is_ok());
    }

    #[test]
    fn vmbackend_name_and_capabilities_delegate_to_the_driver() {
        let driver = MockDriver::default();
        let want_name = driver.name().to_string();
        let want_caps = driver.capabilities();
        let runner = WorkloadRunner::new(driver, RecordingSpawner::new("/run/ep.sock"));

        assert_eq!(runner.name(), want_name);
        assert_eq!(runner.capabilities().vsock, want_caps.vsock);
        assert!(runner.is_available().unwrap());
    }
}
