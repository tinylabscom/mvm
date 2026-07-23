//! The driver-generic workload start mechanics. `WorkloadRunner` spawns the
//! per-VM host-side gating endpoint, maps the admitted config onto a `VmmSpec`,
//! and boots it through the `VmmDriver` seam — once, over the seam, instead of
//! copied into each backend's `start`. The endpoint spawn is itself behind the
//! `EndpointSpawner` trait so the runner is unit-testable with no real VM and no
//! real endpoint process.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mvm_agentd::vsock::BROKER_PORT;
use mvm_core::config::{vm_state_dir, vm_substitution_endpoint_socket, vms_dir};
use mvm_core::plan::SecretBinding;
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, SnapshotCapability, StartMode,
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::driver::{RunningVm, VmmDriver};
use crate::egress_shared::decode_plan_secrets_from_state;
use crate::network_tunnel_spawn::{
    NetworkTunnelListener, NetworkTunnelWorkerSpawnParams, reap_network_tunnel_worker,
    spawn_network_tunnel_worker_if_configured,
};
use crate::substitution_spawn::{
    EndpointTransport, SubstitutionSpawnParams, reap_substitution_endpoint,
    spawn_substitution_endpoint,
};
use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use crate::workload_runner::cmdline;
use crate::workload_runner::spec_map::{
    WorkloadSockets, WorkloadSpecInputs, console_data_sockets, ensure_no_dir_share_volumes,
    network_tunnel_socket, workload_spec,
};

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

/// What the runner needs to register the per-VM host-services broker after boot.
pub struct BrokerRegisterRequest<'a> {
    /// VM name — the registration's `vm_id`, workload id, and per-VM chain key.
    pub vm_name: &'a str,
    /// Per-VM state dir (audit-signer pid/sock + the daemon tenant-ref marker).
    pub state_dir: &'a Path,
    /// Tenant from the admitted plan. `None` ⇒ unadmitted ⇒ a defused no-op:
    /// no broker services and no BROKER_PORT in the spec, so a stray guest dial
    /// stays `ECONNREFUSED` (fail-closed).
    pub tenant: Option<&'a str>,
    /// The `BROKER_PORT` socket the broker/daemon binds — the same path the spec
    /// wires the guest's `BROKER_PORT` relay to. `None` on the unadmitted path.
    pub broker_listen_socket: Option<&'a Path>,
}

/// Register/spawn the per-VM host-services broker for an admitted workload,
/// returning a guard whose Drop reaps until defused. The claims-12/13 seam:
/// `host.audit.v1` / `host.secrets.v1` reach the guest over `BROKER_PORT`, and
/// no raw secret ever crosses that channel. Behind a trait so the runner is
/// unit-testable with no real broker subprocess.
pub trait BrokerRegistrar: Send + Sync {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard>;
}

/// RAII guard around the registered broker services: Drop reaps them until the
/// VM is confirmed up and `defuse`d (the `stop` path then owns teardown). Wraps
/// the existing `ServicesGuard` so no reaping logic is duplicated.
pub struct BrokerGuard(crate::host_agent_spawn::ServicesGuard);

impl BrokerGuard {
    /// A guard that reaps nothing on drop — the unadmitted / spawn-failed path.
    fn defused() -> Self {
        Self(crate::host_agent_spawn::ServicesGuard::None)
    }

    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.0.defuse();
    }
}

/// The production `BrokerRegistrar`: delegates to the existing per-tenant
/// host-agent registration (default) or the per-VM broker fork
/// (`MVM_HOST_AGENT_DAEMON=0`). No broker logic is reimplemented here — this is
/// the same registration the raw backend `start` paths run, lifted onto the
/// runner so a workload moved here keeps its host services.
pub struct RealBrokerRegistrar;

impl BrokerRegistrar for RealBrokerRegistrar {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        // Unadmitted (no tenant, hence no broker socket): register nothing. The
        // spec carries no BROKER_PORT either, so a stray guest dial fails closed.
        let (Some(tenant), Some(broker_listen_socket)) = (req.tenant, req.broker_listen_socket)
        else {
            return Ok(BrokerGuard::defused());
        };

        // Best-effort, matching the raw backends: an absent broker only disables
        // host.audit.v1 for this VM — the workload still runs and the host-side
        // audit chain is intact — so a spawn failure is logged, never a rollback.
        let guard = if crate::host_agent_spawn::host_agent_daemon_enabled() {
            match crate::host_agent_spawn::register_host_agent_services_if_admitted(
                crate::host_agent_spawn::HostAgentServicesParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                },
            ) {
                Ok(g) => crate::host_agent_spawn::ServicesGuard::Agent(g),
                Err(e) => {
                    tracing::warn!(vm = %req.vm_name, error = %e, "host-agent registration failed; host.audit.v1 unavailable for this VM");
                    crate::host_agent_spawn::ServicesGuard::None
                }
            }
        } else {
            match crate::broker_services_spawn::spawn_broker_services_if_admitted(
                crate::broker_services_spawn::BrokerServicesSpawnParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                },
            ) {
                Ok(g) => crate::host_agent_spawn::ServicesGuard::Fork(g),
                Err(e) => {
                    tracing::warn!(vm = %req.vm_name, error = %e, "host-services broker spawn failed; host.audit.v1 unavailable for this VM");
                    crate::host_agent_spawn::ServicesGuard::None
                }
            }
        };
        Ok(BrokerGuard(guard))
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
    /// Host-services broker socket, resolved only for an admitted workload
    /// (`tenant_id.is_some()`). `None` for an unadmitted VM, which carries no
    /// broker channel at all. The one path threaded into both the spec and the
    /// `BrokerRegistrar::register` call so the relay target and bind path match.
    broker: Option<PathBuf>,
    network_tunnel: Option<(u32, PathBuf)>,
    console_log: PathBuf,
    /// Per-port UDS for the interactive console data range. Non-empty only when
    /// `VmStartConfig.dev_console` is true; empty for all sealed prod boots.
    console_data: Vec<(u32, PathBuf)>,
}

fn standing_sockets(state_dir: &Path, config: &VmStartConfig) -> StandingSockets {
    StandingSockets {
        // Single source of truth shared with the host-side resolver so the
        // guest agent bridge can't drift out of the host's reach.
        agent: mvm_core::config::vm_inhouse_agent_socket_at(state_dir),
        exit: state_dir.join("workload.exit"),
        // Admitted-only: an unadmitted VM gets no broker channel, so a stray
        // guest BROKER_PORT dial stays ECONNREFUSED (fail-closed).
        broker: config
            .tenant_id
            .is_some()
            .then(|| mvm_core::config::vm_vsock_port_socket_at(state_dir, BROKER_PORT)),
        network_tunnel: network_tunnel_socket(state_dir, config),
        console_log: state_dir.join("console.log"),
        console_data: console_data_sockets(state_dir, config.dev_console),
    }
}

/// Starts workloads over the `VmmDriver` seam: spawn the per-VM gating endpoint,
/// map the config to a `VmmSpec`, boot via the driver.
pub struct WorkloadRunner<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar> {
    driver: D,
    spawner: S,
    broker: B,
}

impl<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    pub fn new(driver: D, spawner: S, broker: B) -> Self {
        Self {
            driver,
            spawner,
            broker,
        }
    }

    /// Spawn the gating endpoint, compose the spec, and boot. The endpoint is
    /// ALWAYS spawned — it is the sole egress gate now, even for the no-secret
    /// raw path.
    pub fn start_workload(&self, inputs: &WorkloadLaunchInputs<'_>) -> Result<Box<dyn RunningVm>> {
        // Fail closed before any side effect (endpoint/tunnel spawn) runs: a
        // `DirShare` volume has no `VmmSpec` representation on this driver
        // seam, so refuse it here rather than silently dropping it later in
        // `workload_blocks`.
        ensure_no_dir_share_volumes(inputs.config)?;

        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // A secret-free workload speaks raw TCP; a secret-bearing one speaks the
        // WireRequest substitution protocol so the real secret never enters the guest.
        let raw_egress = inputs.secrets.is_empty();
        let mut tunnel_guard =
            spawn_network_tunnel_worker_if_configured(NetworkTunnelWorkerSpawnParams {
                state_dir: &state_dir,
                runtime_config: inputs.config.network_tunnel.as_ref(),
                listener: inputs.config.network_tunnel.as_ref().map(|tunnel| {
                    NetworkTunnelListener::Uds(mvm_core::config::vm_vsock_port_socket_at(
                        &state_dir,
                        tunnel.guest_port,
                    ))
                }),
                network_policy: Some(&inputs.config.network_policy),
            })?;

        let egress_uds = self.spawner.spawn(&EndpointSpawnRequest {
            vm_name: &inputs.config.name,
            state_dir: &state_dir,
            tenant: inputs.tenant,
            secrets: inputs.secrets,
            redaction: inputs.redaction,
            network_policy: inputs.network_policy,
            raw_egress,
        })?;

        let socks = standing_sockets(&state_dir, inputs.config);
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            sockets: WorkloadSockets {
                agent: &socks.agent,
                egress_gateway: &egress_uds,
                exit: &socks.exit,
                broker: socks.broker.as_deref(),
                network_tunnel: socks.network_tunnel,
                console_data: socks.console_data,
            },
            cmdline: inputs.cmdline.clone(),
            console_log: socks.console_log,
        });

        let vm = self.driver.boot(&spec)?;
        tunnel_guard.defuse();

        // Register the per-VM host-services broker (host.audit.v1 /
        // host.secrets.v1) for an admitted workload — the same registration the
        // raw backends run, lifted here so a workload on this runner keeps those
        // services. The guard's Drop reaps on any early return until it's defused;
        // registration is best-effort (a failure is logged inside `register`,
        // never a launch rollback).
        let mut broker_guard = self.broker.register(&BrokerRegisterRequest {
            vm_name: &inputs.config.name,
            state_dir: &state_dir,
            tenant: inputs.config.tenant_id.as_deref(),
            broker_listen_socket: socks.broker.as_deref(),
        })?;
        broker_guard.defuse();
        Ok(vm)
    }
}

/// The runner IS the workload backend: the lifecycle runs through the `VmmDriver`
/// seam (`boot` on start, `attach` for stop/status/wait/pause/resume) instead of
/// per-backend code. State is disk-backed under the per-VM `vm_state_dir`, so a
/// stateless CLI invocation reconstructs a handle by id.
impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static, B: BrokerRegistrar + 'static> VmBackend
    for WorkloadRunner<D, S, B>
{
    fn name(&self) -> &str {
        self.driver.name()
    }

    fn kind(&self) -> BackendKind {
        self.driver.kind()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.driver.capabilities()
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        self.driver.snapshot_capability()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.driver.security_profile()
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.driver.guest_channel_info(id)
    }

    fn is_available(&self) -> Result<bool> {
        self.driver.is_available()
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Admission gate — refuse a rootfs whose parent dir carries no
        // overlay-aware sidecar (no `/mvm/runtime` mount point). Runs before any
        // endpoint/broker spawn or boot, so a refusal leaves no live process
        // behind. The raw per-backend `start` paths run this; the runner is the
        // sole path for the drivers behind it, so the gate lives here once.
        let rootfs = Path::new(&config.rootfs_path);
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_runtime_overlay_contract(
            rootfs_dir,
            config.runtime_source_policy,
        )?;
        // Record per-VM runtime metadata (the sidecar accessibility bit + the
        // boot contract) so the `mvmctl console` accessible/sealed gate holds on
        // every runner-launched VM, matching the raw backend start paths.
        crate::base::runtime_meta::record_from_start_config(
            &config.name,
            StartMode::Detached,
            config,
        )?;

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
            cmdline: cmdline::runner_cmdline(config, &state_dir, |virtiofs_root, has_disk| {
                self.driver.workload_base_bootargs(virtiofs_root, has_disk)
            }),
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
        reap_network_tunnel_worker(&vm_state_dir(&id.0));
        // Reap the per-VM broker + audit-signer (fork path) and deregister from
        // the per-tenant host-agent daemon (daemon path), so neither can outlive
        // the guest. Each is an idempotent no-op for the other path and for a VM
        // that registered none.
        crate::broker_services_spawn::reap_broker_services(&vm_state_dir(&id.0));
        crate::host_agent_spawn::reap_host_agent_services_from_state(&vm_state_dir(&id.0), &id.0);
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
        let root = vms_dir();
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
        // The hvf VMM needs no host install.
        Ok(())
    }
}

impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    WorkloadBackend for WorkloadRunner<D, S, B>
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

    use mvm_agentd::vsock::EGRESS_PORT;
    use mvm_core::plan::{Nonce, SecretBinding, SecretSource, VerbGrant, VerbId};
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::util::test_env::TestEnv;

    use crate::driver::HvfDriver;
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

    /// A `BrokerRegistrar` test double: records the request it saw and returns a
    /// defused no-op guard (spawns no broker subprocess). `Mutex` for the
    /// `Send + Sync` bound a `VmBackend`'s registrar must satisfy.
    struct RecordingBrokerRegistrar {
        seen: Mutex<Option<RecordedBroker>>,
    }

    struct RecordedBroker {
        vm_name: String,
        tenant: Option<String>,
        broker_listen_socket: Option<PathBuf>,
    }

    impl RecordingBrokerRegistrar {
        fn new() -> Self {
            Self {
                seen: Mutex::new(None),
            }
        }
    }

    impl BrokerRegistrar for RecordingBrokerRegistrar {
        fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
            *self.seen.lock().unwrap() = Some(RecordedBroker {
                vm_name: req.vm_name.to_string(),
                tenant: req.tenant.map(str::to_string),
                broker_listen_socket: req.broker_listen_socket.map(Path::to_path_buf),
            });
            Ok(BrokerGuard::defused())
        }
    }

    fn config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    /// Seed an overlay-aware `mvm-meta.json` sidecar next to a rootfs file in a
    /// fresh tempdir and return `(dir, rootfs_path)`. `VmBackend::start`'s
    /// admission gate refuses a rootfs whose parent dir carries no overlay-aware
    /// sidecar, so every test that drives the full trait method provides one.
    /// The returned `TempDir` must stay in scope for the rootfs to exist.
    fn overlay_aware_rootfs(name: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // sealed=false (accessible dev image), runtime_lean=true so the sidecar
        // clears the gate under every runtime-source policy, not just the default.
        mvm_build::builder_vm::GuestSidecar::for_oci_run(name, false, true)
            .write_to_dir(dir.path())
            .unwrap();
        (dir, rootfs.display().to_string())
    }

    fn keystore_secret() -> SecretBinding {
        SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "test-key".into(),
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
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

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
        let raw_runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
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
        let wire_runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let cfg = config("w-wire");
        let secrets = [keystore_secret()];
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
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

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

    fn admitted_config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            tenant_id: Some("tenant-x".into()),
            ..Default::default()
        }
    }

    #[test]
    fn start_workload_registers_the_broker_and_wires_it_into_the_spec_when_admitted() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = admitted_config("w-broker-admitted");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload succeeds");

        // register saw the tenant + the resolved BROKER_PORT bind socket.
        let expected_socket =
            mvm_core::config::vm_vsock_port_socket("w-broker-admitted", BROKER_PORT);
        let recorded = runner.broker.seen.lock().unwrap();
        let recorded = recorded.as_ref().expect("register was called");
        assert_eq!(recorded.vm_name, "w-broker-admitted");
        assert_eq!(recorded.tenant.as_deref(), Some("tenant-x"));
        assert_eq!(
            recorded.broker_listen_socket.as_deref(),
            Some(expected_socket.as_path())
        );

        // The spec carries the same socket as a GuestDials BROKER_PORT channel, so
        // the supervisor relay target and the daemon's bind path are identical.
        let specs = runner.driver.booted_specs();
        let broker = specs[0]
            .vsock
            .iter()
            .find(|p| p.guest_port == BROKER_PORT)
            .expect("admitted spec carries a BROKER_PORT channel");
        assert_eq!(broker.direction, crate::driver::VsockDirection::GuestDials);
        assert_eq!(broker.host_uds, expected_socket);
    }

    #[test]
    fn start_workload_broker_is_a_defused_no_op_when_unadmitted() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        // config() sets no tenant_id ⇒ unadmitted.
        let cfg = config("w-broker-unadmitted");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "local",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload succeeds");

        // register is still called, but with no tenant + no broker socket.
        let recorded = runner.broker.seen.lock().unwrap();
        let recorded = recorded.as_ref().expect("register is still called");
        assert_eq!(recorded.tenant, None);
        assert_eq!(recorded.broker_listen_socket, None);

        // The spec carries NO BROKER_PORT channel, so a stray guest dial to
        // BROKER_PORT stays ECONNREFUSED (fail-closed).
        let specs = runner.driver.booted_specs();
        assert!(
            specs[0].vsock.iter().all(|p| p.guest_port != BROKER_PORT),
            "unadmitted VM must carry no broker port"
        );
    }

    #[test]
    fn stop_reaps_the_host_agent_tenant_ref_marker() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let vm_name = "runner-stop-reaps-broker";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        // Plant the daemon-path tenant-ref marker `register` writes; the stop reap
        // must remove it, proving `reap_host_agent_services_from_state` ran.
        std::fs::write(state_dir.join("host-agent.tenant"), "tenant-x").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.stop(&VmId(vm_name.into())).expect("stop succeeds");

        assert!(
            !state_dir.join("host-agent.tenant").exists(),
            "stop must reap the host-agent registration marker"
        );
    }

    #[test]
    fn vmbackend_start_then_status_wait_stop_via_the_driver() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let exit = VmExitStatus {
            code: Some(0),
            success: true,
        };
        let runner = WorkloadRunner::new(
            MockDriver::with_exit(exit),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w");
        let cfg = VmStartConfig {
            name: "w".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        let id = runner.start(&cfg).expect("start succeeds");
        assert_eq!(id.0, "w");

        // attach hands back a MockRunningVm, so the lifecycle works with no real VM.
        assert_eq!(runner.status(&id).unwrap(), VmStatus::Running);
        assert_eq!(runner.wait(&id).unwrap(), exit);
        // stop reaps a nonexistent endpoint (no-op) then kills the attached handle.
        assert!(runner.stop(&VmId("w".into())).is_ok());
    }

    /// Write a `verb-grant.json` sidecar plus the host-signer public key
    /// under `vm_name`'s state dir, the shape the grant cmdline tokens read.
    fn seed_grant_sidecar_and_key(vm_name: &str) {
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        let nonce = Nonce::from_bytes([9u8; 16]);
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "cc".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: VerbGrant {
                session_id: vm_name.to_string(),
                plan_nonce: nonce,
                not_after,
                verbs: vec![VerbId::new("run-entrypoint").unwrap()],
                sig: vec![0u8; 64],
            },
        };
        std::fs::write(
            state_dir.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
    }

    /// `WorkloadRunner::start` (the `VmBackend::start` production path) must
    /// assemble the same security-bearing kernel cmdline the raw HVF backend
    /// does — dm-verity, the plan-bound grant triple, vsock egress, and the
    /// runtime-source-policy token — instead of booting with an empty
    /// cmdline. Drives the whole trait method through a `MockDriver` and
    /// inspects the booted `VmmSpec` it recorded.
    #[test]
    fn start_assembles_the_security_cmdline_tokens_via_the_shared_assembler() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        let verity = rootfs_dir.path().join("rootfs.verity");
        let initrd = rootfs_dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();
        // Overlay-aware sidecar next to the rootfs so `start`'s admission gate
        // (refuses a rootfs with no `/mvm/runtime` mount point) admits this boot.
        mvm_build::builder_vm::GuestSidecar::for_oci_run(
            "runner-security-cmdline-tokens",
            false,
            true,
        )
        .write_to_dir(rootfs_dir.path())
        .unwrap();

        let vm_name = "runner-security-cmdline-tokens";
        seed_grant_sidecar_and_key(vm_name);

        let cfg = VmStartConfig {
            name: vm_name.into(),
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
            ..Default::default()
        };

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let cmdline = &specs[0].cmdline;

        let require_grant = crate::microvm::require_grant_cmdline_token(vm_name)
            .expect("sidecar present ⇒ enforcement token");
        for needle in [
            "mvm.roothash=",
            "mvm.data=/dev/vda",
            "mvm.verb_grant=",
            require_grant.as_str(),
            "mvm.host_signer_pub=",
            "mvm.vsock_egress=1",
            "mvm.runtime_source_policy=",
        ] {
            assert!(
                cmdline.contains(needle),
                "booted cmdline missing {needle:?}: {cmdline}"
            );
        }
    }

    /// The base console/earlycon/root bootargs the runner boots with must come
    /// from the driver (`VmmDriver::workload_base_bootargs`), not a hardcoded
    /// HVF default — proven by driving `start` through a `MockDriver` whose
    /// base uses `hvc0` rather than HVF's `ttyAMA0` and asserting the booted
    /// spec's cmdline carries that base.
    #[test]
    fn start_uses_the_drivers_base_bootargs_not_a_hardcoded_hvf_default() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let driver = MockDriver::default();
        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-driver-base-bootargs");
        let cfg = VmStartConfig {
            name: "runner-driver-base-bootargs".into(),
            rootfs_path: rootfs,
            network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
            ..Default::default()
        };

        let runner = WorkloadRunner::new(
            driver.clone(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let cmdline = &specs[0].cmdline;

        let expected_base = driver.workload_base_bootargs(false, true);
        assert!(
            cmdline.starts_with(&expected_base),
            "cmdline did not start with the driver's base bootargs {expected_base:?}: {cmdline}"
        );
        assert!(
            !cmdline.contains("ttyAMA0"),
            "cmdline carried the hardcoded HVF console rather than the driver's: {cmdline}"
        );
    }

    fn disk_volume(host: &str, guest: &str, read_only: bool) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    fn dir_share_volume(host: &str, guest: &str) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: false,
            kind: mvm_core::vm_backend::VmVolumeKind::DirShare,
            encrypted: false,
        }
    }

    /// A `--volume` disk (claim 11's sealed app-dep disk, or any other
    /// `Disk`-kind volume) must reach a runner-booted guest both as an
    /// attached `BlockDev` and as an `mvm.uvols=` cmdline entry naming it —
    /// otherwise the guest has the bytes on `/dev/vdb` but no manifest saying
    /// what they are for.
    #[test]
    fn start_carries_a_disk_volume_into_both_blocks_and_the_uvols_token() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-uvol");
        let cfg = VmStartConfig {
            name: "w-uvol".into(),
            rootfs_path: rootfs,
            volumes: vec![disk_volume("/vol/data.img", "/data", true)],
            ..Default::default()
        };
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];

        // The rootfs takes /dev/vda; the volume disk lands right after it.
        assert_eq!(
            spec.blocks
                .iter()
                .map(|b| b.device_node())
                .collect::<Vec<_>>(),
            vec!["/dev/vda", "/dev/vdb"]
        );
        assert_eq!(spec.blocks[1].source, PathBuf::from("/vol/data.img"));
        assert!(spec.blocks[1].read_only);

        assert!(
            spec.cmdline.contains("mvm.uvols=uvol0:"),
            "booted cmdline missing the uvols token: {}",
            spec.cmdline
        );
    }

    #[test]
    fn start_emits_no_uvols_token_when_there_are_no_volumes() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-no-uvol");
        let cfg = VmStartConfig {
            name: "w-no-uvol".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert!(
            !specs[0].cmdline.contains("mvm.uvols="),
            "cmdline must carry no uvols token with no volumes: {}",
            specs[0].cmdline
        );
    }

    /// The lifted admission gate: `VmBackend::start` refuses a rootfs whose
    /// parent dir carries no overlay-aware sidecar (no `/mvm/runtime` mount
    /// point) before any endpoint spawn or boot, and on an admitted boot it
    /// records the per-VM runtime metadata the console accessible/sealed gate
    /// reads. Drives the whole trait method through a `MockDriver`.
    #[test]
    fn start_refuses_a_rootfs_without_the_overlay_sidecar_and_records_runtime_meta() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        // A rootfs whose parent dir carries no sidecar is refused before boot.
        let bare = tempfile::tempdir().unwrap();
        let bare_rootfs = bare.path().join("rootfs.ext4");
        std::fs::write(&bare_rootfs, b"rootfs").unwrap();
        let refused = VmStartConfig {
            name: "runner-gate-refused".into(),
            rootfs_path: bare_rootfs.display().to_string(),
            ..Default::default()
        };
        let err = runner
            .start(&refused)
            .expect_err("a rootfs with no overlay-aware sidecar must be refused");
        assert!(
            err.to_string().contains("mvm-meta.json"),
            "refusal must name the missing sidecar: {err}"
        );
        assert!(
            runner.driver.booted_specs().is_empty(),
            "the gate must fire before any boot"
        );

        // An overlay-aware rootfs is admitted, and start records runtime_meta so
        // the console accessible/sealed gate has a per-VM record to read.
        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-gate-admitted");
        let admitted = VmStartConfig {
            name: "runner-gate-admitted".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        runner
            .start(&admitted)
            .expect("an overlay-aware rootfs is admitted");
        let meta = crate::base::runtime_meta::read("runner-gate-admitted")
            .expect("runtime_meta read")
            .expect("start records runtime_meta");
        assert_eq!(
            meta.rootfs_path.as_deref(),
            Some(admitted.rootfs_path.as_str())
        );
    }

    /// A `DirShare` volume has no `VmmSpec` representation on this driver
    /// seam. `start_workload` must refuse it before spawning the gating
    /// endpoint or the broker — never boot a VM missing a share the caller
    /// asked for.
    #[test]
    fn start_workload_refuses_a_dir_share_volume_before_any_side_effect() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            volumes: vec![dir_share_volume("/host/dir", "/mnt/share")],
            ..config("w-dirshare-refused")
        };
        let result = runner.start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        });
        let message = match result {
            Ok(_) => panic!("a DirShare volume must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains("/host/dir"), "message: {message}");
        assert!(message.contains("/mnt/share"), "message: {message}");

        assert!(
            runner.driver.booted_specs().is_empty(),
            "refused start must never reach the driver"
        );
        assert!(
            runner.spawner.seen.lock().unwrap().is_none(),
            "refused start must never spawn the gating endpoint"
        );
        assert!(
            runner.broker.seen.lock().unwrap().is_none(),
            "refused start must never register the broker"
        );
    }

    #[test]
    fn vmbackend_name_and_capabilities_delegate_to_the_driver() {
        let driver = MockDriver::default();
        let want_name = driver.name().to_string();
        let want_caps = driver.capabilities();
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        assert_eq!(runner.name(), want_name);
        assert_eq!(runner.capabilities().vsock, want_caps.vsock);
        assert!(runner.is_available().unwrap());
    }

    #[test]
    fn vmbackend_kind_snapshot_security_and_channel_delegate_to_the_hvf_driver() {
        // Proves the runner reads these from the driver rather than the old
        // `BackendKind::Hvf` hardcode / the VmBackend trait's fail-closed
        // defaults — a runner wrapping a *different* driver would report that
        // driver's own values instead.
        let driver = HvfDriver::new();
        let want_kind = driver.kind();
        let want_snapshot = driver.snapshot_capability();
        let want_security_tier = driver.security_profile().tier;
        let id = VmId("kind-delegation-test-vm".into());
        let want_channel_err = driver.guest_channel_info(&id).is_err();
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        assert_eq!(runner.kind(), want_kind);
        assert_eq!(runner.kind(), BackendKind::Hvf);
        assert_eq!(runner.snapshot_capability(), want_snapshot);
        assert_eq!(runner.security_profile().tier, want_security_tier);
        assert_eq!(runner.guest_channel_info(&id).is_err(), want_channel_err);
    }

    #[test]
    fn start_workload_with_dev_console_threads_128_console_ports_into_spec() {
        use mvm_agentd::vsock::CONSOLE_PORT_BASE;
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            dev_console: true,
            ..config("w-dev-console")
        };
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "t",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload with dev_console succeeds");

        let specs = runner.driver.booted_specs();
        let spec = &specs[0];

        // 3 standing + 128 console data = 131 vsock entries.
        assert_eq!(spec.vsock.len(), 131);

        // Every console port is in range and routed as HostDials.
        let console: Vec<_> = spec
            .vsock
            .iter()
            .filter(|p| p.guest_port > CONSOLE_PORT_BASE)
            .collect();
        assert_eq!(console.len(), 128);
        assert!(
            console
                .iter()
                .all(|p| p.direction == crate::driver::VsockDirection::HostDials),
            "console ports must be HostDials"
        );

        // Paths live under <state_dir>/vsock/ — the shared HVF vsock convention.
        let first = &console[0];
        assert!(
            first.host_uds.to_string_lossy().contains("/vsock/vsock-"),
            "path must be under vsock/ subdir: {}",
            first.host_uds.display()
        );
    }

    #[test]
    fn start_workload_without_dev_console_carries_only_three_vsock_entries() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            dev_console: false,
            ..config("w-sealed")
        };
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "t",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload without dev_console succeeds");

        let specs = runner.driver.booted_specs();
        let spec = &specs[0];
        assert_eq!(
            spec.vsock.len(),
            3,
            "sealed prod boot must carry no console listeners"
        );
    }
}
