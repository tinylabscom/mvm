//! Doubles and fixtures the runner tests share.
#![cfg(test)]

use super::*;
use crate::driver::MockDriver;
use mvm_agentd::vsock::GUEST_AGENT_PORT;
use mvm_core::policy::network_policy::HostPort;
use std::collections::HashMap;
use std::sync::Mutex;

/// An `NetworkEndpointSpawner` test double: records the request it was handed and
/// returns a canned UDS without spawning any process. `Mutex` (not `RefCell`)
/// so it satisfies the `Send + Sync` a `VmBackend` spawner must be.
pub(super) struct RecordingSpawner {
    pub(super) uds: PathBuf,
    pub(super) seen: Mutex<Option<Recorded>>,
}

pub(super) struct Recorded {
    pub(super) mints_identity: bool,
    pub(super) tenant: String,
    pub(super) secrets_len: usize,
    pub(super) policy: NetworkPolicy,
    pub(super) network_limits: mvm_core::plan::NetworkLimits,
}

impl RecordingSpawner {
    pub(super) fn new(uds: &str) -> Self {
        Self {
            uds: PathBuf::from(uds),
            seen: Mutex::new(None),
        }
    }
}

impl NetworkEndpointSpawner for RecordingSpawner {
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        // The real spawner clears any stale provisioning marker here, so a
        // re-used state dir never asserts a previous boot's telemetry.
        let _ =
            mvm_vmm::host::telemetry_provisioning::record_boot_provisioning(req.state_dir, false);
        if !matches!(req.identity, FlowMuxIdentitySource::Mint) {
            return Ok(None);
        }
        std::fs::create_dir_all(req.state_dir)?;
        let path = req
            .state_dir
            .join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE);
        std::fs::write(&path, b"mock-identity-drive")?;
        Ok(Some(path))
    }

    fn start_telemetry_without_endpoint(
        &self,
        req: &NetworkEndpointSpawnRequest<'_>,
    ) -> TelemetryStart {
        // Recorded now because the guest's cmdline is built from the
        // marker; the double itself starts no collector process.
        let provisioned = spawner::telemetry_for_boot(
            mvm_vmm::host::telemetry_provisioning::telemetry_collection_enabled(),
            req.identity,
        );
        if provisioned {
            let _ = mvm_vmm::host::telemetry_provisioning::record_boot_provisioning(
                req.state_dir,
                true,
            );
        }
        TelemetryStart::default()
    }

    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        *self.seen.lock().unwrap() = Some(Recorded {
            mints_identity: matches!(req.identity, FlowMuxIdentitySource::Mint),
            tenant: req.tenant.to_string(),
            secrets_len: req.secrets.len(),
            policy: req.network_policy.clone(),
            network_limits: req.network_limits,
        });
        let identity_drive = self.prepare_identity(req)?;
        // The same record the real endpoint spawn writes, so the cmdline
        // token gate observes this boot's provisioning decision.
        let _ = mvm_vmm::host::telemetry_provisioning::record_boot_provisioning(
            req.state_dir,
            spawner::telemetry_for_boot(
                mvm_vmm::host::telemetry_provisioning::telemetry_collection_enabled(),
                req.identity,
            ),
        );
        Ok(SpawnedEndpoint {
            egress_uds: self.uds.clone(),
            identity_drive,
        })
    }
}

/// A `BrokerRegistrar` test double: records the request it saw and returns a
/// defused no-op guard (spawns no broker subprocess). `Mutex` for the
/// `Send + Sync` bound a `VmBackend`'s registrar must satisfy.
pub(super) struct RecordingBrokerRegistrar {
    pub(super) seen: Mutex<Option<RecordedBroker>>,
}

pub(super) struct RecordedBroker {
    pub(super) vm_name: String,
    pub(super) tenant: Option<String>,
    pub(super) broker_listen_socket: Option<PathBuf>,
    pub(super) services: Vec<ServiceId>,
}

impl RecordingBrokerRegistrar {
    pub(super) fn new() -> Self {
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
            services: req.services.to_vec(),
        });
        Ok(BrokerGuard::defused())
    }
}

pub(super) fn service(id: &str) -> ServiceId {
    ServiceId::parse(id.to_string()).unwrap()
}

/// A `ConsoleStreamer` double proving the *wiring*, not re-proving the
/// follower's own polling correctness (that lives, and is tested, in
/// `mvm-hostd::stream::console_source` — the crate this one cannot
/// depend on, which is why the hook exists). Records every `start`/`stop`
/// call, and on `stop` snapshots whatever the console-log path holds at
/// that moment: a real follower's `stop` synchronously drains before
/// returning, so a wired `stop` that runs before the file is read back
/// would show up here as a snapshot missing bytes that were already on
/// disk.
#[derive(Default)]
pub(super) struct RecordingConsoleStreamer {
    pub(super) started: Mutex<Vec<(String, PathBuf)>>,
    /// `ConsoleCapture::supervisor_owned` of each `start`, in call order.
    pub(super) supervisor_owned: Mutex<Vec<bool>>,
    pub(super) stopped: Mutex<Vec<String>>,
    pub(super) captured_at_stop: Mutex<HashMap<String, Vec<u8>>>,
}

impl ConsoleStreamer for RecordingConsoleStreamer {
    fn start(&self, capture: &ConsoleCapture<'_>) {
        self.supervisor_owned
            .lock()
            .unwrap()
            .push(capture.supervisor_owned);
        self.started.lock().unwrap().push((
            capture.vm_name.to_string(),
            capture.console_log.to_path_buf(),
        ));
    }

    fn stop(&self, vm_name: &str) {
        self.stopped.lock().unwrap().push(vm_name.to_string());
        let path = self
            .started
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name == vm_name)
            .map(|(_, path)| path.clone());
        if let Some(path) = path {
            let bytes = std::fs::read(&path).unwrap_or_default();
            self.captured_at_stop
                .lock()
                .unwrap()
                .insert(vm_name.to_string(), bytes);
        }
    }
}

pub(super) fn config(name: &str) -> VmStartConfig {
    VmStartConfig {
        name: name.into(),
        rootfs_path: "/img/rootfs.ext4".into(),
        ..Default::default()
    }
}

// These adapters exercise post-admission mapping with synthetic artifacts,
// not launch authorization. Public entrypoint tests below separately
// exercise refusal and checked-source verification.
pub(super) fn mapping_start<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar>(
    runner: &WorkloadRunner<D, S, B>,
    config: &VmStartConfig,
) -> Result<VmId> {
    let state_dir = vm_state_dir(&config.name);
    std::fs::create_dir_all(&state_dir)?;
    let default_redaction = RedactionPolicy::default();
    let decoded = decode_plan_secrets_from_state(&state_dir)?;
    let (secrets, redaction, tenant): (&[SecretBinding], &RedactionPolicy, &str) = match &decoded {
        Some((secrets, redaction, tenant)) => (secrets.as_slice(), redaction, tenant.as_str()),
        None => (
            &[],
            &default_redaction,
            config.tenant_id.as_deref().unwrap_or("local"),
        ),
    };
    let cmdline = cmdline::runner_cmdline(config, &state_dir, |has_disk| {
        runner.driver.workload_base_bootargs(has_disk)
    });
    runner
        .boot_bound_workload(&WorkloadLaunchInputs {
            config,
            tenant,
            secrets,
            redaction,
            network_policy: &config.network_policy,
            cmdline,
        })
        .map(|vm| vm.id().clone())
}

pub(super) fn checked_source_config(name: &str, rootfs_path: String) -> VmStartConfig {
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let workspace = mvm_build::image_source::guest_runtime_source_checkout()
        .expect("source-channel test checkout");
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
        &cache, &workspace, version, arch,
    )
    .unwrap();
    let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache, version, arch, &runtime,
    )
    .unwrap();
    let initramfs =
        mvm_build::initramfs::build_initramfs_from_guest_runtime(&cache, version, arch, &runtime)
            .unwrap();
    VmStartConfig {
        name: name.into(),
        rootfs_path,
        kernel_path: Some("/img/kernel".into()),
        initrd_path: Some(initramfs.image_path.display().to_string()),
        runtime_overlay_path: Some(overlay.overlay_ext4.display().to_string()),
        runtime_overlay_verity_path: Some(overlay.sidecar.display().to_string()),
        runtime_overlay_roothash: Some(overlay.roothash),
        runtime_overlay_version: Some(version.into()),
        unsigned_runtime_development: true,
        cpus: 1,
        memory_mib: 64,
        ..Default::default()
    }
}

pub(super) fn egress_allowing_policy() -> NetworkPolicy {
    NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)])
}

/// Seed an overlay-aware `mvm-meta.json` sidecar next to a rootfs file in a
/// fresh tempdir and return `(dir, rootfs_path)`. `VmBackend::start`'s
/// admission gate refuses a rootfs whose parent dir carries no overlay-aware
/// sidecar, so every test that drives the full trait method provides one.
/// The returned `TempDir` must stay in scope for the rootfs to exist.
pub(super) fn overlay_aware_rootfs(name: &str) -> (tempfile::TempDir, String) {
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

pub(super) fn spawn_activation_guest(
    driver: MockDriver,
    vm_name: &str,
) -> std::thread::JoinHandle<()> {
    use ed25519_dalek::SigningKey;
    use mvm_agentd::vsock::{AuthenticatedSession, GuestRequest, GuestResponse};

    let host_signer = [7u8; 32];
    let keys_dir = mvm_core::config::mvm_keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(keys_dir.join("host-signer.ed25519"), host_signer).unwrap();
    let vm_id = VmId(vm_name.to_string());

    std::thread::spawn(move || {
        let mut stream = {
            let mut found = None;
            // A loaded full run can delay the runner's connect by many
            // seconds. Giving up early panics this thread while the runner,
            // still unconnected, blocks forever in its handshake read.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while std::time::Instant::now() < deadline {
                if let Some(end) = driver.take_guest_end(&vm_id, GUEST_AGENT_PORT) {
                    found = Some(end);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            found.expect("the runner connected to the guest agent port")
        };
        let host_key = SigningKey::from_bytes(&host_signer).verifying_key();
        let mut session =
            AuthenticatedSession::guest(&mut stream, SigningKey::from_bytes(&[9u8; 32]), &host_key)
                .expect("guest handshake");
        let req: GuestRequest = session.read(&mut stream).expect("read request");
        assert!(
            matches!(req, GuestRequest::ActivateEnvironment(_)),
            "the first post-boot verb must be ActivateEnvironment, got: {req:?}"
        );
        session
            .write(&mut stream, &GuestResponse::ActivateEnvironmentAck)
            .expect("write ack");
    })
}

pub(super) fn launch(runner_cfg: &VmStartConfig) -> WorkloadLaunchInputs<'_> {
    static POLICY: std::sync::OnceLock<NetworkPolicy> = std::sync::OnceLock::new();
    static REDACTION: std::sync::OnceLock<RedactionPolicy> = std::sync::OnceLock::new();
    WorkloadLaunchInputs {
        config: runner_cfg,
        tenant: "local",
        secrets: &[],
        redaction: REDACTION.get_or_init(RedactionPolicy::default),
        network_policy: POLICY.get_or_init(NetworkPolicy::deny_all),
        cmdline: String::new(),
    }
}

/// A pool record for a parent of `rootfs`, booting no guest egress client.
/// Tests that warm a parent *for a launch* go through [`standby_spec_for`]
/// instead, so the record they match on is the one a real spawn would write.
pub(super) fn sample_standby_spec(
    id: &str,
    vm_state_dir: &Path,
    rootfs: &Path,
) -> mvm_core::vm_backend::StandbySpec {
    mvm_core::vm_backend::StandbySpec {
        id: id.to_string(),
        template_id: None,
        kernel_path: "/img/kernel".into(),
        kernel_sha256: "a".repeat(64),
        vcpus: 2,
        mem_mib: 512,
        signing_key_path: "/keys/host-signer.ed25519".into(),
        signer_id: "host:test".into(),
        binding_nonce: "b".repeat(64),
        control_socket: vm_state_dir.join("control.sock").display().to_string(),
        vm_state_dir: vm_state_dir.display().to_string(),
        image_path: Some(rootfs.display().to_string()),
        image_sha256: Some("c".repeat(64)),
        root_strategy: Default::default(),
        vsock_egress: false,
    }
}

/// The pool record a spawn for `launch` would write: the base fixture plus
/// the egress enablement the compat-key builder derives from that launch, so
/// the parent boots the value a claim for the same launch would match on.
pub(super) fn standby_spec_for(
    id: &str,
    vm_state_dir: &Path,
    launch: &VmStartConfig,
) -> mvm_core::vm_backend::StandbySpec {
    mvm_core::vm_backend::StandbySpec {
        vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(launch),
        ..sample_standby_spec(id, vm_state_dir, Path::new(&launch.rootfs_path))
    }
}
