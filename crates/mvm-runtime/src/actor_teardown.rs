//! Original-owner teardown for cold actors. Journal records are observations, never release authority.

use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use mvm_core::vm_backend::{BackendKind, VmId, VmStartConfig};
use mvm_vmm::host::network_endpoint_spawn::{EndpointPid, OwnedEndpoint};
use serde::{Deserialize, Serialize};

mod entrypoint;
mod native;
mod resources;
mod start_failure;
#[cfg(test)]
mod tests;
pub use crate::workload_runner::runner::ActorNoDispatchProof;
pub use entrypoint::{ActorEntrypoint, ActorEntrypointCancel};
pub use native::ActorInstance;
use native::{OriginalExit, OriginalVm};
pub use start_failure::ActorStartFailure;

use crate::backend::AnyBackend;
use crate::driver::RunningVm;
use crate::runtime_evidence::{RuntimeLifecycleLease, VerifiedRuntimeSet};
use crate::workload_runner::runner::{
    BrokerGuard, BrokerRegisterRequest, BrokerRegistrar, NetworkEndpointSpawnRequest,
    NetworkEndpointSpawner, RealNetworkEndpointSpawner, SpawnedEndpoint, WorkloadRunner,
};

/// Original helper returned by the trusted pre-activation holder bootstrap.
#[derive(Debug)]
pub struct ActorBootstrapHelper {
    /// Original child produced by spawn, not a reconstructed PID.
    pub child: Child,
    /// Only private helper sockets/files, not shared durable mailbox storage.
    pub resources: Vec<PathBuf>,
}

/// Consume the once-minted host key before the guest can run its entrypoint.
pub type ActorBootstrap = Box<
    dyn FnOnce(mvm_vmm::host::actor_identity::ActorBootMaterial) -> Result<ActorBootstrapHelper>
        + Send,
>;

pub(crate) type BootstrapHook =
    Box<dyn FnOnce(mvm_vmm::host::actor_identity::ActorBootMaterial) -> Result<()> + Send>;
pub(crate) type FailedVmSlot = Arc<Mutex<Option<Box<dyn RunningVm>>>>;

/// Host-only crash information. Deserialization never reconstructs original custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorTeardownJournal {
    /// Original native generation, not a guest-visible actor handle.
    pub instance: ActorInstance,
    /// Original private runtime directory, never a cleanup permit on recovery.
    pub state: ResourceIdentity,
    /// Separate per-VM socket namespace when long paths require a short directory.
    pub socket_directory: Option<ResourceIdentity>,
    /// All explicitly attached helper processes.
    pub helpers: Vec<HelperIdentity>,
    /// Original children whose resource capture failed; these forbid release proof.
    pub unverified_helpers: Vec<UnverifiedHelperIdentity>,
}

/// An original child retained after a failed pre-Running resource capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedHelperIdentity {
    /// Trusted launch component.
    pub role: String,
    /// Descriptive only; recovery must never signal it.
    pub pid: Option<u32>,
}

/// Descriptive identity of an originally owned child.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperIdentity {
    /// Trusted launch component that supplied this child.
    pub role: String,
    /// Host-local PID, never a signal authority after recovery.
    pub pid: u32,
    /// Native start identity captured before Running.
    pub started: u64,
    /// Exact helper resources captured during launch.
    pub resources: Vec<ResourceIdentity>,
}

/// Original processes exited and captured resources were removed.
///
/// Not serializable, clonable, or publicly constructible. Host lifecycle must
/// durably append its terminal record before releasing a reservation. Dropping
/// this value performs neither operation. A crash without that durable record
/// remains unknown; the journal is not a replacement for this proof.
#[derive(Debug)]
#[must_use = "persist the terminal record before releasing reserved capacity"]
pub struct TerminalProof {
    journal: ActorTeardownJournal,
}

impl TerminalProof {
    /// Exact original generation whose teardown was verified.
    pub fn journal(&self) -> &ActorTeardownJournal {
        &self.journal
    }
}

struct Helper {
    identity: HelperIdentity,
    owner: OwnedEndpoint,
    resources: Vec<ResourceIdentity>,
}

struct QuarantinedChild {
    child: Option<Child>,
    owner: Option<OwnedEndpoint>,
    uncertain: bool,
}

impl QuarantinedChild {
    fn reap(&mut self) -> Result<()> {
        ensure!(!self.uncertain, "quarantined child custody is uncertain");
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(error) => {
                    self.uncertain = true;
                    return Err(error.into());
                }
            }
            self.owner = Some(OwnedEndpoint::adopt(&mut self.child)?);
        }
        if let Some(owner) = &mut self.owner {
            let stopped = owner.shutdown();
            if owner.exit_status().is_none() {
                stopped?;
            }
        }
        Ok(())
    }
}

/// An original native owner plus its explicitly retained support processes.
#[must_use = "retain until stop_and_reap succeeds; dropping is not teardown evidence"]
pub struct ActorOwner {
    vm: Option<OriginalVm>,
    journal: ActorTeardownJournal,
    helpers: Vec<Helper>,
    quarantined: Vec<QuarantinedChild>,
    native_exit: Option<OriginalExit>,
    lifecycle: Option<RuntimeLifecycleLease>,
    state: ResourceIdentity,
    socket_directory: Option<ResourceIdentity>,
    terminal: bool,
    startup_failure: Option<anyhow::Error>,
    entrypoint: entrypoint::DispatchState,
    failed_entrypoint_stream: Option<std::os::unix::net::UnixStream>,
}

impl std::fmt::Debug for ActorOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorOwner")
            .field("vm_id", self.vm_id())
            .field("journal", &self.journal)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl ActorOwner {
    fn original(&self) -> &OriginalVm {
        self.vm
            .as_ref()
            .expect("original actor VM retained until drop")
    }

    /// The host-private VM identity; never embed this in a guest actor handle.
    pub fn vm_id(&self) -> &VmId {
        self.original().id()
    }

    /// Observe the retained original native generation; errors remain unknown.
    pub fn is_running(&self) -> Result<bool> {
        if self.native_exit.is_some() {
            return Ok(false);
        }
        Ok(matches!(
            self.original().status()?,
            mvm_core::vm_backend::VmStatus::Running
        ))
    }

    /// Wait through the original native owner, not a newly attached VM name.
    pub fn wait(&self) -> Result<mvm_core::vm_backend::VmExitStatus> {
        self.original().wait()
    }

    /// Observe original native exit on another thread while this owner retains stop authority.
    ///
    /// Wait on `wait_event` with a deadline. An event is only a wakeup; it never
    /// substitutes for `stop_and_reap` or grants reservation release.
    pub fn exit_observer(&self) -> Result<mvm_vmm::host::process_exit::ProcessExitObserver> {
        self.original().exit_observer()
    }

    /// Snapshot for a host journal before publishing Running.
    pub fn journal(&self) -> ActorTeardownJournal {
        self.journal.clone()
    }

    /// Attach an original spawn result before publishing Running.
    ///
    /// The caller must retain exclusive child reaping custody. Resources must
    /// name only this helper's private files/sockets, never shared mailbox storage.
    /// The child is always taken, including on failure. Failed capture leaves
    /// quarantined original custody in this owner and permanently forbids proof.
    pub fn attach_helper(
        &mut self,
        role: &str,
        child: &mut Option<Child>,
        resources: &[PathBuf],
    ) -> Result<()> {
        let mut original = child.take();
        let captured = (|| {
            ensure!(self.native_exit.is_none(), "actor teardown already started");
            capture_helper(role, &mut original, resources)
        })();
        match captured {
            Ok(helper) => {
                self.journal.helpers.push(helper.identity.clone());
                self.helpers.push(helper);
                Ok(())
            }
            Err(error) => {
                self.terminal = false;
                self.journal
                    .unverified_helpers
                    .push(UnverifiedHelperIdentity {
                        role: role.into(),
                        pid: original.as_ref().map(Child::id),
                    });
                if let Some(child) = original {
                    self.quarantined.push(QuarantinedChild {
                        child: Some(child),
                        owner: None,
                        uncertain: false,
                    });
                }
                Err(error)
            }
        }
    }

    /// Stop only the original native owner, then reap every original helper.
    ///
    /// Errors retain all remaining custody and prevent terminal proof. No PID
    /// marker is consulted and no recovered numeric PID is signalled.
    pub fn stop_and_reap(&mut self) -> Result<TerminalProof> {
        if self.terminal {
            return Ok(TerminalProof {
                journal: self.journal.clone(),
            });
        }
        if self.native_exit.is_none() {
            let proof = self.original().stop()?;
            ensure!(
                proof.identity() == self.journal.instance,
                "native teardown returned another generation"
            );
            self.native_exit = Some(proof);
        }
        reap_helpers(&mut self.helpers)?;
        if let Some(error) = &self.startup_failure
            && let Some(failure) =
                error.downcast_ref::<mvm_vmm::host::retained_spawn::RetainedSpawnFailure>()
        {
            failure.retry_stop()?;
        }
        for child in &mut self.quarantined {
            child.reap()?;
        }
        ensure!(
            self.journal.unverified_helpers.is_empty(),
            "helper resource capture is unverified; teardown remains unknown"
        );
        let proof = self.native_exit.as_ref().context("native exit missing")?;
        self.failed_entrypoint_stream = None;
        let lifecycle = self
            .lifecycle
            .as_ref()
            .expect("actor lifecycle retained until drop");
        proof.release_kernel(lifecycle)?;
        lifecycle.release_installed_bundle_after_stop(&self.vm_id().0)?;
        remove_helper_resources(&self.helpers)?;
        if let Some(directory) = &self.socket_directory {
            directory.remove()?;
        }
        self.state.remove()?;
        self.terminal = true;
        Ok(TerminalProof {
            journal: self.journal.clone(),
        })
    }
}

impl Drop for ActorOwner {
    fn drop(&mut self) {
        if !self.terminal {
            // Drop cannot establish terminal evidence or dispose of uncertain custody.
            std::mem::forget(self.vm.take());
            std::mem::forget(self.lifecycle.take());
            std::mem::forget(std::mem::take(&mut self.helpers));
            std::mem::forget(std::mem::take(&mut self.quarantined));
        }
    }
}

fn reap_helpers(helpers: &mut [Helper]) -> Result<()> {
    for helper in helpers {
        let stopped = helper.owner.shutdown();
        // An unsuccessful helper exit still proves death, not successful work.
        if helper.owner.exit_status().is_none() {
            stopped.context("original helper exit remains unknown")?;
            anyhow::bail!("helper stop returned without an original exit status");
        }
    }
    Ok(())
}

fn remove_helper_resources(helpers: &[Helper]) -> Result<()> {
    for helper in helpers {
        for resource in &helper.resources {
            resource.remove()?;
        }
    }
    Ok(())
}

/// Refuse a backend without an original-owner actor teardown implementation.
pub fn supports_actor_backend(backend: &AnyBackend) -> Result<()> {
    #[cfg(feature = "test-support")]
    if matches!(backend, AnyBackend::Mock(_)) {
        return Ok(());
    }
    ensure!(
        cfg!(target_os = "macos") && backend.kind() == BackendKind::Hvf,
        "actor teardown requires original cold macOS HVF custody"
    );
    mvm_vmm::host::process_exit::require_owned_child_custody()?;
    Ok(())
}

/// Check unsupported helper modes before any workload process is created.
pub fn require_actor_teardown(backend: &AnyBackend, config: &VmStartConfig) -> Result<()> {
    supports_actor_backend(backend)?;
    ensure!(!config.gpu, "actor GPU helper ownership is unsupported");
    validate_actor_routes(&config.service_proxies)?;
    if !config.service_proxies.is_empty() {
        let (services, capabilities, _) =
            crate::workload_runner::runner::admitted_broker_bindings(config.plan_json.as_deref())?;
        for route in &config.service_proxies {
            ensure!(
                services.contains(&route.service)
                    && route
                        .capabilities
                        .iter()
                        .all(|descriptor| capabilities.contains(&descriptor.binding())),
                "actor route exceeds the admitted service bindings"
            );
        }
    }
    Ok(())
}

impl AnyBackend {
    /// Use the ordinary runner start and admission durability barriers, retaining custody.
    ///
    /// This is a runtime dispatch operation, not an admission bypass. The host
    /// admission owner must finish its usual grants, charge, and mailbox steps.
    pub fn start_owned_actor(
        &self,
        config: &VmStartConfig,
        runtime: Option<&VerifiedRuntimeSet>,
    ) -> Result<ActorOwner> {
        self.start_owned_actor_with_bootstrap(config, runtime, None)
    }

    /// Install a holder bootstrap consumer on the same ordinary cold launch path.
    pub fn start_owned_actor_with_bootstrap(
        &self,
        config: &VmStartConfig,
        runtime: Option<&VerifiedRuntimeSet>,
        bootstrap: Option<ActorBootstrap>,
    ) -> Result<ActorOwner> {
        let helpers = Arc::new(Mutex::new(Vec::new()));
        let failed_vm = Arc::new(Mutex::new(None));
        let mut runner = WorkloadRunner::new(
            mvm_backends::driver::hvf::HvfDriver::new(),
            ActorSpawner(Arc::clone(&helpers)),
            ActorBroker(Arc::clone(&helpers)),
        )
        .with_actor_custody(Arc::clone(&failed_vm));
        require_actor_teardown(self, config).map_err(|error| {
            ActorStartFailure::before_dispatch(error, runner.no_dispatch_proof(config))
        })?;
        #[cfg(feature = "test-support")]
        if let Self::Mock(backend) = self {
            ensure!(
                runtime.is_none() && bootstrap.is_none(),
                "mock actor cannot claim native bootstrap or runtime custody"
            );
            return native::start_mock(backend, config);
        }
        let prepared = (|| {
            if let Some(runtime) = runtime {
                runtime.verify_config(config)?;
            }
            let needs_holder = config
                .plan_json
                .as_deref()
                .map(mvm_core::plan::plan_from_admitted_json)
                .transpose()?
                .is_some_and(|plan| {
                    plan.services
                        .iter()
                        .any(|service| service.as_str() == "host.actor.v1")
                });
            ensure!(
                needs_holder == bootstrap.is_some(),
                "actor holder bootstrap must exactly match the admitted controller service"
            );
            let state_dir = mvm_core::config::vm_state_dir(&config.name);
            std::fs::create_dir_all(&state_dir)?;
            let state = ResourceIdentity::capture(&state_dir)?;
            mvm_core::config::secure_fallback_socket_dir_at(&state_dir)?;
            let socket_path = mvm_core::config::vm_socket_dir_at(&state_dir);
            let socket_directory = (socket_path != state_dir)
                .then(|| ResourceIdentity::capture(&socket_path))
                .transpose()?;
            Ok((state, socket_directory))
        })();
        let (state, socket_directory) = prepared.map_err(|error| {
            ActorStartFailure::before_dispatch(error, runner.no_dispatch_proof(config))
        })?;
        if let Some(bootstrap) = bootstrap {
            let custody = Arc::clone(&helpers);
            runner = runner.with_actor_bootstrap(Box::new(move |material| {
                let spawned = bootstrap(material)?;
                let helper =
                    capture_spawned_helper("actor-holder", spawned.child, &spawned.resources)?;
                custody
                    .lock()
                    .expect("actor helper custody poisoned")
                    .push(helper);
                Ok(())
            }));
        }
        let started =
            runner.start_retaining_vm(config, Vec::new(), runtime.map(VerifiedRuntimeSet::release));
        let (vm, result) = match started {
            Ok(vm) => (Some(vm), Ok(())),
            Err(error) => (
                failed_vm
                    .lock()
                    .expect("original actor VM custody poisoned")
                    .take(),
                Err(error),
            ),
        };
        start_failure::finish(
            start_failure::PendingStart {
                vm: vm.map(OriginalVm::Hvf),
                helpers,
                state,
                socket_directory,
                name: config.name.clone(),
                no_dispatch: runner.no_dispatch_proof(config),
            },
            result,
        )
    }
}

fn capture_helper(role: &str, child: &mut Option<Child>, paths: &[PathBuf]) -> Result<Helper> {
    let pid = child
        .as_ref()
        .context("original helper child missing")?
        .id();
    let identity = EndpointPid::of_child(pid);
    let started = identity
        .started
        .context("original helper start identity unavailable")?;
    let resources = paths
        .iter()
        .map(|path| ResourceIdentity::capture(path))
        .collect::<Result<Vec<_>>>()?;
    let owner = OwnedEndpoint::adopt(child)?;
    Ok(Helper {
        identity: HelperIdentity {
            role: role.into(),
            pid,
            started,
            resources: resources.clone(),
        },
        owner,
        resources,
    })
}

fn capture_spawned_helper(role: &str, child: Child, paths: &[PathBuf]) -> Result<Helper> {
    let mut child = Some(child);
    match capture_helper(role, &mut child, paths) {
        Ok(helper) => Ok(helper),
        Err(error) => match child {
            Some(child) => Err(mvm_vmm::host::retained_spawn::rollback(error, child)),
            None => Err(error),
        },
    }
}

type Helpers = Arc<Mutex<Vec<Helper>>>;
struct ActorSpawner(Helpers);

impl NetworkEndpointSpawner for ActorSpawner {
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        RealNetworkEndpointSpawner.prepare_identity(req)
    }

    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        let (endpoint, child) = RealNetworkEndpointSpawner.spawn_actor_retained(req)?;
        let helper = capture_spawned_helper(
            "network-endpoint",
            child,
            std::slice::from_ref(&endpoint.egress_uds),
        )?;
        self.0
            .lock()
            .expect("actor helper custody poisoned")
            .push(helper);
        Ok(endpoint)
    }
}

struct ActorBroker(Helpers);

impl BrokerRegistrar for ActorBroker {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        use mvm_vmm::host::broker_services_spawn as spawn;
        validate_actor_routes(req.service_proxies)?;
        if req.services.is_empty() {
            return Ok(BrokerGuard::from_services_guard(
                mvm_vmm::host::host_agent_spawn::ServicesGuard::None,
            ));
        }
        let tenant = req.tenant.context("actor broker has no admitted tenant")?;
        let socket = req
            .broker_listen_socket
            .context("actor broker socket missing")?;
        let audit = spawn::spawn_audit_signer(spawn::AuditSignerSpawnParams {
            workload_id: req.vm_name,
            tenant_id: tenant,
            vm_name: req.vm_name,
            state_dir: req.state_dir,
            epoch: req.epoch,
        })?;
        let helper = capture_spawned_helper(
            "audit-signer",
            audit.child,
            std::slice::from_ref(&audit.uds_path),
        )?;
        self.0
            .lock()
            .expect("actor helper custody poisoned")
            .push(helper);
        let broker = spawn::spawn_broker_with_actor_routes(
            spawn::BrokerSpawnParams {
                workload_id: req.vm_name,
                tenant_id: tenant,
                broker_uds_path: socket,
                state_dir: req.state_dir,
                audit_signer_uds_path: &audit.uds_path,
                services: req.services,
                capability_bindings: req.capability_bindings,
                service_proxies: req.service_proxies,
                epoch: req.epoch,
            },
            req.service_proxies,
        )?;
        let helper = capture_spawned_helper("broker", broker.child, &[broker.uds_path])?;
        self.0
            .lock()
            .expect("actor helper custody poisoned")
            .push(helper);
        Ok(BrokerGuard::from_services_guard(
            mvm_vmm::host::host_agent_spawn::ServicesGuard::Fork(
                spawn::BrokerServicesGuard::defused(),
            ),
        ))
    }
}

fn validate_actor_routes(
    routes: &[mvm_contract::protocol::broker_control::ServiceProxyBinding],
) -> Result<()> {
    ensure!(
        routes.len() <= 1,
        "actor launch accepts at most one original holder route"
    );
    for route in routes {
        ensure!(
            route.service.as_str() == "host.actor.v1",
            "actor service-proxy teardown is unsupported"
        );
        route.validate().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// The original directory entry, not a path that may have been replaced since launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    directory: bool,
    socket: bool,
}

impl ResourceIdentity {
    fn capture(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "actor resource is a symlink"
        );
        Ok(Self {
            path: path.into(),
            device: meta.dev(),
            inode: meta.ino(),
            directory: meta.is_dir(),
            socket: meta.file_type().is_socket(),
        })
    }

    fn verify_metadata(&self, meta: &std::fs::Metadata) -> Result<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        ensure!(
            !meta.file_type().is_symlink()
                && meta.dev() == self.device
                && meta.ino() == self.inode
                && meta.is_dir() == self.directory
                && meta.file_type().is_socket() == self.socket,
            "actor resource identity changed: {}",
            self.path.display()
        );
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        self.verify_metadata(&meta)?;
        if self.directory {
            std::fs::remove_dir_all(&self.path)?;
        } else {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}
