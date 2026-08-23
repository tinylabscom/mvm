//! Persistent + transient launch lifecycle through [`LocalBackend`].
//!
//! Both modes route through the one canonical admitted-boot seam
//! (`mvm_hostd::run::admit_and_boot_local`): the plan is synthesized, signed,
//! verified, window-checked, replay-checked, and chain-audited before the
//! backend sees a byte of launch config. Volume attachments resolve through
//! the local volume service (exclusive leases, RAII rollback on a failed
//! boot) and typed secret references are validated fail-closed and recorded
//! as metadata-only sidecars before any boot.

mod request;
#[cfg(test)]
mod tests;

pub use request::{
    AccessMode, LaunchNetworkPolicy, LaunchRequest, LaunchRequestBuilder, LaunchVolumeSpec,
    LifecycleMode, MachineSecretRef,
};

use std::path::PathBuf;
use std::sync::Arc;

use mvm_core::client::dto::{MachineId, MachineState, MachineStatus};
use mvm_core::client::{MvmError, Result};
use mvm_core::config::{machine_spec_path, machine_state_dir, machine_state_root, vm_state_dir};
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::plan::ExecutionPlan;
use mvm_core::protocol::vm_backend::{VmId, VmStatus};
use mvm_core::rootfs_source::RootfsSource;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::plan_admission::{InMemoryNonceLedger, StartedMachine, SystemClock};
use mvm_hostd::run::{LocalRunContext, LocalRunRequest, admit_and_boot_local};
use mvm_runtime::AnyBackend;
use mvm_runtime::machine::persist as mp;

use crate::local::LocalBackend;
use crate::registration::{MachineRegistration, register_machine};
use crate::secret::SecretService;
use crate::volume::{
    AdmittedProfile, AttachmentRequest, LaunchLeaseRequest, LocalVolumeService, UnlockPolicy,
    VolumeService,
};

/// The tenant every locally-launched machine is admitted and scoped under —
/// mirrors the admission seam's fixed local tenant label.
const LOCAL_TENANT: &str = "local";

/// The result of a successful launch: the machine's observed state plus the
/// admitted plan identity (for correlation with the chain-signed audit log).
#[derive(Debug)]
pub struct LaunchOutcome {
    pub machine: MachineState,
    /// Content-addressed id of the admitted plan.
    pub plan_id: String,
    pub(crate) mode: LifecycleMode,
    pub(crate) plan: ExecutionPlan,
}

/// Exit report for a waited-on transient machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitReport {
    /// Captured workload exit code, when the guest reported one before
    /// shutdown; `None` when no capture exists (e.g. the hermetic mock).
    pub exit_code: Option<i32>,
}

/// Options for [`LocalBackend::remove_machine_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoveOptions {
    /// Explicitly requested force flow: stop a RUNNING persistent machine
    /// before removal. Without it, removing a running persistent machine is
    /// refused.
    pub force: bool,
}

/// Generate a name for a nameless transient launch.
fn generated_transient_name() -> String {
    let n: u64 = rand::random();
    format!("transient-{:012x}", n & 0xffff_ffff_ffff)
}

/// RFC 3339 expiry timestamp `ttl_seconds` from now, or `None`.
fn expires_at_from_ttl(ttl_seconds: Option<u64>) -> Option<String> {
    ttl_seconds
        .map(|secs| (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339())
}

/// Best-effort chain-signed emitter under the host signer. Audit emission is
/// tamper-evidence, not part of the admission decision: a construction
/// failure warns and the boot proceeds unaudited-on-chain (CLI parity).
fn build_audit_emitter() -> Option<AuditEmitter> {
    let signer = match mvm_hostd::audit::host_keypair::load_or_init() {
        Ok(signer) => signer,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; skipping chain audit emission");
            return None;
        }
    };
    match AuditEmitter::new(signer.signing) {
        Ok(emitter) => Some(emitter.with_receipts()),
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; skipping chain audit emission");
            None
        }
    }
}

impl LocalBackend {
    /// The secret lifecycle service to validate/record references through:
    /// the injected one, else the production-wired local service.
    fn secrets(&self) -> Result<Arc<SecretService>> {
        if let Some(service) = &self.secret_service {
            return Ok(service.clone());
        }
        SecretService::local()
            .map(Arc::new)
            .map_err(|e| crate::local::backend_err(format!("secret service: {e}")))
    }

    /// Clear a machine's secret-reference sidecar through the same seam
    /// [`SecretService::clear_machine_references`] wraps. Idempotent.
    fn clear_secret_refs(&self, name: &str) -> Result<()> {
        match &self.secret_service {
            Some(service) => service
                .clear_machine_references(name)
                .map_err(|e| crate::local::backend_err(format!("clearing secret refs: {e}"))),
            None => crate::secret::refs::clear_refs(&machine_state_root(), name)
                .map_err(|e| crate::local::backend_err(format!("clearing secret refs: {e:#}"))),
        }
    }

    /// Whether `name` is running: prefer the VMM that owns the started VM
    /// (state-dir marker), falling back to this client's backend so the
    /// hermetic mock stays observable.
    fn machine_running(&self, name: &str) -> bool {
        let status = match AnyBackend::for_started_vm(name) {
            Some(owner) => owner.status(&VmId(name.to_string())),
            None => self.backend.status(&VmId(name.to_string())),
        };
        matches!(status, Ok(VmStatus::Running))
    }

    /// Resolve the backend handle for a launch: the request override when it
    /// names a different hypervisor (validated selectable), else this
    /// client's own backend.
    fn launch_backend(&self, override_name: Option<&str>) -> Result<BackendHandle<'_>> {
        match override_name {
            Some(name) if name != self.backend.name() => {
                crate::boot::require_hypervisor_selectable(name)?;
                Ok(BackendHandle::Owned(AnyBackend::from_hypervisor(name)))
            }
            _ => Ok(BackendHandle::Borrowed(&self.backend)),
        }
    }
}

/// A borrowed-or-owned backend handle (`AnyBackend` is not `Clone`, so `Cow`
/// can't carry it). Borrowing the client's own backend keeps the hermetic
/// in-memory mock observable across the launch verbs.
enum BackendHandle<'a> {
    Borrowed(&'a AnyBackend),
    Owned(AnyBackend),
}

impl std::ops::Deref for BackendHandle<'_> {
    type Target = AnyBackend;

    fn deref(&self) -> &AnyBackend {
        match self {
            BackendHandle::Borrowed(backend) => backend,
            BackendHandle::Owned(backend) => backend,
        }
    }
}

/// The resolved inputs for one admitted boot — the shared core both
/// lifecycle modes (and the trait's `run_machine`) reach.
pub(crate) struct BootParams {
    pub(crate) name: String,
    pub(crate) image: RootfsSource,
    pub(crate) cpus: u32,
    pub(crate) memory_mib: u32,
    pub(crate) backend_override: Option<String>,
    pub(crate) volumes: Vec<mvm_core::vm_backend::VmVolume>,
    pub(crate) transient: bool,
    /// The request's permission set, carried into the signed plan and — for
    /// its egress dimension — into the policy the gate enforces.
    pub(crate) grants: Option<mvm_contract::grants::Grants>,
    /// Path to an operator-authored campaign declaration, when one was asked
    /// for. Read and validated here, so a malformed declaration refuses the
    /// launch instead of producing a boot with no campaign on it.
    pub(crate) assurance_campaign: Option<std::path::PathBuf>,
}

impl LocalBackend {
    /// Resolve the per-backend workload kernel: every explicit-kernel backend
    /// boots a verified kernel from the CLI-populated cache; bundled-kernel
    /// backends carry their own.
    ///
    /// One arm serves all of them. Firecracker and the qemu dev tier used to
    /// take a separate branch that accepted the cache path on `is_file()`, so
    /// the backend that carries real workloads on Linux booted whatever sat at
    /// the expected filename while HVF next door required a digest match.
    pub(crate) fn resolve_workload_kernel(backend: &AnyBackend) -> Result<Option<PathBuf>> {
        use mvm_core::protocol::vm_backend::BackendKind;
        let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let arch = mvm_core::arch::GuestArch::host().to_string();
        match backend.kind() {
            // Bundled-kernel backends: libkrun boots the libkrunfw kernel and
            // the hermetic mock boots nothing — no host kernel path needed.
            BackendKind::Mock | BackendKind::Libkrun => Ok(None),
            // Cache-hit-or-error; populating the cache is a CLI concern. A hit
            // means the bytes matched their recorded digest, and an entry that
            // fails to verify is evicted by the resolve — so the hint below is
            // the right next step for a rejected kernel as much as a missing
            // one.
            _ => match mvm_build::kernel_fetch::resolve_kernel(&cache, &arch, "workload", false) {
                mvm_build::kernel_fetch::KernelResolution::Cached(verified) => {
                    Ok(Some(verified.path().to_path_buf()))
                }
                _ => Err(crate::local::backend_err(format!(
                    "{} needs a verified workload kernel at {} — create it once with \
                     `mvmctl kernel build --which workload`, then retry",
                    backend.name(),
                    mvm_build::kernel_fetch::cached_kernel_path(&cache, &arch, "workload")
                        .display()
                ))),
            },
        }
    }

    /// Boot one machine through the canonical signed-plan admission seam.
    /// The chain-signed `plan.admitted`/`plan.launched`/`plan.failed`
    /// entries are emitted inside the seam; any failure returns with no VM
    /// created.
    pub(crate) async fn boot_admitted(&self, params: BootParams) -> Result<StartedMachine> {
        let backend = self.launch_backend(params.backend_override.as_deref())?;
        // Crash/unclean-stop leftovers in the per-VM runtime dir (notably a
        // stale substitution-endpoint socket) make the fresh endpoint die
        // binding it before its ready handshake; a non-running machine owns
        // no live state there, so recover by starting from an empty dir.
        if !self.machine_running(&params.name) {
            remove_dir_if_present(&vm_state_dir(&params.name))?;
        }
        let rootfs = crate::local::resolve_local_rootfs(&params.image, &params.name).await?;
        let (verity_path, roothash) = crate::local::host_verity_sidecars(&rootfs);
        let kernel_path = Self::resolve_workload_kernel(&backend)?;

        let req = LocalRunRequest {
            name: params.name.clone(),
            rootfs_path: rootfs,
            kernel_path,
            verity_path: verity_path.map(PathBuf::from),
            roothash,
            cpus: params.cpus,
            mem_mib: params.memory_mib,
            backend_name: backend.name().to_string(),
            volumes: params.volumes,
            destroy_on_exit: params.transient,
            grants: params.grants.clone(),
        };

        // A fresh per-launch ledger: local launches are one-shot from this
        // process, so replay protection spans this admission (the CLI uses
        // the same per-invocation shape). Keys dir `None` → the host signer
        // at the configured keys dir.
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let emitter = build_audit_emitter().map(std::sync::Arc::new);

        // Read the declaration before the boot: a campaign an operator asked
        // for and that turns out to be malformed must refuse the launch, not
        // produce a running workload with no campaign attached to it.
        let campaign = match (&params.assurance_campaign, &emitter) {
            (Some(path), Some(emitter)) => Some(
                Self::build_campaign(path, emitter, &backend, params.grants.as_ref())
                    .map_err(|e| crate::local::backend_err(format!("{e:#}")))?,
            ),
            (Some(_), None) => {
                return Err(crate::local::backend_err(
                    "an assurance campaign was declared but this process writes no audit chain, \
                     so nothing the campaign did could be recorded"
                        .to_string(),
                ));
            }
            (None, _) => None,
        };

        admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: None,
                emitter: emitter.as_deref(),
                assurance: campaign.as_ref(),
            },
        )
        .map_err(|e| crate::local::backend_err(format!("{e:#}")))
    }

    /// Load a declared campaign and bind it to this boot.
    ///
    /// The policy handed to the probe is the one the launch was granted, so a
    /// probe asks the same question the workload's own egress would: an
    /// operator cannot widen what a campaign observes by writing a different
    /// policy into the declaration, because the declaration carries none.
    fn build_campaign(
        path: &std::path::Path,
        emitter: &std::sync::Arc<AuditEmitter>,
        backend: &AnyBackend,
        grants: Option<&mvm_contract::grants::Grants>,
    ) -> anyhow::Result<mvm_hostd::assurance_session::CampaignRequest> {
        let declaration = mvm_hostd::assurance_session::load_declaration(path)?;
        // The policy handed to the probe is the launch's own granted egress, so
        // a probe asks exactly the question the workload's traffic would. A
        // declaration carries no policy of its own, so an operator cannot widen
        // what a campaign observes by writing one.
        let policy = grants
            .and_then(|g| g.egress.as_ref())
            .map(|egress| {
                mvm_core::policy::network_policy::NetworkPolicy::allow_list(egress.allow.clone())
            })
            .unwrap_or_else(mvm_core::policy::network_policy::NetworkPolicy::deny_all);
        Ok(mvm_hostd::assurance_session::CampaignRequest {
            declaration,
            emitter: std::sync::Arc::clone(emitter),
            policy_ceiling: mvm_hostd::assurance_session::default_policy_ceiling(),
            policy,
            backend: format!("{:?}", backend.kind()).to_lowercase(),
            now_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
        })
    }

    /// Fail-closed admission validation of typed secret references, then
    /// persist the metadata-only sidecar. Runs on every admission that
    /// declares references; a machine with any invalid reference must not
    /// boot (and nothing is recorded for it).
    fn validate_and_record_secret_refs(&self, name: &str, refs: &[MachineSecretRef]) -> Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let service = self.secrets()?;
        service
            .validate_for_admission(LOCAL_TENANT, refs)
            .map_err(|e| MvmError::Rejected {
                reason: format!("secret reference admission refused: {e}"),
            })?;
        service
            .record_machine_references(name, refs)
            .map_err(|e| crate::local::backend_err(format!("recording secret refs: {e}")))
    }

    /// Register the request's typed volume attachments for `name`. An
    /// identical existing registration is reused; a guest path already
    /// claimed by a different volume/access is a conflict.
    fn register_volume_attachments(
        &self,
        name: &str,
        volumes: &[LaunchVolumeSpec],
        profile: AdmittedProfile,
    ) -> Result<()> {
        if volumes.is_empty() {
            return Ok(());
        }
        let service = LocalVolumeService::new();
        let existing = service
            .list_attachments(name)
            .map_err(|e| crate::local::backend_err(format!("listing attachments: {e:#}")))?;
        for spec in volumes {
            let identical = existing.iter().any(|a| {
                a.guest_path == spec.guest_path
                    && a.volume == spec.volume
                    && a.access == spec.access
            });
            if identical {
                continue;
            }
            if existing.iter().any(|a| a.guest_path == spec.guest_path) {
                return Err(MvmError::Conflict {
                    reason: format!(
                        "guest path {:?} is already attached with a different volume or \
                         access mode; detach it first",
                        spec.guest_path
                    ),
                });
            }
            let request = AttachmentRequest::builder(name, &spec.volume)
                .and_then(|b| {
                    b.guest_path(&spec.guest_path)
                        .access(spec.access)
                        .profile(profile)
                        .build()
                })
                .map_err(|e| MvmError::InvalidSpec {
                    reason: format!("volume attachment {:?}: {e:#}", spec.volume),
                })?;
            service.prepare_attachment(&request).map_err(|e| {
                crate::local::backend_err(format!("attaching {:?}: {e:#}", spec.volume))
            })?;
        }
        Ok(())
    }

    /// Resolve `name`'s registered attachments and take exclusive leases for
    /// this launch (locked managed volumes unlock just in time and re-seal
    /// on release).
    fn acquire_leases(
        &self,
        name: &str,
        profile: AdmittedProfile,
    ) -> Result<crate::volume::LaunchPreparation> {
        let request = LaunchLeaseRequest::builder(name)
            .map_err(|e| MvmError::InvalidSpec {
                reason: format!("{e:#}"),
            })?
            .profile(profile)
            .unlock(UnlockPolicy::JustInTime)
            .build();
        LocalVolumeService::new()
            .acquire_launch_lease(&request)
            .map_err(|e| crate::local::backend_err(format!("volume leases for {name:?}: {e:#}")))
    }
}

/// Rebuild the launch request for a persistent start from the stored
/// definition.
///
/// Every field a start needs comes from the spec, `grants` included. A start
/// that reassembled the request from sizing alone would let a permission set
/// hold for the machine's first boot and lapse on every one after — deny-all
/// for egress, and simply unbounded for CPU and wall clock. Split out from
/// `start_persistent` so that is checkable without booting a VM.
fn start_request_from_spec(
    name: &str,
    image: RootfsSource,
    memory_mib: u32,
    spec: &mp::MachineSpec,
) -> Result<LaunchRequest> {
    let mut builder = LaunchRequest::builder(LifecycleMode::Persistent, image)
        .name(name)
        .cpus(spec.cpus)
        .memory_mib(memory_mib)
        .profile(spec.profile.clone());
    if let Some(grants) = spec.grants.clone() {
        builder = builder.grants(grants);
    }
    builder.build()
}

/// Build the persisted declarative spec a persistent launch writes.
fn persisted_spec_from_request(request: &LaunchRequest, name: &str) -> mp::MachineSpec {
    mp::MachineSpec {
        schema_version: mp::MACHINE_SPEC_SCHEMA_VERSION,
        name: name.to_string(),
        // The persisted record carries the written form — the same token the
        // caller declared, so a spec read back reconstructs the same value.
        image: Some(request.image.to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: vec![],
        ai: None,
        ports: vec![],
        cpus: request.cpus,
        memory: format!("{}M", request.memory_mib),
        mem_initial: None,
        profile: request.profile.clone(),
        volumes: vec![],
        init: vec![],
        agent_verb: vec![],
        created_at: Some(mvm_core::util::time::utc_now()),
        last_started_at: None,
        health_check: None,
        // The permission set the launch was admitted under, so a later
        // `start` by name re-admits under the same bounds.
        grants: request.grants.clone(),
    }
}

impl LocalBackend {
    /// Refuse a transient launch whose name is already claimed — by a
    /// persisted definition (that name is managed via the persistent verbs)
    /// or by a live VM.
    fn ensure_transient_name_free(&self, name: &str) -> Result<()> {
        if machine_spec_path(name).exists() {
            return Err(MvmError::Conflict {
                reason: format!(
                    "a persistent machine named {name:?} exists; use the persistent \
                     lifecycle verbs (or another name)"
                ),
            });
        }
        if self.machine_running(name) {
            return Err(MvmError::Conflict {
                reason: format!("a machine named {name:?} is already running"),
            });
        }
        Ok(())
    }

    /// Reconcile + persist the declarative definition for a persistent
    /// launch. A same-config definition is reused; a different config is
    /// refused without `force` and recreated (stopping any old instance)
    /// with it. Never boots.
    fn persist_definition(&self, request: &LaunchRequest, name: &str) -> Result<mp::MachineSpec> {
        let desired = persisted_spec_from_request(request, name);
        let existing = if machine_spec_path(name).exists() {
            Some(mp::load_machine_spec(name).map_err(crate::local::backend_err)?)
        } else {
            None
        };
        let reconcile = mp::reconcile_machine_spec(existing.as_ref(), &desired, request.force)
            .map_err(|e| MvmError::Conflict {
                reason: format!("{e:#}"),
            })?;
        match reconcile {
            mp::SpecReconcile::Create => {
                mp::save_machine_spec(&desired, false).map_err(crate::local::backend_err)?;
                mvm_core::audit_emit!(ConfigChange, vm: name, "action=machine.create mode=persistent");
                Ok(desired)
            }
            mp::SpecReconcile::Reuse => Ok(existing.expect("reuse implies an existing spec")),
            mp::SpecReconcile::Recreate { changed } => {
                if self.machine_running(name) {
                    self.stop_for_recreate(name);
                }
                mp::overwrite_machine_spec(&desired).map_err(crate::local::backend_err)?;
                mvm_core::audit_emit!(
                    ConfigChange,
                    vm: name,
                    "action=machine.recreate changed={changed}"
                );
                Ok(desired)
            }
        }
    }

    /// Stop the old instance ahead of a forced recreate. Best-effort: the
    /// overwrite proceeds either way and the boot surfaces any leftover.
    fn stop_for_recreate(&self, name: &str) {
        let vid = VmId(name.to_string());
        let result = match AnyBackend::for_started_vm(name) {
            Some(owner) => owner.stop(&vid),
            None => self.backend.stop(&vid),
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, machine = name, "stopping old instance before recreate failed");
        }
    }

    /// Launch a machine from a fully-validated typed request. Transient
    /// requests boot immediately and are cleaned up on exit/TTL; persistent
    /// requests persist their definition first, then boot from it — both
    /// through the one canonical signed-admission seam.
    pub async fn launch(&self, request: LaunchRequest) -> Result<LaunchOutcome> {
        match request.mode {
            LifecycleMode::Transient => self.launch_transient(request).await,
            LifecycleMode::Persistent => {
                let name = request
                    .name
                    .clone()
                    .expect("validated: persistent requests carry a name");
                self.create_definition(&request, &name)?;
                self.boot_persistent(&name, &request).await
            }
        }
    }

    /// Persist a machine definition (spec + secret-reference sidecar +
    /// typed volume attachments) without booting. Persistent mode only.
    pub fn create_from_request(&self, request: &LaunchRequest) -> Result<MachineState> {
        if request.mode != LifecycleMode::Persistent {
            return Err(MvmError::InvalidSpec {
                reason: "create (persist without boot) requires a persistent request".into(),
            });
        }
        let name = request
            .name
            .clone()
            .expect("validated: persistent requests carry a name");
        let spec = self.create_definition(request, &name)?;
        Ok(MachineState {
            id: MachineId(name.clone()),
            name,
            status: MachineStatus::Stopped,
            cpus: spec.cpus,
            memory_mib: request.memory_mib,
            profile: Some(spec.profile),
            ..Default::default()
        })
    }

    /// The persistent create path: reconcile + persist the spec, validate +
    /// record secret references, register typed volume attachments.
    fn create_definition(&self, request: &LaunchRequest, name: &str) -> Result<mp::MachineSpec> {
        let spec = self.persist_definition(request, name)?;
        self.validate_and_record_secret_refs(name, &request.secret_refs)?;
        self.register_volume_attachments(
            name,
            &request.volumes,
            AdmittedProfile::from_profile_name(&request.profile),
        )?;
        Ok(spec)
    }

    /// The transient launch path: collision check, secret-ref validation +
    /// recording, attachment registration, lease acquisition, admitted boot,
    /// registration. Any failure after recording rolls the session-owned
    /// state back (leases via RAII, secret refs + attachments explicitly).
    #[tracing::instrument(skip_all)]
    async fn launch_transient(&self, request: LaunchRequest) -> Result<LaunchOutcome> {
        let name = request
            .name
            .clone()
            .unwrap_or_else(generated_transient_name);
        self.ensure_transient_name_free(&name)?;
        self.validate_and_record_secret_refs(&name, &request.secret_refs)?;

        let result = self.attach_lease_and_boot(&name, &request, true).await;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                // Idempotent rollback of everything this session recorded.
                if let Err(cleanup) = self.cleanup_transient(&name) {
                    tracing::warn!(error = %cleanup, machine = %name, "transient cleanup after failed launch");
                }
                Err(e)
            }
        }
    }

    /// Boot a persistent definition that was just created/reconciled from
    /// `request` (TTL and backend override honored from the request).
    ///
    /// The reconciled on-disk definition — not the request — is the boot
    /// authority: the `Reuse` arm keeps an earlier definition, so the spec
    /// is re-checked for in-process bootability and the sidecar's recorded
    /// secret references are re-validated fail-closed even when this
    /// request carries none.
    async fn boot_persistent(&self, name: &str, request: &LaunchRequest) -> Result<LaunchOutcome> {
        if self.machine_running(name) {
            return Err(MvmError::Conflict {
                reason: format!("machine {name:?} is already running"),
            });
        }
        let spec = mp::load_machine_spec(name).map_err(crate::local::backend_err)?;
        ensure_spec_bootable_in_process(&spec)?;
        self.validate_sidecar_refs(name)?;
        self.attach_lease_and_boot(name, request, false).await
    }

    /// Re-validate the secret references recorded in `name`'s sidecar —
    /// the fail-closed gate every persistent admission passes, whether the
    /// references arrived with this request or with an earlier create.
    fn validate_sidecar_refs(&self, name: &str) -> Result<()> {
        let refs = crate::secret::refs::load_refs(&machine_state_root(), name)
            .map_err(|e| crate::local::backend_err(format!("loading secret refs: {e:#}")))?
            .map(|record| record.references)
            .unwrap_or_default();
        if refs.is_empty() {
            return Ok(());
        }
        self.secrets()?
            .validate_for_admission(LOCAL_TENANT, &refs)
            .map_err(|e| MvmError::Rejected {
                reason: format!("secret reference admission refused: {e}"),
            })
    }

    /// Shared tail of both launch paths: acquire volume leases, boot through
    /// admission, commit leases, register + track readiness.
    async fn attach_lease_and_boot(
        &self,
        name: &str,
        request: &LaunchRequest,
        transient: bool,
    ) -> Result<LaunchOutcome> {
        let profile = AdmittedProfile::from_profile_name(&request.profile);
        let mut preparation = self.acquire_leases(name, profile)?;
        let volumes: Vec<mvm_core::vm_backend::VmVolume> = preparation
            .volumes
            .iter()
            .map(|volume| mvm_core::vm_backend::VmVolume {
                host: volume.host.clone(),
                guest: volume.guest.clone(),
                size: volume.size.clone(),
                read_only: volume.read_only,
                kind: volume.kind,
                encrypted: volume.encrypted,
            })
            .collect();

        let started = self
            .boot_admitted(BootParams {
                name: name.to_string(),
                image: request.image.clone(),
                cpus: request.cpus,
                memory_mib: request.memory_mib,
                backend_override: request.backend.clone(),
                volumes,
                transient,
                grants: request.grants.clone(),
                assurance_campaign: request.assurance_campaign.clone(),
            })
            .await?;
        preparation.commit();

        self.register_started(name, request, transient);
        Ok(self.launch_outcome(name, request, started, transient))
    }

    /// Post-boot bookkeeping: name-registry registration (with TTL),
    /// host-observed readiness, and — for a persistent machine — the
    /// last-started stamp on its spec. All best-effort: the machine is up.
    fn register_started(&self, name: &str, request: &LaunchRequest, transient: bool) {
        register_machine(&MachineRegistration {
            expires_at: expires_at_from_ttl(request.ttl_seconds),
            vm_dir: vm_state_dir(name).to_string_lossy().into_owned(),
            ..MachineRegistration::minimal(name, "none")
        });
        crate::record_readiness(name, InstanceReadiness::LaunchAccepted);
        if !transient && let Ok(mut spec) = mp::load_machine_spec(name) {
            spec.last_started_at = Some(mvm_core::util::time::utc_now());
            if let Err(e) = mp::overwrite_machine_spec(&spec) {
                tracing::warn!(error = %e, machine = name, "stamping last_started_at failed (non-fatal)");
            }
        }
    }

    /// Assemble the outcome for a successful admitted boot.
    fn launch_outcome(
        &self,
        name: &str,
        request: &LaunchRequest,
        started: StartedMachine,
        transient: bool,
    ) -> LaunchOutcome {
        LaunchOutcome {
            machine: MachineState {
                id: MachineId(started.vm_id.0.clone()),
                name: name.to_string(),
                status: MachineStatus::Running,
                backend: self
                    .launch_backend(request.backend.as_deref())
                    .map(|b| b.name().to_string())
                    .unwrap_or_default(),
                cpus: request.cpus,
                memory_mib: request.memory_mib,
                profile: Some(request.profile.clone()),
                expires_at: expires_at_from_ttl(request.ttl_seconds),
                ..Default::default()
            },
            plan_id: started.admitted.plan_id().0.clone(),
            mode: if transient {
                LifecycleMode::Transient
            } else {
                LifecycleMode::Persistent
            },
            plan: started.admitted.plan().clone(),
        }
    }
}

/// Refusals for persisted-spec shapes the in-process backend cannot honor
/// (fail closed, never silently ignore a persisted field).
fn ensure_spec_bootable_in_process(spec: &mp::MachineSpec) -> Result<RootfsSource> {
    let unsupported = |what: &str| MvmError::InvalidSpec {
        reason: format!(
            "machine {:?} declares {what}, which the in-process local backend cannot \
             honor; use the CLI's `machine start`",
            spec.name
        ),
    };
    if spec.manifest.is_some() {
        return Err(unsupported("a manifest-backed source"));
    }
    if spec.deployment.is_some() {
        return Err(unsupported("an attested-deployment source"));
    }
    if spec.runtime_pack {
        return Err(unsupported("a runtime-pack source"));
    }
    if spec.net || !spec.allow_host.is_empty() {
        return Err(unsupported("a network policy other than deny-all"));
    }
    if !spec.volumes.is_empty() {
        return Err(unsupported(
            "CLI-grammar volume strings (use typed attachments)",
        ));
    }
    if !spec.init.is_empty() {
        return Err(unsupported("init commands"));
    }
    let image = spec.image.as_deref().ok_or_else(|| MvmError::InvalidSpec {
        reason: format!("machine {:?} has no image source", spec.name),
    })?;
    // The on-disk record stores the written form; a start reconstructs the
    // declaration from it rather than passing the bytes on unread.
    image.parse().map_err(|e| MvmError::InvalidSpec {
        reason: format!(
            "machine {:?} declares an unusable image source: {e}",
            spec.name
        ),
    })
}

impl LocalBackend {
    /// Start a stopped persistent machine from its persisted definition:
    /// sidecar secret references re-validated fail-closed, registered
    /// attachments re-resolved and leased, then the canonical admitted boot.
    /// Starting a machine that is already running returns its state.
    pub async fn start_persistent(&self, name: &str) -> Result<MachineState> {
        let spec = mp::load_machine_spec(name).map_err(|e| MvmError::NotFound {
            id: format!("{name}: {e}"),
        })?;
        if self.machine_running(name) {
            return Ok(MachineState {
                id: MachineId(name.to_string()),
                name: name.to_string(),
                status: MachineStatus::Running,
                cpus: spec.cpus,
                ..Default::default()
            });
        }
        let image = ensure_spec_bootable_in_process(&spec)?;
        self.validate_sidecar_refs(name)?;
        let memory_mib =
            mvm_core::util::parse_human_size(&spec.memory).map_err(crate::local::backend_err)?;
        let request = start_request_from_spec(name, image, memory_mib, &spec)?;
        let outcome = self.attach_lease_and_boot(name, &request, false).await?;
        Ok(outcome.machine)
    }

    /// Restart a persistent machine: stop it when running (spec kept), then
    /// start it again from its persisted definition.
    pub async fn restart_persistent(&self, name: &str) -> Result<MachineState> {
        if self.machine_running(name) {
            use mvm_core::client::MvmClient as _;
            self.stop_machine(&MachineId(name.to_string())).await?;
        }
        self.start_persistent(name).await
    }

    /// Remove a machine. For a persistent definition this is the separate
    /// confirmed action that deletes the spec: a RUNNING persistent machine
    /// is refused unless `options.force` explicitly requests the reviewed
    /// force flow (stop, then remove). A spec-less name gets transient
    /// semantics: stop + idempotent session cleanup. Removing an absent
    /// machine is `Ok`.
    pub async fn remove_machine_with(&self, id: &MachineId, options: RemoveOptions) -> Result<()> {
        let name = id.0.as_str();
        let has_spec = machine_spec_path(name).exists();
        if has_spec {
            if self.machine_running(name) {
                if !options.force {
                    return Err(MvmError::Conflict {
                        reason: format!(
                            "machine {name:?} is running; stop it first, or explicitly \
                             request the force removal flow"
                        ),
                    });
                }
                self.stop_for_recreate(name);
            }
            self.release_session_resources(name)?;
            // Drop the per-VM runtime dir too: a stale substitution-endpoint
            // socket left behind blocks the next launch under the same name
            // (the endpoint dies binding it, before its ready handshake).
            remove_dir_if_present(&vm_state_dir(name))?;
            // The definition directory carries machine.json plus the
            // secret-refs sidecar (already cleared above) — drop it whole.
            remove_dir_if_present(&machine_state_dir(name))?;
            mvm_core::audit_emit!(
                ConfigChange,
                vm: name,
                "action=machine.remove mode=persistent force={force}",
                force = options.force,
            );
            return Ok(());
        }
        // Transient semantics: stop whatever is live, then idempotent cleanup.
        self.cleanup_transient(name)
    }

    /// Release every session-owned resource `name` holds: registered volume
    /// attachments, attachment leases (re-sealing just-in-time unlocks),
    /// secret-reference sidecar, name-registry entry. Idempotent.
    fn release_session_resources(&self, name: &str) -> Result<()> {
        let service = LocalVolumeService::new();
        match service.list_attachments(name) {
            Ok(attachments) => {
                for attachment in attachments {
                    if let Err(e) = service.detach(name, &attachment.guest_path) {
                        tracing::warn!(error = %e, machine = name, guest = %attachment.guest_path, "detach during cleanup failed");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, machine = name, "listing attachments during cleanup failed");
            }
        }
        service
            .release_owner_leases(name)
            .map_err(|e| crate::local::backend_err(format!("releasing volume leases: {e:#}")))?;
        self.clear_secret_refs(name)?;
        crate::local::deregister_from_name_registry(name);
        Ok(())
    }

    /// Idempotent transient cleanup: stop the VM when live, release every
    /// session-owned resource, and drop the per-VM state dirs. Safe to call
    /// repeatedly and on names that never launched.
    pub fn cleanup_transient(&self, name: &str) -> Result<()> {
        if self.machine_running(name) {
            self.stop_for_recreate(name);
        }
        self.release_session_resources(name)?;
        remove_dir_if_present(&vm_state_dir(name))?;
        // The state dir under machines/ only carries session sidecars for a
        // transient (no machine.json); never touch a persistent definition.
        if !machine_spec_path(name).exists() {
            remove_dir_if_present(&machine_state_dir(name))?;
        }
        Ok(())
    }
}

impl LocalBackend {
    /// Wait for a transient launch to run to completion, report its captured
    /// exit code, and clean up its session-owned resources. Polls the owning
    /// backend; fails with a timeout error if the machine is still running
    /// after `timeout`. The `plan.exited` chain entry carries the exit code.
    pub fn wait_for_exit(
        &self,
        outcome: &LaunchOutcome,
        poll: std::time::Duration,
        timeout: std::time::Duration,
    ) -> Result<ExitReport> {
        let name = outcome.machine.name.clone();
        let deadline = std::time::Instant::now() + timeout;
        while self.machine_running(&name) {
            if std::time::Instant::now() >= deadline {
                return Err(crate::local::backend_err(format!(
                    "machine {name:?} still running after {}s",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(poll);
        }
        self.report_exit(outcome)
    }

    /// Report an already-exited machine's captured exit code, emit the
    /// chain-signed `plan.exited` entry, and (for a transient) run the
    /// idempotent cleanup.
    pub fn report_exit(&self, outcome: &LaunchOutcome) -> Result<ExitReport> {
        let name = outcome.machine.name.as_str();
        let exit_code = mvm_core::exit_capture::read_captured(&vm_state_dir(name));
        // Capture fidelity: a missing capture is recorded as uncaptured,
        // never attested as exit 0.
        if let Some(emitter) = build_audit_emitter()
            && let Err(e) =
                emitter.emit_exited_with_capture(&outcome.plan, exit_code, &outcome.machine.backend)
        {
            tracing::warn!(error = %e, machine = name, "audit emit_exited failed (non-fatal)");
        }
        if outcome.mode == LifecycleMode::Transient {
            self.cleanup_transient(name)?;
        }
        Ok(ExitReport { exit_code })
    }

    /// Stop and clean every transient machine whose registry TTL has lapsed
    /// at `now` (RFC 3339). Persistent definitions are never touched — their
    /// TTL semantics stay with the idle reaper. Returns the reaped names.
    pub fn reap_expired_transients(&self, now_rfc3339: &str) -> Result<Vec<String>> {
        let Some(now) = mvm_core::util::time::parse_iso8601(now_rfc3339) else {
            return Err(MvmError::InvalidSpec {
                reason: format!("invalid RFC 3339 timestamp {now_rfc3339:?}"),
            });
        };
        let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(
            &mvm_runtime::vm::name_registry::registry_path(),
        )
        .unwrap_or_default();
        let expired: Vec<String> = registry
            .vms
            .iter()
            .filter(|(name, reg)| {
                !machine_spec_path(name).exists()
                    && matches!(
                        reg.expires_at
                            .as_deref()
                            .and_then(mvm_core::util::time::parse_iso8601),
                        Some(exp) if exp < now
                    )
            })
            .map(|(name, _)| name.clone())
            .collect();
        let mut reaped = Vec::with_capacity(expired.len());
        for name in expired {
            self.cleanup_transient(&name)?;
            reaped.push(name);
        }
        reaped.sort();
        Ok(reaped)
    }
}

/// Remove a directory tree, treating "already absent" as success.
fn remove_dir_if_present(dir: &std::path::Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::local::backend_err(format!(
            "removing {}: {e}",
            dir.display()
        ))),
    }
}
