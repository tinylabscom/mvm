//! The post-admission tail every admitted boot shares, and the one-call
//! admit-and-boot entry point.

mod portable_entrypoint;

pub use portable_entrypoint::prepare_portable_entrypoint;

use super::admit::admit_plan_for_run;
use super::assurance_runtime::verify_selected_runtime;
use super::rollback::{
    FailureAuditPolicy, UndoLaunch, UndoLaunchFailure, apply_admitted_grants_or_undo_launch,
    apply_admitted_grants_with_rollback, apply_entrypoint_grants_or_undo_launch,
    record_charge_or_undo_launch, record_charge_with_owned_rollback,
    record_entrypoint_charge_or_undo_launch, undo_cli_launch, undo_launch, undo_launch_with,
};
use super::{AdmitAndStartParams, AdmittedPlan, RunPosture, final_gates, registry_pack};
use anyhow::{Context, Result};
use chrono::Utc;
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_core::plan::{ExecutionPlan, synthesize_plan};
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::{StandbyClaim, StandbyError, StandbyHandle, VmId, VmStartConfig};
use mvm_runtime::AnyBackend;
use mvm_runtime::vm::instance_snapshot::MachineLifecycleLock;

/// Dispatch an already admitted entrypoint on its original native channel.
///
/// The caller supplies slots inside its original custody group. The runtime
/// slot is populated before activation, so even an uncertain activation error
/// cannot discard the child or its admission and image owners.
///
/// # Errors
/// Refuses an unsupported backend, spent admission, invalid runtime or host
/// gate, or failed native preparation/activation. A post-preparation failure
/// leaves the original runtime in `runtime` for its caller to stop.
pub fn start_owned_entrypoint(
    backend: &AnyBackend,
    admitted: &mut AdmittedPlan,
    config: &mut VmStartConfig,
    policy_bundle: Option<&PolicyBundle>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    built_runtime: &mut Option<super::PreparedBuiltPackRuntime>,
    runtime: &mut Option<mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch>,
) -> Result<()> {
    anyhow::ensure!(
        !admitted.dispatched,
        "original admitted plan was already dispatched"
    );
    // The mailbox profile is a property of the admitted plan, not the start
    // config, and an unservable guest mailbox refuses before any native
    // preparation spends the one-use admission.
    crate::mailbox_launch::require_legacy_launch(admitted.plan().mailbox.as_ref())?;
    anyhow::ensure!(
        runtime.is_none(),
        "native runtime slot must be empty before dispatch"
    );
    anyhow::ensure!(
        backend.kind() == mvm_core::vm_backend::BackendKind::Hvf,
        "original-owner entrypoint requires HVF"
    );
    anyhow::ensure!(
        admitted.backend == Some(backend.kind()),
        "original-owner entrypoint backend differs from admitted backend"
    );
    mvm_runtime::workload_backend::require_workload_backend(backend)?;
    if let Some(release) = verified_runtime {
        release.verify_config(config)?;
        admitted
            .plan()
            .require_runtime_identity(release.identity())?;
    } else if admitted.plan().runtime_identity.is_none() {
        verify_selected_runtime(config)?;
    }
    *built_runtime = final_gates::run_post_admission_gates_for_source(
        config,
        admitted,
        backend.kind(),
        policy_bundle,
        final_gates::ImageSource::OwnedNative,
    )
    .map_err(|(stage, err)| err.context(format!("admission gate refused ({stage})")))?;
    anyhow::ensure!(
        admitted.plan().runtime_identity.is_none()
            || verified_runtime.is_some()
            || built_runtime.is_some(),
        "admitted runtime identity has no retained verification"
    );
    if let Some(release) = verified_runtime {
        release.verify_config(config)?;
        admitted
            .plan()
            .require_runtime_identity(release.identity())?;
    }
    registry_pack::verify_runtime_at_dispatch(built_runtime.as_ref(), config, admitted, None)?;
    crate::mailbox_process::require_servable(config, backend, admitted.mailbox_posture().as_ref())?;
    if super::persists_plan_before_start(backend.name()) {
        super::stash_plan_for_bridge(config)?;
    }
    // The one-use authority is spent before the first native side effect.
    admitted.dispatched = true;
    let images = built_runtime
        .as_mut()
        .context("owned native image preparation missing")?
        .take_boot_images()?;
    *runtime = Some(backend.prepare_owned_launch_with_verified_runtime(
        config,
        images,
        verified_runtime,
    )?);
    let original = runtime
        .as_mut()
        .context("original native runtime missing")?;
    if let Some(built) = built_runtime.as_ref() {
        built.verify_config(original.config()?)?;
    }
    original.activate()
}

/// CLI transient boots keep their completion narrative with the caller.
enum StartFinalization {
    /// Record launch and failures at the host dispatch boundary.
    Immediate,
    /// Keep the ordinary launch/rollback tail, but persist the bridge
    /// substrate before an entrypoint's backend opens its endpoint.
    Entrypoint,
    /// Defer success until confirmed transient teardown.
    CliTransient {
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    },
    /// Defer acceptance until the persistent guest proves authenticated readiness.
    Persistent {
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    },
    /// Fork launch/failure audit stays with the CLI; no immediate grant acceptance or charge.
    FsQuickFork,
}

/// Distinguish an already-audited pack refusal, a CLI-owned failure, and an uncertain stop.
#[derive(Debug, thiserror::Error)]
pub enum CliStartFailure {
    #[error("{0:#}")]
    Recorded(anyhow::Error),
    #[error("{0:#}")]
    Unrecorded(anyhow::Error),
    /// The selected name is held by another launch; the caller cannot clean its state.
    #[error("{0:#}")]
    StateNotOwned(anyhow::Error),
    #[error("{0:#}")]
    UncertainStop(anyhow::Error),
}

pub(super) fn cli_rollback_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<UndoLaunchFailure>() {
        CliStartFailure::UncertainStop(error).into()
    } else {
        CliStartFailure::Unrecorded(error).into()
    }
}

fn entrypoint_rollback_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<UndoLaunchFailure>() {
        CliStartFailure::UncertainStop(error).into()
    } else {
        error
    }
}

struct StartTailResult {
    vm_id: VmId,
    admitted: AdmittedPlan,
    enforced_grants: Option<EnforcedGrants>,
    config: VmStartConfig,
}

#[cfg(test)]
thread_local! {
    pub(super) static TRAP_LAUNCH_PREPARATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Outcome of a successful admitted boot: the backend's VM id plus the
/// `AdmittedPlan` (for the caller's audit chain / typed result).
#[derive(Debug)]
pub struct StartedMachine {
    pub vm_id: VmId,
    pub admitted: AdmittedPlan,
    /// What actually bounded this workload, read back off the live controls by
    /// the backend that booted it.
    ///
    /// Not the grants that were requested — those are already on the signed
    /// plan. A caller building a receipt gets the tier that fired, so it cannot
    /// report a bound that was only asked for.
    pub enforced_grants: EnforcedGrants,
}

/// A persistent VM dispatched under its one-use plan but not yet accepted.
pub struct DispatchedPersistent {
    pub vm_id: VmId,
    pub admitted: AdmittedPlan,
    /// The exact admitted configuration handed to the backend, for post-start
    /// mailbox setup; the caller's pre-gate config is not authoritative.
    pub config: VmStartConfig,
}

/// Inputs whose verification, admission and dispatch must stay under one lifecycle lock.
pub struct PreparePersistentParams<'a> {
    /// The selected backend instance that will receive the admitted config.
    pub backend: &'a AnyBackend,
    /// Source-prepared config whose selected runtime is not yet launch-verified.
    pub config: VmStartConfig,
    /// Writable image locks transferred to the backend on dispatch.
    pub writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    /// The caller-held guard spanning source preparation through readiness.
    pub lifecycle: &'a MachineLifecycleLock,
}

/// One signed fresh-cold admission plus source-owned post-dispatch state.
pub struct LaunchAdmission<C> {
    /// The one-use authority created for this exact persistent config.
    pub admitted: AdmittedPlan,
    /// The signer that records later readiness acceptance or refusal.
    pub emitter: crate::audit::emitter::AuditEmitter,
    /// The resolved policy bundle enforced by final launch gates.
    pub policy_bundle: Option<PolicyBundle>,
    /// Opaque client state returned without granting launch authority.
    pub continuation: C,
}

/// A persistent child dispatched under the admission created in the same call.
pub struct PreparedPersistent<C> {
    /// Backend identity of the dispatched but not yet accepted child.
    pub vm_id: VmId,
    /// Original admitted authority and audit continuation for readiness.
    pub admission: LaunchAdmission<C>,
    /// Exact post-gate config handed to the backend and mailbox owner.
    pub config: VmStartConfig,
}

pub(crate) enum LaunchSource<'a> {
    Persistent {
        lifecycle: &'a MachineLifecycleLock,
    },
    FilesystemFork {
        backend_kind: mvm_core::vm_backend::BackendKind,
    },
    CliCold {
        backend_kind: mvm_core::vm_backend::BackendKind,
    },
    LocalTransient {
        lifecycle: &'a MachineLifecycleLock,
    },
    Entrypoint {
        backend_kind: mvm_core::vm_backend::BackendKind,
    },
    PortableEntrypoint {
        backend_kind: mvm_core::vm_backend::BackendKind,
    },
}

pub(crate) struct PreparedLaunch<A> {
    pub(crate) config: VmStartConfig,
    pub(crate) verified_runtime:
        Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    pub(crate) admission: A,
}

pub(crate) fn prepare_launch<A>(
    source: LaunchSource<'_>,
    mut config: VmStartConfig,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<A>,
) -> Result<PreparedLaunch<A>> {
    match source {
        LaunchSource::Persistent { lifecycle } | LaunchSource::LocalTransient { lifecycle } => {
            lifecycle
                .require_name(&config.name)
                .map_err(CliStartFailure::StateNotOwned)?;
            lifecycle
                .require_cold_state()
                .map_err(CliStartFailure::StateNotOwned)?;
        }
        LaunchSource::FilesystemFork { backend_kind }
        | LaunchSource::CliCold { backend_kind }
        | LaunchSource::Entrypoint { backend_kind }
        | LaunchSource::PortableEntrypoint { backend_kind } => {
            tracing::trace!(
                backend = backend_kind.as_str(),
                "preparing selected cold source"
            );
        }
    }

    let release = attach(&mut config)?;
    let verified_runtime = match release {
        Some(release) => Some(std::sync::Arc::new(
            mvm_runtime::runtime_evidence::verify_release_runtime_set(&config, release)?,
        )),
        None => mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&config)?
            .map(std::sync::Arc::new),
    };
    let admission = admit(&mut config, verified_runtime.as_deref())?;
    Ok(PreparedLaunch {
        config,
        verified_runtime,
        admission,
    })
}

/// An ordinary entrypoint prepared through attachment, runtime verification and admission.
pub struct PreparedEntrypoint<A> {
    config: VmStartConfig,
    verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    admission: A,
}

impl<A> PreparedEntrypoint<A> {
    /// Return the exact prepared config, retained runtime evidence and admission.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VmStartConfig,
        Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
        A,
    ) {
        (self.config, self.verified_runtime, self.admission)
    }
}

/// Prepare an ordinary entrypoint without changing its source-specific dispatch tail.
///
/// Attachment includes installed-bundle authentication when the client selects
/// one. The returned runtime evidence is the same launch-scoped set supplied to
/// admission and must be retained through dispatch.
///
/// # Errors
/// Propagates attachment, runtime verification, or admission refusal before any
/// backend dispatch.
pub fn prepare_entrypoint<A>(
    config: VmStartConfig,
    backend_kind: mvm_core::vm_backend::BackendKind,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<A>,
) -> Result<PreparedEntrypoint<A>> {
    let prepared = prepare_launch(
        LaunchSource::Entrypoint { backend_kind },
        config,
        attach,
        admit,
    )?;
    Ok(PreparedEntrypoint {
        config: prepared.config,
        verified_runtime: prepared.verified_runtime,
        admission: prepared.admission,
    })
}

/// Attach, verify, admit and dispatch a persistent cold boot in that order.
///
/// Source-specific attachment and plan lowering stay in the client callbacks,
/// while this boundary owns their order and retains the verified runtime
/// through dispatch. The supplied lifecycle lock is never reacquired.
///
/// # Errors
/// Refuses a mismatched or non-cold lifecycle before attachment or admission,
/// or propagates attachment, verification, durable admission and dispatch
/// failures without starting a backend past the refusing stage.
pub fn boot_vm<C>(
    params: PreparePersistentParams<'_>,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<LaunchAdmission<C>>,
) -> Result<PreparedPersistent<C>> {
    let PreparePersistentParams {
        backend,
        config,
        writable_images,
        lifecycle,
    } = params;
    let PreparedLaunch {
        config,
        verified_runtime,
        admission,
    } = prepare_launch(
        LaunchSource::Persistent { lifecycle },
        config,
        attach,
        admit,
    )?;
    let LaunchAdmission {
        admitted,
        emitter,
        policy_bundle,
        continuation,
    } = admission;
    let audit_plan = admitted.plan().clone();
    let started = start_admitted_with_finalization(
        StartAdmittedParams {
            backend,
            admitted,
            config,
            policy_bundle: policy_bundle.as_ref(),
            emitter: Some(&emitter),
            assurance: None,
        },
        verified_runtime.as_deref(),
        StartFinalization::Persistent { writable_images },
        None,
        None,
        || Ok(()),
    )
    .inspect_err(|dispatch_error| {
        if matches!(
            dispatch_error.downcast_ref::<CliStartFailure>(),
            Some(CliStartFailure::UncertainStop(_))
        ) {
            return;
        }
        if let Err(error) =
            emitter.seal_session(&audit_plan, crate::audit::session::SealReason::Failed)
        {
            tracing::warn!(%error, "sealing refused persistent admission failed");
        }
    })?;
    Ok(PreparedPersistent {
        vm_id: started.vm_id,
        admission: LaunchAdmission {
            admitted: started.admitted,
            emitter,
            policy_bundle,
            continuation,
        },
        config: started.config,
    })
}

/// Dispatch a persistent guest while its caller retains readiness-dependent finalization.
pub fn start_persistent(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
) -> Result<DispatchedPersistent> {
    let started = start_admitted_with_finalization(
        params,
        verified_runtime,
        StartFinalization::Persistent { writable_images },
        None,
        None,
        || Ok(()),
    )?;
    Ok(DispatchedPersistent {
        vm_id: started.vm_id,
        admitted: started.admitted,
        config: started.config,
    })
}

pub(super) fn launch_decision_record(plan: &ExecutionPlan, backend_name: &str) -> DecisionRecord {
    DecisionRecordBuilder::new()
        .version(1)
        .category(DecisionCategory::Launch)
        .actor(ActorRef {
            principal: crate::audit::host_keypair::host_signer_id(),
            key_id: crate::audit::host_keypair::host_signer_id(),
            key_role: Some(DecisionActorRole::Orchestrator),
        })
        .scenario(mvm_contract::provenance::DecisionScenario {
            plan_id: Some(plan.plan_id.0.clone()),
            ..Default::default()
        })
        .reasoning(format!("workload launched on backend {backend_name}"))
        .outcome(DecisionOutcome::Approved)
        .timestamp(Utc::now().to_rfc3339())
        .attestation(AttestationBinding {
            plan_id: Some(plan.plan_id.0.clone()),
            ..AttestationBinding::default()
        })
        .build()
        .expect("launch decision record is well-formed")
}

pub(super) fn attach_assurance_proxy(
    config: &mut VmStartConfig,
    proxy: mvm_contract::protocol::broker_control::ServiceProxyBinding,
) -> Result<()> {
    if config
        .service_proxies
        .iter()
        .any(|binding| binding.service == proxy.service)
    {
        anyhow::bail!("assurance controller proxy service is already configured");
    }
    config.service_proxies.push(proxy);
    Ok(())
}

/// Everything the post-admission tail needs, in one struct.
///
/// A params struct rather than six positional arguments: three of the fields
/// are optional borrows of unrelated types and a positional call could drop or
/// transpose one with nothing to catch it.
pub struct StartAdmittedParams<'a> {
    pub backend: &'a AnyBackend,
    /// The plan this boot runs under. Taken by value because it is handed back
    /// on the [`StartedMachine`], and holding one is the only proof admission
    /// ran — it cannot be built any other way.
    pub admitted: AdmittedPlan,
    pub config: VmStartConfig,
    pub policy_bundle: Option<&'a PolicyBundle>,
    /// Optional chain-signed emitter: ordinary starts emit `plan.launched`
    /// after backend start; CLI transient starts defer it until completed exit.
    /// Ordinary boot refusals emit `plan.failed` here; CLI transient refusals
    /// leave their original `launch`-class failure entry with the CLI audit owner.
    /// The caller owns `plan.admitted`, which is already recorded by the time
    /// this runs.
    pub emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// An assurance campaign to open against this boot, when the operator
    /// declared one. `None` — the default — is every ordinary run.
    pub assurance: Option<&'a crate::assurance_session::CampaignRequest>,
}

/// The post-admission tail every admitted boot shares: the gates, the backend
/// start, the grants, the budget charge and the launch records.
///
/// Split out of [`admit_and_start`] so a caller holding an already-admitted
/// plan — a resumed durable session, for one — can boot it without admitting a
/// second time. Two admissions would mean two nonces and two signed plans, with
/// the second silently becoming the real authority. Because this is the only
/// path from an `AdmittedPlan` to a running VM, a caller cannot boot on a path
/// that skipped a gate.
///
/// Order matters and is fail-closed: the signed plan is threaded onto the
/// launch config and every volume checked against the admitted shares
/// (claim 1); only then does the backend start the VM. A refusal in any gate
/// returns with **no VM created**, and a refusal *after* the start rolls the
/// launch back rather than leaving a VM up whose only record says it was
/// bounded.
///
/// The caller resolves the image to a `config.rootfs_path` beforehand; this
/// function is backend-agnostic (it drives whatever `AnyBackend` it is handed,
/// including the in-memory mock in tests).
#[tracing::instrument(skip_all)]
pub fn start_admitted(params: StartAdmittedParams<'_>) -> Result<StartedMachine> {
    let verified =
        mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&params.config)?;
    start_admitted_with_verified_release(params, verified.as_ref())
}

/// Start an entrypoint with the release evidence retained by this admission.
///
/// Selection, signed-plan binding, host gates, budget rollback and launch
/// audit all remain in the ordinary admitted tail.
///
/// # Errors
/// A launch gate or backend refusal, or a post-start grant or charge that
/// could not be applied and rolled back.
pub fn start_entrypoint(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<StartedMachine> {
    let started = start_admitted_with_finalization(
        params,
        verified_runtime,
        StartFinalization::Entrypoint,
        None,
        None,
        || Ok(()),
    )?;
    Ok(StartedMachine {
        vm_id: started.vm_id,
        admitted: started.admitted,
        enforced_grants: started
            .enforced_grants
            .expect("entrypoint host start checks enforced grants"),
    })
}

/// Start a locally admitted release using this launch's authenticated archive.
pub(crate) fn start_admitted_with_verified_release(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<StartedMachine> {
    let started = start_admitted_with_finalization(
        params,
        verified_runtime,
        StartFinalization::Immediate,
        None,
        None,
        || Ok(()),
    )?;
    Ok(StartedMachine {
        vm_id: started.vm_id,
        admitted: started.admitted,
        enforced_grants: started
            .enforced_grants
            .expect("immediate host start always checks enforced grants"),
    })
}

/// Consume a CLI's one-shot admission without repeating verification or signing.
pub fn start_cli_transient(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
) -> Result<VmId> {
    start_admitted_with_finalization(
        params,
        verified_runtime,
        StartFinalization::CliTransient { writable_images },
        None,
        None,
        || Ok(()),
    )
    .map(|started| started.vm_id)
}

/// Dispatch a one-use admitted filesystem child through the common gates.
pub fn start_fs_quick_fork(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<VmId> {
    start_admitted_with_finalization(
        params,
        verified_runtime,
        StartFinalization::FsQuickFork,
        None,
        None,
        || Ok(()),
    )
    .map(|started| started.vm_id)
}

/// Outcome of a selected warm claim. A lost reservation never spent its
/// authority, so the caller can cold-dispatch that same admission.
pub enum WarmClaimDispatch {
    Claimed(mvm_runtime::backend::OwnedWarmClaim),
    ReservationLost(Box<AdmittedPlan>),
}

/// Dispatch a CLI's already-admitted transient as a separately admitted warm child.
///
/// The parent is a planless, verified boot substrate; the child receives this
/// one-use admission. Pool selection is done before this call so a miss keeps
/// the caller's authority available for the ordinary cold dispatch.
pub fn claim_cli_transient(
    backend: &AnyBackend,
    admitted: AdmittedPlan,
    config: VmStartConfig,
    policy_bundle: Option<&mvm_core::policy::PolicyBundle>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ctx: &mvm_runtime::workload_runner::ClaimContext<'_>,
    handle: &StandbyHandle,
) -> Result<WarmClaimDispatch> {
    let mut admitted = admitted;
    anyhow::ensure!(!admitted.dispatched, "CLI admission was already dispatched");
    // A standby's scope was created before this launch was placed, so it holds
    // no CPU set and a claimed child would run unconfined.
    anyhow::ensure!(
        admitted.allowed_cpus().is_none(),
        "a launch placed on host cores cannot claim a warm standby"
    );
    anyhow::ensure!(
        admitted.plan().image.name == config.name,
        "warm claim identity differs from admitted plan"
    );
    anyhow::ensure!(
        admitted.plan().runtime_identity.is_none() == verified_runtime.is_none(),
        "CLI release admission and its launch-owned verification set differ"
    );
    if let Some(runtime) = verified_runtime {
        runtime.verify_config(&config)?;
        admitted
            .plan()
            .require_runtime_identity(runtime.identity())?;
    } else {
        verify_selected_runtime(&config)?;
    }
    let (mut prepared, built_runtime) = final_gates::run_post_admission_gates(
        config.clone(),
        &admitted,
        backend.kind(),
        policy_bundle,
    )
    .map_err(|(stage, error)| error.context(format!("warm admission gate refused ({stage})")))?;
    anyhow::ensure!(
        prepared.rootfs_path == config.rootfs_path,
        "warm claim cannot replace the selected parent image"
    );
    registry_pack::verify_runtime_at_dispatch(built_runtime.as_ref(), &prepared, &admitted, None)?;
    crate::mailbox_process::require_servable(
        &prepared,
        backend,
        admitted.mailbox_posture().as_ref(),
    )?;
    anyhow::ensure!(
        prepared.volumes.iter().all(|volume| volume.read_only),
        "warm claim cannot transfer writable volume custody"
    );
    crate::seal_gate::persist_sealed_plan(&config.name, admitted.plan())?;
    let audit = mvm_vmm::host::audit_substrate::compute_audit_substrate(
        &config.name,
        prepared.tenant_id.as_deref(),
    )?;
    let plan_json = prepared
        .plan_json
        .clone()
        .context("warm claim missing admitted plan")?;
    let tenant_id = prepared
        .tenant_id
        .clone()
        .context("warm claim missing admitted tenant")?;
    let rootfs_path = prepared.rootfs_path.clone();
    let bundle_json = prepared.bundle_json.clone();
    let audit_context = prepared.audit_context.clone();
    let network_policy = prepared.network_policy.clone();
    prepared.name = handle.id.clone();
    let claim = StandbyClaim {
        start_config: Some(prepared),
        rootfs_path,
        tenant_id,
        audit_dir: audit
            .audit_dir
            .context("warm claim missing audit directory")?,
        gateway_audit_socket: audit
            .gateway_audit_socket
            .context("warm claim missing gateway audit socket")?,
        gateway_events_socket: audit.gateway_events_socket,
        plan_json,
        audit_context,
        bundle_json,
        network_policy,
    };
    // No plan JSON can create this authority: only admission owns this value.
    // Spend it before the runner can fork or resume the child.
    admitted.dispatched = true;
    match backend.claim_standby_owned_via_runner(ctx, handle, &claim) {
        Ok(owned) => Ok(WarmClaimDispatch::Claimed(owned)),
        Err(StandbyError::ReservationLost) => {
            admitted.dispatched = false;
            Ok(WarmClaimDispatch::ReservationLost(Box::new(admitted)))
        }
        Err(error) => Err(super::cli_cold::map_cli_warm_claim_error(error)),
    }
}

fn start_admitted_with_finalization(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    finalization: StartFinalization,
    mut actor_owner: Option<&mut Option<mvm_runtime::actor_teardown::ActorOwner>>,
    bootstrap: Option<mvm_runtime::actor_teardown::ActorBootstrap>,
    before_dispatch: impl FnOnce() -> Result<()>,
) -> Result<StartTailResult> {
    let cli_transient = matches!(finalization, StartFinalization::CliTransient { .. });
    let persistent = matches!(finalization, StartFinalization::Persistent { .. });
    let fork = matches!(finalization, StartFinalization::FsQuickFork);
    let entrypoint = matches!(finalization, StartFinalization::Entrypoint);
    let backend = params.backend;
    let mut admitted = params.admitted;
    anyhow::ensure!(
        !admitted.dispatched,
        "original admitted plan was already dispatched"
    );
    anyhow::ensure!(
        admitted.plan().runtime_identity.is_none() || params.emitter.is_some(),
        "signed release runtime cannot dispatch without an admission audit emitter"
    );

    // A refusal in any post-admission gate must still terminate the chain:
    // `plan.admitted` already fired, so a gate refusal emits `plan.failed`
    // carrying the refusing stage rather than leaving a dangling admission.
    let gated = (|| {
        crate::mailbox_launch::require_legacy_launch(admitted.plan().mailbox.as_ref())
            .map_err(|error| ("mailbox-profile", anyhow::Error::from(error)))?;
        #[cfg(test)]
        if TRAP_LAUNCH_PREPARATION.get() {
            return Err((
                "test-preparation",
                anyhow::anyhow!("launch preparation reached"),
            ));
        }
        if params.assurance.is_some() {
            admitted
                .bind_assurance_runtime(&params.config, verified_runtime)
                .map_err(|error| ("assurance-runtime", error))?;
        }
        if params.assurance.is_some() || admitted.assurance_runtime.is_some() {
            admitted
                .verify_assurance_launch(&params.config, verified_runtime)
                .map_err(|error| ("assurance-runtime", error))?;
        }
        if !persistent && let Some(runtime) = verified_runtime {
            runtime
                .verify_config(&params.config)
                .map_err(|error| ("guest-runtime", error))?;
            admitted
                .plan()
                .require_runtime_identity(runtime.identity())
                .map_err(|error| ("guest-runtime", anyhow::Error::from(error)))?;
        } else if !persistent
            && !(entrypoint
                && verified_runtime.is_none()
                && admitted.plan().runtime_identity.is_some())
        {
            verify_selected_runtime(&params.config).map_err(|error| ("guest-runtime", error))?;
        }
        let (config, built_runtime) = final_gates::run_post_admission_gates(
            params.config,
            &admitted,
            backend.kind(),
            params.policy_bundle,
        )?;
        if entrypoint
            && verified_runtime.is_none()
            && built_runtime.is_none()
            && admitted.plan().runtime_identity.is_some()
        {
            return Err((
                "release-runtime",
                anyhow::anyhow!("admitted runtime identity has no retained verification"),
            ));
        }
        if persistent {
            if verified_runtime.is_none()
                && built_runtime.is_none()
                && admitted.plan().runtime_identity.is_some()
            {
                return Err((
                    "release-runtime",
                    anyhow::anyhow!("admitted runtime identity has no retained verification"),
                ));
            }
            if let Some(runtime) = verified_runtime {
                runtime
                    .verify_config(&config)
                    .map_err(|error| ("release-runtime", error))?;
                admitted
                    .plan()
                    .require_runtime_identity(runtime.identity())
                    .map_err(|error| ("release-runtime", anyhow::Error::from(error)))?;
            }
            if let Some(runtime) = &built_runtime {
                runtime
                    .verify_config(&config)
                    .map_err(|error| ("registry-pack-runtime", error))?;
            }
        }
        Ok((config, built_runtime))
    })();
    let (mut config, _built_runtime) = match gated {
        Ok(prepared) => prepared,
        Err((stage, err)) => {
            if !cli_transient
                && !fork
                && let Some(emitter) = params.emitter
                && let Err(e) = emitter.emit_failed(admitted.plan(), stage, &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            let err = err.context(format!("admission gate refused ({stage})"));
            return Err(if cli_transient {
                CliStartFailure::Unrecorded(err).into()
            } else {
                err
            });
        }
    };
    if params.assurance.is_some() {
        let proxy = crate::assurance_session::prepare_controller_proxy(&config.name)
            .context("preparing admitted assurance controller proxy")?;
        attach_assurance_proxy(&mut config, proxy)?;
    }

    let backend_name = backend.name().to_string();
    let vm_name = config.name.clone();
    let mailbox_posture = admitted.mailbox_posture();
    registry_pack::verify_runtime_at_dispatch(
        _built_runtime.as_ref(),
        &config,
        &admitted,
        params.emitter,
    )
    .map_err(|err| {
        if cli_transient && _built_runtime.is_some() {
            CliStartFailure::Recorded(err).into()
        } else {
            err
        }
    })?;
    // Before the boot, so a grant this backend cannot serve never reaches a
    // guest that would assert it.
    if let Err(err) =
        crate::mailbox_process::require_servable(&config, backend, mailbox_posture.as_ref())
    {
        if (persistent || entrypoint)
            && let Some(emitter) = params.emitter
            && let Err(e) =
                emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
        {
            tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
        }
        return Err(err);
    }
    // A unit admitted under a topology reads as sealed only through its
    // persisted plan, so that write is part of the launch. It goes first: the
    // bridge stash below replaces it with the signed envelope, which reads as
    // the same plan.
    if let Err(err) = crate::seal_gate::persist_sealed_plan(&vm_name, admitted.plan()) {
        if (persistent || entrypoint)
            && let Some(emitter) = params.emitter
            && let Err(e) = emitter.emit_failed(admitted.plan(), "seal-plan", &format!("{err:#}"))
        {
            tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
        }
        return Err(if cli_transient {
            CliStartFailure::Unrecorded(err).into()
        } else {
            err
        });
    }
    if (persistent || fork || entrypoint) && super::persists_plan_before_start(backend.name()) {
        super::stash_plan_for_bridge(&config).inspect_err(|err| {
            if !fork
                && let Some(emitter) = params.emitter
                && let Err(e) =
                    emitter.emit_failed(admitted.plan(), "bridge-plan", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
        })?;
    }
    if persistent && let Err(err) = mvm_runtime::workload_backend::require_workload_backend(backend)
    {
        if let Some(emitter) = params.emitter
            && let Err(e) =
                emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
        {
            tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
        }
        return Err(err);
    }
    // Actor launches run one last caller gate after every shared admission
    // check and before the budget marks dispatch.
    before_dispatch()?;
    // Spent before the backend starts, so an admission that reached dispatch
    // can never authorize another launch, whatever the start's outcome.
    if let Err(error) = admitted.mark_host_budget_dispatching(&config.name) {
        if let Some(emitter) = params.emitter
            && let Err(audit_error) =
                emitter.emit_failed(admitted.plan(), "host-budget", &format!("{error:#}"))
        {
            tracing::warn!(error = %audit_error, "audit emit_failed failed (non-fatal)");
        }
        return Err(error.context("host-budget dispatch refused"));
    }
    admitted.dispatched = true;
    if cli_transient
        && (mvm_runtime::catalog::descriptor(backend.kind()).is_workload
            // The hermetic mock is not a shipped workload backend, but it
            // exercises this exact bridge handoff in CLI integration tests.
            || backend.kind() == mvm_core::vm_backend::BackendKind::Mock)
        && let Err(err) = super::stash_plan_for_bridge(&config)
    {
        return Err(CliStartFailure::Unrecorded(err).into());
    }
    let start = if let Some(slot) = actor_owner.as_mut() {
        backend
            .start_owned_actor_with_bootstrap(&config, verified_runtime, bootstrap)
            .map(|owner| {
                let vm_id = owner.vm_id().clone();
                **slot = Some(owner);
                vm_id
            })
            .inspect_err(|error| {
                if let Some(failure) =
                    error.downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
                    && let Ok(Some(owner)) = failure.take_owner()
                {
                    **slot = Some(owner);
                }
                // An ownerless typed failure may still hold original boot/helper
                // custody. Return it intact for the lifecycle coordinator to retain.
            })
    } else if let StartFinalization::CliTransient { writable_images }
    | StartFinalization::Persistent {
        writable_images, ..
    } = finalization
    {
        #[cfg(unix)]
        {
            backend.start_custodied_verified_release(
                &config,
                writable_images,
                verified_runtime.map(|runtime| runtime.release()),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = writable_images;
            if persistent && verified_runtime.is_none() {
                backend.start(&config)
            } else {
                Err(anyhow::anyhow!(
                    "verified runtime custody is unavailable on this host"
                ))
            }
        }
    } else if let Some(runtime) = verified_runtime {
        #[cfg(unix)]
        {
            backend.start_custodied_verified_release(&config, Vec::new(), Some(runtime.release()))
        }
        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!(
                "verified release runtime custody is unavailable on this host"
            ))
        }
    } else {
        backend.start(&config)
    };
    let start = if cli_transient || persistent {
        start
    } else {
        start.context("backend start after signed-plan admission")
    };
    match start {
        Ok(vm_id) => {
            // A VM whose grants could not be applied is running without the
            // bounds it was admitted under; the helper stops it rather than
            // leaving a run whose only record says it was bounded.
            let enforced_grants = if actor_owner.is_some() {
                Some(apply_admitted_grants_with_rollback(
                    backend,
                    &vm_id,
                    &admitted,
                    params.emitter,
                    || stop_actor(&mut actor_owner),
                    FailureAuditPolicy::OwnedAfterConfirmedRollback,
                )?)
            } else if (cli_transient || fork) && admitted.allowed_cpus().is_some() {
                // Neither path reads grants back later, so a launch placed on
                // host cores is checked here: a scope that does not hold the
                // admitted set stops the VM before the caller sees it start.
                // Persistent starts reach the same check after readiness.
                apply_admitted_grants_with_rollback(
                    backend,
                    &vm_id,
                    &admitted,
                    None,
                    || backend.stop(&vm_id).map(|_| ()),
                    FailureAuditPolicy::OwnedAfterConfirmedRollback,
                )
                .map_err(cli_rollback_error)?;
                None
            } else if cli_transient || persistent || fork {
                // The CLI finalizes on teardown; persistent starts finalize
                // after authenticated readiness. Fs-quick forks retain their
                // previous launch-time audit without immediate grant acceptance.
                None
            } else if entrypoint {
                Some(
                    apply_entrypoint_grants_or_undo_launch(
                        backend,
                        &vm_id,
                        &admitted,
                        params.emitter,
                    )
                    .map_err(entrypoint_rollback_error)?,
                )
            } else {
                Some(apply_admitted_grants_or_undo_launch(
                    backend,
                    &vm_id,
                    &admitted,
                    params.emitter,
                )?)
            };

            // Record what this boot committed, so every later admission counts
            // it. A machine running without a record is invisible to the
            // budget, and an undercounted host is precisely the state the
            // budget exists to prevent — so this is fatal, and rolls the
            // launch back the same way an unapplied grant does.
            if actor_owner.is_some() {
                record_charge_with_owned_rollback(
                    backend,
                    &vm_id,
                    &vm_name,
                    &admitted,
                    params.emitter,
                    || stop_actor(&mut actor_owner),
                )?;
            } else if entrypoint {
                record_entrypoint_charge_or_undo_launch(
                    backend,
                    &vm_id,
                    &vm_name,
                    &admitted,
                    params.emitter,
                )
                .map_err(entrypoint_rollback_error)?;
            } else if !cli_transient && !persistent && !fork {
                record_charge_or_undo_launch(backend, &vm_id, &vm_name, &admitted, params.emitter)?;
            }
            if !cli_transient
                && !persistent
                && !fork
                && let Some(emitter) = params.emitter
            {
                if let Err(e) = emitter.emit_launched(admitted.plan(), &backend_name) {
                    if actor_owner.is_some() {
                        return Err(e);
                    }
                    tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
                }
                let record = launch_decision_record(admitted.plan(), &backend_name);
                if let Err(e) = emitter.emit_decision_record(admitted.plan(), record) {
                    if actor_owner.is_some() {
                        return Err(e);
                    }
                    tracing::warn!(error = %e, "audit emit_decision_record for launch failed (non-fatal)");
                }
                if let Some(enforced_grants) = &enforced_grants
                    && let Err(e) = emitter.emit_grants_enforced(
                        admitted.plan(),
                        enforced_grants,
                        backend.kind(),
                    )
                {
                    if actor_owner.is_some() {
                        return Err(e);
                    }
                    tracing::warn!(error = %e, "audit emit_grants_enforced failed (non-fatal)");
                }
            }
            // After the VM is running, so a failed boot leaves no session, and
            // after `plan.launched`, so the campaign's own records follow the
            // launch they belong to. A refusal here fails the boot: a campaign
            // the operator declared and that silently did not open would be
            // reported as a trial that observed nothing.
            if let Some(campaign) = params.assurance
                && let Err(err) =
                    crate::assurance_session::open_for_boot(campaign, &vm_id.0, &admitted)
            {
                // Rolls the launch back rather than returning with the VM up.
                // The session opens after the backend start, so a bare `?`
                // here left a running workload behind while reporting the boot
                // as failed — and an orphan whose only record says it did not
                // start is worse than either outcome alone.
                let undo = UndoLaunch {
                    backend,
                    vm_id: &vm_id,
                    admitted: &admitted,
                    emitter: if cli_transient || fork {
                        None
                    } else {
                        params.emitter
                    },
                    stage: "assurance-session",
                    reason: "the declared assurance campaign could not be opened",
                    err,
                };
                return Err(if cli_transient || fork {
                    cli_rollback_error(undo_cli_launch(undo))
                } else if entrypoint {
                    entrypoint_rollback_error(undo_cli_launch(undo))
                } else {
                    undo_start(undo, &mut actor_owner)
                });
            }
            // Last, so no earlier rollback leaves a mailbox process behind.
            // A grant that cannot be served is refused rather than booting a
            // guest whose mailbox port nobody answers.
            if !persistent {
                let mailbox =
                    if let Some(owner) = actor_owner.as_mut().and_then(|slot| slot.as_mut()) {
                        let mut child = crate::mailbox_process::spawn_for_launch_owned(
                            admitted.plan(),
                            backend,
                            &vm_name,
                            mailbox_posture.as_ref(),
                        )
                        .context("actor mailbox helper spawn/readiness failed")?;
                        let state_dir = mvm_core::config::vm_state_dir(&vm_name);
                        owner.attach_helper(
                            "mailbox",
                            &mut child,
                            &[
                                state_dir.join(mvm_vmm::host::vm_helpers::MAILBOX_PID_FILE),
                                mvm_core::config::vm_mailbox_secret_at(&state_dir),
                            ],
                        )
                    } else {
                        crate::mailbox_process::spawn_for_launch(
                            admitted.plan(),
                            backend,
                            &vm_name,
                            mailbox_posture.as_ref(),
                        )
                        .map(|_| ())
                        .map_err(anyhow::Error::from)
                    };
                if let Err(err) = mailbox {
                    let undo = UndoLaunch {
                        backend,
                        vm_id: &vm_id,
                        admitted: &admitted,
                        emitter: if cli_transient || fork {
                            None
                        } else {
                            params.emitter
                        },
                        stage: "mailbox-process",
                        reason: "the granted guest mailbox could not be served",
                        err,
                    };
                    return Err(if cli_transient || fork {
                        cli_rollback_error(undo_cli_launch(undo))
                    } else if entrypoint {
                        entrypoint_rollback_error(undo_cli_launch(undo))
                    } else {
                        undo_start(undo, &mut actor_owner)
                    });
                }
            }
            // Entrypoint callers previously persisted the plan after their
            // successful boot, including QEMU (which has no bridge sidecar).
            // Keep the lifecycle audit cache independent of bridge eligibility.
            if entrypoint
                && let Err(error) =
                    crate::audit::plan_persist::write_plan(&vm_name, admitted.plan())
            {
                tracing::warn!(%error, "persisting entrypoint plan failed (non-fatal)");
            }
            Ok(StartTailResult {
                vm_id,
                admitted,
                enforced_grants,
                config,
            })
        }
        Err(err) => {
            if let Some(proof) = err
                .downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
                .and_then(|failure| failure.no_dispatch_proof())
            {
                let reconciled = params
                    .emitter
                    .context("runtime cancellation requires durable audit")
                    .and_then(|emitter| {
                        admitted.host_budget.record_runtime_no_dispatch(
                            proof,
                            &vm_name,
                            admitted.plan(),
                            emitter,
                        )
                    });
                return match reconciled {
                    Ok(()) => Err(err),
                    Err(reconcile) => {
                        Err(err
                            .context(format!("runtime cancellation remains held: {reconcile:#}")))
                    }
                };
            }
            let (err, persistent_stop_uncertain) = if persistent {
                classify_persistent_dispatch_error(err)
            } else {
                (err, false)
            };
            if persistent_stop_uncertain {
                crate::audit::unsealed::record_unsealed_end(
                    params.emitter.map(|emitter| (emitter, admitted.plan())),
                    crate::audit::unsealed::UnsealedEnd::new(
                        &vm_name,
                        crate::audit::unsealed::UnsealedReason::StopFailed,
                    )
                    .error(format!("backend-start: {err:#}")),
                );
                return Err(CliStartFailure::UncertainStop(err).into());
            }
            if !cli_transient
                && !fork
                && let Some(emitter) = params.emitter
                && let Err(e) =
                    emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            Err(if cli_transient {
                CliStartFailure::Unrecorded(err).into()
            } else {
                err
            })
        }
    }
}

fn classify_persistent_dispatch_error(error: anyhow::Error) -> (anyhow::Error, bool) {
    match mvm_runtime::backend::release_confirmed_start_failure(error) {
        Ok(error) => (error, false),
        Err(error) => (error, true),
    }
}

/// Start through the ordinary gates while retaining original actor teardown custody.
///
/// The owner slot remains populated after a post-start error. Callers must retain
/// it until cleanup is proved; an error never authorizes a capacity refund.
pub fn start_admitted_owned_actor(
    params: StartAdmittedParams<'_>,
    owner: &mut Option<mvm_runtime::actor_teardown::ActorOwner>,
    before_dispatch: impl FnOnce() -> Result<()>,
) -> Result<StartedMachine> {
    start_owned_admitted_impl(params, owner, None, before_dispatch)
}

/// Start an admitted controller with its original per-boot holder provisioned before activation.
pub fn start_admitted_owned_actor_with_bootstrap(
    params: StartAdmittedParams<'_>,
    owner: &mut Option<mvm_runtime::actor_teardown::ActorOwner>,
    bootstrap: mvm_runtime::actor_teardown::ActorBootstrap,
    before_dispatch: impl FnOnce() -> Result<()>,
) -> Result<StartedMachine> {
    start_owned_admitted_impl(params, owner, Some(bootstrap), before_dispatch)
}

fn start_owned_admitted_impl(
    params: StartAdmittedParams<'_>,
    owner: &mut Option<mvm_runtime::actor_teardown::ActorOwner>,
    bootstrap: Option<mvm_runtime::actor_teardown::ActorBootstrap>,
    before_dispatch: impl FnOnce() -> Result<()>,
) -> Result<StartedMachine> {
    anyhow::ensure!(owner.is_none(), "actor owner slot is already occupied");
    anyhow::ensure!(
        params.emitter.is_some(),
        "actor launch requires durable audit"
    );
    mvm_runtime::actor_teardown::supports_actor_backend(params.backend)?;
    let verified =
        mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&params.config)?;
    let started = start_admitted_with_finalization(
        params,
        verified.as_ref(),
        StartFinalization::Immediate,
        Some(owner),
        bootstrap,
        before_dispatch,
    )?;
    Ok(StartedMachine {
        vm_id: started.vm_id,
        admitted: started.admitted,
        enforced_grants: started
            .enforced_grants
            .expect("actor host start always checks enforced grants"),
    })
}

fn stop_actor(
    slot: &mut Option<&mut Option<mvm_runtime::actor_teardown::ActorOwner>>,
) -> Result<()> {
    let owner = slot
        .as_mut()
        .and_then(|slot| slot.as_mut())
        .ok_or_else(|| anyhow::anyhow!("original actor owner missing"))?;
    let _proof = owner.stop_and_reap()?;
    Ok(())
}

fn undo_start(
    undo: UndoLaunch<'_>,
    slot: &mut Option<&mut Option<mvm_runtime::actor_teardown::ActorOwner>>,
) -> anyhow::Error {
    if slot.is_some() {
        undo_launch_with(
            undo,
            || stop_actor(slot),
            FailureAuditPolicy::OwnedAfterConfirmedRollback,
        )
    } else {
        undo_launch(undo)
    }
}

/// The single admitted-boot entrypoint every driver shares — the CLI's
/// `mvmctl run` / `mvmctl machine run` and the `mvm-client` local backend both reach it, so a
/// workload can never boot on a path that skipped admission.
///
/// Order matters and is fail-closed: synthesize + sign + verify + validity +
/// replay (+ bundle re-verify) run first, and any failure among them returns
/// with **no VM created** — admission is a gate, not a formality. Only once the
/// admission is recorded does this delegate to [`start_admitted`], which owns
/// the rest of the order.
#[tracing::instrument(skip_all)]
pub fn admit_and_start(
    backend: &AnyBackend,
    params: AdmitAndStartParams<'_>,
) -> Result<StartedMachine> {
    let verified =
        mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&params.config)?;
    admit_and_start_with_verified_release(backend, params, verified.as_ref())
}

/// Admit and boot a local launch with one release verification for all gates.
pub(crate) fn admit_and_start_with_verified_release(
    backend: &AnyBackend,
    params: AdmitAndStartParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<StartedMachine> {
    let admitted = admit_synthesized_with_verified_release(backend, &params, verified_runtime)?;
    start_admitted_with_verified_release(
        StartAdmittedParams {
            backend,
            admitted,
            config: params.config,
            policy_bundle: params.policy_bundle,
            emitter: params.emitter,
            assurance: params.assurance,
        },
        verified_runtime,
    )
}

/// Admit a synthesized plan without dispatching it; the caller retains its one-use authority.
pub(crate) fn admit_synthesized_with_verified_release(
    backend: &AnyBackend,
    params: &AdmitAndStartParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<AdmittedPlan> {
    // The tier comes from the backend that is about to boot this plan — the
    // object itself, via its typed discriminant. Nothing here reads a backend
    // name: the grant gate decides which resource controls a run is measured
    // against, and deciding that from a string is how a plan ends up measured
    // against a tier it is not running on.
    let posture = RunPosture::on_backend(params.variant, backend.kind())
        .with_runtime(Some(&params.config))
        .with_verified_runtime(verified_runtime);

    // Synthesize the plan up-front so a refusal can be recorded with the
    // plan context if admission fails. Synthesis failures have no plan to
    // anchor to; they propagate without a chain entry.
    let mut plan = synthesize_plan(params.synthesis).context("synthesizing plan")?;
    if let Some(runtime) = verified_runtime {
        plan.runtime_identity = Some(runtime.identity().clone());
    }

    let admitted_result = admit_plan_for_run(
        &plan,
        params.clock,
        params.ledger,
        params.host_signer_keys_dir,
        params.bundle_ctx,
        params.extension_ctx,
        posture,
    );
    let admitted = match admitted_result {
        Ok(admitted) => admitted,
        Err(err) => {
            if let Some(emitter) = params.emitter
                && err
                    .downcast_ref::<super::topology_binding::TopologyRefusalAudited>()
                    .is_none()
                && let Err(e) =
                    emitter.emit_refused(&plan, "admit_plan_for_run", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_refused failed (non-fatal)");
            }
            return Err(err);
        }
    };

    crate::audit::durability::record_admission(
        params.emitter,
        admitted.plan(),
        admitted.signer_id(),
        params.audit_durability,
    )?;

    Ok(admitted)
}
