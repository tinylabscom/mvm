//! The post-admission tail every admitted boot shares, and the one-call
//! admit-and-boot entry point.

use super::admit::admit_plan_for_run;
use super::assurance_runtime::verify_selected_runtime;
use super::rollback::{
    UndoLaunch, UndoLaunchFailure, apply_admitted_grants_or_undo_launch,
    record_charge_or_undo_launch, undo_cli_launch, undo_launch,
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
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::AnyBackend;

/// CLI transient boots keep their completion narrative with the caller.
enum StartFinalization {
    /// Record launch and failures at the host dispatch boundary.
    Immediate,
    /// Defer success until confirmed transient teardown.
    CliTransient {
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    },
    /// Defer acceptance until the persistent guest proves authenticated readiness.
    Persistent {
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    },
}

/// Distinguish an already-audited pack refusal, a CLI-owned failure, and an uncertain stop.
#[derive(Debug, thiserror::Error)]
pub enum CliStartFailure {
    #[error("{0:#}")]
    Recorded(anyhow::Error),
    #[error("{0:#}")]
    Unrecorded(anyhow::Error),
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

struct StartTailResult {
    vm_id: VmId,
    admitted: AdmittedPlan,
    enforced_grants: Option<EnforcedGrants>,
    config: VmStartConfig,
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

/// Start a locally admitted release using this launch's authenticated archive.
pub(crate) fn start_admitted_with_verified_release(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<StartedMachine> {
    let started =
        start_admitted_with_finalization(params, verified_runtime, StartFinalization::Immediate)?;
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
    )
    .map(|started| started.vm_id)
}

fn start_admitted_with_finalization(
    params: StartAdmittedParams<'_>,
    verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    finalization: StartFinalization,
) -> Result<StartTailResult> {
    let cli_transient = matches!(finalization, StartFinalization::CliTransient { .. });
    let persistent = matches!(finalization, StartFinalization::Persistent { .. });
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
        } else if !persistent {
            verify_selected_runtime(&params.config).map_err(|error| ("guest-runtime", error))?;
        }
        let (config, built_runtime) = final_gates::run_post_admission_gates(
            params.config,
            &admitted,
            backend.kind(),
            params.policy_bundle,
        )?;
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
        if persistent
            && let Some(emitter) = params.emitter
            && let Err(e) =
                emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
        {
            tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
        }
        return Err(err);
    }
    if persistent && super::persists_plan_before_start(backend.name()) {
        super::stash_plan_for_bridge(&config).inspect_err(|err| {
            if let Some(emitter) = params.emitter
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
    // Spent before the backend starts, so an admission that reached dispatch
    // can never authorize another launch, whatever the start's outcome.
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
    let start = if let StartFinalization::CliTransient { writable_images }
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
            let enforced_grants = if cli_transient || persistent {
                // The CLI finalizes on teardown; persistent starts finalize
                // after authenticated readiness. Neither accepts here.
                None
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
            if !cli_transient && !persistent {
                record_charge_or_undo_launch(backend, &vm_id, &vm_name, &admitted, params.emitter)?;
            }
            if !cli_transient
                && !persistent
                && let Some(emitter) = params.emitter
            {
                if let Err(e) = emitter.emit_launched(admitted.plan(), &backend_name) {
                    tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
                }
                let record = launch_decision_record(admitted.plan(), &backend_name);
                if let Err(e) = emitter.emit_decision_record(admitted.plan(), record) {
                    tracing::warn!(error = %e, "audit emit_decision_record for launch failed (non-fatal)");
                }
                if let Some(enforced_grants) = &enforced_grants
                    && let Err(e) = emitter.emit_grants_enforced(admitted.plan(), enforced_grants)
                {
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
                    emitter: if cli_transient { None } else { params.emitter },
                    stage: "assurance-session",
                    reason: "the declared assurance campaign could not be opened",
                    err,
                };
                return Err(if cli_transient {
                    cli_rollback_error(undo_cli_launch(undo))
                } else {
                    undo_launch(undo)
                });
            }
            // Last, so no earlier rollback leaves a mailbox process behind.
            // A grant that cannot be served is refused rather than booting a
            // guest whose mailbox port nobody answers.
            if !persistent
                && let Err(err) = crate::mailbox_process::spawn_for_launch(
                    admitted.plan(),
                    backend,
                    &vm_name,
                    mailbox_posture.as_ref(),
                )
            {
                let undo = UndoLaunch {
                    backend,
                    vm_id: &vm_id,
                    admitted: &admitted,
                    emitter: if cli_transient { None } else { params.emitter },
                    stage: "mailbox-process",
                    reason: "the granted guest mailbox could not be served",
                    err: err.into(),
                };
                return Err(if cli_transient {
                    cli_rollback_error(undo_cli_launch(undo))
                } else {
                    undo_launch(undo)
                });
            }
            Ok(StartTailResult {
                vm_id,
                admitted,
                enforced_grants,
                config,
            })
        }
        Err(err) => {
            if !cli_transient
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
