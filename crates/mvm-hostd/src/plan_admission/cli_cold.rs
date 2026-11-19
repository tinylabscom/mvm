//! One-shot CLI cold authority prepared before warm/template/cold selection.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;
use mvm_core::vm_backend::{StandbyHandle, VmId, VmStartConfig};
use mvm_runtime::AnyBackend;

use super::start::{
    LaunchAdmission, LaunchSource, PreparedLaunch, StartAdmittedParams, WarmClaimDispatch,
    claim_cli_transient, prepare_launch, start_cli_transient,
};

/// Inputs for preparing one admitted CLI cold launch without starting a backend.
pub struct PrepareCliColdParams<'a> {
    /// The selected backend whose enforcement tier shapes admission.
    pub backend: &'a AnyBackend,
    /// Source-materialized config before runtime attachment and admission lowering.
    pub config: VmStartConfig,
}

/// Opaque, one-shot authority for the admitted CLI cold alternative.
///
/// The exact config and launch-scoped runtime evidence stay private. Signed-plan
/// JSON is only a projection and cannot construct this capability.
pub struct PreparedCliCold<C> {
    prepared: PreparedLaunch<LaunchAdmission<C>>,
    backend_kind: mvm_core::vm_backend::BackendKind,
}

/// A CLI cold capability after its launch authority was spent.
pub struct DispatchedCliCold<C> {
    plan: ExecutionPlan,
    emitter: crate::audit::emitter::AuditEmitter,
    continuation: C,
}

/// Result of trying the prepared authority against a selected warm parent.
pub enum PreparedCliWarmClaim<C> {
    /// The warm child owns the authority; cold dispatch is no longer possible.
    Claimed {
        claim: mvm_runtime::backend::OwnedWarmClaim,
        dispatched: DispatchedCliCold<C>,
    },
    /// The reservation disappeared before dispatch; the exact authority remains pending.
    ReservationLost(Box<PreparedCliCold<C>>),
    /// Dispatch reached a refusal that spent the authority.
    Refused {
        error: anyhow::Error,
        dispatched: DispatchedCliCold<C>,
    },
}

impl<C> PreparedCliCold<C> {
    /// The exact signed plan retained by this capability.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        self.prepared.admission.admitted.plan()
    }

    /// Read-only caller continuation retained alongside launch authority.
    #[must_use]
    pub fn continuation(&self) -> &C {
        &self.prepared.admission.continuation
    }

    /// The exact lowered config retained for later selection and dispatch.
    #[must_use]
    pub fn config(&self) -> &VmStartConfig {
        &self.prepared.config
    }

    /// Compare the legacy identity projections without treating them as authority.
    ///
    /// # Errors
    /// Refuses changed name, rootfs, signed-plan JSON or policy-bundle JSON.
    pub fn verify_projection(&self, config: &VmStartConfig) -> Result<()> {
        anyhow::ensure!(
            config.name == self.prepared.config.name,
            "launch identity differs from prepared CLI cold config"
        );
        anyhow::ensure!(
            config.rootfs_path == self.prepared.config.rootfs_path,
            "launch rootfs differs from prepared CLI cold config"
        );
        anyhow::ensure!(
            config.plan_json == self.prepared.config.plan_json,
            "legacy launch plan projection differs from prepared CLI cold authority"
        );
        anyhow::ensure!(
            config.bundle_json == self.prepared.config.bundle_json,
            "legacy launch policy projection differs from prepared CLI cold authority"
        );
        Ok(())
    }
}

impl<C> DispatchedCliCold<C> {
    /// Split the immutable audit owner from source-specific continuation state.
    #[must_use]
    pub fn into_parts(self) -> (ExecutionPlan, crate::audit::emitter::AuditEmitter, C) {
        (self.plan, self.emitter, self.continuation)
    }
}

/// Attach, verify and durably admit one CLI cold alternative without starting it.
///
/// # Errors
/// Propagates attachment, selected-runtime verification, admission and lowering
/// failures. No backend start occurs in this function.
pub fn prepare_cli_cold<C>(
    params: PrepareCliColdParams<'_>,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<LaunchAdmission<C>>,
) -> Result<PreparedCliCold<C>> {
    let backend_kind = params.backend.kind();
    let prepared = prepare_launch(
        LaunchSource::CliCold { backend_kind },
        params.config,
        attach,
        admit,
    )?;
    Ok(PreparedCliCold {
        prepared,
        backend_kind,
    })
}

/// Spend a prepared CLI cold capability through the final host gates.
///
/// The continuation is returned on both success and refusal so the CLI remains
/// the owner of its deferred completion narrative.
pub fn start_prepared_cli_cold<C>(
    prepared: PreparedCliCold<C>,
    backend: &AnyBackend,
    writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
) -> (DispatchedCliCold<C>, Result<VmId>) {
    let PreparedCliCold {
        prepared:
            PreparedLaunch {
                config,
                verified_runtime,
                admission,
            },
        backend_kind,
    } = prepared;
    let LaunchAdmission {
        admitted,
        emitter,
        policy_bundle,
        continuation,
    } = admission;
    let plan = admitted.plan().clone();
    let result = if backend.kind() != backend_kind {
        Err(anyhow::anyhow!(
            "CLI cold dispatch selected backend {} after preparing {}",
            backend.kind().as_str(),
            backend_kind.as_str()
        ))
    } else {
        start_cli_transient(
            StartAdmittedParams {
                backend,
                admitted,
                config,
                policy_bundle: policy_bundle.as_ref(),
                emitter: Some(&emitter),
                assurance: None,
            },
            verified_runtime.as_deref(),
            writable_images,
        )
    };
    (
        DispatchedCliCold {
            plan,
            emitter,
            continuation,
        },
        result,
    )
}

/// Retire an unselected prepared capability and return its audit continuation.
#[must_use]
pub fn abandon_prepared_cli_cold<C>(prepared: PreparedCliCold<C>) -> DispatchedCliCold<C> {
    let LaunchAdmission {
        admitted,
        emitter,
        policy_bundle: _,
        continuation,
    } = prepared.prepared.admission;
    DispatchedCliCold {
        plan: admitted.plan().clone(),
        emitter,
        continuation,
    }
}

/// Try a selected warm parent with the exact authority prepared before selection.
pub fn claim_prepared_cli_cold<C>(
    prepared: PreparedCliCold<C>,
    backend: &AnyBackend,
    ctx: &mvm_runtime::workload_runner::ClaimContext<'_>,
    handle: &StandbyHandle,
) -> PreparedCliWarmClaim<C> {
    let PreparedCliCold {
        prepared:
            PreparedLaunch {
                config,
                verified_runtime,
                admission,
            },
        backend_kind,
    } = prepared;
    let LaunchAdmission {
        admitted,
        emitter,
        policy_bundle,
        continuation,
    } = admission;
    let plan = admitted.plan().clone();
    if backend.kind() != backend_kind {
        return PreparedCliWarmClaim::Refused {
            error: anyhow::anyhow!(
                "CLI warm dispatch selected backend {} after preparing {}",
                backend.kind().as_str(),
                backend_kind.as_str()
            ),
            dispatched: DispatchedCliCold {
                plan,
                emitter,
                continuation,
            },
        };
    }
    let retained_config = config.clone();
    match claim_cli_transient(
        backend,
        admitted,
        config,
        policy_bundle.as_ref(),
        verified_runtime.as_deref(),
        ctx,
        handle,
    ) {
        Ok(WarmClaimDispatch::Claimed(claim)) => PreparedCliWarmClaim::Claimed {
            claim,
            dispatched: DispatchedCliCold {
                plan,
                emitter,
                continuation,
            },
        },
        Ok(WarmClaimDispatch::ReservationLost(admitted)) => {
            PreparedCliWarmClaim::ReservationLost(Box::new(PreparedCliCold {
                prepared: PreparedLaunch {
                    config: retained_config,
                    verified_runtime,
                    admission: LaunchAdmission {
                        admitted: *admitted,
                        emitter,
                        policy_bundle,
                        continuation,
                    },
                },
                backend_kind,
            }))
        }
        Err(error) => PreparedCliWarmClaim::Refused {
            error,
            dispatched: DispatchedCliCold {
                plan,
                emitter,
                continuation,
            },
        },
    }
}
