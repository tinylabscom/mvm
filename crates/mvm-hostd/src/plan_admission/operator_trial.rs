//! Private one-shot preparation and dispatch for operator-admitted trials.
//!
//! This module deliberately does not expose a generic "start prepared" seam.
//! The only constructible capability fixes Required audit durability, retains
//! the launch-scoped runtime evidence, and can be consumed exactly once.

use anyhow::{Context, Result};
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_core::vm_backend::VmId;
use mvm_runtime::AnyBackend;

use super::start::PreparedLaunch;
use super::{
    AdmitAndStartParams, AdmittedPlan, LaunchSource, StartAdmittedParams, StartedMachine,
    admit_synthesized_with_verified_release, prepare_launch,
    start_operator_trial_with_verified_release,
};

/// Exact admitted child retained when an operator-trial rollback is uncertain.
pub(crate) struct OperatorTrialDispatchUncertain {
    pub(crate) vm_id: VmId,
    pub(crate) admitted: AdmittedPlan,
    pub(crate) enforced_grants: Option<EnforcedGrants>,
    pub(crate) uncertainty: anyhow::Error,
}

impl std::fmt::Debug for OperatorTrialDispatchUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperatorTrialDispatchUncertain")
            .field("vm_id", &self.vm_id)
            .field("plan_id", &self.admitted.plan().plan_id)
            .field("enforced_grants", &self.enforced_grants)
            .field("uncertainty", &format_args!("{:#}", self.uncertainty))
            .finish()
    }
}

impl std::fmt::Display for OperatorTrialDispatchUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operator trial {} retains uncertain dispatch custody: {}",
            self.vm_id.0, self.uncertainty
        )
    }
}

impl std::error::Error for OperatorTrialDispatchUncertain {}

pub(super) fn dispatch_error(
    error: anyhow::Error,
    vm_id: VmId,
    admitted: AdmittedPlan,
    enforced_grants: Option<EnforcedGrants>,
) -> anyhow::Error {
    match error.downcast::<super::UndoLaunchFailure>() {
        Ok(rollback) => anyhow::Error::new(OperatorTrialDispatchUncertain {
            vm_id,
            admitted,
            enforced_grants,
            uncertainty: anyhow::Error::new(rollback),
        }),
        Err(error) => error,
    }
}

pub(super) fn classify_start_error(
    error: anyhow::Error,
) -> std::result::Result<anyhow::Error, anyhow::Error> {
    mvm_runtime::backend::release_confirmed_start_failure(error)
}

/// A prepared operator trial. Its fields and constructor stay inside this module.
#[must_use = "dropping this value abandons its one-shot admitted trial"]
pub(crate) struct PreparedOperatorTrial<'a> {
    backend: &'a AnyBackend,
    prepared: PreparedLaunch<AdmittedPlan>,
    policy_bundle: Option<&'a mvm_core::policy::PolicyBundle>,
    emitter: &'a crate::audit::emitter::AuditEmitter,
    assurance: &'a crate::assurance_session::CampaignRequest,
}

/// Attach, verify once, sign and durably admit an operator trial.
///
/// The baseline legacy bundle runtime remains accepted by the existing
/// selected-runtime verifier and does not acquire a release identity. Portable
/// runtime support is not projected into the operator configuration surface.
///
/// # Errors
///
/// Refuses attachment, selected-runtime verification, signed admission, or
/// Required audit durability before a backend can start.
pub(crate) fn prepare<'a>(
    backend: &'a AnyBackend,
    params: AdmitAndStartParams<'a>,
) -> Result<PreparedOperatorTrial<'a>> {
    prepare_with_attachment(backend, params, |config| {
        if runtime_selection_is_absent(config) {
            crate::run::attach_guest_runtime_selection(config, backend.name())
                .context("resolving guest runtime for admitted assurance boot")
        } else {
            Ok(None)
        }
    })
}

fn prepare_with_attachment<'a>(
    backend: &'a AnyBackend,
    mut params: AdmitAndStartParams<'a>,
    attach: impl FnOnce(
        &mut mvm_core::vm_backend::VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
) -> Result<PreparedOperatorTrial<'a>> {
    anyhow::ensure!(
        params.audit_durability == crate::audit::durability::AuditDurability::Required,
        "operator trial admission requires durable audit"
    );
    let emitter = params
        .emitter
        .context("operator trial admission requires an audit emitter")?;
    let assurance = params
        .assurance
        .context("operator trial admission requires a campaign binding")?;
    let policy_bundle = params.policy_bundle;
    let config = std::mem::take(&mut params.config);
    let prepared = prepare_launch(
        LaunchSource::OperatorTrial {
            backend_kind: backend.kind(),
        },
        config,
        attach,
        |config, verified_runtime| {
            // Admission receives the exact config prepared above and the same
            // Arc-backed evidence retained by the dispatch capability.
            params.config = config.clone();
            admit_synthesized_with_verified_release(backend, &params, verified_runtime)
        },
    )?;
    Ok(PreparedOperatorTrial {
        backend,
        prepared,
        policy_bundle,
        emitter,
        assurance,
    })
}

#[cfg(test)]
pub(crate) fn fixture_with_attachment<'a>(
    backend: &'a AnyBackend,
    params: AdmitAndStartParams<'a>,
    attach: impl FnOnce(
        &mut mvm_core::vm_backend::VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
) -> Result<PreparedOperatorTrial<'a>> {
    prepare_with_attachment(backend, params, attach)
}

impl PreparedOperatorTrial<'_> {
    #[cfg(test)]
    pub(crate) fn retained_release_ptr(&self) -> Option<usize> {
        self.prepared
            .verified_runtime
            .as_ref()
            .map(|runtime| runtime.release() as *const _ as usize)
    }

    #[cfg(test)]
    pub(crate) fn admitted_runtime_archive_sha256(&self) -> Option<&str> {
        self.prepared
            .admission
            .plan()
            .runtime_identity
            .as_ref()
            .map(|identity| identity.archive_sha256.as_str())
    }

    /// Consume the sole dispatch authority through the shared final gates.
    ///
    /// # Errors
    ///
    /// Refuses a changed runtime/config, final host gate, backend start, or
    /// post-start enforcement failure using the shared rollback policy.
    pub(crate) fn dispatch(self) -> Result<StartedMachine> {
        let PreparedLaunch {
            config,
            verified_runtime,
            admission: admitted,
        } = self.prepared;
        start_operator_trial_with_verified_release(
            StartAdmittedParams {
                backend: self.backend,
                admitted,
                config,
                policy_bundle: self.policy_bundle,
                emitter: Some(self.emitter),
                assurance: Some(self.assurance),
            },
            verified_runtime.as_deref(),
        )
    }
}

fn runtime_selection_is_absent(config: &mvm_core::vm_backend::VmStartConfig) -> bool {
    config.runtime_overlay_path.is_none()
        && config.runtime_overlay_verity_path.is_none()
        && config.runtime_overlay_roothash.is_none()
        && config.runtime_overlay_version.is_none()
        && config.initrd_path.is_none()
        && config.runtime_release_proof.is_none()
        && config.legacy_bundle_runtime.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_legacy_selection_is_not_replaced_by_cached_release() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let key_id = mvm_core::plan::bundle::key_id_from_pubkey(&key.verifying_key());
        let config = mvm_core::vm_backend::VmStartConfig {
            legacy_bundle_runtime: Some(mvm_core::vm_backend::LegacyBundleRuntimeProof {
                archive: "/operator/runtime.mvmpkg".into(),
                pin: mvm_core::plan::bundle::PlanArtifact::new("a".repeat(64), &[0; 64], key_id),
            }),
            ..Default::default()
        };
        assert!(!runtime_selection_is_absent(&config));
    }
}
