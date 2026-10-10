//! Public launch-registration bytes, not an admission capability.
//!
//! Caller possession and even a host signature do not authorize installation.
//! The supervisor must independently establish trusted local admission provenance
//! before accepting these bytes.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::entrypoint_delegation::{
    RegistrationBinding, RegistrationChallenge, RegistrationProof,
};
use crate::crypto::entrypoint_identity::EnrolledIdentity;
use crate::plan::ExecutionPlan;

/// Untrusted wire data carried only by an explicitly opted-in launch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerRegistration {
    pub vm: String,
    /// The trusted launcher's expectation, fixed before asking for possession.
    /// A later producer's proof must never supply or replace this expectation.
    pub expected: RegistrationChallenge,
    pub proof: RegistrationProof,
}

impl std::fmt::Debug for CallerRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallerRegistration").finish_non_exhaustive()
    }
}

impl CallerRegistration {
    /// Prepare fresh coordinates for one concrete launch. This does not admit
    /// the supplied plan or authorize registration of the supplied identity.
    pub fn challenge_for_plan(
        vm: &str,
        plan: &ExecutionPlan,
        identity: EnrolledIdentity,
        now: u64,
    ) -> Result<RegistrationChallenge> {
        crate::naming::validate_vm_name(vm)?;
        RegistrationChallenge::fresh(
            RegistrationBinding {
                tenant: plan.tenant.0.clone(),
                instance: format!("{vm}/{}", Uuid::new_v4()),
                plan_id: plan.plan_id.0.clone(),
                plan_nonce: plan.nonce.clone(),
                run: Uuid::new_v4(),
                producer: Uuid::new_v4(),
                session: Uuid::new_v4(),
                not_before: u64::try_from(plan.valid_from.timestamp())
                    .context("invalid registration validity start")?,
                not_after: u64::try_from(plan.valid_until.timestamp())
                    .context("invalid registration validity end")?,
            },
            identity,
            now,
        )
        .map_err(Into::into)
    }

    /// Check a trusted startup record against the independently verified plan
    /// and concrete launch name. This is not an untrusted producer admission API.
    pub fn verify_context(
        &self,
        vm: &str,
        plan: &ExecutionPlan,
        now: u64,
    ) -> Result<crate::crypto::entrypoint_delegation::VerifiedCallerProof> {
        let binding = &self.expected.binding;
        let prefix = format!("{vm}/");
        let instance = binding
            .instance
            .strip_prefix(&prefix)
            .context("caller registration instance mismatch")?;
        anyhow::ensure!(
            !Uuid::parse_str(instance)?.is_nil(),
            "invalid caller instance"
        );
        anyhow::ensure!(
            self.vm == vm
                && binding.tenant == plan.tenant.0
                && binding.plan_id == plan.plan_id.0
                && binding.plan_nonce == plan.nonce
                && binding.not_before == u64::try_from(plan.valid_from.timestamp())?
                && binding.not_after == u64::try_from(plan.valid_until.timestamp())?,
            "caller registration context mismatch"
        );
        self.proof.verify(&self.expected, now).map_err(Into::into)
    }
}
