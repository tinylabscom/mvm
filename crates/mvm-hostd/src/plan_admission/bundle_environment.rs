//! Plan requirements from an authenticated pinned bundle environment.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;
use mvm_core::plan::bundle::{
    BundleManifest, forbidden_capabilities, unbound_environment_secret_slots,
};

/// A verified plan refused by its authenticated bundle environment, for auditing.
///
/// This carries no admission authority and is constructed only after plan and
/// bundle authentication. It lets callers record a refusal against that plan
/// without re-admitting it or parsing an unverified envelope.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct BundleEnvironmentRefused {
    plan: Box<ExecutionPlan>,
    reason: String,
}

impl BundleEnvironmentRefused {
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }
}

/// Called only after both the plan and its pinned bundle have authenticated.
pub(super) fn verify_environment(plan: &ExecutionPlan, manifest: &BundleManifest) -> Result<()> {
    let Some(environment) = manifest.environment() else {
        return Ok(());
    };
    let unbound = unbound_environment_secret_slots(environment, &plan.secrets);
    if !unbound.is_empty() {
        return Err(BundleEnvironmentRefused {
            plan: Box::new(plan.clone()),
            reason: format!(
                "the plan does not meet the bundle's signed environment: required secret slots {} have no binding",
                unbound.join(", ")
            ),
        }
        .into());
    }
    let forbidden = forbidden_capabilities(environment, manifest.security_posture());
    if !forbidden.is_empty() {
        return Err(BundleEnvironmentRefused {
            plan: Box::new(plan.clone()),
            reason: format!(
                "the plan does not meet the bundle's signed environment: capabilities {} exceed the authenticated bundle posture",
                forbidden.join(", ")
            ),
        }
        .into());
    }
    Ok(())
}
