//! Plan requirements from an authenticated pinned bundle environment.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;
use mvm_core::plan::bundle::{
    BundleManifest, forbidden_capabilities, unbound_environment_secret_slots,
    unsupported_environment_requirements,
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
pub(super) fn verify_environment(
    plan: &ExecutionPlan,
    manifest: &BundleManifest,
    run: super::RunPosture<'_>,
) -> Result<()> {
    let Some(environment) = manifest.environment() else {
        return Ok(());
    };
    if environment.policy.is_some()
        && !run.runtime_config.is_some_and(|config| {
            mvm_core::plan::environment_network_permitted(environment, &config.network_policy)
        })
    {
        return Err(BundleEnvironmentRefused {
            plan: Box::new(plan.clone()),
            reason: "the actual launch network is missing or exceeds the bundle's signed environment policy".into(),
        }.into());
    }
    let unsupported = unsupported_environment_requirements(environment);
    if !unsupported.is_empty() {
        return Err(BundleEnvironmentRefused {
            plan: Box::new(plan.clone()),
            reason: format!(
                "this host cannot enforce the signed environment requirements {}; \
                 use an environment whose requirements this host supports",
                unsupported.join(", ")
            ),
        }
        .into());
    }
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
