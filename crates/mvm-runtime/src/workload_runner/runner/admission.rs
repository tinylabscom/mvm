//! Admitted network surfaces decoded for workload launch.

use anyhow::{Context, Result};

pub(super) fn admitted_network_limits(
    plan_json: Option<&str>,
) -> Result<mvm_core::plan::NetworkLimits> {
    plan_json
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan network limits")?
        .map(|plan| plan.effective_network_limits())
        .transpose()
        .context("validate admitted plan network limits")
        .map(Option::unwrap_or_default)
}

pub(super) fn admitted_ingress(
    plan_json: Option<&str>,
) -> Result<Vec<mvm_core::plan::IngressMapping>> {
    let plan = plan_json
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan ingress")?;
    if let Some(plan) = &plan {
        plan.validate_ingress()
            .context("validate admitted plan ingress")?;
    }
    Ok(plan.map_or_else(Vec::new, |plan| plan.ingress))
}
