//! What a resolved policy puts into the signed plan.
//!
//! `mvmctl policy show --format plan` prints this: the policy folded into a
//! launch with no other flags, then run through the same grant resolution a
//! launch runs, so the grants and egress rules shown are the ones the plan
//! would carry — computed, not described.

use anyhow::Result;
use mvm_contract::grants::Grants;
use mvm_contract::policy::network_policy::HostPort;
use mvm_contract::policy::routes::EgressRoute;
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::manifest::{LaunchFlags, fold};
use super::model::PolicyBody;
use crate::admission::run_grants::{GrantInputs, resolve_run_grants};

/// The plan-bearing values of a resolved policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlanPreview {
    /// The grants the signed plan carries (`None` when nothing is granted).
    pub grants: Option<Grants>,
    /// The egress allow-list the gate enforces. Empty is deny-all.
    pub egress_allow: Vec<HostPort>,
    /// Endpoint routes the plan carries.
    pub routes: Vec<EgressRoute>,
    /// Secret bindings, as `NAME[:HOST,...]`, checked against the stored
    /// allow-lists at launch.
    pub secrets: Vec<String>,
    /// Shares, as `HOST:GUEST:ro|rw`.
    pub mounts: Vec<String>,
    /// Denied variables the policy re-admits.
    pub readmitted_env: Vec<String>,
    /// Variables the workload may be handed, when the policy restricts them.
    pub env_allow: Vec<String>,
    /// Tool privileges: recorded, not enforced.
    pub tools_not_enforced: Vec<String>,
}

/// Preview `policy` under the operator's host configuration.
///
/// # Errors
///
/// A policy the fold or grant resolution refuses — the same refusals a
/// launch would hit.
pub fn preview(policy: &PolicyBody, config: &MvmConfig) -> Result<PlanPreview> {
    let folded = fold(policy, &LaunchFlags::default())?;
    let grants = resolve_run_grants(GrantInputs {
        cpu_limit_millicores: folded.cpu_limit,
        timeout_secs: folded.timeout,
        allow_host: &folded.allow_host,
        peer: &[],
        net: false,
        network_preset: None,
        grants_file: None,
        manifest: None,
        config,
        ai: None,
    })?;
    Ok(PlanPreview {
        egress_allow: grants.network_policy.resolve_rules().unwrap_or_default(),
        grants: grants.plan_grants,
        routes: folded.routes,
        secrets: folded.secret,
        mounts: folded.mounts,
        readmitted_env: folded.allow_env,
        env_allow: policy.env.allow.clone(),
        tools_not_enforced: policy.tools.allow.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_profiles::model::{NetworkSection, ResourcesSection};

    #[test]
    fn the_preview_carries_the_grants_a_launch_would() {
        let policy = PolicyBody {
            network: NetworkSection {
                allow: vec!["api.example.com".into()],
                ..NetworkSection::default()
            },
            resources: ResourcesSection {
                cpu_millicores: Some(500),
                wall_clock_secs: Some(60),
                ..ResourcesSection::default()
            },
            ..PolicyBody::default()
        };
        let preview = preview(&policy, &MvmConfig::default()).unwrap();
        assert_eq!(
            preview.egress_allow,
            vec![HostPort::new("api.example.com", 443)]
        );
        let grants = preview.grants.expect("grants are authored");
        assert!(grants.cpu.is_some() && grants.wall_clock.is_some() && grants.egress.is_some());
    }

    #[test]
    fn an_empty_policy_previews_deny_all_and_no_grants() {
        let preview = preview(&PolicyBody::default(), &MvmConfig::default()).unwrap();
        assert!(preview.grants.is_none());
        assert!(preview.egress_allow.is_empty());
    }
}
