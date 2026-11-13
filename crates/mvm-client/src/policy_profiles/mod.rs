//! Composable policy: groups, profiles, and the resolved manifest.
//!
//! What a workload may do is composed from `mvm.toml`, a grants file,
//! workload IR and flags. The shared `mvm-policy` crate owns the authored
//! policy rules; this module preserves client paths and lowers them into
//! launch inputs:
//!
//! 1. **Groups** ([`model::GroupFile`]) — named, reusable TOML fragments
//!    covering network, secrets, shares, env and resources. A group
//!    may be `required`.
//! 2. **Profiles** ([`model::ProfileFile`]) — `extends`, `groups.include` /
//!    `groups.exclude`, `[[when]]` platform blocks and `[overrides]`,
//!    resolved by [`resolve::resolve`] and merged by [`merge::merge_layers`]
//!    under rules that only narrow what a deny, a block, or a bound says.
//! 3. **The resolved manifest** ([`manifest::ResolvedManifest`]) — the merged
//!    policy as a document, lowered by [`manifest::fold`] into the launch's
//!    own flags so it reaches the signed `ExecutionPlan` through exactly the
//!    grant resolution, synthesis, signing and admission every launch takes.
//!
//! Profiles and groups are found by [`source::PolicyStore`]: a path, a name
//! in the user's policy directory, or a built-in ([`builtin`]).

use std::path::Path;

use anyhow::Context;

pub mod environment;
pub mod manifest;
pub mod preview;
pub mod query;
pub mod resolve;
pub use mvm_policy::{builtin, merge, model, source};

pub use manifest::{FoldedLaunch, LaunchFlags, ResolvedManifest, fold};
pub use mvm_policy::{
    GroupFile, LayerOrigin, LayerSummary, MAX_EXTENDS_DEPTH, Platform, PolicyBody, PolicyError,
    PolicyRef, PolicySelection, PolicyStore, ProfileFile, ProjectPolicy, ResolvedPolicy,
};
pub use resolve::resolve;

/// Select launch policy with operator-configured fallbacks. Explicit CLI or
/// project selection replaces defaults; project network hosts remain attached.
///
/// # Errors
///
/// A selected policy reference is malformed.
pub fn select_launch_policy(
    cli: &[String],
    project: Option<ProjectPolicy>,
    defaults: &[String],
) -> anyhow::Result<Option<PolicySelection>> {
    let project_selects = project
        .as_ref()
        .is_some_and(|policy| policy.profile.is_some() || !policy.include.is_empty());
    if cli.is_empty() && !project_selects {
        PolicySelection::for_launch(defaults, project)
            .context("selecting configured default_policy")
    } else {
        PolicySelection::for_launch(cli, project).map_err(Into::into)
    }
}

/// The policy selected for a launch, before application and plan admission.
#[derive(Debug)]
pub struct SelectedPolicy {
    /// The source to name in diagnostics and telemetry.
    pub label: String,
    /// The resolved policy to fold into the launch.
    pub resolved: ResolvedPolicy,
}

/// Select and resolve a launch policy, with a resolved manifest taking
/// precedence over authored policy and configured defaults.
///
/// # Errors
///
/// Configuration, the selected source, or policy composition is invalid.
pub fn select_for_launch(
    plan: Option<&Path>,
    cli: &[String],
    project: Option<ProjectPolicy>,
    platform: Platform,
) -> anyhow::Result<Option<SelectedPolicy>> {
    let config = mvm_core::user_config::load_strict(None)?;
    if let Some(path) = plan {
        let manifest = ResolvedManifest::read(path)?;
        return Ok(Some(SelectedPolicy {
            label: format!("resolved manifest {}", path.display()),
            resolved: manifest.into_resolved("resolved manifest", Some(path))?,
        }));
    }
    let Some(selection) = select_launch_policy(cli, project, &config.default_policy)? else {
        return Ok(None);
    };
    let label = if !cli.is_empty() {
        format!("policy {}", cli.join(", "))
    } else if let Some(project) = &selection.project {
        format!("the project policy in {}", project.manifest.display())
    } else {
        "policy".to_string()
    };
    let resolved = resolve(&PolicyStore::from_config(), &selection, platform)?;
    Ok(Some(SelectedPolicy { label, resolved }))
}

#[cfg(test)]
mod equivalence_tests;

#[cfg(test)]
mod selection_tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn client_selection_respects_plan_explicit_policy_and_configured_defaults() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        mvm_core::user_config::save(
            &mvm_core::user_config::MvmConfig {
                default_policy: vec!["offline".into()],
                ..Default::default()
            },
            None,
        )
        .unwrap();

        let default = select_for_launch(None, &[], None, Platform::default())
            .unwrap()
            .unwrap();
        assert_eq!(default.resolved.policy.network.block, Some(true));

        let explicit = select_for_launch(None, &["agent-apis".into()], None, Platform::default())
            .unwrap()
            .unwrap();
        assert!(explicit.resolved.policy.network.block.is_none());
        assert!(
            explicit
                .resolved
                .policy
                .network
                .allow
                .contains(&"api.openai.com:443".into())
        );

        let plan = home.path().join("policy.json");
        std::fs::write(&plan, r#"{"policy":{"network":{"allow":["plan.test"]}}}"#).unwrap();
        let selected = select_for_launch(
            Some(&plan),
            &["missing-profile".into()],
            None,
            Platform::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.resolved.policy.network.allow, ["plan.test:443"]);
    }
}
