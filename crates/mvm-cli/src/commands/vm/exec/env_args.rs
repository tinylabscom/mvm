//! The environment a run hands its guest: `--env` parsing and the hygiene
//! check over everything the caller supplied.
//!
//! Both `--env` pairs and a launch plan's entrypoint env are written by the
//! caller, so a denied variable in either is refused by name rather than
//! dropped: the caller typed it and is told which one and why. `--allow-env
//! NAME` re-admits one variable by its exact name.

use anyhow::{Context, Result};
use mvm_core::env_hygiene::{EnvFilter, EnvReadmit};
use std::collections::BTreeMap;

/// Parse one `--env KEY=VALUE` argument.
pub(super) fn parse_env_pair(kv: &str) -> Result<(String, String)> {
    let (k, v) = kv
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
    if k.is_empty() {
        anyhow::bail!("--env '{kv}': KEY must not be empty");
    }
    if !mvm_core::vm_backend::is_secret_env_name(k) {
        anyhow::bail!("--env '{kv}': KEY must match [A-Za-z_][A-Za-z0-9_]* (got '{k}')");
    }
    Ok((k.to_string(), v.to_string()))
}

/// Refuse a denied variable in `--env` or in the launch plan's env unless
/// `--allow-env` names it exactly.
pub(super) fn check_run_env(
    allow_env: &[String],
    env: &[(String, String)],
    launch_env: Option<&BTreeMap<String, String>>,
) -> Result<()> {
    let filter = EnvFilter::new(EnvReadmit::from_names(allow_env).context("--allow-env")?);
    refuse(&filter, env.iter().map(|(name, _)| name.as_str()), "--env")?;
    if let Some(launch_env) = launch_env {
        refuse(
            &filter,
            launch_env.keys().map(String::as_str),
            "--launch-plan env",
        )?;
    }
    Ok(())
}

/// The env a launch plan carries, if the run has one.
pub(super) fn launch_env(target: &crate::exec::ExecTarget) -> Option<&BTreeMap<String, String>> {
    match target {
        crate::exec::ExecTarget::LaunchPlan { entrypoint } => Some(&entrypoint.env),
        crate::exec::ExecTarget::Inline { .. } => None,
    }
}

/// Refuse the denied names among `names`, naming `source` and the flag that
/// re-admits one.
pub(in crate::commands) fn refuse<'a>(
    filter: &EnvFilter,
    names: impl IntoIterator<Item = &'a str>,
    source: &str,
) -> Result<()> {
    filter
        .refuse_denied(names)
        .map_err(|denied| anyhow::anyhow!("{source}: {denied} (pass `--allow-env NAME`)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(names: &[&str]) -> Vec<(String, String)> {
        names
            .iter()
            .map(|name| ((*name).to_string(), "value".to_string()))
            .collect()
    }

    #[test]
    fn ordinary_env_passes() {
        check_run_env(&[], &pairs(&["APP_MODE", "PATH"]), None).expect("ordinary names pass");
    }

    #[test]
    fn a_denied_env_pair_is_refused_by_name_without_its_value() {
        let err = check_run_env(
            &[],
            &[("LD_PRELOAD".to_string(), "/tmp/evil-value.so".to_string())],
            None,
        )
        .expect_err("a loader variable refuses");
        let message = format!("{err:#}");
        assert!(message.contains("--env"), "{message}");
        assert!(message.contains("LD_PRELOAD (loader)"), "{message}");
        assert!(message.contains("--allow-env"), "{message}");
        assert!(!message.contains("evil-value"), "{message}");
    }

    #[test]
    fn allow_env_readmits_exactly_the_named_variable() {
        let allow = vec!["PYTHONPATH".to_string()];
        check_run_env(&allow, &pairs(&["PYTHONPATH"]), None).expect("re-admitted");
        let err = check_run_env(&allow, &pairs(&["PYTHONPATH", "PYTHONSTARTUP"]), None)
            .expect_err("only the named variable is re-admitted");
        assert!(format!("{err:#}").contains("PYTHONSTARTUP"));
    }

    #[test]
    fn allow_env_refuses_a_pattern() {
        let err = check_run_env(&["LD_*".to_string()], &pairs(&["LD_PRELOAD"]), None)
            .expect_err("a pattern is never a re-admission");
        assert!(format!("{err:#}").contains("never a pattern"), "{err:#}");
    }

    #[test]
    fn a_denied_launch_plan_variable_is_refused() {
        let launch = BTreeMap::from([("BASH_ENV".to_string(), "/tmp/rc".to_string())]);
        let err = check_run_env(&[], &pairs(&["APP_MODE"]), Some(&launch))
            .expect_err("launch-plan env is caller-authored");
        let message = format!("{err:#}");
        assert!(message.contains("--launch-plan env"), "{message}");
        assert!(message.contains("BASH_ENV (shell)"), "{message}");
        check_run_env(&["BASH_ENV".to_string()], &[], Some(&launch)).expect("re-admitted");
    }

    #[test]
    fn a_session_token_is_refused() {
        let err = check_run_env(&[], &pairs(&["OP_SESSION_team"]), None)
            .expect_err("a vault session token refuses");
        assert!(
            format!("{err:#}").contains("password-manager session"),
            "{err:#}"
        );
    }
}
