//! `--policy`, `--plan`, and the project's `[policy]`: folding an authored
//! policy into a launch's own flags before anything else reads them.
//!
//! Resolution and the merge rules live in `mvm_client::policy_profiles`. What this
//! does is pick the source (`--plan`; otherwise `--policy` and the project
//! manifest the run names — its `[policy]` table and `[network] allow_hosts`),
//! resolve it on this host and the backend the run will use, and write the
//! result back into `RunArgs`. Every later step —
//! grant resolution, route resolution, secret binding, the mount and env
//! checks, plan synthesis, signing, admission — then runs on those flags
//! exactly as if they had been typed, which is what makes a profile and the
//! equivalent flags produce the same signed plan.

use anyhow::{Context, Result};
use mvm_client::policy_profiles::{
    LaunchFlags, Platform, PolicySelection, PolicyStore, ProjectPolicy, ResolvedManifest, fold,
    resolve,
};

use super::exec::RunArgs;
use crate::ui;

/// The authored policy a launch runs under, if it names one.
struct Selected {
    label: String,
    policy: mvm_client::policy_profiles::PolicyBody,
    notes: Vec<String>,
    backend_conditioned: bool,
}

fn select(args: &RunArgs) -> Result<Option<Selected>> {
    if let Some(path) = &args.plan {
        let manifest = ResolvedManifest::read(path)?;
        return Ok(Some(Selected {
            label: format!("resolved manifest {}", path.display()),
            policy: manifest.policy,
            notes: Vec::new(),
            backend_conditioned: false,
        }));
    }
    let project = super::run_routes::project_manifest(args)?
        .map(|(path, manifest)| ProjectPolicy::from_manifest(&path, &manifest));
    let Some(selection) = PolicySelection::for_launch(&args.policy, project)? else {
        return Ok(None);
    };
    let label = if !args.policy.is_empty() {
        format!("policy {}", args.policy.join(", "))
    } else if let Some(project) = &selection.project {
        format!("the project policy in {}", project.manifest.display())
    } else {
        "policy".to_string()
    };
    let resolved = resolve(&PolicyStore::from_config(), &selection, run_platform(args))?;
    Ok(Some(Selected {
        label,
        policy: resolved.policy,
        notes: resolved.notes,
        backend_conditioned: resolved.backend_conditioned,
    }))
}

/// This host, and the backend the run asks for or the host would pick.
fn run_platform(args: &RunArgs) -> Platform {
    let requested = args.hypervisor.clone().or_else(|| {
        ["MVM_HYPERVISOR", "MVM_BACKEND"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(|value| value.to_string_lossy().trim().to_ascii_lowercase())
            .find(|value| !value.is_empty())
    });
    let backend = requested.as_deref().map_or_else(
        || mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name()),
        mvm_client::backend_kind_for,
    );
    Platform::current(Some(backend))
}

fn launch_flags(args: &RunArgs) -> Result<LaunchFlags> {
    let mut env_names = args
        .env
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(name, _)| name.to_string())
                .with_context(|| format!("--env '{pair}': expected KEY=VALUE"))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(path) = &args.launch_plan {
        for name in crate::exec::load_launch_plan(std::path::Path::new(path))?
            .env
            .into_keys()
        {
            if !env_names.contains(&name) {
                env_names.push(name);
            }
        }
    }
    let mut declared_secrets = super::run_secrets::project_secret_specs(args)?
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    if let Some(workload) =
        mvm_client::admission::secrets::load_workload_ir(args.from_workload_ir.as_deref())?
    {
        for app in &workload.apps {
            for name in app.env.keys() {
                if !env_names.contains(name) {
                    env_names.push(name.clone());
                }
            }
            for entrypoint in &app.entrypoints {
                let env = match entrypoint {
                    mvm_contract::ir::Entrypoint::Command { env, .. }
                    | mvm_contract::ir::Entrypoint::Function { env, .. } => env,
                };
                for name in env.keys() {
                    if !env_names.contains(name) {
                        env_names.push(name.clone());
                    }
                }
            }
        }
        for reference in mvm_client::admission::secrets::workload_machine_refs(&workload, "local") {
            if !declared_secrets.contains(&reference.name) {
                declared_secrets.push(reference.name);
            }
        }
    }
    Ok(LaunchFlags {
        allow_host: args.allow_host.clone(),
        net: args.net,
        network_preset: args.network_preset.is_some(),
        allow_endpoint: args.allow_endpoint.clone(),
        cpu_limit: args.cpu_limit,
        timeout: args.timeout,
        secret: args.secret.clone(),
        declared_secrets,
        mounts: args.mounts.clone(),
        env_names,
        allow_env: args.allow_env.clone(),
        cpus: args.cpus,
        memory_mib: u64::from(
            mvm_core::util::parse_human_size(&args.memory).context("Invalid --memory")?,
        ),
    })
}

/// Fold the launch's authored policy, if it has one, into `args`.
///
/// # Errors
///
/// A policy that does not resolve, or a flag that asks for something the
/// policy denies, blocks, or bounds — named.
pub(in crate::commands) fn apply_run_policy(args: &mut RunArgs) -> Result<()> {
    let Some(selected) = select(args)? else {
        return Ok(());
    };
    for note in &selected.notes {
        ui::warn(&format!("policy: {note}"));
    }
    let folded = fold(&selected.policy, &launch_flags(args)?)
        .with_context(|| format!("applying {}", selected.label))?;
    args.allow_host = folded.allow_host;
    args.policy_routes = folded.routes;
    args.cpu_limit = folded.cpu_limit;
    args.timeout = folded.timeout;
    args.secret = folded.secret;
    args.mounts = folded.mounts;
    args.allow_env = folded.allow_env;
    args.policy_backend = selected
        .backend_conditioned
        .then_some(run_platform(args).backend)
        .flatten();
    args.applied_policy = Some(selected.policy);
    tracing::info!(policy = %selected.label, "running under an authored policy");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn isolated() -> (TestEnv, tempfile::TempDir) {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    #[test]
    fn a_run_that_names_no_policy_is_untouched() {
        let (_env, _home) = isolated();
        let mut args = RunArgs {
            allow_host: vec!["a.test".into()],
            ..RunArgs::default()
        };
        let before = format!("{args:?}");
        apply_run_policy(&mut args).unwrap();
        assert_eq!(format!("{args:?}"), before);
    }

    #[test]
    fn a_built_in_profile_becomes_the_equivalent_flags() {
        let (_env, _home) = isolated();
        let mut args = RunArgs {
            policy: vec!["agent-apis".into()],
            allow_host: vec!["extra.test".into()],
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        for host in ["api.anthropic.com:443", "github.com:443", "extra.test:443"] {
            assert!(
                args.allow_host.contains(&host.to_string()),
                "{:?}",
                args.allow_host
            );
        }
    }

    #[test]
    fn a_blocked_policy_refuses_a_host_flag() {
        let (_env, _home) = isolated();
        let mut args = RunArgs {
            policy: vec!["offline".into()],
            allow_host: vec!["a.test".into()],
            ..RunArgs::default()
        };
        let err = apply_run_policy(&mut args).unwrap_err();
        assert!(format!("{err:#}").contains("blocks the network"), "{err:#}");
    }

    #[test]
    fn several_policies_compose_in_flag_order_and_the_last_wins() {
        let (_env, home) = isolated();
        let base = home.path().join("base.toml");
        std::fs::write(&base, "[overrides.network]\nallow = [\"a.test\"]\n").unwrap();
        let team = home.path().join("team.toml");
        std::fs::write(
            &team,
            "[overrides.network]\nallow = [\"b.test\"]\ndeny = [\"a.test\"]\n",
        )
        .unwrap();
        let mut args = RunArgs {
            policy: vec![base.display().to_string(), team.display().to_string()],
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        assert_eq!(args.allow_host, ["b.test:443".to_string()]);

        // JSON composes the same way, and a JSON profile file is a path.
        let json = home.path().join("mine.json");
        std::fs::write(&json, r#"{"overrides":{"network":{"allow":["c.test"]}}}"#).unwrap();
        let mut args = RunArgs {
            policy: vec![
                base.display().to_string(),
                team.display().to_string(),
                json.display().to_string(),
            ],
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        assert_eq!(
            args.allow_host,
            ["b.test:443".to_string(), "c.test:443".to_string()]
        );
    }

    #[test]
    fn a_pack_reference_without_an_installed_pack_points_at_pull() {
        let (_env, _home) = isolated();
        let mut args = RunArgs {
            policy: vec!["acme/agent".into()],
            ..RunArgs::default()
        };
        let err = apply_run_policy(&mut args).unwrap_err();
        let shown = format!("{err:#}");
        assert!(shown.contains("mvmctl pull"), "{shown}");
        assert!(shown.contains("acme/agent"), "{shown}");
    }

    #[test]
    fn a_project_policy_table_applies_and_a_policy_flag_replaces_it() {
        let (_env, _home) = isolated();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[policy]\nprofile = \"dev-network\"\n",
        )
        .unwrap();
        let flake = project.path().display().to_string();
        let mut args = RunArgs {
            flake: Some(flake.clone()),
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        assert!(args.allow_host.contains(&"pypi.org:443".to_string()));

        let mut replaced = RunArgs {
            flake: Some(flake),
            policy: vec!["agent-apis".into()],
            ..RunArgs::default()
        };
        apply_run_policy(&mut replaced).unwrap();
        assert!(!replaced.allow_host.contains(&"pypi.org:443".to_string()));
        assert!(
            replaced
                .allow_host
                .contains(&"api.openai.com:443".to_string())
        );
    }

    #[test]
    fn a_projects_network_allow_hosts_reach_the_run_without_any_policy() {
        let (_env, _home) = isolated();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[network]\nallow_hosts = [\"api.example.com\"]\n",
        )
        .unwrap();
        let mut args = RunArgs {
            flake: Some(project.path().display().to_string()),
            allow_host: vec!["b.test".into()],
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        assert_eq!(args.allow_host, ["api.example.com:443", "b.test:443"]);
    }

    #[test]
    fn a_resolved_manifest_applies_like_its_profile() {
        let (_env, _home) = isolated();
        let dir = tempfile::tempdir().unwrap();
        let plan = dir.path().join("resolved.json");
        std::fs::write(
            &plan,
            r#"{"policy":{"network":{"allow":["a.test"]},"resources":{"wall_clock_secs":30}}}"#,
        )
        .unwrap();
        let mut args = RunArgs {
            plan: Some(plan.clone()),
            ..RunArgs::default()
        };
        apply_run_policy(&mut args).unwrap();
        assert_eq!(args.allow_host, ["a.test:443"]);
        assert_eq!(args.timeout, Some(30));

        std::fs::write(&plan, r#"{"plan":{},"signature":"AAAA"}"#).unwrap();
        let err = apply_run_policy(&mut RunArgs {
            plan: Some(plan),
            ..RunArgs::default()
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("never trusted"), "{err:#}");
    }

    #[test]
    fn a_policy_reaches_workload_ir_secrets() {
        let (_env, home) = isolated();
        let profile = home.path().join("deny-secret.toml");
        std::fs::write(&profile, "[overrides.secrets]\ndeny = [\"anthropic\"]\n").unwrap();
        let workload = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/agent-workload/workload.json");
        let mut args = RunArgs {
            policy: vec![profile.display().to_string()],
            from_workload_ir: Some(workload),
            ..RunArgs::default()
        };
        let error = apply_run_policy(&mut args).expect_err("denied IR secret must be refused");
        assert!(format!("{error:#}").contains("anthropic"));
    }

    #[test]
    fn a_policy_reaches_launch_plan_environment() {
        let (_env, home) = isolated();
        let profile = home.path().join("deny-env.toml");
        std::fs::write(&profile, "[overrides.env]\ndeny = [\"DEBUG\"]\n").unwrap();
        let launch = home.path().join("launch.json");
        std::fs::write(
            &launch,
            r#"{"entrypoint":{"command":["echo"],"env":{"DEBUG":"1"}}}"#,
        )
        .unwrap();
        let mut args = RunArgs {
            policy: vec![profile.display().to_string()],
            launch_plan: Some(launch.display().to_string()),
            ..RunArgs::default()
        };
        let error = apply_run_policy(&mut args).expect_err("denied launch env must be refused");
        assert!(format!("{error:#}").contains("DEBUG"));
    }
}
