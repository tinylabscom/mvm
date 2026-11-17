//! The secret bindings a transient run is admitted with.
//!
//! Resolution itself lives in `mvm_client::admission::run_secrets`; this is
//! the run surface's one call into it, plus the launch-shape consequence a
//! secret-bearing run carries.

use anyhow::Result;
use mvm_client::admission::run_secrets::{
    RunSecretSpec, manifest_secret_specs, merge_secret_specs, parse_run_secret_specs,
    resolve_launch_secrets,
};
use mvm_client::admission::secrets::ResolvedPlanSecrets;

use super::exec::RunArgs;

/// Resolve every secret binding the run carries — the workload IR's and the
/// `--secret` flags' — before anything boots.
///
/// A secret-bearing run cold-boots: a restored warm parent has already run
/// PID 1, so it cannot receive a per-boot placeholder.
pub(in crate::commands) fn admitted_run_secrets(args: &mut RunArgs) -> Result<ResolvedPlanSecrets> {
    let project = project_secret_specs(args)?;
    let resolved = resolve_launch_secrets(
        args.from_workload_ir.as_deref(),
        &args.secret,
        &project,
        "local",
    )?;
    if !resolved.secrets.is_empty() {
        args.warm_pool_size = 0;
    }
    Ok(resolved)
}

/// The secrets the run's project manifest declares in `[secrets]`: the
/// manifest `--manifest` points at, or the one beside a local `--flake`
/// directory. A registered manifest name or a remote flake has no local file
/// to read, and declares none here.
pub(in crate::commands) fn project_secret_specs(args: &RunArgs) -> Result<Vec<RunSecretSpec>> {
    Ok(super::run_routes::project_manifest(args)?
        .map(|(_, manifest)| manifest_secret_specs(&manifest))
        .unwrap_or_default())
}

/// The run's project secrets merged with its `--secret` flags, for a launch
/// that records references rather than resolving a plan now.
pub(in crate::commands) fn merged_secret_specs(args: &RunArgs) -> Result<Vec<RunSecretSpec>> {
    merge_secret_specs(
        project_secret_specs(args)?,
        parse_run_secret_specs(&args.secret)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_without_secrets_keeps_its_warm_pool_and_opens_no_store() {
        let mut args = RunArgs {
            warm_pool_size: 3,
            ..RunArgs::default()
        };
        let resolved = admitted_run_secrets(&mut args).expect("nothing to resolve");
        assert!(resolved.secrets.is_empty());
        assert_eq!(args.warm_pool_size, 3);
    }

    #[test]
    fn a_flake_directory_manifest_contributes_its_secrets_and_a_flag_narrows_them() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[secrets]\ngitlab = { hosts = [\"gitlab.com\", \"*.gitlab.example\"] }\n",
        )
        .unwrap();
        let mut args = RunArgs {
            flake: Some(project.path().display().to_string()),
            ..RunArgs::default()
        };
        let specs = merged_secret_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].destinations, ["gitlab.com", "*.gitlab.example"]);

        args.secret = vec!["gitlab:ci.gitlab.example".into()];
        assert_eq!(
            merged_secret_specs(&args).unwrap()[0].destinations,
            ["ci.gitlab.example"]
        );

        args.secret = vec!["gitlab:evil.test".into()];
        let err = merged_secret_specs(&args).unwrap_err();
        assert!(format!("{err:#}").contains("widens"), "{err:#}");
    }

    #[test]
    fn a_manifest_edit_after_policy_resolution_cannot_widen_secret_destinations() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("mvm.toml");
        std::fs::write(
            &path,
            "flake = \".\"\n[secrets]\ngitlab = { hosts = [\"gitlab.com\"] }\n",
        )
        .unwrap();
        let mut args = RunArgs {
            flake: Some(project.path().display().to_string()),
            ..RunArgs::default()
        };
        super::super::run_policy::apply_run_policy(&mut args).unwrap();

        std::fs::write(
            &path,
            "flake = \".\"\n[secrets]\ngitlab = { hosts = [\"evil.test\"] }\n",
        )
        .unwrap();

        let specs = merged_secret_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].destinations, ["gitlab.com"]);
    }

    #[test]
    fn a_new_manifest_after_policy_resolution_cannot_declare_secrets() {
        let project = tempfile::tempdir().unwrap();
        let mut args = RunArgs {
            flake: Some(project.path().display().to_string()),
            ..RunArgs::default()
        };
        super::super::run_policy::apply_run_policy(&mut args).unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[secrets]\ngitlab = { hosts = [\"gitlab.com\"] }\n",
        )
        .unwrap();
        assert!(merged_secret_specs(&args).unwrap().is_empty());
    }

    #[test]
    fn a_run_with_no_local_manifest_declares_no_project_secrets() {
        let args = RunArgs {
            flake: Some("github:owner/repo".into()),
            ..RunArgs::default()
        };
        assert!(project_secret_specs(&args).unwrap().is_empty());
    }

    #[test]
    fn a_malformed_secret_flag_refuses_before_boot() {
        let mut args = RunArgs {
            secret: vec!["anthropic:api.anthropic.com:443".to_string()],
            ..RunArgs::default()
        };
        let err = admitted_run_secrets(&mut args).expect_err("a port is not a destination");
        assert!(format!("{err:#}").contains("port"), "{err:#}");
    }

    #[test]
    fn run_and_machine_run_accept_repeatable_secret_specs() {
        use clap::Parser;

        let parsed = crate::commands::Cli::try_parse_from([
            "mvmctl",
            "run",
            "--secret",
            "anthropic",
            "--secret",
            "gh:api.github.com",
            "--",
            "true",
        ])
        .expect("run --secret parses");
        let crate::commands::Commands::Run(parsed) = parsed.command else {
            panic!("expected Commands::Run");
        };
        assert_eq!(
            parsed.machine.run.secret,
            vec!["anthropic", "gh:api.github.com"]
        );

        let parsed = crate::commands::Cli::try_parse_from([
            "mvmctl",
            "machine",
            "run",
            "--secret",
            "anthropic:api.anthropic.com",
            "--",
            "true",
        ])
        .expect("machine run --secret parses");
        let crate::commands::Commands::Machine(machine) = parsed.command else {
            panic!("expected Commands::Machine");
        };
        let crate::commands::machine::MachineAction::Run(parsed) = machine.action else {
            panic!("expected MachineAction::Run");
        };
        assert_eq!(parsed.run.secret, vec!["anthropic:api.anthropic.com"]);
    }
}
