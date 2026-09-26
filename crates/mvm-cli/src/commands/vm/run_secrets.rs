//! The secret bindings a transient run is admitted with.
//!
//! Resolution itself lives in `mvm_client::admission::run_secrets`; this is
//! the run surface's one call into it, plus the launch-shape consequence a
//! secret-bearing run carries.

use anyhow::Result;
use mvm_client::admission::run_secrets::resolve_launch_secrets;
use mvm_client::admission::secrets::ResolvedPlanSecrets;

use super::exec::RunArgs;

/// Resolve every secret binding the run carries — the workload IR's and the
/// `--secret` flags' — before anything boots.
///
/// A secret-bearing run cold-boots: a restored warm parent has already run
/// PID 1, so it cannot receive a per-boot placeholder.
pub(in crate::commands) fn admitted_run_secrets(args: &mut RunArgs) -> Result<ResolvedPlanSecrets> {
    let resolved = resolve_launch_secrets(args.from_workload_ir.as_deref(), &args.secret, "local")?;
    if !resolved.secrets.is_empty() {
        args.warm_pool_size = 0;
    }
    Ok(resolved)
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
        assert_eq!(parsed.run.secret, vec!["anthropic", "gh:api.github.com"]);

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
