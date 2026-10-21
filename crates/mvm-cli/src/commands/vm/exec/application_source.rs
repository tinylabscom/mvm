//! An installed application reference as the source of `run`.
//!
//! `mvmctl run agent/claude@1.0.1` and `mvmctl run --app agent/claude` resolve
//! the reference to the bundle `mvmctl pack pull` installed, after verifying
//! it again, and then continue as `--manifest <bundle-sha256>`: the same plan
//! synthesis, signing and admit-time bundle re-verification a `.mvmpkg` gets.
//!
//! A flag treats its value strictly as a reference. A positional is one only
//! when it parses as a reference and names an installed application, so an
//! OCI image reference or a `.mvmpkg` path goes where it always went.

use anyhow::{Context, Result};
use mvm_core::registry_pack::PackReference;
use mvm_core::registry_pack::application_bundle::{
    ApplicationInstallStore, ApplicationLaunchError, ResolvedApplication,
    names_installed_application, names_installed_policy_pack, resolve_installed_application,
};

use super::RunArgs;

/// Replace an application reference with the installed bundle it resolves to.
pub(in crate::commands) fn apply_application_source(args: &mut RunArgs) -> Result<()> {
    if args.application.is_none() && args.source.is_none() {
        return Ok(());
    }
    let store = ApplicationInstallStore::new(
        mvm_core::config::registry_pack_cache_dir(),
        mvm_core::config::pack_lockfile_path(),
        mvm_core::plan::bundle::BundleRegistry::default_path()?
            .root()
            .to_path_buf(),
    );
    let trust = mvm_core::plan::bundle::FsTrustStore::default_path()?;
    let policy = mvm_core::config::registry_pack_publisher_policy_path();
    settle(
        args,
        |reference| names_installed_application(reference, &store),
        |reference| names_installed_policy_pack(reference, &store),
        |reference| resolve_installed_application(reference, &store, &policy, &trust),
    )
}

/// Record that the plan `plan_id` admitted for run `run_id` boots `resolved`.
/// Written once admission has produced the plan, so the entry names both ids.
pub(in crate::commands) fn record_launch(
    resolved: &ResolvedApplication,
    run_id: &str,
    plan_id: &str,
    log: Option<&std::path::Path>,
) {
    let mut event = mvm_core::policy::audit::event(
        mvm_core::policy::audit::LocalAuditKind::ApplicationLaunch,
    )
    .vm_name(run_id)
    .detail(format!(
        "application={},descriptor_sha256={},bundle_sha256={},run_id={run_id},plan_id={plan_id}",
        resolved.reference, resolved.descriptor_sha256, resolved.bundle_sha256,
    ));
    if let Some(log) = log {
        event = event.to_path(log);
    }
    event.emit();
}

/// A positional that names an installed policy pack is not an OCI image; say
/// so rather than let it fall through to a registry pull.
fn refuse_positional_policy_pack(
    source: Option<&str>,
    names_policy_pack: impl Fn(&PackReference) -> bool,
) -> Result<()> {
    let Some((raw, reference)) =
        source.and_then(|raw| Some((raw, raw.parse::<PackReference>().ok()?)))
    else {
        return Ok(());
    };
    if names_policy_pack(&reference) {
        anyhow::bail!(
            "`{raw}` is installed as a policy pack, not an application, and cannot be run; \
             to run an OCI image of that name use `--image {raw}`"
        );
    }
    Ok(())
}

fn settle(
    args: &mut RunArgs,
    names_installed: impl Fn(&PackReference) -> bool,
    names_policy_pack: impl Fn(&PackReference) -> bool,
    resolve: impl Fn(&PackReference) -> Result<ResolvedApplication, ApplicationLaunchError>,
) -> Result<()> {
    let reference = if let Some(raw) = args.application.take() {
        raw.parse::<PackReference>().with_context(|| {
            format!("`{raw}` is not an application reference (NAMESPACE/NAME[@VERSION])")
        })?
    } else if let Some(reference) = args
        .source
        .as_deref()
        .and_then(|raw| raw.parse::<PackReference>().ok())
        .filter(|reference| names_installed(reference))
    {
        args.source = None;
        reference
    } else {
        refuse_positional_policy_pack(args.source.as_deref(), names_policy_pack)?;
        return Ok(());
    };
    let resolved = resolve(&reference)?;
    eprintln!(
        "[mvm] {} is installed as bundle {}",
        resolved.reference, resolved.bundle_sha256
    );
    args.manifest = Some(resolved.bundle_sha256.clone());
    args.resolved_application = Some(resolved);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "ab";

    fn resolved(reference: &PackReference) -> Result<ResolvedApplication, ApplicationLaunchError> {
        Ok(ResolvedApplication {
            reference: reference.clone(),
            descriptor_sha256: "d".repeat(64),
            bundle_sha256: SHA.repeat(32),
        })
    }

    fn missing(reference: &PackReference) -> Result<ResolvedApplication, ApplicationLaunchError> {
        Err(ApplicationLaunchError::NotInstalled {
            reference: reference.to_string(),
        })
    }

    fn positional(value: &str) -> RunArgs {
        RunArgs {
            source: Some(value.to_string()),
            ..RunArgs::default()
        }
    }

    #[test]
    fn the_launch_entry_names_the_run_and_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let reference: PackReference = "agent/claude@1.0.1".parse().unwrap();
        let resolved = resolved(&reference).unwrap();
        record_launch(&resolved, "run-7", "plan-9", Some(&log));
        let line = std::fs::read_to_string(&log).unwrap();
        let event: mvm_core::policy::audit::LocalAuditEvent =
            serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(
            event.kind,
            mvm_core::policy::audit::LocalAuditKind::ApplicationLaunch
        );
        assert_eq!(event.vm_name.as_deref(), Some("run-7"));
        let detail = event.detail.unwrap();
        for want in [
            "application=agent/claude@1.0.1",
            &format!("descriptor_sha256={}", resolved.descriptor_sha256),
            &format!("bundle_sha256={}", resolved.bundle_sha256),
            "run_id=run-7",
            "plan_id=plan-9",
        ] {
            assert!(detail.contains(want), "{want} missing from {detail}");
        }
    }

    #[test]
    fn a_positional_naming_an_installed_application_becomes_its_bundle() {
        let mut args = positional("agent/claude@1.0.1");
        settle(&mut args, |_| true, |_| false, resolved).unwrap();
        assert_eq!(args.manifest.as_deref(), Some(SHA.repeat(32).as_str()));
        assert!(args.source.is_none() && args.image.is_none());
    }

    #[test]
    fn oci_references_and_archives_keep_their_route() {
        for value in [
            "alpine/curl:latest",
            "alpine",
            "./app.mvmpkg",
            "/tmp/app.mvmpkg",
        ] {
            let mut args = positional(value);
            settle(
                &mut args,
                |_| true,
                |_| false,
                |_| panic!("must not resolve"),
            )
            .unwrap();
            assert_eq!(args.source.as_deref(), Some(value));
            assert!(args.manifest.is_none());
        }
    }

    #[test]
    fn a_positional_naming_an_installed_policy_pack_is_refused_not_routed_to_oci() {
        let mut args = positional("policy/strict@1.0.0");
        let error = settle(
            &mut args,
            |_| false,
            |_| true,
            |_| panic!("must not resolve"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("policy pack") && error.contains("--image"),
            "{error}"
        );
        let mut oci = positional("alpine/curl:latest");
        settle(&mut oci, |_| false, |_| true, resolved).unwrap();
    }

    #[test]
    fn a_positional_reference_that_is_not_installed_is_left_alone() {
        let mut args = positional("agent/claude");
        settle(
            &mut args,
            |_| false,
            |_| false,
            |_| panic!("must not resolve"),
        )
        .unwrap();
        assert_eq!(args.source.as_deref(), Some("agent/claude"));
    }

    #[test]
    fn the_flag_never_falls_back_and_names_the_pull() {
        let mut args = RunArgs {
            application: Some("agent/claude".to_string()),
            ..RunArgs::default()
        };
        let error = settle(&mut args, |_| false, |_| false, missing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("mvmctl pack pull agent/claude"), "{error}");
        assert!(args.manifest.is_none() && args.image.is_none());
    }

    #[test]
    fn the_flag_refuses_a_value_that_is_not_a_reference() {
        let mut args = RunArgs {
            application: Some("alpine/curl:latest".to_string()),
            ..RunArgs::default()
        };
        assert!(settle(&mut args, |_| true, |_| false, resolved).is_err());
    }

    #[test]
    fn the_flag_resolves_through_the_same_bundle_route() {
        let mut args = RunArgs {
            application: Some("agent/claude".to_string()),
            ..RunArgs::default()
        };
        settle(&mut args, |_| false, |_| false, resolved).unwrap();
        assert_eq!(args.manifest.as_deref(), Some(SHA.repeat(32).as_str()));
    }

    fn parse(argv: &[&str]) -> Result<RunArgs, clap::Error> {
        use clap::Parser;
        let cli = crate::commands::Cli::try_parse_from(
            ["mvmctl", "run"].iter().chain(argv.iter()).copied(),
        )?;
        match cli.command {
            crate::commands::Commands::Run(verb) => Ok(verb.machine.run),
            _ => unreachable!("run parses as the run verb"),
        }
    }

    #[test]
    fn the_three_spellings_of_the_flag_parse_to_one_field() {
        for flag in ["-a", "--app", "--application"] {
            let args = parse(&[flag, "agent/claude@1.0.1", "--", "true"]).unwrap();
            assert_eq!(
                args.application.as_deref(),
                Some("agent/claude@1.0.1"),
                "{flag}"
            );
        }
        let args = parse(&["agent/claude", "--", "true"]).unwrap();
        assert_eq!(args.source.as_deref(), Some("agent/claude"));
    }

    #[test]
    fn the_flag_conflicts_with_every_other_source() {
        for other in [
            &["--image", "alpine"][..],
            &["--manifest", "./a.mvmpkg"],
            &["--flake", "."],
            &["agent/claude"],
        ] {
            let mut argv = vec!["--app", "agent/claude"];
            argv.extend_from_slice(other);
            argv.extend(["--", "true"]);
            assert!(parse(&argv).is_err(), "{other:?}");
        }
    }
}
