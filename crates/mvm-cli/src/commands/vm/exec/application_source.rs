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
use mvm_client::policy_profiles::environment::with_request_ceiling;
use mvm_core::registry_pack::PackReference;
use mvm_core::registry_pack::application_bundle::{
    ApplicationInstallStore, ApplicationLaunchError, ResolvedApplication,
    names_installed_application, names_installed_policy_pack, resolve_installed_application,
};

use super::RunArgs;

/// Refuse routes whose synthesis cannot retain the application descriptor identity.
pub(in crate::commands) fn require_bound_route(
    application: Option<&ResolvedApplication>,
    persistent: bool,
    attach: bool,
) -> Result<()> {
    anyhow::ensure!(
        application.is_none() || (!persistent && !attach),
        "application references require foreground plan-bound launch without persistent options or --attach"
    );
    Ok(())
}

/// Refuse request dimensions the application entrypoint route cannot preserve.
pub(in crate::commands) fn require_entrypoint_request(args: &RunArgs) -> Result<()> {
    if args.resolved_application.is_none() {
        return Ok(());
    }
    anyhow::ensure!(
        args.grants_file.is_none()
            && args.cpu_limit.is_none()
            && !args.dry_run
            && args.launch_plan.is_none()
            && args.peer.is_empty()
            && args.host_service.is_empty()
            && args.assets.is_empty()
            && args.receipt.is_none()
            && !args.gpu
            && args.gpu_device.is_none()
            && args.mounts.is_empty()
            && args.env.is_empty()
            && args.allow_env.is_empty()
            && args
                .applied_policy
                .as_ref()
                .is_none_or(|policy| policy.tools.to_tool_rules().is_empty()),
        "application --entrypoint cannot yet preserve --grants-file, --cpu-limit, \
         --dry-run, --launch-plan, --peer, --host-service, --asset, --receipt, \
         GPU options, --mount, --env, --allow-env or policy tool rules"
    );
    Ok(())
}

/// Read defaults only after the installed application resolver authenticated its bundle.
pub(in crate::commands) fn environment(
    args: &RunArgs,
) -> Result<Option<mvm_core::plan::EnvironmentDescriptor>> {
    let Some(application) = &args.resolved_application else {
        return Ok(None);
    };
    mvm_client::admission::bundle_environment::installed_bundle_environment(
        &application.bundle_sha256,
    )
}

/// Signed sizing must be applied before the operator policy resource fold.
pub(in crate::commands) fn apply_entrypoint_resource_defaults(args: &mut RunArgs) -> Result<()> {
    if let Some(environment) = environment(args)? {
        super::environment_defaults::apply(args, &environment);
    }
    Ok(())
}

/// Apply a signed subtractive request ceiling while retaining token-accounting flags.
pub(in crate::commands) fn ai_policy(
    args: &RunArgs,
) -> Result<Option<mvm_core::network_policy::AiPolicy>> {
    if let Some(ai) = &args.applied_ai_policy {
        return Ok(Some(ai.clone()));
    }
    let ai = crate::commands::shared::resolve_ai_policy(args.ai_token_budget);
    let ceiling = environment(args)?
        .and_then(|env| env.policy)
        .and_then(|policy| policy.request_budget);
    with_request_ceiling(ai, ceiling).map_err(Into::into)
}

/// Fill only slots not already satisfied by the operator's folded selections.
pub(in crate::commands) fn apply_entrypoint_secret_defaults(args: &mut RunArgs) -> Result<()> {
    let Some(environment) = environment(args)? else {
        return Ok(());
    };
    if environment.required_secret_slots().next().is_none() {
        return Ok(());
    }
    let service = mvm_client::secret::SecretService::local()
        .context("opening the local secret service for application slots")?;
    apply_required_secret_defaults(args, &environment, &service)
}

fn apply_required_secret_defaults(
    args: &mut RunArgs,
    environment: &mvm_core::plan::EnvironmentDescriptor,
    service: &mvm_client::secret::SecretService,
) -> Result<()> {
    let slots = environment.required_secret_slots().collect::<Vec<_>>();
    if slots.is_empty() {
        return Ok(());
    }
    let specs = crate::commands::vm::run_secrets::merged_secret_specs(args)?;
    let explicit = mvm_client::admission::run_secrets::run_secret_refs(service, "local", &specs)?;
    let missing = slots
        .into_iter()
        .filter(|slot| {
            !explicit
                .iter()
                .any(|reference| reference.placeholder_var.as_deref() == Some(*slot))
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    let metadata = service
        .list("local")
        .context("listing host secret bindings")?;
    let selected = select_slot_bindings(&missing, &metadata)?;
    // The ordinary policy fold ran first; its denies also bind automatically added names.
    if let Some(policy) = &args.applied_policy {
        let mut secret = args.secret.clone();
        secret.extend(selected.iter().cloned());
        mvm_client::policy_profiles::fold(
            policy,
            &mvm_client::policy_profiles::LaunchFlags {
                secret,
                declared_secrets: specs.iter().map(|spec| spec.name.clone()).collect(),
                ..Default::default()
            },
        )
        .context("applying operator policy to automatic application secret bindings")?;
    }
    args.secret.extend(selected);
    let specs = crate::commands::vm::run_secrets::merged_secret_specs(args)?;
    mvm_client::admission::run_secrets::run_secret_refs(service, "local", &specs)?;
    Ok(())
}

fn select_slot_bindings(
    slots: &[&str],
    metadata: &[mvm_client::secret::SecretMetadata],
) -> Result<Vec<String>> {
    slots
        .iter()
        .map(|slot| {
            let eligible = metadata
                .iter()
                .filter(|meta| {
                    meta.binding.as_ref().is_some_and(|binding| {
                        binding
                            .provider
                            .as_deref()
                            .and_then(|provider| {
                                mvm_contract::service_catalog::builtin().find(provider).cloned()
                            })
                            .is_some_and(|provider| provider.env_var.is_some())
                            && mvm_client::admission::run_secrets::guest_env_var_for(
                                &meta.name, binding,
                            )
                            .is_ok_and(|var| var == *slot)
                    })
                })
                .collect::<Vec<_>>();
            anyhow::ensure!(
                eligible.len() == 1,
                "application requires secret slot {slot}; found {} eligible host bindings; \
                 select exactly one with --secret NAME, or configure one provider-bound host secret",
                eligible.len()
            );
            let [selected] = eligible.as_slice() else {
                anyhow::bail!("application secret selection requires exactly one binding");
            };
            Ok(selected.name.clone())
        })
        .collect()
}

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
    anyhow::ensure!(
        args.source.is_none()
            && args.image.is_none()
            && args.manifest.is_none()
            && args.flake.is_none()
            && args.deployment.is_none()
            && !args.runtime_pack
            && args.runtime.is_none(),
        "an application reference cannot be combined with another boot source"
    );
    args.registry_pack_image = Some(mvm_core::registry_pack::PackPin::new(
        resolved.reference.clone(),
        mvm_core::packs::Sha256Hex::new(&resolved.descriptor_sha256)?,
    )?);
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

    #[test]
    fn signed_request_ceiling_defaults_without_flags_and_cannot_widen_operator_limits() {
        use mvm_core::network_policy::{AiBudgetModel, AiPolicy, AiRequestBudget};
        let ceiling = AiRequestBudget {
            model: AiBudgetModel::ClaudeHaiku45,
            max_requests: 1,
            max_spend_microusd: 500_000,
        };
        let defaults = with_request_ceiling(None, Some(ceiling)).unwrap().unwrap();
        assert_eq!(defaults.request_budget, Some(ceiling));
        assert!(defaults.metering);
        let mut operator = AiPolicy::metered().with_total_budget(100);
        operator.request_budget = Some(AiRequestBudget {
            max_spend_microusd: 400_000,
            ..ceiling
        });
        let folded = with_request_ceiling(Some(operator.clone()), Some(ceiling))
            .unwrap()
            .unwrap();
        assert_eq!(folded.request_budget.unwrap().max_spend_microusd, 400_000);
        assert_eq!(folded.budget, operator.budget);
        assert_eq!(
            with_request_ceiling(Some(operator.clone()), None).unwrap(),
            Some(operator)
        );
        assert_eq!(with_request_ceiling(None, None).unwrap(), None);
    }

    const SHA: &str = "ab";

    fn metadata(name: &str, provider: Option<&str>) -> mvm_client::secret::SecretMetadata {
        mvm_client::secret::SecretMetadata {
            tenant: "local".into(),
            name: name.into(),
            binding: Some(
                serde_json::from_value(serde_json::json!({
                    "auth_type": "bearer",
                    "allowed_hosts": ["api.anthropic.com"],
                    "provider": provider,
                }))
                .unwrap(),
            ),
            referenced_by: Vec::new(),
        }
    }

    fn secret_fixture(names: &[&str]) -> (tempfile::TempDir, mvm_client::secret::SecretService) {
        use mvm_client::secret::{SecretAudit, SecretService, SecretValueInput};
        use mvm_core::crypto::secret_store::FileSecretStore;
        use mvm_hostd::keyholder::FileBindingStore;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(
                dir.path().join("values"),
            )))
            .bindings(Arc::new(FileBindingStore::with_dir(
                dir.path().join("bindings"),
            )))
            .machines_root(dir.path().join("machines"))
            .audit(SecretAudit::with_path(dir.path().join("audit.jsonl")))
            .build()
            .unwrap();
        for name in names {
            service
                .put(
                    "local",
                    name,
                    SecretValueInput::new("unit-test-value".into()),
                )
                .unwrap();
            service
                .bind(
                    "local",
                    name,
                    metadata(name, Some("anthropic")).binding.unwrap(),
                )
                .unwrap();
        }
        (dir, service)
    }

    fn secret_environment() -> mvm_core::plan::EnvironmentDescriptor {
        serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": {"argv": ["/etc/mvm/entrypoint"]},
            "secret_slots": [{"name": "ANTHROPIC_API_KEY", "required": true}],
        }))
        .unwrap()
    }

    #[test]
    fn policy_and_plan_selections_precede_ambiguous_application_defaults() {
        let (dir, service) = secret_fixture(&["first", "second"]);
        let profile = dir.path().join("choose-first.toml");
        std::fs::write(
            &profile,
            "[overrides.secrets]\nbind = [{ name = \"first\" }]\n",
        )
        .unwrap();
        let plan = dir.path().join("choose-first.json");
        std::fs::write(
            &plan,
            r#"{"policy":{"secrets":{"bind":[{"name":"first"}]}}}"#,
        )
        .unwrap();
        for use_plan in [false, true] {
            let mut args = RunArgs {
                cpus: 2,
                memory: "512M".into(),
                policy: if use_plan {
                    Vec::new()
                } else {
                    vec![profile.display().to_string()]
                },
                plan: use_plan.then(|| plan.clone()),
                ..Default::default()
            };
            crate::commands::vm::run_policy::apply_run_policy(&mut args).unwrap();
            assert_eq!(args.secret, ["first"]);
            apply_required_secret_defaults(&mut args, &secret_environment(), &service).unwrap();
            assert_eq!(args.secret, ["first"]);
        }
    }

    #[test]
    fn explicit_and_unique_secret_defaults_are_preserved() {
        let (_dir, service) = secret_fixture(&["first", "second"]);
        let mut args = RunArgs {
            secret: vec!["second".into()],
            ..Default::default()
        };
        apply_required_secret_defaults(&mut args, &secret_environment(), &service).unwrap();
        assert_eq!(args.secret, ["second"]);
        args.secret.clear();
        assert!(
            apply_required_secret_defaults(&mut args, &secret_environment(), &service).is_err()
        );
        let (_single, service) = secret_fixture(&["only"]);
        apply_required_secret_defaults(&mut args, &secret_environment(), &service).unwrap();
        assert_eq!(args.secret, ["only"]);
    }

    #[test]
    fn automatic_selection_obeys_folded_secret_denies() {
        let (_dir, service) = secret_fixture(&["only"]);
        let mut policy = mvm_client::policy_profiles::PolicyBody::default();
        policy.secrets.deny = vec!["only".into()];
        let mut args = RunArgs {
            applied_policy: Some(policy),
            ..Default::default()
        };
        let error =
            apply_required_secret_defaults(&mut args, &secret_environment(), &service).unwrap_err();
        assert!(format!("{error:#}").contains("denied"));
        assert!(args.secret.is_empty());
    }

    #[test]
    fn required_slots_select_exactly_one_provider_bound_metadata_row() {
        let rows = vec![
            metadata("work-key", Some("anthropic")),
            metadata("other-key", Some("openai")),
            metadata("ANTHROPIC_API_KEY", None),
        ];
        assert_eq!(
            select_slot_bindings(&["ANTHROPIC_API_KEY"], &rows).unwrap(),
            ["work-key"]
        );
        assert!(select_slot_bindings(&["UNRELATED_KEY"], &rows).is_err());
        assert!(select_slot_bindings(&["ANTHROPIC_API_KEY"], &[]).is_err());
        assert!(
            select_slot_bindings(
                &["ANTHROPIC_API_KEY"],
                &[metadata("ANTHROPIC_API_KEY", Some("unknown-provider"))],
            )
            .is_err()
        );
        let ambiguous = vec![
            metadata("first", Some("anthropic")),
            metadata("second", Some("anthropic")),
        ];
        let error = select_slot_bindings(&["ANTHROPIC_API_KEY"], &ambiguous)
            .unwrap_err()
            .to_string();
        assert!(error.contains("2 eligible host bindings") && error.contains("--secret"));
        assert!(select_slot_bindings(&[], &ambiguous).unwrap().is_empty());
    }

    #[test]
    fn application_sources_cannot_silently_replace_another_source() {
        let mut args = RunArgs {
            application: Some("agent/claude".into()),
            source: Some("alpine".into()),
            ..Default::default()
        };
        assert!(settle(&mut args, |_| true, |_| false, resolved).is_err());
        assert_eq!(args.source.as_deref(), Some("alpine"));
        assert!(args.resolved_application.is_none());
    }

    #[test]
    fn application_routes_and_unforwarded_dimensions_fail_closed() {
        let application = resolved(&"agent/claude@2.0.0".parse().unwrap()).unwrap();
        for (persistent, attach) in [(true, false), (false, true), (true, true)] {
            assert!(require_bound_route(Some(&application), persistent, attach).is_err());
            require_bound_route(None, persistent, attach).unwrap();
        }
        require_bound_route(Some(&application), false, false).unwrap();
        let mut args = RunArgs {
            resolved_application: Some(application),
            ..Default::default()
        };
        require_entrypoint_request(&args).unwrap();
        args.env.push("MODE=dev".into());
        assert!(require_entrypoint_request(&args).is_err());
        args.env.clear();
        args.grants_file = Some("/operator/grants.json".into());
        assert!(require_entrypoint_request(&args).is_err());
    }

    fn resolved(reference: &PackReference) -> Result<ResolvedApplication, ApplicationLaunchError> {
        let reference = if reference.version().is_some() {
            reference.clone()
        } else {
            format!("{reference}@1.0.1")
                .parse()
                .expect("test application reference is exact")
        };
        Ok(ResolvedApplication {
            reference,
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
        let pin = args
            .registry_pack_image
            .as_ref()
            .expect("application descriptor pin reaches admission");
        assert_eq!(pin.reference().to_string(), "agent/claude@1.0.1");
        assert_eq!(pin.manifest_sha256().as_str(), "d".repeat(64));
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
        let mut args = positional("agent/claude@1.0.1");
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
