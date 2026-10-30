//! Authenticated application defaults folded through ordinary authored policy.

use mvm_core::plan::EnvironmentDescriptor;

use super::merge::{Layer, ResolvedPolicy, merge_layers};
use super::{FoldedLaunch, LaunchFlags, LayerOrigin, PolicyBody, PolicyError, fold};

/// Apply a signed request ceiling without widening the caller's AI limits.
pub fn with_request_ceiling(
    mut ai: Option<mvm_core::network_policy::AiPolicy>,
    ceiling: Option<mvm_core::network_policy::AiRequestBudget>,
) -> Result<Option<mvm_core::network_policy::AiPolicy>, PolicyError> {
    if let Some(ceiling) = ceiling {
        let ai = ai.get_or_insert_with(mvm_core::network_policy::AiPolicy::metered);
        ai.request_budget = Some(match ai.request_budget {
            Some(current) => current
                .intersect(ceiling)
                .map_err(|reason| PolicyError::new("signed application environment", reason))?,
            None => ceiling,
        });
    }
    Ok(ai)
}

/// Fold signed network defaults without widening an explicit operator selection.
///
/// # Errors
///
/// Invalid policy, launch flags, or actual destinations outside the signed ceiling.
pub fn fold_environment_policy(
    environment: &EnvironmentDescriptor,
    operator: Option<&ResolvedPolicy>,
    flags: &LaunchFlags,
    preset: Option<mvm_core::network_policy::NetworkPreset>,
) -> Result<(PolicyBody, FoldedLaunch), PolicyError> {
    let error = |message: String| PolicyError::new("signed application environment", message);
    let Some(ceiling) = &environment.policy else {
        let policy = operator
            .map(|resolved| resolved.policy.clone())
            .unwrap_or_default();
        let folded = fold(&policy, flags)?;
        return Ok((policy, folded));
    };
    // Keep the authored fold aware of an actual preset even for non-CLI callers.
    let flags = LaunchFlags {
        network_preset: flags.network_preset || preset.is_some(),
        ai: with_request_ceiling(flags.ai.clone(), ceiling.request_budget)?,
        ..flags.clone()
    };
    let mut policy = operator
        .map(|resolved| resolved.policy.clone())
        .unwrap_or_default();
    let network_selected = operator.is_some_and(ResolvedPolicy::network_selected)
        || !flags.allow_host.is_empty()
        || !flags.allow_endpoint.is_empty()
        || flags.net
        || flags.network_preset
        || preset.is_some();
    if !network_selected {
        policy.network.allow = ceiling
            .allow_hosts
            .iter()
            .map(|host| {
                mvm_core::plan::EnvironmentPolicy::parse_authority(host)
                    .map(|authority| authority.to_string())
                    .map_err(|reason| error(reason.to_string()))
            })
            .collect::<Result<_, _>>()?;
    }
    // Canonicalization and deny filtering must have the same meaning as authored policy.
    let policy = merge_layers(&[Layer {
        label: "application launch policy".into(),
        file: None,
        origin: LayerOrigin::User,
        body: policy,
    }])?
    .policy;
    let folded = fold(&policy, &flags)?;
    let mut destinations = folded.allow_host.clone();
    destinations.extend(
        folded
            .routes
            .iter()
            .map(|route| format!("{}:{}", route.host, route.port)),
    );
    for spec in &flags.allow_endpoint {
        let (_, host, port, _) =
            mvm_contract::policy::routes::parse_endpoint_spec(spec).map_err(error)?;
        destinations.push(format!("{host}:{port}"));
    }
    let actual = crate::admission::run_network::resolve_run_network_policy(
        flags.net,
        preset,
        &destinations,
        &[],
    )
    .map_err(|reason| error(reason.to_string()))?
    .with_ai(folded.ai.clone());
    if !mvm_core::plan::environment_network_permitted(environment, &actual) {
        return Err(error(
            "operator network selection exceeds the signed application's allow_hosts ceiling"
                .into(),
        ));
    }
    Ok((policy, folded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fold_environment_policy(
        environment: &EnvironmentDescriptor,
        operator: Option<&PolicyBody>,
        flags: &LaunchFlags,
        preset: Option<mvm_core::network_policy::NetworkPreset>,
    ) -> Result<(PolicyBody, FoldedLaunch), PolicyError> {
        let resolved = operator
            .map(|body| {
                merge_layers(&[Layer {
                    label: "test operator".into(),
                    file: None,
                    origin: LayerOrigin::User,
                    body: body.clone(),
                }])
            })
            .transpose()?;
        super::fold_environment_policy(environment, resolved.as_ref(), flags, preset)
    }

    fn environment(policy: bool) -> EnvironmentDescriptor {
        let mut value = serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": {"argv": ["/bin/agent"]},
        });
        if policy {
            value["policy"] = serde_json::json!({
                "allow_hosts": ["api.anthropic.com:443", "example.com:443"]
            });
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn signed_request_budget_defaults_without_launch_flags() {
        let mut env = environment(true);
        env.policy.as_mut().unwrap().request_budget =
            Some(mvm_core::network_policy::AiRequestBudget {
                model: mvm_core::network_policy::AiBudgetModel::ClaudeHaiku45,
                max_requests: 1,
                max_spend_microusd: 500_000,
            });
        let original = env.clone();
        let (_, folded) = fold_environment_policy(&env, None, &LaunchFlags::default(), None)
            .expect("signed network and request budget must fold together");
        assert_eq!(folded.allow_host.len(), 2);
        assert_eq!(
            folded.ai.as_ref().unwrap().request_budget,
            env.policy.as_ref().unwrap().request_budget
        );
        let actual = crate::admission::run_network::resolve_run_network_policy(
            false,
            None,
            &folded.allow_host,
            &[],
        )
        .unwrap()
        .with_ai(folded.ai);
        assert!(mvm_core::plan::environment_network_permitted(&env, &actual));
        assert!(!mvm_core::plan::environment_network_permitted(
            &env,
            &actual.clone().with_ai(None),
        ));
        let mut widened = actual.ai().unwrap().clone();
        widened.request_budget.as_mut().unwrap().max_spend_microusd += 1;
        assert!(!mvm_core::plan::environment_network_permitted(
            &env,
            &actual.with_ai(Some(widened)),
        ));
        assert_eq!(env, original, "folding must not mutate signed metadata");
    }

    #[test]
    fn signed_request_budget_preserves_narrower_operator_limits_and_token_accounting() {
        use mvm_core::network_policy::{AiBudgetModel, AiPolicy, AiRequestBudget};

        let ceiling = AiRequestBudget {
            model: AiBudgetModel::ClaudeHaiku45,
            max_requests: 1,
            max_spend_microusd: 500_000,
        };
        let mut env = environment(true);
        env.policy.as_mut().unwrap().request_budget = Some(ceiling);
        for (requests, spend) in [(0, 100_000), (1, 500_000), (2, 600_000)] {
            let mut ai = AiPolicy::metered().with_total_budget(100);
            ai.request_budget = Some(AiRequestBudget {
                max_requests: requests,
                max_spend_microusd: spend,
                ..ceiling
            });
            let flags = LaunchFlags {
                ai: Some(ai.clone()),
                ..Default::default()
            };
            let (_, folded) = fold_environment_policy(&env, None, &flags, None).unwrap();
            let actual = folded.ai.unwrap();
            assert_eq!(actual.budget, ai.budget);
            assert_eq!(
                actual.request_budget,
                Some(ai.request_budget.unwrap().intersect(ceiling).unwrap())
            );
            assert_eq!(flags.ai, Some(ai), "caller policy must not be mutated");
        }
        // There is only one reviewed model variant; incompatible model identifiers
        // must fail parsing rather than becoming a typed policy the fold can accept.
        let mut value = serde_json::to_value(&env).unwrap();
        value["policy"]["request_budget"]["model"] = serde_json::json!("claude-haiku-4-5");
        assert!(serde_json::from_value::<EnvironmentDescriptor>(value).is_err());
    }

    #[test]
    fn signed_request_budget_preserves_resource_only_and_offline_operator_choices() {
        let mut env = environment(true);
        env.policy.as_mut().unwrap().request_budget =
            Some(mvm_core::network_policy::AiRequestBudget {
                model: mvm_core::network_policy::AiBudgetModel::ClaudeHaiku45,
                max_requests: 1,
                max_spend_microusd: 500_000,
            });
        let mut policy = PolicyBody::default();
        policy.resources.max_cpus = Some(2);
        let flags = LaunchFlags {
            cpus: 2,
            ..Default::default()
        };
        let (_, resource_only) =
            fold_environment_policy(&env, Some(&policy), &flags, None).unwrap();
        assert_eq!(resource_only.allow_host.len(), 2);
        policy.network.block = Some(true);
        let (_, offline) = fold_environment_policy(&env, Some(&policy), &flags, None).unwrap();
        assert!(offline.allow_host.is_empty());
        assert_eq!(offline.ai, resource_only.ai);
        let (_, preset_offline) = fold_environment_policy(
            &env,
            None,
            &flags,
            Some(mvm_core::network_policy::NetworkPreset::None),
        )
        .unwrap();
        assert!(preset_offline.allow_host.is_empty());
        assert_eq!(preset_offline.ai, resource_only.ai);
        let flags = LaunchFlags {
            allow_host: vec!["api.anthropic.com:443".into()],
            ..flags
        };
        assert!(fold_environment_policy(&env, Some(&policy), &flags, None).is_err());
    }

    #[test]
    fn an_environment_without_a_request_ceiling_preserves_the_operator_ai_policy() {
        let ai = mvm_core::network_policy::AiPolicy::metered().with_total_budget(123);
        let flags = LaunchFlags {
            ai: Some(ai.clone()),
            ..Default::default()
        };
        for has_policy in [false, true] {
            let (_, folded) =
                fold_environment_policy(&environment(has_policy), None, &flags, None).unwrap();
            assert_eq!(folded.ai, Some(ai.clone()));
        }
        assert_eq!(fold(&PolicyBody::default(), &flags).unwrap().ai, Some(ai));
    }

    #[test]
    fn defaults_and_explicit_narrowing_use_the_same_fold() {
        let env = environment(true);
        let (_, defaults) =
            fold_environment_policy(&env, None, &LaunchFlags::default(), None).unwrap();
        assert_eq!(defaults.allow_host.len(), 2);
        let flags = LaunchFlags {
            allow_host: vec!["api.anthropic.com".into()],
            ..Default::default()
        };
        let (_, narrowed) = fold_environment_policy(&env, None, &flags, None).unwrap();
        assert_eq!(narrowed.allow_host, ["api.anthropic.com:443"]);
    }

    #[test]
    fn resolved_policy_selection_survives_denies_removing_all_hosts_or_routes() {
        use super::super::{Platform, PolicySelection, PolicyStore, resolve};

        let dir = tempfile::tempdir().unwrap();
        for authored in [
            "[overrides.network]\nallow = [\"api.anthropic.com:443\"]\ndeny = [\"api.anthropic.com:443\"]\n",
            "[overrides.network]\ndeny = [\"api.anthropic.com:443\"]\n\
             [[overrides.network.routes]]\nid = \"api\"\nhost = \"api.anthropic.com\"\nport = 443\n",
        ] {
            let path = dir.path().join("selected.toml");
            std::fs::write(&path, authored).unwrap();
            let selection = PolicySelection::for_launch(&[path.display().to_string()], None)
                .unwrap()
                .unwrap();
            let resolved = resolve(
                &PolicyStore::at(dir.path()),
                &selection,
                Platform::default(),
            )
            .unwrap();
            assert!(resolved.policy.network.allow.is_empty());
            assert!(resolved.policy.network.routes.is_empty());
            assert!(resolved.network_selected());
            let (_, folded) = super::fold_environment_policy(
                &environment(true),
                Some(&resolved),
                &LaunchFlags::default(),
                None,
            )
            .unwrap();
            assert!(
                folded.allow_host.is_empty(),
                "signed defaults must not reappear"
            );
            assert!(folded.routes.is_empty());
            let flags = LaunchFlags {
                allow_host: vec!["example.com:443".into()],
                ..Default::default()
            };
            let (_, explicit) =
                super::fold_environment_policy(&environment(true), Some(&resolved), &flags, None)
                    .unwrap();
            assert_eq!(explicit.allow_host, ["example.com:443"]);
            let flags = LaunchFlags {
                allow_host: vec!["api.anthropic.com:443".into()],
                ..Default::default()
            };
            assert!(
                super::fold_environment_policy(&environment(true), Some(&resolved), &flags, None)
                    .is_err()
            );
        }
    }

    #[test]
    fn ipv6_denies_normalize_both_hosts_and_patterns_without_losing_ports() {
        let mut env = environment(true);
        env.policy.as_mut().unwrap().allow_hosts =
            vec!["[2001:db8::1]:443".into(), "[2001:db8::1]:8443".into()];
        for deny in [
            "[2001:db8::1]:443",
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:443",
        ] {
            let mut policy = PolicyBody::default();
            policy.network.deny = vec![deny.into()];
            let (_, folded) =
                fold_environment_policy(&env, Some(&policy), &LaunchFlags::default(), None)
                    .unwrap();
            assert_eq!(folded.allow_host, ["2001:db8::1:8443"]);
            for host in [
                "[2001:db8::1]:443",
                "[2001:0db8:0000:0000:0000:0000:0000:0001]:443",
            ] {
                let flags = LaunchFlags {
                    allow_host: vec![host.into()],
                    ..Default::default()
                };
                let error = fold_environment_policy(&env, Some(&policy), &flags, None)
                    .expect_err("equivalent IPv6 spelling must remain denied");
                assert!(error.to_string().contains("denied"));
            }
            let flags = LaunchFlags {
                allow_host: vec!["2001:db8::1:8443".into()],
                ..Default::default()
            };
            let (_, explicit) = fold_environment_policy(&env, Some(&policy), &flags, None).unwrap();
            assert_eq!(explicit.allow_host, ["2001:db8::1:8443"]);
        }
    }

    #[test]
    fn old_schema_resolved_manifests_never_inherit_signed_network_defaults() {
        use super::super::ResolvedManifest;

        for json in [
            r#"{"policy":{"network":{"allow":[],"deny":["api.anthropic.com:443"]}}}"#,
            r#"{"policy":{"resources":{"max_cpus":2}}}"#,
            r#"{"policy":{}}"#,
        ] {
            let manifest = ResolvedManifest::from_json(json.as_bytes(), "old plan", None).unwrap();
            let resolved = manifest.into_resolved("old plan", None).unwrap();
            assert!(resolved.network_selected());
            assert_ne!(resolved.policy.network.block, Some(true));
            let (_, folded) = super::fold_environment_policy(
                &environment(true),
                Some(&resolved),
                &LaunchFlags::default(),
                None,
            )
            .unwrap();
            assert!(folded.allow_host.is_empty());
            let flags = LaunchFlags {
                allow_host: vec!["example.com:443".into()],
                ..Default::default()
            };
            let (_, folded) =
                super::fold_environment_policy(&environment(true), Some(&resolved), &flags, None)
                    .unwrap();
            assert_eq!(folded.allow_host, ["example.com:443"]);
        }
    }

    #[test]
    fn explicit_policy_may_narrow_or_block_but_not_widen() {
        let env = environment(true);
        let mut policy = PolicyBody::default();
        policy.network.allow = vec!["api.anthropic.com:443".into()];
        let (_, narrowed) =
            fold_environment_policy(&env, Some(&policy), &LaunchFlags::default(), None).unwrap();
        assert_eq!(narrowed.allow_host, policy.network.allow);
        policy.network.allow = vec!["unrelated.example:443".into()];
        assert!(
            fold_environment_policy(&env, Some(&policy), &LaunchFlags::default(), None).is_err()
        );
        policy.network.allow.clear();
        policy.network.block = Some(true);
        let (_, blocked) =
            fold_environment_policy(&env, Some(&policy), &LaunchFlags::default(), None).unwrap();
        assert!(blocked.allow_host.is_empty());
    }

    #[test]
    fn denies_filter_defaults_and_flags_cannot_reopen_them() {
        let mut policy = PolicyBody::default();
        policy.network.deny = vec!["*.anthropic.com".into()];
        let (_, narrowed) = fold_environment_policy(
            &environment(true),
            Some(&policy),
            &LaunchFlags::default(),
            None,
        )
        .unwrap();
        assert_eq!(narrowed.allow_host, ["example.com:443"]);
        let flags = LaunchFlags {
            allow_host: vec!["api.anthropic.com".into()],
            ..Default::default()
        };
        assert!(fold_environment_policy(&environment(true), Some(&policy), &flags, None).is_err());
    }

    #[test]
    fn flags_and_presets_cannot_widen_and_legacy_descriptors_do_not_default() {
        let flags = LaunchFlags {
            allow_host: vec!["unrelated.example:443".into()],
            ..Default::default()
        };
        assert!(fold_environment_policy(&environment(true), None, &flags, None).is_err());
        let flags = LaunchFlags {
            net: true,
            ..Default::default()
        };
        assert!(fold_environment_policy(&environment(true), None, &flags, None).is_err());
        let (_, legacy) =
            fold_environment_policy(&environment(false), None, &LaunchFlags::default(), None)
                .unwrap();
        assert!(legacy.allow_host.is_empty());
    }

    #[test]
    fn endpoint_selections_narrow_without_restoring_host_defaults() {
        let flags = LaunchFlags {
            allow_endpoint: vec!["POST https://api.anthropic.com/v1/messages".into()],
            ..Default::default()
        };
        let (_, narrowed) =
            fold_environment_policy(&environment(true), None, &flags, None).unwrap();
        assert!(narrowed.allow_host.is_empty());
        let flags = LaunchFlags {
            allow_endpoint: vec!["GET https://unrelated.example/**".into()],
            ..Default::default()
        };
        assert!(fold_environment_policy(&environment(true), None, &flags, None).is_err());
    }

    #[test]
    fn resource_only_policy_inherits_defaults_and_respects_resource_bounds() {
        let mut policy = PolicyBody::default();
        policy.resources.max_cpus = Some(2);
        let flags = LaunchFlags {
            cpus: 2,
            ..Default::default()
        };
        let (_, folded) =
            fold_environment_policy(&environment(true), Some(&policy), &flags, None).unwrap();
        assert_eq!(folded.allow_host.len(), 2);
        let flags = LaunchFlags { cpus: 3, ..flags };
        assert!(fold_environment_policy(&environment(true), Some(&policy), &flags, None).is_err());
    }

    #[test]
    fn policy_routes_are_explicit_selections_and_remain_inside_the_ceiling() {
        let policy: PolicyBody = serde_json::from_value(serde_json::json!({
            "network": {"routes": [{
                "id": "anthropic",
                "host": "api.anthropic.com",
                "port": 443
            }]}
        }))
        .unwrap();
        let (_, folded) = fold_environment_policy(
            &environment(true),
            Some(&policy),
            &LaunchFlags::default(),
            None,
        )
        .unwrap();
        assert!(folded.allow_host.is_empty());
        assert_eq!(folded.routes.len(), 1);
        let mut outside = policy;
        outside.network.routes[0].host = "unrelated.example".into();
        assert!(
            fold_environment_policy(
                &environment(true),
                Some(&outside),
                &LaunchFlags::default(),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn presets_obey_blocks_denies_and_the_signed_ceiling() {
        use mvm_core::network_policy::NetworkPreset;

        let (_, offline) = fold_environment_policy(
            &environment(true),
            None,
            &LaunchFlags::default(),
            Some(NetworkPreset::None),
        )
        .unwrap();
        assert!(
            offline.allow_host.is_empty(),
            "explicit off must not restore defaults"
        );
        assert!(
            fold_environment_policy(
                &environment(true),
                None,
                &LaunchFlags::default(),
                Some(NetworkPreset::Dev),
            )
            .is_err()
        );
        let mut policy = PolicyBody::default();
        policy.network.block = Some(true);
        assert!(
            fold_environment_policy(
                &environment(true),
                Some(&policy),
                &LaunchFlags::default(),
                Some(NetworkPreset::Dev),
            )
            .is_err()
        );
        policy.network.block = None;
        policy.network.deny = vec!["*.anthropic.com".into()];
        assert!(
            fold_environment_policy(
                &environment(true),
                Some(&policy),
                &LaunchFlags::default(),
                Some(NetworkPreset::Dev),
            )
            .is_err()
        );
    }
}
