//! Authenticated application defaults folded through ordinary authored policy.

use mvm_core::plan::EnvironmentDescriptor;

use super::merge::{Layer, merge_layers};
use super::{FoldedLaunch, LaunchFlags, LayerOrigin, PolicyBody, PolicyError, fold};

/// Fold signed network defaults without widening an explicit operator selection.
///
/// # Errors
///
/// Invalid policy, launch flags, or actual destinations outside the signed ceiling.
pub fn fold_environment_policy(
    environment: &EnvironmentDescriptor,
    operator: Option<&PolicyBody>,
    flags: &LaunchFlags,
    preset: Option<mvm_core::network_policy::NetworkPreset>,
) -> Result<(PolicyBody, FoldedLaunch), PolicyError> {
    let error = |message: String| PolicyError::new("signed application environment", message);
    let Some(ceiling) = &environment.policy else {
        let policy = operator.cloned().unwrap_or_default();
        let folded = fold(&policy, flags)?;
        return Ok((policy, folded));
    };
    // Keep the authored fold aware of an actual preset even for non-CLI callers.
    let flags = LaunchFlags {
        network_preset: flags.network_preset || preset.is_some(),
        ..flags.clone()
    };
    let mut policy = operator.cloned().unwrap_or_default();
    let network_selected = !policy.network.allow.is_empty()
        || !policy.network.routes.is_empty()
        || policy.network.block == Some(true)
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
    .map_err(|reason| error(reason.to_string()))?;
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
