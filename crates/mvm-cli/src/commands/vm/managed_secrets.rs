use mvm_contract::ir::{App, Entrypoint, EnvValue, SecretMount, Workload};
use mvm_core::plan::{SecretBinding, SecretReleasePolicy, SecretSource};

// allow(secret-debug): `SecretBinding` is a reference type carrying
// only metadata (provider id, binding name, release policy) — it does
// not hold the secret value itself. Raw secret bytes resolve at admit
// time inside `mvm-supervisor` (claim 13: no raw secret crosses the
// channel). The `Debug` derive prints binding refs only, never
// plaintext.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct LoweredPlanSecrets {
    pub secrets: Vec<SecretBinding>,
    pub secret_release: SecretReleasePolicy,
}

pub(super) fn lower_workload_secrets(workload: &Workload) -> LoweredPlanSecrets {
    let mut secrets = Vec::new();
    for app in &workload.apps {
        secrets.extend(lower_app_secret_bindings(app));
    }
    LoweredPlanSecrets {
        secret_release: secret_release_for_bindings(&secrets),
        secrets,
    }
}

pub(super) fn lower_app_secrets(app: &App) -> LoweredPlanSecrets {
    let secrets = lower_app_secret_bindings(app);
    LoweredPlanSecrets {
        secret_release: secret_release_for_bindings(&secrets),
        secrets,
    }
}

fn lower_app_secret_bindings(app: &App) -> Vec<SecretBinding> {
    let mut secrets = Vec::new();
    lower_env_map(&app.env, &mut secrets);
    for entrypoint in &app.entrypoints {
        match entrypoint {
            Entrypoint::Command { env, .. } | Entrypoint::Function { env, .. } => {
                lower_env_map(env, &mut secrets);
            }
        }
    }
    secrets
}

fn lower_env_map(env: &std::collections::BTreeMap<String, EnvValue>, out: &mut Vec<SecretBinding>) {
    for value in env.values() {
        let EnvValue::SecretRef { reference } = value else {
            continue;
        };
        let binding_name = match &reference.mount {
            SecretMount::Env { var } => var.clone(),
            SecretMount::File { path } => path.clone(),
        };
        out.push(SecretBinding {
            name: binding_name,
            source: SecretSource::Keystore {
                address: reference.name.clone(),
            },
        });
    }
}

/// `PlanBound` the moment a plan declares any binding. A plan that lists
/// bindings under `None` would declare capability it can never release, so
/// this is derived from the set rather than chosen by each caller.
pub(in crate::commands::vm) fn secret_release_for_bindings(
    bindings: &[SecretBinding],
) -> SecretReleasePolicy {
    if bindings.is_empty() {
        SecretReleasePolicy::None
    } else {
        SecretReleasePolicy::PlanBound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{Image, Resources, Source};
    use std::collections::BTreeMap;

    fn app_with_envs(
        app_env: BTreeMap<String, EnvValue>,
        ep_env: BTreeMap<String, EnvValue>,
    ) -> App {
        App {
            name: "app".into(),
            source: Source::LocalPath {
                path: ".".into(),
                include: vec!["**".into()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".into()],
            },
            entrypoints: vec![Entrypoint::Command {
                command: vec!["python".into(), "-m".into(), "app".into()],
                working_dir: "/app".into(),
                env: ep_env,
            }],
            env: app_env,
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 256,
                rootfs_size_mb: 512,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
            files: vec![],
            health_check: None,
        }
    }

    fn secret_env_ref(name: &str, var: &str) -> EnvValue {
        EnvValue::SecretRef {
            reference: mvm_contract::ir::SecretRef {
                name: name.into(),
                mount: SecretMount::Env { var: var.into() },
                auth_type: mvm_contract::ir::AuthType::Bearer,
                allowed_hosts: vec!["api.example.com".into()],
                sigv4: None,
            },
        }
    }

    #[test]
    fn lowers_secret_refs_from_app_and_entrypoint_envs() {
        let mut app_env = BTreeMap::new();
        app_env.insert("APP_KEY".into(), secret_env_ref("app-key", "APP_KEY"));
        let mut ep_env = BTreeMap::new();
        ep_env.insert("EP_KEY".into(), secret_env_ref("ep-key", "EP_KEY"));

        let lowered = lower_app_secrets(&app_with_envs(app_env, ep_env));
        assert_eq!(lowered.secret_release, SecretReleasePolicy::PlanBound);
        assert_eq!(lowered.secrets.len(), 2);
        assert_eq!(lowered.secrets[0].name, "APP_KEY");
        assert_eq!(
            lowered.secrets[0].source,
            SecretSource::Keystore {
                address: "app-key".into()
            }
        );
        assert_eq!(lowered.secrets[1].name, "EP_KEY");
    }

    #[test]
    fn empty_secret_set_keeps_release_none() {
        let lowered = lower_app_secrets(&app_with_envs(BTreeMap::new(), BTreeMap::new()));
        assert_eq!(lowered.secret_release, SecretReleasePolicy::None);
        assert!(lowered.secrets.is_empty());
    }
}
