//! Secret-binding resolution shared by every admitted launch path.
//!
//! This module handles metadata only. It turns workload declarations or
//! persistent-machine references into plan bindings; raw secret bytes remain
//! inside the host-side substitution endpoint and never enter these types.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::ir::{App, Entrypoint, EnvValue, SecretMount, Workload};
use mvm_core::plan::{SecretBinding, SecretReleasePolicy, SecretSource};

use crate::secret::{MachineSecretRef, SecretService};

// allow(secret-debug): bindings contain provider addresses and guest-facing
// names only. They are references, never secret values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedPlanSecrets {
    pub secrets: Vec<SecretBinding>,
    pub secret_release: SecretReleasePolicy,
}

impl ResolvedPlanSecrets {
    #[must_use]
    pub fn from_bindings(bindings: Vec<SecretBinding>) -> Self {
        Self {
            secret_release: release_for_bindings(&bindings),
            secrets: bindings,
        }
    }

    #[must_use]
    pub fn from_machine_refs(references: &[MachineSecretRef]) -> Self {
        let bindings = references
            .iter()
            .filter_map(|reference| {
                reference
                    .placeholder_var
                    .as_ref()
                    .or(reference.guest_path.as_ref())
                    .map(|name| SecretBinding {
                        name: name.clone(),
                        source: SecretSource::Keystore {
                            address: reference.name.clone(),
                        },
                    })
            })
            .collect();
        Self::from_bindings(bindings)
    }
}

pub fn load_workload_ir(workload_ir_path: Option<&Path>) -> Result<Option<Workload>> {
    let Some(ir_path) = workload_ir_path else {
        return Ok(None);
    };
    let bytes = std::fs::read(ir_path)
        .with_context(|| format!("reading workload IR at {}", ir_path.display()))?;
    let workload = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing workload IR at {}", ir_path.display()))?;
    Ok(Some(workload))
}

pub fn resolve_workload_secrets(workload_ir_path: Option<&Path>) -> Result<ResolvedPlanSecrets> {
    Ok(load_workload_ir(workload_ir_path)?
        .as_ref()
        .map(lower_workload_secrets)
        .unwrap_or_default())
}

/// Load and validate the metadata-only references recorded beside a persistent
/// machine spec, then lower them through the same binding seam as Workload IR.
/// An unreadable sidecar or invalid reference refuses admission.
pub fn resolve_machine_secrets(machine: &str) -> Result<ResolvedPlanSecrets> {
    let references = load_machine_secret_refs(machine)?;
    if references.is_empty() {
        return Ok(ResolvedPlanSecrets::default());
    }
    SecretService::local()
        .context("opening the local secret service")?
        .validate_for_admission("local", &references)
        .context("validating persistent-machine secret references")?;
    Ok(ResolvedPlanSecrets::from_machine_refs(&references))
}

pub fn load_machine_secret_refs(machine: &str) -> Result<Vec<MachineSecretRef>> {
    Ok(
        crate::secret::refs::load_refs(&mvm_core::config::machine_state_root(), machine)
            .with_context(|| format!("loading secret references for machine {machine:?}"))?
            .map(|record| record.references)
            .unwrap_or_default(),
    )
}

#[must_use]
pub fn lower_workload_secrets(workload: &Workload) -> ResolvedPlanSecrets {
    let bindings = workload.apps.iter().flat_map(app_secret_bindings).collect();
    ResolvedPlanSecrets::from_bindings(bindings)
}

#[must_use]
pub fn lower_app_secrets(app: &App) -> ResolvedPlanSecrets {
    ResolvedPlanSecrets::from_bindings(app_secret_bindings(app))
}

#[must_use]
pub fn workload_machine_refs(workload: &Workload, tenant: &str) -> Vec<MachineSecretRef> {
    workload
        .apps
        .iter()
        .flat_map(|app| app_secret_references(app, tenant))
        .collect()
}

#[must_use]
pub fn release_for_bindings(bindings: &[SecretBinding]) -> SecretReleasePolicy {
    if bindings.is_empty() {
        SecretReleasePolicy::None
    } else {
        SecretReleasePolicy::PlanBound
    }
}

fn app_secret_bindings(app: &App) -> Vec<SecretBinding> {
    let mut bindings = Vec::new();
    append_env_bindings(&app.env, &mut bindings);
    for entrypoint in &app.entrypoints {
        match entrypoint {
            Entrypoint::Command { env, .. } | Entrypoint::Function { env, .. } => {
                append_env_bindings(env, &mut bindings);
            }
        }
    }
    bindings
}

fn app_secret_references(app: &App, tenant: &str) -> Vec<MachineSecretRef> {
    let mut references = Vec::new();
    append_env_references(&app.env, tenant, &mut references);
    for entrypoint in &app.entrypoints {
        match entrypoint {
            Entrypoint::Command { env, .. } | Entrypoint::Function { env, .. } => {
                append_env_references(env, tenant, &mut references);
            }
        }
    }
    references
}

fn append_env_references(
    env: &std::collections::BTreeMap<String, EnvValue>,
    tenant: &str,
    out: &mut Vec<MachineSecretRef>,
) {
    for value in env.values() {
        let EnvValue::SecretRef { reference } = value else {
            continue;
        };
        let placeholder_var = match &reference.mount {
            SecretMount::Env { var } => Some(var.clone()),
            SecretMount::File { .. } => None,
        };
        let guest_path = match &reference.mount {
            SecretMount::Env { .. } => None,
            SecretMount::File { path } => Some(path.clone()),
        };
        out.push(MachineSecretRef {
            tenant: tenant.to_string(),
            name: reference.name.clone(),
            placeholder_var,
            guest_path,
            destinations: reference.allowed_hosts.clone(),
        });
    }
}

fn append_env_bindings(
    env: &std::collections::BTreeMap<String, EnvValue>,
    out: &mut Vec<SecretBinding>,
) {
    for value in env.values() {
        let EnvValue::SecretRef { reference } = value else {
            continue;
        };
        let name = match &reference.mount {
            SecretMount::Env { var } => var.clone(),
            SecretMount::File { path } => path.clone(),
        };
        out.push(SecretBinding {
            name,
            source: SecretSource::Keystore {
                address: reference.name.clone(),
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{AuthType, Image, Resources, SecretRef, Source};
    use std::collections::BTreeMap;

    fn workload_with_secret(mount: SecretMount) -> Workload {
        let mut env = BTreeMap::new();
        env.insert(
            "credential".to_string(),
            EnvValue::SecretRef {
                reference: SecretRef {
                    name: "provider-key".to_string(),
                    mount,
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.example.com".to_string()],
                    sigv4: None,
                },
            },
        );
        Workload {
            schema_version: "1.0".to_string(),
            id: "secret-resolution".to_string(),
            apps: vec![App {
                name: "app".to_string(),
                source: Source::LocalPath {
                    path: ".".to_string(),
                    include: vec!["**".to_string()],
                    exclude: Vec::new(),
                },
                image: Image::NixPackages {
                    packages: Vec::new(),
                },
                entrypoints: Vec::new(),
                env,
                mounts: Vec::new(),
                network: None,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 128,
                    rootfs_size_mb: 256,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: Vec::new(),
                hooks: Default::default(),
                files: Vec::new(),
                health_check: None,
            }],
            volumes: Vec::new(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn env_secret_resolves_once_for_plan_and_persistent_reference() {
        let workload = workload_with_secret(SecretMount::Env {
            var: "API_KEY".to_string(),
        });
        let lowered = lower_workload_secrets(&workload);
        let references = workload_machine_refs(&workload, "local");

        assert_eq!(lowered.secret_release, SecretReleasePolicy::PlanBound);
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].placeholder_var.as_deref(), Some("API_KEY"));
        assert_eq!(references[0].guest_path, None);
        assert_eq!(ResolvedPlanSecrets::from_machine_refs(&references), lowered);
    }

    #[test]
    fn file_secret_stays_admitted_but_is_not_exported_as_an_env_var() {
        let workload = workload_with_secret(SecretMount::File {
            path: "/run/secrets/key".to_string(),
        });
        let references = workload_machine_refs(&workload, "local");

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].placeholder_var, None);
        assert_eq!(
            references[0].guest_path.as_deref(),
            Some("/run/secrets/key")
        );
        assert_eq!(
            ResolvedPlanSecrets::from_machine_refs(&references),
            lower_workload_secrets(&workload)
        );
    }

    #[test]
    fn no_bindings_means_no_release() {
        assert_eq!(
            ResolvedPlanSecrets::from_bindings(Vec::new()).secret_release,
            SecretReleasePolicy::None
        );
    }

    #[test]
    fn malformed_persistent_sidecar_refuses_resolution() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let machine_dir = mvm_core::config::machine_state_root().join("bad-sidecar");
        std::fs::create_dir_all(&machine_dir).unwrap();
        std::fs::write(
            machine_dir.join(crate::secret::refs::MACHINE_SECRET_REFS_FILENAME),
            b"not-json",
        )
        .unwrap();

        let error = load_machine_secret_refs("bad-sidecar").unwrap_err();
        assert!(format!("{error:#}").contains("secret-refs.json"));
    }
}
