//! `--secret` on the run surface: parse, validate, and lower a managed
//! secret into the plan bindings the substitution endpoint consumes.
//!
//! A spec names a secret the operator stored with `mvmctl secret set`
//! (value in the encrypted store, egress binding in the binding store).
//! Nothing here touches a value: resolution produces plan *bindings*
//! (guest env var → keystore address) plus reference records, and the
//! admitted plan is what hands them to the per-VM substitution endpoint —
//! the one process that ever resolves the raw credential. The guest only
//! ever receives the endpoint-minted `mvm-secret-<hex>` placeholder.
//!
//! Spec grammar: `NAME[:HOST,...]`. `NAME` is the stored secret's name.
//! The optional host list narrows the destinations this run declares it
//! will reach; each is validated against the stored binding's allow-list
//! and refused when outside it. Enforcement on the wire always uses the
//! stored binding's allow-list (fixed at `secret set` time) — the flag's
//! hosts are an admission-time declaration, never a widening.
//!
//! The guest-facing variable comes from the binding's authoring provider
//! when the catalog names one (`anthropic` → `ANTHROPIC_API_KEY`),
//! otherwise from the secret name uppercased (`my-token` → `MY_TOKEN`).

use anyhow::{Context, Result, bail};
use mvm_client::secret::{MachineSecretRef, SecretBindingMeta, SecretService};
use mvm_contract::service_catalog;
use mvm_core::plan::{SecretBinding, SecretSource};

use super::managed_secrets::{LoweredPlanSecrets, secret_release_for_bindings};

/// One parsed `--secret NAME[:HOST,...]` occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct RunSecretSpec {
    /// Stored secret name (the keystore address).
    pub name: String,
    /// Destinations this run declares; empty ⇒ the binding's own
    /// allow-list governs with no per-run narrowing declared.
    pub destinations: Vec<String>,
}

/// Parse every raw `--secret` value. Fails on an empty name or host so a
/// malformed spec is a refusal at the flag, not a silent no-op downstream.
pub(in crate::commands) fn parse_run_secret_specs(values: &[String]) -> Result<Vec<RunSecretSpec>> {
    values
        .iter()
        .map(|raw| {
            let (name, hosts) = match raw.split_once(':') {
                Some((name, hosts)) => (name.trim(), Some(hosts)),
                None => (raw.trim(), None),
            };
            if name.is_empty() {
                bail!("invalid --secret {raw:?}: expected NAME[:HOST,...] with a non-empty name");
            }
            let destinations = match hosts {
                Some(hosts) => hosts
                    .split(',')
                    .map(|h| {
                        let h = h.trim();
                        if h.is_empty() {
                            bail!("invalid --secret {raw:?}: empty host in destination list");
                        }
                        Ok(h.to_string())
                    })
                    .collect::<Result<Vec<_>>>()?,
                None => Vec::new(),
            };
            Ok(RunSecretSpec {
                name: name.to_string(),
                destinations,
            })
        })
        .collect()
}

/// What `--secret` resolution hands the admission path: the plan bindings
/// (with the derived release policy) and the machine reference records a
/// persistent machine persists beside its spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::commands) struct ResolvedRunSecrets {
    pub lowered: LoweredPlanSecrets,
    pub references: Vec<MachineSecretRef>,
}

/// Resolve parsed specs against the host's secret service, fail-closed.
///
/// Every spec must name a stored secret carrying a well-formed egress
/// binding, every declared destination must sit inside that binding's
/// allow-list, and the derived guest variables must not collide. The
/// service call reuses the same admission validation persistent-machine
/// boots run ([`SecretService::validate_for_admission`]).
pub(in crate::commands) fn resolve_run_secrets(
    service: &SecretService,
    tenant: &str,
    specs: &[RunSecretSpec],
) -> Result<ResolvedRunSecrets> {
    if specs.is_empty() {
        return Ok(ResolvedRunSecrets::default());
    }
    let mut references = Vec::with_capacity(specs.len());
    let mut bindings = Vec::with_capacity(specs.len());
    for spec in specs {
        let meta = service
            .metadata(tenant, &spec.name)
            .with_context(|| format!("reading secret {:?} for tenant {tenant:?}", spec.name))?
            .with_context(|| {
                format!(
                    "unknown secret {:?} for tenant {tenant:?}; store it first with \
                     `mvmctl secret set {} --provider <provider>` (or --host/--type)",
                    spec.name, spec.name
                )
            })?;
        let binding = meta.binding.as_ref().with_context(|| {
            format!(
                "secret {:?} has no egress binding; `mvmctl secret set {}` records \
                 where the substituted credential may go",
                spec.name, spec.name
            )
        })?;
        let var = guest_env_var_for(&spec.name, binding)?;
        if let Some(previous) = bindings
            .iter()
            .find(|b: &&SecretBinding| b.name == var)
            .map(|b: &SecretBinding| b.source.clone())
        {
            bail!(
                "--secret {:?} derives guest variable {var:?}, already taken by {previous:?}; \
                 bind one secret per variable",
                spec.name
            );
        }
        references.push(MachineSecretRef {
            tenant: tenant.to_string(),
            name: spec.name.clone(),
            placeholder_var: Some(var.clone()),
            destinations: spec.destinations.clone(),
        });
        bindings.push(SecretBinding {
            name: var,
            source: SecretSource::Keystore {
                address: spec.name.clone(),
            },
        });
    }
    service
        .validate_for_admission(tenant, &references)
        .context("secret reference admission refused")?;
    Ok(ResolvedRunSecrets {
        lowered: LoweredPlanSecrets {
            secret_release: secret_release_for_bindings(&bindings),
            secrets: bindings,
        },
        references,
    })
}

/// Parse + resolve the raw `--secret` values against the host's local
/// secret service. No specs ⇒ no store access at all, so a run without
/// the flag never pays for (or requires) a secret store.
pub(in crate::commands) fn resolve_cli_run_secrets(
    raw: &[String],
    tenant: &str,
) -> Result<ResolvedRunSecrets> {
    let specs = parse_run_secret_specs(raw)?;
    if specs.is_empty() {
        return Ok(ResolvedRunSecrets::default());
    }
    let service = SecretService::local().context("opening the host secret service")?;
    resolve_run_secrets(&service, tenant, &specs)
}

/// [`resolve_cli_run_secrets`] plus the persistent-machine bookkeeping:
/// record the reference set beside the machine spec (so `mvmctl secret rm`
/// refuses while the machine references the secret), or clear a previous
/// record when the machine no longer declares any. One service open covers
/// resolution and recording.
pub(in crate::commands) fn resolve_and_record_machine_secrets(
    raw: &[String],
    tenant: &str,
    machine: &str,
) -> Result<ResolvedRunSecrets> {
    let specs = parse_run_secret_specs(raw)?;
    let service = SecretService::local().context("opening the host secret service")?;
    if specs.is_empty() {
        service
            .clear_machine_references(machine)
            .context("clearing stale machine secret references")?;
        return Ok(ResolvedRunSecrets::default());
    }
    let resolved = resolve_run_secrets(&service, tenant, &specs)?;
    service
        .record_machine_references(machine, &resolved.references)
        .context("recording machine secret references")?;
    Ok(resolved)
}

/// The guest env var a bound secret surfaces its placeholder under.
///
/// The binding's authoring provider wins when the catalog names a
/// conventional variable — that is what makes `--secret` on an
/// `anthropic`-authored binding surface `ANTHROPIC_API_KEY` with no
/// extra flag. Otherwise the variable is derived from the secret name
/// (uppercased, `-`/`.` folded to `_`). Naming only: no destination or
/// substitution decision reads this.
fn guest_env_var_for(name: &str, binding: &SecretBindingMeta) -> Result<String> {
    if let Some(provider) = &binding.provider
        && let Some(entry) = service_catalog::builtin().find(provider)
        && let Some(var) = &entry.env_var
    {
        return Ok(var.clone());
    }
    let derived: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if !service_catalog::is_valid_env_var_name(&derived) {
        bail!(
            "secret name {name:?} does not derive a usable env var ({derived:?}); \
             rename the secret or author it under a catalog provider"
        );
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::secret::{SecretAudit, SecretValueInput};
    use mvm_contract::ir::AuthType;
    use mvm_core::crypto::secret_store::FileSecretStore;
    use mvm_core::plan::SecretReleasePolicy;
    use mvm_hostd::keyholder::FileBindingStore;
    use std::sync::Arc;
    use tempfile::TempDir;

    // ── Parsing ──────────────────────────────────────────────────────

    #[test]
    fn parses_a_bare_name_and_a_host_list() {
        let specs = parse_run_secret_specs(&[
            "anthropic".to_string(),
            "gh:api.github.com".to_string(),
            "multi:a.example, b.example".to_string(),
        ])
        .unwrap();
        assert_eq!(
            specs,
            vec![
                RunSecretSpec {
                    name: "anthropic".into(),
                    destinations: vec![],
                },
                RunSecretSpec {
                    name: "gh".into(),
                    destinations: vec!["api.github.com".into()],
                },
                RunSecretSpec {
                    name: "multi".into(),
                    destinations: vec!["a.example".into(), "b.example".into()],
                },
            ]
        );
    }

    #[test]
    fn refuses_an_empty_name_or_empty_host() {
        for bad in ["", ":api.example.com", "name:", "name:a.example,,b.example"] {
            assert!(
                parse_run_secret_specs(&[bad.to_string()]).is_err(),
                "{bad:?} must refuse"
            );
        }
    }

    #[test]
    fn no_specs_resolve_to_no_bindings_and_release_none() {
        let f = fixture();
        let resolved = resolve_run_secrets(&f.service, "local", &[]).unwrap();
        assert_eq!(resolved, ResolvedRunSecrets::default());
        assert_eq!(
            resolved.lowered.secret_release,
            SecretReleasePolicy::None,
            "an empty set must not declare release capability"
        );
    }

    // ── Resolution over a real (temp-dir) service ────────────────────

    struct Fixture {
        _tmp: TempDir,
        service: SecretService,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(
                tmp.path().join("secrets"),
            )))
            .bindings(Arc::new(FileBindingStore::with_dir(
                tmp.path().join("bindings"),
            )))
            .machines_root(tmp.path().join("machines"))
            .audit(SecretAudit::with_path(tmp.path().join("secrets.jsonl")))
            .build()
            .unwrap();
        Fixture { _tmp: tmp, service }
    }

    fn put_bound(f: &Fixture, name: &str, meta: SecretBindingMeta) {
        f.service
            .put("local", name, SecretValueInput::new("sk-live-zzz".into()))
            .unwrap();
        f.service.bind("local", name, meta).unwrap();
    }

    fn provider_meta(provider: &str, hosts: &[&str]) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
            provider: Some(provider.to_string()),
        }
    }

    fn explicit_meta(hosts: &[&str]) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
            provider: None,
        }
    }

    fn spec(name: &str, destinations: &[&str]) -> RunSecretSpec {
        RunSecretSpec {
            name: name.into(),
            destinations: destinations.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn an_anthropic_authored_binding_surfaces_anthropic_api_key() {
        let f = fixture();
        put_bound(
            &f,
            "claude",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        let resolved = resolve_run_secrets(&f.service, "local", &[spec("claude", &[])]).unwrap();
        assert_eq!(resolved.lowered.secrets.len(), 1);
        assert_eq!(resolved.lowered.secrets[0].name, "ANTHROPIC_API_KEY");
        assert_eq!(
            resolved.lowered.secrets[0].source,
            SecretSource::Keystore {
                address: "claude".into()
            }
        );
        assert_eq!(
            resolved.lowered.secret_release,
            SecretReleasePolicy::PlanBound
        );
        assert_eq!(
            resolved.references[0].placeholder_var.as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
    }

    #[test]
    fn an_uncatalogued_binding_derives_the_var_from_the_secret_name() {
        // Secret names are shell-id validated (alphanumeric, `-`, `_`), so
        // the derivation only ever folds `-` to `_` and uppercases.
        let f = fixture();
        put_bound(&f, "my-api_token", explicit_meta(&["api.example.com"]));
        let resolved =
            resolve_run_secrets(&f.service, "local", &[spec("my-api_token", &[])]).unwrap();
        assert_eq!(resolved.lowered.secrets[0].name, "MY_API_TOKEN");
    }

    #[test]
    fn an_unknown_secret_name_refuses() {
        let f = fixture();
        let err = resolve_run_secrets(&f.service, "local", &[spec("absent", &[])]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown secret"), "got: {msg}");
        assert!(msg.contains("mvmctl secret set"), "names the fix: {msg}");
    }

    #[test]
    fn a_value_only_secret_without_a_binding_refuses() {
        let f = fixture();
        f.service
            .put("local", "bare", SecretValueInput::new("sk-live-zzz".into()))
            .unwrap();
        let err = resolve_run_secrets(&f.service, "local", &[spec("bare", &[])]).unwrap_err();
        assert!(
            format!("{err:#}").contains("no egress binding"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_destination_outside_the_binding_allow_list_refuses() {
        let f = fixture();
        put_bound(
            &f,
            "claude",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        let err = resolve_run_secrets(
            &f.service,
            "local",
            &[spec("claude", &["evil.example.com"])],
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("admission refused"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_destination_inside_the_binding_allow_list_is_admitted_and_recorded() {
        let f = fixture();
        put_bound(
            &f,
            "claude",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        let resolved = resolve_run_secrets(
            &f.service,
            "local",
            &[spec("claude", &["api.anthropic.com"])],
        )
        .unwrap();
        assert_eq!(
            resolved.references[0].destinations,
            vec!["api.anthropic.com"]
        );
    }

    #[test]
    fn two_secrets_deriving_the_same_var_refuse() {
        let f = fixture();
        put_bound(
            &f,
            "claude",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        put_bound(
            &f,
            "claude-backup",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        let err = resolve_run_secrets(
            &f.service,
            "local",
            &[spec("claude", &[]), spec("claude-backup", &[])],
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("ANTHROPIC_API_KEY"),
            "names the collision: {err:#}"
        );
    }

    #[test]
    fn resolution_never_touches_the_secret_value() {
        // The resolved output is bindings + references — metadata shapes with
        // no value slot. Assert the serialized forms carry no value bytes.
        let f = fixture();
        put_bound(
            &f,
            "claude",
            provider_meta("anthropic", &["api.anthropic.com"]),
        );
        let resolved = resolve_run_secrets(&f.service, "local", &[spec("claude", &[])]).unwrap();
        let bindings = serde_json::to_string(&resolved.lowered.secrets).unwrap();
        let refs = serde_json::to_string(&resolved.references).unwrap();
        assert!(!bindings.contains("sk-live-zzz"), "got: {bindings}");
        assert!(!refs.contains("sk-live-zzz"), "got: {refs}");
    }
}
