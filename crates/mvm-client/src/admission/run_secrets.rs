//! `--secret NAME[:HOST,...]`: bind a stored secret to one launch.
//!
//! A spec names a secret the operator stored with `mvmctl secret set` — the
//! value in the encrypted store, its egress binding (auth type and destination
//! allow-list) beside it. Resolution here reads metadata only and produces
//! [`MachineSecretRef`] records: the guest variable the placeholder is handed
//! under, and the destinations this launch may reach with the credential. The
//! admitted plan carries those as signed bindings, and the per-VM network
//! endpoint is the only process that ever resolves the value.
//!
//! The optional host list narrows. Each host must already be admitted by the
//! stored allow-list, and the signed plan then carries exactly that list, so
//! the placeholder the guest receives is valid for those destinations and no
//! others — a flag can never widen what the operator bound.

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::vm_backend::is_secret_env_name;
use mvm_contract::service_catalog;
use mvm_core::crypto::secret_binding::SecretBindingMeta;

use super::secrets::ResolvedPlanSecrets;
use crate::secret::{MachineSecretRef, SecretService};

/// One parsed `--secret NAME[:HOST,...]` occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSecretSpec {
    /// The stored secret's name.
    pub name: String,
    /// The destinations this launch declares. Empty keeps the stored
    /// allow-list whole.
    pub destinations: Vec<String>,
}

impl FromStr for RunSecretSpec {
    type Err = anyhow::Error;

    /// Parse `NAME` or `NAME:HOST[,HOST...]`.
    ///
    /// A malformed spec is refused here, at the flag, rather than turning into
    /// a binding that quietly means something else downstream: an empty name
    /// or host, a port on a host (the port belongs to the network policy), or
    /// whitespace inside a host.
    fn from_str(raw: &str) -> Result<Self> {
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
                .map(|host| parse_destination(raw, host))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        Ok(Self {
            name: name.to_string(),
            destinations,
        })
    }
}

fn parse_destination(raw: &str, host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        bail!("invalid --secret {raw:?}: empty host in the destination list");
    }
    if host.contains(':') {
        bail!(
            "invalid --secret {raw:?}: {host:?} carries a port; name the host only \
             (which ports are reachable is the network policy's decision)"
        );
    }
    if host.chars().any(char::is_whitespace) || host.contains('/') {
        bail!("invalid --secret {raw:?}: {host:?} is not a host name");
    }
    Ok(host.to_string())
}

/// Parse every raw `--secret` value.
///
/// # Errors
///
/// The first malformed spec, named.
pub fn parse_run_secret_specs(raw: &[String]) -> Result<Vec<RunSecretSpec>> {
    raw.iter().map(|value| value.parse()).collect()
}

/// The specs a manifest's `[secrets]` table declares, in name order.
#[must_use]
pub fn manifest_secret_specs(manifest: &mvm_core::manifest::Manifest) -> Vec<RunSecretSpec> {
    manifest
        .secrets
        .iter()
        .map(|(name, secret)| RunSecretSpec {
            name: name.clone(),
            destinations: secret.hosts.clone(),
        })
        .collect()
}

/// Merge the secrets a project declares with the `--secret` flags of one run.
///
/// The same narrowing rule the stored binding imposes on both: a flag naming a
/// declared secret replaces that entry, and its hosts must each be admitted by
/// the declared ones, so the command line can narrow what the project declared
/// and never widen it. A flag with no hosts keeps the declared list. A flag
/// naming a secret the project does not declare is added as it is. Every host
/// is still checked against the stored allow-list afterwards.
///
/// # Errors
///
/// A flag host the declared entry does not admit.
pub fn merge_secret_specs(
    declared: Vec<RunSecretSpec>,
    flags: Vec<RunSecretSpec>,
) -> Result<Vec<RunSecretSpec>> {
    let mut merged = declared;
    for flag in flags {
        let Some(entry) = merged.iter_mut().find(|spec| spec.name == flag.name) else {
            merged.push(flag);
            continue;
        };
        if flag.destinations.is_empty() {
            continue;
        }
        if !entry.destinations.is_empty()
            && let Some(outside) = flag
                .destinations
                .iter()
                .find(|host| !mvm_contract::ir::host_is_bound(&entry.destinations, host))
        {
            bail!(
                "--secret {}:{outside} widens what the manifest declares for {:?} ({}); \
                     a flag can only narrow it",
                flag.name,
                flag.name,
                entry.destinations.join(",")
            );
        }
        entry.destinations = flag.destinations;
    }
    Ok(merged)
}

/// Resolve parsed specs against `service`, fail-closed, into reference records.
///
/// Every spec must name a stored secret that carries a well-formed egress
/// binding; every declared destination must lie inside that binding's
/// allow-list; and no two specs may hand the guest the same variable. The
/// final check is the same admission validation a persistent machine's
/// recorded references go through on every start.
///
/// # Errors
///
/// An unknown secret, a value-only secret with no binding, a destination the
/// binding does not admit, a variable collision, or a store failure.
pub fn run_secret_refs(
    service: &SecretService,
    tenant: &str,
    specs: &[RunSecretSpec],
) -> Result<Vec<MachineSecretRef>> {
    let mut references: Vec<MachineSecretRef> = Vec::with_capacity(specs.len());
    for spec in specs {
        let meta = service
            .metadata(tenant, &spec.name)
            .with_context(|| format!("reading secret {:?}", spec.name))?
            .with_context(|| {
                format!(
                    "unknown secret {:?}; store it first with `mvmctl secret set {} \
                     --provider <provider>` (or `--host <host> --type <type>`)",
                    spec.name, spec.name
                )
            })?;
        let binding = meta.binding.as_ref().with_context(|| {
            format!(
                "secret {:?} has no egress binding, so there is nowhere its credential \
                 may be sent; bind it with `mvmctl secret set {} --provider <provider>`",
                spec.name, spec.name
            )
        })?;
        let var = guest_env_var_for(&spec.name, binding)?;
        if let Some(taken) = references
            .iter()
            .find(|r| r.placeholder_var.as_deref() == Some(var.as_str()))
        {
            bail!(
                "--secret {:?} would hand the guest {var}, which --secret {:?} already uses; \
                 bind one secret per variable",
                spec.name,
                taken.name
            );
        }
        references.push(MachineSecretRef {
            tenant: tenant.to_string(),
            name: spec.name.clone(),
            placeholder_var: Some(var),
            guest_path: None,
            destinations: spec.destinations.clone(),
        });
    }
    service
        .validate_for_admission(tenant, &references)
        .context("--secret refused before boot")?;
    Ok(references)
}

/// Parse and resolve raw `--secret` values against the host's own secret
/// service. No values means no store access at all, so a launch without the
/// flag never needs (or opens) a secret store.
///
/// # Errors
///
/// As [`parse_run_secret_specs`] and [`run_secret_refs`], plus a failure to
/// open the local secret service.
pub fn resolve_run_secret_flags(raw: &[String], tenant: &str) -> Result<Vec<MachineSecretRef>> {
    resolve_run_secret_specs(parse_run_secret_specs(raw)?, tenant)
}

/// Resolve already-merged specs against the host's own secret service. No
/// specs means no store access at all.
///
/// # Errors
///
/// As [`run_secret_refs`], plus a failure to open the local secret service.
pub fn resolve_run_secret_specs(
    specs: Vec<RunSecretSpec>,
    tenant: &str,
) -> Result<Vec<MachineSecretRef>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let service = SecretService::local().context("opening the host secret service")?;
    run_secret_refs(&service, tenant, &specs)
}

/// Every secret binding one launch is admitted with: those the workload IR at
/// `workload_ir` declares, plus the raw `--secret` values in `flags`. Resolved
/// before anything boots, so an unknown secret, a missing binding, or a
/// destination the binding does not admit refuses the launch rather than a VM
/// that already exists.
///
/// # Errors
///
/// As [`super::secrets::resolve_workload_secrets`],
/// [`resolve_run_secret_flags`] and [`with_run_secret_flags`].
pub fn resolve_launch_secrets(
    workload_ir: Option<&std::path::Path>,
    flags: &[String],
    manifest: &[RunSecretSpec],
    tenant: &str,
) -> Result<ResolvedPlanSecrets> {
    let declared = super::secrets::resolve_workload_secrets(workload_ir)?;
    let specs = merge_secret_specs(manifest.to_vec(), parse_run_secret_specs(flags)?)?;
    let bound = resolve_run_secret_specs(specs, tenant)?;
    with_run_secret_flags(declared, &bound)
}

/// The plan bindings for one launch: what a workload declares, plus what
/// `--secret` binds on the command line.
///
/// Refused when both name the same guest variable. Either would silently
/// shadow the other, and which credential a variable holds is exactly the
/// thing that must not depend on ordering.
///
/// # Errors
///
/// A guest variable declared by both sources.
pub fn with_run_secret_flags(
    declared: ResolvedPlanSecrets,
    flags: &[MachineSecretRef],
) -> Result<ResolvedPlanSecrets> {
    if flags.is_empty() {
        return Ok(declared);
    }
    refuse_shadowing(declared.secrets.iter().map(|b| b.name.as_str()), flags)?;
    let mut secrets = declared.secrets;
    secrets.extend(ResolvedPlanSecrets::from_machine_refs(flags).secrets);
    Ok(ResolvedPlanSecrets::from_bindings(secrets))
}

/// The reference set a persistent machine records: what its workload
/// declares, plus what `--secret` binds. The same refusal as
/// [`with_run_secret_flags`], over references rather than bindings, because a
/// persistent machine records references and lowers them on every start.
///
/// # Errors
///
/// A guest variable declared by both sources.
pub fn with_run_secret_flag_refs(
    declared: Vec<MachineSecretRef>,
    flags: Vec<MachineSecretRef>,
) -> Result<Vec<MachineSecretRef>> {
    refuse_shadowing(declared.iter().filter_map(guest_name), &flags)?;
    let mut references = declared;
    references.extend(flags);
    Ok(references)
}

/// The name a reference reaches the guest under — the one
/// [`ResolvedPlanSecrets::from_machine_refs`] lowers it to.
fn guest_name(reference: &MachineSecretRef) -> Option<&str> {
    reference
        .placeholder_var
        .as_deref()
        .or(reference.guest_path.as_deref())
}

/// Refuse a flag that would take a guest name the workload already holds.
fn refuse_shadowing<'a>(
    taken: impl IntoIterator<Item = &'a str>,
    flags: &[MachineSecretRef],
) -> Result<()> {
    let taken: Vec<&str> = taken.into_iter().collect();
    if let Some(name) = flags
        .iter()
        .filter_map(guest_name)
        .find(|name| taken.contains(name))
    {
        bail!("--secret binds {name}, which the workload already declares; drop one of them");
    }
    Ok(())
}

/// The guest variable a bound secret hands its placeholder over under.
///
/// The provider the binding was authored from wins when the catalog names a
/// conventional variable for it — that is what makes `--secret` on an
/// `anthropic` binding surface `ANTHROPIC_API_KEY` with nothing else to type.
/// Otherwise the variable is the secret's name, uppercased, `-` folded to `_`.
/// Naming only: nothing about where the credential may go reads this.
///
/// # Errors
///
/// A name that does not fold to a shell identifier.
pub fn guest_env_var_for(name: &str, binding: &SecretBindingMeta) -> Result<String> {
    if let Some(var) = binding
        .provider
        .as_deref()
        .and_then(|provider| service_catalog::builtin().find(provider).cloned())
        .and_then(|entry| entry.env_var)
    {
        return Ok(var);
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
    if !is_secret_env_name(&derived) {
        bail!(
            "secret {name:?} does not fold to a usable variable name ({derived:?}); \
             rename it, or author it with --provider"
        );
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{SecretAudit, SecretValueInput};
    use mvm_contract::ir::AuthType;
    use mvm_core::crypto::secret_store::FileSecretStore;
    use mvm_core::plan::{SecretReleasePolicy, SecretSource};
    use mvm_hostd::keyholder::FileBindingStore;
    use std::sync::Arc;

    const VALUE: &str = "sk-live-never-leaves-the-host";

    struct Fixture {
        _dir: tempfile::TempDir,
        service: SecretService,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(
                dir.path().join("values"),
            )))
            .bindings(Arc::new(FileBindingStore::with_dir(
                dir.path().join("bindings"),
            )))
            .machines_root(dir.path().join("machines"))
            .audit(SecretAudit::with_path(dir.path().join("secrets.jsonl")))
            .build()
            .unwrap();
        Fixture { _dir: dir, service }
    }

    fn bound(f: &Fixture, name: &str, provider: Option<&str>, hosts: &[&str]) {
        f.service
            .put("local", name, SecretValueInput::new(VALUE.into()))
            .unwrap();
        f.service
            .bind(
                "local",
                name,
                SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
                    sigv4: None,
                    provider: provider.map(str::to_string),
                    approve: Default::default(),
                },
            )
            .unwrap();
    }

    fn spec(raw: &str) -> RunSecretSpec {
        raw.parse().unwrap()
    }

    #[test]
    fn a_flag_narrows_a_declared_secret_and_cannot_widen_it() {
        let declared = vec![
            spec("gitlab:gitlab.com,*.gitlab.example"),
            spec("anthropic"),
        ];
        let merged =
            merge_secret_specs(declared.clone(), vec![spec("gitlab:ci.gitlab.example")]).unwrap();
        assert_eq!(merged[0].destinations, ["ci.gitlab.example"]);
        assert!(merged[1].destinations.is_empty(), "untouched entries stay");

        let err = merge_secret_specs(declared.clone(), vec![spec("gitlab:evil.test")]).unwrap_err();
        assert!(format!("{err:#}").contains("widens"), "{err:#}");

        // A declared entry with no hosts leaves the stored allow-list to judge.
        let merged =
            merge_secret_specs(declared.clone(), vec![spec("anthropic:api.anthropic.com")])
                .unwrap();
        assert_eq!(merged[1].destinations, ["api.anthropic.com"]);

        // A bare flag keeps what the project declared; a new name is added.
        let merged = merge_secret_specs(declared, vec![spec("gitlab"), spec("openai")]).unwrap();
        assert_eq!(merged[0].destinations, ["gitlab.com", "*.gitlab.example"]);
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn a_manifest_secrets_table_becomes_specs() {
        let manifest = mvm_core::manifest::Manifest::from_toml_str(
            "flake = \".\"\n[secrets]\nanthropic = {}\ngitlab = { hosts = [\"gitlab.com\"] }\n",
        )
        .unwrap();
        let specs = manifest_secret_specs(&manifest);
        assert_eq!(specs, vec![spec("anthropic"), spec("gitlab:gitlab.com")]);
    }

    #[test]
    fn a_manifest_secret_resolves_like_a_flag_and_is_refused_like_one() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let declared = vec![spec("claude")];
        let refs = run_secret_refs(
            &f.service,
            "local",
            &merge_secret_specs(declared, Vec::new()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            refs[0].placeholder_var.as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        let widening = vec![spec("claude:collector.evil.test")];
        assert!(run_secret_refs(&f.service, "local", &widening).is_err());
    }

    #[test]
    fn parses_a_bare_name_and_a_host_list() {
        assert_eq!(
            parse_run_secret_specs(&[
                "anthropic".into(),
                "gh:api.github.com".into(),
                "multi: a.example , b.example".into(),
            ])
            .unwrap(),
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
    fn a_malformed_spec_is_refused_at_the_flag() {
        for bad in [
            "",
            ":api.example.com",
            "name:",
            "name:a.example,,b.example",
            "name:api.example.com:443",
            "name:https://api.example.com",
            "name:a b.example",
        ] {
            assert!(bad.parse::<RunSecretSpec>().is_err(), "{bad:?} must refuse");
        }
    }

    #[test]
    fn an_anthropic_binding_hands_the_guest_anthropic_api_key() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let refs = run_secret_refs(&f.service, "local", &[spec("claude")]).unwrap();
        assert_eq!(
            refs[0].placeholder_var.as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        let lowered = ResolvedPlanSecrets::from_machine_refs(&refs);
        assert_eq!(lowered.secret_release, SecretReleasePolicy::PlanBound);
        assert_eq!(lowered.secrets[0].name, "ANTHROPIC_API_KEY");
        assert_eq!(
            lowered.secrets[0].source,
            SecretSource::Keystore {
                address: "claude".into()
            }
        );
    }

    #[test]
    fn an_uncatalogued_binding_folds_the_secret_name_into_the_variable() {
        let f = fixture();
        bound(&f, "my-api_token", None, &["api.example.com"]);
        let refs = run_secret_refs(&f.service, "local", &[spec("my-api_token")]).unwrap();
        assert_eq!(refs[0].placeholder_var.as_deref(), Some("MY_API_TOKEN"));
    }

    #[test]
    fn an_unknown_secret_refuses_before_boot_and_names_the_fix() {
        let f = fixture();
        let err = run_secret_refs(&f.service, "local", &[spec("absent")]).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("unknown secret"), "{message}");
        assert!(message.contains("mvmctl secret set absent"), "{message}");
    }

    #[test]
    fn a_secret_without_a_binding_refuses_before_boot() {
        let f = fixture();
        f.service
            .put("local", "bare", SecretValueInput::new(VALUE.into()))
            .unwrap();
        let err = run_secret_refs(&f.service, "local", &[spec("bare")]).unwrap_err();
        assert!(format!("{err:#}").contains("no egress binding"), "{err:#}");
    }

    #[test]
    fn a_destination_the_binding_does_not_admit_refuses_before_boot() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let err = run_secret_refs(&f.service, "local", &[spec("claude:collector.evil.test")])
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("refused before boot"), "{message}");
        assert!(message.contains("collector.evil.test"), "{message}");
    }

    #[test]
    fn declared_destinations_narrow_the_signed_binding() {
        let f = fixture();
        bound(
            &f,
            "claude",
            Some("anthropic"),
            &["api.anthropic.com", "platform.claude.com"],
        );
        let refs =
            run_secret_refs(&f.service, "local", &[spec("claude:api.anthropic.com")]).unwrap();
        let lowered = ResolvedPlanSecrets::from_machine_refs(&refs);
        assert_eq!(lowered.secrets[0].destinations, vec!["api.anthropic.com"]);
    }

    #[test]
    fn two_secrets_handing_over_the_same_variable_refuse() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        bound(
            &f,
            "claude-backup",
            Some("anthropic"),
            &["api.anthropic.com"],
        );
        let err = run_secret_refs(
            &f.service,
            "local",
            &[spec("claude"), spec("claude-backup")],
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("ANTHROPIC_API_KEY"), "{err:#}");
    }

    #[test]
    fn a_flag_and_a_workload_declaring_the_same_variable_refuse() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let refs = run_secret_refs(&f.service, "local", &[spec("claude")]).unwrap();
        let declared = ResolvedPlanSecrets::from_bindings(vec![mvm_core::plan::SecretBinding {
            name: "ANTHROPIC_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "other".into(),
            },
            destinations: Vec::new(),
        }]);
        let err = with_run_secret_flags(declared, &refs).unwrap_err();
        assert!(format!("{err:#}").contains("ANTHROPIC_API_KEY"), "{err:#}");
    }

    #[test]
    fn a_persistent_machine_refuses_the_same_shadowing_over_references() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let flags = run_secret_refs(&f.service, "local", &[spec("claude")]).unwrap();
        let declared = vec![MachineSecretRef {
            tenant: "local".into(),
            name: "other".into(),
            placeholder_var: Some("ANTHROPIC_API_KEY".into()),
            guest_path: None,
            destinations: Vec::new(),
        }];
        let err = with_run_secret_flag_refs(declared, flags.clone()).unwrap_err();
        assert!(format!("{err:#}").contains("ANTHROPIC_API_KEY"), "{err:#}");
        let merged = with_run_secret_flag_refs(Vec::new(), flags).unwrap();
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn flags_extend_the_declared_bindings_and_turn_on_release() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let refs = run_secret_refs(&f.service, "local", &[spec("claude")]).unwrap();
        let merged = with_run_secret_flags(ResolvedPlanSecrets::default(), &refs).unwrap();
        assert_eq!(merged.secrets.len(), 1);
        assert_eq!(merged.secret_release, SecretReleasePolicy::PlanBound);
        assert_eq!(
            with_run_secret_flags(ResolvedPlanSecrets::default(), &[]).unwrap(),
            ResolvedPlanSecrets::default(),
            "no flags leaves release denied"
        );
    }

    #[test]
    fn resolution_never_carries_the_secret_value() {
        let f = fixture();
        bound(&f, "claude", Some("anthropic"), &["api.anthropic.com"]);
        let refs = run_secret_refs(&f.service, "local", &[spec("claude")]).unwrap();
        let lowered = ResolvedPlanSecrets::from_machine_refs(&refs);
        let bindings = serde_json::to_string(&lowered.secrets).unwrap();
        let records = serde_json::to_string(&refs).unwrap();
        assert!(!bindings.contains(VALUE), "{bindings}");
        assert!(!records.contains(VALUE), "{records}");
    }

    #[test]
    fn no_flags_never_opens_a_secret_store() {
        // A launch without `--secret` must not need a store to exist.
        assert!(resolve_run_secret_flags(&[], "local").unwrap().is_empty());
    }
}
