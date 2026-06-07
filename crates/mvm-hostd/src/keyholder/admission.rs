//! Plan 129 / ADR-067 §4 — admission-time substitution registry assembly.
//!
//! At admission the host turns the plan's secret bindings into a
//! [`SubstitutionRegistry`]: one opaque placeholder per egress secret, minted
//! and mapped to a reconstructed [`SecretRef`]. The plan's `SecretBinding`
//! carries only the name + source (the lowering dropped the egress binding), so
//! the auth-type and destination allow-list are read back from the local
//! [`BindingStore`] (`mvmctl secret set` metadata), keyed by the secret's
//! keystore address.
//!
//! Returns the registry plus a `(guest-facing name → placeholder)` list the
//! caller hands to the guest (env/file injection) so the workload sends the
//! opaque token where its credential would go — it never sees the value.

use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_sdk::ir::{SecretMount, SecretRef};

use super::binding::BindingStore;
use super::substitution::{Placeholder, SubstitutionRegistry};

/// Errors from assembling the registry at admission.
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    /// A plan secret has no local egress binding. Fail closed: without an
    /// allow-list there is no destination to substitute toward (claim 12).
    #[error(
        "secret `{name}` has no local binding; run `mvmctl secret set {name} --host <h> --type <t>`"
    )]
    NoBinding { name: String },
    #[error(transparent)]
    Binding(#[from] anyhow::Error),
}

/// Build the substitution registry from `plan_secrets`, reconstructing each
/// egress secret's binding from `bindings`. Only [`SecretSource::Keystore`]
/// secrets participate — `Static` (test-only) and `External` (Vault/AWS SM)
/// take other paths and are skipped. Returns the registry and the
/// `(guest name, placeholder)` pairs to hand to the guest.
pub fn assemble_registry(
    plan_secrets: &[SecretBinding],
    tenant: &str,
    bindings: &dyn BindingStore,
) -> Result<(SubstitutionRegistry, Vec<(String, Placeholder)>), AssembleError> {
    let mut registry = SubstitutionRegistry::new();
    let mut handed = Vec::new();
    for b in plan_secrets {
        let address = match &b.source {
            SecretSource::Keystore { address } => address,
            // Non-keystore sources don't go through local egress substitution.
            SecretSource::Static { .. } | SecretSource::External { .. } => continue,
        };
        let meta = bindings
            .get(tenant, address)?
            .ok_or_else(|| AssembleError::NoBinding {
                name: address.clone(),
            })?;
        // `mount` is irrelevant to substitution (which keys on name/auth/hosts);
        // record the guest-facing name so the placeholder reaches the right env
        // slot when handed to the guest.
        let secret_ref = SecretRef {
            name: address.clone(),
            mount: SecretMount::Env {
                var: b.name.clone(),
            },
            auth_type: meta.auth_type,
            allowed_hosts: meta.allowed_hosts,
        };
        let placeholder = registry.mint(secret_ref);
        handed.push((b.name.clone(), placeholder));
    }
    Ok((registry, handed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{FileBindingStore, SecretBindingMeta};
    use mvm_sdk::ir::AuthType;
    use tempfile::tempdir;

    fn keystore_binding(guest_name: &str, address: &str) -> SecretBinding {
        SecretBinding {
            name: guest_name.into(),
            source: SecretSource::Keystore {
                address: address.into(),
            },
        }
    }

    #[test]
    fn assembles_registry_and_handed_placeholders_from_bindings() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                },
            )
            .unwrap();

        let plan = [keystore_binding("OPENAI_API_KEY", "openai")];
        let (registry, handed) = assemble_registry(&plan, "local", &store).unwrap();

        // The guest is handed its env name + an opaque placeholder.
        assert_eq!(handed.len(), 1);
        let (guest_name, placeholder) = &handed[0];
        assert_eq!(guest_name, "OPENAI_API_KEY");
        assert!(placeholder.as_str().starts_with("mvm-secret-"));

        // The registry resolves that placeholder to the reconstructed binding.
        let secret_ref = registry.resolve(placeholder.as_str()).unwrap();
        assert_eq!(secret_ref.name, "openai");
        assert_eq!(secret_ref.auth_type, AuthType::Bearer);
        assert_eq!(secret_ref.allowed_hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn fails_closed_when_a_secret_has_no_local_binding() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        let plan = [keystore_binding("OPENAI_API_KEY", "openai")];
        let err = assemble_registry(&plan, "local", &store).unwrap_err();
        assert!(matches!(err, AssembleError::NoBinding { name } if name == "openai"));
    }

    #[test]
    fn skips_static_and_external_sources() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        let plan = [
            SecretBinding {
                name: "T".into(),
                source: SecretSource::Static { value: "x".into() },
            },
            SecretBinding {
                name: "E".into(),
                source: SecretSource::External {
                    provider: "vault".into(),
                    path: "kv/x".into(),
                },
            },
        ];
        let (registry, handed) = assemble_registry(&plan, "local", &store).unwrap();
        assert!(handed.is_empty());
        // Nothing minted: a probe token resolves to nothing.
        assert!(registry.resolve("mvm-secret-deadbeef").is_none());
    }
}
