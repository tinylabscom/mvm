//! The `SecretResolver` trait + `LocalResolver`.
//!
//! A resolver maps a workload's [`SecretRef`] (by name) to its raw
//! credential value, handed back in a zeroizing `SecretBox`. The value
//! source is swappable: [`LocalResolver`] reads the single-host
//! [`SecretStore`] (the `mvmctl secret set` backend) so the standalone
//! demo needs no `mvmd`; the fleet resolver is a separate mvmd plan.
//!
//! Raw bytes never widen past this boundary — the value lands in a
//! `SecretBox<Vec<u8>>` that zeroizes on drop, and the keyholder
//! consumes it on egress without copying it into the guest.

use std::sync::Arc;

use mvm_core::crypto::secret_store::SecretStore;
use mvm_sdk::ir::SecretRef;
use secrecy::{ExposeSecret, SecretBox};

/// Errors from resolving a [`SecretRef`] to its stored value.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The ref carries no `allowed_hosts` — an unbound secret must never
    /// resolve (claim 12, fail-closed). Validation rejects this earlier
    /// (`SecretWithoutBinding`); this is the resolver's own backstop.
    #[error("secret `{name}` has no destination binding")]
    Unbound { name: String },
    /// The store had no value for the ref, or the backend failed.
    #[error("secret `{name}` could not be resolved: {source}")]
    Backend {
        name: String,
        #[source]
        source: anyhow::Error,
    },
}

/// Resolves a workload [`SecretRef`] to its raw credential value.
///
/// One trait, swappable value source. The returned `SecretBox`
/// zeroizes on drop; callers must not copy the exposed bytes into a
/// longer-lived buffer.
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, r: &SecretRef) -> Result<SecretBox<Vec<u8>>, ResolveError>;
}

/// Single-host resolver over the local [`SecretStore`] (the
/// `mvmctl secret set` backend). The fleet resolver lives in mvmd.
pub struct LocalResolver {
    tenant: String,
    store: Arc<dyn SecretStore>,
}

impl LocalResolver {
    pub fn new(tenant: impl Into<String>, store: Arc<dyn SecretStore>) -> Self {
        Self {
            tenant: tenant.into(),
            store,
        }
    }
}

impl SecretResolver for LocalResolver {
    fn resolve(&self, r: &SecretRef) -> Result<SecretBox<Vec<u8>>, ResolveError> {
        if r.allowed_hosts.is_empty() {
            return Err(ResolveError::Unbound {
                name: r.name.clone(),
            });
        }
        let value =
            self.store
                .get(&self.tenant, &r.name)
                .map_err(|source| ResolveError::Backend {
                    name: r.name.clone(),
                    source,
                })?;
        // `SecretStore` yields `SecretBox<String>`; re-box as bytes so the
        // keyholder treats every credential uniformly. The String buffer
        // zeroizes when `value` drops at end of scope; the new Vec is owned
        // by the returned box and zeroizes on its drop.
        Ok(SecretBox::new(Box::new(
            value.expose_secret().as_bytes().to_vec(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::secret_store::FileSecretStore;
    use mvm_sdk::ir::{AuthType, SecretMount};
    use tempfile::tempdir;

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env {
                var: "API_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    fn store_with(
        tenant: &str,
        name: &str,
        value: &str,
    ) -> (tempfile::TempDir, Arc<dyn SecretStore>) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(tenant, name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        (dir, Arc::new(store))
    }

    #[test]
    fn local_resolver_returns_zeroizing_value_for_a_known_ref() {
        let (_dir, store) = store_with("local", "openai", "sk-live-xxx");
        let resolver = LocalResolver::new("local", store);
        let secret = resolver
            .resolve(&bearer_ref("openai", &["api.openai.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"sk-live-xxx");
    }

    #[test]
    fn local_resolver_rejects_unbound_ref() {
        let (_dir, store) = store_with("local", "openai", "sk-live-xxx");
        let resolver = LocalResolver::new("local", store);
        let err = resolver.resolve(&bearer_ref("openai", &[])).unwrap_err();
        assert!(matches!(err, ResolveError::Unbound { .. }));
    }

    #[test]
    fn local_resolver_reports_missing_secret_as_backend_error() {
        let dir = tempdir().unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(FileSecretStore::with_dir(dir.path()));
        let resolver = LocalResolver::new("local", store);
        let err = resolver
            .resolve(&bearer_ref("absent", &["api.openai.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::Backend { .. }));
    }
}
