//! The `SecretResolver` trait + `LocalResolver`.
//!
//! A resolver maps a workload's [`SecretRef`] (by name) to its raw
//! credential value, handed back in a zeroizing `SecretBox`. The value
//! source is swappable: `LocalResolver` reads the single-host
//! [`SecretStore`] (the `mvmctl secret set` backend) so the standalone
//! demo needs no `mvmd`; the fleet resolver is a separate mvmd plan.
//!
//! Raw bytes never widen past this boundary — the value lands in a
//! `SecretBox<Vec<u8>>` that zeroizes on drop, and the keyholder
//! consumes it on egress without copying it into the guest.

use std::sync::Arc;

use chrono::{Duration, Utc};
use mvm_contract::ir::SecretRef;
use mvm_core::crypto::secret_binding::BindingStore;
use mvm_core::crypto::secret_store::SecretStore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

const OAUTH_REFRESH_SKEW: Duration = Duration::seconds(60);

/// OAuth token set stored in the encrypted secret store for an OAuth binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenSet {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

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
    /// The OAuth access token is near expiry and must be refreshed host-side
    /// before it is sent to a destination.
    #[error("secret `{name}` requires OAuth refresh before use (expires_at={expires_at})")]
    OAuthRefreshRequired {
        name: String,
        expires_at: chrono::DateTime<Utc>,
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
    bindings: Option<Arc<dyn BindingStore>>,
}

impl LocalResolver {
    pub fn new(tenant: impl Into<String>, store: Arc<dyn SecretStore>) -> Self {
        Self {
            tenant: tenant.into(),
            store,
            bindings: None,
        }
    }

    pub fn with_bindings(
        tenant: impl Into<String>,
        store: Arc<dyn SecretStore>,
        bindings: Arc<dyn BindingStore>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            store,
            bindings: Some(bindings),
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
        if let Some(bindings) = &self.bindings {
            let binding =
                bindings
                    .get(&self.tenant, &r.name)
                    .map_err(|source| ResolveError::Backend {
                        name: r.name.clone(),
                        source,
                    })?;
            if binding.and_then(|meta| meta.oauth).is_some() {
                let token_set: OAuthTokenSet = serde_json::from_str(value.expose_secret())
                    .map_err(|source| ResolveError::Backend {
                        name: r.name.clone(),
                        source: anyhow::Error::new(source)
                            .context("parsing oauth token set from secret value"),
                    })?;
                let refresh_deadline = Utc::now() + OAUTH_REFRESH_SKEW;
                if token_set.expires_at <= refresh_deadline {
                    return Err(ResolveError::OAuthRefreshRequired {
                        name: r.name.clone(),
                        expires_at: token_set.expires_at,
                    });
                }
                return Ok(SecretBox::new(Box::new(
                    token_set.access_token.into_bytes(),
                )));
            }
        }
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
    use mvm_contract::ir::{AuthType, SecretMount};
    use mvm_core::crypto::secret_binding::{FileBindingStore, OAuthBindingMeta, SecretBindingMeta};
    use mvm_core::crypto::secret_store::FileSecretStore;
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

    fn oauth_binding_meta() -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.example.com".into()],
            sigv4: None,
            provider: None,
            approve: Default::default(),
            oauth: Some(OAuthBindingMeta {
                authorization_url: "https://auth.example.com/authorize".into(),
                token_url: "https://auth.example.com/token".into(),
                client_id: "public-client-id".into(),
                scopes: vec!["scope-a".into()],
                response_access_token_pointer: None,
            }),
        }
    }

    #[test]
    fn local_resolver_with_bindings_returns_oauth_access_token() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        let token_set = OAuthTokenSet {
            access_token: "oauth-access-token".into(),
            refresh_token: Some("oauth-refresh-token".into()),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        store
            .put(
                "local",
                "oauth-secret",
                &SecretBox::new(Box::new(serde_json::to_string(&token_set).unwrap())),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "oauth-secret", &oauth_binding_meta())
            .unwrap();
        let resolver = LocalResolver::with_bindings("local", Arc::new(store), Arc::new(bindings));
        let secret = resolver
            .resolve(&bearer_ref("oauth-secret", &["api.example.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"oauth-access-token");
    }

    #[test]
    fn local_resolver_with_bindings_refuses_oauth_token_near_expiry() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        let token_set = OAuthTokenSet {
            access_token: "oauth-access-token".into(),
            refresh_token: Some("oauth-refresh-token".into()),
            expires_at: Utc::now() + Duration::seconds(30),
        };
        store
            .put(
                "local",
                "oauth-secret",
                &SecretBox::new(Box::new(serde_json::to_string(&token_set).unwrap())),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "oauth-secret", &oauth_binding_meta())
            .unwrap();
        let resolver = LocalResolver::with_bindings("local", Arc::new(store), Arc::new(bindings));
        let err = resolver
            .resolve(&bearer_ref("oauth-secret", &["api.example.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::OAuthRefreshRequired { .. }));
    }
}
