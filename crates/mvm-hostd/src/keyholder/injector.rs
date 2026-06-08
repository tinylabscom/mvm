//! Plan 129 / ADR-067 §3 — the injecting keyholder (bearer/basic fallback).
//!
//! For transmitted-value auth (bearer tokens, basic credentials) the raw
//! value must reach the wire, so there is no "host never sees it" — and we
//! don't overclaim. Instead we confine it: the value is decrypted only
//! inside this component, substituted into the outbound bytes, and
//! zeroized. The blast radius is one audited component scoped to the
//! secret's destinations.
//!
//! claim 12: the destination allow-list is checked **before** the value is
//! resolved, so an out-of-policy request never triggers a decrypt.

use mvm_sdk::ir::{AuthType, SecretRef, host_matches};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::resolver::{ResolveError, SecretResolver};

/// Errors from the injecting keyholder.
#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The injector handles only transmitted-value schemes; sigv4/hmac go
    /// to the signer (whose key never leaves it).
    #[error("injector handles bearer/basic only, not {0:?}; use the signer")]
    WrongAuthType(AuthType),
    /// The destination is not in the secret's `allowed_hosts`. Returned
    /// **before** any decrypt (claim 12).
    #[error("destination `{0}` is not in the secret's allowed_hosts")]
    DestinationNotBound(String),
    /// The stored value is not UTF-8 — bearer/basic credentials are text.
    #[error("secret value is not valid UTF-8")]
    NonUtf8Value,
}

/// The injecting keyholder. Borrows a [`SecretResolver`] for the value
/// source.
pub struct Injector<'a> {
    resolver: &'a dyn SecretResolver,
}

impl<'a> Injector<'a> {
    pub fn new(resolver: &'a dyn SecretResolver) -> Self {
        Self { resolver }
    }

    /// Substitute `placeholder` in `text` with the secret's resolved value,
    /// for an outbound request to `destination`. The result is a zeroizing
    /// buffer because it carries the raw credential. Refuses — without
    /// decrypting — if `destination` is not bound or the auth type is a
    /// signing scheme.
    pub fn inject_placeholder(
        &self,
        r: &SecretRef,
        destination: &str,
        text: &str,
        placeholder: &str,
    ) -> Result<Zeroizing<String>, InjectError> {
        // Both guards run BEFORE resolve, so a wrong-scheme or out-of-policy
        // request never triggers a decrypt (claim 12).
        match r.auth_type {
            AuthType::Bearer | AuthType::Basic => {}
            other => return Err(InjectError::WrongAuthType(other)),
        }
        if !r.allowed_hosts.iter().any(|p| host_matches(p, destination)) {
            return Err(InjectError::DestinationNotBound(destination.to_string()));
        }
        let value = self.resolver.resolve(r)?;
        let value =
            std::str::from_utf8(value.expose_secret()).map_err(|_| InjectError::NonUtf8Value)?;
        // The output carries the raw credential — hand it back zeroizing so
        // the caller's copy wipes on drop.
        Ok(Zeroizing::new(text.replace(placeholder, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::SecretMount;
    use secrecy::SecretBox;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use tempfile::tempdir;

    /// Wraps a real resolver and counts `resolve` calls so a test can prove
    /// the injector never decrypted for an out-of-policy destination.
    struct SpyResolver {
        inner: LocalResolver,
        calls: AtomicUsize,
    }
    impl SecretResolver for SpyResolver {
        fn resolve(&self, r: &SecretRef) -> Result<SecretBox<Vec<u8>>, ResolveError> {
            self.calls.fetch_add(1, SeqCst);
            self.inner.resolve(r)
        }
    }

    fn spy_with(name: &str, value: &str) -> (tempfile::TempDir, SpyResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (
            dir,
            SpyResolver {
                inner: LocalResolver::new("local", store),
                calls: AtomicUsize::new(0),
            },
        )
    }

    fn secret_ref(name: &str, auth_type: AuthType, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn substitutes_value_for_a_bound_destination() {
        let (_dir, spy) = spy_with("api", "sk-tok");
        let injector = Injector::new(&spy);
        let out = injector
            .inject_placeholder(
                &secret_ref("api", AuthType::Bearer, &["api.openai.com"]),
                "api.openai.com",
                "Authorization: Bearer %TOK%",
                "%TOK%",
            )
            .unwrap();
        assert_eq!(&*out, "Authorization: Bearer sk-tok");
    }

    #[test]
    fn refuses_unbound_destination_without_decrypting() {
        let (_dir, spy) = spy_with("api", "sk-tok");
        let injector = Injector::new(&spy);
        let err = injector
            .inject_placeholder(
                &secret_ref("api", AuthType::Bearer, &["api.openai.com"]),
                "evil.example.com",
                "Authorization: Bearer %TOK%",
                "%TOK%",
            )
            .unwrap_err();
        assert!(matches!(err, InjectError::DestinationNotBound(_)));
        assert_eq!(
            spy.calls.load(SeqCst),
            0,
            "must not resolve/decrypt for an unbound destination"
        );
    }

    #[test]
    fn honors_wildcard_host_binding() {
        let (_dir, spy) = spy_with("api", "sk-tok");
        let injector = Injector::new(&spy);
        let out = injector
            .inject_placeholder(
                &secret_ref("api", AuthType::Bearer, &["*.openai.com"]),
                "api.openai.com",
                "Bearer %TOK%",
                "%TOK%",
            )
            .unwrap();
        assert_eq!(&*out, "Bearer sk-tok");
    }

    #[test]
    fn rejects_signing_auth_type_without_decrypting() {
        let (_dir, spy) = spy_with("api", "sk-tok");
        let injector = Injector::new(&spy);
        let err = injector
            .inject_placeholder(
                &secret_ref("api", AuthType::Sigv4, &["api.openai.com"]),
                "api.openai.com",
                "Bearer %TOK%",
                "%TOK%",
            )
            .unwrap_err();
        assert!(matches!(err, InjectError::WrongAuthType(AuthType::Sigv4)));
        assert_eq!(spy.calls.load(SeqCst), 0);
    }
}
