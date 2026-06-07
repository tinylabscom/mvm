//! Plan 129 / ADR-067 §1 + §4 — the substitution registry + endpoint core.
//!
//! ADR-067 §1: a guest routes a secret-bearing request to a host-local
//! substitution endpoint carrying an opaque [`Placeholder`] where the
//! secret goes. The endpoint resolves the placeholder to its `SecretRef`,
//! binding-checks the destination (claim 12), and substitutes the real
//! credential via the keyholder — then (transport leg, see below) makes
//! the real TLS to the destination.
//!
//! This module is the **dispatch core**: the per-session placeholder
//! registry + the resolve→bind→inject decision. The vsock/UDS transport,
//! the real-TLS forward, the signer-path endpoint shape, and the SDK
//! client routing are the remaining Phase D legs (tracked in the plan).

use std::collections::HashMap;

use mvm_sdk::ir::SecretRef;
use rand::RngCore;
use zeroize::Zeroizing;

use super::injector::{InjectError, Injector};
use super::resolver::SecretResolver;

/// The host-owned namespace every minted [`Placeholder`] carries. This prefix
/// is reserved: it must never appear in a workload's own egress, so the
/// Phase E leak scan can drop any non-substitution egress that contains it
/// (ADR-067 §1 backstop) — the legitimate substitution path routes the
/// placeholder to the host-local endpoint, never out the raw egress wire.
pub const PLACEHOLDER_PREFIX: &str = "mvm-secret-";

/// An opaque, per-session placeholder standing in for a secret on the guest
/// side. **Not** the secret name and **not** the value: a leaked
/// placeholder reveals nothing and resolves to nothing outside the session
/// registry that minted it (ADR-067 §4). Destination non-replay comes from
/// the binding check at substitution time, not the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Placeholder(String);

impl Placeholder {
    /// The on-the-wire token form the guest embeds in its request.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Find the first placeholder token embedded in `text` (e.g. a header value
/// `Bearer mvm-secret-<hex>`). Returns the `mvm-secret-<hex>` slice — the
/// reserved prefix plus its trailing hex run — or `None` if no token is
/// present. Used by the substitution endpoint to locate the placeholder a
/// guest put in a request header without the guest having to name the header.
pub fn find_placeholder(text: &str) -> Option<&str> {
    let start = text.find(PLACEHOLDER_PREFIX)?;
    let after = start + PLACEHOLDER_PREFIX.len();
    let hex_len = text[after..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    if hex_len == 0 {
        return None;
    }
    Some(&text[start..after + hex_len])
}

/// Per-session map from a minted [`Placeholder`] to the [`SecretRef`] it
/// stands for. Session-scoped: dropped when the session ends, so a
/// placeholder can never be replayed in a different session.
#[derive(Default)]
pub struct SubstitutionRegistry {
    map: HashMap<Placeholder, SecretRef>,
}

impl SubstitutionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh opaque placeholder for `secret` and record the mapping.
    /// Each call returns a distinct high-entropy token, so two requests for
    /// the same secret are not linkable by their placeholders.
    pub fn mint(&mut self, secret: SecretRef) -> Placeholder {
        let mut bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut bytes);
        let ph = Placeholder(format!("{PLACEHOLDER_PREFIX}{}", hex::encode(bytes)));
        self.map.insert(ph.clone(), secret);
        ph
    }

    /// Resolve a placeholder by its on-the-wire string form. `None` for a
    /// token this session never minted (a smuggled or stale token).
    pub fn resolve(&self, token: &str) -> Option<&SecretRef> {
        self.map.get(&Placeholder(token.to_string()))
    }
}

/// Errors from the substitution endpoint.
#[derive(Debug, thiserror::Error)]
pub enum SubstituteError {
    /// The token was never minted in this session — a smuggled or stale
    /// placeholder. Nothing is resolved or decrypted.
    #[error("unknown placeholder")]
    UnknownPlaceholder,
    #[error(transparent)]
    Inject(#[from] InjectError),
}

/// The host substitution endpoint core (ADR-067 §1): resolve a guest's
/// placeholder to its secret, then substitute the real credential toward a
/// bound destination. Dispatch only — the transport + real-TLS forward are
/// separate Phase D legs.
pub struct SubstitutionEndpoint<'a> {
    registry: &'a SubstitutionRegistry,
    injector: Injector<'a>,
}

impl<'a> SubstitutionEndpoint<'a> {
    pub fn new(registry: &'a SubstitutionRegistry, resolver: &'a dyn SecretResolver) -> Self {
        Self {
            registry,
            injector: Injector::new(resolver),
        }
    }

    /// Substitute `placeholder` in `request_text` with the real credential
    /// for `destination`. Returns the rewritten request `Zeroizing` (it now
    /// carries the raw credential). Refuses — without decrypting — when the
    /// placeholder is unknown, the destination is unbound (claim 12), or the
    /// auth type is a signing scheme (those take the signer path).
    pub fn substitute(
        &self,
        placeholder: &str,
        destination: &str,
        request_text: &str,
    ) -> Result<Zeroizing<String>, SubstituteError> {
        let secret = self
            .registry
            .resolve(placeholder)
            .ok_or(SubstituteError::UnknownPlaceholder)?;
        Ok(self
            .injector
            .inject_placeholder(secret, destination, request_text, placeholder)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use tempfile::tempdir;

    struct SpyResolver {
        inner: LocalResolver,
        calls: AtomicUsize,
    }
    impl SecretResolver for SpyResolver {
        fn resolve(
            &self,
            r: &SecretRef,
        ) -> Result<SecretBox<Vec<u8>>, super::super::resolver::ResolveError> {
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

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn find_placeholder_extracts_token_from_a_header_value() {
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let header = format!("Bearer {}", ph.as_str());
        assert_eq!(find_placeholder(&header), Some(ph.as_str()));
    }

    #[test]
    fn find_placeholder_stops_at_non_hex_and_ignores_clean_text() {
        // Trailing non-hex (quote, space) bounds the token.
        assert_eq!(
            find_placeholder("Bearer mvm-secret-abc123\"; x=1"),
            Some("mvm-secret-abc123")
        );
        // No token, and the bare prefix with no hex run, both yield None.
        assert_eq!(find_placeholder("Bearer ya29.real-token"), None);
        assert_eq!(find_placeholder("mvm-secret-"), None);
    }

    #[test]
    fn mint_returns_distinct_opaque_tokens() {
        let mut reg = SubstitutionRegistry::new();
        let a = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let b = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        assert_ne!(a, b, "each mint must be a distinct token");
        // Opaque: neither the secret name nor value appears in the token.
        assert!(!a.as_str().contains("openai"));
        assert!(a.as_str().starts_with("mvm-secret-"));
    }

    #[test]
    fn substitutes_real_credential_for_a_bound_destination() {
        let (_dir, spy) = spy_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &spy);

        let req = format!(
            "GET /v1 HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
            ph.as_str()
        );
        let out = endpoint
            .substitute(ph.as_str(), "api.openai.com", &req)
            .unwrap();
        assert!(out.contains("Authorization: Bearer sk-live-zzz"));
        assert!(!out.contains(ph.as_str()), "placeholder must be gone");
    }

    #[test]
    fn unknown_placeholder_is_refused_without_decrypting() {
        let (_dir, spy) = spy_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &spy);
        let err = endpoint
            .substitute(
                "mvm-secret-deadbeef",
                "api.openai.com",
                "Bearer mvm-secret-deadbeef",
            )
            .unwrap_err();
        assert!(matches!(err, SubstituteError::UnknownPlaceholder));
        assert_eq!(spy.calls.load(SeqCst), 0);
    }

    #[test]
    fn unbound_destination_is_refused_without_decrypting() {
        let (_dir, spy) = spy_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &spy);
        let err = endpoint
            .substitute(
                ph.as_str(),
                "evil.example.com",
                &format!("Bearer {}", ph.as_str()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SubstituteError::Inject(InjectError::DestinationNotBound(_))
        ));
        assert_eq!(spy.calls.load(SeqCst), 0);
    }

    #[test]
    fn placeholder_from_another_session_does_not_resolve() {
        // Session scope: a token minted in one registry is unknown to
        // another, so it can't be replayed across sessions.
        let mut reg_a = SubstitutionRegistry::new();
        let ph = reg_a.mint(bearer_ref("openai", &["api.openai.com"]));
        let reg_b = SubstitutionRegistry::new();
        assert!(reg_b.resolve(ph.as_str()).is_none());
    }
}
