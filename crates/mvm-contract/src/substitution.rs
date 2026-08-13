//! The guest-side placeholder token: its reserved namespace, its opaque
//! newtype, and the scan that locates one inside a request header.
//!
//! A guest never holds a credential. It holds a [`Placeholder`] — an opaque,
//! per-session token — and routes the request to a host-local substitution
//! endpoint, which resolves the token, checks the destination binding, and
//! puts the real credential on the wire. This module is the part of that
//! path with no custody, no I/O and no randomness: what a token looks like,
//! and how to find one in a string.
//!
//! Minting stays host-side. Generating a token draws from the OS RNG, which
//! is exactly the `getrandom`-in-the-bundle dependency the browser build
//! avoids, so [`Placeholder::new`] takes the token as given and the caller
//! decides where the bytes came from.
//!
//! # Three prefixes, none interchangeable
//!
//! Be precise about which notation you mean:
//!
//! | Notation | Where | What it is |
//! |---|---|---|
//! | `mvm-secret-<hex>` | here | the runtime wire token a guest actually holds |
//! | `mvm-managed:<var>` | [`crate::policy::secret_binding`] | a CLI binding's display form |
//! | `${NAME}` | the Workload IR | an authoring notation; nothing resolves it at runtime |
//!
//! The constant here is [`SECRET_PLACEHOLDER_PREFIX`] rather than a third
//! `PLACEHOLDER_PREFIX` precisely so the first two cannot be confused at a
//! glance in this crate.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::ir::{SecretRef, host_is_bound};

/// The host-owned namespace every minted [`Placeholder`] carries. This prefix
/// is reserved: it must never appear in a workload's own egress, so the
/// leak scan can drop any non-substitution egress that contains it — the
/// legitimate substitution path routes the placeholder to the host-local
/// endpoint, never out the raw egress wire.
pub const SECRET_PLACEHOLDER_PREFIX: &str = "mvm-secret-";

/// An opaque, per-session placeholder standing in for a secret on the guest
/// side. **Not** the secret name and **not** the value: a leaked
/// placeholder reveals nothing and resolves to nothing outside the session
/// registry that minted it. Destination non-replay comes from the binding
/// check at substitution time, not the token itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Placeholder(String);

impl Placeholder {
    /// Wrap an already-generated token.
    ///
    /// Deliberately does not generate one: entropy is the caller's business,
    /// which keeps the RNG on the host side of this crate's boundary. A
    /// caller that hands over a low-entropy or attacker-chosen string gets a
    /// guessable placeholder — the type is a wrapper, not a guarantee.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

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
    let start = text.find(SECRET_PLACEHOLDER_PREFIX)?;
    let after = start + SECRET_PLACEHOLDER_PREFIX.len();
    let hex_len = text[after..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    if hex_len == 0 {
        return None;
    }
    Some(&text[start..after + hex_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;

    #[test]
    fn find_placeholder_extracts_token_from_a_header_value() {
        let ph = Placeholder::new(format!("{SECRET_PLACEHOLDER_PREFIX}deadbeef"));
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
    fn the_two_reserved_prefixes_do_not_collide() {
        // `mvm-managed:` is the CLI binding's display form and must never be
        // mistaken for a runtime token. Asserted rather than assumed, because
        // both now live in this crate.
        let managed = crate::policy::secret_binding::PLACEHOLDER_PREFIX;
        assert_ne!(managed, SECRET_PLACEHOLDER_PREFIX);
        assert_eq!(find_placeholder("mvm-managed:OPENAI_API_KEY"), None);
    }

    fn secret_ref(name: &str, hosts: &[&str]) -> SecretRef {
        use crate::ir::{AuthType, SecretMount};
        use alloc::string::ToString;
        use alloc::vec::Vec;
        SecretRef {
            name: name.to_string(),
            mount: SecretMount::Env {
                var: "API_KEY".to_string(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            sigv4: None,
        }
    }

    #[test]
    fn a_token_the_session_never_minted_does_not_resolve() {
        // The smuggled/stale-token case. Nothing is decrypted downstream
        // because nothing resolves here.
        let mut map = PlaceholderMap::new();
        map.insert(
            Placeholder::new("mvm-secret-aaaa"),
            secret_ref("openai", &["api.openai.com"]),
        );

        assert!(map.resolve("mvm-secret-aaaa").is_some());
        assert!(map.resolve("mvm-secret-bbbb").is_none());
        assert!(map.resolve("").is_none());
    }

    #[test]
    fn host_is_bound_answers_over_every_recorded_secret() {
        let mut map = PlaceholderMap::new();
        assert!(!map.host_is_bound("api.openai.com"), "empty binds nothing");

        map.insert(
            Placeholder::new("mvm-secret-1111"),
            secret_ref("openai", &["api.openai.com"]),
        );
        map.insert(
            Placeholder::new("mvm-secret-2222"),
            secret_ref("gh", &["*.github.com"]),
        );

        assert!(map.host_is_bound("api.openai.com"));
        assert!(map.host_is_bound("api.github.com"), "wildcard applies");
        assert!(!map.host_is_bound("evil.example.com"));
        // The wildcard's apex is not covered -- same rule as `host_matches`.
        assert!(!map.host_is_bound("github.com"));
    }

    #[test]
    fn two_placeholders_for_the_same_secret_both_resolve() {
        // Minting twice for one secret is deliberate -- it stops two requests
        // being linked by their token -- so the map must not collapse them.
        let mut map = PlaceholderMap::new();
        let s = secret_ref("openai", &["api.openai.com"]);
        map.insert(Placeholder::new("mvm-secret-1111"), s.clone());
        map.insert(Placeholder::new("mvm-secret-2222"), s);

        assert_eq!(map.len(), 2);
        assert!(map.resolve("mvm-secret-1111").is_some());
        assert!(map.resolve("mvm-secret-2222").is_some());
    }

    #[test]
    fn substitute_into_replaces_the_token_and_leaves_the_rest() {
        let text = "Bearer mvm-secret-deadbeef, Accept: application/json";
        let out = substitute_into(text, "mvm-secret-deadbeef", "real-api-key");
        assert_eq!(out, "Bearer real-api-key, Accept: application/json");

        // A token that does not appear is a no-op, not an error.
        assert_eq!(substitute_into("clean", "mvm-secret-deadbeef", "x"), "clean");
    }
}

/// Per-session map from a minted [`Placeholder`] to the [`SecretRef`] it
/// stands for. Session-scoped: dropped when the session ends, so a
/// placeholder can never be replayed in a different session.
///
/// A `BTreeMap` rather than a `HashMap` because `HashMap` is a `std` type and
/// this crate is `no_std`. Nothing here depends on iteration order —
/// [`Self::host_is_bound`] is an `any()` — so the change is confined to the
/// container.
///
/// Minting is not here: drawing a fresh token needs an RNG, so it lives with
/// the host that has one. This type is what remains once that is taken out —
/// insert, look up, and answer whether any binding covers a host — and it is
/// the whole of what a browser needs to replay a substitution decision.
// `SecretRef` holds only binding metadata (name + auth-type + hosts), no
// value, so `Debug` here cannot leak a secret.
#[derive(Debug, Default, Clone)]
pub struct PlaceholderMap {
    map: BTreeMap<Placeholder, SecretRef>,
}

impl PlaceholderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `placeholder` stands for `secret`. The caller owns where
    /// the token came from; see [`Placeholder::new`].
    pub fn insert(&mut self, placeholder: Placeholder, secret: SecretRef) {
        self.map.insert(placeholder, secret);
    }

    /// Resolve a placeholder by its on-the-wire string form. `None` for a
    /// token this session never minted (a smuggled or stale token).
    pub fn resolve(&self, token: &str) -> Option<&SecretRef> {
        self.map.get(&Placeholder::new(token))
    }

    /// Whether any secret in this session is bound to `host` — a
    /// [`host_is_bound`](crate::ir::host_is_bound) hit against some
    /// `SecretRef.allowed_hosts`.
    ///
    /// This is a coarse gate, not the claim-12 enforcement point: it answers
    /// "could any secret reach this host", which the transparent `https`
    /// terminator uses to decide whether to MITM-terminate a connection at
    /// all. The per-request bind check still runs at substitution time.
    pub fn host_is_bound(&self, host: &str) -> bool {
        self.map
            .values()
            .any(|r| host_is_bound(&r.allowed_hosts, host))
    }

    /// Number of recorded placeholders. Session bookkeeping only.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Replace every occurrence of `placeholder` in `text` with `value`.
///
/// This is the pure half of secret substitution: no binding check, no
/// decrypt, no secret custody. The host runs those guards first and then
/// calls this; the browser demo calls it with fixture values after the same
/// policy decision. Keeping one definition guarantees the two sides produce
/// identical bytes.
pub fn substitute_into(text: &str, placeholder: &str, value: &str) -> String {
    text.replace(placeholder, value)
}
