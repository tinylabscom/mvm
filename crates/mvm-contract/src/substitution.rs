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
//! # Two notations, not interchangeable
//!
//! Be precise about which one you mean:
//!
//! | Notation | Where | What it is |
//! |---|---|---|
//! | `mvm-secret-<hex>` | here | the runtime wire token a guest actually holds |
//! | `${NAME}` | the Workload IR | an authoring notation; nothing resolves it at runtime |
//!
//! The constant here is [`SECRET_PLACEHOLDER_PREFIX`] rather than a bare
//! `PLACEHOLDER_PREFIX` so it reads unambiguously at its use sites.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ir::{AuthType, SecretRef, host_is_bound};

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

    /// `is_empty` is session bookkeeping, but it is bookkeeping the keyholder
    /// reads to decide whether a session has any substitution to do at all. A
    /// constant-`true` version makes a populated session look empty; a
    /// constant-`false` one makes an empty session look populated. Neither
    /// direction had a test, so both survived mutation.
    #[test]
    fn is_empty_tracks_whether_the_session_holds_any_placeholder() {
        let mut map = PlaceholderMap::new();
        assert!(map.is_empty(), "a fresh map holds nothing");
        assert_eq!(map.len(), 0);

        let ph = Placeholder::new(format!("{SECRET_PLACEHOLDER_PREFIX}deadbeef"));
        map.insert(ph, secret_ref("token", &["api.example.com"]));

        assert!(
            !map.is_empty(),
            "a map holding a placeholder must not report empty"
        );
        assert_eq!(map.len(), 1);
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
        assert_eq!(
            map.resolve_name("openai")
                .map(|secret| secret.name.as_str()),
            Some("openai")
        );
        assert!(map.resolve_name("missing").is_none());
    }

    #[test]
    fn substitute_into_replaces_the_token_and_leaves_the_rest() {
        let text = "Bearer mvm-secret-deadbeef, Accept: application/json";
        let out = substitute_into(text, "mvm-secret-deadbeef", "real-api-key");
        assert_eq!(out, "Bearer real-api-key, Accept: application/json");

        // A token that does not appear is a no-op, not an error.
        assert_eq!(
            substitute_into("clean", "mvm-secret-deadbeef", "x"),
            "clean"
        );
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

    /// Resolve a signed plan secret by its stable name. This is for host-owned
    /// material such as an ingress TLS key, where no placeholder ever needs to
    /// cross toward the guest. Multiple unlinkable placeholders for the same
    /// secret intentionally collapse to the same immutable reference here.
    pub fn resolve_name(&self, name: &str) -> Option<&SecretRef> {
        self.map.values().find(|secret| secret.name == name)
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

/// A request whose headers may carry opaque placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A request with placeholders substituted, ready to forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from the pure header-walk preparation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError<E> {
    /// More than one signing placeholder appeared in one request.
    MultipleSigningPlaceholders,
    /// The driver produced an error.
    Driver(E),
}

impl<E> From<E> for PrepareError<E> {
    fn from(e: E) -> Self {
        Self::Driver(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for PrepareError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MultipleSigningPlaceholders => {
                write!(f, "more than one signing placeholder in one request")
            }
            Self::Driver(e) => write!(f, "{e}"),
        }
    }
}

/// Driver for [`prepare_request`]: resolves a placeholder's auth type,
/// substitutes inject-style secrets, and signs signing-style secrets.
///
/// The trait is object-safe in intent but uses an associated error type so
/// the host can carry its rich error enums while the browser demo carries
/// a simple string.
pub trait SubstitutionDriver {
    /// Error returned by [`Self::substitute`] and [`Self::sign`].
    type Error: core::fmt::Display;

    /// The auth type of a placeholder, if known.
    fn auth_type(&self, placeholder: &str) -> Option<AuthType>;

    /// Substitute `placeholder` in `text` for `destination`.
    fn substitute(
        &self,
        placeholder: &str,
        destination: &str,
        text: &str,
    ) -> Result<String, Self::Error>;

    /// Sign the request described by `method`, `url`, `headers`, and `body`
    /// under `placeholder` bound to `destination`. Returns the complete
    /// signed headers (the caller replaces its header vec with this).
    fn sign(
        &self,
        placeholder: &str,
        destination: &str,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<(String, String)>, Self::Error>;
}

/// Walk `req`'s headers, dispatching each placeholder through `driver`.
///
/// Inject-style placeholders (Bearer/Basic) are substituted in-place.
/// Signing-style placeholders (SigV4/Hmac) cause their header to be dropped
/// and a single sign pass to run after the walk. More than one signing
/// placeholder is an error.
///
/// `destination` is the host (no port) extracted from the request URL by the
/// caller; keeping URL parsing out of this function keeps the crate
/// `url`-dependency-free.
pub fn prepare_request<D: SubstitutionDriver>(
    driver: &D,
    destination: &str,
    req: ProxyRequest,
) -> Result<PreparedRequest, PrepareError<D::Error>> {
    let mut headers = Vec::with_capacity(req.headers.len());
    let mut signing: Option<String> = None;

    for (name, value) in req.headers {
        let new_value = match find_placeholder(&value) {
            Some(ph) => {
                let ph = ph.to_string();
                match driver.auth_type(&ph) {
                    Some(AuthType::Bearer) | Some(AuthType::Basic) => {
                        driver.substitute(&ph, destination, &value)?
                    }
                    Some(AuthType::Sigv4 | AuthType::Hmac) => {
                        if signing.is_some() {
                            return Err(PrepareError::MultipleSigningPlaceholders);
                        }
                        signing = Some(ph);
                        continue;
                    }
                    None => driver.substitute(&ph, destination, &value)?,
                }
            }
            None => value,
        };
        headers.push((name, new_value));
    }

    if let Some(ph) = signing {
        headers = driver.sign(&ph, destination, &req.method, &req.url, &headers, &req.body)?;
    }

    Ok(PreparedRequest {
        method: req.method,
        url: req.url,
        headers,
        body: req.body,
    })
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyDriver {
        allow_substitute: bool,
    }

    impl SubstitutionDriver for DummyDriver {
        type Error = &'static str;

        fn auth_type(&self, placeholder: &str) -> Option<AuthType> {
            match placeholder {
                "mvm-secret-bea70000" => Some(AuthType::Bearer),
                "mvm-secret-deadbeef" => Some(AuthType::Hmac),
                "mvm-secret-cafebabe" => Some(AuthType::Hmac),
                _ => None,
            }
        }

        fn substitute(
            &self,
            placeholder: &str,
            _destination: &str,
            text: &str,
        ) -> Result<String, Self::Error> {
            if !self.allow_substitute {
                return Err("substitute refused");
            }
            Ok(text.replace(placeholder, "REAL"))
        }

        fn sign(
            &self,
            _placeholder: &str,
            _destination: &str,
            _method: &str,
            _url: &str,
            headers: &[(String, String)],
            _body: &[u8],
        ) -> Result<Vec<(String, String)>, Self::Error> {
            let mut out = headers.to_vec();
            out.push(("x-signature".to_string(), "sig".to_string()));
            Ok(out)
        }
    }

    fn req() -> ProxyRequest {
        ProxyRequest {
            method: "GET".to_string(),
            url: "https://api.example.com/v1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn passes_through_a_request_with_no_placeholder() {
        let driver = DummyDriver {
            allow_substitute: true,
        };
        let req = ProxyRequest {
            headers: vec![("Accept".to_string(), "application/json".to_string())],
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert_eq!(
            prepared.headers,
            vec![("Accept".to_string(), "application/json".to_string())]
        );
    }

    #[test]
    fn substitutes_an_inject_placeholder() {
        let driver = DummyDriver {
            allow_substitute: true,
        };
        let req = ProxyRequest {
            headers: vec![(
                "Authorization".to_string(),
                "Bearer mvm-secret-bea70000".to_string(),
            )],
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert_eq!(
            prepared.headers,
            vec![("Authorization".to_string(), "Bearer REAL".to_string())]
        );
    }

    #[test]
    fn propagates_a_driver_substitute_error() {
        let driver = DummyDriver {
            allow_substitute: false,
        };
        let req = ProxyRequest {
            headers: vec![(
                "Authorization".to_string(),
                "Bearer mvm-secret-bea70000".to_string(),
            )],
            ..req()
        };
        let err = prepare_request(&driver, "api.example.com", req).unwrap_err();
        assert!(matches!(err, PrepareError::Driver("substitute refused")));
    }

    #[test]
    fn refuses_more_than_one_signing_placeholder() {
        let driver = DummyDriver {
            allow_substitute: true,
        };
        let req = ProxyRequest {
            headers: vec![
                (
                    "Authorization".to_string(),
                    "Bearer mvm-secret-cafebabe".to_string(),
                ),
                ("X-Other".to_string(), "mvm-secret-deadbeef".to_string()),
            ],
            ..req()
        };
        let err = prepare_request(&driver, "api.example.com", req).unwrap_err();
        assert!(matches!(err, PrepareError::MultipleSigningPlaceholders));
    }

    #[test]
    fn signing_placeholder_drops_its_header_then_signs() {
        let driver = DummyDriver {
            allow_substitute: true,
        };
        let req = ProxyRequest {
            headers: vec![
                (
                    "Authorization".to_string(),
                    "Bearer mvm-secret-cafebabe".to_string(),
                ),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert!(!prepared.headers.iter().any(|(k, _)| k == "Authorization"));
        assert!(
            prepared
                .headers
                .contains(&("Accept".to_string(), "application/json".to_string()))
        );
        assert!(
            prepared
                .headers
                .contains(&("x-signature".to_string(), "sig".to_string()))
        );
    }
}
