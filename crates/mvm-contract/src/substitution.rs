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

use crate::ir::{AuthType, InjectionMode, SecretRef, host_is_bound};

mod position;
pub use position::{
    LocatedPlaceholder, PlaceholderPosition, basic_credential, basic_header, locate_placeholders,
    percent_encode,
};
use position::{UrlParts, mentions_placeholder};

/// The host-owned namespace every minted [`Placeholder`] carries. This prefix
/// is reserved: a placeholder is substituted only in the position its binding
/// declares (a header by default), so the endpoint refuses a request that
/// carries one anywhere else rather than sending the token itself to the
/// destination.
pub const SECRET_PLACEHOLDER_PREFIX: &str = "mvm-secret-";

/// Hex digits after [`SECRET_PLACEHOLDER_PREFIX`] in a minted placeholder:
/// 24 random bytes, hex-encoded.
pub const SECRET_PLACEHOLDER_HEX_LEN: usize = 48;

/// Byte length of a minted placeholder.
pub const SECRET_PLACEHOLDER_LEN: usize =
    SECRET_PLACEHOLDER_PREFIX.len() + SECRET_PLACEHOLDER_HEX_LEN;

/// Whether `bytes` contains a token of the minted placeholder shape: the
/// reserved prefix followed by at least [`SECRET_PLACEHOLDER_HEX_LEN`] hex
/// digits.
///
/// This is the check for places a placeholder may not travel, such as a URL
/// or a request body. It is deliberately narrower than [`find_placeholder`],
/// which accepts any hex run and suits a header, where a placeholder is
/// expected. A body can legitimately mention the prefix (source code, logs,
/// documentation), and a short token such as `mvm-secret-deadbeef` is not one
/// the host minted. "At least" rather than "exactly" means a streamed body can
/// be checked one chunk at a time with a fixed carry of
/// `SECRET_PLACEHOLDER_LEN - 1` bytes, and a longer run is placeholder-shaped
/// anyway.
pub fn contains_minted_placeholder(bytes: &[u8]) -> bool {
    let prefix = SECRET_PLACEHOLDER_PREFIX.as_bytes();
    bytes.windows(SECRET_PLACEHOLDER_LEN).any(|window| {
        window.starts_with(prefix) && window[prefix.len()..].iter().all(u8::is_ascii_hexdigit)
    })
}

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

    fn minted() -> String {
        format!("{SECRET_PLACEHOLDER_PREFIX}{}", "ab12".repeat(12))
    }

    #[test]
    fn a_minted_placeholder_is_found_wherever_it_sits() {
        let ph = minted();
        assert_eq!(ph.len(), SECRET_PLACEHOLDER_LEN);
        assert!(contains_minted_placeholder(ph.as_bytes()));
        let body = format!("{{\"messages\":[{{\"content\":\"key={ph}\"}}]}}");
        assert!(contains_minted_placeholder(body.as_bytes()));
        let url = format!("https://api.example.com/v1?key={ph}&x=1");
        assert!(contains_minted_placeholder(url.as_bytes()));
    }

    #[test]
    fn a_mention_of_the_prefix_is_not_a_minted_placeholder() {
        for text in [
            "clean text",
            "mvm-secret-",
            "mvm-secret-deadbeef",
            "the prefix is `mvm-secret-` followed by hex",
        ] {
            assert!(!contains_minted_placeholder(text.as_bytes()), "{text}");
        }
        // One hex digit short of the minted length.
        let short = &minted()[..SECRET_PLACEHOLDER_LEN - 1];
        assert!(!contains_minted_placeholder(short.as_bytes()));
        // A non-hex byte inside the run.
        let mut broken = minted().into_bytes();
        broken[SECRET_PLACEHOLDER_PREFIX.len() + 10] = b'z';
        assert!(!contains_minted_placeholder(&broken));
    }

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
            inject: Default::default(),
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

    /// Whether any secret in this session puts its value on the wire — a
    /// bearer or basic credential, rather than a signing key that only ever
    /// leaves as a signature. Only such a value can come back in a response.
    pub fn injects_a_credential(&self) -> bool {
        self.map
            .values()
            .any(|r| matches!(r.auth_type, AuthType::Bearer | AuthType::Basic))
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

/// Errors from the pure preparation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError<E> {
    /// More than one signing placeholder appeared in one request.
    MultipleSigningPlaceholders,
    /// A placeholder sat somewhere its binding does not substitute.
    PlaceholderOutOfPosition(PlaceholderPosition),
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
            Self::PlaceholderOutOfPosition(position) => write!(
                f,
                "a secret placeholder is substituted only where its binding says; refusing one \
                 found here ({})",
                position.refusal_label()
            ),
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

    /// Where a placeholder's binding substitutes it, if known.
    fn inject_mode(&self, placeholder: &str) -> Option<InjectionMode>;

    /// Record that `wire` went on the wire where the guest wrote `guest`, so
    /// a response echoing `wire` can be given back as `guest`. The raw value
    /// is recorded when it is substituted; this is for the encoded forms a
    /// URL or Basic credential puts on the wire instead.
    fn reflect(&self, _placeholder: &str, _guest: &str, _wire: &str) {}

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

/// Substitute every placeholder in `req`, in the position its binding
/// declares, dispatching each through `driver`.
///
/// - A header placeholder (`inject = header`) is substituted as written.
/// - A placeholder in a Basic credential (`inject = basic_auth`) is
///   substituted inside the decoded `user:password`, which is re-encoded.
/// - A placeholder in a path segment (`url_path`) or a query value
///   (`query_param`) is replaced by the percent-encoded value.
/// - Signing-style placeholders (SigV4/Hmac) cause their header to be dropped
///   and a single sign pass to run after the walk; more than one is an error.
///
/// A placeholder anywhere its binding does not declare — including a part of
/// the URL no mode covers — is [`PrepareError::PlaceholderOutOfPosition`], and
/// nothing is forwarded.
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
        if let Some(credential) = basic_credential(&name, &value)
            && let Some(ph) = find_placeholder(&credential)
        {
            let ph = ph.to_string();
            require_position(driver, &ph, PlaceholderPosition::BasicAuth)?;
            let substituted = driver.substitute(&ph, destination, &credential)?;
            let wire = basic_header(&substituted);
            driver.reflect(&ph, token_of(&basic_header(&credential)), token_of(&wire));
            headers.push((name, wire));
            continue;
        }
        let new_value = match find_placeholder(&value) {
            Some(ph) => {
                let ph = ph.to_string();
                match driver.auth_type(&ph) {
                    Some(AuthType::Sigv4 | AuthType::Hmac) => {
                        if signing.is_some() {
                            return Err(PrepareError::MultipleSigningPlaceholders);
                        }
                        signing = Some(ph);
                        continue;
                    }
                    Some(AuthType::Bearer | AuthType::Basic) | None => {
                        require_position(driver, &ph, PlaceholderPosition::Header)?;
                        driver.substitute(&ph, destination, &value)?
                    }
                }
            }
            None => value,
        };
        headers.push((name, new_value));
    }

    let url = if mentions_placeholder(&req.url) {
        substitute_url(driver, destination, &req.url)?
    } else {
        req.url
    };

    if let Some(ph) = signing {
        headers = driver.sign(&ph, destination, &req.method, &url, &headers, &req.body)?;
    }

    Ok(PreparedRequest {
        method: req.method,
        url,
        headers,
        body: req.body,
    })
}

/// The base64 token of a `Basic <token>` header.
fn token_of(header: &str) -> &str {
    header.split_once(' ').map_or(header, |(_, token)| token)
}

/// Refuse `placeholder` in `position` unless its binding substitutes there.
/// An unknown placeholder passes: the driver refuses it with its own error.
fn require_position<D: SubstitutionDriver>(
    driver: &D,
    placeholder: &str,
    position: PlaceholderPosition,
) -> Result<(), PrepareError<D::Error>> {
    match (driver.inject_mode(placeholder), position.mode()) {
        (None, Some(_)) => Ok(()),
        (Some(declared), Some(here)) if declared == here => Ok(()),
        _ => Err(PrepareError::PlaceholderOutOfPosition(position)),
    }
}

/// `url` with each path-segment and query-value placeholder replaced by its
/// percent-encoded value. A placeholder in the authority, a parameter name or
/// the fragment is out of position whatever its binding says.
fn substitute_url<D: SubstitutionDriver>(
    driver: &D,
    destination: &str,
    url: &str,
) -> Result<String, PrepareError<D::Error>> {
    let parts = UrlParts::split(url);
    let outside = [Some(parts.head), parts.fragment];
    if outside
        .into_iter()
        .flatten()
        .any(|s| find_placeholder(s).is_some())
    {
        return Err(PrepareError::PlaceholderOutOfPosition(
            PlaceholderPosition::UrlOther,
        ));
    }
    let path = substitute_component(
        driver,
        destination,
        parts.path,
        PlaceholderPosition::UrlPath,
    )?;
    let query = match parts.query {
        Some(query) => {
            let mut pairs = Vec::new();
            for pair in query.split('&') {
                let (key, value) = match pair.split_once('=') {
                    Some((key, value)) => (key, Some(value)),
                    None => (pair, None),
                };
                if find_placeholder(key).is_some() {
                    return Err(PrepareError::PlaceholderOutOfPosition(
                        PlaceholderPosition::UrlOther,
                    ));
                }
                pairs.push(match value {
                    Some(value) => {
                        let value = substitute_component(
                            driver,
                            destination,
                            value,
                            PlaceholderPosition::QueryParam,
                        )?;
                        alloc::format!("{key}={value}")
                    }
                    None => key.to_string(),
                });
            }
            Some(pairs.join("&"))
        }
        None => None,
    };
    Ok(parts.join(&path, query.as_deref()))
}

/// `text` with every placeholder in it replaced by its percent-encoded value,
/// each required to be bound for `position`.
fn substitute_component<D: SubstitutionDriver>(
    driver: &D,
    destination: &str,
    text: &str,
    position: PlaceholderPosition,
) -> Result<String, PrepareError<D::Error>> {
    let mut out = String::from(text);
    while let Some(ph) = find_placeholder(&out) {
        let ph = ph.to_string();
        require_position(driver, &ph, position)?;
        let value = driver.substitute(&ph, destination, &ph)?;
        let encoded = percent_encode(&value);
        if encoded != value {
            driver.reflect(&ph, &ph, &encoded);
        }
        out = out.replacen(&ph, &encoded, 1);
    }
    Ok(out)
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    struct DummyDriver {
        allow_substitute: bool,
        value: &'static str,
        reflected: core::cell::RefCell<Vec<(String, String)>>,
    }

    impl SubstitutionDriver for DummyDriver {
        type Error = &'static str;

        fn inject_mode(&self, placeholder: &str) -> Option<InjectionMode> {
            match placeholder {
                "mvm-secret-a0e70000" => Some(InjectionMode::QueryParam),
                "mvm-secret-a0a70000" => Some(InjectionMode::UrlPath),
                "mvm-secret-ba5c0000" => Some(InjectionMode::BasicAuth),
                "mvm-secret-bea70000" | "mvm-secret-deadbeef" | "mvm-secret-cafebabe" => {
                    Some(InjectionMode::Header)
                }
                _ => None,
            }
        }

        fn reflect(&self, _placeholder: &str, guest: &str, wire: &str) {
            self.reflected
                .borrow_mut()
                .push((guest.to_string(), wire.to_string()));
        }

        fn auth_type(&self, placeholder: &str) -> Option<AuthType> {
            match placeholder {
                "mvm-secret-bea70000" | "mvm-secret-a0e70000" | "mvm-secret-a0a70000" => {
                    Some(AuthType::Bearer)
                }
                "mvm-secret-ba5c0000" => Some(AuthType::Basic),
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
            let value = if self.value.is_empty() {
                "REAL"
            } else {
                self.value
            };
            Ok(text.replace(placeholder, value))
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
            ..DummyDriver::default()
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
            ..DummyDriver::default()
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
            ..DummyDriver::default()
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
            ..DummyDriver::default()
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
            ..DummyDriver::default()
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

    fn driver_with(value: &'static str) -> DummyDriver {
        DummyDriver {
            allow_substitute: true,
            value,
            ..DummyDriver::default()
        }
    }

    #[test]
    fn a_query_param_binding_is_substituted_percent_encoded_in_the_query_value() {
        let driver = driver_with("k/y+1");
        let req = ProxyRequest {
            url: "https://api.example.com/v1/models?alt=json&key=mvm-secret-a0e70000#top".into(),
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert_eq!(
            prepared.url,
            "https://api.example.com/v1/models?alt=json&key=k%2Fy%2B1#top"
        );
        assert_eq!(
            driver.reflected.borrow().as_slice(),
            [("mvm-secret-a0e70000".to_string(), "k%2Fy%2B1".to_string())]
        );
    }

    #[test]
    fn a_url_path_binding_is_substituted_in_its_segment() {
        let driver = driver_with("123:ABC");
        let req = ProxyRequest {
            url: "https://api.example.com/botmvm-secret-a0a70000/sendMessage?x=1".into(),
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert_eq!(
            prepared.url,
            "https://api.example.com/bot123%3AABC/sendMessage?x=1"
        );
    }

    #[test]
    fn a_basic_auth_binding_is_substituted_inside_the_decoded_credential() {
        let driver = driver_with("s3cret-pass");
        let req = ProxyRequest {
            headers: vec![(
                "Authorization".into(),
                basic_header("robot:mvm-secret-ba5c0000"),
            )],
            ..req()
        };
        let prepared = prepare_request(&driver, "api.example.com", req).unwrap();
        assert_eq!(
            prepared.headers,
            vec![("Authorization".into(), basic_header("robot:s3cret-pass"))]
        );
        let reflected = driver.reflected.borrow();
        assert_eq!(reflected.len(), 1);
        assert_eq!(
            basic_credential("authorization", &alloc::format!("Basic {}", reflected[0].1))
                .as_deref(),
            Some("robot:s3cret-pass")
        );
    }

    #[test]
    fn every_placeholder_out_of_its_declared_position_is_refused() {
        let driver = driver_with("v");
        let cases: Vec<(ProxyRequest, PlaceholderPosition)> = vec![
            // A header binding in the query, and in a path segment.
            (
                ProxyRequest {
                    url: "https://h/x?key=mvm-secret-bea70000".into(),
                    ..req()
                },
                PlaceholderPosition::QueryParam,
            ),
            (
                ProxyRequest {
                    url: "https://h/mvm-secret-bea70000".into(),
                    ..req()
                },
                PlaceholderPosition::UrlPath,
            ),
            // A query binding in a header, and in a path segment.
            (
                ProxyRequest {
                    headers: vec![("X-Key".into(), "mvm-secret-a0e70000".into())],
                    ..req()
                },
                PlaceholderPosition::Header,
            ),
            (
                ProxyRequest {
                    url: "https://h/mvm-secret-a0e70000".into(),
                    ..req()
                },
                PlaceholderPosition::UrlPath,
            ),
            // A basic binding written raw in a header.
            (
                ProxyRequest {
                    headers: vec![("Authorization".into(), "Bearer mvm-secret-ba5c0000".into())],
                    ..req()
                },
                PlaceholderPosition::Header,
            ),
            // A header binding hidden inside a Basic credential.
            (
                ProxyRequest {
                    headers: vec![(
                        "Authorization".into(),
                        basic_header("u:mvm-secret-bea70000"),
                    )],
                    ..req()
                },
                PlaceholderPosition::BasicAuth,
            ),
            // No binding substitutes in a parameter name, the authority or the
            // fragment.
            (
                ProxyRequest {
                    url: "https://h/x?mvm-secret-a0e70000=1".into(),
                    ..req()
                },
                PlaceholderPosition::UrlOther,
            ),
            (
                ProxyRequest {
                    url: "https://mvm-secret-a0a70000.h/x".into(),
                    ..req()
                },
                PlaceholderPosition::UrlOther,
            ),
            (
                ProxyRequest {
                    url: "https://h/x#mvm-secret-a0e70000".into(),
                    ..req()
                },
                PlaceholderPosition::UrlOther,
            ),
        ];
        for (request, position) in cases {
            let err = prepare_request(&driver, "h", request.clone()).unwrap_err();
            assert_eq!(
                err,
                PrepareError::PlaceholderOutOfPosition(position),
                "{request:?}"
            );
        }
    }

    #[test]
    fn a_signing_request_signs_the_substituted_url() {
        struct UrlSigner;
        impl SubstitutionDriver for UrlSigner {
            type Error = &'static str;
            fn auth_type(&self, ph: &str) -> Option<AuthType> {
                Some(if ph == "mvm-secret-deadbeef" {
                    AuthType::Hmac
                } else {
                    AuthType::Bearer
                })
            }
            fn inject_mode(&self, ph: &str) -> Option<InjectionMode> {
                Some(if ph == "mvm-secret-deadbeef" {
                    InjectionMode::Header
                } else {
                    InjectionMode::QueryParam
                })
            }
            fn substitute(&self, ph: &str, _d: &str, text: &str) -> Result<String, &'static str> {
                Ok(text.replace(ph, "VAL"))
            }
            fn sign(
                &self,
                _ph: &str,
                _d: &str,
                _m: &str,
                url: &str,
                headers: &[(String, String)],
                _b: &[u8],
            ) -> Result<Vec<(String, String)>, &'static str> {
                let mut out = headers.to_vec();
                out.push(("x-signed-url".into(), url.to_string()));
                Ok(out)
            }
        }
        let req = ProxyRequest {
            url: "https://h/x?key=mvm-secret-a0e70000".into(),
            headers: vec![("Authorization".into(), "mvm-secret-deadbeef".into())],
            ..req()
        };
        let prepared = prepare_request(&UrlSigner, "h", req).unwrap();
        assert!(
            prepared
                .headers
                .contains(&("x-signed-url".into(), "https://h/x?key=VAL".into()))
        );
    }
}
