//! Egress routes: per-destination endpoint rules over HTTP method and path.
//!
//! The network policy's allow-list decides *which* destinations a workload
//! may reach. A route narrows what it may do there: `GET` on
//! `/repos/org/**` of `api.github.com`, nothing else. Rules are only
//! enforceable where the host endpoint reads the request — a flow it
//! terminates — so a route never causes interception by itself: an endpoint
//! rule on a destination no secret is bound to is enforced only when the
//! route says `intercept = true`, which the operator wrote and the signed plan
//! carries. Without it the flow is refused rather than relayed unchecked.
//!
//! # Decision
//!
//! A request matches the route for its host and port (an exact host beats a
//! `*.suffix` wildcard). Its rules are tried in order and the first whose
//! method and path glob match decides; a request no rule matches takes the
//! route's `otherwise`, which defaults to deny. A route with no rules decides
//! every request by `otherwise`. A destination no route names is not decided
//! here at all — the allow-list alone admits it.
//!
//! # Paths
//!
//! A path is matched after one canonicalisation, and a path that cannot be
//! canonicalised without guessing is refused rather than matched: a dot
//! segment, an empty segment, a backslash, or a percent-encoding of `/`, `\`,
//! `.` or a control byte. Other percent-encodings of unreserved characters are
//! decoded first, so `/%61dmin` cannot slip past a rule on `/admin`. The query
//! string is not part of the match.
//!
//! A glob segment `**` matches any number of segments, including none; `*`
//! inside a segment matches any run of characters within it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::ir::{host_matches, host_pattern_is_single_label_wildcard};

/// Most routes one policy may carry.
pub const MAX_ROUTES: usize = 256;
/// Most endpoint rules one route may carry.
pub const MAX_RULES_PER_ROUTE: usize = 256;
/// Longest request path decided; a longer one is refused.
pub const MAX_PATH_LEN: usize = 8192;
/// Most segments in a rule's path glob.
const MAX_GLOB_SEGMENTS: usize = 64;

/// What a route or rule decides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RouteOutcome {
    /// Forward the request.
    Allow,
    /// Refuse it.
    #[default]
    Deny,
    /// Ask an approval backend. Until one is wired, an `ask` is refused.
    Ask,
}

impl RouteOutcome {
    /// Stable audit label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        }
    }
}

/// One endpoint rule: a method (or any) and a path glob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EndpointRule {
    /// Optional stable id for the audit record; the rule's position is used
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// HTTP method, upper case. Absent matches any method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Path glob, starting with `/`.
    pub path: String,
    /// What a matching request gets.
    pub outcome: RouteOutcome,
}

/// One route: a destination and the endpoint rules that apply there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EgressRoute {
    /// Stable id, recorded on every decision this route makes.
    pub id: String,
    /// An exact host or a `*.suffix` wildcard.
    pub host: String,
    /// Destination port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Endpoint rules, tried in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<EndpointRule>,
    /// What a request no rule matches gets.
    #[serde(default)]
    pub otherwise: RouteOutcome,
    /// Whether the host endpoint may terminate this destination's TLS to
    /// enforce the rules when no secret binding already terminates it. An
    /// explicit grant: nothing is intercepted silently.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub intercept: bool,
}

const fn default_port() -> u16 {
    443
}

/// Why a route set is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("more than {MAX_ROUTES} routes")]
    TooManyRoutes,
    #[error("route {0:?}: more than {MAX_RULES_PER_ROUTE} rules")]
    TooManyRules(String),
    #[error("route id {0:?} must be 1-64 characters of [a-z0-9._-]")]
    BadId(String),
    #[error("route id {0:?} is used twice")]
    DuplicateId(String),
    #[error(
        "route {id:?}: host {host:?} must be a lower-case host name or a *.suffix wildcard over two or more labels"
    )]
    BadHost { id: String, host: String },
    #[error("routes {0:?} and {1:?} name the same destination")]
    DuplicateDestination(String, String),
    #[error("route {id:?}: port 0 is not a destination")]
    BadPort { id: String },
    #[error(
        "route {id:?}: rule path {path:?} must start with `/` and use `*` and `**` only as globs"
    )]
    BadPath { id: String, path: String },
    #[error("route {id:?}: method {method:?} must be an upper-case HTTP token")]
    BadMethod { id: String, method: String },
    #[error("the route set is not a JSON array of routes with only the known fields")]
    Undecodable,
}

/// A validated set of routes. Not itself serialised: a policy carries its
/// routes as a plain list, and every consumer builds a set through
/// [`RouteSet::new`], so an unvalidated list can never decide a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteSet {
    routes: Vec<EgressRoute>,
}

/// Where a decision came from, for the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// The rule with this label (its id, or `rule-N` by position).
    Rule(String),
    /// No rule matched; the route's `otherwise` decided.
    Otherwise,
    /// The path could not be canonicalised, so it was refused unmatched.
    AmbiguousPath,
}

impl DecidedBy {
    /// Stable audit label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Rule(label) => label.clone(),
            Self::Otherwise => "otherwise".to_string(),
            Self::AmbiguousPath => "ambiguous_path".to_string(),
        }
    }
}

/// A route's decision on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    /// The route that decided.
    pub route_id: String,
    /// Which part of it decided.
    pub decided_by: DecidedBy,
    /// The outcome.
    pub outcome: RouteOutcome,
}

impl RouteSet {
    /// Validate `routes` into a set.
    ///
    /// # Errors
    ///
    /// The first [`RouteError`] found.
    pub fn new(routes: Vec<EgressRoute>) -> Result<Self, RouteError> {
        let set = Self { routes };
        set.validate()?;
        Ok(set)
    }

    /// Decode and validate a JSON array of routes.
    ///
    /// # Errors
    ///
    /// [`RouteError::Undecodable`], or a validation failure.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RouteError> {
        let routes: Vec<EgressRoute> =
            serde_json::from_slice(bytes).map_err(|_| RouteError::Undecodable)?;
        Self::new(routes)
    }

    /// The routes, in order.
    #[must_use]
    pub fn routes(&self) -> &[EgressRoute] {
        &self.routes
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Every rule a set carries is consistent: ids, hosts, ports, methods and
    /// globs are well formed, and no two routes name one destination.
    ///
    /// # Errors
    ///
    /// The first [`RouteError`] found.
    pub fn validate(&self) -> Result<(), RouteError> {
        if self.routes.len() > MAX_ROUTES {
            return Err(RouteError::TooManyRoutes);
        }
        for (index, route) in self.routes.iter().enumerate() {
            validate_route(route)?;
            if let Some(earlier) = self.routes[..index]
                .iter()
                .find(|other| other.id == route.id)
            {
                return Err(RouteError::DuplicateId(earlier.id.clone()));
            }
            if let Some(earlier) = self.routes[..index]
                .iter()
                .find(|other| other.host == route.host && other.port == route.port)
            {
                return Err(RouteError::DuplicateDestination(
                    earlier.id.clone(),
                    route.id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// The route for `host:port`: an exact host before a wildcard.
    #[must_use]
    pub fn route_for(&self, host: &str, port: u16) -> Option<&EgressRoute> {
        let host = host.to_ascii_lowercase();
        let candidates = || self.routes.iter().filter(move |r| r.port == port);
        candidates().find(|r| r.host == host).or_else(|| {
            candidates().find(|r| r.host.starts_with("*.") && host_matches(&r.host, &host))
        })
    }

    /// Whether the endpoint must read requests to `host:port` to decide
    /// them — some route there has rules or refuses by default.
    #[must_use]
    pub fn needs_inspection(&self, host: &str, port: u16) -> bool {
        self.route_for(host, port)
            .is_some_and(EgressRoute::inspects)
    }

    /// Whether the plan grants terminating `host:port` to enforce its rules.
    #[must_use]
    pub fn grants_interception(&self, host: &str, port: u16) -> bool {
        self.route_for(host, port)
            .is_some_and(|route| route.intercept && route.inspects())
    }

    /// Decide one request, or `None` when no route names its destination.
    #[must_use]
    pub fn decide(&self, host: &str, port: u16, method: &str, path: &str) -> Option<RouteDecision> {
        let route = self.route_for(host, port)?;
        Some(route.decide(method, path))
    }
}

impl EgressRoute {
    /// Whether this route needs the request read to decide it.
    #[must_use]
    pub fn inspects(&self) -> bool {
        !self.rules.is_empty() || self.otherwise != RouteOutcome::Allow
    }

    /// Decide one request against this route.
    #[must_use]
    pub fn decide(&self, method: &str, path: &str) -> RouteDecision {
        let decision = |decided_by, outcome| RouteDecision {
            route_id: self.id.clone(),
            decided_by,
            outcome,
        };
        let Some(segments) = canonical_segments(path) else {
            return decision(DecidedBy::AmbiguousPath, RouteOutcome::Deny);
        };
        let method = method.to_ascii_uppercase();
        for (index, rule) in self.rules.iter().enumerate() {
            let method_matches = rule.method.as_deref().is_none_or(|m| m == method);
            if method_matches && glob_matches(&rule.path, &segments) {
                let label = rule
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("rule-{}", index + 1));
                return decision(DecidedBy::Rule(label), rule.outcome);
            }
        }
        decision(DecidedBy::Otherwise, self.otherwise)
    }
}

fn validate_route(route: &EgressRoute) -> Result<(), RouteError> {
    let id_ok = !route.id.is_empty()
        && route.id.len() <= 64
        && route.id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if !id_ok {
        return Err(RouteError::BadId(route.id.clone()));
    }
    if !is_route_host(&route.host) {
        return Err(RouteError::BadHost {
            id: route.id.clone(),
            host: route.host.clone(),
        });
    }
    if route.port == 0 {
        return Err(RouteError::BadPort {
            id: route.id.clone(),
        });
    }
    if route.rules.len() > MAX_RULES_PER_ROUTE {
        return Err(RouteError::TooManyRules(route.id.clone()));
    }
    for rule in &route.rules {
        if !is_valid_glob(&rule.path) {
            return Err(RouteError::BadPath {
                id: route.id.clone(),
                path: rule.path.clone(),
            });
        }
        if let Some(method) = &rule.method
            && !is_method(method)
        {
            return Err(RouteError::BadMethod {
                id: route.id.clone(),
                method: method.clone(),
            });
        }
    }
    Ok(())
}

fn is_route_host(host: &str) -> bool {
    let bare = host.strip_prefix("*.").unwrap_or(host);
    !bare.is_empty()
        && bare.len() <= 253
        && !host_pattern_is_single_label_wildcard(host)
        && bare.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// An upper-case HTTP method token.
fn is_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
}

fn is_valid_glob(glob: &str) -> bool {
    let Some(rest) = glob.strip_prefix('/') else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    segments.len() <= MAX_GLOB_SEGMENTS
        && segments.iter().enumerate().all(|(i, segment)| {
            // A trailing empty segment (`/repos/`) is allowed only as the
            // root `/`; elsewhere an empty segment is refused.
            let empty_ok = segment.is_empty() && i == segments.len() - 1 && segments.len() == 1;
            (empty_ok || !segment.is_empty())
                && (*segment == "**" || !segment.contains("**"))
                && *segment != "."
                && *segment != ".."
                && !segment.contains('?')
                && !segment.contains('#')
                && !segment.contains('\\')
                && !segment.chars().any(char::is_control)
        })
}

/// The request path's segments after canonicalisation, or `None` when it
/// cannot be canonicalised without guessing.
fn canonical_segments(path: &str) -> Option<Vec<String>> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.len() > MAX_PATH_LEN || !path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let decoded = decode_unreserved(path)?;
    let rest = &decoded[1..];
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len() - 1;
    let mut out = Vec::with_capacity(segments.len());
    for (i, segment) in segments.iter().enumerate() {
        match *segment {
            "." | ".." => return None,
            // A trailing slash names the same resource as its absence.
            "" if i == last => {}
            "" => return None,
            other => out.push(other.to_string()),
        }
    }
    Some(out)
}

/// Decode percent-escapes of unreserved characters; refuse an escape of a
/// separator, a dot or a control byte, and any raw non-ASCII or control byte;
/// keep every other escape as written, upper-cased.
fn decode_unreserved(path: &str) -> Option<String> {
    if !path.is_ascii() {
        return None;
    }
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte.is_ascii_control() {
            return None;
        }
        if byte != b'%' {
            out.push(char::from(byte));
            i += 1;
            continue;
        }
        let hex = core::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
        let value = u8::from_str_radix(hex, 16).ok()?;
        if matches!(value, b'/' | b'\\' | b'.') || value.is_ascii_control() {
            return None;
        }
        if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'~') {
            out.push(char::from(value));
        } else {
            out.push('%');
            out.push_str(&hex.to_ascii_uppercase());
        }
        i += 3;
    }
    Some(out)
}

/// Whether the glob matches the canonical segments.
fn glob_matches(glob: &str, segments: &[String]) -> bool {
    let pattern: Vec<&str> = match glob.strip_prefix('/') {
        Some("") => Vec::new(),
        Some(rest) => rest.split('/').collect(),
        None => return false,
    };
    // Dynamic programming over (pattern index, segment index): no
    // backtracking blow-up however many `**` a rule carries.
    let (p, s) = (pattern.len(), segments.len());
    let mut table = vec![vec![false; s + 1]; p + 1];
    table[p][s] = true;
    for pi in (0..p).rev() {
        for si in (0..=s).rev() {
            table[pi][si] = if pattern[pi] == "**" {
                table[pi + 1][si] || (si < s && table[pi][si + 1])
            } else {
                si < s && segment_matches(pattern[pi], &segments[si]) && table[pi + 1][si + 1]
            };
        }
    }
    table[0][0]
}

/// `*` within a segment matches any run of characters; everything else is
/// literal.
fn segment_matches(pattern: &str, segment: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == segment;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !segment.starts_with(first) || segment.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &segment[first.len()..segment.len() - last.len()];
    if !segment.ends_with(last) {
        return false;
    }
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

/// Parse an `--allow-endpoint` spec: `[METHOD ]https://host[:port]/path-glob`.
///
/// The URL's scheme picks the default port (`https` 443, `http` 80); the path
/// glob defaults to `/**`.
///
/// # Errors
///
/// A description of what is malformed. Nothing from the spec beyond what is
/// quoted back to the operator who wrote it.
pub fn parse_endpoint_spec(spec: &str) -> Result<(Option<String>, String, u16, String), String> {
    let spec = spec.trim();
    let (method, url) = match spec.split_once(char::is_whitespace) {
        Some((method, url)) => (Some(method.trim().to_string()), url.trim()),
        None => (None, spec),
    };
    if let Some(method) = &method
        && !is_method(method)
    {
        return Err(format!("{method:?} is not an upper-case HTTP method"));
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url:?} is not a URL; expected https://host/path"))?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        other => return Err(format!("scheme {other:?} is not http or https")),
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/**"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| format!("{port:?} is not a port"))?,
        ),
        None => (authority, default_port),
    };
    let host = host.to_ascii_lowercase();
    if !is_route_host(&host) {
        return Err(format!("{host:?} is not a host name"));
    }
    if !is_valid_glob(path) {
        return Err(format!(
            "{path:?} is not a path glob; use `*` within a segment and `**` for any depth"
        ));
    }
    Ok((method, host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(method: Option<&str>, path: &str, outcome: RouteOutcome) -> EndpointRule {
        EndpointRule {
            id: None,
            method: method.map(ToString::to_string),
            path: path.to_string(),
            outcome,
        }
    }

    fn github() -> RouteSet {
        RouteSet::new(vec![EgressRoute {
            id: "github".into(),
            host: "api.github.com".into(),
            port: 443,
            rules: vec![
                rule(Some("DELETE"), "/repos/**", RouteOutcome::Deny),
                rule(Some("GET"), "/repos/org/**", RouteOutcome::Allow),
                rule(Some("POST"), "/repos/org/*/issues", RouteOutcome::Ask),
            ],
            otherwise: RouteOutcome::Deny,
            intercept: true,
        }])
        .unwrap()
    }

    fn outcome(set: &RouteSet, method: &str, path: &str) -> RouteOutcome {
        set.decide("api.github.com", 443, method, path)
            .unwrap()
            .outcome
    }

    #[test]
    fn rules_decide_in_order_and_otherwise_denies() {
        let set = github();
        assert_eq!(
            outcome(&set, "GET", "/repos/org/x/pulls"),
            RouteOutcome::Allow
        );
        assert_eq!(outcome(&set, "get", "/repos/org"), RouteOutcome::Allow);
        assert_eq!(outcome(&set, "DELETE", "/repos/org/x"), RouteOutcome::Deny);
        assert_eq!(
            outcome(&set, "POST", "/repos/org/x/issues"),
            RouteOutcome::Ask
        );
        assert_eq!(
            outcome(&set, "POST", "/repos/org/x/pulls"),
            RouteOutcome::Deny
        );
        assert_eq!(outcome(&set, "GET", "/repos/other/x"), RouteOutcome::Deny);
        let decision = set.decide("api.github.com", 443, "GET", "/user").unwrap();
        assert_eq!(decision.decided_by, DecidedBy::Otherwise);
        assert_eq!(decision.route_id, "github");
        let decision = set
            .decide("api.github.com", 443, "GET", "/repos/org/x?q=1")
            .unwrap();
        assert_eq!(decision.decided_by, DecidedBy::Rule("rule-2".into()));
    }

    #[test]
    fn a_destination_no_route_names_is_not_decided_here() {
        let set = github();
        assert!(set.decide("api.github.com", 80, "GET", "/").is_none());
        assert!(set.decide("github.com", 443, "GET", "/").is_none());
    }

    #[test]
    fn a_path_that_cannot_be_canonicalised_is_refused() {
        let set = github();
        for path in [
            "/repos/org/../admin",
            "/repos/org/./x",
            "/repos//org/x",
            "/repos/org%2fx",
            "/repos/org%2Fx",
            "/repos/org/%2e%2e/x",
            "/repos\\org/x",
            "/repos/org/x%00",
            "relative",
        ] {
            let decision = set.decide("api.github.com", 443, "GET", path).unwrap();
            assert_eq!(decision.decided_by, DecidedBy::AmbiguousPath, "{path}");
            assert_eq!(decision.outcome, RouteOutcome::Deny, "{path}");
        }
    }

    #[test]
    fn an_encoded_unreserved_character_cannot_evade_a_rule() {
        let set = github();
        // `%72` is `r`: the request is /repos/org/..., which DELETE refuses.
        assert_eq!(
            outcome(&set, "DELETE", "/%72epos/org/x"),
            RouteOutcome::Deny
        );
        assert_eq!(outcome(&set, "GET", "/%72epos/org/x"), RouteOutcome::Allow);
        // A trailing slash is the same resource.
        assert_eq!(outcome(&set, "GET", "/repos/org/x/"), RouteOutcome::Allow);
    }

    #[test]
    fn globs_match_within_and_across_segments() {
        let segs = |p: &str| canonical_segments(p).unwrap();
        assert!(glob_matches("/**", &segs("/")));
        assert!(glob_matches("/**", &segs("/a/b/c")));
        assert!(glob_matches("/a/**/z", &segs("/a/z")));
        assert!(glob_matches("/a/**/z", &segs("/a/b/c/z")));
        assert!(!glob_matches("/a/**/z", &segs("/a/b/c")));
        assert!(glob_matches("/v1/*.json", &segs("/v1/models.json")));
        assert!(!glob_matches("/v1/*.json", &segs("/v1/models.json/x")));
        assert!(glob_matches("/a*b*c", &segs("/aXXbYYc")));
        assert!(!glob_matches("/a*b*c", &segs("/aXXcYYb")));
        assert!(glob_matches("/", &segs("/")));
        assert!(!glob_matches("/", &segs("/a")));
        // Many `**` stay cheap.
        let deep = format!("/{}", ["**"; 60].join("/"));
        assert!(is_valid_glob(&deep));
        assert!(glob_matches(
            &deep,
            &segs(&format!("/{}", ["x"; 200].join("/")))
        ));
    }

    #[test]
    fn an_exact_host_beats_a_wildcard() {
        let set = RouteSet::new(vec![
            EgressRoute {
                id: "any".into(),
                host: "*.example.com".into(),
                port: 443,
                rules: vec![],
                otherwise: RouteOutcome::Deny,
                intercept: false,
            },
            EgressRoute {
                id: "api".into(),
                host: "api.example.com".into(),
                port: 443,
                rules: vec![],
                otherwise: RouteOutcome::Allow,
                intercept: false,
            },
        ])
        .unwrap();
        assert_eq!(set.route_for("api.example.com", 443).unwrap().id, "api");
        assert_eq!(set.route_for("cdn.example.com", 443).unwrap().id, "any");
        assert!(
            set.route_for("example.com", 443).is_none(),
            "the apex is not a subdomain"
        );
        assert!(!set.needs_inspection("api.example.com", 443));
        assert!(set.needs_inspection("cdn.example.com", 443));
    }

    #[test]
    fn a_malformed_set_is_refused() {
        let base = || EgressRoute {
            id: "r".into(),
            host: "api.example.com".into(),
            port: 443,
            rules: vec![],
            otherwise: RouteOutcome::Deny,
            intercept: false,
        };
        let bad = |edit: &dyn Fn(&mut EgressRoute)| {
            let mut r = base();
            edit(&mut r);
            RouteSet::new(vec![r]).is_err()
        };
        assert!(bad(&|r| r.id = "Upper".into()));
        assert!(bad(&|r| r.id = String::new()));
        assert!(bad(&|r| r.host = "API.example.com".into()));
        assert!(bad(&|r| r.host = "*.com".into()));
        assert!(bad(&|r| r.host = "api.example.com:443".into()));
        assert!(bad(&|r| r.host = "https://api.example.com".into()));
        assert!(bad(&|r| r.port = 0));
        assert!(bad(
            &|r| r.rules = vec![rule(None, "repos", RouteOutcome::Allow)]
        ));
        assert!(bad(
            &|r| r.rules = vec![rule(None, "/a/../b", RouteOutcome::Allow)]
        ));
        assert!(bad(
            &|r| r.rules = vec![rule(None, "/a**", RouteOutcome::Allow)]
        ));
        assert!(bad(
            &|r| r.rules = vec![rule(Some("get"), "/", RouteOutcome::Allow)]
        ));
        assert!(RouteSet::new(vec![base(), base()]).is_err(), "duplicate id");
        let mut other = base();
        other.id = "s".into();
        assert!(
            RouteSet::new(vec![base(), other]).is_err(),
            "same destination"
        );
    }

    #[test]
    fn unknown_fields_are_refused_on_decode() {
        let good = br#"[{"id":"gh","host":"api.github.com","rules":[{"method":"GET","path":"/repos/**","outcome":"allow"}],"intercept":true}]"#;
        let set = RouteSet::from_json(good).unwrap();
        assert_eq!(set.routes()[0].port, 443);
        assert_eq!(set.routes()[0].otherwise, RouteOutcome::Deny);
        let extra = br#"[{"id":"gh","host":"api.github.com","upstream":"http://evil"}]"#;
        assert!(RouteSet::from_json(extra).is_err());
        let rule_extra = br#"[{"id":"gh","host":"api.github.com","rules":[{"path":"/","outcome":"allow","header":"x"}]}]"#;
        assert!(RouteSet::from_json(rule_extra).is_err());
    }

    #[test]
    fn an_endpoint_spec_parses_method_host_port_and_glob() {
        assert_eq!(
            parse_endpoint_spec("GET https://api.github.com/repos/org/**").unwrap(),
            (
                Some("GET".into()),
                "api.github.com".into(),
                443,
                "/repos/org/**".into()
            )
        );
        assert_eq!(
            parse_endpoint_spec("http://Example.com:8080").unwrap(),
            (None, "example.com".into(), 8080, "/**".into())
        );
        for bad in [
            "get https://api.github.com/",
            "ftp://x.example.com/",
            "api.github.com/repos",
            "GET https://api.github.com/a/../b",
            "GET https://api.github.com:0x/a",
            "GET https://*.com/",
        ] {
            assert!(parse_endpoint_spec(bad).is_err(), "{bad}");
        }
    }
}
