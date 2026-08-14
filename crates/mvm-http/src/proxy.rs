//! Upstream proxy configuration for the forward leg.
//!
//! Some hosts force-tunnel all outbound traffic: the only route off the machine
//! is an operator-run proxy. Without this the client cannot reach anything on
//! such a host, and there is no knob to fix it.
//!
//! # What a proxy does and does not change
//!
//! The proxy is chosen by the **transport**, never by policy. Whether a
//! destination is permitted at all is decided before a request reaches this
//! client; selecting a proxy afterwards must not widen that decision, and
//! [`NoProxy`] must not be usable as a second, weaker allow-list — it only
//! chooses how an already-permitted destination is reached.
//!
//! One consequence has to be stated plainly rather than discovered. The
//! client's [`Resolve`](crate::resolve::Resolve) seam is the SSRF chokepoint:
//! it decides which addresses may be dialled for a guest-influenced hostname.
//! When a request is proxied, the client dials the *proxy* and hands it the
//! destination by name, so the proxy performs the final resolution and the
//! SSRF guard no longer constrains the destination's address. That is inherent
//! to proxying, not an oversight. It is acceptable only because the proxy comes
//! from operator configuration on the host and is trusted the way the host is;
//! it is never guest-supplied. For the same reason the proxy's own address is
//! resolved outside the guard — a corporate proxy is almost always on RFC1918,
//! which the guard exists to reject.

use std::fmt;

use url::Url;

/// Which wire protocol the proxy speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// HTTP proxy: `CONNECT` for TLS destinations, absolute-URI request line
    /// for plaintext ones.
    Http,
    /// SOCKS5, connecting by domain name so the proxy resolves the destination.
    Socks5,
}

/// Errors from parsing proxy configuration.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy url {0:?} is not a valid url")]
    Url(String),
    #[error(
        "proxy url {url:?} has unsupported scheme {scheme:?}; expected http, https, socks5 or socks5h"
    )]
    Scheme { url: String, scheme: String },
    #[error("proxy url {0:?} has no host")]
    NoHost(String),
}

/// One upstream proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Credentials from the proxy URL's userinfo, if any.
    pub auth: Option<ProxyAuth>,
}

/// Proxy credentials. Deliberately not `Display`/`Debug`-transparent for the
/// password.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Proxy {
    /// Parse a proxy endpoint from a URL such as `http://proxy.corp:3128` or
    /// `socks5h://127.0.0.1:1080`.
    ///
    /// `socks5` and `socks5h` are both accepted and behave identically here:
    /// this client always sends the destination as a domain name, which is
    /// `socks5h` semantics. Resolving locally would defeat the point on a host
    /// that cannot resolve external names itself.
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        let url = Url::parse(raw).map_err(|_| ProxyError::Url(raw.to_string()))?;
        let scheme = url.scheme().to_ascii_lowercase();
        let (kind, default_port) = match scheme.as_str() {
            "http" => (ProxyKind::Http, 80),
            "https" => (ProxyKind::Http, 443),
            "socks5" | "socks5h" => (ProxyKind::Socks5, 1080),
            other => {
                return Err(ProxyError::Scheme {
                    url: raw.to_string(),
                    scheme: other.to_string(),
                });
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| ProxyError::NoHost(raw.to_string()))?
            .to_string();
        let auth = match (url.username(), url.password()) {
            ("", _) => None,
            (user, pass) => Some(ProxyAuth {
                username: user.to_string(),
                password: pass.unwrap_or_default().to_string(),
            }),
        };
        Ok(Self {
            kind,
            host,
            port: url.port().unwrap_or(default_port),
            auth,
        })
    }

    /// `host:port`, for logs and audit labels. Carries no credentials.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The `NO_PROXY` bypass list.
///
/// Matches a host exactly, or as a domain suffix (`corp.example` matches
/// `api.corp.example`), or everything when the list contains `*`. Entries are
/// compared case-insensitively with any leading `.` ignored.
///
/// CIDR entries are **not** interpreted; an entry that looks like a network is
/// treated as a literal name and simply will not match. Silently
/// half-implementing CIDR would be worse than not accepting it, because an
/// operator would believe a range was bypassed when it was not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxy {
    all: bool,
    entries: Vec<String>,
}

impl NoProxy {
    /// Parse a comma- (or whitespace-) separated `NO_PROXY` value.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut all = false;
        let mut entries = Vec::new();
        for part in raw.split([',', ' ', '\t']) {
            let t = part.trim().trim_start_matches('.').to_ascii_lowercase();
            if t.is_empty() {
                continue;
            }
            if t == "*" {
                all = true;
            } else {
                entries.push(t);
            }
        }
        Self { all, entries }
    }

    /// True when `host` should bypass the proxy.
    #[must_use]
    pub fn bypasses(&self, host: &str) -> bool {
        if self.all {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.entries.iter().any(|e| {
            host == *e || (host.len() > e.len() && host.ends_with(e) && host_boundary(&host, e))
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.all && self.entries.is_empty()
    }
}

/// True when `entry` sits on a label boundary in `host`, so `notevil.com` does
/// not match an entry of `evil.com`.
fn host_boundary(host: &str, entry: &str) -> bool {
    host.as_bytes()[host.len() - entry.len() - 1] == b'.'
}

/// Resolved proxy configuration: which proxy to use, and what bypasses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Proxy for `https://` destinations.
    pub https: Option<Proxy>,
    /// Proxy for `http://` destinations.
    pub http: Option<Proxy>,
    pub no_proxy: NoProxy,
}

impl ProxyConfig {
    /// A configuration that proxies everything of both schemes through one
    /// endpoint.
    #[must_use]
    pub fn all(proxy: Proxy) -> Self {
        Self {
            https: Some(proxy.clone()),
            http: Some(proxy),
            no_proxy: NoProxy::default(),
        }
    }

    #[must_use]
    pub fn with_no_proxy(mut self, no_proxy: NoProxy) -> Self {
        self.no_proxy = no_proxy;
        self
    }

    /// The proxy to use for `host` under `tls`, or `None` to dial directly.
    #[must_use]
    pub fn select(&self, host: &str, tls: bool) -> Option<&Proxy> {
        if self.no_proxy.bypasses(host) {
            return None;
        }
        if tls {
            self.https.as_ref()
        } else {
            self.http.as_ref()
        }
    }

    /// True when no scheme has a proxy configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.https.is_none() && self.http.is_none()
    }

    /// Read the conventional environment variables.
    ///
    /// `ALL_PROXY` is the fallback for either scheme. Lowercase spellings win
    /// over uppercase, matching curl: `http_proxy` is conventionally the
    /// lowercase-only one because an uppercase `HTTP_PROXY` collides with the
    /// CGI request header of the same name.
    ///
    /// A malformed value is reported rather than ignored. Silently dialling
    /// direct because a proxy URL had a typo is the failure mode this whole
    /// module exists to remove.
    pub fn from_env() -> Result<Option<Self>, ProxyError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`Self::from_env`] against an arbitrary lookup, so the precedence rules
    /// are testable without mutating process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ProxyError> {
        let pick = |names: &[&str]| -> Option<String> {
            names
                .iter()
                .find_map(|n| get(n).map(|v| v.trim().to_string()))
                .filter(|v| !v.is_empty())
        };
        let all = pick(&["all_proxy", "ALL_PROXY"]);
        let https = pick(&["https_proxy", "HTTPS_PROXY"]).or_else(|| all.clone());
        let http = pick(&["http_proxy", "HTTP_PROXY"]).or_else(|| all.clone());
        let no_proxy = pick(&["no_proxy", "NO_PROXY"]).unwrap_or_default();

        let https = https.as_deref().map(Proxy::parse).transpose()?;
        let http = http.as_deref().map(Proxy::parse).transpose()?;
        if https.is_none() && http.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            https,
            http,
            no_proxy: NoProxy::parse(&no_proxy),
        }))
    }

    /// A one-line human summary for diagnostics. Never includes credentials.
    #[must_use]
    pub fn summary(&self) -> String {
        let leg = |name: &str, p: Option<&Proxy>| match p {
            Some(p) => format!("{name}={}://{}", scheme_word(p.kind), p.endpoint()),
            None => format!("{name}=direct"),
        };
        let mut s = format!(
            "{} {}",
            leg("https", self.https.as_ref()),
            leg("http", self.http.as_ref())
        );
        if !self.no_proxy.is_empty() {
            s.push_str(" no_proxy=set");
        }
        s
    }
}

fn scheme_word(kind: ProxyKind) -> &'static str {
    match kind {
        ProxyKind::Http => "http",
        ProxyKind::Socks5 => "socks5",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_supported_scheme_with_its_default_port() {
        for (raw, kind, port) in [
            ("http://proxy.corp", ProxyKind::Http, 80),
            ("https://proxy.corp", ProxyKind::Http, 443),
            ("socks5://proxy.corp", ProxyKind::Socks5, 1080),
            ("socks5h://proxy.corp", ProxyKind::Socks5, 1080),
        ] {
            let p = Proxy::parse(raw).expect(raw);
            assert_eq!(p.kind, kind, "{raw}");
            assert_eq!(p.port, port, "{raw}");
            assert_eq!(p.host, "proxy.corp");
        }
        assert_eq!(Proxy::parse("http://proxy.corp:3128").unwrap().port, 3128);
    }

    #[test]
    fn an_unsupported_scheme_is_an_error_not_a_silent_direct_dial() {
        assert!(matches!(
            Proxy::parse("ftp://proxy.corp"),
            Err(ProxyError::Scheme { .. })
        ));
        assert!(matches!(Proxy::parse("not a url"), Err(ProxyError::Url(_))));
    }

    #[test]
    fn credentials_never_appear_in_debug_or_endpoint() {
        let p = Proxy::parse("http://user:hunter2@proxy.corp:3128").unwrap();
        let auth = p.auth.as_ref().expect("userinfo parsed");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "hunter2");
        let rendered = format!("{:?} {}", p, p.endpoint());
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn no_proxy_matches_exact_and_suffix_on_a_label_boundary() {
        let np = NoProxy::parse("corp.example, .internal ,localhost");
        assert!(np.bypasses("corp.example"));
        assert!(np.bypasses("api.corp.example"));
        assert!(np.bypasses("svc.internal"));
        assert!(np.bypasses("LOCALHOST"));
        assert!(
            np.bypasses("corp.example."),
            "trailing dot is the same host"
        );
        assert!(
            !np.bypasses("notcorp.example"),
            "a suffix must sit on a label boundary"
        );
        assert!(!np.bypasses("example"));
    }

    #[test]
    fn a_star_entry_bypasses_everything() {
        assert!(NoProxy::parse("*").bypasses("anything.at.all"));
        assert!(NoProxy::parse("").is_empty());
    }

    #[test]
    fn a_cidr_entry_does_not_silently_match_its_range() {
        let np = NoProxy::parse("10.0.0.0/8");
        assert!(
            !np.bypasses("10.1.2.3"),
            "CIDR is not interpreted; it must not appear to work"
        );
    }

    #[test]
    fn select_honours_scheme_and_bypass() {
        let cfg = ProxyConfig {
            https: Some(Proxy::parse("http://secure.corp:3128").unwrap()),
            http: Some(Proxy::parse("http://plain.corp:8080").unwrap()),
            no_proxy: NoProxy::parse("internal.example"),
        };
        assert_eq!(cfg.select("api.example", true).unwrap().port, 3128);
        assert_eq!(cfg.select("api.example", false).unwrap().port, 8080);
        assert!(cfg.select("internal.example", true).is_none());
    }

    #[test]
    fn env_precedence_prefers_scheme_specific_then_all_proxy() {
        let cfg = ProxyConfig::from_lookup(|k| match k {
            "ALL_PROXY" => Some("socks5://fallback.corp:1080".into()),
            "HTTPS_PROXY" => Some("http://secure.corp:3128".into()),
            "NO_PROXY" => Some("internal.example".into()),
            _ => None,
        })
        .unwrap()
        .expect("some proxy configured");
        assert_eq!(cfg.https.as_ref().unwrap().port, 3128);
        assert_eq!(
            cfg.http.as_ref().unwrap().kind,
            ProxyKind::Socks5,
            "http falls back to ALL_PROXY"
        );
        assert!(cfg.no_proxy.bypasses("internal.example"));
    }

    #[test]
    fn lowercase_wins_over_uppercase() {
        let cfg = ProxyConfig::from_lookup(|k| match k {
            "http_proxy" => Some("http://lower.corp:1111".into()),
            "HTTP_PROXY" => Some("http://upper.corp:2222".into()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.http.as_ref().unwrap().port, 1111);
    }

    #[test]
    fn no_env_means_no_config_rather_than_an_empty_one() {
        assert!(ProxyConfig::from_lookup(|_| None).unwrap().is_none());
        assert!(
            ProxyConfig::from_lookup(|_| Some("   ".into()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_malformed_env_value_is_reported_not_ignored() {
        let err =
            ProxyConfig::from_lookup(|k| (k == "HTTPS_PROXY").then(|| "ftp://nope".to_string()));
        assert!(err.is_err(), "a typo must not silently dial direct");
    }

    #[test]
    fn summary_is_credential_free() {
        let cfg = ProxyConfig::all(Proxy::parse("http://u:p@proxy.corp:3128").unwrap())
            .with_no_proxy(NoProxy::parse("internal.example"));
        let s = cfg.summary();
        assert!(s.contains("proxy.corp:3128"), "{s}");
        assert!(!s.contains('p') || !s.contains("u:p"), "{s}");
        assert!(s.contains("no_proxy=set"), "{s}");
    }
}
