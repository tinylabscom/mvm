//! Exporter configuration from the standard OpenTelemetry environment.

use std::fmt;
use std::time::Duration;

use mvm_http::{HeaderMap, HeaderName, HeaderValue, Url};

/// Signal-specific endpoint, used exactly as given.
pub const ENV_TRACES_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
/// Base endpoint; the traces path is appended.
pub const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// `name=value` pairs separated by commas, values percent-encoded.
pub const ENV_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
/// Per-request timeout in milliseconds.
pub const ENV_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TIMEOUT";
/// `service.name` resource attribute.
pub const ENV_SERVICE_NAME: &str = "OTEL_SERVICE_NAME";
/// Target filter for the exporter's own layer, independent of the log filter.
pub const ENV_FILTER: &str = "MVM_OTLP_FILTER";

/// Filter applied to exported spans when [`ENV_FILTER`] is unset.
pub const DEFAULT_FILTER: &str = "info";
/// Timeout applied when [`ENV_TIMEOUT`] is unset or unparseable; the
/// OpenTelemetry default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10_000);

const TRACES_PATH: &str = "v1/traces";

/// Why the environment could not produce an exporter.
///
/// No variant carries the endpoint as written. An endpoint can embed a
/// credential, and these errors are printed to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The endpoint is not an absolute URL.
    InvalidEndpoint { reason: String },
    /// The endpoint carries a username or password. It would be echoed by
    /// every message that names the endpoint; credentials belong in
    /// the headers variable, which is never printed.
    CredentialsInEndpoint,
    /// `http://` to a host that is not loopback would carry span contents and
    /// any credential headers across a network in the clear.
    CleartextToRemoteHost { host: String },
    /// Only `http` and `https` are OTLP/HTTP transports.
    UnsupportedScheme { scheme: String },
    /// A header entry is malformed or not a legal HTTP header. Names the entry
    /// by header name only; a value can be a credential.
    InvalidHeader { name: String, reason: &'static str },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint { reason } => write!(f, "invalid OTLP endpoint: {reason}"),
            Self::CredentialsInEndpoint => write!(
                f,
                "refusing an OTLP endpoint that embeds a username or password; \
                 pass credentials through {ENV_HEADERS}"
            ),
            Self::CleartextToRemoteHost { host } => write!(
                f,
                "refusing cleartext OTLP export to non-loopback host '{host}'; use https://"
            ),
            Self::UnsupportedScheme { scheme } => write!(
                f,
                "unsupported OTLP endpoint scheme '{scheme}'; use https:// or loopback http://"
            ),
            Self::InvalidHeader { name, reason } => {
                write!(f, "invalid {ENV_HEADERS} entry '{name}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// A validated exporter configuration.
///
/// Construction enforces the transport rule, so holding one means the endpoint
/// is `https://` or loopback `http://`.
#[derive(Clone)]
pub struct OtlpConfig {
    endpoint: Url,
    headers: HeaderMap,
    timeout: Duration,
    service_name: String,
    filter: String,
}

impl fmt::Debug for OtlpConfig {
    // Header values commonly carry collector API keys, so only names print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(HeaderName::as_str).collect();
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("headers", &header_names)
            .field("header_values", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("service_name", &self.service_name)
            .field("filter", &self.filter)
            .finish()
    }
}

impl OtlpConfig {
    /// Read the process environment. `Ok(None)` when no endpoint is set.
    pub fn from_env(default_service_name: &str) -> Result<Option<Self>, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok(), default_service_name)
    }

    /// Read configuration through `lookup`, so callers and tests need not
    /// mutate process-global environment. `Ok(None)` when no endpoint is set.
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
        default_service_name: &str,
    ) -> Result<Option<Self>, ConfigError> {
        let Some(endpoint) = resolve_endpoint(&lookup) else {
            return Ok(None);
        };
        let endpoint = parse_endpoint(&endpoint)?;
        let headers = match non_empty(&lookup, ENV_HEADERS) {
            Some(raw) => parse_headers(&raw)?,
            None => HeaderMap::new(),
        };
        Ok(Some(Self {
            endpoint,
            headers,
            timeout: parse_timeout(non_empty(&lookup, ENV_TIMEOUT).as_deref()),
            service_name: non_empty(&lookup, ENV_SERVICE_NAME)
                .unwrap_or_else(|| default_service_name.to_string()),
            filter: non_empty(&lookup, ENV_FILTER).unwrap_or_else(|| DEFAULT_FILTER.to_string()),
        }))
    }

    /// The full traces URL requests are POSTed to.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Headers added to every export request.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Bound on a single export request, connect included.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The `service.name` resource attribute.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Target filter directives for the exporter layer.
    pub fn filter(&self) -> &str {
        &self.filter
    }
}

fn non_empty(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The signal-specific variable wins and is used verbatim; the base variable
/// gets the traces path appended, as the OpenTelemetry convention specifies.
fn resolve_endpoint(lookup: &impl Fn(&str) -> Option<String>) -> Option<String> {
    non_empty(lookup, ENV_TRACES_ENDPOINT)
        .or_else(|| non_empty(lookup, ENV_ENDPOINT).map(|base| join_traces_path(&base)))
}

fn join_traces_path(base: &str) -> String {
    format!("{}/{TRACES_PATH}", base.trim_end_matches('/'))
}

fn parse_endpoint(raw: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(raw).map_err(|e| ConfigError::InvalidEndpoint {
        reason: e.to_string(),
    })?;
    // Checked before the scheme so that no later error, and no log line that
    // names the endpoint, can carry the credential.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::CredentialsInEndpoint);
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if mvm_http::is_loopback_host(&url) => Ok(url),
        "http" => Err(ConfigError::CleartextToRemoteHost {
            host: url.host_str().unwrap_or_default().to_string(),
        }),
        scheme => Err(ConfigError::UnsupportedScheme {
            scheme: scheme.to_string(),
        }),
    }
}

fn parse_timeout(raw: Option<&str>) -> Duration {
    raw.and_then(|ms| ms.parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map_or(DEFAULT_TIMEOUT, Duration::from_millis)
}

/// Parse `name=value,name2=value2`. Empty entries (a trailing comma) are
/// ignored; anything else that is not a legal header refuses the whole set,
/// because exporting without an intended auth header only trades a clear
/// configuration error for a stream of rejected requests.
fn parse_headers(raw: &str) -> Result<HeaderMap, ConfigError> {
    let mut headers = HeaderMap::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (name, value) = parse_header_entry(entry)?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn parse_header_entry(entry: &str) -> Result<(HeaderName, HeaderValue), ConfigError> {
    let Some((name, value)) = entry.split_once('=') else {
        return Err(ConfigError::InvalidHeader {
            name: entry.to_string(),
            reason: "expected name=value",
        });
    };
    let name = name.trim();
    let invalid = |reason| ConfigError::InvalidHeader {
        name: name.to_string(),
        reason,
    };
    let header_name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid("not a valid header name"))?;
    let decoded: Vec<u8> = percent_encoding::percent_decode_str(value.trim()).collect();
    let header_value =
        HeaderValue::from_bytes(&decoded).map_err(|_| invalid("not a valid header value"))?;
    Ok((header_name, header_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<Option<OtlpConfig>, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        OtlpConfig::from_lookup(|name| map.get(name).cloned(), "mvmctl")
    }

    fn endpoint_of(vars: &[(&str, &str)]) -> String {
        config(vars).unwrap().unwrap().endpoint().to_string()
    }

    #[test]
    fn no_endpoint_means_no_exporter() {
        assert!(config(&[]).unwrap().is_none());
        assert!(config(&[(ENV_ENDPOINT, "  ")]).unwrap().is_none());
        assert!(
            config(&[(ENV_HEADERS, "a=b"), (ENV_SERVICE_NAME, "x")])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_traces_endpoint_wins_and_is_used_verbatim() {
        let url = endpoint_of(&[
            (ENV_TRACES_ENDPOINT, "https://traces.example.com/custom"),
            (ENV_ENDPOINT, "https://base.example.com"),
        ]);
        assert_eq!(url, "https://traces.example.com/custom");
    }

    #[test]
    fn the_base_endpoint_gets_the_traces_path_with_or_without_a_trailing_slash() {
        for base in [
            "https://collector.example.com",
            "https://collector.example.com/",
        ] {
            assert_eq!(
                endpoint_of(&[(ENV_ENDPOINT, base)]),
                "https://collector.example.com/v1/traces"
            );
        }
        assert_eq!(
            endpoint_of(&[(ENV_ENDPOINT, "https://collector.example.com/otlp/")]),
            "https://collector.example.com/otlp/v1/traces"
        );
    }

    #[test]
    fn cleartext_http_is_allowed_to_loopback_hosts() {
        for endpoint in [
            "http://localhost:4318",
            "http://127.0.0.1:4318",
            "http://[::1]:4318",
        ] {
            assert!(
                config(&[(ENV_ENDPOINT, endpoint)]).unwrap().is_some(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn cleartext_http_to_a_remote_host_is_refused() {
        let err = config(&[(ENV_ENDPOINT, "http://collector.example.com:4318")]).unwrap_err();
        assert!(matches!(err, ConfigError::CleartextToRemoteHost { .. }));
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn an_endpoint_carrying_credentials_is_refused_without_echoing_them() {
        for endpoint in [
            "https://user:s3cret-token@collector.example.com",
            "https://s3cret-token@collector.example.com",
            "http://user:s3cret-token@collector.example.com",
            "grpc://user:s3cret-token@localhost:4317",
        ] {
            let err = config(&[(ENV_ENDPOINT, endpoint)]).unwrap_err();
            assert_eq!(err, ConfigError::CredentialsInEndpoint, "{endpoint}");
            assert!(!err.to_string().contains("s3cret-token"), "{err}");
        }
    }

    #[test]
    fn endpoint_errors_do_not_repeat_the_endpoint_as_written() {
        let err = config(&[(ENV_ENDPOINT, "http://collector.example.com:4318/p?k=v")]).unwrap_err();
        assert!(!err.to_string().contains("k=v"), "{err}");
        let err = config(&[(ENV_ENDPOINT, "not a url k=v")]).unwrap_err();
        assert!(!err.to_string().contains("k=v"), "{err}");
    }

    #[test]
    fn https_is_allowed_to_any_host() {
        assert!(
            config(&[(ENV_ENDPOINT, "https://collector.example.com")])
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_non_http_scheme_or_unparseable_endpoint_is_refused() {
        assert!(matches!(
            config(&[(ENV_TRACES_ENDPOINT, "grpc://localhost:4317")]).unwrap_err(),
            ConfigError::UnsupportedScheme { .. }
        ));
        assert!(matches!(
            config(&[(ENV_TRACES_ENDPOINT, "localhost:4318")]).unwrap_err(),
            ConfigError::UnsupportedScheme { .. } | ConfigError::InvalidEndpoint { .. }
        ));
        assert!(matches!(
            config(&[(ENV_TRACES_ENDPOINT, "not a url")]).unwrap_err(),
            ConfigError::InvalidEndpoint { .. }
        ));
    }

    #[test]
    fn headers_are_trimmed_and_percent_decoded() {
        let cfg = config(&[
            (ENV_ENDPOINT, "https://c.example.com"),
            (
                ENV_HEADERS,
                " authorization = Bearer%20abc%3D%3D , x-tenant=a%2Cb,",
            ),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(cfg.headers()["authorization"], "Bearer abc==");
        assert_eq!(cfg.headers()["x-tenant"], "a,b");
        assert_eq!(cfg.headers().len(), 2);
    }

    #[test]
    fn an_invalid_header_name_refuses_the_configuration() {
        let err = config(&[
            (ENV_ENDPOINT, "https://c.example.com"),
            (ENV_HEADERS, "bad name=value"),
        ])
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHeader { .. }));
    }

    #[test]
    fn a_header_entry_without_a_value_or_with_a_control_byte_is_refused() {
        for headers in ["justaname", "x-key=bad%0Avalue"] {
            let err = config(&[
                (ENV_ENDPOINT, "https://c.example.com"),
                (ENV_HEADERS, headers),
            ])
            .unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidHeader { .. }),
                "{headers}"
            );
            assert!(!err.to_string().contains("bad"), "value leaked: {err}");
        }
    }

    #[test]
    fn timeout_is_read_in_milliseconds_and_falls_back_when_unparseable() {
        let timeout_of = |raw: &str| {
            config(&[(ENV_ENDPOINT, "https://c.example.com"), (ENV_TIMEOUT, raw)])
                .unwrap()
                .unwrap()
                .timeout()
        };
        assert_eq!(timeout_of("2500"), Duration::from_millis(2500));
        assert_eq!(timeout_of("soon"), DEFAULT_TIMEOUT);
        assert_eq!(timeout_of("-1"), DEFAULT_TIMEOUT);
        assert_eq!(timeout_of("0"), DEFAULT_TIMEOUT);
    }

    #[test]
    fn service_name_and_filter_default_and_override() {
        let base = [(ENV_ENDPOINT, "https://c.example.com")];
        let cfg = config(&base).unwrap().unwrap();
        assert_eq!(cfg.service_name(), "mvmctl");
        assert_eq!(cfg.filter(), DEFAULT_FILTER);
        assert_eq!(cfg.timeout(), DEFAULT_TIMEOUT);

        let cfg = config(&[
            base[0],
            (ENV_SERVICE_NAME, "builder"),
            (ENV_FILTER, "mvm=debug"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(cfg.service_name(), "builder");
        assert_eq!(cfg.filter(), "mvm=debug");
    }

    #[test]
    fn debug_output_names_headers_but_never_prints_their_values() {
        let cfg = config(&[
            (ENV_ENDPOINT, "https://c.example.com"),
            (ENV_HEADERS, "authorization=Bearer%20s3cr3t-token"),
        ])
        .unwrap()
        .unwrap();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("authorization"));
        assert!(!debug.contains("s3cr3t"), "{debug}");
    }
}
