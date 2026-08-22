//! `mvm.web_fetch` — single-URL HTTPS fetch through a per-tenant
//! host allowlist.
//!
//! The agent passes a URL; the supervisor:
//!
//! 1. Parses the URL — rejects anything that isn't a syntactically
//!    valid RFC-3986 absolute reference with an explicit host.
//! 2. Requires `https://` — `http://`, `file://`, `ftp://`, and any
//!    other scheme fail closed. Plain-HTTP fetches would side-step
//!    every cert pin and proxy guarantee the rest of the tool lays
//!    down.
//! 3. Checks the host against the tool's allowlist — an empty
//!    allowlist means *nothing is fetchable* (fail-closed default;
//!    operators must opt in per upstream).
//! 4. Delegates the actual HTTP call to an injected
//!    [`HttpFetcher`] so the policy/validation layers can be tested
//!    without live network IO. The default fetcher is
//!    [`NoopHttpFetcher`], which always returns
//!    [`FetchError::Unwired`]; the hardened impl lands in a
//!    follow-up slice.
//!
//! ## Why bodies come back base64
//!
//! Response bodies may be binary (images, gzip-compressed JSON, the
//! occasional UTF-16 surprise). Base64 over the JSON wire keeps the
//! tool's contract uniform: every fetched byte round-trips losslessly
//! regardless of `Content-Type`. The `bytes` field carries the
//! pre-encoding length so callers can decide whether to skip the
//! decode.
//!
//! ## What this tool is NOT
//!
//! - Not a search tool — `mvm.web_search` is a sibling that takes a
//!   query string and routes through a provider.
//! - Not a download tool — `mvm.download` is for retrieving artifacts
//!   into the agent's persistent overlay (with checksum verification);
//!   `web_fetch` is for inline-by-value reads.
//! - Not a proxy — the tool sends one typed request to the per-VM network
//!   endpoint, which owns all DNS, connects, TLS, transformation, and audit.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use super::{HostMediatedTool, ToolInvokeError};
use crate::supervisor::network_endpoint_connector::EndpointHttpConnector;

pub const TOOL_NAME: &str = "mvm.web_fetch";

/// Default body cap. 1 MiB is the working budget for "fetch a page
/// and pass it back to the LLM"; anything larger should use
/// `mvm.download` into the overlay.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 20;

/// Hard upper bound on `max_bytes` so a misconfigured agent can't
/// request an unbounded read. Caller-supplied values above this are
/// clamped; the JSON schema doesn't reject them so older clients
/// still make progress.
pub const MAX_ALLOWED_BYTES: u64 = 16 * (1 << 20);

/// The supervisor's HTTP-fetch adapter. Injected so the tool's
/// policy/validation layers are testable without live network IO.
#[async_trait]
pub trait HttpFetcher: Send + Sync {
    async fn fetch(&self, url: &Url, max_bytes: u64) -> Result<FetchedResponse, FetchError>;
}

/// Result returned by the fetcher impl.
#[derive(Debug, Clone)]
pub struct FetchedResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("network error: {0}")]
    Network(String),
    #[error("response exceeded max_bytes ({limit})")]
    BodyTooLarge { limit: u64 },
    #[error("non-success status: {status}")]
    BadStatus { status: u16 },
    /// The default fetcher is not wired. A production caller plugs
    /// a real HTTP impl via
    /// [`WebFetchTool::with_fetcher`].
    #[error("fetcher not wired (NoopHttpFetcher)")]
    Unwired,
}

/// Default fetcher — refuses every call with [`FetchError::Unwired`].
/// Used as the substrate's fail-closed placeholder; gets swapped for
/// the endpoint connector adapter in production.
pub struct NoopHttpFetcher;

#[async_trait]
impl HttpFetcher for NoopHttpFetcher {
    async fn fetch(&self, _url: &Url, _max_bytes: u64) -> Result<FetchedResponse, FetchError> {
        Err(FetchError::Unwired)
    }
}

/// Production [`HttpFetcher`] backed by the per-VM endpoint's typed Unix
/// connector. This process performs validation and authorization but cannot
/// resolve or connect to the destination itself. DNS pinning, SSRF refusal,
/// TLS 1.3, no-auto-redirect, substitution, response redaction, and audit are
/// applied by the endpoint's shared hardened forwarder.
#[derive(Debug)]
pub struct HardenedHttpFetcher {
    connector: EndpointHttpConnector,
}

impl HardenedHttpFetcher {
    /// Default timeout for one fetch round-trip (connect + read).
    /// Conservative — most legitimate fetches complete in <2 s; the
    /// 30 s upper bound forgives slow upstreams without letting a
    /// hung connection occupy a tokio task forever.
    pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

    #[must_use]
    pub fn new(connector_uds_path: impl Into<PathBuf>) -> Self {
        Self::with_timeout_secs(connector_uds_path, Self::DEFAULT_TIMEOUT_SECS)
    }

    #[must_use]
    pub fn with_timeout_secs(connector_uds_path: impl Into<PathBuf>, timeout_secs: u64) -> Self {
        Self {
            connector: EndpointHttpConnector::new(
                connector_uds_path,
                Duration::from_secs(timeout_secs),
            ),
        }
    }
}

#[async_trait]
impl HttpFetcher for HardenedHttpFetcher {
    async fn fetch(&self, url: &Url, max_bytes: u64) -> Result<FetchedResponse, FetchError> {
        let request = mvm_core::substitution_wire::WireRequest {
            method: "GET".into(),
            url: url.as_str().to_string(),
            headers: Vec::new(),
            body_b64: String::new(),
        };
        let response = self
            .connector
            .execute(&request)
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?;
        match response {
            mvm_core::substitution_wire::WireResponse::Ok {
                status,
                headers,
                body_b64,
            } => {
                let body = base64::engine::general_purpose::STANDARD
                    .decode(body_b64)
                    .map_err(|_| {
                        FetchError::Network("endpoint returned invalid body encoding".into())
                    })?;
                if body.len() > usize::try_from(max_bytes).unwrap_or(usize::MAX) {
                    return Err(FetchError::BodyTooLarge { limit: max_bytes });
                }
                let content_type = headers
                    .into_iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                    .map(|(_, value)| value);
                Ok(FetchedResponse {
                    status,
                    body,
                    content_type,
                })
            }
            mvm_core::substitution_wire::WireResponse::Refused { message } => {
                Err(FetchError::Network(message))
            }
        }
    }
}

/// Parse a comma-separated env-var value into a set of allowlisted
/// hostnames. Empty/missing returns an empty set (the fail-closed
/// default the substrate ships with).
///
/// Whitespace around commas is trimmed; empty entries are dropped so
/// a trailing comma in the env var doesn't widen the allowlist.
/// Hostnames are stored verbatim — the caller is responsible for
/// ensuring they match `url.host_str()` exactly (lower-case ASCII
/// in practice).
///
/// Example: `MVM_WEB_FETCH_ALLOWLIST=api.openai.com,api.anthropic.com`.
pub fn allowlist_from_env_var(var_name: &str) -> std::collections::BTreeSet<String> {
    let Ok(raw) = std::env::var(var_name) else {
        return std::collections::BTreeSet::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Canonical env-var name carrying the `mvm.web_fetch` host
/// allowlist. Read once at supervisor / dispatcher start.
pub const ALLOWLIST_ENV_VAR: &str = "MVM_WEB_FETCH_ALLOWLIST";

/// One agent-callable web fetch, scoped to an allowlist of upstream
/// hosts.
pub struct WebFetchTool {
    /// Hosts the tool is permitted to fetch from. Empty = nothing
    /// allowed (fail-closed). Match is exact on `url.host_str()` but
    /// case-insensitive: DNS hostnames are case-insensitive and this list is
    /// typed by an operator, so a mixed-case entry must still match. Stored
    /// already lowercased, so the comparison is a plain set lookup.
    /// Wildcards (e.g. `*.example.com`) live in a follow-up slice once we
    /// have a use case for them.
    allowed_hosts: BTreeSet<String>,
    /// Pluggable HTTP impl. Defaults to [`NoopHttpFetcher`].
    fetcher: Arc<dyn HttpFetcher>,
}

impl WebFetchTool {
    /// Empty allowlist + Noop fetcher. Every invoke returns
    /// `Upstream` with a clear "not on allowlist" message. Useful as
    /// the default when no per-tenant config is wired yet.
    pub fn fail_closed() -> Self {
        Self {
            allowed_hosts: BTreeSet::new(),
            fetcher: Arc::new(NoopHttpFetcher),
        }
    }

    /// Build with an explicit host allowlist. Production callers
    /// pull this list from the plan's `egress_policy` bundle (or a
    /// future `tool_policy` field that carries per-tool config).
    pub fn with_allowlist(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            // Normalised once, here, so every later lookup is a plain set
            // membership test rather than a comparison that has to remember
            // to fold case at each call site.
            allowed_hosts: hosts
                .into_iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            fetcher: Arc::new(NoopHttpFetcher),
        }
    }

    /// Swap the default Noop fetcher for a real HTTP impl. Returns
    /// `self` for chaining.
    pub fn with_fetcher(mut self, fetcher: Arc<dyn HttpFetcher>) -> Self {
        self.fetcher = fetcher;
        self
    }

    /// Read-only view of the allowlist for diagnostic surfaces
    /// (`mvmctl doctor`, the error string on a denied fetch).
    pub fn allowlist(&self) -> Vec<&str> {
        self.allowed_hosts.iter().map(String::as_str).collect()
    }
}

impl Default for WebFetchTool {
    fn default() -> Self {
        Self::fail_closed()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebFetchParams {
    pub url: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetchResult {
    pub status: u16,
    pub url: String,
    pub content_type: Option<String>,
    /// URL-safe-no-pad base64 of the response body, capped at
    /// `min(max_bytes, MAX_ALLOWED_BYTES)`.
    pub body_base64: String,
    /// Pre-encoding byte length. Useful for callers that want to
    /// know "is this binary big" without decoding.
    pub bytes: u64,
}

#[async_trait]
impl HostMediatedTool for WebFetchTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    async fn invoke(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        let parsed: WebFetchParams =
            serde_json::from_value(params).map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;

        let url = Url::parse(&parsed.url).map_err(|e| ToolInvokeError::InvalidParams {
            tool: TOOL_NAME.to_string(),
            message: format!("invalid url: {e}"),
        })?;

        if url.scheme() != "https" {
            return Err(ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: format!(
                    "scheme must be https, got {scheme:?}",
                    scheme = url.scheme()
                ),
            });
        }

        let host = url
            .host_str()
            .ok_or_else(|| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: "url missing host".to_string(),
            })?;

        // `Url` already lowercases a domain host, but fold again rather than
        // depend on that: the check must not be one parser change away from
        // silently denying everything.
        if !self.allowed_hosts.contains(&host.to_ascii_lowercase()) {
            return Err(ToolInvokeError::Upstream {
                tool: TOOL_NAME.to_string(),
                message: format!(
                    "host {host:?} not on per-tenant allowlist (allowed: {allowed:?})",
                    allowed = self.allowlist()
                ),
            });
        }

        let max = parsed.max_bytes.min(MAX_ALLOWED_BYTES);
        let resp = self
            .fetcher
            .fetch(&url, max)
            .await
            .map_err(|e| ToolInvokeError::Upstream {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;

        let bytes = resp.body.len() as u64;
        let body_base64 = URL_SAFE_NO_PAD.encode(&resp.body);

        serde_json::to_value(WebFetchResult {
            status: resp.status,
            url: url.to_string(),
            content_type: resp.content_type,
            body_base64,
            bytes,
        })
        .map_err(|e| ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("serializing result: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    // Test fetcher — records its calls + returns canned responses.
    struct StubFetcher {
        calls: std::sync::Mutex<Vec<(String, u64)>>,
        response: FetchedResponse,
    }

    impl StubFetcher {
        fn new(response: FetchedResponse) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                response,
            }
        }
        fn calls(&self) -> Vec<(String, u64)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpFetcher for StubFetcher {
        async fn fetch(&self, url: &Url, max_bytes: u64) -> Result<FetchedResponse, FetchError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), max_bytes));
            Ok(self.response.clone())
        }
    }

    fn tool_with_stub(
        hosts: &[&str],
        response: FetchedResponse,
    ) -> (WebFetchTool, Arc<StubFetcher>) {
        let stub = Arc::new(StubFetcher::new(response));
        let tool = WebFetchTool::with_allowlist(hosts.iter().map(|s| s.to_string()))
            .with_fetcher(stub.clone());
        (tool, stub)
    }

    // ──────────────────────────────────────────────────────────────
    // Policy: allowlist
    // ──────────────────────────────────────────────────────────────

    /// DNS hostnames are case-insensitive, and the allowlist is typed by an
    /// operator into `MVM_WEB_FETCH_ALLOWLIST`. A mixed-case entry must still
    /// match the lowercase host the URL parser produces, or the tool denies
    /// every fetch to a host the operator plainly allowed.
    #[tokio::test]
    async fn allowlist_matching_is_case_insensitive() {
        let tool = WebFetchTool::with_allowlist(["API.Allowed.Example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "https://api.allowed.example/x" }))
            .await
            .unwrap_err();
        // The host IS allowed, so this must not be an allowlist refusal. It
        // fails later (the default fetcher is a Noop), which is fine — what
        // matters is that it got past the gate.
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(
                    !message.contains("not on per-tenant allowlist"),
                    "a mixed-case allowlist entry must still match: {message}"
                );
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    /// The mirror case: an uppercase URL host against a lowercase allowlist
    /// entry. This already held before the allowlist was normalised, because
    /// `Url` lowercases a domain host while parsing — so it is a
    /// characterisation pin on that parser behaviour, not a regression this
    /// fix repaired. It earns its place by failing loudly if that behaviour
    /// ever changes underneath us.
    #[tokio::test]
    async fn an_uppercase_url_host_matches_a_lowercase_allowlist_entry() {
        let tool = WebFetchTool::with_allowlist(["api.allowed.example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "https://API.Allowed.Example/x" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(
                    !message.contains("not on per-tenant allowlist"),
                    "an uppercase URL host must still match: {message}"
                );
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denies_unallowlisted_host() {
        let tool = WebFetchTool::with_allowlist(["api.allowed.example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "https://evil.example/x" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { tool, message } => {
                assert_eq!(tool, TOOL_NAME);
                assert!(message.contains("not on per-tenant allowlist"), "{message}");
                assert!(message.contains("evil.example"), "{message}");
                // The allowed list shows up in the message so an
                // operator can spot "I forgot to allowlist that".
                assert!(message.contains("api.allowed.example"), "{message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_allowlist_denies_every_host() {
        let tool = WebFetchTool::fail_closed();
        let err = tool
            .invoke(serde_json::json!({ "url": "https://anything.example/" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::Upstream { .. }));
    }

    #[tokio::test]
    async fn allowlisted_host_passes_to_fetcher() {
        let (tool, stub) = tool_with_stub(
            &["api.allowed.example"],
            FetchedResponse {
                status: 200,
                body: b"hello".to_vec(),
                content_type: Some("text/plain".to_string()),
            },
        );
        let out = tool
            .invoke(serde_json::json!({ "url": "https://api.allowed.example/v1/x" }))
            .await
            .unwrap();
        let parsed: WebFetchResult = serde_json::from_value(out).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.bytes, 5);
        assert_eq!(parsed.content_type.as_deref(), Some("text/plain"));
        // Body round-trips through base64.
        let decoded = URL_SAFE_NO_PAD.decode(&parsed.body_base64).unwrap();
        assert_eq!(decoded, b"hello");
        // Fetcher saw exactly one call to the requested URL.
        let calls = stub.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://api.allowed.example/v1/x");
    }

    // ──────────────────────────────────────────────────────────────
    // URL validation
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_non_https_scheme() {
        // Plain HTTP would side-step every TLS pin the rest of the
        // tool lays down.
        let tool = WebFetchTool::with_allowlist(["api.allowed.example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "http://api.allowed.example/" }))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
        assert!(msg.contains("https"), "got: {msg}");
    }

    #[tokio::test]
    async fn rejects_unparseable_url() {
        let tool = WebFetchTool::with_allowlist(["api.allowed.example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "not a url" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn rejects_unknown_field() {
        // Host-boundary types use `deny_unknown_fields` so a stale
        // client that adds an unknown param doesn't silently lose it.
        let tool = WebFetchTool::fail_closed();
        let err = tool
            .invoke(serde_json::json!({
                "url": "https://api.allowed.example/",
                "method": "POST"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    // ──────────────────────────────────────────────────────────────
    // max_bytes plumbing
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn default_max_bytes_is_one_mib() {
        let (tool, stub) = tool_with_stub(
            &["api.allowed.example"],
            FetchedResponse {
                status: 200,
                body: vec![],
                content_type: None,
            },
        );
        tool.invoke(serde_json::json!({ "url": "https://api.allowed.example/" }))
            .await
            .unwrap();
        let calls = stub.calls();
        assert_eq!(calls[0].1, DEFAULT_MAX_BYTES);
    }

    #[tokio::test]
    async fn custom_max_bytes_passes_through() {
        let (tool, stub) = tool_with_stub(
            &["api.allowed.example"],
            FetchedResponse {
                status: 200,
                body: vec![],
                content_type: None,
            },
        );
        tool.invoke(serde_json::json!({
            "url": "https://api.allowed.example/",
            "max_bytes": 4096_u64
        }))
        .await
        .unwrap();
        assert_eq!(stub.calls()[0].1, 4096);
    }

    #[tokio::test]
    async fn caller_supplied_max_bytes_clamped_to_max_allowed() {
        // A misconfigured agent shouldn't be able to request an
        // unbounded read.
        let (tool, stub) = tool_with_stub(
            &["api.allowed.example"],
            FetchedResponse {
                status: 200,
                body: vec![],
                content_type: None,
            },
        );
        tool.invoke(serde_json::json!({
            "url": "https://api.allowed.example/",
            "max_bytes": u64::MAX
        }))
        .await
        .unwrap();
        assert_eq!(stub.calls()[0].1, MAX_ALLOWED_BYTES);
    }

    // ──────────────────────────────────────────────────────────────
    // Fetcher errors propagate as Upstream
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn noop_fetcher_surfaces_unwired_via_upstream_error() {
        let tool = WebFetchTool::with_allowlist(["api.allowed.example".to_string()]);
        let err = tool
            .invoke(serde_json::json!({ "url": "https://api.allowed.example/" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { tool, message } => {
                assert_eq!(tool, TOOL_NAME);
                assert!(message.contains("not wired"), "{message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Trait surface
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn tool_name_is_canonical_mvm_prefix() {
        let tool = WebFetchTool::default();
        assert_eq!(tool.name(), TOOL_NAME);
        assert!(TOOL_NAME.starts_with("mvm."));
    }

    #[test]
    fn fail_closed_is_the_default_construction() {
        let t = WebFetchTool::default();
        assert!(t.allowlist().is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // allowlist_from_env_var
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn allowlist_from_env_var_parses_comma_separated() {
        // Use a process-unique var name so parallel tests don't
        // race on the same key.
        let mut env = TestEnv::new();
        let var = "MVM_TEST_WEB_FETCH_ALLOWLIST_PARSE";
        env.set(var, "api.openai.com,api.anthropic.com,api.brave.com");
        let set = allowlist_from_env_var(var);
        assert!(set.contains("api.openai.com"));
        assert!(set.contains("api.anthropic.com"));
        assert!(set.contains("api.brave.com"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn allowlist_from_env_var_drops_empty_entries_and_trims_whitespace() {
        let mut env = TestEnv::new();
        let var = "MVM_TEST_WEB_FETCH_ALLOWLIST_TRIM";
        env.set(var, "  api.openai.com  , ,, api.brave.com,");
        let set = allowlist_from_env_var(var);
        assert!(set.contains("api.openai.com"));
        assert!(set.contains("api.brave.com"));
        // Empty entries (`,,` / trailing comma) and whitespace-only
        // entries don't widen the allowlist.
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn allowlist_from_env_var_unset_returns_empty_set() {
        // A truly-unset var must produce an empty set, not panic.
        // Pick a name unlikely to be set by any CI environment.
        let set = allowlist_from_env_var("MVM_TEST_WEB_FETCH_ALLOWLIST_DEFINITELY_NOT_SET_XYZZY");
        assert!(set.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // HardenedHttpFetcher
    //
    // Live network behaviour is not exercised here — the impl is
    // covered by the policy/validation layer's tests against a
    // stub fetcher. These tests pin the construction surface so a
    // future refactor that breaks `new()` / `with_timeout_secs()`
    // trips loudly.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn hardened_fetcher_constructs_with_default_timeout() {
        let _f = HardenedHttpFetcher::new("/tmp/endpoint.sock");
    }

    #[test]
    fn hardened_fetcher_constructs_with_explicit_timeout() {
        let _f = HardenedHttpFetcher::with_timeout_secs("/tmp/endpoint.sock", 5);
    }

    #[test]
    fn hardened_fetcher_is_a_host_mediated_tool_via_web_fetch() {
        // Compile-check: `HardenedHttpFetcher` satisfies the
        // `HttpFetcher` trait so it slots into
        // `WebFetchTool::with_fetcher`.
        let f = HardenedHttpFetcher::new("/tmp/endpoint.sock");
        let _tool =
            WebFetchTool::with_allowlist(["api.example".to_string()]).with_fetcher(Arc::new(f));
    }

    #[tokio::test]
    async fn unavailable_endpoint_refuses_without_a_direct_network_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let fetcher = HardenedHttpFetcher::new(dir.path().join("absent.sock"));
        let url = Url::parse("https://example.test/").unwrap();
        let err = fetcher.fetch(&url, 1024).await.unwrap_err();
        assert!(matches!(err, FetchError::Network(_)));
    }
}
