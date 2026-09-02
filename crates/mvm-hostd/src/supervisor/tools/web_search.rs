//! `mvm.web_search` — provider-fronted web search through a
//! per-tenant provider allowlist.
//!
//! The agent passes a query string + (optionally) a
//! preferred provider; the supervisor:
//!
//! 1. Validates the query — non-empty, length-capped, no embedded
//!    control characters that would confuse upstream APIs.
//! 2. Resolves the provider — caller-supplied name (`"brave"`,
//!    `"google"`, …) or the tool's `default_provider` if absent.
//! 3. Checks the provider against the tool's allowlist. An empty
//!    allowlist means *no provider is reachable* (fail-closed
//!    default; operators must opt in per provider).
//! 4. Delegates to an injected [`SearchProvider`] so the
//!    policy/validation layers are testable without an upstream
//!    endpoint connector. The default provider is [`NoopSearchProvider`],
//!    which always returns [`SearchError::Unwired`]; real Brave /
//!    Google / DuckDuckGo impls land in follow-up slices.
//!
//! ## Why provider-name allowlists instead of host allowlists
//!
//! `mvm.web_fetch` constrains the *destination host* (the agent
//! decides where to look). `mvm.web_search` constrains the
//! *provider service* — the agent has no say over which upstream
//! the provider impl ultimately calls. Pinning by provider name is
//! the granularity that matches the security model: an operator
//! grants "Brave can search; not Google, not Bing." A future slice
//! may add per-provider host pinning so a wedged DNS doesn't let a
//! provider impl reach the wrong endpoint.
//!
//! ## What this tool is NOT
//!
//! - Not a fetch tool — see `mvm.web_fetch`.
//! - Not a "let the agent pick any API key" surface — provider
//!   credentials are supervisor-owned. The agent doesn't see them.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use mvm_contract::substitution::Placeholder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use super::http_hardening::DEFAULT_RESPONSE_BODY_CAP;
use super::{HostMediatedTool, ToolInvokeError};
use crate::supervisor::network_endpoint_connector::EndpointHttpConnector;

pub const TOOL_NAME: &str = "mvm.web_search";

/// Default `max_results` when the caller doesn't specify. Bounded
/// at the upper end by [`MAX_ALLOWED_RESULTS`].
pub const DEFAULT_MAX_RESULTS: u32 = 10;

/// Hard upper bound on `max_results`. Caller-supplied values above
/// this are clamped (not errored) so older clients still make
/// progress.
pub const MAX_ALLOWED_RESULTS: u32 = 50;

/// Query-length cap. Defense in depth: most search APIs reject
/// queries longer than ~512 chars anyway, but pre-rejecting here
/// keeps the audit chain from logging giant strings.
pub const MAX_QUERY_LEN: usize = 1024;

fn build_query_url(endpoint: &str, params: &[(&str, &str)]) -> Result<Url, SearchError> {
    let mut url = Url::parse(endpoint)
        .map_err(|e| SearchError::Upstream(format!("invalid provider endpoint {endpoint}: {e}")))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

async fn execute_provider_request(
    connector: &EndpointHttpConnector,
    request: &mvm_core::substitution_wire::WireRequest,
) -> Result<(u16, Vec<u8>), SearchError> {
    let response = connector
        .execute(request)
        .await
        .map_err(|error| SearchError::Upstream(error.to_string()))?;
    match response {
        mvm_core::substitution_wire::WireResponse::Ok {
            status, body_b64, ..
        } => {
            let body = base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .map_err(|_| {
                    SearchError::Upstream("endpoint returned invalid body encoding".into())
                })?;
            if body.len() > DEFAULT_RESPONSE_BODY_CAP {
                return Err(SearchError::Upstream(format!(
                    "response body exceeded {DEFAULT_RESPONSE_BODY_CAP}-byte cap"
                )));
            }
            Ok((status, body))
        }
        mvm_core::substitution_wire::WireResponse::Refused { message } => {
            Err(SearchError::Upstream(message))
        }
    }
}

fn classify_status(provider: &str, status: u16) -> Result<(), SearchError> {
    if status == 429 {
        return Err(SearchError::RateLimited);
    }
    if !(200..300).contains(&status) {
        return Err(SearchError::Upstream(format!(
            "{provider} search returned status {status}"
        )));
    }
    Ok(())
}

/// Pluggable upstream search adapter. Production impls (`BraveProvider`,
/// `GoogleProvider`, …) format typed requests for the endpoint connector;
/// [`NoopSearchProvider`] is the substrate default and returns
/// [`SearchError::Unwired`] so the tool ships fail-closed.
#[async_trait]
pub trait SearchProvider: Send + Sync {
    /// Provider name as exposed to the agent. Must be lowercase,
    /// stable, and unique within a [`WebSearchTool`]'s allowlist.
    fn name(&self) -> &'static str;

    /// Run a search. `max_results` is the post-clamp upper bound;
    /// the impl is free to return fewer.
    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<SearchHit>, SearchError>;
}

/// One result row in the response array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("upstream returned no results")]
    Empty,
    #[error("upstream API error: {0}")]
    Upstream(String),
    #[error("upstream rate-limited")]
    RateLimited,
    #[error("provider not wired (NoopSearchProvider)")]
    Unwired,
}

/// Default fail-closed provider — refuses every call with
/// [`SearchError::Unwired`].
pub struct NoopSearchProvider;

#[async_trait]
impl SearchProvider for NoopSearchProvider {
    fn name(&self) -> &'static str {
        "noop"
    }
    async fn search(&self, _query: &str, _max: u32) -> Result<Vec<SearchHit>, SearchError> {
        Err(SearchError::Unwired)
    }
}

/// Brave Search API provider. Documented at
/// <https://api.search.brave.com/app/documentation>.
///
/// Auth is a `X-Subscription-Token` header carrying the operator's
/// API key. The agent never sees the key — it's pinned inside this
/// struct at construction and consumed only by the HTTP send.
///
/// The provider holds only the endpoint-minted opaque placeholder. The real
/// API key remains inside the endpoint process and is substituted only after
/// destination binding and network-policy admission.
///
/// ## Wire shape
///
/// Brave's `/res/v1/web/search` returns JSON with a `web.results`
/// array; each row carries `{ title, url, description }`. Other
/// fields exist (mixed, query, type, …) but we ignore them — this
/// is an upstream API so `deny_unknown_fields` would brittle the
/// type to a single Brave version. The minimal extractor types
/// `BraveResponse`/`BraveWebResults`/`BraveResult` carry only what
/// we need.
pub struct BraveSearchProvider {
    api_key: Placeholder,
    connector: EndpointHttpConnector,
    endpoint: String,
}

impl BraveSearchProvider {
    /// Canonical Brave Search API endpoint.
    pub const DEFAULT_ENDPOINT: &'static str = "https://api.search.brave.com/res/v1/web/search";

    /// Build with the default endpoint and the per-VM typed connector.
    /// `api_key` is the operator's `X-Subscription-Token` value
    /// represented by an endpoint-minted placeholder; raw credentials are not
    /// accepted by this constructor.
    #[must_use]
    pub fn new(connector_uds_path: impl Into<PathBuf>, api_key: Placeholder) -> Self {
        Self {
            api_key,
            connector: EndpointHttpConnector::new(connector_uds_path, Duration::from_secs(15)),
            endpoint: Self::DEFAULT_ENDPOINT.to_string(),
        }
    }

    /// Override the endpoint — used by tests to point at a mock
    /// HTTP server. Production callers stick with the default.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

/// Minimal extractor for the Brave web-search response. We
/// intentionally do not `deny_unknown_fields` — Brave's payload
/// carries many fields we don't care about and adding/removing one
/// upstream shouldn't break our parse.
#[derive(Debug, Deserialize)]
struct BraveResponse {
    #[serde(default)]
    web: Option<BraveWebResults>,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(Debug, Deserialize)]
struct BraveResult {
    title: String,
    url: String,
    #[serde(default)]
    description: String,
}

#[async_trait]
impl SearchProvider for BraveSearchProvider {
    fn name(&self) -> &'static str {
        "brave"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<SearchHit>, SearchError> {
        // Brave's `count` param caps at 20 per their docs. Clamp
        // before forwarding so a caller-supplied 50 doesn't trip a
        // 422 from upstream.
        let count = max_results.min(20);
        let count_string = count.to_string();
        let request_url = build_query_url(
            &self.endpoint,
            &[("q", query), ("count", count_string.as_str())],
        )?;
        let request = mvm_core::substitution_wire::WireRequest {
            method: "GET".into(),
            url: request_url.to_string(),
            headers: vec![(
                "X-Subscription-Token".into(),
                self.api_key.as_str().to_string(),
            )],
            body_b64: String::new(),
        };
        let (status, body) = execute_provider_request(&self.connector, &request).await?;
        classify_status("Brave", status)?;
        let parsed: BraveResponse = serde_json::from_slice(&body)
            .map_err(|e| SearchError::Upstream(format!("decoding Brave response: {e}")))?;
        let hits: Vec<SearchHit> = parsed
            .web
            .map(|w| w.results)
            .unwrap_or_default()
            .into_iter()
            .map(|r| SearchHit {
                title: r.title,
                url: r.url,
                snippet: r.description,
            })
            .collect();
        if hits.is_empty() {
            return Err(SearchError::Empty);
        }
        Ok(hits)
    }
}

/// One agent-callable search surface, scoped to an allowlist of
/// provider names.
pub struct WebSearchTool {
    /// Provider names the tool is permitted to call. Empty =
    /// nothing reachable (fail-closed).
    allowed_providers: BTreeSet<String>,
    /// Provider used when the agent doesn't specify one. Must
    /// appear in `allowed_providers` to be reachable; if it
    /// doesn't, the search fails closed with a clear message.
    default_provider: String,
    /// Concrete provider impls keyed by `provider.name()`. Built
    /// via [`Self::register_provider`].
    providers: std::collections::BTreeMap<String, Arc<dyn SearchProvider>>,
}

impl WebSearchTool {
    /// Build with an empty allowlist + no providers wired. Every
    /// invoke returns `Upstream` with a clear "no providers
    /// configured" message. Useful as the default until per-tenant
    /// config lands.
    pub fn fail_closed() -> Self {
        Self {
            allowed_providers: BTreeSet::new(),
            default_provider: "noop".to_string(),
            providers: std::collections::BTreeMap::new(),
        }
    }

    /// Build with an explicit provider allowlist + default. The
    /// default is allowed to be a name that isn't registered yet;
    /// a search with the unregistered default fails closed when
    /// invoked (so config drift is loud, not silent).
    pub fn with_allowlist(
        allowed: impl IntoIterator<Item = String>,
        default_provider: String,
    ) -> Self {
        Self {
            allowed_providers: allowed.into_iter().collect(),
            default_provider,
            providers: std::collections::BTreeMap::new(),
        }
    }

    /// Plug a concrete provider impl. Replaces any previous entry
    /// with the same `name()` — useful in tests for swapping a
    /// stub. The provider's name is NOT automatically added to the
    /// allowlist; operators control that surface separately so
    /// "registered" and "permitted" stay distinct concepts.
    pub fn register_provider(mut self, provider: Arc<dyn SearchProvider>) -> Self {
        self.providers.insert(provider.name().to_string(), provider);
        self
    }

    /// Read-only view of the allowlist for diagnostic surfaces.
    pub fn allowlist(&self) -> Vec<&str> {
        self.allowed_providers.iter().map(String::as_str).collect()
    }
}

impl Default for WebSearchTool {
    fn default() -> Self {
        Self::fail_closed()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchParams {
    pub query: String,
    /// Optional provider override. When absent, the tool's
    /// `default_provider` is used. Must appear in the allowlist.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
}

fn default_max_results() -> u32 {
    DEFAULT_MAX_RESULTS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSearchResult {
    pub provider: String,
    pub query: String,
    pub hits: Vec<SearchHit>,
}

#[async_trait]
impl HostMediatedTool for WebSearchTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    async fn invoke(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        let parsed: WebSearchParams =
            serde_json::from_value(params).map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;

        let query = parsed.query.trim();
        if query.is_empty() {
            return Err(ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: "query must be non-empty".to_string(),
            });
        }
        if query.chars().any(|c| c.is_control()) {
            return Err(ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: "query contains control characters".to_string(),
            });
        }
        if query.len() > MAX_QUERY_LEN {
            return Err(ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: format!("query length {} exceeds max {MAX_QUERY_LEN}", query.len()),
            });
        }

        let provider_name = parsed.provider.as_deref().unwrap_or(&self.default_provider);

        if !self.allowed_providers.contains(provider_name) {
            return Err(ToolInvokeError::Upstream {
                tool: TOOL_NAME.to_string(),
                message: format!(
                    "provider {provider_name:?} not on per-tenant allowlist (allowed: {allowed:?})",
                    allowed = self.allowlist()
                ),
            });
        }

        let provider =
            self.providers
                .get(provider_name)
                .ok_or_else(|| ToolInvokeError::Upstream {
                    tool: TOOL_NAME.to_string(),
                    message: format!(
                        "provider {provider_name:?} is allowed but no impl is registered \
                     (config drift between allowlist and provider table)"
                    ),
                })?;

        let max = parsed.max_results.min(MAX_ALLOWED_RESULTS);
        let hits = provider
            .search(query, max)
            .await
            .map_err(|e| ToolInvokeError::Upstream {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;

        serde_json::to_value(WebSearchResult {
            provider: provider_name.to_string(),
            query: query.to_string(),
            hits,
        })
        .map_err(|e| ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("serializing result: {e}"),
        })
    }
}

/// Tavily Search API provider. Documented at
/// <https://docs.tavily.com/api-reference/endpoint/search>.
///
/// Tavily's auth shape differs from Brave's: the API key travels
/// in an authorization header, and the search itself is a POST. The broker
/// carries only a placeholder; the endpoint injects the real key immediately
/// before the external send.
///
/// Tavily is "search-for-LLMs" by design: each result row carries
/// a `content` field that's an LLM-friendly snippet (often longer
/// than Brave's `description`). We map it to `snippet` so the
/// agent surface stays uniform across providers.
pub struct TavilySearchProvider {
    api_key: Placeholder,
    connector: EndpointHttpConnector,
    endpoint: String,
}

impl TavilySearchProvider {
    /// Canonical Tavily Search API endpoint.
    pub const DEFAULT_ENDPOINT: &'static str = "https://api.tavily.com/search";

    /// Default per-call timeout. Tavily aggregates multiple
    /// upstreams and historically responds in 1-3 s; 20 s gives
    /// plenty of headroom for the slow-tail case.
    const DEFAULT_TIMEOUT_SECS: u64 = 20;

    /// Build with the default endpoint and the per-VM typed connector.
    #[must_use]
    pub fn new(connector_uds_path: impl Into<PathBuf>, api_key: Placeholder) -> Self {
        Self {
            api_key,
            connector: EndpointHttpConnector::new(
                connector_uds_path,
                Duration::from_secs(Self::DEFAULT_TIMEOUT_SECS),
            ),
            endpoint: Self::DEFAULT_ENDPOINT.to_string(),
        }
    }

    /// Test seam — point at a mock HTTP server. Production callers
    /// stick with the default.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

/// Minimal extractor for Tavily's `/search` response. Like the
/// Brave extractor, we intentionally do NOT
/// `deny_unknown_fields` — Tavily adds optional fields over time
/// (`answer`, `images`, `follow_up_questions`, `response_time`)
/// and an upstream addition shouldn't brittle our parse.
#[derive(Debug, Deserialize)]
struct TavilyResponse {
    #[serde(default)]
    results: Vec<TavilyResult>,
}

#[derive(Debug, Deserialize)]
struct TavilyResult {
    title: String,
    url: String,
    #[serde(default)]
    content: String,
}

#[async_trait]
impl SearchProvider for TavilySearchProvider {
    fn name(&self) -> &'static str {
        "tavily"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<SearchHit>, SearchError> {
        // Tavily's documented cap is 20 results per call. Clamp so a
        // caller-supplied 50 doesn't trip an upstream 422.
        let max = max_results.min(20);
        let body = serde_json::json!({
            "query": query,
            "max_results": max,
        });
        let request = mvm_core::substitution_wire::WireRequest {
            method: "POST".into(),
            url: self.endpoint.clone(),
            headers: vec![
                (
                    "Authorization".into(),
                    format!("Bearer {}", self.api_key.as_str()),
                ),
                ("Content-Type".into(), "application/json".into()),
            ],
            body_b64: base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&body)
                    .map_err(|error| SearchError::Upstream(error.to_string()))?,
            ),
        };
        let (status, body) = execute_provider_request(&self.connector, &request).await?;
        classify_status("Tavily", status)?;
        let parsed: TavilyResponse = serde_json::from_slice(&body)
            .map_err(|e| SearchError::Upstream(format!("decoding Tavily response: {e}")))?;
        let hits: Vec<SearchHit> = parsed
            .results
            .into_iter()
            .map(|r| SearchHit {
                title: r.title,
                url: r.url,
                snippet: r.content,
            })
            .collect();
        if hits.is_empty() {
            return Err(SearchError::Empty);
        }
        Ok(hits)
    }
}

/// Google Custom Search API provider. Documented at
/// <https://developers.google.com/custom-search/v1/overview>.
///
/// The API key is carried as an opaque `x-goog-api-key` placeholder and
/// substituted by the endpoint after binding and admission. Only the CSE ID,
/// query, and result count appear in the URL. The hand-written `Debug` and
/// error scrubber remain defensive barriers around both identifiers.
pub struct GoogleSearchProvider {
    api_key: Placeholder,
    cse_id: String,
    connector: EndpointHttpConnector,
    endpoint: String,
}

impl GoogleSearchProvider {
    /// Canonical Google Custom Search API endpoint.
    pub const DEFAULT_ENDPOINT: &'static str = "https://www.googleapis.com/customsearch/v1";

    /// Default per-call timeout. Google CSE typically responds in
    /// ~500ms; 15 s covers slow-tail without permitting hung
    /// connections to occupy a tokio task.
    const DEFAULT_TIMEOUT_SECS: u64 = 15;

    /// Build with the default endpoint and per-VM typed connector. `api_key`
    /// is an opaque endpoint placeholder; `cse_id` is the public search-engine
    /// selector placed in the query.
    #[must_use]
    pub fn new(
        connector_uds_path: impl Into<PathBuf>,
        api_key: Placeholder,
        cse_id: impl Into<String>,
    ) -> Self {
        Self {
            api_key,
            cse_id: cse_id.into(),
            connector: EndpointHttpConnector::new(
                connector_uds_path,
                Duration::from_secs(Self::DEFAULT_TIMEOUT_SECS),
            ),
            endpoint: Self::DEFAULT_ENDPOINT.to_string(),
        }
    }

    /// Test seam — point at a mock HTTP server. Production callers
    /// stick with the default.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Redaction helper. Replaces every occurrence of the API
    /// key + CSE ID in `message` with `<REDACTED>`. Public for
    /// tests that want to assert the same redaction shape; the
    /// production path uses it internally before every `SearchError`
    /// emission.
    ///
    /// This is defense in depth for the opaque placeholder and CSE identifier;
    /// the raw API key never enters this process.
    pub fn redact_credentials(&self, message: String) -> String {
        let api_key = self.api_key.as_str();
        let scrubbed = if api_key.is_empty() {
            message
        } else {
            message.replace(api_key, "<REDACTED>")
        };
        if self.cse_id.is_empty() {
            scrubbed
        } else {
            scrubbed.replace(&self.cse_id, "<REDACTED>")
        }
    }
}

// Hand-written Debug redacts both credentials. Mirrors the
// `HostSigner` pattern.
//
// allow(secret-debug): the Debug impl is the redaction, not a leak.
impl std::fmt::Debug for GoogleSearchProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleSearchProvider")
            .field("api_key", &"<redacted>")
            .field("cse_id", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Minimal extractor for Google Custom Search's response. Like
/// the other provider response types, we intentionally do not
/// `deny_unknown_fields` — Google's payload carries many fields
/// (`queries`, `searchInformation`, `context`, …) that we don't
/// need; tracking them would brittle the parse to a single API
/// version.
#[derive(Debug, Deserialize)]
struct GoogleResponse {
    #[serde(default)]
    items: Vec<GoogleResult>,
}

#[derive(Debug, Deserialize)]
struct GoogleResult {
    title: String,
    link: String,
    #[serde(default)]
    snippet: String,
}

#[async_trait]
impl SearchProvider for GoogleSearchProvider {
    fn name(&self) -> &'static str {
        "google"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<SearchHit>, SearchError> {
        // Google CSE caps `num` at 10 per call. Clamp before
        // forwarding so a caller-supplied 50 doesn't trip a 400.
        let num = max_results.min(10);
        let num_string = num.to_string();
        let request_url = build_query_url(
            &self.endpoint,
            &[
                ("cx", self.cse_id.as_str()),
                ("q", query),
                ("num", num_string.as_str()),
            ],
        )?;
        let request = mvm_core::substitution_wire::WireRequest {
            method: "GET".into(),
            url: request_url.to_string(),
            headers: vec![("x-goog-api-key".into(), self.api_key.as_str().to_string())],
            body_b64: String::new(),
        };
        let (status, body) = execute_provider_request(&self.connector, &request)
            .await
            .map_err(|error| SearchError::Upstream(self.redact_credentials(error.to_string())))?;
        classify_status("Google", status)?;
        let parsed: GoogleResponse = serde_json::from_slice(&body).map_err(|e| {
            SearchError::Upstream(self.redact_credentials(format!("decoding Google response: {e}")))
        })?;
        let hits: Vec<SearchHit> = parsed
            .items
            .into_iter()
            .map(|r| SearchHit {
                title: r.title,
                url: r.link,
                snippet: r.snippet,
            })
            .collect();
        if hits.is_empty() {
            return Err(SearchError::Empty);
        }
        Ok(hits)
    }
}

/// Parse a comma-separated env-var into a set of provider names.
/// Same shape as [`crate::supervisor::tools::web_fetch::allowlist_from_env_var`];
/// kept as a sibling for tidiness rather than re-exported, since
/// the audit / error messages here name "provider" specifically.
///
/// Example: `MVM_WEB_SEARCH_ALLOWLIST=brave,google`.
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

/// Canonical env-var name for the `mvm.web_search` provider
/// allowlist.
pub const ALLOWLIST_ENV_VAR: &str = "MVM_WEB_SEARCH_ALLOWLIST";

/// Canonical env-var name for the `mvm.web_search` default
/// provider. Must appear in the allowlist to be reachable.
pub const DEFAULT_PROVIDER_ENV_VAR: &str = "MVM_WEB_SEARCH_DEFAULT";

/// Canonical env-var name for the operator's Brave Search API key.
/// When unset (and `"brave"` is on the allowlist), the "allowed
/// but unregistered" config-drift error fires on first invoke.
pub const BRAVE_API_KEY_ENV_VAR: &str = "BRAVE_SEARCH_API_KEY";

/// Canonical env-var name for the operator's Tavily API key. Same
/// posture as [`BRAVE_API_KEY_ENV_VAR`] — set this and put
/// `"tavily"` on `MVM_WEB_SEARCH_ALLOWLIST` to enable.
pub const TAVILY_API_KEY_ENV_VAR: &str = "TAVILY_API_KEY";

/// Canonical env-var name for the operator's Google Cloud API
/// key. Paired with [`GOOGLE_CSE_ID_ENV_VAR`]; both must be set
/// AND `"google"` must appear on `MVM_WEB_SEARCH_ALLOWLIST` for
/// the Google provider to be reachable.
pub const GOOGLE_API_KEY_ENV_VAR: &str = "GOOGLE_API_KEY";

/// Canonical env-var name for the operator's Google Custom Search
/// Engine ID (the `cx=` parameter). See
/// [`GOOGLE_API_KEY_ENV_VAR`].
pub const GOOGLE_CSE_ID_ENV_VAR: &str = "GOOGLE_CSE_ID";

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn sk(s: &str) -> Placeholder {
        Placeholder::new(s)
    }

    fn connector() -> &'static str {
        "/tmp/mvm-search-endpoint.sock"
    }

    async fn spawn_connector(
        body: &'static [u8],
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        tokio::sync::oneshot::Receiver<mvm_core::substitution_wire::WireRequest>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = crate::framing::read_json_frame(&mut stream, 16 * 1024 * 1024)
                .await
                .unwrap();
            tx.send(request).ok();
            crate::framing::write_json_frame(
                &mut stream,
                &mvm_core::substitution_wire::WireResponse::Ok {
                    status: 200,
                    headers: Vec::new(),
                    body_b64: base64::engine::general_purpose::STANDARD.encode(body),
                },
            )
            .await
            .unwrap();
        });
        (dir, path, rx)
    }

    struct StubProvider {
        name: &'static str,
        calls: std::sync::Mutex<Vec<(String, u32)>>,
        response: Vec<SearchHit>,
    }

    impl StubProvider {
        fn new(name: &'static str, response: Vec<SearchHit>) -> Self {
            Self {
                name,
                calls: std::sync::Mutex::new(Vec::new()),
                response,
            }
        }
        fn calls(&self) -> Vec<(String, u32)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SearchProvider for StubProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn search(&self, query: &str, max: u32) -> Result<Vec<SearchHit>, SearchError> {
            self.calls.lock().unwrap().push((query.to_string(), max));
            Ok(self.response.clone())
        }
    }

    fn hits_sample() -> Vec<SearchHit> {
        vec![
            SearchHit {
                title: "Rust".into(),
                url: "https://www.rust-lang.org".into(),
                snippet: "systems language".into(),
            },
            SearchHit {
                title: "Cargo".into(),
                url: "https://crates.io".into(),
                snippet: "package registry".into(),
            },
        ]
    }

    #[test]
    fn build_query_url_encodes_pairs() {
        let url = build_query_url(
            "https://example.com/search",
            &[("q", "rust async"), ("count", "10")],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/search?q=rust+async&count=10"
        );
    }

    #[test]
    fn build_query_url_rejects_invalid_endpoint() {
        let err = build_query_url("not a url", &[("q", "rust")]).unwrap_err();
        assert!(matches!(err, SearchError::Upstream(_)));
        assert!(err.to_string().contains("invalid provider endpoint"));
    }

    fn tool_with_stub(
        allow: &[&str],
        default: &str,
        provider_name: &'static str,
    ) -> (WebSearchTool, Arc<StubProvider>) {
        let stub = Arc::new(StubProvider::new(provider_name, hits_sample()));
        let tool =
            WebSearchTool::with_allowlist(allow.iter().map(|s| s.to_string()), default.to_string())
                .register_provider(stub.clone());
        (tool, stub)
    }

    // ──────────────────────────────────────────────────────────────
    // Policy: provider allowlist
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn allowlist_blocks_unconfigured_provider() {
        let tool = WebSearchTool::with_allowlist(["brave".to_string()], "brave".to_string());
        let err = tool
            .invoke(serde_json::json!({
                "query": "rust async",
                "provider": "google"
            }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { tool, message } => {
                assert_eq!(tool, TOOL_NAME);
                assert!(message.contains("google"), "{message}");
                assert!(message.contains("not on per-tenant allowlist"), "{message}");
                // The allowed providers show up so an operator can
                // see "ah, only brave is on".
                assert!(message.contains("brave"), "{message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_allowlist_denies_every_provider() {
        let tool = WebSearchTool::fail_closed();
        let err = tool
            .invoke(serde_json::json!({ "query": "x" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::Upstream { .. }));
    }

    #[tokio::test]
    async fn allowlisted_provider_falls_through_to_impl() {
        let (tool, stub) = tool_with_stub(&["brave"], "brave", "brave");
        let out = tool
            .invoke(serde_json::json!({ "query": "rust async" }))
            .await
            .unwrap();
        let parsed: WebSearchResult = serde_json::from_value(out).unwrap();
        assert_eq!(parsed.provider, "brave");
        assert_eq!(parsed.query, "rust async");
        assert_eq!(parsed.hits.len(), 2);
        // Provider saw the trimmed query + clamped max.
        let calls = stub.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "rust async");
        assert_eq!(calls[0].1, DEFAULT_MAX_RESULTS);
    }

    #[tokio::test]
    async fn explicit_provider_overrides_default() {
        let (tool, _stub) = tool_with_stub(&["brave", "google"], "brave", "google");
        // The default is "brave" but the agent asks for "google";
        // since "google" is on the allowlist and a Google provider
        // is registered, the explicit choice wins.
        let out = tool
            .invoke(serde_json::json!({
                "query": "rust",
                "provider": "google"
            }))
            .await
            .unwrap();
        let parsed: WebSearchResult = serde_json::from_value(out).unwrap();
        assert_eq!(parsed.provider, "google");
    }

    #[tokio::test]
    async fn allowlisted_but_unregistered_provider_fails_loudly() {
        // Operator put "brave" on the allowlist but the supervisor
        // didn't register a provider impl for it. Caller gets a
        // clear "config drift" message rather than a silent fall-
        // through.
        let tool = WebSearchTool::with_allowlist(["brave".to_string()], "brave".to_string());
        let err = tool
            .invoke(serde_json::json!({ "query": "x" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(message.contains("config drift"), "{message}");
                assert!(message.contains("brave"), "{message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Query validation
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_empty_query() {
        let (tool, _) = tool_with_stub(&["brave"], "brave", "brave");
        let err = tool
            .invoke(serde_json::json!({ "query": "" }))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
        assert!(msg.contains("non-empty"), "got: {msg}");
    }

    #[tokio::test]
    async fn rejects_whitespace_only_query() {
        let (tool, _) = tool_with_stub(&["brave"], "brave", "brave");
        let err = tool
            .invoke(serde_json::json!({ "query": "   \t  " }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn rejects_query_with_control_characters() {
        // A control byte in the query would confuse upstream APIs
        // (or worse, smuggle through TLS). Pre-reject so the audit
        // chain doesn't log it either.
        let (tool, _) = tool_with_stub(&["brave"], "brave", "brave");
        let err = tool
            .invoke(serde_json::json!({ "query": "hello\nworld" }))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("control characters"), "got: {msg}");
    }

    #[tokio::test]
    async fn rejects_overlong_query() {
        let (tool, _) = tool_with_stub(&["brave"], "brave", "brave");
        let query = "x".repeat(MAX_QUERY_LEN + 1);
        let err = tool
            .invoke(serde_json::json!({ "query": query }))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds max"), "got: {msg}");
    }

    #[tokio::test]
    async fn rejects_unknown_field() {
        let (tool, _) = tool_with_stub(&["brave"], "brave", "brave");
        let err = tool
            .invoke(serde_json::json!({
                "query": "x",
                "extra": 1
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    // ──────────────────────────────────────────────────────────────
    // max_results plumbing
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn caller_max_results_clamped_to_max_allowed() {
        let (tool, stub) = tool_with_stub(&["brave"], "brave", "brave");
        tool.invoke(serde_json::json!({
            "query": "x",
            "max_results": 9999_u32
        }))
        .await
        .unwrap();
        assert_eq!(stub.calls()[0].1, MAX_ALLOWED_RESULTS);
    }

    #[tokio::test]
    async fn custom_max_results_passes_through() {
        let (tool, stub) = tool_with_stub(&["brave"], "brave", "brave");
        tool.invoke(serde_json::json!({
            "query": "x",
            "max_results": 3_u32
        }))
        .await
        .unwrap();
        assert_eq!(stub.calls()[0].1, 3);
    }

    // ──────────────────────────────────────────────────────────────
    // Trait surface
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn tool_name_is_canonical_mvm_prefix() {
        let tool = WebSearchTool::default();
        assert_eq!(tool.name(), TOOL_NAME);
        assert!(TOOL_NAME.starts_with("mvm."));
    }

    #[test]
    fn noop_provider_is_named_noop() {
        let p = NoopSearchProvider;
        assert_eq!(p.name(), "noop");
    }

    #[test]
    fn build_query_url_appends_and_encodes_params() {
        let url = build_query_url(
            "https://example.test/search",
            &[("q", "rust async"), ("count", "20")],
        )
        .expect("url");
        assert_eq!(
            url.as_str(),
            "https://example.test/search?q=rust+async&count=20"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // BraveSearchProvider
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn brave_provider_is_named_brave() {
        let p = BraveSearchProvider::new(connector(), sk("test-key"));
        assert_eq!(p.name(), "brave");
    }

    #[test]
    fn brave_provider_constructs_with_default_endpoint() {
        let p = BraveSearchProvider::new(connector(), sk("key"));
        assert_eq!(p.endpoint, BraveSearchProvider::DEFAULT_ENDPOINT);
    }

    #[test]
    fn brave_provider_with_endpoint_overrides() {
        let p = BraveSearchProvider::new(connector(), sk("key"))
            .with_endpoint("https://mock.test/search");
        assert_eq!(p.endpoint, "https://mock.test/search");
    }

    #[tokio::test]
    async fn brave_routes_a_placeholder_through_the_endpoint_connector() {
        let (_dir, path, request) = spawn_connector(
            br#"{"web":{"results":[{"title":"x","url":"https://x.test","description":"y"}]}}"#,
        )
        .await;
        let provider = BraveSearchProvider::new(path, sk("mvm-secret-deadbeef"));
        provider.search("rust", 1).await.unwrap();
        let request = request.await.unwrap();
        assert_eq!(request.headers[0].1, "mvm-secret-deadbeef");
        assert!(!request.headers[0].1.contains("real-key"));
    }

    #[test]
    fn brave_response_parses_minimal_payload() {
        // Parsing pins: the minimal extractor types must consume a
        // real-shaped Brave response without choking on extra
        // fields and must map description → snippet.
        let json = r#"{
            "type": "search",
            "query": { "original": "rust" },
            "mixed": { "type": "mixed", "main": [], "top": [], "side": [] },
            "web": {
                "type": "search",
                "results": [
                    {
                        "title": "The Rust Programming Language",
                        "url": "https://www.rust-lang.org/",
                        "description": "A language empowering everyone…",
                        "is_source_local": false
                    },
                    {
                        "title": "Cargo",
                        "url": "https://crates.io/",
                        "description": "The Rust package registry"
                    }
                ]
            }
        }"#;
        let parsed: BraveResponse = serde_json::from_str(json).expect("parse");
        let web = parsed.web.expect("web array present");
        assert_eq!(web.results.len(), 2);
        assert_eq!(web.results[0].title, "The Rust Programming Language");
        assert_eq!(web.results[0].url, "https://www.rust-lang.org/");
        assert!(
            web.results[0]
                .description
                .starts_with("A language empowering")
        );
    }

    #[test]
    fn brave_response_handles_missing_web_field() {
        // A search with no results may omit the `web` key entirely.
        // Don't panic; map to empty hits.
        let json = r#"{ "type": "search", "query": { "original": "x" } }"#;
        let parsed: BraveResponse = serde_json::from_str(json).expect("parse");
        assert!(parsed.web.is_none());
    }

    #[test]
    fn brave_result_tolerates_missing_description() {
        // `description` defaults to empty string when absent, so a
        // snippet-less hit still produces a SearchHit shape.
        let json = r#"{
            "title": "x", "url": "https://x.test/"
        }"#;
        let r: BraveResult = serde_json::from_str(json).expect("parse");
        assert_eq!(r.description, "");
    }

    // ──────────────────────────────────────────────────────────────
    // TavilySearchProvider
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn tavily_provider_is_named_tavily() {
        let p = TavilySearchProvider::new(connector(), sk("test-key"));
        assert_eq!(p.name(), "tavily");
    }

    #[test]
    fn tavily_provider_constructs_with_default_endpoint() {
        let p = TavilySearchProvider::new(connector(), sk("key"));
        assert_eq!(p.endpoint, TavilySearchProvider::DEFAULT_ENDPOINT);
    }

    #[test]
    fn tavily_provider_with_endpoint_overrides() {
        let p = TavilySearchProvider::new(connector(), sk("key"))
            .with_endpoint("https://mock.test/search");
        assert_eq!(p.endpoint, "https://mock.test/search");
    }

    #[tokio::test]
    async fn tavily_routes_a_placeholder_through_the_endpoint_connector() {
        let (_dir, path, request) =
            spawn_connector(br#"{"results":[{"title":"x","url":"https://x.test","content":"y"}]}"#)
                .await;
        let provider = TavilySearchProvider::new(path, sk("mvm-secret-deadbeef"));
        provider.search("rust", 1).await.unwrap();
        let request = request.await.unwrap();
        assert_eq!(request.headers[0].1, "Bearer mvm-secret-deadbeef");
        let body = base64::engine::general_purpose::STANDARD
            .decode(request.body_b64)
            .unwrap();
        assert!(!String::from_utf8(body).unwrap().contains("api_key"));
    }

    #[test]
    fn tavily_response_parses_canonical_payload() {
        let json = r#"{
            "query": "rust async",
            "response_time": 1.23,
            "results": [
                {
                    "title": "Tokio",
                    "url": "https://tokio.rs/",
                    "content": "An asynchronous runtime for Rust",
                    "score": 0.95,
                    "raw_content": null
                },
                {
                    "title": "async-std",
                    "url": "https://async.rs/",
                    "content": "Async version of the Rust standard library"
                }
            ]
        }"#;
        let parsed: TavilyResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].title, "Tokio");
        assert_eq!(parsed.results[0].url, "https://tokio.rs/");
        assert!(parsed.results[0].content.contains("asynchronous"));
    }

    #[test]
    fn tavily_response_handles_missing_results_field() {
        // A query with no hits may omit `results`. The extractor
        // defaults to empty so a downstream `if hits.is_empty()`
        // check fires SearchError::Empty cleanly.
        let json = r#"{ "query": "x", "response_time": 0.4 }"#;
        let parsed: TavilyResponse = serde_json::from_str(json).expect("parse");
        assert!(parsed.results.is_empty());
    }

    #[test]
    fn tavily_result_tolerates_missing_content() {
        // Tavily occasionally returns hits without `content` for
        // image / video rows. Map to empty snippet.
        let json = r#"{
            "title": "x", "url": "https://x.test/"
        }"#;
        let r: TavilyResult = serde_json::from_str(json).expect("parse");
        assert_eq!(r.content, "");
    }

    // ──────────────────────────────────────────────────────────────
    // GoogleSearchProvider
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn google_provider_is_named_google() {
        let p = GoogleSearchProvider::new(connector(), sk("test-key"), "test-cse");
        assert_eq!(p.name(), "google");
    }

    #[test]
    fn google_provider_constructs_with_default_endpoint() {
        let p = GoogleSearchProvider::new(connector(), sk("k"), "c");
        assert_eq!(p.endpoint, GoogleSearchProvider::DEFAULT_ENDPOINT);
    }

    #[tokio::test]
    async fn google_routes_a_placeholder_through_the_endpoint_connector() {
        let (_dir, path, request) =
            spawn_connector(br#"{"items":[{"title":"x","link":"https://x.test","snippet":"y"}]}"#)
                .await;
        let provider = GoogleSearchProvider::new(path, sk("mvm-secret-deadbeef"), "cse");
        provider.search("rust", 1).await.unwrap();
        let request = request.await.unwrap();
        assert_eq!(request.headers[0].1, "mvm-secret-deadbeef");
        assert!(!request.url.contains("key="));
        assert!(request.url.contains("cx=cse"));
    }

    #[test]
    fn google_response_parses_canonical_payload() {
        let json = r#"{
            "kind": "customsearch#search",
            "searchInformation": { "totalResults": "2" },
            "items": [
                {
                    "kind": "customsearch#result",
                    "title": "Tokio",
                    "link": "https://tokio.rs/",
                    "snippet": "An asynchronous runtime for Rust"
                },
                {
                    "title": "async-std",
                    "link": "https://async.rs/",
                    "snippet": "Async stdlib for Rust"
                }
            ]
        }"#;
        let parsed: GoogleResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].title, "Tokio");
        assert_eq!(parsed.items[0].link, "https://tokio.rs/");
        assert!(parsed.items[0].snippet.contains("asynchronous"));
    }

    #[test]
    fn google_response_handles_missing_items_field() {
        let json = r#"{ "kind": "customsearch#search" }"#;
        let parsed: GoogleResponse = serde_json::from_str(json).expect("parse");
        assert!(parsed.items.is_empty());
    }

    #[test]
    fn google_result_tolerates_missing_snippet() {
        let json = r#"{ "title": "x", "link": "https://x.test/" }"#;
        let r: GoogleResult = serde_json::from_str(json).expect("parse");
        assert_eq!(r.snippet, "");
    }

    #[test]
    fn google_provider_debug_redacts_credentials() {
        // The hand-written Debug must NOT print the api_key or
        // cse_id verbatim, so `tracing::error!(provider = ?p,
        // ...)` doesn't leak them into the audit chain.
        let p = GoogleSearchProvider::new(connector(), sk("MY-SECRET-KEY"), "MY-CSE-ID");
        let formatted = format!("{p:?}");
        assert!(
            !formatted.contains("MY-SECRET-KEY"),
            "key leaked into Debug: {formatted}"
        );
        assert!(
            !formatted.contains("MY-CSE-ID"),
            "cse_id leaked into Debug: {formatted}"
        );
        assert!(
            formatted.contains("redacted"),
            "expected explicit redaction marker in Debug: {formatted}"
        );
    }

    #[test]
    fn redact_credentials_removes_api_key_and_cse_id() {
        let p = GoogleSearchProvider::new(connector(), sk("MY-SECRET-KEY"), "MY-CSE-ID");
        let raw = "connect error to \
                   https://www.googleapis.com/customsearch/v1?key=MY-SECRET-KEY&cx=MY-CSE-ID&q=x"
            .to_string();
        let scrubbed = p.redact_credentials(raw);
        assert!(
            !scrubbed.contains("MY-SECRET-KEY"),
            "key leaked through redact_credentials: {scrubbed}"
        );
        assert!(
            !scrubbed.contains("MY-CSE-ID"),
            "cse_id leaked through redact_credentials: {scrubbed}"
        );
        assert!(
            scrubbed.contains("<REDACTED>"),
            "expected explicit marker in redacted output: {scrubbed}"
        );
    }

    #[test]
    fn redact_credentials_handles_empty_inputs_without_expanding() {
        // Edge case: a fixture provider constructed with empty
        // strings would, under naive `String::replace("", ...)`,
        // expand a marker between every character. The impl
        // short-circuits empty inputs to avoid that.
        let p = GoogleSearchProvider::new(connector(), sk(""), "");
        assert_eq!(
            p.redact_credentials("hello world".to_string()),
            "hello world"
        );
    }

    #[tokio::test]
    async fn google_search_network_error_does_not_leak_api_key() {
        // An absent connector must return a payload-free error and cannot fall
        // back to a direct network connection.
        let p = GoogleSearchProvider::new(connector(), sk("MY-SECRET-KEY"), "MY-CSE-ID")
            .with_endpoint("http://127.0.0.1:1/");
        let err = p.search("rust async", 5).await.unwrap_err();
        match err {
            SearchError::Upstream(msg) => {
                assert!(
                    !msg.contains("MY-SECRET-KEY"),
                    "API key leaked into Upstream error: {msg}"
                );
                assert!(
                    !msg.contains("MY-CSE-ID"),
                    "CSE id leaked into Upstream error: {msg}"
                );
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Env-var config helpers
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn allowlist_env_var_parses_comma_separated() {
        let mut env = TestEnv::new();
        let var = "MVM_TEST_WEB_SEARCH_ALLOWLIST_PARSE";
        env.set(var, "brave,google,duckduckgo");
        let set = allowlist_from_env_var(var);
        assert!(set.contains("brave"));
        assert!(set.contains("google"));
        assert!(set.contains("duckduckgo"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn allowlist_env_var_unset_returns_empty_set() {
        let set = allowlist_from_env_var("MVM_TEST_WEB_SEARCH_DEFINITELY_NOT_SET_PLUGH");
        assert!(set.is_empty());
    }
}
