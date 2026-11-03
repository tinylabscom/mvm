//! Provider-reported AI token extraction and per-VM budget tracking at the
//! host substitution endpoint.
//!
//! The endpoint already holds cleartext upstream responses. This module
//! inspects JSON bodies from known AI providers, reads their `usage` fields,
//! and turns them into structured token counts. It never logs bodies or
//! credentials.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use mvm_contract::policy::network_policy::AiBudget;
use serde_json::Value;

pub(super) mod request_budget {
    //! Conservative reservations before a request can reach the upstream.

    use std::sync::Mutex;

    use mvm_contract::policy::network_policy::{AiBudgetModel, AiRequestBudget};
    use serde_json::Value;
    use url::Url;

    pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

    /// Reserved attempts and USD millionths; never inferred from response usage.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Reserved {
        pub requests: u64,
        pub spend_microusd: u64,
    }

    pub(crate) struct RequestBudgetTracker {
        limit: AiRequestBudget,
        reserved: Mutex<Reserved>,
        lifetime_id: String,
    }

    impl RequestBudgetTracker {
        pub(crate) fn new(limit: AiRequestBudget) -> Self {
            Self {
                limit,
                reserved: Mutex::new(Reserved::default()),
                lifetime_id: uuid::Uuid::new_v4().to_string(),
            }
        }

        pub(crate) fn lifetime_id(&self) -> &str {
            &self.lifetime_id
        }

        pub(crate) fn audit_labels(
            &self,
            reserved: Reserved,
        ) -> Result<Vec<(String, String)>, &'static str> {
            Ok(vec![
                ("budget_id".into(), self.lifetime_id.clone()),
                (
                    "request_budget".into(),
                    serde_json::to_string(&self.limit).map_err(|_| "ai_budget_audit_encoding")?,
                ),
                ("host".into(), "api.anthropic.com".into()),
                ("port".into(), "443".into()),
                ("reserved_requests".into(), reserved.requests.to_string()),
                (
                    "reserved_spend_microusd".into(),
                    reserved.spend_microusd.to_string(),
                ),
            ])
        }

        /// Commit both dimensions atomically. Errors and cancellation do not refund.
        pub(crate) fn reserve(&self, cost_microusd: u64) -> Result<Reserved, &'static str> {
            let mut current = self.reserved.lock().map_err(|_| "ai_budget_poisoned")?;
            let next = Reserved {
                requests: current
                    .requests
                    .checked_add(1)
                    .ok_or("ai_budget_overflow")?,
                spend_microusd: current
                    .spend_microusd
                    .checked_add(cost_microusd)
                    .ok_or("ai_budget_overflow")?,
            };
            if next.requests > self.limit.max_requests
                || next.spend_microusd > self.limit.max_spend_microusd
            {
                return Err("ai_request_budget_exhausted");
            }
            *current = next;
            Ok(next)
        }

        /// Canonicalize what was inspected so duplicate JSON keys cannot give the
        /// provider a different model, output bound or tool class from this gate.
        pub(crate) fn inspect(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: &[u8],
        ) -> Result<(Vec<u8>, u64), &'static str> {
            let url = Url::parse(url).map_err(|_| "ai_budget_destination")?;
            if method != "POST"
                || url.scheme() != "https"
                || url.host_str() != Some("api.anthropic.com")
                || url.port_or_known_default() != Some(443)
                || url.path() != "/v1/messages"
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("ai_budget_destination");
            }
            if headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("anthropic-beta")
                    || (name.eq_ignore_ascii_case("anthropic-version") && value != "2023-06-01")
                    || (name.eq_ignore_ascii_case("content-encoding") && value != "identity")
            }) {
                return Err("ai_budget_unsupported_headers");
            }
            if body.len() > MAX_REQUEST_BODY_BYTES {
                return Err("ai_budget_request_size");
            }
            let json: Value = serde_json::from_slice(body).map_err(|_| "ai_budget_request_json")?;
            let object = json.as_object().ok_or("ai_budget_request_json")?;
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "model"
                        | "max_tokens"
                        | "messages"
                        | "system"
                        | "stream"
                        | "temperature"
                        | "top_p"
                        | "top_k"
                        | "stop_sequences"
                        | "metadata"
                        | "tools"
                        | "tool_choice"
                        | "cache_control"
                        | "thinking"
                )
            }) {
                return Err("ai_budget_unsupported_parameter");
            }
            let (model, context, input_rate, output_rate, max_output) = match self.limit.model {
                AiBudgetModel::ClaudeHaiku45 => (
                    "claude-haiku-4-5-20251001",
                    200_000_u64,
                    2_u64,
                    5_u64,
                    64_000_u64,
                ),
            };
            if json.get("model").and_then(Value::as_str) != Some(model) {
                return Err("ai_budget_model_mismatch");
            }
            let output = json
                .get("max_tokens")
                .and_then(Value::as_u64)
                .filter(|tokens| (1..=max_output).contains(tokens))
                .ok_or("ai_budget_output_bound")?;
            if json.get("messages").and_then(Value::as_array).is_none() {
                return Err("ai_budget_request_json");
            }
            if let Some(tools) = json.get("tools") {
                let tools = tools.as_array().ok_or("ai_budget_unsupported_tools")?;
                if tools.iter().any(|tool| {
                    !tool.is_object()
                        || tool
                            .get("type")
                            .is_some_and(|kind| kind.as_str() != Some("custom"))
                        || tool.get("name").and_then(Value::as_str).is_none()
                        || tool
                            .get("input_schema")
                            .and_then(Value::as_object)
                            .is_none()
                        || tool.as_object().is_some_and(|fields| {
                            fields.keys().any(|key| {
                                !matches!(
                                    key.as_str(),
                                    "type"
                                        | "name"
                                        | "description"
                                        | "input_schema"
                                        | "cache_control"
                                )
                            })
                        })
                }) {
                    return Err("ai_budget_unsupported_tools");
                }
            }
            // Reserve the entire model context at the highest supported input
            // tariff, not a byte-based token estimate or reported cache discount.
            let cost = context
                .checked_mul(input_rate)
                .and_then(|input| output.checked_mul(output_rate)?.checked_add(input))
                .ok_or("ai_budget_overflow")?;
            let canonical = serde_json::to_vec(&json).map_err(|_| "ai_budget_request_json")?;
            Ok((canonical, cost))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;

        fn tracker(requests: u64, spend: u64) -> RequestBudgetTracker {
            RequestBudgetTracker::new(AiRequestBudget {
                max_requests: requests,
                max_spend_microusd: spend,
                model: AiBudgetModel::ClaudeHaiku45,
            })
        }

        fn body() -> Vec<u8> {
            br#"{"model":"claude-haiku-4-5-20251001","max_tokens":20000,"messages":[]}"#.to_vec()
        }

        #[test]
        fn reserves_exact_half_dollar_without_refunds() {
            let tracker = tracker(1, 500_000);
            let (_, cost) = tracker
                .inspect(
                    "POST",
                    "https://api.anthropic.com/v1/messages",
                    &[],
                    &body(),
                )
                .unwrap();
            assert_eq!(cost, 500_000);
            assert_eq!(tracker.reserve(cost).unwrap().requests, 1);
            assert!(tracker.reserve(cost).is_err());
        }

        #[test]
        fn both_dimensions_are_atomic_under_concurrency() {
            let tracker = Arc::new(tracker(1, 500_000));
            let barrier = Arc::new(std::sync::Barrier::new(16));
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        tracker.reserve(500_000).is_ok()
                    })
                })
                .collect();
            assert_eq!(
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .filter(|won| *won)
                    .count(),
                1
            );
        }

        #[test]
        fn insufficient_zero_and_overflow_fail_closed() {
            for tracker in [tracker(0, 500_000), tracker(1, 499_999), tracker(1, 0)] {
                assert!(tracker.reserve(500_000).is_err());
                assert_eq!(*tracker.reserved.lock().unwrap(), Reserved::default());
            }
            let tracker = tracker(u64::MAX, u64::MAX);
            tracker.reserve(u64::MAX).unwrap();
            assert!(tracker.reserve(1).is_err());
        }

        #[test]
        fn spend_is_an_independent_ceiling_and_refusal_does_not_change_it() {
            let tracker = tracker(10, 500_000);
            tracker.reserve(400_005).unwrap();
            assert!(tracker.reserve(400_005).is_err());
            assert_eq!(tracker.reserved.lock().unwrap().spend_microusd, 400_005);
            assert_eq!(tracker.reserved.lock().unwrap().requests, 1);
        }

        #[test]
        fn token_counting_endpoint_is_not_forwarded_and_does_not_spend_the_allowance() {
            let tracker = tracker(1, 500_000);
            assert_eq!(
                tracker.inspect(
                    "POST",
                    "https://api.anthropic.com/v1/messages/count_tokens",
                    &[],
                    &body()
                ),
                Err("ai_budget_destination")
            );
            assert_eq!(tracker.reserve(500_000).unwrap().requests, 1);
        }

        #[test]
        fn canonicalization_binds_the_inspected_fields_and_poison_does_not_reset() {
            let tracker = Arc::new(tracker(1, 500_000));
            let body = br#"{"model":"expensive","model":"claude-haiku-4-5-20251001",
            "max_tokens":64000,"max_tokens":1,"messages":[]}"#;
            let (canonical, cost) = tracker
                .inspect("POST", "https://api.anthropic.com/v1/messages", &[], body)
                .unwrap();
            assert_eq!(cost, 400_005);
            let json: Value = serde_json::from_slice(&canonical).unwrap();
            assert_eq!(json["max_tokens"], 1);
            assert_eq!(
                String::from_utf8(canonical)
                    .unwrap()
                    .matches("\"model\"")
                    .count(),
                1
            );
            let clone = Arc::clone(&tracker);
            let _ = std::thread::spawn(move || {
                let _held = clone.reserved.lock().unwrap();
                panic!("synthetic poison");
            })
            .join();
            assert_eq!(tracker.reserve(cost), Err("ai_budget_poisoned"));
        }

        #[test]
        fn model_routes_betas_surcharges_and_unknown_fields_are_refused() {
            let tracker = tracker(1, 500_000);
            for url in [
                "http://api.anthropic.com/v1/messages",
                "https://example.com/v1/messages",
                "https://api.anthropic.com/v1/messages/batches",
                "https://api.anthropic.com/v1/messages?beta=true",
            ] {
                assert!(tracker.inspect("POST", url, &[], &body()).is_err());
            }
            let url = "https://api.anthropic.com/v1/messages";
            for headers in [
                vec![("anthropic-beta".into(), "unknown".into())],
                vec![("Content-Encoding".into(), "gzip".into())],
            ] {
                assert!(tracker.inspect("POST", url, &headers, &body()).is_err());
            }
            for (key, value) in [
                ("model", serde_json::json!("claude-haiku-4-5")),
                ("max_tokens", serde_json::json!(20001)),
                ("service_tier", serde_json::json!("priority")),
                (
                    "tools",
                    serde_json::json!([{"type":"web_search_20250305","name":"web_search"}]),
                ),
            ] {
                let mut json: Value = serde_json::from_slice(&body()).unwrap();
                json[key] = value;
                let bytes = serde_json::to_vec(&json).unwrap();
                let inspected = tracker.inspect("POST", url, &[], &bytes);
                assert!(inspected.is_err() || inspected.unwrap().1 > 500_000);
            }
        }
    }
}
/// One AI API call's extracted token counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractedUsage {
    /// Provider label, e.g. `"openai"` or `"anthropic"`.
    pub provider: &'static str,
    /// Model name reported by the provider, when present.
    pub model: Option<String>,
    /// Provider-reported input/prompt tokens. `None` when usage is missing
    /// or malformed.
    pub input_tokens: Option<u64>,
    /// Provider-reported output/completion tokens. `None` when usage is
    /// missing or malformed.
    pub output_tokens: Option<u64>,
    /// Provider-reported total tokens. `None` when usage is missing or
    /// malformed.
    pub total_tokens: Option<u64>,
}

/// Specification for extracting usage from one provider's response body.
struct ProviderSpec {
    name: &'static str,
    hosts: &'static [&'static str],
    input_path: &'static [&'static str],
    output_path: &'static [&'static str],
    total_path: &'static [&'static str],
    model_path: &'static [&'static str],
}

macro_rules! define_provider {
    (
        $const_name:ident {
            name: $name:literal,
            hosts: [$($host:literal),* $(,)?],
            input_tokens: [$($in:literal),* $(,)?],
            output_tokens: [$($out:literal),* $(,)?],
            total_tokens: [$($total:literal),* $(,)?],
            model: [$($model:literal),* $(,)?] $(,)?
        }
    ) => {
        #[allow(non_upper_case_globals)]
        const $const_name: ProviderSpec = ProviderSpec {
            name: $name,
            hosts: &[$($host),*],
            input_path: &[$($in),*],
            output_path: &[$($out),*],
            total_path: &[$($total),*],
            model_path: &[$($model),*],
        };
    };
}

define_provider! {
    OpenAi {
        name: "openai",
        hosts: ["api.openai.com", "*.openai.azure.com"],
        input_tokens: ["usage", "prompt_tokens"],
        output_tokens: ["usage", "completion_tokens"],
        total_tokens: ["usage", "total_tokens"],
        model: ["model"],
    }
}

define_provider! {
    Anthropic {
        name: "anthropic",
        hosts: ["api.anthropic.com"],
        input_tokens: ["usage", "input_tokens"],
        output_tokens: ["usage", "output_tokens"],
        total_tokens: ["usage", "total_tokens"],
        model: ["model"],
    }
}

const PROVIDERS: &[ProviderSpec] = &[OpenAi, Anthropic];

/// Extract provider-reported token counts from an upstream JSON response.
///
/// Returns `None` when the URL does not match a known provider or the body
/// is not valid JSON. Returns `Some` with `None` counts when the provider is
/// known but the usage block is missing or malformed.
/// Returns `true` if the URL's host matches a known AI provider.
pub fn is_known_ai_provider(url: &str) -> bool {
    extract_host(url)
        .map(|host| PROVIDERS.iter().any(|p| host_matches_any(p, &host)))
        .unwrap_or(false)
}

pub fn extract_usage(url: &str, body: &[u8]) -> Option<ExtractedUsage> {
    let host = extract_host(url)?;
    let provider = PROVIDERS.iter().find(|p| host_matches_any(p, &host))?;
    let value: Value = serde_json::from_slice(body).ok()?;
    Some(ExtractedUsage {
        provider: provider.name,
        model: read_string_path(&value, provider.model_path),
        input_tokens: read_u64_path(&value, provider.input_path),
        output_tokens: read_u64_path(&value, provider.output_path),
        total_tokens: read_u64_path(&value, provider.total_path),
    })
}

fn extract_host(url: &str) -> Option<String> {
    // Accept both absolute URLs (https://host/path) and authority-only
    // strings (host:port). The substitution endpoint uses absolute URLs.
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    Some(host.to_lowercase())
}

fn host_matches_any(provider: &ProviderSpec, host: &str) -> bool {
    provider
        .hosts
        .iter()
        .any(|pattern| host_matches(pattern, host))
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

fn read_u64_path(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_u64()
}

fn read_string_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().map(|s| s.to_string())
}

/// Extract usage from a streaming (SSE) response body.
///
/// Looks for a trailing JSON object in the stream carrying `usage`. This
/// covers OpenAI when the workload set `stream_options.include_usage=true`
/// and Anthropic's `message_delta` event. If no usage object is found,
/// returns `None`.
pub fn extract_streaming_usage(url: &str, body: &[u8]) -> Option<ExtractedUsage> {
    let host = extract_host(url)?;
    let provider = PROVIDERS.iter().find(|p| host_matches_any(p, &host))?;

    // SSE frames are `data: <json>\n\n` separated. Walk backwards and try
    // each `data:` line as a JSON object containing `usage`.
    let text = std::str::from_utf8(body).ok()?;
    for line in text.lines().rev() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("data:") {
            continue;
        }
        let payload = trimmed.strip_prefix("data:").unwrap_or("").trim();
        if payload == "[DONE]" {
            continue;
        }
        let value: Value = serde_json::from_str(payload).ok()?;
        if value.get("usage").is_some() {
            return Some(ExtractedUsage {
                provider: provider.name,
                model: read_string_path(&value, provider.model_path),
                input_tokens: read_u64_path(&value, provider.input_path),
                output_tokens: read_u64_path(&value, provider.output_path),
                total_tokens: read_u64_path(&value, provider.total_path),
            });
        }
    }
    None
}

/// Cumulative AI token totals after recording one request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageTotals {
    /// Number of AI API requests recorded.
    pub requests: u64,
    /// Cumulative input/prompt tokens.
    pub input_tokens: u64,
    /// Cumulative output/completion tokens.
    pub output_tokens: u64,
    /// Cumulative total tokens.
    pub total_tokens: u64,
    /// Whether the VM's budget has been exceeded at any point.
    pub exceeded: bool,
}

/// Thread-safe per-VM AI token budget tracker.
///
/// Counters are monotonically increasing. A request that pushes the VM over
/// budget is still recorded; the tracker sets `exceeded` so the *next* request
/// can be refused before forwarding.
pub struct AiBudgetTracker {
    budget: Option<AiBudget>,
    pub(super) request_budget: Option<request_budget::RequestBudgetTracker>,
    requests: AtomicU64,
    input_tokens: AtomicU64,
    output_tokens: AtomicU64,
    total_tokens: AtomicU64,
    exceeded: AtomicBool,
}

impl AiBudgetTracker {
    /// Create a tracker with the given budget. `None` means meter-only,
    /// unlimited.
    pub fn new(budget: Option<AiBudget>) -> Self {
        Self {
            budget,
            request_budget: None,
            requests: AtomicU64::new(0),
            input_tokens: AtomicU64::new(0),
            output_tokens: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
        }
    }

    /// Whether the VM has exceeded its AI budget.
    pub fn is_exceeded(&self) -> bool {
        self.exceeded.load(Ordering::SeqCst)
    }

    /// Record one provider-reported usage sample.
    ///
    /// Increments cumulative counters and checks the configured budget. The
    /// returned totals reflect the state after this request.
    pub fn record(&self, usage: &ExtractedUsage) -> UsageTotals {
        let input_delta = usage.input_tokens.unwrap_or(0);
        let output_delta = usage.output_tokens.unwrap_or(0);
        let total_delta = usage.total_tokens.unwrap_or(0);

        let requests = self
            .requests
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let input_tokens = self
            .input_tokens
            .fetch_add(input_delta, Ordering::SeqCst)
            .saturating_add(input_delta);
        let output_tokens = self
            .output_tokens
            .fetch_add(output_delta, Ordering::SeqCst)
            .saturating_add(output_delta);
        let total_tokens = self
            .total_tokens
            .fetch_add(total_delta, Ordering::SeqCst)
            .saturating_add(total_delta);

        let exceeded = self.check_exceeded(input_tokens, output_tokens, total_tokens);
        if exceeded {
            self.exceeded.store(true, Ordering::SeqCst);
        }

        UsageTotals {
            requests,
            input_tokens,
            output_tokens,
            total_tokens,
            exceeded: exceeded || self.exceeded.load(Ordering::SeqCst),
        }
    }

    fn check_exceeded(&self, input: u64, output: u64, total: u64) -> bool {
        let Some(budget) = self.budget else {
            return false;
        };
        budget.max_input_tokens.is_some_and(|limit| input > limit)
            || budget.max_output_tokens.is_some_and(|limit| output > limit)
            || budget.max_total_tokens.is_some_and(|limit| total > limit)
    }

    /// Current cumulative totals without recording a new request.
    pub fn totals(&self) -> UsageTotals {
        UsageTotals {
            requests: self.requests.load(Ordering::SeqCst),
            input_tokens: self.input_tokens.load(Ordering::SeqCst),
            output_tokens: self.output_tokens.load(Ordering::SeqCst),
            total_tokens: self.total_tokens.load(Ordering::SeqCst),
            exceeded: self.exceeded.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_usage_is_extracted() {
        let body = br#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let usage = extract_usage("https://api.openai.com/v1/chat/completions", body).unwrap();
        assert_eq!(usage.provider, "openai");
        assert_eq!(usage.model.as_deref(), Some("gpt-4"));
        assert_eq!(usage.input_tokens, Some(10));
        assert_eq!(usage.output_tokens, Some(5));
        assert_eq!(usage.total_tokens, Some(15));
    }

    #[test]
    fn anthropic_usage_is_extracted() {
        let body = br#"{"model":"claude-3","usage":{"input_tokens":20,"output_tokens":7,"total_tokens":27}}"#;
        let usage = extract_usage("https://api.anthropic.com/v1/messages", body).unwrap();
        assert_eq!(usage.provider, "anthropic");
        assert_eq!(usage.model.as_deref(), Some("claude-3"));
        assert_eq!(usage.input_tokens, Some(20));
        assert_eq!(usage.output_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(27));
    }

    #[test]
    fn unknown_host_returns_none() {
        let body = br#"{"usage":{"prompt_tokens":1}}"#;
        assert!(extract_usage("https://example.com/v1", body).is_none());
    }

    #[test]
    fn known_provider_with_missing_usage_returns_some_with_none_counts() {
        let body = br#"{"model":"gpt-4","choices":[]}"#;
        let usage = extract_usage("https://api.openai.com/v1/chat/completions", body).unwrap();
        assert_eq!(usage.provider, "openai");
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, None);
        assert_eq!(usage.total_tokens, None);
    }

    #[test]
    fn malformed_body_returns_none() {
        let body = b"not json";
        assert!(extract_usage("https://api.openai.com/v1", body).is_none());
    }

    #[test]
    fn wildcard_host_matches() {
        assert!(host_matches("*.openai.azure.com", "foo.openai.azure.com"));
        assert!(host_matches("*.openai.azure.com", "openai.azure.com"));
        assert!(!host_matches("*.openai.azure.com", "api.openai.com"));
    }

    #[test]
    fn streaming_openai_trailing_usage_is_extracted() {
        let body = b"data: {\"choices\":[]}\n\ndata: {\"model\":\"gpt-4\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n";
        let usage =
            extract_streaming_usage("https://api.openai.com/v1/chat/completions", body).unwrap();
        assert_eq!(usage.provider, "openai");
        assert_eq!(usage.input_tokens, Some(3));
        assert_eq!(usage.output_tokens, Some(2));
        assert_eq!(usage.total_tokens, Some(5));
    }

    #[test]
    fn tracker_meters_without_budget() {
        let tracker = AiBudgetTracker::new(None);
        let usage = ExtractedUsage {
            provider: "openai",
            model: Some("gpt-4".into()),
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
        };
        let totals = tracker.record(&usage);
        assert_eq!(totals.requests, 1);
        assert_eq!(totals.input_tokens, 10);
        assert!(!totals.exceeded);
        assert!(!tracker.is_exceeded());
    }

    #[test]
    fn tracker_flags_total_budget_exceeded() {
        let tracker = AiBudgetTracker::new(Some(AiBudget {
            max_input_tokens: None,
            max_output_tokens: None,
            max_total_tokens: Some(20),
        }));
        let usage = ExtractedUsage {
            provider: "openai",
            model: None,
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
        };
        let first = tracker.record(&usage);
        assert!(!first.exceeded);
        let second = tracker.record(&usage);
        assert!(second.exceeded);
        assert!(tracker.is_exceeded());
    }

    #[test]
    fn tracker_flags_input_budget_exceeded() {
        let tracker = AiBudgetTracker::new(Some(AiBudget {
            max_input_tokens: Some(5),
            max_output_tokens: None,
            max_total_tokens: None,
        }));
        let usage = ExtractedUsage {
            provider: "anthropic",
            model: None,
            input_tokens: Some(10),
            output_tokens: None,
            total_tokens: None,
        };
        let totals = tracker.record(&usage);
        assert!(totals.exceeded);
    }
}
