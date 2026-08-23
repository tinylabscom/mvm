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
