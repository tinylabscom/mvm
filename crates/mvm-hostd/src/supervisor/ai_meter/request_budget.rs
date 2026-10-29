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
                                "type" | "name" | "description" | "input_schema" | "cache_control"
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
