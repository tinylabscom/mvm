//! Payload-free AI egress usage record.
//!
//! This type carries only provider-reported counts and correlation metadata.
//! Request and response bodies, headers, and credentials never appear here.

use serde::{Deserialize, Serialize};

/// One AI API call's worth of extracted, non-sensitive metadata.
///
/// Emitted by the host egress seam after a known provider returns a usage
/// block. The counts are the provider's own numbers, not host-side estimates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiUsageRecord {
    /// Trace identifier carried on the request, if any.
    pub trace_id: String,
    /// Span identifier carried on the request, if any.
    pub span_id: String,
    /// Destination host the VM contacted.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Provider label, e.g. `openai` or `anthropic`.
    pub provider: String,
    /// Model name reported by the provider, when present.
    pub model: Option<String>,
    /// Provider-reported input/prompt tokens, when present.
    pub input_tokens: Option<u64>,
    /// Provider-reported output/completion tokens, when present.
    pub output_tokens: Option<u64>,
    /// Provider-reported total tokens, when present.
    pub total_tokens: Option<u64>,
    /// HTTP response status code.
    pub status: u16,
    /// Whether this request caused the VM's AI budget to be exceeded.
    pub budget_exceeded: bool,
}

impl AiUsageRecord {
    /// Flatten the record into key/value pairs suitable for a chain-signed
    /// audit entry's `labels` map. Only non-sensitive, provider-reported
    /// counts and routing metadata are included.
    pub fn to_labels(&self) -> Vec<(String, String)> {
        let mut labels = vec![
            ("host".to_string(), self.host.clone()),
            ("port".to_string(), self.port.to_string()),
            ("method".to_string(), self.method.clone()),
            ("path".to_string(), self.path.clone()),
            ("provider".to_string(), self.provider.clone()),
            ("status".to_string(), self.status.to_string()),
            (
                "budget_exceeded".to_string(),
                if self.budget_exceeded {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
        ];
        if !self.trace_id.is_empty() {
            labels.push(("trace_id".to_string(), self.trace_id.clone()));
        }
        if !self.span_id.is_empty() {
            labels.push(("span_id".to_string(), self.span_id.clone()));
        }
        if let Some(model) = &self.model {
            labels.push(("model".to_string(), model.clone()));
        }
        if let Some(n) = self.input_tokens {
            labels.push(("input_tokens".to_string(), n.to_string()));
        }
        if let Some(n) = self.output_tokens {
            labels.push(("output_tokens".to_string(), n.to_string()));
        }
        if let Some(n) = self.total_tokens {
            labels.push(("total_tokens".to_string(), n.to_string()));
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_usage_record_roundtrips() {
        let record = AiUsageRecord {
            trace_id: "trace-1".to_string(),
            span_id: "span-1".to_string(),
            host: "api.openai.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            provider: "openai".to_string(),
            model: Some("gpt-4".to_string()),
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
            status: 200,
            budget_exceeded: false,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: AiUsageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn ai_usage_record_labels_omit_missing_counts() {
        let record = AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host: "api.anthropic.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            provider: "anthropic".to_string(),
            model: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            status: 200,
            budget_exceeded: true,
        };
        let labels: std::collections::BTreeMap<String, String> =
            record.to_labels().into_iter().collect();
        assert!(!labels.contains_key("trace_id"));
        assert!(!labels.contains_key("model"));
        assert!(!labels.contains_key("input_tokens"));
        assert_eq!(labels["budget_exceeded"], "true");
    }
}
