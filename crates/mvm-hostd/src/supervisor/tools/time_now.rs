//! `mvm.time_now` — host wall-clock time as a host-mediated tool.
//!
//! The simplest possible host-mediated tool: zero network, zero
//! filesystem, pure function over the system clock. Useful as:
//!
//! - The first walking-skeleton impl of [`HostMediatedTool`] —
//!   exercises the trait + [`crate::supervisor::tools::ToolRegistry`] dispatch
//!   path without needing an HTTP client, an allowlist of upstream
//!   hosts, or a credential store.
//! - A canonical "is the agent → supervisor → host pipe alive?"
//!   diagnostic. An agent that can call `mvm.time_now` and get a
//!   sane RFC 3339 back has working JSON-RPC, working policy gate,
//!   and a working tool registry.
//!
//! ## Params (`TimeNowParams`)
//!
//! - `format`: `"rfc3339"` (default) or `"unix"`. Out-of-set values
//!   are rejected with `ToolInvokeError::InvalidParams` so a typo
//!   surfaces immediately rather than silently falling through to a
//!   default.
//!
//! ## Result (`TimeNowResult`)
//!
//! - `time`: the formatted timestamp (string).
//! - `format`: echoes back the format used, so a script can
//!   round-trip without re-deriving it.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{HostMediatedTool, ToolInvokeError};

/// Stateless tool — `Default::default()` is the canonical
/// constructor.
#[derive(Default)]
pub struct TimeNowTool;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeNowParams {
    #[serde(default)]
    pub format: TimeFormat,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TimeFormat {
    /// `"2026-05-11T18:00:00+00:00"` — ISO 8601 / RFC 3339. Default.
    #[default]
    Rfc3339,
    /// Seconds since the Unix epoch, as a base-10 string.
    Unix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeNowResult {
    pub time: String,
    pub format: TimeFormat,
}

/// Tool name as exposed to the agent. Kept as a `const` so
/// allowlist code and tests share one spelling.
pub const TOOL_NAME: &str = "mvm.time_now";

#[async_trait]
impl HostMediatedTool for TimeNowTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    async fn invoke(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        // Empty-object inputs are common (the tool has no required
        // fields). `from_value` accepts `{}` directly.
        let parsed: TimeNowParams =
            serde_json::from_value(params).map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;
        let now = chrono::Utc::now();
        let time = match parsed.format {
            TimeFormat::Rfc3339 => now.to_rfc3339(),
            TimeFormat::Unix => now.timestamp().to_string(),
        };
        let result = TimeNowResult {
            time,
            format: parsed.format,
        };
        serde_json::to_value(&result).map_err(|e| ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("serializing result: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invoke_with_empty_object_returns_rfc3339() {
        let t = TimeNowTool;
        let v = t.invoke(serde_json::json!({})).await.unwrap();
        let parsed: TimeNowResult = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.format, TimeFormat::Rfc3339);
        // RFC 3339 timestamps always carry a `T` separator. Cheaper
        // than re-parsing the date.
        assert!(parsed.time.contains('T'), "got: {}", parsed.time);
    }

    #[tokio::test]
    async fn invoke_with_unix_format_returns_decimal_seconds() {
        let t = TimeNowTool;
        let v = t
            .invoke(serde_json::json!({ "format": "unix" }))
            .await
            .unwrap();
        let parsed: TimeNowResult = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.format, TimeFormat::Unix);
        // Must parse as an i64 and be in a sane modern range
        // (post-2020, pre-2100 — defends against a clock that's
        // wandered off).
        let secs: i64 = parsed.time.parse().expect("decimal seconds");
        assert!(
            (1_577_836_800..4_102_444_800).contains(&secs),
            "unix time out of range: {secs}"
        );
    }

    #[tokio::test]
    async fn invoke_rejects_unknown_format_value() {
        let t = TimeNowTool;
        let err = t
            .invoke(serde_json::json!({ "format": "klingon" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
        let msg = err.to_string();
        assert!(msg.contains(TOOL_NAME), "got: {msg}");
    }

    #[tokio::test]
    async fn invoke_rejects_unknown_field() {
        // `#[serde(deny_unknown_fields)]` makes unexpected fields
        // fail closed, so a stale agent that adds a `timezone` param
        // doesn't silently drop the timezone.
        let t = TimeNowTool;
        let err = t
            .invoke(serde_json::json!({ "format": "rfc3339", "timezone": "UTC" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[test]
    fn time_format_serde_roundtrip_lowercase() {
        // Wire-format pin: the agent sends `"rfc3339"` and `"unix"`,
        // not `"Rfc3339"`. The `rename_all = "lowercase"` attr
        // enforces this; this test makes a future refactor that
        // drops the attr fail loudly.
        let v: TimeFormat = serde_json::from_str("\"rfc3339\"").unwrap();
        assert_eq!(v, TimeFormat::Rfc3339);
        let v: TimeFormat = serde_json::from_str("\"unix\"").unwrap();
        assert_eq!(v, TimeFormat::Unix);
    }

    #[test]
    fn tool_name_is_canonical_mvm_prefix() {
        assert!(TOOL_NAME.starts_with("mvm."));
        assert_eq!(TimeNowTool.name(), TOOL_NAME);
    }
}
