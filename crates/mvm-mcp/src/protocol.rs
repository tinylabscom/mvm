//! MCP wire protocol: JSON-RPC 2.0 frames and tool-result types.
//!
//! Hand-rolled to avoid pulling in `rmcp` as a new external dependency
//! (every workspace dep needs to clear ADR-002's supply-chain bar:
//! `cargo-deny`, `cargo-audit`, audited and pinned). The protocol is
//! ~200 LoC; the operational risk of writing it ourselves is lower
//! than the supply-chain cost of importing it.
//!
//! Available under `protocol-only` so mvmd (per plan 33) can consume
//! these types without dragging in stdio I/O.

use serde::{Deserialize, Serialize};

/// MCP protocol revision we advertise during `initialize`. Pinned to
/// the current spec at implementation time. Plan 32: bump in lockstep
/// with the upstream spec, never silently drift.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Server identity advertised in `initialize` responses.
pub const SERVER_NAME: &str = "mvm";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON-RPC 2.0 request frame.
///
/// `id` is `Option` because `notifications/*` methods are id-less; we
/// don't currently emit notifications but the wire format requires
/// tolerating them on the way in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: format!("Parse error: {}", detail.into()),
            data: None,
        }
    }
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: format!("Invalid request: {}", detail.into()),
            data: None,
        }
    }
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
            data: None,
        }
    }
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: format!("Invalid params: {}", detail.into()),
            data: None,
        }
    }
    pub fn internal_error(detail: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: format!("Internal error: {}", detail.into()),
            data: None,
        }
    }
}

impl JsonRpcResponse {
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }
    pub fn err(id: serde_json::Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// One block of a tool-call result. MCP defines several content types;
/// `text` is the only one mvm emits in v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
}

/// `tools/call` response shape per the MCP spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ContentBlock>,
    #[serde(default, rename = "isError", skip_serializing_if = "is_false")]
    pub is_error: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_request_serde_roundtrip() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "tools/list".to_string(),
            params: Some(serde_json::json!({})),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: JsonRpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.method, "tools/list");
        assert_eq!(parsed.jsonrpc, "2.0");
    }

    #[test]
    fn jsonrpc_request_rejects_unknown_fields() {
        // `deny_unknown_fields` is W4.1 hygiene — every type that
        // crosses an untrusted boundary fails closed on extras.
        let bad = r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{},"unknown":42}"#;
        assert!(serde_json::from_str::<JsonRpcRequest>(bad).is_err());
    }

    #[test]
    fn error_codes_match_jsonrpc_spec() {
        assert_eq!(JsonRpcError::parse_error("x").code, -32700);
        assert_eq!(JsonRpcError::invalid_request("x").code, -32600);
        assert_eq!(JsonRpcError::method_not_found("x").code, -32601);
        assert_eq!(JsonRpcError::invalid_params("x").code, -32602);
        assert_eq!(JsonRpcError::internal_error("x").code, -32603);
    }

    #[test]
    fn tool_result_text_block_serializes_with_type_tag() {
        let r = ToolResult {
            content: vec![ContentBlock::Text {
                text: "hi".to_string(),
            }],
            is_error: false,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""type":"text""#));
        assert!(s.contains(r#""text":"hi""#));
        assert!(!s.contains("isError"), "is_error=false omitted");
    }

    #[test]
    fn tool_result_error_emits_is_error_field() {
        let r = ToolResult {
            content: vec![ContentBlock::Text {
                text: "boom".to_string(),
            }],
            is_error: true,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""isError":true"#));
    }
}
