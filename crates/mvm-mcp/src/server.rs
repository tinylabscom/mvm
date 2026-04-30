//! Stdio JSON-RPC dispatch loop.
//!
//! Per-line framed (one JSON object per line, `\n`-terminated). Reads
//! from `stdin`, writes responses to `stdout`. **All non-protocol
//! output must go to stderr** — a stray byte on stdout corrupts the
//! wire. Cross-cutting "A: stdout-only-JSON-RPC discipline" enforces
//! this via `init_stderr_tracing` below and a CI smoke test.

use std::io::{BufRead, Write};

use anyhow::Result;
use serde_json::Value;

use crate::dispatcher::Dispatcher;
use crate::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION,
};
use crate::tools::{RunParams, all_tools};

/// Initialize a stderr-only tracing subscriber. MUST be called before
/// the dispatch loop, since `tracing` defaults to stdout — and a
/// single stdout log line breaks the JSON-RPC framing.
pub fn init_stderr_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt::Subscriber::builder()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
}

/// Dispatch one JSON-RPC line through `dispatcher` and either return
/// a response (request) or `None` (notification — no reply expected).
pub fn run_with_dispatcher<R: BufRead, W: Write, D: Dispatcher>(
    reader: R,
    writer: &mut W,
    dispatcher: &D,
) -> Result<()> {
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(err=%e, "stdin read error");
                return Err(e.into());
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match handle_one(&line, dispatcher) {
            Some(resp) => {
                let s = serde_json::to_string(&resp)?;
                writeln!(writer, "{s}")?;
                writer.flush()?;
            }
            None => continue,
        }
    }
    Ok(())
}

/// Parse one line and produce zero (notification) or one response.
fn handle_one<D: Dispatcher>(line: &str, dispatcher: &D) -> Option<JsonRpcResponse> {
    let req: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Some(JsonRpcResponse::err(
                Value::Null,
                JsonRpcError::parse_error(e.to_string()),
            ));
        }
    };

    if req.jsonrpc != "2.0" {
        return Some(JsonRpcResponse::err(
            req.id.unwrap_or(Value::Null),
            JsonRpcError::invalid_request("jsonrpc must be \"2.0\""),
        ));
    }

    // Notifications: no id, no response.
    let id = req.id?;

    let result = match req.method.as_str() {
        "initialize" => Ok(initialize_response()),
        "tools/list" => Ok(tools_list_response()),
        "tools/call" => tools_call_response(req.params, dispatcher),
        other => Err(JsonRpcError::method_not_found(other)),
    };

    Some(match result {
        Ok(v) => JsonRpcResponse::ok(id, v),
        Err(e) => JsonRpcResponse::err(id, e),
    })
}

fn initialize_response() -> Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            // We do not change the tool list at runtime.
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
        "instructions": instructions_text(),
    })
}

fn instructions_text() -> &'static str {
    "Run code in an mvm microVM. Use the `run` tool with `env` (which template) and `code` \
     (the program text). Discover envs via `mvmctl template list` on the host. The default \
     curated env after Proposal B lands is `claude-code-vm`; users can build their own via \
     `mvmctl template create … && mvmctl template build <name>`."
}

fn tools_list_response() -> Value {
    serde_json::json!({ "tools": all_tools() })
}

fn tools_call_response<D: Dispatcher>(
    params: Option<Value>,
    dispatcher: &D,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| JsonRpcError::invalid_params("missing params object"))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_params("missing tool name"))?;
    if name != "run" {
        return Err(JsonRpcError::method_not_found(&format!("tool '{name}'")));
    }
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let run_params: RunParams = serde_json::from_value(args)
        .map_err(|e| JsonRpcError::invalid_params(format!("decoding `run` params: {e}")))?;
    let result = dispatcher.run(run_params);
    serde_json::to_value(&result)
        .map_err(|e| JsonRpcError::internal_error(format!("encoding tool result: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ContentBlock, ToolResult};

    /// Mock dispatcher that records the params it saw and returns a
    /// canned ToolResult.
    struct MockDispatcher {
        last_env: std::sync::Mutex<Option<String>>,
    }
    impl Dispatcher for MockDispatcher {
        fn run(&self, params: RunParams) -> ToolResult {
            *self.last_env.lock().unwrap() = Some(params.env);
            ToolResult {
                content: vec![ContentBlock::Text {
                    text: "mock-stdout".to_string(),
                }],
                is_error: false,
            }
        }
    }

    fn run_one(req_json: &str, dispatcher: &impl Dispatcher) -> JsonRpcResponse {
        handle_one(req_json, dispatcher).expect("response")
    }

    #[test]
    fn initialize_returns_protocol_version() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = run_one(req, &dispatcher);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
    }

    #[test]
    fn tools_list_returns_single_run_tool() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = run_one(req, &dispatcher);
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "run");
    }

    #[test]
    fn tools_call_dispatches_to_run() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"run","arguments":{"env":"shell","code":"echo hi"}}
        }"#;
        let resp = run_one(req, &dispatcher);
        assert!(resp.error.is_none(), "got error: {:?}", resp.error);
        let result = resp.result.unwrap();
        assert_eq!(result["content"][0]["text"], "mock-stdout");
        assert_eq!(
            *dispatcher.last_env.lock().unwrap(),
            Some("shell".to_string())
        );
    }

    #[test]
    fn tools_call_rejects_unknown_tool_name() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"not-a-tool","arguments":{}}
        }"#;
        let resp = run_one(req, &dispatcher);
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601, "method not found");
    }

    #[test]
    fn tools_call_rejects_unknown_arg_field() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"run","arguments":{"env":"shell","code":"x","extra":1}}
        }"#;
        let resp = run_one(req, &dispatcher);
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602, "invalid params");
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{"jsonrpc":"2.0","id":6,"method":"resources/list","params":{}}"#;
        let resp = run_one(req, &dispatcher);
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
    }

    #[test]
    fn malformed_json_returns_parse_error_with_null_id() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let resp = handle_one("not-json", &dispatcher).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32700);
        assert_eq!(resp.id, Value::Null);
    }

    #[test]
    fn notification_request_returns_no_response() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        // No `id` field = notification.
        let req = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(handle_one(req, &dispatcher).is_none());
    }

    #[test]
    fn jsonrpc_version_must_be_2_0() {
        let dispatcher = MockDispatcher {
            last_env: std::sync::Mutex::new(None),
        };
        let req = r#"{"jsonrpc":"1.0","id":7,"method":"initialize","params":{}}"#;
        let resp = run_one(req, &dispatcher);
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
    }
}
