//! Every `MvmError` variant must reach the tool server's `_meta` as a stable
//! `code` plus a `retryable` flag, derived from `MvmError` itself rather than
//! from a copy of the mapping kept here. One test per variant is the
//! contract: if a variant's classification ever drifts, exactly one of these
//! fails and names which one.

use std::sync::Arc;

use async_trait::async_trait;
use mvm_client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, PauseOpts,
    PauseOutcome, ReconfigureRequest, ResumeOpts, ResumeOutcome,
};
use mvm_client::mock::MockBackend;
use mvm_client::{BackendCapabilityReport, MvmClient, MvmError};
use mvm_mcp::{CURRENT_PROTOCOL_VERSION, McpServer};
use serde_json::{Value, json};

fn current_request(id: u64, method: &str, extra: Value) -> String {
    let mut params = extra.as_object().cloned().expect("params object");
    params.insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": CURRENT_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "mvm-test", "version": "1"}
        }),
    );
    json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}).to_string()
}

async fn call(server: &McpServer, id: u64, name: &str, arguments: Value) -> Value {
    let response = server
        .handle_json(&current_request(
            id,
            "tools/call",
            json!({"name":name, "arguments":arguments}),
        ))
        .await
        .expect("request receives a response");
    serde_json::from_str(&response).expect("response json")
}

async fn list_tools(server: &McpServer, id: u64) -> Value {
    let response = server
        .handle_json(&current_request(id, "tools/list", json!({})))
        .await
        .expect("request receives a response");
    serde_json::from_str(&response).expect("response json")
}

/// A client double that reports full capabilities (by delegating to a real
/// `MockBackend`) but fails every machine operation with a fixed,
/// caller-supplied `MvmError`. Exists only to reach `tool_error` with each
/// variant in turn — `MockBackend` on its own can only produce `NotFound`
/// and `InvalidSpec` through its ordinary machine lifecycle.
struct FailingBackend {
    error: MvmError,
    inner: MockBackend,
}

impl FailingBackend {
    fn new(error: MvmError) -> Self {
        Self {
            error,
            inner: MockBackend::default(),
        }
    }
}

#[async_trait]
impl MvmClient for FailingBackend {
    async fn backend_capabilities(&self) -> mvm_client::Result<BackendCapabilityReport> {
        self.inner.backend_capabilities().await
    }

    async fn list_machines(&self, _filter: MachineFilter) -> mvm_client::Result<Vec<MachineState>> {
        Err(self.error.clone())
    }

    async fn inspect_machine(&self, _id: &MachineId) -> mvm_client::Result<MachineState> {
        Err(self.error.clone())
    }

    async fn create_machine(&self, _spec: MachineSpec) -> mvm_client::Result<MachineState> {
        Err(self.error.clone())
    }

    async fn run_machine(&self, _spec: MachineSpec) -> mvm_client::Result<MachineState> {
        Err(self.error.clone())
    }

    async fn start_machine(&self, _id: &MachineId) -> mvm_client::Result<MachineState> {
        Err(self.error.clone())
    }

    async fn stop_machine(&self, _id: &MachineId) -> mvm_client::Result<()> {
        Err(self.error.clone())
    }

    async fn pause_machine(
        &self,
        _id: &MachineId,
        _opts: PauseOpts,
    ) -> mvm_client::Result<PauseOutcome> {
        Err(self.error.clone())
    }

    async fn resume_machine(
        &self,
        _id: &MachineId,
        _opts: ResumeOpts,
    ) -> mvm_client::Result<ResumeOutcome> {
        Err(self.error.clone())
    }

    async fn remove_machine(&self, _id: &MachineId) -> mvm_client::Result<()> {
        Err(self.error.clone())
    }

    async fn machine_logs(&self, _id: &MachineId, _opts: LogOpts) -> mvm_client::Result<Vec<u8>> {
        Err(self.error.clone())
    }

    async fn exec_machine(
        &self,
        _id: &MachineId,
        _command: Vec<String>,
    ) -> mvm_client::Result<ExecResult> {
        Err(self.error.clone())
    }

    async fn reconfigure_machine(
        &self,
        _id: &MachineId,
        _cfg: ReconfigureRequest,
    ) -> mvm_client::Result<MachineState> {
        Err(self.error.clone())
    }

    async fn set_ttl(
        &self,
        _id: &MachineId,
        _expires_at: Option<String>,
    ) -> mvm_client::Result<()> {
        Err(self.error.clone())
    }
}

/// Drive one `MvmError` variant through `mvm.machine.inspect` and assert the
/// tool result's `_meta` carries the given literal `code`/`retryable` — not
/// whatever `error.code()`/`error.retryable()` themselves return, so a bug
/// in that mapping cannot pass by comparing itself against itself.
async fn assert_variant_is_classified(
    error: MvmError,
    expected_code: &str,
    expected_retryable: bool,
) {
    let server = McpServer::new(Arc::new(FailingBackend::new(error)));
    let response = call(&server, 1, "mvm.machine.inspect", json!({"id":"m1"})).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["_meta"]["code"], expected_code,
        "{response}"
    );
    assert_eq!(
        response["result"]["_meta"]["retryable"], expected_retryable,
        "{response}"
    );
}

#[tokio::test]
async fn not_found_is_classified() {
    assert_variant_is_classified(MvmError::NotFound { id: "m1".into() }, "NOT_FOUND", false).await;
}

#[tokio::test]
async fn invalid_spec_is_classified() {
    assert_variant_is_classified(
        MvmError::InvalidSpec {
            reason: "bad spec".into(),
        },
        "INVALID_SPEC",
        false,
    )
    .await;
}

#[tokio::test]
async fn backend_is_classified() {
    assert_variant_is_classified(
        MvmError::Backend {
            reason: "backend blew up".into(),
        },
        "BACKEND_ERROR",
        false,
    )
    .await;
}

#[tokio::test]
async fn unauthorized_is_classified() {
    assert_variant_is_classified(
        MvmError::Unauthorized {
            reason: "no grant".into(),
        },
        "UNAUTHORIZED",
        false,
    )
    .await;
}

#[tokio::test]
async fn conflict_is_classified() {
    assert_variant_is_classified(
        MvmError::Conflict {
            reason: "already exists".into(),
        },
        "CONFLICT",
        false,
    )
    .await;
}

#[tokio::test]
async fn rejected_is_classified() {
    assert_variant_is_classified(
        MvmError::Rejected {
            reason: "policy refused it".into(),
        },
        "REJECTED",
        false,
    )
    .await;
}

#[tokio::test]
async fn unavailable_is_classified_and_is_the_only_retryable_variant() {
    assert_variant_is_classified(
        MvmError::Unavailable {
            reason: "backend offline".into(),
        },
        "UNAVAILABLE",
        true,
    )
    .await;
}

/// Failures that never reach an `MvmError` (bad tool arguments here) still
/// get a stable, documented generic code rather than an unclassified error —
/// picked and pinned so the two failure families are both machine-readable.
#[tokio::test]
async fn input_errors_get_the_documented_generic_code() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let response = call(&server, 1, "mvm.machine.list", json!({"unexpected":true})).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(response["result"]["_meta"]["code"], "INVALID_INPUT");
    assert_eq!(response["result"]["_meta"]["retryable"], false);
}

/// A failed tool call carries the backend's own message, since that is often
/// what the caller needs, but capped at 512 characters like every tool error.
#[tokio::test]
async fn a_backend_message_reaches_the_caller_capped() {
    let server = McpServer::new(Arc::new(FailingBackend::new(MvmError::NotFound {
        id: format!("m1{}", "x".repeat(2000)),
    })));
    let response = call(&server, 5, "mvm.machine.inspect", json!({"id":"m1"})).await;
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    assert!(text.contains("machine not found: m1"), "{text}");
    assert_eq!(text.chars().count(), 512, "{text}");
    assert_eq!(response["result"]["_meta"]["code"], "NOT_FOUND");
}

/// A client double whose `backend_capabilities()` itself fails — the one
/// surface `McpServer::capabilities()` (not `call_tool`) is responsible for
/// classifying. Every other method is unreachable: a `tools/list` request
/// (this double's only use below) never calls a machine operation, and a
/// `tools/call` request never reaches one either once capability discovery
/// has already failed.
struct FailingCapabilities {
    error: MvmError,
}

#[async_trait]
impl MvmClient for FailingCapabilities {
    async fn backend_capabilities(&self) -> mvm_client::Result<BackendCapabilityReport> {
        Err(self.error.clone())
    }

    async fn list_machines(&self, _filter: MachineFilter) -> mvm_client::Result<Vec<MachineState>> {
        unreachable!("capability discovery already failed")
    }

    async fn inspect_machine(&self, _id: &MachineId) -> mvm_client::Result<MachineState> {
        unreachable!("capability discovery already failed")
    }

    async fn create_machine(&self, _spec: MachineSpec) -> mvm_client::Result<MachineState> {
        unreachable!("capability discovery already failed")
    }

    async fn run_machine(&self, _spec: MachineSpec) -> mvm_client::Result<MachineState> {
        unreachable!("capability discovery already failed")
    }

    async fn start_machine(&self, _id: &MachineId) -> mvm_client::Result<MachineState> {
        unreachable!("capability discovery already failed")
    }

    async fn stop_machine(&self, _id: &MachineId) -> mvm_client::Result<()> {
        unreachable!("capability discovery already failed")
    }

    async fn pause_machine(
        &self,
        _id: &MachineId,
        _opts: PauseOpts,
    ) -> mvm_client::Result<PauseOutcome> {
        unreachable!("capability discovery already failed")
    }

    async fn resume_machine(
        &self,
        _id: &MachineId,
        _opts: ResumeOpts,
    ) -> mvm_client::Result<ResumeOutcome> {
        unreachable!("capability discovery already failed")
    }

    async fn remove_machine(&self, _id: &MachineId) -> mvm_client::Result<()> {
        unreachable!("capability discovery already failed")
    }

    async fn machine_logs(&self, _id: &MachineId, _opts: LogOpts) -> mvm_client::Result<Vec<u8>> {
        unreachable!("capability discovery already failed")
    }

    async fn exec_machine(
        &self,
        _id: &MachineId,
        _command: Vec<String>,
    ) -> mvm_client::Result<ExecResult> {
        unreachable!("capability discovery already failed")
    }

    async fn reconfigure_machine(
        &self,
        _id: &MachineId,
        _cfg: ReconfigureRequest,
    ) -> mvm_client::Result<MachineState> {
        unreachable!("capability discovery already failed")
    }

    async fn set_ttl(
        &self,
        _id: &MachineId,
        _expires_at: Option<String>,
    ) -> mvm_client::Result<()> {
        unreachable!("capability discovery already failed")
    }
}

/// `capabilities()` failures surface as a JSON-RPC protocol error (there is
/// no tool result to attach `_meta` to yet), so the classification lives in
/// the error's `data` field instead.
#[tokio::test]
async fn capabilities_failure_is_classified_in_the_protocol_error_data_on_tools_list() {
    let server = McpServer::new(Arc::new(FailingCapabilities {
        error: MvmError::Unavailable {
            reason: "backend offline".into(),
        },
    }));
    let response = list_tools(&server, 90).await;
    assert_eq!(response["error"]["code"], -32603);
    assert_eq!(
        response["error"]["message"], "client capability discovery failed",
        "the backend's own error text must not reach the caller"
    );
    assert_eq!(response["error"]["data"]["code"], "UNAVAILABLE");
    assert_eq!(response["error"]["data"]["retryable"], true);
}

/// The other call site that reaches capability discovery — `tools/call` —
/// is classified the same way.
#[tokio::test]
async fn capabilities_failure_is_classified_in_the_protocol_error_data_on_tools_call() {
    let server = McpServer::new(Arc::new(FailingCapabilities {
        error: MvmError::Backend {
            reason: "internal detail /var/run/backend.sock".into(),
        },
    }));
    let response = call(&server, 91, "mvm.machine.list", json!({})).await;
    assert_eq!(response["error"]["code"], -32603);
    assert!(
        !response.to_string().contains("internal detail"),
        "the backend's own error text must not reach the caller: {response}"
    );
    assert_eq!(response["error"]["data"]["code"], "BACKEND_ERROR");
    assert_eq!(response["error"]["data"]["retryable"], false);
}
