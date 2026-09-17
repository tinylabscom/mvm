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
/// tool result's `_meta` carries the variant's own `code`/`retryable`.
async fn assert_variant_is_classified(error: MvmError) {
    let expected_code = error.code();
    let expected_retryable = error.retryable();
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
    assert_variant_is_classified(MvmError::NotFound { id: "m1".into() }).await;
}

#[tokio::test]
async fn invalid_spec_is_classified() {
    assert_variant_is_classified(MvmError::InvalidSpec {
        reason: "bad spec".into(),
    })
    .await;
}

#[tokio::test]
async fn backend_is_classified() {
    assert_variant_is_classified(MvmError::Backend {
        reason: "backend blew up".into(),
    })
    .await;
}

#[tokio::test]
async fn unauthorized_is_classified() {
    assert_variant_is_classified(MvmError::Unauthorized {
        reason: "no grant".into(),
    })
    .await;
}

#[tokio::test]
async fn conflict_is_classified() {
    assert_variant_is_classified(MvmError::Conflict {
        reason: "already exists".into(),
    })
    .await;
}

#[tokio::test]
async fn rejected_is_classified() {
    assert_variant_is_classified(MvmError::Rejected {
        reason: "policy refused it".into(),
    })
    .await;
}

#[tokio::test]
async fn unavailable_is_classified_and_is_the_only_retryable_variant() {
    assert_variant_is_classified(MvmError::Unavailable {
        reason: "backend offline".into(),
    })
    .await;
    // Pinned explicitly: this is the one variant the whole feature exists to
    // flag as safe to retry unchanged.
    assert!(MvmError::Unavailable { reason: "x".into() }.retryable());
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
