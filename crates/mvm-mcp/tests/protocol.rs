use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use mvm_client::dto::{MachineFilter, MachineId, MachineStatus};
use mvm_client::mock::MockBackend;
use mvm_client::{ClientOperationCapabilities, MvmClient};
use mvm_mcp::{CURRENT_PROTOCOL_VERSION, McpServer, ServerLimits};
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

async fn request(server: &McpServer, id: u64, method: &str, params: Value) -> Value {
    let response = server
        .handle_json(&current_request(id, method, params))
        .await
        .expect("request receives a response");
    serde_json::from_str(&response).expect("response json")
}

async fn call(server: &McpServer, id: u64, name: &str, arguments: Value) -> Value {
    request(
        server,
        id,
        "tools/call",
        json!({"name":name, "arguments":arguments}),
    )
    .await
}

#[tokio::test]
async fn current_discovery_is_stateless_and_private() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let response = request(&server, 1, "server/discover", json!({})).await;
    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(
        response["result"]["supportedVersions"][0],
        CURRENT_PROTOCOL_VERSION
    );
    assert_eq!(response["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(response["result"]["cacheScope"], "private");
    assert!(response["result"]["ttlMs"].as_u64().is_some());
}

#[tokio::test]
async fn tool_catalog_is_deterministic_and_derived_from_client_operations() {
    let operations = ClientOperationCapabilities::builder()
        .list(true)
        .stop(true)
        .build();
    let server = McpServer::new(Arc::new(MockBackend::default().with_operations(operations)));
    let response = request(&server, 2, "tools/list", json!({})).await;
    let names: Vec<&str> = response["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "mvm.backend_capabilities",
            "mvm.machine.list",
            "mvm.machine.stop"
        ]
    );
    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(response["result"]["cacheScope"], "private");
}

#[tokio::test]
async fn every_mock_operation_routes_through_the_facade() {
    let mock = Arc::new(MockBackend::default());
    let client: Arc<dyn MvmClient> = mock.clone();
    let server = McpServer::new(client);

    let created = call(
        &server,
        10,
        "mvm.machine.create",
        json!({"name":"all-ops", "image":"alpine", "cpus":2, "memory_mib":128}),
    )
    .await;
    let id = created["result"]["structuredContent"]["id"]
        .as_str()
        .expect("machine id")
        .to_string();
    for (request_id, name, arguments) in [
        (11, "mvm.machine.inspect", json!({"id":id})),
        (12, "mvm.machine.start", json!({"id":id})),
        (13, "mvm.machine.pause", json!({"id":id})),
        (14, "mvm.machine.resume", json!({"id":id, "warm":false})),
        (15, "mvm.machine.logs", json!({"id":id, "tail_lines":10})),
        (16, "mvm.machine.exec", json!({"id":id, "command":["true"]})),
        (17, "mvm.machine.reconfigure", json!({"id":id, "cpus":3})),
        (
            18,
            "mvm.machine.set_ttl",
            json!({"id":id, "expires_at":"2030-01-01T00:00:00Z"}),
        ),
        (19, "mvm.machine.stop", json!({"id":id})),
    ] {
        let response = call(&server, request_id, name, arguments).await;
        assert_eq!(response["result"]["isError"], false, "{name}: {response}");
    }
    let listed = call(&server, 20, "mvm.machine.list", json!({})).await;
    assert_eq!(
        listed["result"]["structuredContent"][0]["status"],
        "stopped"
    );
    let removed = call(&server, 21, "mvm.machine.remove", json!({"id":id})).await;
    assert_eq!(removed["result"]["isError"], false);
    assert!(
        mock.list_machines(MachineFilter::all())
            .await
            .expect("mock list")
            .is_empty()
    );
}

#[tokio::test]
async fn backend_failure_is_a_tool_result_the_model_can_correct() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let response = call(&server, 30, "mvm.machine.inspect", json!({"id":"absent"})).await;
    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("error text")
            .contains("absent")
    );
}

#[tokio::test]
async fn invalid_arguments_are_strict_and_unknown_tools_are_protocol_errors() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let invalid = call(&server, 40, "mvm.machine.list", json!({"unexpected":true})).await;
    assert_eq!(invalid["result"]["isError"], true);

    let unknown = call(&server, 41, "mvm.machine.nope", json!({})).await;
    assert_eq!(unknown["error"]["code"], -32602);
}

#[tokio::test]
async fn invalid_ttl_and_oversized_output_fail_as_tool_results() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let created = call(
        &server,
        42,
        "mvm.machine.create",
        json!({"name":"ttl-check", "image":"alpine"}),
    )
    .await;
    let id = created["result"]["structuredContent"]["id"]
        .as_str()
        .expect("machine id");
    let invalid = call(
        &server,
        43,
        "mvm.machine.set_ttl",
        json!({"id":id, "expires_at":"tomorrow"}),
    )
    .await;
    assert_eq!(invalid["result"]["isError"], true);

    let bounded = McpServer::with_limits(
        Arc::new(MockBackend::default()),
        ServerLimits::default()
            .max_frame_bytes(4096)
            .max_output_bytes(512),
    );
    let response = call(&bounded, 44, "mvm.backend_capabilities", json!({})).await;
    assert_eq!(response["result"]["isError"], true);
}

#[tokio::test]
async fn notifications_receive_no_response_and_legacy_initialize_still_works() {
    let server = McpServer::new(Arc::new(MockBackend::default()));
    let notification = json!({
        "jsonrpc":"2.0", "method":"notifications/initialized", "params":{}
    })
    .to_string();
    assert!(server.handle_json(&notification).await.is_none());

    let initialize = json!({
        "jsonrpc":"2.0", "id":50, "method":"initialize",
        "params":{"protocolVersion":"2025-11-25", "capabilities":{},
                  "clientInfo":{"name":"legacy", "version":"1"}}
    })
    .to_string();
    let response: Value = serde_json::from_str(
        &server
            .handle_json(&initialize)
            .await
            .expect("initialize response"),
    )
    .expect("initialize json");
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(response["result"]["serverInfo"]["name"], "mvm");
}

#[test]
fn stdio_frame_bound_is_recoverable_for_the_next_request() {
    let valid = current_request(61, "server/discover", json!({}));
    let input = format!("{}\n{valid}\n", "x".repeat(513));
    let mut output = Vec::new();
    McpServer::with_limits(
        Arc::new(MockBackend::default()),
        ServerLimits::default()
            .max_frame_bytes(512)
            .max_output_bytes(4096),
    )
    .serve(Cursor::new(input), &mut output)
    .expect("serve recovers after oversized frame");
    let frames: Vec<Value> = String::from_utf8(output)
        .expect("utf8 output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("response frame"))
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert_eq!(frames[1]["id"], 61);
}

#[test]
fn invalid_utf8_frame_is_recoverable_for_the_next_request() {
    let valid = current_request(62, "server/discover", json!({}));
    let mut input = vec![0xff, b'\n'];
    input.extend_from_slice(valid.as_bytes());
    input.push(b'\n');
    let mut output = Vec::new();
    McpServer::new(Arc::new(MockBackend::default()))
        .serve(Cursor::new(input), &mut output)
        .expect("serve recovers after invalid UTF-8");
    let frames: Vec<Value> = String::from_utf8(output)
        .expect("utf8 output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("response frame"))
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert_eq!(frames[1]["id"], 62);
}

#[tokio::test]
async fn list_status_filter_uses_the_wire_enum() {
    let mock = Arc::new(MockBackend::default());
    let server = McpServer::new(mock.clone());
    call(
        &server,
        70,
        "mvm.machine.run",
        json!({"name":"running", "image":"alpine"}),
    )
    .await;
    let response = call(&server, 71, "mvm.machine.list", json!({"status":"running"})).await;
    assert_eq!(
        response["result"]["structuredContent"][0]["name"],
        "running"
    );
    assert_eq!(
        mock.list_machines(MachineFilter {
            name: None,
            status: Some(MachineStatus::Running)
        })
        .await
        .expect("mock list")[0]
            .id,
        MachineId("m1".into())
    );
}

/// Where the agent-facing tool contract is pinned.
const TOOL_CONTRACT_FIXTURE: &str = "tests/fixtures/tool-contract.json";

/// Set to rewrite the pinned contract from what the server advertises.
const TOOL_CONTRACT_UPDATE_ENV: &str = "MVM_UPDATE_MCP_TOOL_CONTRACT";

fn operation_keys() -> Vec<String> {
    serde_json::to_value(ClientOperationCapabilities::default())
        .expect("operation capabilities serialize")
        .as_object()
        .expect("operation capabilities are an object")
        .keys()
        .cloned()
        .collect()
}

fn operations_serving(keys: &[String]) -> ClientOperationCapabilities {
    let fields = keys
        .iter()
        .map(|key| (key.clone(), Value::Bool(true)))
        .collect();
    serde_json::from_value(Value::Object(fields)).expect("known operation keys deserialize")
}

async fn advertised_tools(operations: ClientOperationCapabilities) -> Vec<Value> {
    let server = McpServer::new(Arc::new(MockBackend::default().with_operations(operations)));
    request(&server, 80, "tools/list", json!({})).await["result"]["tools"]
        .as_array()
        .expect("tools")
        .clone()
}

fn tool_name(tool: &Value) -> String {
    tool["name"].as_str().expect("tool name").to_string()
}

/// Rebuild `value` with every object's keys in sorted order, whatever map
/// ordering `serde_json` was compiled with.
fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<String, Value> = object
                .into_iter()
                .map(|(key, value)| (key, sort_keys(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// The advertised tool surface in its pinned form: every tool a fully capable
/// client is offered, with the one client operation that gates it (`null` when
/// every client is offered it), sorted by name, keys sorted, pretty-printed.
async fn normalized_tool_contract() -> String {
    let keys = operation_keys();
    let always: Vec<String> = advertised_tools(ClientOperationCapabilities::default())
        .await
        .iter()
        .map(tool_name)
        .collect();
    let mut gates: BTreeMap<String, String> = BTreeMap::new();
    for key in &keys {
        for tool in advertised_tools(operations_serving(std::slice::from_ref(key))).await {
            let name = tool_name(&tool);
            if !always.contains(&name) {
                gates.insert(name, key.clone());
            }
        }
    }

    let mut tools = advertised_tools(operations_serving(&keys)).await;
    tools.sort_by_key(tool_name);
    let contract: Vec<Value> = tools
        .into_iter()
        .map(|mut tool| {
            let name = tool_name(&tool);
            let requires = if always.contains(&name) {
                Value::Null
            } else {
                let key = gates.get(&name).unwrap_or_else(|| {
                    panic!("`{name}` is not gated by a single client operation")
                });
                Value::String(key.clone())
            };
            tool.as_object_mut()
                .expect("tool is an object")
                .insert("requires".into(), requires);
            sort_keys(tool)
        })
        .collect();
    let mut rendered =
        serde_json::to_string_pretty(&json!({ "tools": contract })).expect("contract serializes");
    rendered.push('\n');
    rendered
}

/// Names of tools present in only one side, or present in both but different.
fn contract_drift(pinned: &str, advertised: &str) -> String {
    let by_name = |text: &str| -> BTreeMap<String, Value> {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|contract| contract["tools"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|tool| (tool_name(&tool), tool))
            .collect()
    };
    let (pinned, advertised) = (by_name(pinned), by_name(advertised));
    let mut lines = Vec::new();
    for (name, tool) in &advertised {
        match pinned.get(name) {
            None => lines.push(format!("  added:   {name}")),
            Some(previous) if previous != tool => lines.push(format!("  changed: {name}")),
            Some(_) => {}
        }
    }
    for name in pinned.keys().filter(|name| !advertised.contains_key(*name)) {
        lines.push(format!("  removed: {name}"));
    }
    if lines.is_empty() {
        lines.push("  (formatting only)".into());
    }
    lines.join("\n")
}

#[tokio::test]
async fn tool_surface_matches_the_pinned_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(TOOL_CONTRACT_FIXTURE);
    let advertised = normalized_tool_contract().await;

    if std::env::var_os(TOOL_CONTRACT_UPDATE_ENV).is_some() {
        std::fs::write(&path, &advertised).expect("write pinned tool contract");
        return;
    }

    let pinned = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        pinned == advertised,
        "the MCP tool surface no longer matches {TOOL_CONTRACT_FIXTURE}:\n{}\n\n\
         Tool names, descriptions, input schemas, and gating operations are what an agent \
         is offered, so a change here is a contract change. If it is intended, re-bless and \
         review the fixture diff:\n  \
         {TOOL_CONTRACT_UPDATE_ENV}=1 cargo test -p mvm-mcp --test protocol \
         tool_surface_matches_the_pinned_contract",
        contract_drift(&pinned, &advertised)
    );
}
