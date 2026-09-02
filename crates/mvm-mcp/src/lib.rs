//! A bounded, stdio-only Model Context Protocol adapter over [`MvmClient`].
//!
//! This crate owns JSON-RPC framing and DTO translation only. It performs no
//! lifecycle, admission, or authorization work: every advertised machine
//! operation delegates to the selected client facade.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, OnceLock};

use mvm_client::dto::{
    LogOpts, MachineFilter, MachineId, MachineSpec, MachineStatus, PauseOpts, ReconfigureRequest,
    ResumeOpts,
};
use mvm_client::{
    BackendCapabilityReport, ClientOperationCapabilities, MvmClient, validate_vm_name,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Current stateless MCP protocol version supported by this server.
pub const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";
/// Legacy handshake version retained for clients that have not moved to
/// per-request discovery metadata yet.
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

const CATALOG_TTL_MS: u64 = 300_000;
const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Bounds applied before allocating or emitting protocol payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    max_frame_bytes: usize,
    max_output_bytes: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl ServerLimits {
    /// Set the maximum request-frame size. Values below one byte are clamped
    /// to one so the bound remains meaningful.
    #[must_use]
    pub fn max_frame_bytes(mut self, bytes: usize) -> Self {
        self.max_frame_bytes = bytes.max(1);
        self
    }

    /// Set the maximum successful tool-result payload size. Protocol errors
    /// have a small fixed envelope and remain available when this cap trips.
    #[must_use]
    pub fn max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes.max(1);
        self
    }
}

/// A stdio serving failure. Protocol and backend errors are encoded as JSON-RPC
/// responses and do not terminate the loop.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("MCP stdio I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Stateless request adapter with one process-lifetime capability snapshot.
pub struct McpServer {
    client: Arc<dyn MvmClient>,
    capabilities: OnceLock<BackendCapabilityReport>,
    limits: ServerLimits,
}

impl McpServer {
    /// Construct a server over the selected facade implementation.
    #[must_use]
    pub fn new(client: Arc<dyn MvmClient>) -> Self {
        Self::with_limits(client, ServerLimits::default())
    }

    /// Construct a server with explicit transport/output bounds.
    #[must_use]
    pub fn with_limits(client: Arc<dyn MvmClient>, limits: ServerLimits) -> Self {
        Self {
            client,
            capabilities: OnceLock::new(),
            limits,
        }
    }

    /// Handle one newline-delimited JSON-RPC frame. Notifications return
    /// `None`; all requests return exactly one serialized response.
    pub async fn handle_json(&self, frame: &str) -> Option<String> {
        if frame.len() > self.limits.max_frame_bytes {
            return Some(response_error(
                Value::Null,
                -32700,
                "request frame exceeds limit",
            ));
        }
        let value: Value = match serde_json::from_str(frame) {
            Ok(value) => value,
            Err(_) => return Some(response_error(Value::Null, -32700, "invalid JSON")),
        };
        let request = match ParsedRequest::parse(value) {
            Ok(request) => request,
            Err(error) => return Some(error),
        };
        let id = request.id?;
        Some(self.dispatch(id, request.method, request.params).await)
    }

    /// Serve newline-delimited MCP over the supplied streams until EOF.
    /// stdout-equivalent output contains protocol frames only.
    pub fn serve<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), ServerError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        loop {
            match read_bounded_frame(&mut reader, self.limits.max_frame_bytes)? {
                Frame::Eof => return Ok(()),
                Frame::Oversized => {
                    writeln!(
                        writer,
                        "{}",
                        response_error(Value::Null, -32700, "request frame exceeds limit")
                    )?;
                    writer.flush()?;
                }
                Frame::InvalidUtf8 => {
                    writeln!(
                        writer,
                        "{}",
                        response_error(Value::Null, -32700, "request frame is not UTF-8")
                    )?;
                    writer.flush()?;
                }
                Frame::Line(line) => {
                    if let Some(response) = runtime.block_on(self.handle_json(&line)) {
                        writeln!(writer, "{response}")?;
                        writer.flush()?;
                    }
                }
            }
        }
    }

    async fn capabilities(&self) -> Result<&BackendCapabilityReport, String> {
        if let Some(report) = self.capabilities.get() {
            return Ok(report);
        }
        let report = self
            .client
            .backend_capabilities()
            .await
            .map_err(|_| "client capability discovery failed".to_string())?;
        let _ = self.capabilities.set(report);
        self.capabilities
            .get()
            .ok_or_else(|| "client capability discovery did not persist".to_string())
    }

    async fn dispatch(&self, id: Value, method: String, mut params: Map<String, Value>) -> String {
        if method == "initialize" {
            return legacy_initialize(id, params);
        }

        let meta = params.remove("_meta");
        if method == "server/discover" && meta.is_none() {
            return response_error(id, -32602, "server/discover requires request metadata");
        }
        if let Some(meta) = meta {
            if let Err(message) = validate_current_meta(&meta) {
                return response_error(id, -32602, message);
            }
        }

        match method.as_str() {
            "server/discover" => {
                if !params.is_empty() {
                    return response_error(id, -32602, "unexpected discovery parameters");
                }
                response_result(id, discover_result())
            }
            "tools/list" => match parse_params::<ListParams>(params) {
                Ok(list) if list.cursor.is_none() => match self.capabilities().await {
                    Ok(report) => response_result(id, tools_result(&report.operations)),
                    Err(message) => response_error(id, -32603, &message),
                },
                Ok(_) => response_error(id, -32602, "tool catalog has no further page"),
                Err(message) => response_error(id, -32602, &message),
            },
            "tools/call" => {
                let call = match parse_params::<CallParams>(params) {
                    Ok(call) => call,
                    Err(message) => return response_error(id, -32602, &message),
                };
                let report = match self.capabilities().await {
                    Ok(report) => report,
                    Err(message) => return response_error(id, -32603, &message),
                };
                if !tool_enabled(&call.name, &report.operations) {
                    return response_error(id, -32602, "unknown or unavailable tool");
                }
                match self.call_tool(&call.name, call.arguments, report).await {
                    Ok(value) => response_result(id, self.tool_success(value)),
                    Err(ToolFailure::Input(message) | ToolFailure::Backend(message)) => {
                        response_result(id, tool_error(&message))
                    }
                }
            }
            _ => response_error(id, -32601, "method not found"),
        }
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Map<String, Value>,
        report: &BackendCapabilityReport,
    ) -> Result<Value, ToolFailure> {
        match name {
            "mvm.backend_capabilities" => {
                parse_arguments::<EmptyArgs>(arguments)?;
                serde_json::to_value(report).map_err(ToolFailure::serialization)
            }
            "mvm.machine.list" => {
                let args = parse_arguments::<ListArgs>(arguments)?;
                let machines = self
                    .client
                    .list_machines(MachineFilter {
                        name: args.name,
                        status: args.status,
                    })
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(machines).map_err(ToolFailure::serialization)
            }
            "mvm.machine.inspect" => {
                let args = parse_arguments::<IdArgs>(arguments)?;
                let state = self
                    .client
                    .inspect_machine(&MachineId(args.id))
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(state).map_err(ToolFailure::serialization)
            }
            "mvm.machine.create" | "mvm.machine.run" => {
                let args = parse_arguments::<LaunchArgs>(arguments)?;
                let spec = args.into_spec()?;
                let state = if name == "mvm.machine.create" {
                    self.client.create_machine(spec).await
                } else {
                    self.client.run_machine(spec).await
                }
                .map_err(ToolFailure::backend)?;
                serde_json::to_value(state).map_err(ToolFailure::serialization)
            }
            "mvm.machine.start" => {
                let args = parse_arguments::<IdArgs>(arguments)?;
                let state = self
                    .client
                    .start_machine(&MachineId(args.id))
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(state).map_err(ToolFailure::serialization)
            }
            "mvm.machine.stop" => {
                let args = parse_arguments::<IdArgs>(arguments)?;
                self.client
                    .stop_machine(&MachineId(args.id))
                    .await
                    .map_err(ToolFailure::backend)?;
                Ok(json!({"ok": true}))
            }
            "mvm.machine.pause" => {
                let args = parse_arguments::<PauseArgs>(arguments)?;
                if args.primed_timeout_secs == 0 {
                    return Err(ToolFailure::Input(
                        "primed_timeout_secs must be greater than zero".into(),
                    ));
                }
                let outcome = self
                    .client
                    .pause_machine(
                        &MachineId(args.id),
                        PauseOpts {
                            primed_barrier: args.primed_barrier,
                            primed_timeout_secs: args.primed_timeout_secs,
                        },
                    )
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(outcome).map_err(ToolFailure::serialization)
            }
            "mvm.machine.resume" => {
                let args = parse_arguments::<ResumeArgs>(arguments)?;
                let outcome = self
                    .client
                    .resume_machine(&MachineId(args.id), ResumeOpts { warm: args.warm })
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(outcome).map_err(ToolFailure::serialization)
            }
            "mvm.machine.remove" => {
                let args = parse_arguments::<IdArgs>(arguments)?;
                self.client
                    .remove_machine(&MachineId(args.id))
                    .await
                    .map_err(ToolFailure::backend)?;
                Ok(json!({"ok": true}))
            }
            "mvm.machine.logs" => {
                let args = parse_arguments::<LogsArgs>(arguments)?;
                let bytes = self
                    .client
                    .machine_logs(
                        &MachineId(args.id),
                        LogOpts {
                            follow: args.follow,
                            tail_lines: args.tail_lines,
                        },
                    )
                    .await
                    .map_err(ToolFailure::backend)?;
                Ok(json!({"logs": String::from_utf8_lossy(&bytes)}))
            }
            "mvm.machine.exec" => {
                let args = parse_arguments::<ExecArgs>(arguments)?;
                if args.command.is_empty() {
                    return Err(ToolFailure::Input("command must not be empty".into()));
                }
                let result = self
                    .client
                    .exec_machine(&MachineId(args.id), args.command)
                    .await
                    .map_err(ToolFailure::backend)?;
                Ok(json!({
                    "exit_code": result.exit_code,
                    "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr)
                }))
            }
            "mvm.machine.reconfigure" => {
                let args = parse_arguments::<ReconfigureArgs>(arguments)?;
                if args.cpus == Some(0) || args.memory_mib == Some(0) {
                    return Err(ToolFailure::Input(
                        "cpus and memory_mib must be greater than zero".into(),
                    ));
                }
                let state = self
                    .client
                    .reconfigure_machine(
                        &MachineId(args.id),
                        ReconfigureRequest {
                            net: args.net,
                            allow_host: args.allow_host,
                            cpus: args.cpus,
                            memory_mib: args.memory_mib,
                        },
                    )
                    .await
                    .map_err(ToolFailure::backend)?;
                serde_json::to_value(state).map_err(ToolFailure::serialization)
            }
            "mvm.machine.set_ttl" => {
                let args = parse_arguments::<SetTtlArgs>(arguments)?;
                if args.expires_at.as_ref().is_some_and(|expires_at| {
                    chrono::DateTime::parse_from_rfc3339(expires_at).is_err()
                }) {
                    return Err(ToolFailure::Input(
                        "expires_at must be an RFC 3339 timestamp or null".into(),
                    ));
                }
                self.client
                    .set_ttl(&MachineId(args.id), args.expires_at)
                    .await
                    .map_err(ToolFailure::backend)?;
                Ok(json!({"ok": true}))
            }
            _ => Err(ToolFailure::Input("unknown tool".into())),
        }
    }

    fn tool_success(&self, value: Value) -> Value {
        let text = match serde_json::to_string(&value) {
            Ok(text) => text,
            Err(_) => return tool_error("tool output could not be serialized"),
        };
        let result = json!({
            "resultType": "complete",
            "content": [{"type":"text", "text":text}],
            "structuredContent": value,
            "isError": false,
            "_meta": server_meta()
        });
        if serde_json::to_vec(&result)
            .is_ok_and(|bytes| bytes.len() <= self.limits.max_output_bytes)
        {
            result
        } else {
            tool_error("tool output exceeds configured limit")
        }
    }
}

#[derive(Debug)]
struct ParsedRequest {
    id: Option<Value>,
    method: String,
    params: Map<String, Value>,
}

impl ParsedRequest {
    fn parse(value: Value) -> Result<Self, String> {
        let Some(mut object) = value.as_object().cloned() else {
            return Err(response_error(
                Value::Null,
                -32600,
                "request must be an object",
            ));
        };
        let id = object.remove("id");
        if id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number())
        {
            return Err(response_error(Value::Null, -32600, "invalid request id"));
        }
        if object.remove("jsonrpc") != Some(Value::String("2.0".into())) {
            return Err(response_error(
                id.unwrap_or(Value::Null),
                -32600,
                "jsonrpc must be 2.0",
            ));
        }
        let Some(method) = object
            .remove("method")
            .and_then(|method| method.as_str().map(str::to_owned))
        else {
            return Err(response_error(
                id.unwrap_or(Value::Null),
                -32600,
                "method must be a string",
            ));
        };
        let params = match object.remove("params") {
            None => Map::new(),
            Some(Value::Object(params)) => params,
            Some(_) => {
                return Err(response_error(
                    id.unwrap_or(Value::Null),
                    -32602,
                    "params must be an object",
                ));
            }
        };
        if !object.is_empty() {
            return Err(response_error(
                id.unwrap_or(Value::Null),
                -32600,
                "unexpected request fields",
            ));
        }
        Ok(Self { id, method, params })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyInitialize {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: Value,
    #[serde(rename = "clientInfo")]
    client_info: Value,
}

fn legacy_initialize(id: Value, params: Map<String, Value>) -> String {
    let request = match parse_params::<LegacyInitialize>(params) {
        Ok(request) => request,
        Err(message) => return response_error(id, -32602, &message),
    };
    if request.protocol_version != LEGACY_PROTOCOL_VERSION {
        return response_error(id, -32602, "unsupported legacy protocol version");
    }
    if !request.capabilities.is_object() || !request.client_info.is_object() {
        return response_error(id, -32602, "invalid initialize capabilities or clientInfo");
    }
    response_result(
        id,
        json!({
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name":"mvm", "version":env!("CARGO_PKG_VERSION")},
            "instructions":"Drive machines through the MvmClient-backed tools."
        }),
    )
}

fn validate_current_meta(meta: &Value) -> Result<(), &'static str> {
    let Some(meta) = meta.as_object() else {
        return Err("_meta must be an object");
    };
    if meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
        != Some(CURRENT_PROTOCOL_VERSION)
    {
        return Err("unsupported MCP protocol version");
    }
    if !meta
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_some_and(Value::is_object)
    {
        return Err("client capabilities metadata is required");
    }
    Ok(())
}

fn discover_result() -> Value {
    json!({
        "resultType":"complete",
        "supportedVersions":[CURRENT_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
        "capabilities":{"tools":{}},
        "instructions":"Drive machines through the MvmClient-backed tools; unavailable facade operations are not advertised.",
        "ttlMs":CATALOG_TTL_MS,
        "cacheScope":"private",
        "_meta":server_meta()
    })
}

fn server_meta() -> Value {
    json!({
        "io.modelcontextprotocol/serverInfo": {
            "name":"mvm",
            "version":env!("CARGO_PKG_VERSION")
        }
    })
}

fn tools_result(operations: &ClientOperationCapabilities) -> Value {
    let tools: Vec<Value> = tool_specs()
        .into_iter()
        .filter(|tool| tool_enabled(tool["name"].as_str().unwrap_or_default(), operations))
        .collect();
    json!({
        "resultType":"complete",
        "tools":tools,
        "ttlMs":CATALOG_TTL_MS,
        "cacheScope":"private",
        "_meta":server_meta()
    })
}

fn tool_enabled(name: &str, operations: &ClientOperationCapabilities) -> bool {
    match name {
        "mvm.backend_capabilities" => true,
        "mvm.machine.list" => operations.list,
        "mvm.machine.inspect" => operations.inspect,
        "mvm.machine.create" => operations.create,
        "mvm.machine.run" => operations.run,
        "mvm.machine.start" => operations.start,
        "mvm.machine.stop" => operations.stop,
        "mvm.machine.pause" => operations.pause,
        "mvm.machine.resume" => operations.resume,
        "mvm.machine.remove" => operations.remove,
        "mvm.machine.logs" => operations.logs,
        "mvm.machine.exec" => operations.exec,
        "mvm.machine.reconfigure" => operations.reconfigure,
        "mvm.machine.set_ttl" => operations.set_ttl,
        _ => false,
    }
}

fn tool_specs() -> Vec<Value> {
    vec![
        tool(
            "mvm.backend_capabilities",
            "Describe the selected backend and client operation surface.",
            empty_schema(),
        ),
        tool(
            "mvm.machine.list",
            "List machines visible through the selected client.",
            object_schema(
                json!({"name":{"type":"string"}, "status":{"type":"string","enum":["starting","running","stopped","paused","failed"]}}),
                &[],
            ),
        ),
        tool("mvm.machine.inspect", "Inspect one machine.", id_schema()),
        tool(
            "mvm.machine.create",
            "Create a stopped machine through MvmClient.",
            launch_schema(),
        ),
        tool(
            "mvm.machine.run",
            "Create and start a machine through MvmClient.",
            launch_schema(),
        ),
        tool("mvm.machine.start", "Start a created machine.", id_schema()),
        tool(
            "mvm.machine.stop",
            "Stop a machine idempotently.",
            id_schema(),
        ),
        tool(
            "mvm.machine.pause",
            "Pause a running machine.",
            object_schema(
                json!({"id":{"type":"string"},"primed_barrier":{"type":"boolean"},"primed_timeout_secs":{"type":"integer","minimum":1}}),
                &["id"],
            ),
        ),
        tool(
            "mvm.machine.resume",
            "Resume a paused machine.",
            object_schema(
                json!({"id":{"type":"string"},"warm":{"type":"boolean"}}),
                &["id"],
            ),
        ),
        tool(
            "mvm.machine.remove",
            "Remove a machine idempotently.",
            id_schema(),
        ),
        tool(
            "mvm.machine.logs",
            "Read bounded machine logs.",
            object_schema(
                json!({"id":{"type":"string"},"follow":{"type":"boolean"},"tail_lines":{"type":"integer","minimum":0}}),
                &["id"],
            ),
        ),
        tool(
            "mvm.machine.exec",
            "Run a non-interactive command when the selected client supports it.",
            object_schema(
                json!({"id":{"type":"string"},"command":{"type":"array","items":{"type":"string"},"minItems":1}}),
                &["id", "command"],
            ),
        ),
        tool(
            "mvm.machine.reconfigure",
            "Patch supported machine configuration fields.",
            object_schema(
                json!({"id":{"type":"string"},"net":{"type":"boolean"},"allow_host":{"type":"array","items":{"type":"string"}},"cpus":{"type":"integer","minimum":1},"memory_mib":{"type":"integer","minimum":1}}),
                &["id"],
            ),
        ),
        tool(
            "mvm.machine.set_ttl",
            "Set or clear a machine TTL.",
            object_schema(
                json!({"id":{"type":"string"},"expires_at":{"type":["string","null"]}}),
                &["id"],
            ),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({"name":name, "description":description, "inputSchema":input_schema})
}

fn empty_schema() -> Value {
    object_schema(json!({}), &[])
}

fn id_schema() -> Value {
    object_schema(json!({"id":{"type":"string"}}), &["id"])
}

fn launch_schema() -> Value {
    object_schema(
        json!({
            "name":{"type":"string"}, "image":{"type":"string"},
            "cpus":{"type":"integer","minimum":1},
            "memory_mib":{"type":"integer","minimum":1},
            "env":{"type":"object","additionalProperties":{"type":"string"}}
        }),
        &["name", "image"],
    )
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn response_result(id: Value, result: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc":"2.0", "id":id, "result":result}))
        .expect("JSON-RPC result values are serializable")
}

fn response_error(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc":"2.0", "id":id, "error":{"code":code, "message":message}
    }))
    .expect("JSON-RPC error values are serializable")
}

fn tool_error(message: &str) -> Value {
    let message: String = message.chars().take(512).collect();
    json!({
        "resultType":"complete",
        "content":[{"type":"text", "text":message}],
        "isError":true,
        "_meta":server_meta()
    })
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Map<String, Value>) -> Result<T, String> {
    serde_json::from_value(Value::Object(params))
        .map_err(|error| format!("invalid parameters: {error}"))
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Map<String, Value>,
) -> Result<T, ToolFailure> {
    serde_json::from_value(Value::Object(arguments))
        .map_err(|error| ToolFailure::Input(format!("invalid tool arguments: {error}")))
}

#[derive(Debug)]
enum ToolFailure {
    Input(String),
    Backend(String),
}

impl ToolFailure {
    fn backend(error: impl std::fmt::Display) -> Self {
        Self::Backend(format!("MvmClient operation failed: {error}"))
    }

    fn serialization(_: impl std::fmt::Display) -> Self {
        Self::Backend("MvmClient result could not be serialized".into())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallParams {
    name: String,
    #[serde(default)]
    arguments: Map<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    name: Option<String>,
    status: Option<MachineStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchArgs {
    name: String,
    image: String,
    #[serde(default = "default_cpus")]
    cpus: u32,
    #[serde(default = "default_memory_mib")]
    memory_mib: u32,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

impl LaunchArgs {
    fn into_spec(self) -> Result<MachineSpec, ToolFailure> {
        if self.cpus == 0 || self.memory_mib == 0 {
            return Err(ToolFailure::Input(
                "cpus and memory_mib must be greater than zero".into(),
            ));
        }
        validate_vm_name(&self.name)
            .map_err(|_| ToolFailure::Input("invalid machine name".into()))?;
        let builder = MachineSpec::builder(self.name, self.image)
            .map_err(|_| ToolFailure::Input("invalid image declaration".into()))?;
        Ok(builder
            .cpus(self.cpus)
            .memory_mib(self.memory_mib)
            .envs(self.env)
            .build())
    }
}

fn default_cpus() -> u32 {
    1
}

fn default_memory_mib() -> u32 {
    512
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PauseArgs {
    id: String,
    #[serde(default)]
    primed_barrier: bool,
    #[serde(default = "default_primed_timeout_secs")]
    primed_timeout_secs: u64,
}

fn default_primed_timeout_secs() -> u64 {
    120
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeArgs {
    id: String,
    #[serde(default)]
    warm: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogsArgs {
    id: String,
    #[serde(default)]
    follow: bool,
    tail_lines: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecArgs {
    id: String,
    command: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconfigureArgs {
    id: String,
    net: Option<bool>,
    allow_host: Option<Vec<String>>,
    cpus: Option<u32>,
    memory_mib: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetTtlArgs {
    id: String,
    expires_at: Option<String>,
}

enum Frame {
    Eof,
    Oversized,
    InvalidUtf8,
    Line(String),
}

fn read_bounded_frame<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Frame> {
    let mut bytes = Vec::with_capacity(limit.min(4096));
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if bytes.is_empty() && !oversized {
                return Ok(Frame::Eof);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if !oversized {
            let content_len = newline.unwrap_or(consumed);
            let remaining = limit.saturating_sub(bytes.len());
            let copied = content_len.min(remaining);
            bytes.extend_from_slice(&available[..copied]);
            if content_len > remaining {
                oversized = true;
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if oversized {
        return Ok(Frame::Oversized);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(String::from_utf8(bytes).map_or(Frame::InvalidUtf8, Frame::Line))
}
