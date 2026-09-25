//! A bounded, stdio-only Model Context Protocol adapter over [`MvmClient`].
//!
//! This crate owns JSON-RPC framing and DTO translation only. It performs no
//! lifecycle, admission, or authorization work: every advertised machine
//! operation delegates to the selected client facade.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_client::drive::{
    DriveError, DriveFileOperation, EntrypointEvent, FsResult, InputFrame, LocalDrive,
};
use mvm_client::dto::{
    LogOpts, MachineFilter, MachineId, MachineSpec, MachineStatus, PauseOpts, ReconfigureRequest,
    ResumeOpts,
};
use mvm_client::{
    BackendCapabilityReport, ClientOperationCapabilities, MvmClient, MvmError, validate_vm_name,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Current stateless MCP protocol version supported by this server.
pub const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";
/// Legacy handshake version retained for clients that have not moved to
/// per-request discovery metadata yet.
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

const CATALOG_TTL_MS: u64 = 300_000;
const UNKNOWN_TOOL: &str = "unknown tool";
const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Drive operations the MCP adapter exposes. Production uses [`LocalDrive`];
/// tests inject a recording implementation without booting a machine.
pub trait DriveTools: Send + Sync {
    fn open(&self, cwd: &str) -> Result<String, DriveError>;
    fn write(&self, frame: InputFrame, eof: bool) -> Result<usize, DriveError>;
    fn next_event(&self) -> Result<Option<EntrypointEvent>, DriveError>;
    fn file(&self, operation: DriveFileOperation) -> Result<FsResult, DriveError>;
}

impl DriveTools for LocalDrive {
    fn open(&self, cwd: &str) -> Result<String, DriveError> {
        self.open(cwd)
    }

    fn write(&self, frame: InputFrame, eof: bool) -> Result<usize, DriveError> {
        self.write(frame, eof)
    }

    fn next_event(&self) -> Result<Option<EntrypointEvent>, DriveError> {
        self.next_event()
    }

    fn file(&self, operation: DriveFileOperation) -> Result<FsResult, DriveError> {
        self.file(operation)
    }
}

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
    drive: Option<Arc<dyn DriveTools>>,
    capabilities: OnceLock<BackendCapabilityReport>,
    limits: ServerLimits,
}

impl McpServer {
    /// Construct a server over the selected facade implementation.
    #[must_use]
    pub fn new(client: Arc<dyn MvmClient>) -> Self {
        Self::with_limits(client, ServerLimits::default())
    }

    /// Bind the drive tools to one verified grant. A server never given one
    /// neither lists nor accepts any `mvm.drive.*` tool.
    #[must_use]
    pub fn with_drive(mut self, drive: Arc<dyn DriveTools>) -> Self {
        self.drive = Some(drive);
        self
    }

    /// Construct a server with explicit transport/output bounds.
    #[must_use]
    pub fn with_limits(client: Arc<dyn MvmClient>, limits: ServerLimits) -> Self {
        Self {
            client,
            drive: None,
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

    async fn capabilities(&self) -> Result<&BackendCapabilityReport, CapabilitiesFailure> {
        if let Some(report) = self.capabilities.get() {
            return Ok(report);
        }
        let report = self
            .client
            .backend_capabilities()
            .await
            .map_err(CapabilitiesFailure::Backend)?;
        let _ = self.capabilities.set(report);
        self.capabilities.get().ok_or(CapabilitiesFailure::Internal(
            "client capability discovery did not persist",
        ))
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
                    Ok(report) => {
                        response_result(id, tools_result(&report.operations, self.drive.is_some()))
                    }
                    Err(failure) => response_error_classified(id, -32603, &failure),
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
                    Err(failure) => return response_error_classified(id, -32603, &failure),
                };
                if !tool_enabled(&call.name, &report.operations, self.drive.is_some()) {
                    return response_error(id, -32602, "unknown or unavailable tool");
                }
                match self.call_tool(&call.name, call.arguments, report).await {
                    Ok(value) => response_result(id, self.tool_success(value)),
                    Err(failure) => response_result(id, failure.into_tool_result()),
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
            "mvm.drive.open" => {
                let args = parse_arguments::<DriveOpenArgs>(arguments)?;
                let holder = self.drive()?.open(&args.cwd).map_err(ToolFailure::Drive)?;
                Ok(json!({"holder": holder}))
            }
            "mvm.drive.write" => {
                let args = parse_arguments::<DriveWriteArgs>(arguments)?;
                let payload = B64
                    .decode(args.data_b64)
                    .map_err(|_| ToolFailure::Input("data_b64 must be valid base64".into()))?;
                let accepted = self
                    .drive()?
                    .write(
                        InputFrame {
                            seq: args.seq,
                            payload,
                        },
                        args.eof,
                    )
                    .map_err(ToolFailure::Drive)?;
                Ok(json!({"accepted": accepted}))
            }
            "mvm.drive.events" => {
                parse_arguments::<EmptyArgs>(arguments)?;
                let event = self.drive()?.next_event().map_err(ToolFailure::Drive)?;
                serde_json::to_value(event).map_err(ToolFailure::serialization)
            }
            "mvm.drive.files.read" => {
                let args = parse_arguments::<DriveReadArgs>(arguments)?;
                let result = self
                    .drive()?
                    .file(DriveFileOperation::Read {
                        path: args.path,
                        offset: args.offset,
                        length: args.length,
                        follow_symlinks: args.follow_symlinks,
                    })
                    .map_err(ToolFailure::Drive)?;
                match result {
                    FsResult::Read {
                        content,
                        total_size,
                    } => Ok(json!({"data_b64": B64.encode(content), "total_size": total_size})),
                    other => Err(ToolFailure::Input(format!(
                        "drive read returned an unexpected response: {other:?}"
                    ))),
                }
            }
            "mvm.drive.files.write" => {
                let args = parse_arguments::<DriveFileWriteArgs>(arguments)?;
                let content = B64
                    .decode(args.data_b64)
                    .map_err(|_| ToolFailure::Input("data_b64 must be valid base64".into()))?;
                let result = self
                    .drive()?
                    .file(DriveFileOperation::Write {
                        path: args.path,
                        content,
                        mode: args.mode,
                        create_parents: args.create_parents,
                        follow_symlinks: args.follow_symlinks,
                        offset: args.offset,
                        truncate: args.truncate,
                    })
                    .map_err(ToolFailure::Drive)?;
                match result {
                    FsResult::Write { bytes_written } => {
                        Ok(json!({"bytes_written": bytes_written}))
                    }
                    other => Err(ToolFailure::Input(format!(
                        "drive write returned an unexpected response: {other:?}"
                    ))),
                }
            }
            "mvm.drive.files.list" => {
                let args = parse_arguments::<DriveListArgs>(arguments)?;
                let result = self
                    .drive()?
                    .file(DriveFileOperation::List {
                        path: args.path,
                        follow_symlinks: args.follow_symlinks,
                    })
                    .map_err(ToolFailure::Drive)?;
                match result {
                    FsResult::List { entries, truncated } => {
                        Ok(json!({"entries": entries, "truncated": truncated}))
                    }
                    other => Err(ToolFailure::Input(format!(
                        "drive list returned an unexpected response: {other:?}"
                    ))),
                }
            }
            _ => Err(ToolFailure::Input(UNKNOWN_TOOL.into())),
        }
    }

    fn drive(&self) -> Result<&dyn DriveTools, ToolFailure> {
        self.drive
            .as_deref()
            .ok_or(ToolFailure::Drive(DriveError::NotGranted))
    }

    fn tool_success(&self, value: Value) -> Value {
        let text = match serde_json::to_string(&value) {
            Ok(text) => text,
            Err(_) => {
                return tool_error(
                    "tool output could not be serialized",
                    INTERNAL_ERROR_CODE,
                    false,
                );
            }
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
            tool_error(
                "tool output exceeds configured limit",
                OUTPUT_TOO_LARGE_ERROR_CODE,
                false,
            )
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

fn server_meta_object() -> Map<String, Value> {
    let mut meta = Map::new();
    meta.insert(
        "io.modelcontextprotocol/serverInfo".to_string(),
        json!({"name":"mvm", "version":env!("CARGO_PKG_VERSION")}),
    );
    meta
}

fn server_meta() -> Value {
    Value::Object(server_meta_object())
}

fn tools_result(operations: &ClientOperationCapabilities, drive_granted: bool) -> Value {
    let tools: Vec<Value> = tool_catalog()
        .iter()
        .filter(|tool| tool.offered(operations, drive_granted))
        .map(ToolSpec::to_value)
        .collect();
    json!({
        "resultType":"complete",
        "tools":tools,
        "ttlMs":CATALOG_TTL_MS,
        "cacheScope":"private",
        "_meta":server_meta()
    })
}

fn tool_enabled(name: &str, operations: &ClientOperationCapabilities, drive_granted: bool) -> bool {
    tool_catalog()
        .iter()
        .any(|tool| tool.name == name && tool.offered(operations, drive_granted))
}

/// Which client operation must be served before a tool is advertised.
type OperationGate = fn(&ClientOperationCapabilities) -> bool;

/// One agent-facing tool. The advertisement and the gate that decides whether
/// it is offered live in the same row, so a tool cannot be described without
/// saying what enables it.
struct ToolSpec {
    name: &'static str,
    description: &'static str,
    gate: ToolGate,
    input_schema: Value,
}

/// What must hold before a tool is advertised or callable.
#[derive(Clone, Copy)]
enum ToolGate {
    /// Offered by every client.
    Always,
    /// Offered when the client serves this operation.
    Operation(OperationGate),
    /// Offered only when this server is bound to a machine whose signed plan
    /// grants drive access. Without the grant the tool is not listed at all.
    DriveGrant,
}

impl ToolSpec {
    fn always(name: &'static str, description: &'static str, input_schema: Value) -> Self {
        Self {
            name,
            description,
            gate: ToolGate::Always,
            input_schema,
        }
    }

    fn gated(
        name: &'static str,
        description: &'static str,
        requires: OperationGate,
        input_schema: Value,
    ) -> Self {
        Self {
            name,
            description,
            gate: ToolGate::Operation(requires),
            input_schema,
        }
    }

    fn drive(name: &'static str, description: &'static str, input_schema: Value) -> Self {
        Self {
            name,
            description,
            gate: ToolGate::DriveGrant,
            input_schema,
        }
    }

    /// Whether this tool is advertised and callable. A tool the risk table
    /// does not classify is never offered, whatever its gate says.
    fn offered(&self, operations: &ClientOperationCapabilities, drive_granted: bool) -> bool {
        tool_risk(self.name).is_some()
            && match self.gate {
                ToolGate::Always => true,
                ToolGate::Operation(gate) => gate(operations),
                ToolGate::DriveGrant => drive_granted,
            }
    }

    fn to_value(&self) -> Value {
        json!({"name":self.name, "description":self.description, "inputSchema":self.input_schema})
    }
}

/// Explicit risk classification. Absence is deny: a newly specified tool is
/// neither advertised nor callable until this table names its posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolRisk {
    ReadOnly,
    Mutating,
    Interactive,
}

fn tool_risk(name: &str) -> Option<ToolRisk> {
    match name {
        "mvm.backend_capabilities"
        | "mvm.machine.list"
        | "mvm.machine.inspect"
        | "mvm.machine.logs"
        | "mvm.drive.events"
        | "mvm.drive.files.read"
        | "mvm.drive.files.list" => Some(ToolRisk::ReadOnly),
        "mvm.machine.create"
        | "mvm.machine.run"
        | "mvm.machine.start"
        | "mvm.machine.stop"
        | "mvm.machine.pause"
        | "mvm.machine.resume"
        | "mvm.machine.remove"
        | "mvm.machine.reconfigure"
        | "mvm.machine.set_ttl"
        | "mvm.drive.files.write" => Some(ToolRisk::Mutating),
        "mvm.machine.exec" | "mvm.drive.open" | "mvm.drive.write" => Some(ToolRisk::Interactive),
        _ => None,
    }
}

fn tool_catalog() -> &'static [ToolSpec] {
    static CATALOG: OnceLock<Vec<ToolSpec>> = OnceLock::new();
    CATALOG.get_or_init(build_tool_catalog)
}

fn build_tool_catalog() -> Vec<ToolSpec> {
    vec![
        ToolSpec::always(
            "mvm.backend_capabilities",
            "Describe the selected backend and client operation surface.",
            empty_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.list",
            "List machines visible through the selected client.",
            |ops| ops.list,
            object_schema(
                json!({"name":{"type":"string"}, "status":{"type":"string","enum":["starting","running","stopped","paused","failed"]}}),
                &[],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.inspect",
            "Inspect one machine.",
            |ops| ops.inspect,
            id_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.create",
            "Create a stopped machine through MvmClient.",
            |ops| ops.create,
            launch_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.run",
            "Create and start a machine through MvmClient.",
            |ops| ops.run,
            launch_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.start",
            "Start a created machine.",
            |ops| ops.start,
            id_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.stop",
            "Stop a machine idempotently.",
            |ops| ops.stop,
            id_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.pause",
            "Pause a running machine.",
            |ops| ops.pause,
            object_schema(
                json!({"id":{"type":"string"},"primed_barrier":{"type":"boolean"},"primed_timeout_secs":{"type":"integer","minimum":1}}),
                &["id"],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.resume",
            "Resume a paused machine.",
            |ops| ops.resume,
            object_schema(
                json!({"id":{"type":"string"},"warm":{"type":"boolean"}}),
                &["id"],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.remove",
            "Remove a machine idempotently.",
            |ops| ops.remove,
            id_schema(),
        ),
        ToolSpec::gated(
            "mvm.machine.logs",
            "Read bounded machine logs.",
            |ops| ops.logs,
            object_schema(
                json!({"id":{"type":"string"},"follow":{"type":"boolean"},"tail_lines":{"type":"integer","minimum":0}}),
                &["id"],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.exec",
            "Run a non-interactive command when the selected client supports it.",
            |ops| ops.exec,
            object_schema(
                json!({"id":{"type":"string"},"command":{"type":"array","items":{"type":"string"},"minItems":1}}),
                &["id", "command"],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.reconfigure",
            "Patch supported machine configuration fields.",
            |ops| ops.reconfigure,
            object_schema(
                json!({"id":{"type":"string"},"net":{"type":"boolean"},"allow_host":{"type":"array","items":{"type":"string"}},"cpus":{"type":"integer","minimum":1},"memory_mib":{"type":"integer","minimum":1}}),
                &["id"],
            ),
        ),
        ToolSpec::gated(
            "mvm.machine.set_ttl",
            "Set or clear a machine TTL.",
            |ops| ops.set_ttl,
            object_schema(
                json!({"id":{"type":"string"},"expires_at":{"type":["string","null"]}}),
                &["id"],
            ),
        ),
        ToolSpec::drive(
            "mvm.drive.open",
            "Start the program selected by the signed drive grant.",
            object_schema(json!({"cwd":{"type":"string"}}), &["cwd"]),
        ),
        ToolSpec::drive(
            "mvm.drive.write",
            "Write one ordered base64 input frame to the driven program.",
            object_schema(
                json!({"seq":{"type":"integer","minimum":0},"data_b64":{"type":"string"},"eof":{"type":"boolean"}}),
                &["seq", "data_b64"],
            ),
        ),
        ToolSpec::drive(
            "mvm.drive.events",
            "Read the next queued event from the driven program without waiting.",
            empty_schema(),
        ),
        ToolSpec::drive(
            "mvm.drive.files.read",
            "Read bounded bytes from a path inside the granted workspace roots.",
            object_schema(
                json!({"path":{"type":"string"},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":0},"follow_symlinks":{"type":"boolean"}}),
                &["path", "length"],
            ),
        ),
        ToolSpec::drive(
            "mvm.drive.files.write",
            "Write bounded base64 bytes inside the granted workspace roots.",
            object_schema(
                json!({"path":{"type":"string"},"data_b64":{"type":"string"},"mode":{"type":"integer","minimum":0,"maximum":4095},"create_parents":{"type":"boolean"},"follow_symlinks":{"type":"boolean"},"offset":{"type":"integer","minimum":0},"truncate":{"type":"boolean"}}),
                &["path", "data_b64"],
            ),
        ),
        ToolSpec::drive(
            "mvm.drive.files.list",
            "List a directory inside the granted workspace roots.",
            object_schema(
                json!({"path":{"type":"string"},"follow_symlinks":{"type":"boolean"}}),
                &["path"],
            ),
        ),
    ]
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

/// Why capability discovery failed, kept typed long enough to classify the
/// JSON-RPC error's `data` field the same way a tool result's `_meta` is
/// classified — capability discovery is not itself a tool call, so it
/// surfaces as a protocol-level error rather than an `isError` tool result,
/// but a caller deciding whether to retry needs the same `code`/`retryable`
/// pair either way.
#[derive(Debug)]
enum CapabilitiesFailure {
    Backend(MvmError),
    /// The `OnceLock` slot came back empty immediately after a successful
    /// `set` — an invariant violation in this process, not a backend
    /// condition, so it gets the generic internal code rather than any
    /// `MvmError` variant's.
    Internal(&'static str),
}

impl CapabilitiesFailure {
    /// A fixed message: the backend's own error text can carry internal
    /// detail, and the caller already gets its classification in `data`.
    fn message(&self) -> &'static str {
        match self {
            Self::Backend(_) => "client capability discovery failed",
            Self::Internal(message) => message,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Backend(error) => error.code(),
            Self::Internal(_) => INTERNAL_ERROR_CODE,
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Backend(error) => error.retryable(),
            Self::Internal(_) => false,
        }
    }
}

/// A JSON-RPC protocol error carrying the same `code`/`retryable`
/// classification a tool result's `_meta` carries, in the `data` field
/// JSON-RPC 2.0 reserves for exactly this: implementation-defined detail
/// alongside the standard `code`/`message`.
fn response_error_classified(id: Value, code: i64, failure: &CapabilitiesFailure) -> String {
    serde_json::to_string(&json!({
        "jsonrpc":"2.0",
        "id":id,
        "error":{
            "code":code,
            "message":failure.message(),
            "data":{"code":failure.code(), "retryable":failure.retryable()}
        }
    }))
    .expect("JSON-RPC error values are serializable")
}

/// The `code` a tool error carries when it did not originate from an
/// [`MvmError`] (bad tool arguments, an unknown tool name). It is deliberately
/// generic and non-retryable: these are properties of the request the caller
/// sent, not of backend state, so retrying unchanged can never help.
const GENERIC_INPUT_ERROR_CODE: &str = "INVALID_INPUT";
/// The tool server's own output pipeline failed (serialization) rather than
/// the backend or the caller's request.
const INTERNAL_ERROR_CODE: &str = "INTERNAL";
/// A successful result exceeded the server's configured output-size limit.
const OUTPUT_TOO_LARGE_ERROR_CODE: &str = "OUTPUT_TOO_LARGE";

/// Build a failed tool result. `_meta` always carries a stable, machine-
/// readable `code` and a `retryable` flag alongside the existing server
/// keys, so an automated caller can branch on the failure instead of parsing
/// the message text. The one builder every failed tool result goes through.
fn tool_error(message: &str, code: &str, retryable: bool) -> Value {
    let message: String = message.chars().take(512).collect();
    let mut meta = server_meta_object();
    meta.insert("code".to_string(), json!(code));
    meta.insert("retryable".to_string(), json!(retryable));
    json!({
        "resultType":"complete",
        "content":[{"type":"text", "text":message}],
        "isError":true,
        "_meta":Value::Object(meta)
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
    /// Rejected before any client call — bad tool arguments, an unknown
    /// tool, or an argument the client trait cannot express. Not an
    /// [`MvmError`], so it carries no variant to classify.
    Input(String),
    /// The typed facade error, carried through rather than stringified here,
    /// so the dispatch site can still classify it by variant when building
    /// the tool result's `_meta`.
    Backend(MvmError),
    /// The client call succeeded but this server could not turn its result
    /// into JSON: a fault in the tool server, not the backend.
    Internal(&'static str),
    /// The shared local drive controller refused or failed the operation.
    Drive(DriveError),
}

impl ToolFailure {
    fn backend(error: MvmError) -> Self {
        Self::Backend(error)
    }

    fn serialization(_: impl std::fmt::Display) -> Self {
        Self::Internal("MvmClient result could not be serialized")
    }

    /// The failed tool result for this failure. A backend failure keeps the
    /// backend's own message, which is often what the caller needs (which
    /// machine was not found), capped by [`tool_error`] like every other.
    fn into_tool_result(self) -> Value {
        match self {
            Self::Input(message) => tool_error(&message, GENERIC_INPUT_ERROR_CODE, false),
            Self::Backend(error) => {
                let message = format!("MvmClient operation failed: {error}");
                tool_error(&message, error.code(), error.retryable())
            }
            Self::Internal(message) => tool_error(message, INTERNAL_ERROR_CODE, false),
            Self::Drive(error) => {
                let message = format!("drive operation failed: {error}");
                tool_error(&message, error.code(), error.retryable())
            }
        }
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveOpenArgs {
    cwd: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveWriteArgs {
    seq: u64,
    data_b64: String,
    #[serde(default)]
    eof: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveReadArgs {
    path: String,
    #[serde(default)]
    offset: Option<u64>,
    length: u64,
    #[serde(default = "default_true")]
    follow_symlinks: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveFileWriteArgs {
    path: String,
    data_b64: String,
    #[serde(default = "default_file_mode")]
    mode: u32,
    #[serde(default)]
    create_parents: bool,
    #[serde(default)]
    follow_symlinks: bool,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default = "default_true")]
    truncate: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveListArgs {
    path: String,
    #[serde(default = "default_true")]
    follow_symlinks: bool,
}

fn default_true() -> bool {
    true
}

fn default_file_mode() -> u32 {
    0o644
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mvm_client::mock::MockBackend;

    use super::*;

    /// Every field of `ClientOperationCapabilities`, read off its wire form so
    /// a new operation is picked up without this list being edited.
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

    #[test]
    fn every_specified_tool_is_offered_by_a_real_gate() {
        let keys = operation_keys();
        let serving_all = operations_serving(&keys);
        let serving_none = ClientOperationCapabilities::default();
        let mut names = BTreeSet::new();

        for tool in tool_catalog() {
            assert!(
                names.insert(tool.name),
                "`{}` is specified twice in the MCP tool catalog",
                tool.name
            );
            assert!(
                tool_enabled(tool.name, &serving_all, true),
                "`{}` is specified but no client ever offers it: its gate must read a \
                 `ClientOperationCapabilities` field, or the tool must be `ToolSpec::always`",
                tool.name
            );
            assert!(
                tool_risk(tool.name).is_some(),
                "`{}` is specified but has no explicit risk classification",
                tool.name
            );
            match tool.gate {
                ToolGate::Always => continue,
                ToolGate::DriveGrant => {
                    assert!(
                        !tool.offered(&serving_all, false),
                        "`{}` must be absent without a drive grant",
                        tool.name
                    );
                    assert!(
                        tool.offered(&serving_none, true),
                        "`{}` must be enabled by the drive grant alone",
                        tool.name
                    );
                    continue;
                }
                ToolGate::Operation(_) => {}
            }
            assert!(
                !tool.offered(&serving_none, false),
                "`{}` is declared gated but a client serving no operations still offers it; \
                 use `ToolSpec::always` if that is the intent",
                tool.name
            );
            let enabling: Vec<&String> = keys
                .iter()
                .filter(|key| tool.offered(&operations_serving(std::slice::from_ref(*key)), false))
                .collect();
            assert_eq!(
                enabling.len(),
                1,
                "`{}` must be gated by exactly one client operation, but is offered by {enabling:?}",
                tool.name
            );
        }

        assert!(
            !tool_enabled("mvm.machine.unspecified", &serving_all, true),
            "a tool absent from the catalog must never be offered"
        );
    }

    /// A tool the risk table does not name is neither advertised nor
    /// callable, even on a server where every gate it could have is open.
    #[test]
    fn mcp_unclassified_tool_is_denied() {
        let serving_all = operations_serving(&operation_keys());
        for tool in [
            ToolSpec::always("mvm.test.unclassified", "not classified", empty_schema()),
            ToolSpec::gated(
                "mvm.test.unclassified",
                "not classified",
                |_| true,
                empty_schema(),
            ),
            ToolSpec::drive("mvm.test.unclassified", "not classified", empty_schema()),
        ] {
            assert!(tool_risk(tool.name).is_none());
            assert!(
                !tool.offered(&serving_all, true),
                "an unclassified tool was offered through its gate"
            );
        }
    }

    fn advertised_names(result: &Value) -> BTreeSet<String> {
        result["tools"]
            .as_array()
            .expect("tool list")
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect()
    }

    /// With every client operation served, the drive tools are listed and
    /// callable exactly when the server holds a drive grant.
    #[test]
    fn mcp_tool_absent_when_grant_absent() {
        let serving_all = operations_serving(&operation_keys());
        let drive_tools: BTreeSet<String> = tool_catalog()
            .iter()
            .filter(|tool| matches!(tool.gate, ToolGate::DriveGrant))
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(
            drive_tools,
            [
                "mvm.drive.events",
                "mvm.drive.files.list",
                "mvm.drive.files.read",
                "mvm.drive.files.write",
                "mvm.drive.open",
                "mvm.drive.write",
            ]
            .map(str::to_string)
            .into(),
        );

        let ungranted = advertised_names(&tools_result(&serving_all, false));
        assert!(
            ungranted.is_disjoint(&drive_tools),
            "drive tools listed without a grant: {ungranted:?}"
        );
        for name in &drive_tools {
            assert!(
                !tool_enabled(name, &serving_all, false),
                "`{name}` callable"
            );
        }

        let granted = advertised_names(&tools_result(&serving_all, true));
        assert!(
            granted.is_superset(&drive_tools),
            "drive tools missing under a grant: {granted:?}"
        );
    }

    #[tokio::test]
    async fn every_specified_tool_has_a_handler() {
        let server = McpServer::new(Arc::new(MockBackend::default()));
        let report = server
            .capabilities()
            .await
            .expect("mock capability report")
            .clone();
        for tool in tool_catalog() {
            let outcome = server.call_tool(tool.name, Map::new(), &report).await;
            assert!(
                !matches!(&outcome, Err(ToolFailure::Input(message)) if message == UNKNOWN_TOOL),
                "`{}` is advertised but `call_tool` has no arm for it",
                tool.name
            );
        }
    }

    /// No client DTO can fail to serialize today, so this path is not
    /// reachable through a client double; the mapping is pinned here.
    #[test]
    fn a_serialization_failure_is_internal_and_not_retryable() {
        let result = ToolFailure::serialization("boom").into_tool_result();
        assert_eq!(result["isError"], true);
        assert_eq!(result["_meta"]["code"], "INTERNAL");
        assert_eq!(result["_meta"]["retryable"], false);
    }
}
