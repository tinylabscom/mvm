//! Route one dotted method to the [`MvmClient`] call it names.
//!
//! Every method takes one JSON request object and answers with one JSON reply.
//! Request types refuse unknown fields, so a binding that sends a field this
//! library does not know about hears so, rather than having it silently
//! dropped.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_core::client::MvmClient;
use mvm_core::client::dto::{
    LogOpts, MachineFilter, MachineId, MachineStatus, PauseOpts, ReconfigureRequest, ResumeOpts,
};
use mvm_core::client::{TelemetryCursor, TelemetryReadOpts, TelemetryStatus};
use serde::{Deserialize, Serialize};

use crate::status::Outcome;

/// Lists machines. Request: a `MachineFilter`, or an empty body for all.
/// Reply: an array of `MachineState`.
pub const MACHINE_LIST: &str = "machine.list";
/// Inspects one machine. Request: `{"id": ...}`. Reply: a `MachineState`.
pub const MACHINE_INSPECT: &str = "machine.inspect";
/// Returns a machine's captured console output. Request: `{"id": ...,
/// "tail_lines": n?}`. Reply: `{"data_b64": ...}`.
pub const MACHINE_LOGS: &str = "machine.logs";
/// Reports what the backend can do. Request: empty. Reply: a
/// `BackendCapabilityReport`.
pub const BACKEND_CAPABILITIES: &str = "backend.capabilities";
/// Stops one machine. Request: `{"id"}`. Reply: `{}`. Idempotent.
pub const MACHINE_STOP: &str = "machine.stop";
/// Removes one machine, stopping it first when needed. Request: `{"id"}`.
/// Reply: `{}`. Idempotent.
pub const MACHINE_RM: &str = "machine.rm";
/// Runs one non-interactive command in a machine. Request: `{"id",
/// "command": [argv...]}`. Reply: an `ExecResult`.
pub const MACHINE_EXEC: &str = "machine.exec";
/// Boots a persisted machine definition. Request: `{"id"}`. Reply: a
/// `MachineState`. A machine already running is reported, not rebooted.
pub const MACHINE_START: &str = "machine.start";
/// Lists every machine on this host — persisted definitions joined with live
/// ones — with each one's fail-closed `build_mode`. Request: empty. Reply: an
/// array of inventory records.
pub const MACHINE_INVENTORY: &str = "machine.inventory";
/// Pauses a running machine, sealing a snapshot where the backend uses one.
/// Request: `{"id", "primed_barrier"?, "primed_timeout_secs"?}`. Reply: a
/// `PauseOutcome`.
pub const MACHINE_PAUSE: &str = "machine.pause";
/// Resumes a paused machine, refusing a replayed snapshot. Request: `{"id",
/// "warm"?}`. Reply: a `ResumeOutcome`.
pub const MACHINE_RESUME: &str = "machine.resume";
/// Patches a persisted machine's resources and relaunches it when running.
/// Request: `{"id", "net"?, "allow_host"?, "cpus"?, "memory_mib"?}`; an absent
/// field is left unchanged. Reply: a `MachineState`.
pub const MACHINE_RECONFIGURE: &str = "machine.reconfigure";
/// Sets or clears the time the idle reaper removes a machine at. Request:
/// `{"id", "expires_at": rfc3339 | null}`. Reply: `{}`. Errors when the
/// machine is not registered.
pub const MACHINE_SET_TTL: &str = "machine.set_ttl";
/// Reports where host-side telemetry collection stands for a machine.
/// Request: `{"id"}`. Reply: a `TelemetryStatus` — `coverage` is
/// `not_provisioned` for a boot nobody asked to observe, never an error.
pub const TELEMETRY_STATUS: &str = "telemetry.status";
/// Reads one page of the telemetry records collected for a machine.
/// Request: `{"id", "after"?: cursor, "limit"?: n}`. Reply: `{"records":
/// [...], "next": cursor, "more": bool}`; each record is one
/// `mvm.telemetry.v1` record exactly as the collector persisted it. Pass
/// `next` back as `after` to continue; a cursor from before the machine's
/// stream was reset is refused as `REJECTED`.
pub const TELEMETRY_RECORDS: &str = "telemetry.records";

/// Every method this library answers through the client.
pub const METHODS: [&str; 15] = [
    MACHINE_LIST,
    MACHINE_INSPECT,
    MACHINE_LOGS,
    BACKEND_CAPABILITIES,
    MACHINE_STOP,
    MACHINE_RM,
    MACHINE_EXEC,
    MACHINE_START,
    MACHINE_INVENTORY,
    MACHINE_PAUSE,
    MACHINE_RESUME,
    MACHINE_RECONFIGURE,
    MACHINE_SET_TTL,
    TELEMETRY_STATUS,
    TELEMETRY_RECORDS,
];

/// Whether `method` is one this library answers, checked before a client is
/// built so an unknown method costs nothing.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

/// A request naming one machine.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineRef {
    id: String,
}

/// A `machine.logs` request. There is no `follow`: following a log is a
/// stream, and a single call returns once.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogsRequest {
    id: String,
    #[serde(default)]
    tail_lines: Option<u32>,
}

/// A request that carries nothing.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Empty {}

/// A request naming one machine.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StopRequest {
    id: String,
}

/// A request naming one machine for removal.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveRequest {
    id: String,
}

/// A `machine.exec` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecRequest {
    id: String,
    command: Vec<String>,
}

/// A `machine.pause` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PauseRequest {
    id: String,
    /// Wait for the workload to signal that it is primed before sealing, and
    /// refuse rather than seal when it does not signal in time.
    #[serde(default)]
    primed_barrier: bool,
    /// Seconds to wait for that signal. Defaults to the client's own default.
    #[serde(default)]
    primed_timeout_secs: Option<u64>,
}

impl PauseRequest {
    /// The client options this request names, refusing a zero timeout, which
    /// could only ever fail.
    fn opts(&self) -> Result<PauseOpts, Outcome> {
        let mut opts = PauseOpts {
            primed_barrier: self.primed_barrier,
            ..PauseOpts::default()
        };
        if let Some(secs) = self.primed_timeout_secs {
            if secs == 0 {
                return Err(Outcome::invalid_input(
                    "primed_timeout_secs must be greater than zero",
                ));
            }
            opts.primed_timeout_secs = secs;
        }
        Ok(opts)
    }
}

/// A `machine.resume` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeRequest {
    id: String,
    /// Resume through the backend's live-memory warm-start path, which a
    /// disk-only backend refuses.
    #[serde(default)]
    warm: bool,
}

/// A `machine.reconfigure` request: a patch, so an absent field keeps its
/// current value.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconfigurePatchRequest {
    id: String,
    #[serde(default)]
    net: Option<bool>,
    #[serde(default)]
    allow_host: Option<Vec<String>>,
    #[serde(default)]
    cpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u32>,
}

impl ReconfigurePatchRequest {
    /// The machine and the client patch, refusing a zero CPU count or memory
    /// size before anything is persisted.
    fn into_parts(self) -> Result<(MachineId, ReconfigureRequest), Outcome> {
        if self.cpus == Some(0) || self.memory_mib == Some(0) {
            return Err(Outcome::invalid_input(
                "cpus and memory_mib must be greater than zero",
            ));
        }
        Ok((
            MachineId(self.id),
            ReconfigureRequest {
                net: self.net,
                allow_host: self.allow_host,
                cpus: self.cpus,
                memory_mib: self.memory_mib,
            },
        ))
    }
}

/// A `machine.set_ttl` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetTtlRequest {
    id: String,
    /// When the reaper may remove the machine, as RFC 3339. `null` clears it.
    #[serde(default)]
    expires_at: Option<String>,
}

impl SetTtlRequest {
    /// The machine and expiry, refusing a timestamp the reaper could not read.
    fn into_parts(self) -> Result<(MachineId, Option<String>), Outcome> {
        if let Some(at) = &self.expires_at
            && mvm_core::util::time::parse_iso8601(at).is_none()
        {
            return Err(Outcome::invalid_input(
                "expires_at must be an RFC 3339 timestamp or null",
            ));
        }
        Ok((MachineId(self.id), self.expires_at))
    }
}

/// A `telemetry.records` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetryRecordsRequest {
    id: String,
    /// The `next` of the previous page; absent reads from the start.
    #[serde(default)]
    after: Option<u64>,
    /// At most this many records; absent uses the client's default page size.
    #[serde(default)]
    limit: Option<u32>,
}

impl TelemetryRecordsRequest {
    fn into_parts(self) -> (MachineId, TelemetryReadOpts) {
        (
            MachineId(self.id),
            TelemetryReadOpts {
                after: self.after.map(TelemetryCursor),
                limit: self.limit,
            },
        )
    }
}

/// A `telemetry.records` reply. Records cross as the JSON the collector
/// persisted, one `mvm.telemetry.v1` record each; the shape is the record
/// contract's, not this library's, so it is not restated in the ABI schema.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct TelemetryRecordsReply {
    records: Vec<serde_json::Value>,
    next: u64,
    more: bool,
}

/// A `machine.exec` reply. Stream bytes cross as base64, because JSON
/// strings are not byte strings — the same convention as `machine.logs`
/// and every `guest.*` payload.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct ExecReply {
    exit_code: i32,
    stdout_b64: String,
    stderr_b64: String,
}

/// Console bytes, which need not be UTF-8.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct LogsReply {
    data_b64: String,
}

/// Answer `method` on `client`.
pub(crate) async fn dispatch(client: &dyn MvmClient, method: &str, request: &[u8]) -> Outcome {
    match answer(client, method, request).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

async fn answer(client: &dyn MvmClient, method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    Ok(match method {
        MACHINE_LIST => {
            let filter: MachineFilter = parse_or_default(request)?;
            Outcome::ok(&client.list_machines(filter).await?)
        }
        MACHINE_INSPECT => {
            let target: MachineRef = parse(request)?;
            Outcome::ok(&client.inspect_machine(&MachineId(target.id)).await?)
        }
        MACHINE_LOGS => {
            let target: LogsRequest = parse(request)?;
            let opts = LogOpts {
                follow: false,
                tail_lines: target.tail_lines,
            };
            let bytes = client.machine_logs(&MachineId(target.id), opts).await?;
            Outcome::ok(&LogsReply {
                data_b64: B64.encode(bytes),
            })
        }
        BACKEND_CAPABILITIES => {
            let _: Empty = parse_or_default_empty(request)?;
            Outcome::ok(&client.backend_capabilities().await?)
        }
        MACHINE_STOP => {
            let target: StopRequest = parse(request)?;
            client.stop_machine(&MachineId(target.id.clone())).await?;
            crate::approval::remove_server(&target.id);
            Outcome::ok(&Empty {})
        }
        MACHINE_RM => {
            let target: RemoveRequest = parse(request)?;
            client.remove_machine(&MachineId(target.id.clone())).await?;
            crate::approval::remove_server(&target.id);
            Outcome::ok(&Empty {})
        }
        MACHINE_START => {
            let target: MachineRef = parse(request)?;
            let machine = client.start_machine(&MachineId(target.id)).await?;
            crate::approval::ensure_server(&machine.name);
            Outcome::ok(&machine)
        }
        MACHINE_INVENTORY => {
            let _: Empty = parse_or_default_empty(request)?;
            Outcome::ok(&mvm_client::inventory::list_local_inventory(client).await?)
        }
        MACHINE_PAUSE => {
            let target: PauseRequest = parse(request)?;
            let opts = target.opts()?;
            Outcome::ok(&client.pause_machine(&MachineId(target.id), opts).await?)
        }
        MACHINE_RESUME => {
            let target: ResumeRequest = parse(request)?;
            let opts = ResumeOpts { warm: target.warm };
            Outcome::ok(&client.resume_machine(&MachineId(target.id), opts).await?)
        }
        MACHINE_RECONFIGURE => {
            let (id, patch) = parse::<ReconfigurePatchRequest>(request)?.into_parts()?;
            let machine = client.reconfigure_machine(&id, patch).await?;
            if machine.status == MachineStatus::Running {
                // A relaunch is a start, and keeps the broker a start keeps.
                crate::approval::ensure_server(&machine.name);
            }
            Outcome::ok(&machine)
        }
        MACHINE_SET_TTL => {
            let (id, expires_at) = parse::<SetTtlRequest>(request)?.into_parts()?;
            client.set_ttl(&id, expires_at).await?;
            Outcome::ok(&Empty {})
        }
        TELEMETRY_STATUS => {
            let target: MachineRef = parse(request)?;
            let status: TelemetryStatus = client.telemetry_status(&MachineId(target.id)).await?;
            Outcome::ok(&status)
        }
        TELEMETRY_RECORDS => {
            let (id, opts) = parse::<TelemetryRecordsRequest>(request)?.into_parts();
            let page = client.telemetry_records(&id, opts).await?;
            let records = page
                .records
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Outcome::invalid_input(&format!("record did not serialize: {e}")))?;
            Outcome::ok(&TelemetryRecordsReply {
                records,
                next: page.next.0,
                more: page.more,
            })
        }
        MACHINE_EXEC => {
            let target: ExecRequest = parse(request)?;
            if target.command.is_empty() {
                return Err(Outcome::invalid_input("command must not be empty"));
            }
            let result = client
                .exec_machine(&MachineId(target.id), target.command)
                .await?;
            Outcome::ok(&ExecReply {
                exit_code: result.exit_code,
                stdout_b64: B64.encode(result.stdout),
                stderr_b64: B64.encode(result.stderr),
            })
        }
        other => return Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    })
}

/// Parse `request` as `T`.
fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|e| Outcome::invalid_input(&format!("request did not parse: {e}")))
}

/// Parse `request` as `T`, reading an empty body as `T::default()`.
fn parse_or_default<T: serde::de::DeserializeOwned + Default>(
    request: &[u8],
) -> Result<T, Outcome> {
    if request.is_empty() {
        return Ok(T::default());
    }
    parse(request)
}

/// Parse a request that must carry nothing: an empty body or `{}`.
fn parse_or_default_empty(request: &[u8]) -> Result<Empty, Outcome> {
    if request.is_empty() {
        return Ok(Empty {});
    }
    parse(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_NOT_FOUND, MVM_HOSTLIB_OK};
    use mvm_core::client::dto::{MachineSpec, MachineState};
    use mvm_core::client::mock::MockBackend;

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn with_machine(name: &str) -> (MockBackend, MachineState) {
        let client = MockBackend::default();
        let spec = MachineSpec::builder(name, "oci:alpine:3.20")
            .expect("image parses")
            .build();
        let state = run(client.run_machine(spec)).expect("mock runs it");
        (client, state)
    }

    fn body(outcome: &Outcome) -> serde_json::Value {
        serde_json::from_slice(&outcome.body).expect("body is JSON")
    }

    #[test]
    fn machine_list_answers_every_machine_for_an_empty_request() {
        let (client, state) = with_machine("alpha");
        let outcome = run(dispatch(&client, MACHINE_LIST, b""));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let listed: Vec<MachineState> = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(listed, vec![state]);
    }

    #[test]
    fn machine_list_applies_the_filter() {
        let (client, _) = with_machine("alpha");
        let outcome = run(dispatch(&client, MACHINE_LIST, br#"{"name":"beta"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome), serde_json::json!([]));
    }

    #[test]
    fn machine_inspect_answers_the_named_machine() {
        let (client, state) = with_machine("alpha");
        let request = serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_INSPECT, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let inspected: MachineState = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(inspected, state);
    }

    /// A client error reaches the binding as the client's own code.
    #[test]
    fn inspecting_an_absent_machine_is_not_found() {
        let client = MockBackend::default();
        let outcome = run(dispatch(&client, MACHINE_INSPECT, br#"{"id":"nope"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
        assert_eq!(body(&outcome)["code"], "NOT_FOUND");
        assert_eq!(body(&outcome)["retryable"], false);
    }

    #[test]
    fn machine_logs_are_returned_as_base64() {
        let (client, state) = with_machine("alpha");
        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "tail_lines": 10 })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_LOGS, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome), serde_json::json!({ "data_b64": "" }));
    }

    /// Following a log is a stream, which one call cannot return.
    #[test]
    fn machine_logs_refuses_follow() {
        let (client, state) = with_machine("alpha");
        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "follow": true })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_LOGS, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn backend_capabilities_accepts_an_empty_request_and_nothing_else() {
        let client = MockBackend::default();
        for request in [&b""[..], b"{}"] {
            let outcome = run(dispatch(&client, BACKEND_CAPABILITIES, request));
            assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{request:?}");
        }
        let outcome = run(dispatch(&client, BACKEND_CAPABILITIES, br#"{"x":1}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    /// A field this library does not know is refused, not dropped.
    #[test]
    fn an_unknown_request_field_is_refused() {
        let client = MockBackend::default();
        let outcome = run(dispatch(
            &client,
            MACHINE_INSPECT,
            br#"{"id":"m","extra":true}"#,
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        assert_eq!(body(&outcome)["code"], "INVALID_INPUT");
    }

    #[test]
    fn an_unknown_method_is_refused() {
        let client = MockBackend::default();
        assert!(!is_known("machine.shell"));
        let outcome = run(dispatch(&client, "machine.shell", b"{}"));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn machine_stop_stops_the_named_machine() {
        let (client, state) = with_machine("alpha");
        let request = serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_STOP, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome), serde_json::json!({}));
        let outcome = run(dispatch(&client, MACHINE_INSPECT, &request));
        assert_eq!(body(&outcome)["status"], "stopped");
        // An absent machine is the mock's `NotFound`; the real backend's
        // contract is idempotent, and both reach the binding as a typed error.
        let outcome = run(dispatch(&client, MACHINE_STOP, br#"{"id":"ghost"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
    }

    #[test]
    fn machine_rm_removes_the_named_machine() {
        let (client, state) = with_machine("alpha");
        let request = serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_RM, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let listed: Vec<MachineState> =
            serde_json::from_slice(&run(dispatch(&client, MACHINE_LIST, b"")).body).unwrap();
        assert!(listed.is_empty(), "{listed:?}");
    }

    #[test]
    fn machine_exec_returns_the_command_result() {
        let (client, state) = with_machine("alpha");
        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "command": ["true"] }))
                .unwrap();
        let outcome = run(dispatch(&client, MACHINE_EXEC, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome)["exit_code"], 0);
        assert_eq!(body(&outcome)["stdout_b64"], "");
    }

    #[test]
    fn machine_exec_refuses_an_empty_command() {
        let (client, state) = with_machine("alpha");
        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "command": [] })).unwrap();
        let outcome = run(dispatch(&client, MACHINE_EXEC, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn machine_start_boots_the_named_machine() {
        let (client, state) = with_machine("alpha");
        let request = serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap();
        run(dispatch(&client, MACHINE_STOP, &request));
        let outcome = run(dispatch(&client, MACHINE_START, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome)["status"], "running");
    }

    #[test]
    fn machine_start_of_an_absent_machine_is_not_found() {
        let client = MockBackend::default();
        let outcome = run(dispatch(&client, MACHINE_START, br#"{"id":"ghost"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
    }

    /// The inventory joins live machines with persisted definitions and says
    /// each one's posture, defaulting to production.
    #[test]
    fn machine_inventory_lists_live_machines_with_their_posture() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (client, _) = with_machine("alpha");
        let outcome = run(dispatch(&client, MACHINE_INVENTORY, b""));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        let records = body(&outcome);
        let alpha = records
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "alpha")
            .expect("the live machine is listed");
        assert_eq!(alpha["build_mode"], "prod");
        let outcome = run(dispatch(&client, MACHINE_INVENTORY, br#"{"all":true}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    fn named(state: &MachineState) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap()
    }

    fn with_id(state: &MachineState, fields: serde_json::Value) -> Vec<u8> {
        let mut request = fields;
        request["id"] = serde_json::Value::String(state.id.0.clone());
        serde_json::to_vec(&request).unwrap()
    }

    #[test]
    fn machine_pause_then_resume_round_trips_the_machine() {
        let (client, state) = with_machine("alpha");
        let outcome = run(dispatch(&client, MACHINE_PAUSE, &named(&state)));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert_eq!(
            body(&outcome),
            serde_json::json!({ "epoch": 0, "vmstate_len": 0, "mem_len": 0 })
        );
        let inspected = run(dispatch(&client, MACHINE_INSPECT, &named(&state)));
        assert_eq!(body(&inspected)["status"], "paused");

        let outcome = run(dispatch(
            &client,
            MACHINE_RESUME,
            &with_id(&state, serde_json::json!({ "warm": false })),
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert_eq!(body(&outcome)["epoch"], 0);
        assert_eq!(body(&outcome)["reseed"], serde_json::Value::Null);
        let inspected = run(dispatch(&client, MACHINE_INSPECT, &named(&state)));
        assert_eq!(body(&inspected)["status"], "running");
    }

    #[test]
    fn machine_pause_passes_the_primed_barrier_through() {
        let (client, state) = with_machine("alpha");
        let request = with_id(
            &state,
            serde_json::json!({ "primed_barrier": true, "primed_timeout_secs": 5 }),
        );
        let target: PauseRequest = parse(&request).unwrap();
        let opts = target.opts().unwrap();
        assert!(opts.primed_barrier);
        assert_eq!(opts.primed_timeout_secs, 5);
        let outcome = run(dispatch(&client, MACHINE_PAUSE, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
    }

    /// An omitted timeout is the client's default, not zero.
    #[test]
    fn machine_pause_defaults_the_primed_timeout() {
        let target: PauseRequest = parse(br#"{"id":"m","primed_barrier":true}"#).unwrap();
        assert_eq!(
            target.opts().unwrap().primed_timeout_secs,
            PauseOpts::default().primed_timeout_secs
        );
    }

    /// A zero wait could only fail, so it is refused before the client is asked.
    #[test]
    fn machine_pause_refuses_a_zero_primed_timeout() {
        let (client, state) = with_machine("alpha");
        let request = with_id(&state, serde_json::json!({ "primed_timeout_secs": 0 }));
        let outcome = run(dispatch(&client, MACHINE_PAUSE, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        let inspected = run(dispatch(&client, MACHINE_INSPECT, &named(&state)));
        assert_eq!(body(&inspected)["status"], "running");
    }

    #[test]
    fn machine_pause_and_resume_of_an_absent_machine_are_not_found() {
        let client = MockBackend::default();
        for method in [MACHINE_PAUSE, MACHINE_RESUME] {
            let outcome = run(dispatch(&client, method, br#"{"id":"ghost"}"#));
            assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND, "{method}");
        }
    }

    #[test]
    fn machine_resume_refuses_an_unknown_field() {
        let (client, state) = with_machine("alpha");
        let request = with_id(&state, serde_json::json!({ "epoch": 3 }));
        let outcome = run(dispatch(&client, MACHINE_RESUME, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn machine_reconfigure_answers_the_machine_state() {
        let (client, state) = with_machine("alpha");
        let request = with_id(&state, serde_json::json!({ "cpus": 2, "memory_mib": 512 }));
        let outcome = run(dispatch(&client, MACHINE_RECONFIGURE, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        let reconfigured: MachineState = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(reconfigured.id, state.id);
    }

    #[test]
    fn machine_reconfigure_carries_every_patch_field() {
        let request =
            br#"{"id":"m","net":true,"allow_host":["example.com"],"cpus":2,"memory_mib":256}"#;
        let (id, patch) = parse::<ReconfigurePatchRequest>(request)
            .unwrap()
            .into_parts()
            .unwrap();
        assert_eq!(id, MachineId("m".into()));
        assert_eq!(
            patch,
            ReconfigureRequest {
                net: Some(true),
                allow_host: Some(vec!["example.com".into()]),
                cpus: Some(2),
                memory_mib: Some(256),
            }
        );
        let (_, empty) = parse::<ReconfigurePatchRequest>(br#"{"id":"m"}"#)
            .unwrap()
            .into_parts()
            .unwrap();
        assert_eq!(empty, ReconfigureRequest::default());
    }

    #[test]
    fn machine_reconfigure_refuses_zero_resources() {
        let (client, state) = with_machine("alpha");
        for fields in [
            serde_json::json!({ "cpus": 0 }),
            serde_json::json!({ "memory_mib": 0 }),
        ] {
            let outcome = run(dispatch(
                &client,
                MACHINE_RECONFIGURE,
                &with_id(&state, fields.clone()),
            ));
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT, "{fields}");
        }
        let outcome = run(dispatch(&client, MACHINE_RECONFIGURE, br#"{"id":"ghost"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
    }

    #[test]
    fn machine_set_ttl_arms_and_clears_the_expiry() {
        let (client, state) = with_machine("alpha");
        let at = "2030-01-02T03:04:05Z";
        let outcome = run(dispatch(
            &client,
            MACHINE_SET_TTL,
            &with_id(&state, serde_json::json!({ "expires_at": at })),
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert_eq!(body(&outcome), serde_json::json!({}));
        let inspected = run(dispatch(&client, MACHINE_INSPECT, &named(&state)));
        assert_eq!(body(&inspected)["expires_at"], at);

        let outcome = run(dispatch(
            &client,
            MACHINE_SET_TTL,
            &with_id(&state, serde_json::json!({ "expires_at": null })),
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let inspected: MachineState =
            serde_json::from_slice(&run(dispatch(&client, MACHINE_INSPECT, &named(&state))).body)
                .unwrap();
        assert_eq!(inspected.expires_at, None);
    }

    /// A timestamp the reaper could not parse would arm nothing; refuse it.
    #[test]
    fn machine_set_ttl_refuses_a_timestamp_that_is_not_rfc3339() {
        let (client, state) = with_machine("alpha");
        let outcome = run(dispatch(
            &client,
            MACHINE_SET_TTL,
            &with_id(&state, serde_json::json!({ "expires_at": "in an hour" })),
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        let outcome = run(dispatch(
            &client,
            MACHINE_SET_TTL,
            br#"{"id":"ghost","expires_at":"2030-01-02T03:04:05Z"}"#,
        ));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
    }

    fn telemetry_record(sequence: u64) -> mvm_core::protocol::telemetry::TelemetryRecord {
        use mvm_core::protocol::telemetry::{
            Attributes, Level, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
        };
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([5; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: "tick".try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn telemetry_status_answers_the_typed_coverage() {
        let (client, state) = with_machine("alpha");
        let request = serde_json::to_vec(&serde_json::json!({ "id": state.id.0 })).unwrap();
        let outcome = run(dispatch(&client, TELEMETRY_STATUS, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(
            body(&outcome),
            serde_json::json!({ "coverage": { "state": "not_provisioned" }, "shed": 0 })
        );

        client.set_telemetry_status(
            &state.id,
            TelemetryStatus {
                coverage: mvm_core::client::TelemetryCoverage::Degraded {
                    code: "auth_failed".into(),
                },
                shed: 3,
            },
        );
        let outcome = run(dispatch(&client, TELEMETRY_STATUS, &request));
        assert_eq!(
            body(&outcome),
            serde_json::json!({ "coverage": { "state": "degraded", "code": "auth_failed" }, "shed": 3 })
        );

        let outcome = run(dispatch(&client, TELEMETRY_STATUS, br#"{"id":"ghost"}"#));
        assert_eq!(outcome.status, MVM_HOSTLIB_NOT_FOUND);
    }

    #[test]
    fn telemetry_records_page_as_the_collector_wrote_them() {
        let (client, state) = with_machine("alpha");
        client.push_telemetry_records(&state.id, (1..=3).map(telemetry_record));

        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "limit": 2 })).unwrap();
        let outcome = run(dispatch(&client, TELEMETRY_RECORDS, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let page = body(&outcome);
        assert_eq!(page["records"].as_array().unwrap().len(), 2);
        assert_eq!(
            page["records"][0],
            serde_json::to_value(telemetry_record(1)).unwrap()
        );
        assert_eq!(page["next"], 2);
        assert_eq!(page["more"], true);

        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "after": 2 })).unwrap();
        let outcome = run(dispatch(&client, TELEMETRY_RECORDS, &request));
        let page = body(&outcome);
        assert_eq!(page["records"].as_array().unwrap().len(), 1);
        assert_eq!(page["more"], false);

        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "after": 99 })).unwrap();
        let outcome = run(dispatch(&client, TELEMETRY_RECORDS, &request));
        assert_eq!(body(&outcome)["code"], "REJECTED");

        let request =
            serde_json::to_vec(&serde_json::json!({ "id": state.id.0, "follow": true })).unwrap();
        let outcome = run(dispatch(&client, TELEMETRY_RECORDS, &request));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn every_listed_method_is_known() {
        for method in METHODS {
            assert!(is_known(method), "{method}");
        }
    }
}
