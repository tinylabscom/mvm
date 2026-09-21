//! Route one dotted method to the [`MvmClient`] call it names.
//!
//! Every method takes one JSON request object and answers with one JSON reply.
//! Request types refuse unknown fields, so a binding that sends a field this
//! library does not know about hears so, rather than having it silently
//! dropped.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_core::client::MvmClient;
use mvm_core::client::dto::{LogOpts, MachineFilter, MachineId};
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

/// Every method this library answers.
pub const METHODS: [&str; 7] = [
    MACHINE_LIST,
    MACHINE_INSPECT,
    MACHINE_LOGS,
    BACKEND_CAPABILITIES,
    MACHINE_STOP,
    MACHINE_RM,
    MACHINE_EXEC,
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
            client.stop_machine(&MachineId(target.id)).await?;
            Outcome::ok(&Empty {})
        }
        MACHINE_RM => {
            let target: RemoveRequest = parse(request)?;
            client.remove_machine(&MachineId(target.id)).await?;
            Outcome::ok(&Empty {})
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
    fn every_listed_method_is_known() {
        for method in METHODS {
            assert!(is_known(method), "{method}");
        }
    }
}
