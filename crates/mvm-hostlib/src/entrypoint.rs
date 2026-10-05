//! `entrypoint.call`, `session.*` and `machine.prompt`: calling a workload's
//! baked entrypoint, in a transient microVM, a warm session, or — as a prompt
//! for its resident agent — a running machine.
//!
//! Every method goes through `mvm_client::entrypoint`, the implementation
//! `mvmctl machine run --entrypoint` and `mvmctl machine session …` use, so a
//! call made from a language SDK is admitted under a signed plan and audited
//! exactly as one made from the CLI. `RunEntrypoint` is a ProdSafe agent verb:
//! a sealed image serves it, and it runs only the program the image names.
//!
//! A workload is named by the id it was declared with (resolved to the built
//! slot whose image carries that name) or by its manifest. Payloads cross as
//! base64. A transient call's payload travels in the call's own frame when it
//! fits and over the grant-gated input plane when it does not. A session was
//! admitted by the call that started it, so a session call carries only what
//! fits in one frame and refuses anything larger, naming the limit.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_agentd::vsock::RunEntrypointError;
use mvm_client::agent_prompt::{AgentPrompt, PromptOutcome};
use mvm_client::entrypoint::{
    CallLifecycle, CallOutcome, CallStdin, CallTerminal, CapturedOutput, EntrypointAdmission,
    EntrypointCall, EntrypointVm, ONE_SHOT_PAYLOAD_LIMIT, SessionStart, SessionVmName,
    WorkloadSource,
};
use mvm_core::client::MvmError;
use mvm_core::session::{SessionId, SessionMode, SessionRecord};
use serde::{Deserialize, Serialize};

use crate::status::Outcome;

/// Calls a workload's entrypoint in a transient microVM. Request: an
/// [`EntrypointCallRequest`]. Reply: an [`EntrypointCallReply`].
pub const ENTRYPOINT_CALL: &str = "entrypoint.call";
/// Boots a warm session. Request: a [`SessionStartRequest`]. Reply: a
/// [`SessionStartReply`].
pub const SESSION_START: &str = "session.start";
/// Calls the entrypoint in a running session. Request: a
/// [`SessionCallRequest`]. Reply: an [`EntrypointCallReply`].
pub const SESSION_CALL: &str = "session.call";
/// Stops a session and its microVM. Request: a [`SessionRef`]. Reply: `{}`.
pub const SESSION_STOP: &str = "session.stop";
/// Reads a session's record. Request: a [`SessionRef`]. Reply: a
/// [`SessionInfoReply`].
pub const SESSION_INFO: &str = "session.info";
/// Sends one prompt to a running machine's resident agent, granted, journaled,
/// recorded and audited exactly as `mvmctl machine prompt` does. Request: a
/// [`MachinePromptRequest`]. Reply: a [`MachinePromptReply`].
pub const MACHINE_PROMPT: &str = "machine.prompt";

/// Every entrypoint, session and prompt method.
pub const METHODS: [&str; 6] = [
    ENTRYPOINT_CALL,
    SESSION_START,
    SESSION_CALL,
    SESSION_STOP,
    SESSION_INFO,
    MACHINE_PROMPT,
];

/// A call's wall-clock kill window when the request names none — the same
/// default `mvmctl machine run --entrypoint` and `session attach` apply.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Guest memory when the request names none.
const DEFAULT_MEMORY_MIB: u32 = 512;

/// Whether `method` is one of these, checked before any backend is built.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

// ── operations ───────────────────────────────────────────────────────────

/// A resolved transient call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallSpec {
    pub(crate) slot: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) timeout_secs: u64,
    pub(crate) cpus: u32,
    pub(crate) memory_mib: u32,
}

/// A resolved session start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartSpec {
    pub(crate) slot: String,
    pub(crate) cpus: u32,
    pub(crate) memory_mib: u32,
    pub(crate) idle_timeout_secs: u64,
}

/// What one call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallResult {
    pub(crate) terminal: CallTerminal,
    pub(crate) output: CapturedOutput,
}

impl CallResult {
    fn new(outcome: CallOutcome, output: CapturedOutput) -> Self {
        Self {
            terminal: outcome.terminal,
            output,
        }
    }
}

/// The operations the methods call. One production implementation, over
/// `mvm_client::entrypoint`; the tests use a recording double, so dispatch is
/// checkable without a microVM.
pub(crate) trait EntrypointOps: Send + Sync {
    fn resolve(&self, source: WorkloadSource<'_>) -> Result<String>;
    fn call(&self, spec: CallSpec) -> Result<CallResult>;
    fn start(&self, spec: StartSpec) -> Result<SessionRecord>;
    fn session_call(
        &self,
        id: &SessionId,
        payload: Vec<u8>,
        timeout_secs: u64,
    ) -> Result<CallResult>;
    fn stop(&self, id: &SessionId) -> Result<()>;
    fn info(&self, id: &SessionId) -> Result<SessionRecord>;
    fn prompt(&self, prompt: AgentPrompt) -> Result<PromptAnswer>;
}

/// What one prompt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PromptAnswer {
    /// The prompt was delivered at this journal cursor and the agent's run
    /// ended as `result`.
    Delivered {
        journal_cursor: u64,
        result: CallResult,
    },
    /// A prompt under the same retry key was already accepted.
    Duplicate { journal_cursor: u64 },
}

/// The operations on this host.
pub(crate) struct LocalEntrypoint;

impl LocalEntrypoint {
    fn admission(cpus: u32, memory_mib: u32) -> Result<EntrypointAdmission> {
        EntrypointAdmission::builder(mvm_client::entrypoint::backend_name_for(None)?)
            .cpus(cpus)
            .mem_mib(u64::from(memory_mib))
            .build()
    }
}

impl EntrypointOps for LocalEntrypoint {
    fn resolve(&self, source: WorkloadSource<'_>) -> Result<String> {
        mvm_client::entrypoint::resolve_slot(source)
    }

    fn call(&self, spec: CallSpec) -> Result<CallResult> {
        let mut output = CapturedOutput::default();
        let outcome = mvm_client::entrypoint::run_entrypoint_call(
            EntrypointCall {
                vm: EntrypointVm {
                    slot: &spec.slot,
                    vm_name: SessionVmName::Prefixed("invoke"),
                    cpus: spec.cpus,
                    memory_mib: spec.memory_mib,
                    admission: Self::admission(spec.cpus, spec.memory_mib)?,
                },
                stdin: CallStdin::for_payload(spec.payload),
                timeout_secs: spec.timeout_secs,
                lifecycle: CallLifecycle::Transient,
            },
            None,
            &mut output,
        )?;
        Ok(CallResult::new(outcome, output))
    }

    fn start(&self, spec: StartSpec) -> Result<SessionRecord> {
        mvm_client::entrypoint::start_session(
            SessionStart {
                vm: EntrypointVm {
                    slot: &spec.slot,
                    vm_name: SessionVmName::Prefixed("session"),
                    cpus: spec.cpus,
                    memory_mib: spec.memory_mib,
                    admission: Self::admission(spec.cpus, spec.memory_mib)?,
                },
                mode: SessionMode::Prod,
                idle_timeout_secs: spec.idle_timeout_secs,
                ephemeral: false,
            },
            None,
        )
    }

    fn session_call(
        &self,
        id: &SessionId,
        payload: Vec<u8>,
        timeout_secs: u64,
    ) -> Result<CallResult> {
        let (id, record) = mvm_client::entrypoint::require_running_session(id.as_str())?;
        let mut output = CapturedOutput::default();
        let outcome =
            mvm_client::entrypoint::call_session(&id, &record, payload, timeout_secs, &mut output)?;
        Ok(CallResult::new(outcome, output))
    }

    fn stop(&self, id: &SessionId) -> Result<()> {
        mvm_client::entrypoint::kill_session(id.as_str()).map(|_| ())
    }

    fn info(&self, id: &SessionId) -> Result<SessionRecord> {
        mvm_client::entrypoint::session_info(id.as_str())
    }

    /// No step checkpointer: capturing a `vm_full` step is owned by the
    /// command line's checkpoint machinery, so a prompt sent from here is
    /// recorded and audited but is not a replayable step.
    fn prompt(&self, prompt: AgentPrompt) -> Result<PromptAnswer> {
        let mut output = CapturedOutput::default();
        Ok(
            match mvm_client::agent_prompt::send_prompt(&prompt, &mut output, None)? {
                PromptOutcome::Delivered {
                    journal_cursor,
                    call,
                    ..
                } => PromptAnswer::Delivered {
                    journal_cursor,
                    result: CallResult::new(call, output),
                },
                PromptOutcome::Duplicate { journal_cursor } => {
                    PromptAnswer::Duplicate { journal_cursor }
                }
            },
        )
    }
}

// ── requests ─────────────────────────────────────────────────────────────

/// An `entrypoint.call` request. Exactly one of `workload` and `manifest`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntrypointCallRequest {
    /// The id the workload was declared with.
    #[serde(default)]
    workload: Option<String>,
    /// A manifest path, the directory holding one, or a 64-hex slot address.
    #[serde(default)]
    manifest: Option<String>,
    /// The encoded `[args, kwargs]` call, base64. Empty is the no-argument
    /// call.
    payload_b64: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    cpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u32>,
}

/// A `session.start` request. Exactly one of `workload` and `manifest`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionStartRequest {
    #[serde(default)]
    workload: Option<String>,
    #[serde(default)]
    manifest: Option<String>,
    /// How long the session may sit idle before the host reaps it; five
    /// minutes when absent, one day at most.
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    cpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u32>,
}

/// A `session.call` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionCallRequest {
    session_id: String,
    /// The encoded `[args, kwargs]` call, base64.
    payload_b64: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// A `machine.prompt` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachinePromptRequest {
    /// The running machine whose agent is prompted.
    id: String,
    /// The prompt, base64.
    prompt_b64: String,
    /// The agent session to journal under; the machine's name when absent.
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    /// A prompt sent again under a key already accepted is not delivered
    /// twice; the request id when absent.
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// Names a session.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionRef {
    session_id: String,
}

// ── replies ──────────────────────────────────────────────────────────────

/// The structured error a function workload's wrapper reported for an
/// exception the user's function raised.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RemoteErrorReply {
    kind: String,
    error_id: String,
    message: String,
}

/// Why the guest agent (or, for a killed session, the host) ended the call
/// rather than the workload exiting.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AgentErrorReply {
    kind: RunEntrypointError,
    message: String,
}

/// The reply to `entrypoint.call` and `session.call`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct EntrypointCallReply {
    /// The workload's exit status, or the conventional status for how the
    /// agent ended the call (124 timeout, 137 crashed wrapper, 142 killed
    /// session, 75 not ready, 1 otherwise).
    exit_code: i32,
    stdout_b64: String,
    stderr_b64: String,
    /// Output past the per-channel cap was dropped.
    output_truncated: bool,
    /// The wrapper's error envelope, when the call failed with one.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RemoteErrorReply>,
    /// Set when the agent, not the workload, ended the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_error: Option<AgentErrorReply>,
}

impl From<CallResult> for EntrypointCallReply {
    fn from(result: CallResult) -> Self {
        let exit_code = result.terminal.exit_code();
        let error = (exit_code != 0)
            .then(|| mvm_client::entrypoint::parse_last_envelope(&result.output.stderr))
            .flatten()
            .map(|envelope| RemoteErrorReply {
                kind: envelope.kind,
                error_id: envelope.error_id,
                message: envelope.message,
            });
        let agent_error = match result.terminal {
            CallTerminal::Exited { .. } => None,
            CallTerminal::Failed { kind, message } => Some(AgentErrorReply { kind, message }),
        };
        Self {
            exit_code,
            stdout_b64: B64.encode(&result.output.stdout),
            stderr_b64: B64.encode(&result.output.stderr),
            output_truncated: result.output.truncated,
            error,
            agent_error,
        }
    }
}

/// The reply to `machine.prompt`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct MachinePromptReply {
    /// The agent-session journal cursor the prompt was accepted at.
    journal_cursor: u64,
    /// False when a prompt under the same retry key was already accepted and
    /// nothing was sent.
    delivered: bool,
    /// The agent's answer, in the shape `session.call` replies with, when the
    /// prompt was delivered. Flattened so the reply carries one definition of
    /// that shape rather than a second, nested one.
    #[serde(flatten)]
    answer: Option<EntrypointCallReply>,
}

impl From<PromptAnswer> for MachinePromptReply {
    fn from(answer: PromptAnswer) -> Self {
        match answer {
            PromptAnswer::Delivered {
                journal_cursor,
                result,
            } => Self {
                journal_cursor,
                delivered: true,
                answer: Some(EntrypointCallReply::from(result)),
            },
            PromptAnswer::Duplicate { journal_cursor } => Self {
                journal_cursor,
                delivered: false,
                answer: None,
            },
        }
    }
}

/// The reply to `session.start`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct SessionStartReply {
    session_id: String,
    vm_name: String,
}

/// A session's record, as `session.info` reports it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct SessionInfoReply {
    session_id: String,
    vm_name: String,
    /// The built slot the session boots from.
    workload_id: String,
    /// `prod` or `dev`.
    mode: String,
    /// `running`, `killed`, or `reaped`.
    state: String,
    idle_timeout_secs: u64,
    started_at: String,
    last_invoke_at: Option<String>,
    invoke_count: u64,
    ephemeral: bool,
}

impl From<SessionRecord> for SessionInfoReply {
    fn from(r: SessionRecord) -> Self {
        Self {
            session_id: r.id.into_string(),
            vm_name: r.vm_name,
            workload_id: r.workload_id,
            mode: r.mode.to_string(),
            state: r.state.to_string(),
            idle_timeout_secs: r.idle_timeout_secs,
            started_at: r.started_at,
            last_invoke_at: r.last_invoke_at,
            invoke_count: r.invoke_count,
            ephemeral: r.ephemeral,
        }
    }
}

// ── dispatch ─────────────────────────────────────────────────────────────

/// Answer the method `method` using `ops`.
pub(crate) fn dispatch(ops: &dyn EntrypointOps, method: &str, request: &[u8]) -> Outcome {
    match answer(ops, method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(ops: &dyn EntrypointOps, method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    Ok(match method {
        ENTRYPOINT_CALL => {
            let r: EntrypointCallRequest = parse(request)?;
            let source = source_of(r.workload.as_deref(), r.manifest.as_deref())?;
            let payload = decode(&r.payload_b64)?;
            let slot = ops.resolve(source).map_err(spec_error)?;
            let result = ops
                .call(CallSpec {
                    slot,
                    payload,
                    timeout_secs: r.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
                    cpus: r.cpus.unwrap_or_else(mvm_client::default_vcpus),
                    memory_mib: r.memory_mib.unwrap_or(DEFAULT_MEMORY_MIB),
                })
                .map_err(backend_error)?;
            Outcome::ok(&EntrypointCallReply::from(result))
        }
        SESSION_START => {
            let r: SessionStartRequest = parse(request)?;
            let source = source_of(r.workload.as_deref(), r.manifest.as_deref())?;
            let idle_timeout_secs = r
                .idle_timeout_secs
                .unwrap_or(mvm_core::session::DEFAULT_IDLE_TIMEOUT_SECS);
            mvm_client::entrypoint::session::validate_idle_timeout(idle_timeout_secs)
                .map_err(spec_error)?;
            let slot = ops.resolve(source).map_err(spec_error)?;
            let record = ops
                .start(StartSpec {
                    slot,
                    cpus: r.cpus.unwrap_or_else(mvm_client::default_vcpus),
                    memory_mib: r.memory_mib.unwrap_or(DEFAULT_MEMORY_MIB),
                    idle_timeout_secs,
                })
                .map_err(backend_error)?;
            Outcome::ok(&SessionStartReply {
                session_id: record.id.into_string(),
                vm_name: record.vm_name,
            })
        }
        SESSION_CALL => {
            let r: SessionCallRequest = parse(request)?;
            let id = session_id(&r.session_id)?;
            let payload = decode(&r.payload_b64)?;
            refuse_oversized_session_payload(payload.len())?;
            let result = ops
                .session_call(&id, payload, r.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS))
                .map_err(backend_error)?;
            Outcome::ok(&EntrypointCallReply::from(result))
        }
        SESSION_STOP => {
            let r: SessionRef = parse(request)?;
            ops.stop(&session_id(&r.session_id)?)
                .map_err(backend_error)?;
            Outcome::ok(&crate::guest::Empty {})
        }
        SESSION_INFO => {
            let r: SessionRef = parse(request)?;
            let record = ops
                .info(&session_id(&r.session_id)?)
                .map_err(backend_error)?;
            Outcome::ok(&SessionInfoReply::from(record))
        }
        MACHINE_PROMPT => {
            let r: MachinePromptRequest = parse(request)?;
            let prompt = agent_prompt(r)?;
            Outcome::ok(&MachinePromptReply::from(
                ops.prompt(prompt).map_err(backend_error)?,
            ))
        }
        other => return Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    })
}

/// Validate a prompt request into the prompt the client library delivers.
fn agent_prompt(r: MachinePromptRequest) -> Result<AgentPrompt, Outcome> {
    let mut builder = AgentPrompt::builder(r.id, decode(&r.prompt_b64)?);
    if let Some(session) = r.session_id {
        builder = builder.session(session);
    }
    if let Some(request_id) = r.request_id {
        builder = builder.request_id(request_id);
    }
    if let Some(key) = r.idempotency_key {
        builder = builder.idempotency_key(key);
    }
    if let Some(secs) = r.timeout_secs {
        builder = builder.timeout_secs(secs);
    }
    builder
        .build()
        .map_err(|e| Outcome::invalid_input(&format!("{e:#}")))
}

/// The workload a request names: exactly one of its two ways of naming one.
fn source_of<'a>(
    workload: Option<&'a str>,
    manifest: Option<&'a str>,
) -> Result<WorkloadSource<'a>, Outcome> {
    match (workload, manifest) {
        (Some(id), None) if !id.trim().is_empty() => Ok(WorkloadSource::Workload(id)),
        (None, Some(path)) if !path.trim().is_empty() => Ok(WorkloadSource::Manifest(path)),
        (Some(_), Some(_)) => Err(Outcome::invalid_input(
            "name the workload by `workload` or by `manifest`, not both",
        )),
        _ => Err(Outcome::invalid_input(
            "name the workload to call: a non-empty `workload` id or `manifest`",
        )),
    }
}

/// A session was admitted by the call that started it, so there is no plan in
/// this call to open an input stream under; its payload has to fit the frame.
fn refuse_oversized_session_payload(len: usize) -> Result<(), Outcome> {
    if len <= ONE_SHOT_PAYLOAD_LIMIT {
        return Ok(());
    }
    Err(Outcome::from(MvmError::Rejected {
        reason: format!(
            "a {len}-byte payload exceeds the {ONE_SHOT_PAYLOAD_LIMIT}-byte limit one call \
             into a session can carry; call outside the session, or pass large data through \
             a mounted volume"
        ),
    }))
}

fn session_id(raw: &str) -> Result<SessionId, Outcome> {
    SessionId::parse(raw)
        .map_err(|e| Outcome::invalid_input(&format!("session_id is not a session id: {e}")))
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|e| Outcome::invalid_input(&format!("request did not parse: {e}")))
}

fn decode(data_b64: &str) -> Result<Vec<u8>, Outcome> {
    B64.decode(data_b64)
        .map_err(|e| Outcome::invalid_input(&format!("payload_b64 is not base64: {e}")))
}

/// The request named something the host cannot boot: no built image, an
/// ambiguous one, a manifest that does not resolve, or a bad idle timeout.
fn spec_error(error: anyhow::Error) -> Outcome {
    Outcome::from(MvmError::InvalidSpec {
        reason: format!("{error:#}"),
    })
}

/// The backend's answer to a well-formed request: an admission refusal, a
/// boot that failed, an agent that never answered, or a broken stream.
fn backend_error(error: anyhow::Error) -> Outcome {
    Outcome::from(MvmError::Backend {
        reason: format!("{error:#}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{
        MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_INVALID_SPEC, MVM_HOSTLIB_OK,
        MVM_HOSTLIB_REJECTED,
    };
    use std::sync::Mutex;

    /// Records each call and answers from fixed values, so a test sees exactly
    /// what dispatch passed down.
    #[derive(Default)]
    struct Recording {
        calls: Mutex<Vec<String>>,
        result: Option<CallResult>,
        fail: bool,
        unresolvable: bool,
    }

    impl Recording {
        fn note(&self, call: String) -> Result<()> {
            self.calls.lock().unwrap().push(call);
            if self.fail {
                anyhow::bail!("the backend refused");
            }
            Ok(())
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn answering(result: CallResult) -> Self {
            Self {
                result: Some(result),
                ..Self::default()
            }
        }

        fn record(&self) -> SessionRecord {
            let mut record = SessionRecord::new_running("session-vm", "slot-1", SessionMode::Prod);
            record.id = SessionId::parse(SESSION).unwrap();
            record
        }

        fn result(&self) -> CallResult {
            self.result.clone().unwrap_or(CallResult {
                terminal: CallTerminal::Exited { code: 0 },
                output: CapturedOutput::default(),
            })
        }
    }

    impl EntrypointOps for Recording {
        fn resolve(&self, source: WorkloadSource<'_>) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("resolve {source:?}"));
            if self.unresolvable {
                anyhow::bail!("no built image named \"adder\" on this host");
            }
            Ok("slot-1".into())
        }
        fn call(&self, spec: CallSpec) -> Result<CallResult> {
            self.note(format!(
                "call {} {:?} {} {} {}",
                spec.slot,
                String::from_utf8_lossy(&spec.payload),
                spec.timeout_secs,
                spec.cpus,
                spec.memory_mib
            ))?;
            Ok(self.result())
        }
        fn start(&self, spec: StartSpec) -> Result<SessionRecord> {
            self.note(format!(
                "start {} {} {} {}",
                spec.slot, spec.cpus, spec.memory_mib, spec.idle_timeout_secs
            ))?;
            Ok(self.record())
        }
        fn session_call(
            &self,
            id: &SessionId,
            payload: Vec<u8>,
            timeout_secs: u64,
        ) -> Result<CallResult> {
            self.note(format!(
                "session_call {id} {:?} {timeout_secs}",
                String::from_utf8_lossy(&payload)
            ))?;
            Ok(self.result())
        }
        fn stop(&self, id: &SessionId) -> Result<()> {
            self.note(format!("stop {id}"))
        }
        fn info(&self, id: &SessionId) -> Result<SessionRecord> {
            self.note(format!("info {id}"))?;
            Ok(self.record())
        }
        fn prompt(&self, prompt: AgentPrompt) -> Result<PromptAnswer> {
            self.note(format!(
                "prompt {} {} {}",
                prompt.vm_name(),
                prompt.session_id(),
                prompt.idempotency_key()
            ))?;
            Ok(PromptAnswer::Delivered {
                journal_cursor: 2,
                result: self.result(),
            })
        }
    }

    const SESSION: &str = "abcdefghijklmnopqrstuvwxyz";

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn reply(outcome: &Outcome) -> serde_json::Value {
        serde_json::from_slice(&outcome.body).expect("a JSON body")
    }

    fn exited(code: i32, stdout: &[u8], stderr: &[u8]) -> CallResult {
        CallResult {
            terminal: CallTerminal::Exited { code },
            output: CapturedOutput {
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
                truncated: false,
            },
        }
    }

    #[test]
    fn a_call_resolves_the_workload_and_returns_its_output() {
        let ops = Recording::answering(exited(0, b"5", b""));
        let request = serde_json::json!({"workload": "adder", "payload_b64": b64(b"[[2,3],{}]")});
        let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let body = reply(&outcome);
        assert_eq!(body["exit_code"], 0);
        assert_eq!(body["stdout_b64"], b64(b"5"));
        assert_eq!(body["output_truncated"], false);
        assert!(body.get("error").is_none(), "{body}");
        assert!(body.get("agent_error").is_none(), "{body}");
        assert_eq!(
            ops.calls(),
            vec![
                "resolve Workload(\"adder\")".to_string(),
                format!(
                    "call slot-1 \"[[2,3],{{}}]\" 30 {} 512",
                    mvm_client::default_vcpus()
                ),
            ]
        );
    }

    #[test]
    fn a_prompt_reaches_the_machine_and_returns_the_agents_answer() {
        let ops = Recording::answering(exited(0, b"two files changed", b""));
        let request = serde_json::json!({
            "id": "agent-vm",
            "prompt_b64": b64(b"what changed?"),
            "session_id": "review",
            "idempotency_key": "retry-1",
        });
        let outcome = dispatch(&ops, MACHINE_PROMPT, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        let body = reply(&outcome);
        assert_eq!(body["delivered"], true);
        assert_eq!(body["journal_cursor"], 2);
        assert_eq!(body["exit_code"], 0);
        assert_eq!(body["stdout_b64"], b64(b"two files changed"));
        assert_eq!(ops.calls(), ["prompt agent-vm review retry-1"]);
    }

    #[test]
    fn an_invalid_prompt_is_refused_before_the_machine_is_touched() {
        let ops = Recording::default();
        for request in [
            serde_json::json!({"id": "agent-vm", "prompt_b64": ""}),
            serde_json::json!({"id": "agent-vm", "prompt_b64": b64(b"hi"), "session_id": "Bad Id"}),
            serde_json::json!({"id": "agent-vm", "prompt_b64": "%%%"}),
        ] {
            let outcome = dispatch(&ops, MACHINE_PROMPT, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT, "{request}");
        }
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_refused_prompt_is_the_backends_answer() {
        let ops = Recording {
            fail: true,
            ..Recording::default()
        };
        let request = serde_json::json!({"id": "agent-vm", "prompt_b64": b64(b"hi")});
        let outcome = dispatch(&ops, MACHINE_PROMPT, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
    }

    #[test]
    fn a_call_passes_its_sizing_and_timeout_through() {
        let ops = Recording::default();
        let request = serde_json::json!({
            "manifest": "/src/app/mvm.toml",
            "payload_b64": "",
            "timeout_secs": 9,
            "cpus": 3,
            "memory_mib": 1024,
        });
        let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(
            ops.calls(),
            vec![
                "resolve Manifest(\"/src/app/mvm.toml\")".to_string(),
                "call slot-1 \"\" 9 3 1024".to_string(),
            ]
        );
    }

    #[test]
    fn a_raised_exception_comes_back_as_the_wrappers_envelope() {
        let stderr = b"Traceback...\nMVM_ENVELOPE: {\"kind\":\"ValueError\",\"error_id\":\"0123456789abcdef\",\"message\":\"bad\"}\n";
        let ops = Recording::answering(exited(1, b"", stderr));
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let body = reply(&dispatch(
            &ops,
            ENTRYPOINT_CALL,
            request.to_string().as_bytes(),
        ));
        assert_eq!(body["exit_code"], 1);
        assert_eq!(
            body["error"],
            serde_json::json!({"kind": "ValueError", "error_id": "0123456789abcdef", "message": "bad"})
        );
    }

    #[test]
    fn a_failure_without_an_envelope_carries_no_error_field() {
        let ops = Recording::answering(exited(3, b"", b"segfault\n"));
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let body = reply(&dispatch(
            &ops,
            ENTRYPOINT_CALL,
            request.to_string().as_bytes(),
        ));
        assert_eq!(body["exit_code"], 3);
        assert!(body.get("error").is_none());
        assert_eq!(body["stderr_b64"], b64(b"segfault\n"));
    }

    #[test]
    fn a_successful_exit_ignores_an_envelope_shaped_line() {
        let stderr = b"MVM_ENVELOPE: {\"kind\":\"X\",\"error_id\":\"y\",\"message\":\"z\"}\n";
        let ops = Recording::answering(exited(0, b"1", stderr));
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let body = reply(&dispatch(
            &ops,
            ENTRYPOINT_CALL,
            request.to_string().as_bytes(),
        ));
        assert!(body.get("error").is_none());
    }

    #[test]
    fn an_agent_ended_call_reports_why() {
        let ops = Recording::answering(CallResult {
            terminal: CallTerminal::Failed {
                kind: RunEntrypointError::Timeout,
                message: "wrapper exceeded 30s timeout".into(),
            },
            output: CapturedOutput::default(),
        });
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let body = reply(&dispatch(
            &ops,
            ENTRYPOINT_CALL,
            request.to_string().as_bytes(),
        ));
        assert_eq!(body["exit_code"], 124);
        assert_eq!(body["agent_error"]["kind"], "Timeout");
        assert_eq!(
            body["agent_error"]["message"],
            "wrapper exceeded 30s timeout"
        );
    }

    #[test]
    fn a_truncated_call_says_so() {
        let mut result = exited(0, b"x", b"");
        result.output.truncated = true;
        let ops = Recording::answering(result);
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let body = reply(&dispatch(
            &ops,
            ENTRYPOINT_CALL,
            request.to_string().as_bytes(),
        ));
        assert_eq!(body["output_truncated"], true);
    }

    #[test]
    fn a_call_must_name_exactly_one_source() {
        let ops = Recording::default();
        for request in [
            serde_json::json!({"payload_b64": ""}),
            serde_json::json!({"workload": "a", "manifest": "b", "payload_b64": ""}),
            serde_json::json!({"workload": "  ", "payload_b64": ""}),
        ] {
            let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT, "{request}");
        }
        assert!(ops.calls().is_empty(), "nothing is resolved or booted");
    }

    #[test]
    fn a_payload_that_is_not_base64_is_refused() {
        let ops = Recording::default();
        let request = serde_json::json!({"workload": "adder", "payload_b64": "***"});
        let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn unknown_fields_are_refused_on_every_request() {
        let ops = Recording::default();
        for (method, request) in [
            (
                ENTRYPOINT_CALL,
                serde_json::json!({"workload": "a", "payload_b64": "", "fn": "x"}),
            ),
            (
                SESSION_START,
                serde_json::json!({"workload": "a", "mode": "dev"}),
            ),
            (
                SESSION_CALL,
                serde_json::json!({"session_id": SESSION, "payload_b64": "", "stdin": "-"}),
            ),
            (
                SESSION_STOP,
                serde_json::json!({"session_id": SESSION, "force": true}),
            ),
            (
                SESSION_INFO,
                serde_json::json!({"session_id": SESSION, "x": 1}),
            ),
        ] {
            let outcome = dispatch(&ops, method, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT, "{method}");
        }
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_workload_nobody_built_is_an_invalid_spec() {
        let ops = Recording {
            unresolvable: true,
            ..Recording::default()
        };
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
        assert!(
            reply(&outcome)["message"]
                .as_str()
                .unwrap()
                .contains("no built image")
        );
    }

    #[test]
    fn a_backend_failure_is_a_backend_error() {
        let ops = Recording {
            fail: true,
            ..Recording::default()
        };
        let request = serde_json::json!({"workload": "adder", "payload_b64": ""});
        let outcome = dispatch(&ops, ENTRYPOINT_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
    }

    #[test]
    fn a_session_starts_with_the_default_idle_timeout() {
        let ops = Recording::default();
        let request = serde_json::json!({"workload": "adder"});
        let outcome = dispatch(&ops, SESSION_START, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(
            reply(&outcome),
            serde_json::json!({"session_id": SESSION, "vm_name": "session-vm"})
        );
        assert_eq!(
            ops.calls().last().unwrap(),
            &format!(
                "start slot-1 {} 512 {}",
                mvm_client::default_vcpus(),
                mvm_core::session::DEFAULT_IDLE_TIMEOUT_SECS
            )
        );
    }

    #[test]
    fn a_session_idle_timeout_out_of_range_is_refused_before_booting() {
        let ops = Recording::default();
        for secs in [0, mvm_core::session::MAX_IDLE_TIMEOUT_SECS + 1] {
            let request = serde_json::json!({"workload": "adder", "idle_timeout_secs": secs});
            let outcome = dispatch(&ops, SESSION_START, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC, "{secs}");
        }
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_session_call_dispatches_into_the_named_session() {
        let ops = Recording::answering(exited(0, b"9", b""));
        let request = serde_json::json!({
            "session_id": SESSION,
            "payload_b64": b64(b"[[4,5],{}]"),
            "timeout_secs": 7,
        });
        let outcome = dispatch(&ops, SESSION_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(reply(&outcome)["stdout_b64"], b64(b"9"));
        assert_eq!(
            ops.calls(),
            vec![format!("session_call {SESSION} \"[[4,5],{{}}]\" 7")]
        );
    }

    #[test]
    fn a_session_call_past_one_frame_is_refused_naming_the_limit() {
        let ops = Recording::default();
        let request = serde_json::json!({
            "session_id": SESSION,
            "payload_b64": b64(&vec![b'x'; ONE_SHOT_PAYLOAD_LIMIT + 1]),
        });
        let outcome = dispatch(&ops, SESSION_CALL, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_REJECTED);
        assert!(
            reply(&outcome)["message"]
                .as_str()
                .unwrap()
                .contains(&ONE_SHOT_PAYLOAD_LIMIT.to_string())
        );
        assert!(ops.calls().is_empty(), "nothing is truncated and sent");
    }

    #[test]
    fn a_malformed_session_id_is_invalid_input() {
        let ops = Recording::default();
        for method in [SESSION_CALL, SESSION_STOP, SESSION_INFO] {
            let request = serde_json::json!({"session_id": "NOPE", "payload_b64": ""});
            let request = if method == SESSION_CALL {
                request
            } else {
                serde_json::json!({"session_id": "NOPE"})
            };
            let outcome = dispatch(&ops, method, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT, "{method}");
        }
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_session_stops_and_reports_nothing() {
        let ops = Recording::default();
        let request = serde_json::json!({"session_id": SESSION});
        let outcome = dispatch(&ops, SESSION_STOP, request.to_string().as_bytes());
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(reply(&outcome), serde_json::json!({}));
        assert_eq!(ops.calls(), vec![format!("stop {SESSION}")]);
    }

    #[test]
    fn session_info_reports_the_record() {
        let ops = Recording::default();
        let request = serde_json::json!({"session_id": SESSION});
        let body = reply(&dispatch(
            &ops,
            SESSION_INFO,
            request.to_string().as_bytes(),
        ));
        assert_eq!(body["session_id"], SESSION);
        assert_eq!(body["vm_name"], "session-vm");
        assert_eq!(body["workload_id"], "slot-1");
        assert_eq!(body["mode"], "prod");
        assert_eq!(body["state"], "running");
        assert_eq!(body["invoke_count"], 0);
        assert_eq!(body["ephemeral"], false);
        assert!(body["last_invoke_at"].is_null());
    }

    #[test]
    fn a_session_backend_failure_is_a_backend_error() {
        let ops = Recording {
            fail: true,
            ..Recording::default()
        };
        let request = serde_json::json!({"session_id": SESSION});
        for method in [SESSION_STOP, SESSION_INFO] {
            let outcome = dispatch(&ops, method, request.to_string().as_bytes());
            assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND, "{method}");
        }
    }

    #[test]
    fn an_unknown_method_is_refused() {
        let outcome = dispatch(&Recording::default(), "session.exec", b"{}");
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        assert!(!is_known("session.exec"));
        for method in METHODS {
            assert!(is_known(method));
        }
    }

    #[test]
    fn the_local_operations_refuse_a_session_that_does_not_exist() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let id = SessionId::parse(SESSION).unwrap();
        let error = LocalEntrypoint.info(&id).expect_err("no such session");
        assert!(error.to_string().contains("no session with id"));
        assert!(LocalEntrypoint.stop(&id).is_err());
        assert!(LocalEntrypoint.session_call(&id, Vec::new(), 1).is_err());
    }

    #[test]
    fn the_local_operations_refuse_a_workload_nobody_built() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let error = LocalEntrypoint
            .resolve(WorkloadSource::Workload("adder"))
            .expect_err("nothing built");
        assert!(error.to_string().contains("no built image"));
    }
}
