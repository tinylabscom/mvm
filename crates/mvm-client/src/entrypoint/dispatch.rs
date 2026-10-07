//! One `RunEntrypoint` call into a running guest agent.
//!
//! The dispatch owns everything the call itself decides: the connection, the
//! workload's egress environment, the capture that records a redacted copy of
//! the output, the host→guest stdin stream when the plan grants one, and the
//! mapping of the guest's terminal event onto an exit status. What to *do*
//! with the output — print it, buffer it for a binding — is the caller's, and
//! reaches it through [`CallObserver`].
//!
//! **The caller gets the workload's own bytes.** Every frame goes through the
//! VM's capture, which redacts, chains and persists the copy an operator reads
//! back; what the observer is handed is the workload's output unchanged,
//! because whoever made this call has code execution inside the workload that
//! produced it. How the recorded copy differed is tallied in
//! [`RecordedDivergence`] so the caller can say so.

use std::collections::BTreeSet;
use std::io::Read;

use anyhow::{Context, Result};
use mvm_agentd::vsock::{EntrypointEvent, GuestRequest, RunEntrypointError};
use mvm_contract::stream::StreamKind;
use mvm_core::session::{SessionId, SessionState};
use mvm_hostd::plan_admission::AdmittedPlan;
use mvm_hostd::stream::{EntrypointSink, RecordedCopy, ShownChunk};

use super::stdin_stream::{PlaneInput, StdinStream, StreamedInputReport};

/// The largest payload a call carries in its `RunEntrypoint` frame.
///
/// The frame's body is JSON, and a `Vec<u8>` crosses it as an integer array,
/// so a payload byte can cost four bytes of frame. This is the agent crate's
/// own derivation of what fits under the frame cap with room for the rest of
/// the request, so a payload at or below it always travels; a larger one has
/// to stream over the input plane or be refused, never be cut short.
pub const ONE_SHOT_PAYLOAD_LIMIT: usize = mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE;

/// The payload a call with no arguments carries.
///
/// A function-entrypoint wrapper decodes its whole stdin as `[args, kwargs]`,
/// and an empty stdin is a decode error in the guest, so "no payload" is sent
/// as the explicit no-argument call.
pub const NO_ARGUMENT_PAYLOAD: &[u8] = b"[[], {}]";

/// `bytes`, or [`NO_ARGUMENT_PAYLOAD`] when there are none.
#[must_use]
pub fn one_shot_payload(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        NO_ARGUMENT_PAYLOAD.to_vec()
    } else {
        bytes
    }
}

/// Stdin as a caller supplies it, before any admission is consulted.
pub enum CallStdin {
    /// Every byte, known before the call, carried in the call's own frame.
    OneShot(Vec<u8>),
    /// A reader carried into the workload while it runs, its EOF closing the
    /// workload's stdin. Needs the input grant on the plan the VM booted under.
    Streaming(Box<dyn Read + Send>),
}

impl CallStdin {
    /// Whether this call asks for a host→guest stdin stream — the one thing
    /// that puts the input grant on the plan.
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming(_))
    }

    /// How a payload of these bytes has to travel: in the call's frame when it
    /// fits, streamed when it does not.
    #[must_use]
    pub fn for_payload(bytes: Vec<u8>) -> Self {
        if bytes.len() <= ONE_SHOT_PAYLOAD_LIMIT {
            Self::OneShot(one_shot_payload(bytes))
        } else {
            Self::Streaming(Box::new(std::io::Cursor::new(bytes)))
        }
    }
}

/// Stdin as the dispatch sees it, once the caller's request has been resolved
/// against a real admission.
pub enum DispatchStdin<'a> {
    /// The complete payload, carried in the `RunEntrypoint` frame itself.
    OneShot(Vec<u8>),
    /// A live stream opened under this boot's admitted plan.
    ///
    /// Holding the [`AdmittedPlan`] rather than a bool is the point: the gate
    /// takes the type only admission mints, so what authorizes these bytes is
    /// the same signed, verified, window-checked plan the VM booted under.
    Streaming {
        /// The plan the VM booted under.
        admitted: &'a AdmittedPlan,
        /// Where the bytes come from.
        reader: Box<dyn Read + Send>,
    },
    /// A prompt for the resident agent, carried in an `AgentPrompt` request
    /// rather than `RunEntrypoint`. The guest runs the same boot-validated
    /// program; what differs is the verb the signed plan has to grant.
    Prompt(Vec<u8>),
}

/// Decide what a call's stdin may be, now that the boot's admission is known.
///
/// A streamed stdin is the only shape that needs anything from the boot: the
/// grant on the admitted plan is what authorizes a write, so a dispatch with
/// no admitted plan has nothing to write under. A one-shot payload asks for no
/// authority and is unaffected.
///
/// # Errors
/// A streamed stdin with no admitted plan.
pub fn authorize_stdin(
    stdin: CallStdin,
    admitted: Option<&AdmittedPlan>,
) -> Result<DispatchStdin<'_>> {
    match (stdin, admitted) {
        (CallStdin::Streaming(reader), Some(admitted)) => {
            Ok(DispatchStdin::Streaming { admitted, reader })
        }
        (CallStdin::Streaming(_), None) => anyhow::bail!(
            "streamed stdin needs an admitted plan, and this dispatch has none: the \
             input grant is what authorizes a write, so there is nothing here to \
             write under"
        ),
        (CallStdin::OneShot(bytes), _) => Ok(DispatchStdin::OneShot(bytes)),
    }
}

/// One `RunEntrypoint` dispatch against a reachable guest agent.
pub struct EntrypointDispatch<'a> {
    /// The running microVM to dispatch into.
    pub vm_name: &'a str,
    /// What reaches the workload's stdin.
    pub stdin: DispatchStdin<'a>,
    /// Wall-clock kill window for the call.
    pub timeout_secs: u64,
    /// Session record to consult when the transport drops, so an external
    /// session kill is reported as one.
    pub session_id: Option<&'a SessionId>,
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTerminal {
    /// The workload exited with this status.
    Exited {
        /// The workload's exit status.
        code: i32,
    },
    /// The agent (or, for a killed session, the host) ended the call.
    Failed {
        /// Why.
        kind: RunEntrypointError,
        /// The agent's message.
        message: String,
    },
}

impl CallTerminal {
    /// The terminal a guest's last event describes. A non-terminal event
    /// cannot end a call; receiving one here is an internal error.
    #[must_use]
    pub fn from_event(event: &EntrypointEvent) -> Self {
        match event {
            EntrypointEvent::Exit { code } => Self::Exited { code: *code },
            EntrypointEvent::Error { kind, message } => Self::Failed {
                kind: *kind,
                message: message.clone(),
            },
            EntrypointEvent::Stdout { .. }
            | EntrypointEvent::Stderr { .. }
            | EntrypointEvent::Control { .. } => Self::Failed {
                kind: RunEntrypointError::InternalError,
                message: "dispatcher returned non-terminal event".to_string(),
            },
        }
    }

    /// The exit status a caller reports: the workload's own, or the Unix
    /// convention for how the agent ended it — `124` for a timeout (as
    /// `timeout(1)`), `130` for a cancel (128 + SIGINT), `137` for a crashed
    /// wrapper (128 + SIGKILL), `142` for a killed session (128 + SIGALRM,
    /// repurposed as a stable "your session was reaped" status), `75`
    /// (`EX_TEMPFAIL`) for an agent that is not ready yet, `1` otherwise.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Exited { code } => *code,
            Self::Failed { kind, .. } => match kind {
                RunEntrypointError::Timeout => 124,
                RunEntrypointError::Canceled => 130,
                RunEntrypointError::WrapperCrashed => 137,
                RunEntrypointError::SessionKilled => 142,
                RunEntrypointError::NotReady => 75,
                RunEntrypointError::Busy
                | RunEntrypointError::PayloadCap
                | RunEntrypointError::EntrypointInvalid
                | RunEntrypointError::InternalError => 1,
            },
        }
    }

    /// A short label for an agent-ended call, `None` for a workload exit.
    #[must_use]
    pub fn label(&self) -> Option<&'static str> {
        match self {
            Self::Exited { .. } => None,
            Self::Failed { kind, .. } => Some(error_label(*kind)),
        }
    }
}

/// A stable, lower-case label for an agent-side failure.
#[must_use]
pub fn error_label(kind: RunEntrypointError) -> &'static str {
    match kind {
        RunEntrypointError::Timeout => "timeout",
        RunEntrypointError::Busy => "busy",
        RunEntrypointError::PayloadCap => "payload cap exceeded",
        RunEntrypointError::WrapperCrashed => "wrapper crashed",
        RunEntrypointError::EntrypointInvalid => "entrypoint invalid",
        RunEntrypointError::Canceled => "canceled",
        RunEntrypointError::SessionKilled => "session killed",
        RunEntrypointError::NotReady => "agent not ready",
        RunEntrypointError::InternalError => "internal error",
    }
}

/// How the copy of a call's output that was recorded differs from the copy
/// the caller was handed.
///
/// Counts and rule *names* only. A value that fired a rule is exactly the
/// value that must not travel, so naming it would reopen the leak the seam
/// closes — and the caller already has the bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecordedDivergence {
    /// Chunks recorded masked.
    pub masked_chunks: u64,
    /// Chunks the redaction seam would not vouch for, recorded as a marker.
    pub withheld_chunks: u64,
    /// Chunks that went unrecorded after the call had already been sampled
    /// as recorded — the capture was released mid-dispatch, by a teardown
    /// racing this call.
    pub dropped_chunks: u64,
    /// The rules that fired, sorted and deduplicated.
    pub rules_fired: BTreeSet<&'static str>,
}

impl RecordedDivergence {
    /// Tally one chunk's recorded copy.
    pub fn note(&mut self, recorded: &RecordedCopy) {
        match recorded {
            RecordedCopy::NotRecorded => {
                self.dropped_chunks = self.dropped_chunks.saturating_add(1);
            }
            RecordedCopy::Identical => {}
            RecordedCopy::Masked { rules_fired } => {
                self.masked_chunks = self.masked_chunks.saturating_add(1);
                self.rules_fired.extend(rules_fired.iter().copied());
            }
            RecordedCopy::Withheld { .. } => {
                self.withheld_chunks = self.withheld_chunks.saturating_add(1);
            }
        }
    }

    /// Whether the recorded copy is exactly what the caller was handed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.masked_chunks == 0 && self.withheld_chunks == 0 && self.dropped_chunks == 0
    }
}

/// What the capture made of a call that ran to its terminal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureReport {
    /// Whether a capture in this process was recording the VM when the call
    /// started.
    pub recorded: bool,
    /// How the recorded copy differs from what the caller was handed.
    pub divergence: RecordedDivergence,
}

/// The result of one dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOutcome {
    /// How the call ended.
    pub terminal: CallTerminal,
    /// What the capture recorded. `None` when the host synthesized the
    /// terminal (a session killed under the call) and no call finished.
    pub capture: Option<CaptureReport>,
}

impl CallOutcome {
    /// The exit status the caller reports. See [`CallTerminal::exit_code`].
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.terminal.exit_code()
    }
}

/// Where a call's output goes, and what the caller hears about the call.
///
/// The dispatch calls these in order: `output`/`control` as frames arrive,
/// `streamed_input` once a streamed stdin has ended, and `call_finished` once
/// the call has a terminal. Only the first two are required.
pub trait CallObserver {
    /// The call's VM has its final name, before admission or backend startup.
    /// Observers can arm host-side evidence collection without racing boot.
    fn vm_named(&mut self, _vm_name: &str) {}
    /// One chunk of the workload's own bytes, on the channel the guest sent it
    /// on, with how its recorded copy differed.
    fn output(&mut self, chunk: &ShownChunk);
    /// One fd-3 control record: its header (as recorded) and the size of the
    /// payload riding with it.
    fn control(&mut self, header: &str, payload_len: usize);
    /// A streamed stdin has ended. Called even when the call failed, because
    /// a failed call truncated the caller's stdin just as surely.
    fn streamed_input(&mut self, _vm_name: &str, _report: &StreamedInputReport) {}
    /// The call is about to be dispatched into `vm_name`, which is up and
    /// admitted. `streams_stdin` says whether the caller's stdin is streamed
    /// to the workload.
    fn dispatching(&mut self, _vm_name: &str, _streams_stdin: bool) {}
    /// The dispatch returned, before the machine is torn down or kept alive.
    fn dispatched(&mut self) {}
    /// The call has a terminal.
    fn call_finished(&mut self, _vm_name: &str, _outcome: &CallOutcome) {}
    /// A kept-alive call left its VM running under this session.
    fn kept_alive(&mut self, _vm_name: &str, _session_id: Option<&SessionId>) {}
}

/// Hand one streamed event to the capture and the observer.
///
/// Every frame is ingested exactly once — one frame in, one record recorded,
/// one copy handed over — and the ingest waits on neither a follower nor the
/// disk, so nothing downstream can pace the guest through this loop. Terminal
/// events are returned by the dispatch rather than streamed, so they pass
/// through here untouched.
pub fn route_event(
    event: &EntrypointEvent,
    capture: &mut EntrypointSink,
    divergence: &mut RecordedDivergence,
    observer: &mut dyn CallObserver,
) {
    match event {
        EntrypointEvent::Stdout { chunk } => {
            let shown = capture.ingest(StreamKind::Stdout, chunk);
            divergence.note(&shown.recorded);
            observer.output(&shown);
        }
        EntrypointEvent::Stderr { chunk } => {
            let shown = capture.ingest(StreamKind::Stderr, chunk);
            divergence.note(&shown.recorded);
            observer.output(&shown);
        }
        EntrypointEvent::Control {
            header_json,
            payload,
        } => {
            // The header is the record; the fd-3 payload rides along and
            // neither consumer renders it.
            let shown = capture.ingest(StreamKind::Trace, header_json.as_bytes());
            divergence.note(&shown.recorded);
            observer.control(&String::from_utf8_lossy(&shown.body), payload.len());
        }
        EntrypointEvent::Exit { .. } | EntrypointEvent::Error { .. } => {}
    }
}

/// Send the `RunEntrypoint` request and stream its output to `observer`.
///
/// A transport failure under a session that has since been marked `Killed` is
/// attributed to the kill and reported as [`RunEntrypointError::SessionKilled`]
/// rather than as the raw I/O error: the agent cannot emit that itself,
/// because by the time a kill takes effect it is already going down.
///
/// A failure that carries the agent's verb refusal is recorded as a
/// chain-signed `verb_denied` entry before it is returned.
///
/// # Errors
/// The agent unreachable, the stdin route refused, or the stream broken.
pub fn dispatch(
    call: EntrypointDispatch<'_>,
    observer: &mut dyn CallObserver,
) -> Result<CallOutcome> {
    let vm_name = call.vm_name;
    let session_id = call.session_id;
    match dispatch_inner(call, observer) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            if let Some(id) = session_id
                && let Ok(Some(rec)) = mvm_core::session::read_session(id)
                && rec.state == SessionState::Killed
            {
                let outcome = CallOutcome {
                    terminal: CallTerminal::Failed {
                        kind: RunEntrypointError::SessionKilled,
                        message: format!("session {id} killed externally"),
                    },
                    capture: None,
                };
                observer.call_finished(vm_name, &outcome);
                return Ok(outcome);
            }
            super::verb_audit::audit_verb_refusal(vm_name, &err);
            Err(err)
        }
    }
}

fn dispatch_inner(
    call: EntrypointDispatch<'_>,
    observer: &mut dyn CallObserver,
) -> Result<CallOutcome> {
    let EntrypointDispatch {
        vm_name,
        stdin,
        timeout_secs,
        session_id: _,
    } = call;
    let transport = mvm_runtime::vsock_transport::for_vm(vm_name)
        .with_context(|| format!("Picking transport for guest agent on '{vm_name}'"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on '{vm_name}'"))?;

    // Opened before the call is sent, and deliberately: the guest has a stdin
    // to hand frames to only once the entrypoint's child exists, and the pump
    // is built to ride out that window. Opening afterwards would mean opening
    // it from inside the loop that is streaming the workload's output.
    let (payload, streamed, prompt) = match stdin {
        DispatchStdin::OneShot(bytes) => (bytes, None, false),
        // The bytes travel as frames, not in the request.
        DispatchStdin::Streaming { admitted, reader } => (
            Vec::new(),
            Some(open_streamed_stdin(vm_name, admitted, reader)?),
            false,
        ),
        DispatchStdin::Prompt(bytes) => (bytes, None, true),
    };
    let stream_input = streamed.is_some();
    // Every workload routes through the guest's one loopback proxy; a
    // secret-bearing one carries its minted placeholders alongside.
    let env = workload_egress_env(vm_name);
    let audited = if prompt {
        GuestRequest::AgentPrompt {
            prompt: Vec::new(),
            timeout_secs,
            env: Vec::new(),
        }
    } else {
        GuestRequest::RunEntrypoint {
            stdin: Vec::new(),
            timeout_secs,
            env: Vec::new(),
            stream_input,
        }
    };
    crate::guest::emit_vsock_rpc_audit(vm_name, &audited);

    // The entrypoint half of the VM's output capture, for this call only.
    let mut capture = EntrypointSink::for_vm(vm_name);
    let recorded = capture.is_recorded();
    let mut divergence = RecordedDivergence::default();
    let on_event = |event: &EntrypointEvent| {
        route_event(event, &mut capture, &mut divergence, observer);
    };
    // Consulted only when the stream has gone quiet. A guest that dies
    // mid-stream leaves the host socket open, so without this the read
    // blocks forever and the call never returns.
    let still_alive = || mvm_runtime::checkpoint::vm_is_running(vm_name);
    let terminal = if prompt {
        mvm_agentd::vsock::send_agent_prompt_while(
            &mut stream,
            mvm_agentd::vsock::AgentPromptCall {
                prompt: payload,
                timeout_secs,
                env,
            },
            on_event,
            still_alive,
        )
    } else {
        mvm_agentd::vsock::send_run_entrypoint_while(
            &mut stream,
            mvm_agentd::vsock::RunEntrypointCall {
                stdin: payload,
                timeout_secs,
                env,
                // A one-shot dispatch writes its payload once and has no writer
                // behind it, so the guest closes stdin and a read-to-EOF
                // workload exits. A streamed one keeps the pipe open, because
                // the EOF is the host's to send when the caller's own stdin
                // ends.
                stream_input,
            },
            on_event,
            still_alive,
        )
    };
    drop(capture);
    // Before the `?`, not after: a call that failed truncated the caller's
    // stdin just as surely as one that succeeded, and propagating first would
    // swallow the only notice saying so.
    if let Some(streamed) = streamed {
        observer.streamed_input(vm_name, &streamed.finish());
    }
    let terminal = terminal.with_context(|| {
        format!(
            "Streaming {} response",
            if prompt {
                "AgentPrompt"
            } else {
                "RunEntrypoint"
            }
        )
    })?;
    let outcome = CallOutcome {
        terminal: CallTerminal::from_event(&terminal),
        capture: Some(CaptureReport {
            recorded,
            divergence,
        }),
    };
    observer.call_finished(vm_name, &outcome);
    Ok(outcome)
}

/// Open this VM's host→guest stdin route under `admitted` and start pumping
/// `reader` into it.
///
/// Everything that decides whether this may happen is below
/// [`StreamPlane::open_input`](mvm_hostd::stream::StreamPlane::open_input) —
/// the grant on the signed plan, the single-writer lease, the chain-signed
/// record — so a refusal here is a decision already made and logged.
///
/// # Errors
/// No stream plane in this process, or the input gate refused the writer.
pub fn open_streamed_stdin(
    vm_name: &str,
    admitted: &AdmittedPlan,
    reader: Box<dyn Read + Send>,
) -> Result<StdinStream> {
    let plane = mvm_hostd::stream::host_stream_plane().context(
        "this process holds no workload stream plane, so there is no route to open into \
         the workload's stdin",
    )?;
    plane
        .open_input(
            vm_name,
            admitted,
            Box::new(mvm_hostd::stream::VsockInput::new(vm_name)),
        )
        .map_err(|refusal| {
            anyhow::anyhow!("the workload input gate refused this writer: {refusal}")
        })?;
    Ok(StdinStream::start(
        std::sync::Arc::new(PlaneInput::new(plane, vm_name)),
        reader,
    ))
}

/// The workload launch env that routes egress through the active vsock path:
/// the substitution endpoint's env for a secret-bearing workload, the
/// guest-local SOCKS5 client for a plain one with vsock egress, and nothing
/// when the VM has neither.
#[must_use]
pub fn workload_egress_env(vm_name: &str) -> Vec<(String, String)> {
    mvm_hostd::workload_env::workload_egress_env(vm_name)
}

/// Register the process's workload output capture, once.
///
/// A process that starts workloads installs it before its first boot, so the
/// VMs it starts are captured and a call can stream stdin into them. Returns
/// whether this call installed it; later calls are no-ops.
pub fn install_output_capture() -> bool {
    mvm_hostd::stream::install_host_console_streamer()
}

/// A [`CallObserver`] that keeps a call's output for a caller that answers
/// once, bounded per channel.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    /// The workload's stdout.
    pub stdout: Vec<u8>,
    /// The workload's stderr, with any trace-channel chunk.
    pub stderr: Vec<u8>,
    /// Output past [`CapturedOutput::CAP`] on either channel was dropped.
    pub truncated: bool,
}

impl CapturedOutput {
    /// The most of each channel kept. A function's result is decoded whole by
    /// the caller, which refuses one this large anyway; past it the rest is
    /// dropped and `truncated` says so, rather than growing without bound.
    pub const CAP: usize = 16 * 1024 * 1024;

    fn push(buffer: &mut Vec<u8>, truncated: &mut bool, bytes: &[u8]) {
        let room = Self::CAP.saturating_sub(buffer.len());
        if bytes.len() > room {
            *truncated = true;
        }
        buffer.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
}

impl CallObserver for CapturedOutput {
    fn output(&mut self, chunk: &ShownChunk) {
        match chunk.kind {
            StreamKind::Stdout => Self::push(&mut self.stdout, &mut self.truncated, &chunk.body),
            StreamKind::Stderr | StreamKind::Trace => {
                Self::push(&mut self.stderr, &mut self.truncated, &chunk.body);
            }
            // Entrypoint capture never produces frame chunks.
            StreamKind::Frame => {}
        }
    }

    fn control(&mut self, _header: &str, _payload_len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_exit_keeps_its_code() {
        assert_eq!(
            CallTerminal::from_event(&EntrypointEvent::Exit { code: 0 }).exit_code(),
            0
        );
        assert_eq!(
            CallTerminal::from_event(&EntrypointEvent::Exit { code: 7 }).exit_code(),
            7
        );
    }

    fn failed(kind: RunEntrypointError) -> CallTerminal {
        CallTerminal::from_event(&EntrypointEvent::Error {
            kind,
            message: "x".into(),
        })
    }

    #[test]
    fn agent_failures_map_to_their_conventional_statuses() {
        assert_eq!(failed(RunEntrypointError::Timeout).exit_code(), 124);
        assert_eq!(failed(RunEntrypointError::WrapperCrashed).exit_code(), 137);
        assert_eq!(failed(RunEntrypointError::Canceled).exit_code(), 130);
        assert_eq!(failed(RunEntrypointError::SessionKilled).exit_code(), 142);
        assert_eq!(failed(RunEntrypointError::NotReady).exit_code(), 75);
        for kind in [
            RunEntrypointError::Busy,
            RunEntrypointError::PayloadCap,
            RunEntrypointError::EntrypointInvalid,
            RunEntrypointError::InternalError,
        ] {
            assert_eq!(failed(kind).exit_code(), 1, "{kind:?}");
        }
    }

    #[test]
    fn a_non_terminal_event_is_an_internal_error() {
        let terminal = CallTerminal::from_event(&EntrypointEvent::Stdout { chunk: vec![1] });
        assert_eq!(terminal.exit_code(), 1);
        assert_eq!(terminal.label(), Some("internal error"));
    }

    #[test]
    fn only_an_agent_ended_call_has_a_label() {
        assert_eq!(CallTerminal::Exited { code: 3 }.label(), None);
        assert_eq!(failed(RunEntrypointError::Timeout).label(), Some("timeout"));
    }

    #[test]
    fn an_empty_payload_becomes_the_no_argument_call() {
        assert_eq!(one_shot_payload(Vec::new()), NO_ARGUMENT_PAYLOAD);
        assert_eq!(one_shot_payload(b"[[1], {}]".to_vec()), b"[[1], {}]");
    }

    #[test]
    fn a_payload_that_fits_one_frame_travels_in_it() {
        let stdin = CallStdin::for_payload(vec![b'x'; ONE_SHOT_PAYLOAD_LIMIT]);
        assert!(!stdin.is_streaming());
    }

    #[test]
    fn a_payload_past_one_frame_streams_rather_than_being_cut_short() {
        let stdin = CallStdin::for_payload(vec![b'x'; ONE_SHOT_PAYLOAD_LIMIT + 1]);
        assert!(stdin.is_streaming());
    }

    #[test]
    fn the_one_shot_limit_fits_the_frame_after_json_expansion() {
        // A byte array crosses the frame as decimal integers, up to four bytes
        // each; the limit must leave room for the rest of the request.
        let request = GuestRequest::RunEntrypoint {
            stdin: vec![0xFF; ONE_SHOT_PAYLOAD_LIMIT],
            timeout_secs: u64::MAX,
            env: mvm_core::guest_netd::proxy_env_vars(
                mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN,
            ),
            stream_input: false,
        };
        let body = serde_json::to_vec(&request).expect("encodes");
        assert!(
            body.len() <= mvm_agentd::vsock::MAX_FRAME_SIZE,
            "{} bytes",
            body.len()
        );
    }

    #[test]
    fn the_largest_prompt_fits_the_frame_after_json_expansion() {
        let request = GuestRequest::AgentPrompt {
            prompt: vec![0xFF; crate::agent_prompt::MAX_PROMPT_BYTES],
            timeout_secs: u64::MAX,
            env: mvm_core::guest_netd::proxy_env_vars(
                mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN,
            ),
        };
        let body = serde_json::to_vec(&request).expect("encodes");
        assert!(
            body.len() <= mvm_agentd::vsock::MAX_FRAME_SIZE,
            "{} bytes",
            body.len()
        );
    }

    #[test]
    fn a_one_shot_payload_needs_nothing_from_the_boot() {
        match authorize_stdin(CallStdin::OneShot(b"[[], {}]".to_vec()), None) {
            Ok(DispatchStdin::OneShot(bytes)) => assert_eq!(bytes, b"[[], {}]"),
            Ok(DispatchStdin::Streaming { .. }) => panic!("a one-shot call must not stream"),
            Ok(DispatchStdin::Prompt(_)) => panic!("a function call is not a prompt"),
            Err(e) => panic!("a one-shot payload asks for no authority: {e:#}"),
        }
    }

    #[test]
    fn an_unadmitted_boot_refuses_a_streamed_stdin() {
        let stdin = CallStdin::Streaming(Box::new(std::io::empty()));
        let Err(error) = authorize_stdin(stdin, None) else {
            panic!("an unadmitted boot has no grant to write under");
        };
        assert!(format!("{error:#}").contains("admitted plan"));
    }

    #[derive(Default)]
    struct Recording {
        output: Vec<(StreamKind, Vec<u8>)>,
        control: Vec<(String, usize)>,
    }

    impl CallObserver for Recording {
        fn output(&mut self, chunk: &ShownChunk) {
            self.output.push((chunk.kind, chunk.body.clone()));
        }
        fn control(&mut self, header: &str, payload_len: usize) {
            self.control.push((header.to_string(), payload_len));
        }
    }

    #[test]
    fn events_reach_the_observer_on_their_own_channels() {
        let mut capture = EntrypointSink::unrecorded();
        let mut divergence = RecordedDivergence::default();
        let mut observer = Recording::default();
        for event in [
            EntrypointEvent::Stdout {
                chunk: b"out".to_vec(),
            },
            EntrypointEvent::Stderr {
                chunk: b"err".to_vec(),
            },
            EntrypointEvent::Control {
                header_json: r#"{"event":"ready"}"#.into(),
                payload: vec![1, 2, 3],
            },
            EntrypointEvent::Exit { code: 0 },
        ] {
            route_event(&event, &mut capture, &mut divergence, &mut observer);
        }
        assert_eq!(
            observer.output,
            vec![
                (StreamKind::Stdout, b"out".to_vec()),
                (StreamKind::Stderr, b"err".to_vec())
            ]
        );
        assert_eq!(
            observer.control,
            vec![(r#"{"event":"ready"}"#.to_string(), 3)]
        );
        // An unrecorded sink answers every frame `NotRecorded`.
        assert_eq!(divergence.dropped_chunks, 3);
    }

    #[test]
    fn divergence_counts_masks_and_withholds_and_names_rules_once() {
        let mut divergence = RecordedDivergence::default();
        assert!(divergence.is_clean());
        divergence.note(&RecordedCopy::Identical);
        assert!(divergence.is_clean());
        divergence.note(&RecordedCopy::Masked {
            rules_fired: vec!["email", "credit_card"],
        });
        divergence.note(&RecordedCopy::Masked {
            rules_fired: vec!["email"],
        });
        divergence.note(&RecordedCopy::Withheld {
            reason: "detector".into(),
        });
        assert_eq!(divergence.masked_chunks, 2);
        assert_eq!(divergence.withheld_chunks, 1);
        assert_eq!(
            divergence.rules_fired.iter().copied().collect::<Vec<_>>(),
            vec!["credit_card", "email"]
        );
        assert!(!divergence.is_clean());
    }

    #[test]
    fn captured_output_is_bounded_per_channel_and_says_so() {
        let mut out = CapturedOutput::default();
        let big = vec![b'x'; CapturedOutput::CAP];
        out.output(&ShownChunk {
            kind: StreamKind::Stdout,
            body: big,
            recorded: RecordedCopy::NotRecorded,
        });
        assert!(!out.truncated);
        out.output(&ShownChunk {
            kind: StreamKind::Stdout,
            body: b"more".to_vec(),
            recorded: RecordedCopy::NotRecorded,
        });
        assert!(out.truncated);
        assert_eq!(out.stdout.len(), CapturedOutput::CAP);
        out.output(&ShownChunk {
            kind: StreamKind::Trace,
            body: b"trace".to_vec(),
            recorded: RecordedCopy::NotRecorded,
        });
        assert_eq!(out.stderr, b"trace");
    }

    #[test]
    fn a_dispatch_into_a_machine_that_does_not_exist_fails_without_panicking() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let mut observer = CapturedOutput::default();
        let result = dispatch(
            EntrypointDispatch {
                vm_name: "no-such-entrypoint-vm",
                stdin: DispatchStdin::OneShot(NO_ARGUMENT_PAYLOAD.to_vec()),
                timeout_secs: 1,
                session_id: None,
            },
            &mut observer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_transport_drop_under_a_killed_session_is_reported_as_the_kill() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let mut record = mvm_core::session::SessionRecord::new_running(
            "killed-session-vm",
            "wl",
            mvm_core::session::SessionMode::Prod,
        );
        record.state = SessionState::Killed;
        mvm_core::session::write_session(&record).expect("write record");

        #[derive(Default)]
        struct Finished(Option<CallOutcome>);
        impl CallObserver for Finished {
            fn output(&mut self, _: &ShownChunk) {}
            fn control(&mut self, _: &str, _: usize) {}
            fn call_finished(&mut self, _: &str, outcome: &CallOutcome) {
                self.0 = Some(outcome.clone());
            }
        }
        let mut observer = Finished::default();
        let outcome = dispatch(
            EntrypointDispatch {
                vm_name: "killed-session-vm",
                stdin: DispatchStdin::OneShot(NO_ARGUMENT_PAYLOAD.to_vec()),
                timeout_secs: 1,
                session_id: Some(&record.id),
            },
            &mut observer,
        )
        .expect("a killed session is an outcome, not an error");
        assert_eq!(outcome.exit_code(), 142);
        assert_eq!(outcome.capture, None);
        assert_eq!(observer.0, Some(outcome));
    }
}
