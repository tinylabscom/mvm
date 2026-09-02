//! Contract-checked RPC client: enforces each verb's declared
//! `ResponseContract` on the reply, plus the higher-level streaming
//! call helpers (`RunEntrypoint`, `Exec`, `RunDetached`) built on it.

use std::os::unix::net::UnixStream;

use anyhow::{Result, bail};
use mvm_contract::stream::input::{CloseInput, InputFrame};
use mvm_core::security::AgentProfile;

use super::*;

/// Failure of a contract-checked guest RPC call.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Transport / framing / serialization failure.
    #[error("guest agent transport error: {0}")]
    Transport(#[from] anyhow::Error),
    /// The agent answered with the universal `Error { message }`.
    #[error("guest agent returned error: {0}")]
    Agent(String),
    /// The agent refused the verb for its active profile (e.g. a dev-only
    /// verb on a sealed-prod agent).
    #[error("verb {verb} unsupported in agent profile {profile:?}")]
    UnsupportedInProfile {
        /// Profile the agent is running under.
        profile: AgentProfile,
        /// `verb_name()` of the rejected request.
        verb: String,
    },
    /// The pinned verb grant does not authorize this verb.
    #[error("verb {verb} not authorized by the session's verb grant")]
    VerbNotAuthorized {
        /// `kind_name()` (kebab-case) of the rejected request.
        verb: String,
    },
    /// The agent refused to spawn workload code because it is still uid 0.
    /// Indicates a boot path that never reached the privilege drop, not a
    /// policy decision about this particular caller.
    #[error(
        "guest agent refused {verb}: it is still running as uid {uid}, so the workload \
         would have run as root. The agent never reached its privilege drop."
    )]
    WorkloadPrivilegeRefused {
        /// `kind_name()` (kebab-case) of the refused request.
        verb: String,
        /// The uid the agent was serving under.
        uid: u32,
    },
    /// The agent returned a response variant not in the verb's
    /// `response_contract()` — a protocol violation.
    #[error("guest agent returned {got:?} for {verb}, not in its contract {expected:?}")]
    OffContract {
        /// The request verb whose contract was violated.
        verb: &'static str,
        /// The variant the agent actually sent.
        got: ResponseVariant,
        /// The variant(s) the contract permits.
        expected: &'static [ResponseVariant],
    },
}

struct RpcSession {
    #[cfg(not(test))]
    inner: AuthenticatedSession,
}

/// An authenticated control session that can carry multiple RPCs when the
/// peer keeps the connection open. The guest agent's production control
/// listener closes after one operational request, so callers that cross a
/// restore boundary must obtain a new stream and handshake.
pub struct ControlSession {
    inner: RpcSession,
}

impl ControlSession {
    /// Open the authenticated session on an already-connected control stream.
    pub fn open(stream: &mut UnixStream) -> Result<Self> {
        Ok(Self {
            inner: RpcSession::open(stream)?,
        })
    }

    /// Send one unary request on this session and return its checked response.
    pub fn call_unary(
        &mut self,
        stream: &mut UnixStream,
        req: &GuestRequest,
    ) -> Result<GuestResponse, RpcError> {
        self.inner.write(stream, req)?;
        let resp = self.inner.read(stream)?;
        check_response(req, resp)
    }

    /// Send one streaming request on this session and consume frames through
    /// its terminal response.
    pub fn call_streaming(
        &mut self,
        stream: &mut UnixStream,
        req: &GuestRequest,
        mut on_event: impl FnMut(&GuestResponse),
    ) -> Result<(), RpcError> {
        self.inner.write(stream, req)?;
        let mut frame = check_response(req, self.inner.read(stream)?)?;
        loop {
            on_event(&frame);
            if frame.is_stream_terminal() {
                return Ok(());
            }
            frame = check_response(req, self.inner.read(stream)?)?;
        }
    }
}

impl RpcSession {
    fn open(stream: &mut UnixStream) -> Result<Self> {
        #[cfg(test)]
        {
            let _ = stream;
            Ok(Self {})
        }
        #[cfg(not(test))]
        {
            Ok(Self {
                inner: connection::open_authenticated_session(stream)?,
            })
        }
    }

    fn write<T: serde::Serialize>(&mut self, stream: &mut UnixStream, value: &T) -> Result<()> {
        #[cfg(test)]
        {
            write_frame(stream, value)
        }
        #[cfg(not(test))]
        {
            self.inner.write(stream, value)
        }
    }

    fn read<T: serde::de::DeserializeOwned>(&mut self, stream: &mut UnixStream) -> Result<T> {
        #[cfg(test)]
        {
            read_frame(stream)
        }
        #[cfg(not(test))]
        {
            self.inner.read(stream)
        }
    }
}
/// Enforce `req`'s response contract on a received frame. Returns the frame
/// unchanged when it satisfies the contract; maps the universal `Error` /
/// `UnsupportedInProfile` responses and any off-contract variant to
/// [`RpcError`].
pub fn check_response(req: &GuestRequest, resp: GuestResponse) -> Result<GuestResponse, RpcError> {
    match resp {
        GuestResponse::Error { message } => Err(RpcError::Agent(message)),
        GuestResponse::UnsupportedInProfile { profile, verb } => {
            Err(RpcError::UnsupportedInProfile { profile, verb })
        }
        GuestResponse::VerbNotAuthorized { verb } => Err(RpcError::VerbNotAuthorized { verb }),
        GuestResponse::WorkloadPrivilegeRefused { verb, uid } => {
            Err(RpcError::WorkloadPrivilegeRefused { verb, uid })
        }
        other => {
            let got = other.variant();
            let contract = req.response_contract();
            if contract.responses.contains(&got) {
                Ok(other)
            } else {
                Err(RpcError::OffContract {
                    verb: req.verb().name(),
                    got,
                    expected: contract.responses,
                })
            }
        }
    }
}

/// Send a unary request and return its contract-checked response. Use for
/// verbs whose [`ResponseKind`] is `Unary`; streaming verbs use
/// [`call_streaming`].
pub fn call_unary(stream: &mut UnixStream, req: &GuestRequest) -> Result<GuestResponse, RpcError> {
    let mut session = ControlSession::open(stream)?;
    session.call_unary(stream, req)
}

/// Drive a streaming request: send `req`, then invoke `on_event` for each
/// contract-checked response frame until a terminal one
/// ([`GuestResponse::is_stream_terminal`]) arrives. A universal `Error` /
/// `UnsupportedInProfile` frame ends the stream as an `Err`.
pub fn call_streaming(
    stream: &mut UnixStream,
    req: &GuestRequest,
    on_event: impl FnMut(&GuestResponse),
) -> Result<(), RpcError> {
    let mut session = ControlSession::open(stream)?;
    session.call_streaming(stream, req, on_event)
}
/// Prove that a guest agent is serving RPCs on `stream`.
///
/// A bound socket is not a live agent. The host-side VMM binds the agent port
/// before the guest kernel starts, so `connect()` keeps succeeding for the whole
/// of the guest's boot — and succeeds just as well for a guest that panicked
/// before userspace. Readiness therefore has to be settled on the wire, which is
/// what this does: the authenticated session handshake plus one `Ping`, both real
/// I/O against the guest.
///
/// Any answer means ready. A refusal (`Error`, an unsupported profile, a verb the
/// session's grant withholds) still came from an agent that parsed, verified and
/// replied to an authenticated frame, so the caller's next RPC reaches it too.
/// Only a transport failure — EOF, timeout, a frame that won't decode — means
/// "not yet"; callers poll on `Err`.
///
/// Unlike [`negotiate_protocol`], this is never satisfied by a host-local check:
/// a probe that answers without touching the stream cannot tell a booting guest
/// from a serving one.
pub fn probe_agent_ready(stream: &mut UnixStream) -> Result<()> {
    let mut session = connection::open_authenticated_session(stream)?;
    session.write(stream, &GuestRequest::Ping)?;
    let _: GuestResponse = session.read(stream)?;
    Ok(())
}

/// Validate guest-agent protocol version and capabilities on an
/// already-connected control stream.
///
/// This helper is intentionally stream-level so it works with both the
/// Firecracker UDS multiplexer path and Apple Container's direct vsock
/// stream. The authenticated session handshake is performed when the RPC
/// session is opened and is the security boundary for every backend. The
/// `ProtocolHello` request remains a compatibility-level capability check for
/// test transports and older callers; production sessions validate the same
/// capability set locally after the secure handshake.
pub fn negotiate_protocol(
    stream: &mut UnixStream,
    requested_capabilities: Vec<GuestCapability>,
) -> Result<ProtocolNegotiation> {
    #[cfg(test)]
    {
        negotiate_protocol_test(stream, requested_capabilities)
    }

    #[cfg(not(test))]
    {
        negotiate_protocol_authenticated(stream, requested_capabilities)
    }
}

#[cfg(test)]
fn negotiate_protocol_test(
    stream: &mut UnixStream,
    requested_capabilities: Vec<GuestCapability>,
) -> Result<ProtocolNegotiation> {
    let mut session = RpcSession::open(stream)?;
    session.write(
        stream,
        &GuestRequest::ProtocolHello {
            host_protocol_version: PROTOCOL_VERSION,
            min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            host_version: env!("CARGO_PKG_VERSION").to_string(),
            requested_capabilities,
        },
    )?;
    match session.read(stream)? {
        GuestResponse::ProtocolHelloAck {
            agent_protocol_version,
            min_supported_version,
            agent_version,
            capabilities,
        } => Ok(ProtocolNegotiation {
            agent_protocol_version,
            min_supported_version,
            agent_version,
            capabilities,
        }),
        GuestResponse::ProtocolMismatch {
            required_action,
            message,
            ..
        } => bail!("guest-agent protocol mismatch ({required_action:?}): {message}"),
        GuestResponse::Error { message } => {
            bail!("guest-agent protocol negotiation error: {message}")
        }
        other => bail!("unexpected response to ProtocolHello: {other:?}"),
    }
}

#[cfg(not(test))]
fn negotiate_protocol_authenticated(
    _stream: &mut UnixStream,
    requested_capabilities: Vec<GuestCapability>,
) -> Result<ProtocolNegotiation> {
    let capabilities = supported_capabilities();
    let missing: Vec<_> = requested_capabilities
        .iter()
        .copied()
        .filter(|cap| !capabilities.contains(cap))
        .collect();
    if !missing.is_empty() {
        bail!("guest-agent missing required capabilities: {missing:?}");
    }
    Ok(ProtocolNegotiation {
        agent_protocol_version: PROTOCOL_VERSION,
        min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: requested_capabilities,
    })
}

/// Negotiate the guest-agent protocol and fail if any mandatory
/// capability is missing.
pub fn require_capabilities(
    stream: &mut UnixStream,
    required_capabilities: &[GuestCapability],
) -> Result<ProtocolNegotiation> {
    let negotiated = negotiate_protocol(stream, required_capabilities.to_vec())?;
    let missing: Vec<_> = required_capabilities
        .iter()
        .copied()
        .filter(|cap| !negotiated.capabilities.contains(cap))
        .collect();

    if !missing.is_empty() {
        bail!("guest-agent missing required capabilities: {missing:?}");
    }

    Ok(negotiated)
}
/// One `RunEntrypoint` call as a value.
///
/// Grouped rather than passed positionally because the fields are all
/// caller-supplied policy for the same call, and `stream_input` is the kind of
/// trailing `bool` that reads as noise at a call site until it is named.
#[derive(Debug, Clone, Default)]
pub struct RunEntrypointCall {
    /// Bytes piped to the wrapper's stdin before the call starts.
    pub stdin: Vec<u8>,
    /// Wall-clock budget for the call.
    pub timeout_secs: u64,
    /// Env injected into the workload after `env_clear()`.
    pub env: Vec<(String, String)>,
    /// Keep the workload's stdin open for `StreamInput` frames. Only a plan
    /// carrying the input grant gets this; see `mvm_hostd::stream::InputGate`.
    pub stream_input: bool,
}

/// Deliver one gate-admitted input frame to the workload's stdin.
///
/// One RPC per frame, and deliberately so: the guest's production control
/// listener answers one operational request per connection, so a caller that
/// waits for each answer before offering the next is the only shape in which
/// arrival order at the guest is the order the gate accepted. Batching or
/// pipelining would put that ordering at the mercy of the transport, and the
/// gate's secret scan is defined over acceptance order.
pub fn send_stream_input(
    stream: &mut UnixStream,
    frame: InputFrame,
) -> Result<StreamInputResult, RpcError> {
    stream_input_result(stream, GuestRequest::StreamInput(frame))
}

/// Deliver the tail the gate withheld and close the workload's stdin.
pub fn send_close_stream_input(
    stream: &mut UnixStream,
    close: CloseInput,
) -> Result<StreamInputResult, RpcError> {
    stream_input_result(stream, GuestRequest::CloseStreamInput(close))
}

fn stream_input_result(
    stream: &mut UnixStream,
    req: GuestRequest,
) -> Result<StreamInputResult, RpcError> {
    match call_unary(stream, &req)? {
        GuestResponse::StreamInputResult(result) => Ok(result),
        // `check_response` already enforced the contract, which names this
        // variant and no other.
        other => Err(RpcError::OffContract {
            verb: req.verb().name(),
            got: other.variant(),
            expected: req.response_contract().responses,
        }),
    }
}

/// Send a `RunEntrypoint` request and consume the streaming
/// `EntrypointEvent` response.
///
/// `on_event` is invoked for each non-terminal event (`Stdout` /
/// `Stderr` chunk) as it arrives — callers can stream output to their
/// own stdout/stderr without buffering. Returns the terminal event
/// (`Exit` or `Error`) for the caller to inspect.
///
/// The wire format is an authenticated, encrypted session carrying bounded
/// length-prefixed JSON envelopes. Output may span multiple frames;
/// termination is detected via [`EntrypointEvent::is_terminal`], not frame
/// count.
pub fn send_run_entrypoint<F>(
    stream: &mut UnixStream,
    call: RunEntrypointCall,
    on_event: F,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
{
    send_run_entrypoint_while(stream, call, on_event, || true)
}

/// How long a silent entrypoint stream is left alone before the caller's
/// liveness check is consulted.
///
/// Not a timeout on the workload: a build or a test run is legitimately quiet
/// for minutes. It is only how often "is the guest still there" gets asked.
const ENTRYPOINT_LIVENESS_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// [`send_run_entrypoint`], but giving up when the guest is gone.
///
/// The plain loop blocks in `read` forever if the guest dies mid-stream: the
/// host-side socket stays open, so no EOF ever arrives and `mvmctl machine run`
/// sits in `epoll` indefinitely. Observed on a KVM host as a 25-minute
/// `machine run --image alpine -- /bin/echo` with no VM alive, and `--timeout`
/// could not save it — that bounds the command *inside* the guest, so a guest
/// that never runs one is never bounded at all.
///
/// `still_alive` is polled only when the stream has been quiet for
/// [`ENTRYPOINT_LIVENESS_POLL`], so a long silent workload is unaffected: the
/// check costs nothing while output flows, and only decides the case where
/// nothing is coming because nothing is left to send it.
pub fn send_run_entrypoint_while<F, L>(
    stream: &mut UnixStream,
    call: RunEntrypointCall,
    mut on_event: F,
    mut still_alive: L,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
    L: FnMut() -> bool,
{
    require_capabilities(stream, &[GuestCapability::RunEntrypoint])?;
    let RunEntrypointCall {
        stdin,
        timeout_secs,
        env,
        stream_input,
    } = call;
    let req = GuestRequest::RunEntrypoint {
        stdin,
        timeout_secs,
        env,
        stream_input,
    };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &req)?;

    // Restored before returning: the caller may keep using this stream, and a
    // read timeout left behind would turn its next blocking read into a
    // spurious failure.
    let previous_timeout = stream.read_timeout().ok().flatten();
    let _ = stream.set_read_timeout(Some(ENTRYPOINT_LIVENESS_POLL));

    let outcome = loop {
        let resp: GuestResponse = match session.read(stream) {
            Ok(resp) => resp,
            Err(error) if is_read_timeout(&error) => {
                if still_alive() {
                    continue;
                }
                break Err(anyhow::anyhow!(
                    "the guest exited without reporting a result — no VM process is \
                     alive for this run. The entrypoint stream went quiet and stayed \
                     quiet; waiting longer cannot help."
                ));
            }
            Err(error) => break Err(error),
        };
        let event = match resp {
            GuestResponse::EntrypointEvent(e) => e,
            GuestResponse::Error { message } => {
                break Err(anyhow::anyhow!("guest agent error: {message}"));
            }
            GuestResponse::WorkloadPrivilegeRefused { verb, uid } => {
                break Err(RpcError::WorkloadPrivilegeRefused { verb, uid }.into());
            }
            other => {
                break Err(anyhow::anyhow!(
                    "expected EntrypointEvent during RunEntrypoint stream, got {other:?}"
                ));
            }
        };
        if event.is_terminal() {
            break Ok(event);
        }
        on_event(&event);
    };

    let _ = stream.set_read_timeout(previous_timeout);
    outcome
}

/// Whether an error is the read timeout this loop sets, rather than a real
/// transport failure. Platforms differ: Linux reports `WouldBlock`, others
/// `TimedOut`.
fn is_read_timeout(error: &anyhow::Error) -> bool {
    // The kind test itself lives in `connection`, which already had it for the
    // connect retry loop. Only the chain walk is new: `session.read` returns an
    // `anyhow::Error` that has usually been given context by the time it
    // arrives here, so the `io::Error` is a cause rather than the error.
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .is_some_and(super::connection::is_timeout_error)
}

/// Dispatch one exact admitted optional extension and consume its bounded
/// output stream.
pub fn send_run_extension<F>(
    stream: &mut UnixStream,
    dispatch: ExtensionDispatch,
    mut on_event: F,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
{
    require_capabilities(stream, &[GuestCapability::RunExtension])?;
    let request = GuestRequest::RunExtension { dispatch };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &request)?;
    loop {
        let response: GuestResponse = session.read(stream)?;
        let event = match response {
            GuestResponse::EntrypointEvent(event) => event,
            GuestResponse::Error { message } => bail!("guest agent error: {message}"),
            GuestResponse::WorkloadPrivilegeRefused { verb, uid } => {
                return Err(RpcError::WorkloadPrivilegeRefused { verb, uid }.into());
            }
            other => bail!("expected extension EntrypointEvent stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}

/// Cancel one exact active optional-extension invocation.
pub fn send_cancel_extension(
    stream: &mut UnixStream,
    cancellation: ExtensionCancellation,
) -> Result<()> {
    require_capabilities(stream, &[GuestCapability::RunExtension])?;
    let request = GuestRequest::CancelExtension { cancellation };
    match call_unary(stream, &request)? {
        GuestResponse::ExtensionCancellationAck => Ok(()),
        other => bail!("expected extension cancellation acknowledgement, got {other:?}"),
    }
}

/// Send an `Exec` request and stream its response. Invokes `on_event`
/// for each `Stdout`/`Stderr` chunk as it arrives; returns the terminal
/// `Exit` or `TimedOut`. The guest agent applies its runtime profile and
/// signed-grant gate after protocol authentication.
pub fn send_exec_streaming<F>(
    stream: &mut UnixStream,
    command: &str,
    stdin: Option<String>,
    timeout_secs: Option<u64>,
    on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::Exec {
        command: command.to_string(),
        stdin,
        timeout_secs,
    };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &req)?;
    read_exec_stream_with_session(stream, &mut session, on_event)
}

/// Send a `RunCode` request and stream its authenticated response.
pub fn send_run_code_streaming<F>(
    stream: &mut UnixStream,
    code: &str,
    timeout_secs: Option<u64>,
    on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::RunCode {
        code: code.to_string(),
        timeout_secs,
    };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &req)?;
    read_exec_stream_with_session(stream, &mut session, on_event)
}

/// Send a `RunDetached` request and read its single `DetachedStarted`
/// ack, returning the detached workload's guest PID.
///
/// Non-streaming: the workload runs independently of this connection, so
/// there is exactly one response frame. Its exit is reported to the
/// host's workload-exit port by the agent's reaper, not over this
/// stream. Like `Exec`, `RunDetached` is admitted by the guest agent's
/// runtime profile and signed-grant gate after protocol authentication.
pub fn send_run_detached(
    stream: &mut UnixStream,
    argv: Vec<String>,
    env: Vec<(String, String)>,
) -> Result<i32> {
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::RunDetached { argv, env };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &req)?;
    let resp: GuestResponse = session.read(stream)?;
    match resp {
        GuestResponse::DetachedStarted { pid } => Ok(pid),
        GuestResponse::Error { message } => bail!("guest agent error: {message}"),
        GuestResponse::VerbNotAuthorized { verb } => {
            Err(RpcError::VerbNotAuthorized { verb }.into())
        }
        GuestResponse::WorkloadPrivilegeRefused { verb, uid } => {
            Err(RpcError::WorkloadPrivilegeRefused { verb, uid }.into())
        }
        other => bail!("expected DetachedStarted for RunDetached, got {other:?}"),
    }
}

/// Read an `ExecEvent` response stream from `stream`: invoke `on_event`
/// for each non-terminal chunk, return the terminal `Exit`. The caller
/// must have already done the protocol hello and written the request
/// frame (`Exec` or `RunCode` — both stream `ExecEvent`).
pub fn read_exec_stream<F>(stream: &mut UnixStream, on_event: F) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let mut session = RpcSession::open(stream)?;
    read_exec_stream_with_session(stream, &mut session, on_event)
}

fn read_exec_stream_with_session<F>(
    stream: &mut UnixStream,
    session: &mut RpcSession,
    mut on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    loop {
        let resp: GuestResponse = session.read(stream)?;
        let event = match resp {
            GuestResponse::ExecEvent(e) => e,
            GuestResponse::Error { message } => bail!("guest exec error: {message}"),
            // Surface a grant refusal as the typed RpcError (not a stringified
            // "unexpected variant") so the host can audit it as `verb_denied`.
            GuestResponse::VerbNotAuthorized { verb } => {
                return Err(RpcError::VerbNotAuthorized { verb }.into());
            }
            GuestResponse::WorkloadPrivilegeRefused { verb, uid } => {
                return Err(RpcError::WorkloadPrivilegeRefused { verb, uid }.into());
            }
            other => bail!("expected ExecEvent during exec stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}

#[cfg(test)]
mod tests {

    /// The timeout classifier decides whether a quiet stream consults the
    /// liveness probe or aborts the run. Misclassify a real transport error as
    /// a timeout and a dead connection spins forever; misclassify a timeout as
    /// an error and every quiet workload dies.
    #[test]
    fn read_timeouts_are_told_apart_from_real_errors() {
        use std::io::{Error, ErrorKind};

        for kind in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
            let error = anyhow::Error::from(Error::new(kind, "poll expired"));
            assert!(
                super::is_read_timeout(&error),
                "{kind:?} must read as the liveness poll expiring"
            );
        }

        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
        ] {
            let error = anyhow::Error::from(Error::new(kind, "gone"));
            assert!(
                !super::is_read_timeout(&error),
                "{kind:?} is a transport failure, not a poll expiry"
            );
        }
    }

    /// The classifier has to see through the context the RPC layer adds, or a
    /// wrapped timeout reads as a hard error and kills a healthy quiet run.
    #[test]
    fn a_wrapped_read_timeout_is_still_a_timeout() {
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "poll expired",
        ))
        .context("reading the entrypoint stream");
        assert!(super::is_read_timeout(&error));
    }

    #[test]
    fn a_plain_error_with_no_io_cause_is_not_a_timeout() {
        assert!(!super::is_read_timeout(&anyhow::anyhow!(
            "guest agent error"
        )));
    }
    use super::*;
    use rand::Rng;

    /// A plain call: no streamed input, so the guest closes stdin as soon as
    /// the payload is written.
    fn run_call(stdin: &[u8]) -> RunEntrypointCall {
        RunEntrypointCall {
            stdin: stdin.to_vec(),
            timeout_secs: 30,
            ..RunEntrypointCall::default()
        }
    }

    fn extension_cancellation() -> ExtensionCancellation {
        ExtensionCancellation {
            extension_id: mvm_contract::protocol::extension_pack::ExtensionId::parse(
                "org.example.extension",
            )
            .expect("extension id"),
            pack_digest: [1; 32],
            contract_digest: [2; 32],
            request_id: mvm_contract::assurance::AssuranceId::parse("request-1").expect("request"),
            session_id: mvm_contract::assurance::AssuranceId::parse("session-1").expect("session"),
            campaign_id: mvm_contract::assurance::AssuranceId::parse("campaign-1")
                .expect("campaign"),
            trial_id: mvm_contract::assurance::AssuranceId::parse("trial-1").expect("trial"),
            plan_id: mvm_contract::assurance::AssuranceId::parse(format!(
                "sha256-{}",
                "a".repeat(64)
            ))
            .expect("plan"),
            idempotency_key: mvm_contract::assurance::AssuranceId::parse("trial-1").expect("key"),
            grant_digest: mvm_contract::assurance::Sha256Digest::parse(format!(
                "sha256:{}",
                "b".repeat(64)
            ))
            .expect("grant"),
            nonce: mvm_contract::assurance::AssuranceId::parse("nonce-1").expect("nonce"),
        }
    }

    #[test]
    fn test_negotiate_protocol_round_trip_on_stream() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::ProtocolHello {
                    host_protocol_version,
                    min_supported_version,
                    host_version,
                    requested_capabilities,
                } => {
                    let resp = protocol_hello_response(
                        host_protocol_version,
                        min_supported_version,
                        &host_version,
                        &requested_capabilities,
                    );
                    write_frame(&mut guest, &resp).unwrap();
                }
                other => panic!("expected ProtocolHello, got {other:?}"),
            }
        });

        let negotiated = negotiate_protocol(
            &mut host,
            vec![GuestCapability::Ping, GuestCapability::FilesystemRpc],
        )
        .unwrap();

        guest_thread.join().unwrap();
        assert_eq!(negotiated.agent_protocol_version, PROTOCOL_VERSION);
        assert_eq!(
            negotiated.capabilities,
            vec![GuestCapability::Ping, GuestCapability::FilesystemRpc]
        );
    }

    #[test]
    fn test_negotiate_protocol_mismatch_is_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolMismatch {
                    host_protocol_version: PROTOCOL_VERSION + 1,
                    agent_protocol_version: PROTOCOL_VERSION,
                    required_action: ProtocolUpgradeAction::RebuildGuest,
                    message: "rebuild guest image".to_string(),
                },
            )
            .unwrap();
        });

        let err = negotiate_protocol(&mut host, vec![GuestCapability::Ping]).unwrap_err();
        guest_thread.join().unwrap();
        assert!(err.to_string().contains("protocol mismatch"));
        assert!(err.to_string().contains("rebuild guest image"));
    }

    #[test]
    fn extension_cancellation_round_trips_over_mock_io() {
        let (mut host, mut guest) = UnixStream::pair().expect("socket pair");
        let expected = extension_cancellation();
        let expected_by_guest = expected.clone();
        let guest_thread = std::thread::spawn(move || {
            let hello: GuestRequest = read_frame(&mut guest).expect("hello");
            let GuestRequest::ProtocolHello {
                host_protocol_version,
                min_supported_version,
                host_version,
                requested_capabilities,
            } = hello
            else {
                panic!("expected protocol hello");
            };
            let response = protocol_hello_response(
                host_protocol_version,
                min_supported_version,
                &host_version,
                &requested_capabilities,
            );
            write_frame(&mut guest, &response).expect("hello response");
            let request: GuestRequest = read_frame(&mut guest).expect("cancel request");
            assert!(matches!(
                request,
                GuestRequest::CancelExtension { cancellation }
                    if cancellation == expected_by_guest
            ));
            write_frame(&mut guest, &GuestResponse::ExtensionCancellationAck).expect("cancel ack");
        });

        send_cancel_extension(&mut host, expected).expect("cancel extension");
        guest_thread.join().expect("guest thread");
    }

    #[test]
    fn test_require_capabilities_accepts_present_capability() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::ProtocolHello {
                    host_protocol_version,
                    min_supported_version,
                    host_version,
                    requested_capabilities,
                } => {
                    let resp = protocol_hello_response(
                        host_protocol_version,
                        min_supported_version,
                        &host_version,
                        &requested_capabilities,
                    );
                    write_frame(&mut guest, &resp).unwrap();
                }
                other => panic!("expected ProtocolHello, got {other:?}"),
            }
        });

        let negotiated =
            require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap();

        guest_thread.join().unwrap();
        assert_eq!(
            negotiated.capabilities,
            vec![GuestCapability::FilesystemRpc]
        );
    }

    #[test]
    fn test_require_capabilities_rejects_missing_capability() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolHelloAck {
                    agent_protocol_version: PROTOCOL_VERSION,
                    min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                    agent_version: "0.1.0".to_string(),
                    capabilities: vec![GuestCapability::Ping],
                },
            )
            .unwrap();
        });

        let err = require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap_err();

        guest_thread.join().unwrap();
        assert!(err.to_string().contains("missing required capabilities"));
        assert!(err.to_string().contains("FilesystemRpc"));
    }

    #[test]
    fn test_require_capabilities_surfaces_protocol_mismatch() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolMismatch {
                    host_protocol_version: PROTOCOL_VERSION + 1,
                    agent_protocol_version: PROTOCOL_VERSION,
                    required_action: ProtocolUpgradeAction::RebuildGuest,
                    message: "guest image is stale".to_string(),
                },
            )
            .unwrap();
        });

        let err = require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap_err();

        guest_thread.join().unwrap();
        assert!(err.to_string().contains("protocol mismatch"));
        assert!(err.to_string().contains("guest image is stale"));
    }

    #[test]
    fn test_send_run_detached_returns_pid() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            // Hello prelude.
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::ProtocolHello {
                    host_protocol_version,
                    min_supported_version,
                    host_version,
                    requested_capabilities,
                } => {
                    let resp = protocol_hello_response(
                        host_protocol_version,
                        min_supported_version,
                        &host_version,
                        &requested_capabilities,
                    );
                    write_frame(&mut guest, &resp).unwrap();
                }
                other => panic!("expected ProtocolHello, got {other:?}"),
            }
            // The RunDetached frame, then ack with a pid.
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::RunDetached { argv, env } => {
                    assert_eq!(argv, vec!["/bin/echo", "hi"]);
                    assert_eq!(env, vec![("K".to_string(), "V".to_string())]);
                    write_frame(&mut guest, &GuestResponse::DetachedStarted { pid: 777 }).unwrap();
                }
                other => panic!("expected RunDetached, got {other:?}"),
            }
        });

        let pid = send_run_detached(
            &mut host,
            vec!["/bin/echo".into(), "hi".into()],
            vec![("K".into(), "V".into())],
        )
        .expect("send_run_detached should return the pid");
        guest_thread.join().unwrap();
        assert_eq!(pid, 777);
    }

    #[test]
    fn test_send_run_detached_maps_agent_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _hello: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolHelloAck {
                    agent_protocol_version: PROTOCOL_VERSION,
                    min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                    agent_version: "0.1.0".to_string(),
                    capabilities: vec![],
                },
            )
            .unwrap();
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::Error {
                    message: "spawn failed".to_string(),
                },
            )
            .unwrap();
        });

        let err = send_run_detached(&mut host, vec!["/bin/true".into()], vec![])
            .expect_err("agent Error must surface as a helper error");
        guest_thread.join().unwrap();
        assert!(err.to_string().contains("spawn failed"), "err: {err}");
    }

    // -------------------------------------------------------------------
    // send_run_entrypoint streaming consumer
    // -------------------------------------------------------------------

    fn write_event_frame(stream: &mut UnixStream, event: &EntrypointEvent) {
        write_frame(stream, &GuestResponse::EntrypointEvent(event.clone())).unwrap();
    }

    fn answer_run_entrypoint_protocol_hello(stream: &mut UnixStream) {
        let req: GuestRequest = read_frame(stream).unwrap();
        match req {
            GuestRequest::ProtocolHello {
                requested_capabilities,
                ..
            } => assert_eq!(requested_capabilities, vec![GuestCapability::RunEntrypoint]),
            other => panic!("expected ProtocolHello, got {other:?}"),
        }
        write_frame(
            stream,
            &GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "test-agent".to_string(),
                capabilities: vec![GuestCapability::RunEntrypoint],
            },
        )
        .unwrap();
    }

    #[test]
    fn test_send_run_entrypoint_collects_events_until_terminal() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest side: read the request, emit Stdout, Stderr, Exit.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            assert!(matches!(
                req,
                GuestRequest::RunEntrypoint {
                    timeout_secs: 30,
                    ..
                }
            ));
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"out".to_vec(),
                },
            );
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stderr {
                    chunk: b"err".to_vec(),
                },
            );
            write_event_frame(&mut guest, &EntrypointEvent::Exit { code: 0 });
        });

        let mut received: Vec<EntrypointEvent> = Vec::new();
        let terminal =
            send_run_entrypoint(&mut host, run_call(b"in"), |evt| received.push(evt.clone()))
                .expect("send_run_entrypoint");

        guest_handle.join().unwrap();

        assert_eq!(received.len(), 2);
        assert!(matches!(
            received[0],
            EntrypointEvent::Stdout { ref chunk } if chunk == b"out"
        ));
        assert!(matches!(
            received[1],
            EntrypointEvent::Stderr { ref chunk } if chunk == b"err"
        ));
        assert!(matches!(terminal, EntrypointEvent::Exit { code: 0 }));
    }

    #[test]
    fn test_send_run_entrypoint_terminates_on_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest side: emit one Stdout chunk, then a terminal Error.
        // The handler must observe the Stdout but stop reading after
        // Error.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"partial".to_vec(),
                },
            );
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Error {
                    kind: RunEntrypointError::Timeout,
                    message: "killed at 30s".into(),
                },
            );
            // Write a bogus extra frame after the terminal — the
            // consumer must not read it.
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"should-not-be-read".to_vec(),
                },
            );
        });

        let mut received: Vec<EntrypointEvent> = Vec::new();
        let terminal =
            send_run_entrypoint(&mut host, run_call(b""), |evt| received.push(evt.clone()))
                .expect("send_run_entrypoint");

        guest_handle.join().unwrap();

        assert_eq!(received.len(), 1);
        assert!(matches!(
            received[0],
            EntrypointEvent::Stdout { ref chunk } if chunk == b"partial"
        ));
        assert!(matches!(
            terminal,
            EntrypointEvent::Error {
                kind: RunEntrypointError::Timeout,
                ..
            }
        ));
    }

    #[test]
    fn test_send_run_entrypoint_rejects_unexpected_response() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest writes a Pong instead of an EntrypointEvent.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(&mut guest, &GuestResponse::Pong).unwrap();
        });

        let result = send_run_entrypoint(&mut host, run_call(b""), |_| {});
        guest_handle.join().unwrap();

        let err = result.expect_err("should reject Pong");
        assert!(
            err.to_string().contains("expected EntrypointEvent"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_send_run_entrypoint_surfaces_guest_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest writes a generic Error (not an EntrypointEvent::Error).
        // This shouldn't normally happen for RunEntrypoint, but the
        // host-side consumer should map it to a clear Result error.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::Error {
                    message: "agent panicked before dispatch".into(),
                },
            )
            .unwrap();
        });

        let result = send_run_entrypoint(&mut host, run_call(b""), |_| {});
        guest_handle.join().unwrap();

        let err = result.expect_err("should surface guest error");
        assert!(
            err.to_string().contains("agent panicked"),
            "unexpected error: {err}"
        );
    }

    // send_exec_streaming host reader
    // -------------------------------------------------------------------

    fn answer_exec_protocol_hello(stream: &mut UnixStream) {
        let req: GuestRequest = read_frame(stream).unwrap();
        match req {
            GuestRequest::ProtocolHello {
                requested_capabilities,
                ..
            } => assert_eq!(requested_capabilities, vec![]),
            other => panic!("expected ProtocolHello, got {other:?}"),
        }
        write_frame(
            stream,
            &GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "test-agent".to_string(),
                capabilities: vec![],
            },
        )
        .unwrap();
    }

    #[test]
    fn send_exec_streaming_collects_chunks_until_exit() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let guest_handle = std::thread::spawn(move || {
            answer_exec_protocol_hello(&mut guest);
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            assert!(matches!(req, GuestRequest::Exec { ref command,.. } if command == "echo hi"));
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Stdout {
                    chunk: b"hi\n".to_vec(),
                }),
            )
            .unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Exit { code: 0 }),
            )
            .unwrap();
        });

        let mut got: Vec<ExecEvent> = Vec::new();
        let terminal = send_exec_streaming(&mut host, "echo hi", None, Some(30), |e| {
            got.push(e.clone())
        })
        .expect("send_exec_streaming");
        guest_handle.join().unwrap();

        assert_eq!(got.len(), 1);
        assert!(matches!(got[0], ExecEvent::Stdout { ref chunk } if chunk == b"hi\n"));
        assert!(matches!(terminal, ExecEvent::Exit { code: 0 }));
    }

    #[test]
    fn read_exec_stream_collects_until_exit() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let guest_handle = std::thread::spawn(move || {
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Stderr {
                    chunk: b"e".to_vec(),
                }),
            )
            .unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Exit { code: 2 }),
            )
            .unwrap();
        });
        let mut got = Vec::new();
        let term = read_exec_stream(&mut host, |e| got.push(e.clone())).unwrap();
        guest_handle.join().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(got[0], ExecEvent::Stderr { ref chunk } if chunk == b"e"));
        assert!(matches!(term, ExecEvent::Exit { code: 2 }));
    }

    #[test]
    fn read_exec_stream_surfaces_root_refusal_as_typed_rpc_error() {
        // The no-root gate's refusal must reach the host as a typed, downcastable
        // error naming the uid — the operator's whole diagnosis is "the agent
        // never reached its privilege drop", which a stringified "unexpected
        // variant" would bury.
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let guest_handle = std::thread::spawn(move || {
            write_frame(
                &mut guest,
                &GuestResponse::WorkloadPrivilegeRefused {
                    verb: "exec".to_string(),
                    uid: 0,
                },
            )
            .unwrap();
        });
        let err = read_exec_stream(&mut host, |_| {}).unwrap_err();
        guest_handle.join().unwrap();
        match err.downcast_ref::<RpcError>() {
            Some(RpcError::WorkloadPrivilegeRefused { verb, uid }) => {
                assert_eq!(verb, "exec");
                assert_eq!(*uid, 0);
            }
            other => panic!("expected typed RpcError::WorkloadPrivilegeRefused, got {other:?}"),
        }
    }

    #[test]
    fn read_exec_stream_surfaces_verb_denied_as_typed_rpc_error() {
        // A grant refusal arriving on the exec stream must surface as the typed
        // RpcError::VerbNotAuthorized (downcastable) so the host can audit it as
        // `verb_denied` — not a stringified "unexpected variant".
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let guest_handle = std::thread::spawn(move || {
            write_frame(
                &mut guest,
                &GuestResponse::VerbNotAuthorized {
                    verb: "run-code".to_string(),
                },
            )
            .unwrap();
        });
        let err = read_exec_stream(&mut host, |_| {}).unwrap_err();
        guest_handle.join().unwrap();
        match err.downcast_ref::<RpcError>() {
            Some(RpcError::VerbNotAuthorized { verb }) => assert_eq!(verb, "run-code"),
            other => panic!("expected typed RpcError::VerbNotAuthorized, got {other:?}"),
        }
    }
    // ---- probe_agent_ready: readiness settled on the wire ----

    use ed25519_dalek::SigningKey;

    /// Seed a host signer key so `probe_agent_ready` can open its session, and
    /// return it for the guest side of the fixture to pin as its trust anchor.
    fn seeded_host_signer(home: &std::path::Path) -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let keys = mvm_core::config::mvm_keys_dir();
        assert!(
            keys.starts_with(home),
            "test must isolate MVM_HOME before seeding the host signer key"
        );
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    /// The regression this guards: a probe that reports "ready" without touching
    /// the stream cannot tell a serving agent from a socket the VMM bound before
    /// the guest kernel even started. A peer that accepts and closes must read as
    /// not-ready, so the caller keeps polling instead of issuing an RPC that dies
    /// on EOF.
    #[test]
    fn probe_agent_ready_rejects_a_peer_that_answers_nothing() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let _signer = seeded_host_signer(home.path());

        let (mut host, guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // Nothing is serving: the peer end is gone. That is what the host sees
        // from a socket the VMM bound for a guest still booting, or one that
        // panicked before its agent ever ran.
        drop(guest);

        // Which transport error surfaces is an OS-timing detail — the handshake
        // write may complete and the read then hit EOF, or the closed peer may
        // fail the write with EPIPE first. Both mean "no agent answered", which
        // is the whole property: the caller polls again instead of proceeding to
        // an RPC. Pinning either one passes on macOS and fails on Linux.
        let err = probe_agent_ready(&mut host).expect_err("a silent peer is not ready");
        assert!(
            !err.to_string().is_empty(),
            "a refusal must carry a diagnosable transport error: {err:#}"
        );
    }

    /// The positive case, against the real counterparty: a guest running the
    /// production `AuthenticatedSession` reads as ready.
    #[test]
    fn probe_agent_ready_accepts_a_guest_serving_the_authenticated_session() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let host_key = seeded_host_signer(home.path());
        let anchor = host_key.verifying_key();

        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let guest_thread = std::thread::spawn(move || {
            let mut guest_key_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut guest_key_seed);
            let mut session = AuthenticatedSession::guest(
                &mut guest,
                SigningKey::from_bytes(&guest_key_seed),
                &anchor,
            )
            .expect("guest handshake");
            let req: GuestRequest = session.read(&mut guest).expect("read probe request");
            assert!(matches!(req, GuestRequest::Ping), "got {req:?}");
            session
                .write(&mut guest, &GuestResponse::Pong)
                .expect("write pong");
        });

        probe_agent_ready(&mut host).expect("a serving agent must read as ready");
        guest_thread.join().unwrap();
    }

    // ---- check_response: the pure contract enforcer ----

    #[test]
    fn check_accepts_contracted_unary_response() {
        let ok = check_response(&GuestRequest::Ping, GuestResponse::Pong);
        assert!(matches!(ok, Ok(GuestResponse::Pong)));
    }

    #[test]
    fn check_accepts_either_protocol_hello_outcome() {
        let req = GuestRequest::ProtocolHello {
            host_protocol_version: 1,
            min_supported_version: 1,
            host_version: "t".into(),
            requested_capabilities: vec![],
        };
        let mismatch = GuestResponse::ProtocolMismatch {
            host_protocol_version: 1,
            agent_protocol_version: 2,
            required_action: ProtocolUpgradeAction::UpgradeHost,
            message: "x".into(),
        };
        assert!(check_response(&req, mismatch).is_ok());
    }

    #[test]
    fn check_maps_agent_error() {
        let err = check_response(
            &GuestRequest::Ping,
            GuestResponse::Error {
                message: "boom".into(),
            },
        );
        assert!(matches!(err, Err(RpcError::Agent(m)) if m == "boom"));
    }

    #[test]
    fn check_maps_unsupported_in_profile() {
        let resp = GuestResponse::UnsupportedInProfile {
            profile: AgentProfile::SealedProd,
            verb: "Exec".into(),
        };
        let err = check_response(&GuestRequest::Ping, resp);
        assert!(matches!(err, Err(RpcError::UnsupportedInProfile { verb,.. }) if verb == "Exec"));
    }

    #[test]
    fn check_rejects_off_contract_response() {
        // Ping's contract is [Pong]; a WorkerStatus answer is a protocol violation.
        let resp = GuestResponse::WorkerStatus {
            status: "idle".into(),
            last_busy_at: None,
        };
        let err = check_response(&GuestRequest::Ping, resp);
        assert!(matches!(
            err,
            Err(RpcError::OffContract {
                verb: "Ping",
                got: ResponseVariant::WorkerStatus,
                ..
            })
        ));
    }

    // ---- call_unary / call_streaming round-trip over a socket pair ----

    #[test]
    fn call_unary_round_trips_and_validates() {
        let (mut client, mut agent) = UnixStream::pair().unwrap();
        // Pre-write the agent's response; call_unary writes the request
        // (ignored on the agent side) then reads this frame back.
        write_frame(&mut agent, &GuestResponse::Pong).unwrap();
        let resp = call_unary(&mut client, &GuestRequest::Ping).unwrap();
        assert!(matches!(resp, GuestResponse::Pong));
    }

    #[test]
    fn call_unary_rejects_off_contract_agent() {
        let (mut client, mut agent) = UnixStream::pair().unwrap();
        write_frame(
            &mut agent,
            &GuestResponse::WorkerStatus {
                status: "idle".into(),
                last_busy_at: None,
            },
        )
        .unwrap();
        let err = call_unary(&mut client, &GuestRequest::Ping).unwrap_err();
        assert!(matches!(err, RpcError::OffContract { verb: "Ping", .. }));
    }

    #[test]
    fn call_streaming_yields_frames_until_terminal() {
        let (mut client, mut agent) = UnixStream::pair().unwrap();
        write_frame(
            &mut agent,
            &GuestResponse::EntrypointEvent(EntrypointEvent::Stdout {
                chunk: b"hi".to_vec(),
            }),
        )
        .unwrap();
        write_frame(
            &mut agent,
            &GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 0 }),
        )
        .unwrap();
        let req = GuestRequest::RunEntrypoint {
            stdin: vec![],
            timeout_secs: 5,
            env: vec![],
            stream_input: false,
        };
        let mut events = 0usize;
        call_streaming(&mut client, &req, |_e| events += 1).unwrap();
        assert_eq!(events, 2);
    }
}
