//! Contract-checked RPC client: enforces each verb's declared
//! `ResponseContract` on the reply, plus the higher-level streaming
//! call helpers (`RunEntrypoint`, `Exec`, `RunDetached`) built on it.

use std::os::unix::net::UnixStream;

use anyhow::{Result, bail};
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

/// An authenticated control session that can carry multiple RPCs over one
/// connected stream.
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
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    mut on_event: F,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
{
    require_capabilities(stream, &[GuestCapability::RunEntrypoint])?;
    let req = GuestRequest::RunEntrypoint {
        stdin,
        timeout_secs,
        env,
    };
    let mut session = RpcSession::open(stream)?;
    session.write(stream, &req)?;

    loop {
        let resp: GuestResponse = session.read(stream)?;
        let event = match resp {
            GuestResponse::EntrypointEvent(e) => e,
            GuestResponse::Error { message } => bail!("guest agent error: {message}"),
            other => bail!("expected EntrypointEvent during RunEntrypoint stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}

/// Send an `Exec` request and stream its response. Invokes `on_event`
/// for each `Stdout`/`Stderr` chunk as it arrives; returns the terminal
/// `Exit` or `TimedOut`. Exec carries no `GuestCapability` — the agent
/// gates it at compile time via the `interactive` feature — so this does
/// a plain protocol hello (no capability requirement).
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
/// stream. Like `Exec`, `RunDetached` carries no `GuestCapability` — the
/// agent gates it at compile time via the `interactive` feature — so this
/// does a plain protocol hello.
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
    use super::*;

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
        let terminal = send_run_entrypoint(&mut host, b"in".to_vec(), 30, Vec::new(), |evt| {
            received.push(evt.clone())
        })
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
        let terminal = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |evt| {
            received.push(evt.clone())
        })
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

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |_| {});
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

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |_| {});
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
        };
        let mut events = 0usize;
        call_streaming(&mut client, &req, |_e| events += 1).unwrap();
        assert_eq!(events, 2);
    }
}
