//! Host-side client for the resident builder-VM daemon (`mvm-builderd`).
//!
//! `mvmctl` (and, later, the SDKs through it) drive the builder VM by
//! connecting to the daemon's control socket, completing a protocol
//! handshake, and running one typed operation at a time over the
//! connection. The daemon streams [`BuilderResponse::Progress`] /
//! [`BuilderResponse::LogChunk`] events, which this client surfaces to a
//! caller-supplied sink, then a single terminal frame, which becomes a
//! typed [`OperationOutcome`].
//!
//! This is the host-side counterpart of [`crate::builderd`]'s daemon
//! core. It is transport-and-correlation only: it does not start or stop
//! the builder VM (the lifecycle owner connects this client to an
//! already-running daemon socket) and it keeps all of that orchestration
//! — and every git operation — on the host, outside the builder VM.
//!
//! One operation per connection at a time: a connection carries a
//! handshake, then a request, then that request's event stream and
//! terminal. Concurrency is achieved with multiple connections, not by
//! multiplexing operations on one stream.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::builderd::{HandshakeOutcome, connect_with_timeout, perform_handshake};
use crate::builderd_protocol::{BuilderRequest, BuilderResponse, FailureCategory, OperationId};
// Only the test-only `from_stream` constructor and the tests reference the
// version constant directly; the live client reads it via `perform_handshake`.
#[cfg(test)]
use crate::builderd_protocol::PROTOCOL_VERSION;

/// Failure modes of the host-side builder client.
#[derive(Debug, thiserror::Error)]
pub enum BuilderdClientError {
    /// No daemon answered — the control socket is missing (builder VM
    /// down) or refused the connection. Not a defect; the lifecycle
    /// owner is expected to start the builder VM first.
    #[error("builder daemon not ready: {detail}")]
    NotReady {
        /// Diagnostic detail.
        detail: String,
    },
    /// The daemon refused our protocol version fail-closed. The host and
    /// daemon builds are incompatible.
    #[error("builder daemon protocol version mismatch: {detail}")]
    VersionMismatch {
        /// The daemon's refusal detail.
        detail: String,
    },
    /// A read or write on the control connection failed (not a clean
    /// protocol outcome).
    #[error("builder daemon transport error: {detail}")]
    Transport {
        /// Diagnostic detail.
        detail: String,
    },
    /// An operation exceeded the connection's timeout before a terminal
    /// frame arrived.
    #[error("builder daemon operation timed out")]
    Timeout,
    /// The daemon sent a frame that violates the protocol contract (an
    /// out-of-band acknowledgement mid-operation, or a frame whose
    /// operation id does not match the in-flight request).
    #[error("builder daemon protocol violation: {detail}")]
    Protocol {
        /// Diagnostic detail.
        detail: String,
    },
}

/// A streamed event emitted by the daemon while an operation runs.
/// Carries no operation id — the client has already correlated it to the
/// in-flight request before handing it to the sink.
#[derive(Debug, Clone, PartialEq)]
pub enum OperationEvent {
    /// Structured progress: a best-effort completion fraction and a
    /// short human label.
    Progress {
        /// Completion in `[0.0, 1.0]`, best-effort.
        fraction: f32,
        /// Short human-readable phase label.
        label: String,
    },
    /// A chunk of build log text.
    Log {
        /// Log text (no line-boundary guarantees).
        text: String,
    },
}

/// Terminal result of a builder operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The operation produced an artifact at a mounted output path.
    Artifact {
        /// Path inside the builder VM's mounted output share.
        artifact_path: String,
        /// Backing `/nix/store/...` path, when applicable.
        store_path: Option<String>,
    },
    /// The operation resolved to a store path.
    StorePath {
        /// The resolved `/nix/store/...` path.
        store_path: String,
        /// Whether the path was already present in the store.
        already_present: bool,
    },
    /// The operation succeeded with no artifact or store path (e.g. a
    /// flake check that passed).
    Completed,
    /// The operation failed with a stable category.
    Failed {
        /// Stable failure class.
        category: FailureCategory,
        /// Human-readable detail.
        message: String,
        /// Whether the host may retry the same request unchanged.
        retryable: bool,
    },
    /// The operation was cancelled.
    Cancelled,
}

/// A connected, handshaken control session to a builder daemon.
#[derive(Debug)]
pub struct BuilderdClient {
    stream: UnixStream,
    /// Protocol version the daemon agreed to speak, for diagnostics.
    negotiated_version: u32,
}

impl BuilderdClient {
    /// Connect to a daemon control socket, arm `timeout` on both
    /// directions, and complete the protocol handshake.
    ///
    /// A missing socket or refused connection is
    /// [`BuilderdClientError::NotReady`]; a version refusal is
    /// [`BuilderdClientError::VersionMismatch`].
    pub fn connect(socket_path: &Path, timeout: Duration) -> Result<Self, BuilderdClientError> {
        if !socket_path.exists() {
            return Err(BuilderdClientError::NotReady {
                detail: format!("no control socket at {}", socket_path.display()),
            });
        }
        let mut stream = connect_with_timeout(socket_path, timeout).map_err(|e| {
            BuilderdClientError::NotReady {
                detail: format!("connect failed: {e}"),
            }
        })?;
        match perform_handshake(&mut stream) {
            HandshakeOutcome::Agreed(negotiated_version) => Ok(Self {
                stream,
                negotiated_version,
            }),
            HandshakeOutcome::VersionRefused(detail) => {
                Err(BuilderdClientError::VersionMismatch { detail })
            }
            HandshakeOutcome::Unexpected(detail) => Err(BuilderdClientError::Protocol { detail }),
            HandshakeOutcome::Transport(detail) => Err(BuilderdClientError::Transport { detail }),
        }
    }

    /// The protocol version negotiated at connect time.
    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Run one operation to completion: send `request`, forward each
    /// streamed [`OperationEvent`] to `sink`, and return the terminal
    /// [`OperationOutcome`].
    ///
    /// `request` must be an operation (not a [`BuilderRequest::Handshake`]
    /// — that is connect's job). Every response frame must carry the
    /// request's operation id; a mismatched or out-of-band frame is a
    /// [`BuilderdClientError::Protocol`]. A read timeout before the
    /// terminal frame is [`BuilderdClientError::Timeout`].
    pub fn run_operation(
        &mut self,
        request: &BuilderRequest,
        sink: &mut dyn FnMut(OperationEvent),
    ) -> Result<OperationOutcome, BuilderdClientError> {
        let Some(expected) = request_op(request) else {
            return Err(BuilderdClientError::Protocol {
                detail: "run_operation requires an operation request, not a handshake".to_string(),
            });
        };
        mvm_guest::vsock::write_frame(&mut self.stream, request).map_err(|e| {
            BuilderdClientError::Transport {
                detail: format!("request write failed: {e}"),
            }
        })?;
        loop {
            let response = self.read_frame_classifying_timeout()?;
            let op = response_op(&response);
            if op != expected {
                return Err(BuilderdClientError::Protocol {
                    detail: format!("response for {op} but operation is {expected}"),
                });
            }
            match response {
                BuilderResponse::Progress {
                    fraction, label, ..
                } => sink(OperationEvent::Progress { fraction, label }),
                BuilderResponse::LogChunk { text, .. } => sink(OperationEvent::Log { text }),
                BuilderResponse::ArtifactReady {
                    artifact_path,
                    store_path,
                    ..
                } => {
                    return Ok(OperationOutcome::Artifact {
                        artifact_path,
                        store_path,
                    });
                }
                BuilderResponse::StorePathReady {
                    store_path,
                    already_present,
                    ..
                } => {
                    return Ok(OperationOutcome::StorePath {
                        store_path,
                        already_present,
                    });
                }
                BuilderResponse::Failed {
                    category,
                    message,
                    retryable,
                    ..
                } => {
                    return Ok(OperationOutcome::Failed {
                        category,
                        message,
                        retryable,
                    });
                }
                BuilderResponse::Completed { .. } => return Ok(OperationOutcome::Completed),
                BuilderResponse::Cancelled { .. } => return Ok(OperationOutcome::Cancelled),
                BuilderResponse::Accepted { .. } => {
                    return Err(BuilderdClientError::Protocol {
                        detail: "unexpected Accepted frame mid-operation".to_string(),
                    });
                }
            }
        }
    }

    /// Send a [`BuilderRequest::CancelJob`] for `target` on this
    /// connection. The terminal [`OperationOutcome::Cancelled`] arrives
    /// through [`Self::run_operation`]'s event loop; this only writes the
    /// cancel frame, so a caller can drive it from a separate handle to
    /// the same session (a signal handler, a deadline watcher).
    pub fn request_cancel(&mut self, target: OperationId) -> Result<(), BuilderdClientError> {
        mvm_guest::vsock::write_frame(&mut self.stream, &BuilderRequest::CancelJob { target })
            .map_err(|e| BuilderdClientError::Transport {
                detail: format!("cancel write failed: {e}"),
            })
    }

    /// Read one frame, mapping a read timeout to
    /// [`BuilderdClientError::Timeout`] and any other read failure to
    /// [`BuilderdClientError::Transport`].
    fn read_frame_classifying_timeout(&mut self) -> Result<BuilderResponse, BuilderdClientError> {
        mvm_guest::vsock::read_frame::<BuilderResponse>(&mut self.stream).map_err(|e| {
            let io_kind = e
                .source()
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind);
            match io_kind {
                Some(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    BuilderdClientError::Timeout
                }
                _ => BuilderdClientError::Transport {
                    detail: format!("response read failed: {e}"),
                },
            }
        })
    }

    /// Test-only constructor over an arbitrary stream, so the operation
    /// loop can be driven from a `UnixStream` pair without a listener or
    /// a handshake.
    #[cfg(test)]
    fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream,
            negotiated_version: PROTOCOL_VERSION,
        }
    }
}

/// The operation id a request correlates on, or `None` for a handshake
/// (which has no operation of its own).
fn request_op(request: &BuilderRequest) -> Option<OperationId> {
    match request {
        BuilderRequest::Handshake { .. } => None,
        BuilderRequest::Probe { op }
        | BuilderRequest::FlakeCheck { op, .. }
        | BuilderRequest::BuildGuestImage { op, .. }
        | BuilderRequest::BuildHostTool { op, .. }
        | BuilderRequest::PrefetchSource { op, .. }
        | BuilderRequest::QueryStorePath { op, .. } => Some(*op),
        BuilderRequest::CancelJob { target } => Some(*target),
    }
}

/// The operation id every response frame carries.
fn response_op(response: &BuilderResponse) -> OperationId {
    match response {
        BuilderResponse::Accepted { op, .. }
        | BuilderResponse::Progress { op, .. }
        | BuilderResponse::LogChunk { op, .. }
        | BuilderResponse::ArtifactReady { op, .. }
        | BuilderResponse::StorePathReady { op, .. }
        | BuilderResponse::Failed { op, .. }
        | BuilderResponse::Completed { op }
        | BuilderResponse::Cancelled { op } => *op,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builderd::serve_connection;
    use uuid::Uuid;

    fn op() -> OperationId {
        OperationId(Uuid::nil())
    }

    /// Collect events into a vec while running an operation against a
    /// client built over `client_stream`. The caller has already staged
    /// the server's response frames on the peer end.
    fn run_collecting(
        client_stream: UnixStream,
        request: &BuilderRequest,
    ) -> Result<(OperationOutcome, Vec<OperationEvent>), BuilderdClientError> {
        let mut client = BuilderdClient::from_stream(client_stream);
        let mut events = Vec::new();
        let outcome = client.run_operation(request, &mut |e| events.push(e))?;
        Ok((outcome, events))
    }

    #[test]
    fn streams_progress_and_log_then_artifact() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        // Stage a Progress, a LogChunk, then the terminal ArtifactReady
        // — all for the operation the client will run. Buffered in the
        // client's read direction; the client never blocks.
        for frame in [
            BuilderResponse::Progress {
                op: op(),
                fraction: 0.5,
                label: "building".to_string(),
            },
            BuilderResponse::LogChunk {
                op: op(),
                text: "compiling".to_string(),
            },
            BuilderResponse::ArtifactReady {
                op: op(),
                artifact_path: "/out/rootfs.ext4".to_string(),
                store_path: Some("/nix/store/aaaa-img".to_string()),
            },
        ] {
            mvm_guest::vsock::write_frame(&mut server, &frame).expect("stage frame");
        }
        let (outcome, events) = run_collecting(
            client_stream,
            &BuilderRequest::BuildGuestImage {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
                fingerprint: None,
            },
        )
        .expect("operation");
        assert_eq!(
            events,
            vec![
                OperationEvent::Progress {
                    fraction: 0.5,
                    label: "building".to_string()
                },
                OperationEvent::Log {
                    text: "compiling".to_string()
                },
            ]
        );
        assert_eq!(
            outcome,
            OperationOutcome::Artifact {
                artifact_path: "/out/rootfs.ext4".to_string(),
                store_path: Some("/nix/store/aaaa-img".to_string()),
            }
        );
    }

    #[test]
    fn store_path_terminal_is_returned() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        mvm_guest::vsock::write_frame(
            &mut server,
            &BuilderResponse::StorePathReady {
                op: op(),
                store_path: "/nix/store/cccc-src".to_string(),
                already_present: true,
            },
        )
        .expect("stage");
        let (outcome, events) = run_collecting(
            client_stream,
            &BuilderRequest::QueryStorePath {
                op: op(),
                store_path: "/nix/store/cccc-src".to_string(),
            },
        )
        .expect("operation");
        assert!(events.is_empty());
        assert_eq!(
            outcome,
            OperationOutcome::StorePath {
                store_path: "/nix/store/cccc-src".to_string(),
                already_present: true,
            }
        );
    }

    #[test]
    fn failed_terminal_carries_category() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        mvm_guest::vsock::write_frame(
            &mut server,
            &BuilderResponse::Failed {
                op: op(),
                category: FailureCategory::NixBuild,
                message: "derivation failed".to_string(),
                retryable: false,
            },
        )
        .expect("stage");
        let (outcome, _events) = run_collecting(
            client_stream,
            &BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
        )
        .expect("operation");
        assert_eq!(
            outcome,
            OperationOutcome::Failed {
                category: FailureCategory::NixBuild,
                message: "derivation failed".to_string(),
                retryable: false,
            }
        );
    }

    #[test]
    fn completed_terminal_is_returned() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        mvm_guest::vsock::write_frame(&mut server, &BuilderResponse::Completed { op: op() })
            .expect("stage");
        let (outcome, _events) = run_collecting(
            client_stream,
            &BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
        )
        .expect("operation");
        assert_eq!(outcome, OperationOutcome::Completed);
    }

    #[test]
    fn cancelled_terminal_is_returned() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        mvm_guest::vsock::write_frame(&mut server, &BuilderResponse::Cancelled { op: op() })
            .expect("stage");
        let (outcome, _events) = run_collecting(
            client_stream,
            &BuilderRequest::PrefetchSource {
                op: op(),
                source_ref: "github:nixos/nixpkgs".to_string(),
            },
        )
        .expect("operation");
        assert_eq!(outcome, OperationOutcome::Cancelled);
    }

    #[test]
    fn mismatched_operation_id_is_a_protocol_error() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        // A terminal for a *different* operation id than the request.
        mvm_guest::vsock::write_frame(
            &mut server,
            &BuilderResponse::ArtifactReady {
                op: OperationId(Uuid::from_u128(7)),
                artifact_path: "/out/x".to_string(),
                store_path: None,
            },
        )
        .expect("stage");
        let err = run_collecting(
            client_stream,
            &BuilderRequest::BuildHostTool {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.tool".to_string(),
                fingerprint: None,
            },
        )
        .expect_err("must reject mismatched op");
        assert!(
            matches!(err, BuilderdClientError::Protocol { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn unexpected_accepted_mid_operation_is_a_protocol_error() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        mvm_guest::vsock::write_frame(
            &mut server,
            &BuilderResponse::Accepted {
                op: op(),
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .expect("stage");
        let err = run_collecting(client_stream, &BuilderRequest::Probe { op: op() })
            .expect_err("Accepted is not a valid operation terminal");
        assert!(
            matches!(err, BuilderdClientError::Protocol { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn read_timeout_before_terminal_is_timeout_error() {
        let (client_stream, _server) = UnixStream::pair().expect("pair");
        client_stream
            .set_read_timeout(Some(Duration::from_millis(150)))
            .expect("set timeout");
        // Server end is held open but writes nothing — the operation
        // read blocks until the timeout elapses.
        let err = run_collecting(
            client_stream,
            &BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
        )
        .expect_err("must time out");
        assert!(matches!(err, BuilderdClientError::Timeout), "{err:?}");
    }

    #[test]
    fn run_operation_rejects_a_handshake_request() {
        let (client_stream, _server) = UnixStream::pair().expect("pair");
        let mut client = BuilderdClient::from_stream(client_stream);
        let err = client
            .run_operation(
                &BuilderRequest::Handshake {
                    protocol_version: PROTOCOL_VERSION,
                },
                &mut |_| {},
            )
            .expect_err("handshake is not an operation");
        assert!(
            matches!(err, BuilderdClientError::Protocol { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn request_cancel_writes_a_well_formed_cancel_frame() {
        let (client_stream, mut server) = UnixStream::pair().expect("pair");
        let mut client = BuilderdClient::from_stream(client_stream);
        client.request_cancel(op()).expect("write cancel");
        let frame = mvm_guest::vsock::read_frame::<BuilderRequest>(&mut server).expect("read");
        assert_eq!(frame, BuilderRequest::CancelJob { target: op() });
    }

    #[test]
    fn connect_not_ready_when_socket_absent() {
        let err = BuilderdClient::connect(
            Path::new("/nonexistent/mvm/builderd/vsock-21473.sock"),
            Duration::from_millis(100),
        )
        .expect_err("missing socket");
        assert!(
            matches!(err, BuilderdClientError::NotReady { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn connect_handshakes_against_a_live_daemon_then_runs_an_op() {
        use std::os::unix::net::UnixListener;
        // Full integration against the real daemon core: connect
        // handshakes via serve_connection, then a FlakeCheck (unimplemented
        // in the skeleton) comes back Failed/Unsupported.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock-21473.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            serve_connection(&mut conn).expect("serve");
        });

        let mut client =
            BuilderdClient::connect(&sock, Duration::from_secs(2)).expect("connect+handshake");
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);

        let outcome = client
            .run_operation(
                &BuilderRequest::FlakeCheck {
                    op: op(),
                    flake_path: "/work/nix".to_string(),
                },
                &mut |_| {},
            )
            .expect("operation");
        assert!(
            matches!(
                outcome,
                OperationOutcome::Failed {
                    category: FailureCategory::Unsupported,
                    ..
                }
            ),
            "{outcome:?}"
        );

        // Dropping the client closes the connection; the server loop sees
        // EOF and returns.
        drop(client);
        handle.join().expect("server thread");
    }
}
