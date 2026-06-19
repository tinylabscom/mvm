//! Request-handling core of the resident builder-VM daemon
//! (`mvm-builderd`).
//!
//! This module is the cross-platform, unit-testable heart of the
//! daemon: it turns a decoded [`BuilderRequest`] into a
//! [`BuilderResponse`] ([`dispatch`]) and runs the read-dispatch-write
//! loop over a framed connection ([`serve_connection`]). The binary
//! entrypoint and the Linux AF_VSOCK listener are deliberately *not*
//! here — they land with the builder-VM boot wiring. Keeping the core
//! in the library lets it be driven from a `UnixStream` pair in tests
//! without booting the builder VM.
//!
//! ## Skeleton scope
//!
//! Only [`BuilderRequest::Handshake`] and [`BuilderRequest::Probe`] are
//! fully served (plus a no-op [`BuilderRequest::CancelJob`]
//! acknowledgement, since nothing is in flight yet). The real build/eval
//! operations are recognized and answered with a fail-closed
//! [`BuilderResponse::Failed`] / [`FailureCategory::Unsupported`] until
//! their handlers land. This is honest: a client gets a typed "this
//! daemon build does not implement that operation" rather than a hang or
//! a silently-dropped request.

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;

use crate::builderd_protocol::{
    BuilderRequest, BuilderResponse, FailureCategory, OperationId, PROTOCOL_VERSION,
    handshake_reply,
};

/// Map one [`BuilderRequest`] to its [`BuilderResponse`]. Pure and
/// stateless: the skeleton daemon holds no per-connection or
/// cross-request state yet, so a handshake/probe is answered the same
/// regardless of order. Stateful "must handshake first" enforcement and
/// real operation handlers are later slices.
pub fn dispatch(request: &BuilderRequest) -> BuilderResponse {
    match request {
        BuilderRequest::Handshake { protocol_version } => handshake_reply(*protocol_version),

        BuilderRequest::Probe { op } => BuilderResponse::Accepted {
            op: *op,
            protocol_version: PROTOCOL_VERSION,
        },

        // Nothing is in flight in the skeleton, so a cancel for any id
        // is a no-op the daemon still acknowledges — matching the
        // protocol contract that cancelling an unknown/finished id is a
        // benign ack rather than an error.
        BuilderRequest::CancelJob { target } => BuilderResponse::Cancelled { op: *target },

        // Recognized build/eval operations whose handlers have not
        // landed yet. Fail closed with a typed Unsupported category so
        // the host shows an actionable message and does not retry.
        BuilderRequest::FlakeCheck { op, .. }
        | BuilderRequest::BuildGuestImage { op, .. }
        | BuilderRequest::BuildHostTool { op, .. }
        | BuilderRequest::PrefetchSource { op, .. }
        | BuilderRequest::QueryStorePath { op, .. } => unsupported(*op, request),
    }
}

/// Build the fail-closed [`BuilderResponse::Failed`] for a recognized
/// but not-yet-implemented operation.
fn unsupported(op: OperationId, request: &BuilderRequest) -> BuilderResponse {
    BuilderResponse::Failed {
        op,
        category: FailureCategory::Unsupported,
        message: format!(
            "operation {} is not implemented by this builder daemon",
            request_kind(request)
        ),
        retryable: false,
    }
}

/// The snake_case wire tag for a request, for use in human-readable
/// messages. Cheap and allocation-free; reuses the serde tag so the
/// message and the wire stay in lock-step.
fn request_kind(request: &BuilderRequest) -> &'static str {
    match request {
        BuilderRequest::Handshake { .. } => "handshake",
        BuilderRequest::Probe { .. } => "probe",
        BuilderRequest::FlakeCheck { .. } => "flake_check",
        BuilderRequest::BuildGuestImage { .. } => "build_guest_image",
        BuilderRequest::BuildHostTool { .. } => "build_host_tool",
        BuilderRequest::PrefetchSource { .. } => "prefetch_source",
        BuilderRequest::QueryStorePath { .. } => "query_store_path",
        BuilderRequest::CancelJob { .. } => "cancel_job",
    }
}

/// Serve one control connection: read framed [`BuilderRequest`]s, hand
/// each to [`dispatch`], and write the framed [`BuilderResponse`] back,
/// until the peer closes the connection (clean EOF).
///
/// Framing reuses [`mvm_guest::vsock::read_frame`] /
/// [`mvm_guest::vsock::write_frame`], inheriting the 256 KiB
/// pre-deserialize cap. A clean EOF before a frame starts is the normal
/// end-of-connection and returns `Ok(())`. A malformed/oversized frame
/// or a write failure returns the underlying error so the caller can
/// log it and drop the connection — the daemon keeps serving other
/// connections.
pub fn serve_connection(stream: &mut UnixStream) -> std::io::Result<()> {
    loop {
        match mvm_guest::vsock::read_frame::<BuilderRequest>(stream) {
            Ok(request) => {
                let response = dispatch(&request);
                mvm_guest::vsock::write_frame(stream, &response)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            Err(e) => {
                // A clean EOF at a frame boundary is the expected end of
                // a connection, not an error. `read_frame` surfaces it
                // as an io::Error with kind UnexpectedEof chained
                // underneath anyhow; walk the chain to classify.
                if let Some(io_err) = e.source().and_then(|s| s.downcast_ref::<std::io::Error>())
                    && io_err.kind() == ErrorKind::UnexpectedEof
                {
                    return Ok(());
                }
                return Err(std::io::Error::other(e.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn op() -> OperationId {
        OperationId(Uuid::nil())
    }

    // ---- dispatch ------------------------------------------------------

    #[test]
    fn dispatch_handshake_accepts_supported_version() {
        let resp = dispatch(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        });
        assert!(matches!(
            resp,
            BuilderResponse::Accepted {
                protocol_version,
                ..
            } if protocol_version == PROTOCOL_VERSION
        ));
    }

    #[test]
    fn dispatch_handshake_refuses_bad_version() {
        let resp = dispatch(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION + 1,
        });
        assert!(matches!(
            resp,
            BuilderResponse::Failed {
                category: FailureCategory::Version,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_probe_echoes_op() {
        let resp = dispatch(&BuilderRequest::Probe { op: op() });
        match resp {
            BuilderResponse::Accepted {
                op: got,
                protocol_version,
            } => {
                assert_eq!(got, op());
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_cancel_acks() {
        let resp = dispatch(&BuilderRequest::CancelJob { target: op() });
        assert!(matches!(resp, BuilderResponse::Cancelled { op: got } if got == op()));
    }

    #[test]
    fn dispatch_unimplemented_ops_fail_unsupported_and_echo_op() {
        let cases = [
            BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
            BuilderRequest::BuildGuestImage {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
                fingerprint: None,
            },
            BuilderRequest::BuildHostTool {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.mvm-host-vm-init".to_string(),
                fingerprint: None,
            },
            BuilderRequest::PrefetchSource {
                op: op(),
                source_ref: "github:nixos/nixpkgs".to_string(),
            },
            BuilderRequest::QueryStorePath {
                op: op(),
                store_path: "/nix/store/aaaa-foo".to_string(),
            },
        ];
        for req in cases {
            match dispatch(&req) {
                BuilderResponse::Failed {
                    op: got,
                    category,
                    retryable,
                    ..
                } => {
                    assert_eq!(got, op());
                    assert_eq!(category, FailureCategory::Unsupported);
                    assert!(!retryable);
                }
                other => panic!("expected Failed/Unsupported for {req:?}, got {other:?}"),
            }
        }
    }

    // ---- serve_connection ---------------------------------------------

    /// Drive a request through the serve loop over a `UnixStream` pair
    /// and read back the single response. Single-threaded: the client
    /// writes one request, half-closes its write side so the loop sees
    /// EOF after that frame, the loop serves it and exits, then we read
    /// the buffered response.
    fn roundtrip_one(request: &BuilderRequest) -> BuilderResponse {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_guest::vsock::write_frame(&mut client, request).expect("write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close write");
        serve_connection(&mut server).expect("serve");
        mvm_guest::vsock::read_frame::<BuilderResponse>(&mut client).expect("read response")
    }

    #[test]
    fn serve_handshake_over_the_wire() {
        let resp = roundtrip_one(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        });
        assert!(matches!(resp, BuilderResponse::Accepted { .. }));
    }

    #[test]
    fn serve_probe_over_the_wire() {
        let resp = roundtrip_one(&BuilderRequest::Probe { op: op() });
        assert!(matches!(resp, BuilderResponse::Accepted { op: got, .. } if got == op()));
    }

    #[test]
    fn serve_handles_multiple_requests_then_clean_eof() {
        // Two requests on one connection, then EOF. The loop must
        // answer both and return Ok on the clean close.
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_guest::vsock::write_frame(
            &mut client,
            &BuilderRequest::Handshake {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .expect("write handshake");
        mvm_guest::vsock::write_frame(&mut client, &BuilderRequest::Probe { op: op() })
            .expect("write probe");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close write");

        serve_connection(&mut server).expect("serve returns Ok on clean eof");

        let first = mvm_guest::vsock::read_frame::<BuilderResponse>(&mut client).expect("first");
        let second = mvm_guest::vsock::read_frame::<BuilderResponse>(&mut client).expect("second");
        assert!(matches!(first, BuilderResponse::Accepted { .. }));
        assert!(matches!(second, BuilderResponse::Accepted { op: got, .. } if got == op()));
    }

    #[test]
    fn serve_returns_ok_on_immediate_eof() {
        // A peer that connects and closes without sending anything is a
        // normal, non-error end of connection.
        let (client, mut server) = UnixStream::pair().expect("socketpair");
        drop(client);
        serve_connection(&mut server).expect("immediate eof is Ok");
    }
}
