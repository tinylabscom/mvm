//! In-guest host-services broker client (the workload→host call half).
//!
//! A workload reaches a host service (`host.audit.v1`, `host.time.v1`,
//! `host.cost.v1`) by dialing the supervisor's guest-facing broker port
//! ([`crate::vsock::BROKER_PORT`]) over vsock, writing a framed
//! `ServiceCall`, and reading a framed `ServiceResponse`. The supervisor
//! accepts the connection, derives the workload identity from the connection
//! itself, enforces the admitted `ExecutionPlan.services` binding, and proxies
//! the call to the `mvm-broker` subprocess.
//!
//! This client is **advisory**. It runs inside the untrusted guest, so it is
//! not a security boundary: a compromised workload can bypass it and write raw
//! frames to the port. Every gate — the service binding, the
//! category-forcing and size/rate caps on `host.audit.v1`, and the
//! correlation-id assignment — lives host-side. The client therefore holds no
//! key and no secret: the broker path carries a bare `ServiceCall`, not a
//! signed frame, and the host proves identity from the connection rather than
//! from anything the guest presents.
//!
//! One connection per call. The host assigns the `correlation_id` at ingress
//! (workload-supplied values are rewritten), so a response cannot be matched
//! to a request on a shared connection; multiplexing is therefore avoided and
//! each call opens, exchanges, and closes its own stream — mirroring the
//! substitution relay and the host-side broker proxy.

use std::os::unix::net::UnixStream;

use mvm_contract::protocol::agent_capability::{CapabilityBinding, CapabilityInvocation};
use mvm_contract::protocol::agent_session::AgentRequestId;
use mvm_core::protocol::broker::{
    CorrelationId, ServiceCall, ServiceErrorCode, ServiceId, ServiceResponse,
};

use crate::vsock::{BROKER_PORT, connect_host_vsock, read_frame, write_frame};

/// Failure of an in-guest broker call.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("broker transport error: {0}")]
    Transport(#[from] anyhow::Error),
    /// The host answered with a typed [`ServiceResponse::Err`]. `code` is the
    /// stable wire vocabulary the caller branches on; `message` is
    /// host-authored.
    #[error("broker service error [{code:?}]: {message}")]
    Service {
        /// Typed error code from the host.
        code: ServiceErrorCode,
        /// Host-authored human-readable detail.
        message: String,
    },
}

/// Exchange one `ServiceCall` over an already-open stream and return the host's
/// reply payload. One framed call out, one framed response back: a
/// [`ServiceResponse::Ok`] yields its `payload`; a [`ServiceResponse::Err`] is
/// surfaced as [`BrokerError::Service`]. Transport and framing failures surface
/// as [`BrokerError::Transport`].
pub fn call(
    stream: &mut UnixStream,
    request: &ServiceCall,
) -> Result<serde_json::Value, BrokerError> {
    write_frame(stream, request)?;
    let response: ServiceResponse = read_frame(stream)?;
    match response {
        ServiceResponse::Ok { payload, .. } => Ok(payload),
        ServiceResponse::Err { code, message, .. } => Err(BrokerError::Service { code, message }),
    }
}

/// Open a guest→host vsock stream to [`BROKER_PORT`] and exchange one call.
pub fn broker_call(
    request: &ServiceCall,
    timeout_secs: u64,
) -> Result<serde_json::Value, BrokerError> {
    let mut stream = connect_host_vsock(BROKER_PORT, timeout_secs)?;
    call(&mut stream, request)
}

/// Build and exchange one exact typed capability invocation over an existing
/// broker stream. The payload is serialized once for the wire and its digest
/// is bound into the invocation metadata.
pub fn capability_call<T: serde::Serialize>(
    stream: &mut UnixStream,
    service: ServiceId,
    verb: impl Into<String>,
    binding: CapabilityBinding,
    invocation_id: AgentRequestId,
    payload: T,
) -> Result<serde_json::Value, BrokerError> {
    let payload = serde_json::to_value(payload)
        .map_err(|error| BrokerError::Transport(anyhow::anyhow!(error)))?;
    let invocation = CapabilityInvocation::from_payload(binding, invocation_id.clone(), &payload)
        .map_err(|error| BrokerError::Transport(anyhow::anyhow!(error)))?;
    let request = ServiceCall {
        service,
        verb: verb.into(),
        correlation_id: CorrelationId::new(format!("agent-capability-{invocation_id}")),
        payload,
        capability: Some(invocation),
    };
    call(stream, &request)
}

/// Open a guest→host broker stream and exchange one typed capability call.
pub fn broker_capability_call<T: serde::Serialize>(
    service: ServiceId,
    verb: impl Into<String>,
    binding: CapabilityBinding,
    invocation_id: AgentRequestId,
    payload: T,
    timeout_secs: u64,
) -> Result<serde_json::Value, BrokerError> {
    let mut stream = connect_host_vsock(BROKER_PORT, timeout_secs)?;
    capability_call(&mut stream, service, verb, binding, invocation_id, payload)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::thread;

    use mvm_contract::protocol::agent_capability::{
        CapabilityDescriptor, CapabilityId, CapabilityLimits, SchemaRef, payload_digest,
    };
    use mvm_core::protocol::broker::{CorrelationId, ServiceId};

    use super::*;

    fn sample_call() -> ServiceCall {
        ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HGUEST0000000000000000"),
            payload: serde_json::json!({}),
            capability: None,
        }
    }

    #[test]
    fn call_round_trips_ok_payload_and_sends_the_exact_envelope() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let handle = thread::spawn(move || {
            // The "host" side: read the ServiceCall the guest sent, assert it
            // arrived verbatim, then answer with an Ok payload.
            let got: ServiceCall = read_frame(&mut server).unwrap();
            assert_eq!(got.service.as_str(), "host.time.v1");
            assert_eq!(got.verb, "now");
            write_frame(
                &mut server,
                &ServiceResponse::Ok {
                    correlation_id: got.correlation_id.clone(),
                    payload: serde_json::json!({"wall_ms": 1717000000000_u64}),
                },
            )
            .unwrap();
        });

        let payload = call(&mut client, &sample_call()).expect("ok call must succeed");
        assert_eq!(payload, serde_json::json!({"wall_ms": 1717000000000_u64}));
        handle.join().unwrap();
    }

    #[test]
    fn capability_call_binds_the_payload_digest_into_the_envelope() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let descriptor = CapabilityDescriptor::builder()
            .id(CapabilityId::new(ServiceId::parse("host.dev.echo.v1").unwrap(), "echo").unwrap())
            .description("echo a bounded value")
            .input_schema(SchemaRef::new("echo.input.v1", [1; 32]).unwrap())
            .output_schema(SchemaRef::new("echo.output.v1", [2; 32]).unwrap())
            .limits(CapabilityLimits::new(128, 128, 100).unwrap())
            .build()
            .unwrap();
        let binding = descriptor.binding();
        let request_id = AgentRequestId::parse("typed-client-request-1").unwrap();
        let payload = serde_json::json!({"value": "bounded"});
        let expected_digest = payload_digest(&payload);
        let expected_binding = binding.clone();
        let expected_request_id = request_id.clone();

        let handle = thread::spawn(move || {
            let got: ServiceCall = read_frame(&mut server).unwrap();
            let invocation = got.capability.expect("typed invocation must be present");
            assert_eq!(invocation.binding, expected_binding);
            assert_eq!(invocation.invocation_id, expected_request_id);
            assert_eq!(invocation.input_digest, expected_digest);
            write_frame(
                &mut server,
                &ServiceResponse::Ok {
                    correlation_id: got.correlation_id,
                    payload: serde_json::json!({"ok": true}),
                },
            )
            .unwrap();
        });

        let result = capability_call(
            &mut client,
            ServiceId::parse("host.dev.echo.v1").unwrap(),
            "echo",
            descriptor.binding(),
            AgentRequestId::parse("typed-client-request-1").unwrap(),
            payload,
        )
        .expect("typed call must succeed");
        assert_eq!(result, serde_json::json!({"ok": true}));
        handle.join().unwrap();
    }

    #[test]
    fn call_surfaces_service_err_as_typed_error() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let handle = thread::spawn(move || {
            let got: ServiceCall = read_frame(&mut server).unwrap();
            write_frame(
                &mut server,
                &ServiceResponse::Err {
                    correlation_id: got.correlation_id.clone(),
                    code: ServiceErrorCode::NotBound,
                    message: "service `host.time.v1` not bound to workload `wl`".into(),
                },
            )
            .unwrap();
        });

        let err = call(&mut client, &sample_call()).expect_err("Err response must surface");
        match err {
            BrokerError::Service { code, .. } => assert_eq!(code, ServiceErrorCode::NotBound),
            other => panic!("expected Service error, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn call_rejects_oversize_response_frame() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let handle = thread::spawn(move || {
            // Drain the request so the client's write completes.
            let _: ServiceCall = read_frame(&mut server).unwrap();
            // Claim a body far larger than the guest read cap (256 KiB), then
            // close. The client must reject on the length prefix alone, before
            // allocating or reading the body.
            let huge: u32 = 8 * 1024 * 1024;
            server.write_all(&huge.to_be_bytes()).unwrap();
            server.flush().unwrap();
        });

        let err = call(&mut client, &sample_call()).expect_err("oversize frame must error");
        assert!(
            matches!(err, BrokerError::Transport(_)),
            "expected Transport error, got {err:?}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn call_rejects_truncated_frame_body() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let handle = thread::spawn(move || {
            let _: ServiceCall = read_frame(&mut server).unwrap();
            // Length prefix promises 64 bytes; deliver 4 and hang up. The
            // client's read_exact of the body must fail rather than accept a
            // short frame.
            server.write_all(&64_u32.to_be_bytes()).unwrap();
            server.write_all(b"trun").unwrap();
            server.flush().unwrap();
        });

        let err = call(&mut client, &sample_call()).expect_err("short frame must error");
        assert!(
            matches!(err, BrokerError::Transport(_)),
            "expected Transport error, got {err:?}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn call_rejects_malformed_json_body() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let handle = thread::spawn(move || {
            let _: ServiceCall = read_frame(&mut server).unwrap();
            // A well-formed frame whose body is not a ServiceResponse. The
            // client must surface a deserialization failure, not mis-decode.
            let body = b"{\"not\":\"a service response\"}";
            let len: u32 = body.len().try_into().unwrap();
            server.write_all(&len.to_be_bytes()).unwrap();
            server.write_all(body).unwrap();
            server.flush().unwrap();
        });

        let err = call(&mut client, &sample_call()).expect_err("malformed body must error");
        assert!(
            matches!(err, BrokerError::Transport(_)),
            "expected Transport error, got {err:?}"
        );
        handle.join().unwrap();
    }
}
