//! In-guest `host.audit.v1` typed methods — workload-emitted audit entries.
//!
//! `emit` / `emit_batch` let a workload append to the chain-signed audit log
//! over the broker transport ([`crate::broker_client`]). The payload types
//! (`EmitRequest` / `EmitResponse` / `EmitBatchRequest` /
//! `EmitBatchResponse`) are the shared wire contract in
//! [`mvm_core::protocol::host_audit`]; this module builds the `ServiceCall`
//! envelope and maps the host's typed `ServiceErrorCode` reply onto a typed
//! `AuditError`.
//!
//! Claim 8 — a workload can never write a host-category entry — is structural,
//! not advisory: `EmitRequest` carries no `category` field, so this method
//! cannot express one, and the host handler independently stamps
//! `category: workload_audit` on every forwarded entry. The 4 KiB per-record
//! cap and the 20/s rate limit are likewise enforced host-side; this client
//! surfaces the host's `BadRequest` / `RateLimitExceeded` as typed errors but
//! does not itself gate (it runs in the untrusted guest).

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
use mvm_core::protocol::host_audit::{
    EmitBatchRequest, EmitBatchResponse, EmitRequest, EmitResponse,
};

use crate::broker_client::{self, BrokerError};

/// The broker service every audit emission targets.
pub const HOST_AUDIT_SERVICE: &str = "host.audit.v1";

/// Failure of a `host.audit.v1` call. Maps the broker's typed
/// [`ServiceErrorCode`] onto named variants the SDK veneer can surface as
/// distinct exceptions.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The host rejected the record shape or size (e.g. a single record over
    /// the 4 KiB cap). Carries the host-authored message.
    #[error("audit record rejected: {0}")]
    BadRequest(String),
    /// The per-workload audit emit rate limit (20/s) is exhausted.
    #[error("audit emit rate limit exceeded")]
    RateLimited,
    /// The host could not reach the audit signer (transport down).
    #[error("audit service unavailable: {0}")]
    Unavailable(String),
    /// Any other typed broker error code.
    #[error("audit emit failed [{code:?}]: {message}")]
    Service {
        /// The host's typed error code.
        code: ServiceErrorCode,
        /// Host-authored detail.
        message: String,
    },
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("audit transport error: {0}")]
    Transport(anyhow::Error),
}

impl From<BrokerError> for AuditError {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::Transport(e) => AuditError::Transport(e),
            BrokerError::Service { code, message } => match code {
                ServiceErrorCode::RateLimitExceeded => AuditError::RateLimited,
                ServiceErrorCode::BadRequest => AuditError::BadRequest(message),
                ServiceErrorCode::Unavailable => AuditError::Unavailable(message),
                other => AuditError::Service {
                    code: other,
                    message,
                },
            },
        }
    }
}

/// Append one audit entry over an already-open broker stream.
pub fn emit_on(stream: &mut UnixStream, record: &EmitRequest) -> Result<EmitResponse, AuditError> {
    let call = build_call("emit", record)?;
    let payload = broker_client::call(stream, &call)?;
    decode(payload)
}

/// Append a batch of audit entries over an already-open broker stream.
pub fn emit_batch_on(
    stream: &mut UnixStream,
    batch: &EmitBatchRequest,
) -> Result<EmitBatchResponse, AuditError> {
    let call = build_call("emit_batch", batch)?;
    let payload = broker_client::call(stream, &call)?;
    decode(payload)
}

/// Dial the broker port and append one audit entry.
pub fn emit(record: &EmitRequest, timeout_secs: u64) -> Result<EmitResponse, AuditError> {
    let call = build_call("emit", record)?;
    let payload = broker_client::broker_call(&call, timeout_secs)?;
    decode(payload)
}

/// Dial the broker port and append a batch of audit entries.
pub fn emit_batch(
    batch: &EmitBatchRequest,
    timeout_secs: u64,
) -> Result<EmitBatchResponse, AuditError> {
    let call = build_call("emit_batch", batch)?;
    let payload = broker_client::broker_call(&call, timeout_secs)?;
    decode(payload)
}

/// Build the `host.audit.v1` `ServiceCall` for `verb`, encoding `payload` as
/// the call body. The `correlation_id` is a placeholder the host reassigns.
fn build_call<T: serde::Serialize>(verb: &str, payload: &T) -> Result<ServiceCall, AuditError> {
    let payload =
        serde_json::to_value(payload).map_err(|e| AuditError::Transport(anyhow::Error::from(e)))?;
    Ok(ServiceCall {
        service: host_audit_service(),
        verb: verb.to_string(),
        correlation_id: next_correlation_id(),
        payload,
    })
}

/// Decode a broker `Ok` payload into the typed response `T`.
fn decode<T: serde::de::DeserializeOwned>(payload: serde_json::Value) -> Result<T, AuditError> {
    serde_json::from_value(payload).map_err(|e| AuditError::Transport(anyhow::Error::from(e)))
}

/// The `host.audit.v1` service id.
fn host_audit_service() -> ServiceId {
    ServiceId::parse(HOST_AUDIT_SERVICE).expect("host.audit.v1 is a valid ServiceId")
}

/// Mint a per-call placeholder correlation id. The supervisor reassigns the
/// authoritative id at frame ingress, so this only distinguishes the guest's
/// own in-flight calls in its logs; a monotonic counter suffices and pulls in
/// no id-generation dependency.
fn next_correlation_id() -> CorrelationId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("wl-audit-{n}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use mvm_core::protocol::broker::ServiceResponse;
    use mvm_core::protocol::host_audit::EmitBatchEntryStatus;

    use super::*;
    use crate::vsock::{read_frame, write_frame};

    fn sample_record() -> EmitRequest {
        EmitRequest {
            ts: "2026-05-28T00:00:00Z".into(),
            fields: serde_json::json!({"action": "login", "user": "alice"}),
        }
    }

    /// Spawn a mock broker on the server half of a socket pair: read the one
    /// `ServiceCall`, hand it to `respond` (which also captures it), write the
    /// returned `ServiceResponse`.
    fn serve_once(
        server: UnixStream,
        captured: Arc<Mutex<Option<ServiceCall>>>,
        respond: impl FnOnce(&ServiceCall) -> ServiceResponse + Send + 'static,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut server = server;
            let call: ServiceCall = read_frame(&mut server).unwrap();
            *captured.lock().unwrap() = Some(call.clone());
            write_frame(&mut server, &respond(&call)).unwrap();
        })
    }

    #[test]
    fn emit_sends_host_audit_v1_envelope_with_no_category_and_returns_chain_head() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"chain_head": "head-001"}),
        });

        let resp = emit_on(&mut client, &sample_record()).expect("emit must succeed");
        assert_eq!(resp.chain_head, "head-001");
        handle.join().unwrap();

        let call = captured
            .lock()
            .unwrap()
            .take()
            .expect("server must capture call");
        assert_eq!(call.service.as_str(), "host.audit.v1");
        assert_eq!(call.verb, "emit");
        // The workload cannot express a category — the payload carries none, so
        // it can never request a host-category entry (the host stamps
        // workload_audit). The payload parses as the shared EmitRequest.
        assert!(
            call.payload.get("category").is_none(),
            "workload payload must not carry a category field"
        );
        let record: EmitRequest = serde_json::from_value(call.payload).unwrap();
        assert_eq!(record, sample_record());
    }

    #[test]
    fn emit_surfaces_bad_request_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::BadRequest,
            message: "record 5121 bytes exceeds cap 4096".into(),
        });

        let err = emit_on(&mut client, &sample_record()).expect_err("must surface BadRequest");
        match err {
            AuditError::BadRequest(msg) => assert!(msg.contains("exceeds cap")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn emit_surfaces_rate_limit_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::RateLimitExceeded,
            message: "per-workload audit emit rate limit exceeded".into(),
        });

        let err = emit_on(&mut client, &sample_record()).expect_err("must surface rate limit");
        assert!(matches!(err, AuditError::RateLimited), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn emit_surfaces_unavailable_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::Unavailable,
            message: "audit-signer transport failed".into(),
        });

        let err = emit_on(&mut client, &sample_record()).expect_err("must surface unavailable");
        assert!(matches!(err, AuditError::Unavailable(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn emit_maps_other_code_to_service_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service `host.audit.v1` not bound to workload".into(),
        });

        let err = emit_on(&mut client, &sample_record()).expect_err("must surface service error");
        match err {
            AuditError::Service { code, .. } => assert_eq!(code, ServiceErrorCode::NotBound),
            other => panic!("expected Service, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn emit_batch_sends_batch_envelope_and_returns_statuses() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({
                "chain_head": "head-b2",
                "statuses": [
                    {"kind": "ok", "chain_head": "head-b1"},
                    {"kind": "ok", "chain_head": "head-b2"},
                ],
            }),
        });

        let batch = EmitBatchRequest {
            entries: vec![sample_record(), sample_record()],
        };
        let resp = emit_batch_on(&mut client, &batch).expect("emit_batch must succeed");
        assert_eq!(resp.chain_head, "head-b2");
        assert_eq!(resp.statuses.len(), 2);
        assert!(
            resp.statuses
                .iter()
                .all(|s| matches!(s, EmitBatchEntryStatus::Ok { .. }))
        );
        handle.join().unwrap();

        let call = captured
            .lock()
            .unwrap()
            .take()
            .expect("server must capture call");
        assert_eq!(call.service.as_str(), "host.audit.v1");
        assert_eq!(call.verb, "emit_batch");
        let parsed: EmitBatchRequest = serde_json::from_value(call.payload).unwrap();
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn minted_correlation_ids_are_distinct() {
        assert_ne!(next_correlation_id(), next_correlation_id());
    }
}
