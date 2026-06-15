//! In-guest `host.time.v1` typed method — host wall-clock query.
//!
//! [`now`] returns the host's wall-clock over the broker transport
//! ([`crate::broker_client`]). The response type
//! ([`mvm_core::protocol::host_time::TimeNowResponse`]) is the shared wire
//! contract; this module builds the `host.time.v1::now` `ServiceCall`
//! envelope and maps the host's typed [`ServiceErrorCode`] reply onto a
//! typed [`TimeError`].
//!
//! Like every broker client this runs in the untrusted guest and is
//! advisory: it holds no key, the call carries a bare `ServiceCall`, and the
//! host derives identity from the connection and enforces the
//! `ExecutionPlan.services` binding before dispatch.

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
use mvm_core::protocol::host_time::TimeNowResponse;

use crate::broker_client::{self, BrokerError};

/// The broker service `now` targets.
pub const HOST_TIME_SERVICE: &str = "host.time.v1";

/// Failure of a `host.time.v1` call. Maps the broker's typed
/// [`ServiceErrorCode`] onto named variants the SDK veneer can surface as
/// distinct exceptions.
#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    /// The workload's `ExecutionPlan.services` did not bind `host.time.v1`.
    #[error("host.time.v1 not bound to this workload")]
    NotBound,
    /// The host could not answer (handler down, broker not ready).
    #[error("host.time.v1 unavailable: {0}")]
    Unavailable(String),
    /// Any other typed broker error code.
    #[error("host.time.v1 failed [{code:?}]: {message}")]
    Service {
        /// The host's typed error code.
        code: ServiceErrorCode,
        /// Host-authored detail.
        message: String,
    },
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("host.time.v1 transport error: {0}")]
    Transport(anyhow::Error),
}

impl From<BrokerError> for TimeError {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::Transport(e) => TimeError::Transport(e),
            BrokerError::Service { code, message } => match code {
                ServiceErrorCode::NotBound => TimeError::NotBound,
                ServiceErrorCode::Unavailable | ServiceErrorCode::NotReady => {
                    TimeError::Unavailable(message)
                }
                other => TimeError::Service {
                    code: other,
                    message,
                },
            },
        }
    }
}

/// Query the host wall-clock over an already-open broker stream.
pub fn now_on(stream: &mut UnixStream) -> Result<TimeNowResponse, TimeError> {
    let call = build_call();
    let payload = broker_client::call(stream, &call)?;
    decode(payload)
}

/// Dial the broker port and query the host wall-clock.
pub fn now(timeout_secs: u64) -> Result<TimeNowResponse, TimeError> {
    let call = build_call();
    let payload = broker_client::broker_call(&call, timeout_secs)?;
    decode(payload)
}

/// Build the `host.time.v1::now` `ServiceCall`. The verb takes no payload;
/// the `correlation_id` is a placeholder the host reassigns at ingress.
fn build_call() -> ServiceCall {
    ServiceCall {
        service: host_time_service(),
        verb: "now".to_string(),
        correlation_id: next_correlation_id(),
        payload: serde_json::json!({}),
    }
}

/// Decode a broker `Ok` payload into [`TimeNowResponse`].
fn decode(payload: serde_json::Value) -> Result<TimeNowResponse, TimeError> {
    serde_json::from_value(payload).map_err(|e| TimeError::Transport(anyhow::Error::from(e)))
}

/// The `host.time.v1` service id.
fn host_time_service() -> ServiceId {
    ServiceId::parse(HOST_TIME_SERVICE).expect("host.time.v1 is a valid ServiceId")
}

/// Mint a per-call placeholder correlation id. The supervisor reassigns the
/// authoritative id at ingress, so this only distinguishes the guest's own
/// in-flight calls in its logs.
fn next_correlation_id() -> CorrelationId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("wl-time-{n}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use mvm_core::protocol::broker::ServiceResponse;

    use super::*;
    use crate::vsock::{read_frame, write_frame};

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
    fn now_sends_host_time_v1_now_envelope_and_returns_wall_ms() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"wall_ms": 1_717_000_000_000_u64}),
        });

        let resp = now_on(&mut client).expect("now must succeed");
        assert_eq!(resp.wall_ms, 1_717_000_000_000);
        handle.join().unwrap();

        let call = captured
            .lock()
            .unwrap()
            .take()
            .expect("server must capture call");
        assert_eq!(call.service.as_str(), "host.time.v1");
        assert_eq!(call.verb, "now");
        assert_eq!(call.payload, serde_json::json!({}));
    }

    #[test]
    fn now_surfaces_not_bound_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service `host.time.v1` not bound to workload".into(),
        });

        let err = now_on(&mut client).expect_err("must surface NotBound");
        assert!(matches!(err, TimeError::NotBound), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn now_surfaces_unavailable_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotReady,
            message: "broker subprocess still starting".into(),
        });

        let err = now_on(&mut client).expect_err("must surface unavailable");
        assert!(matches!(err, TimeError::Unavailable(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn now_maps_other_code_to_service_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::Timeout,
            message: "handler call timed out".into(),
        });

        let err = now_on(&mut client).expect_err("must surface service error");
        match err {
            TimeError::Service { code, .. } => assert_eq!(code, ServiceErrorCode::Timeout),
            other => panic!("expected Service, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn now_surfaces_malformed_payload_as_transport_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"not_wall_ms": 1}),
        });

        let err = now_on(&mut client).expect_err("malformed payload must error");
        assert!(matches!(err, TimeError::Transport(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn minted_correlation_ids_are_distinct() {
        assert_ne!(next_correlation_id(), next_correlation_id());
    }
}
