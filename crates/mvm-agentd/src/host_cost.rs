//! In-guest `host.cost.v1` typed methods — accumulated spend query.
//!
//! `workload` returns this workload's spend; `tenant` returns the
//! tenant-aggregated spend (mvmd-delegated, may answer
//! `CostError::NotImplemented` on a build without the cross-VM verb).
//! Both ride the broker transport ([`crate::broker_client`]) and decode the
//! shared wire contract
//! [`mvm_core::protocol::host_cost::CostReport`].
//!
//! Like every broker client this runs in the untrusted guest and is
//! advisory: it holds no key, the call carries a bare `ServiceCall`, and the
//! host derives identity from the connection and enforces the
//! `ExecutionPlan.services` binding before dispatch. The scope is the verb,
//! so the request body is empty — a workload cannot ask for another
//! workload's or tenant's spend.

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
use mvm_core::protocol::host_cost::CostReport;

use crate::broker_client::{self, BrokerError};

/// The broker service every cost query targets.
pub const HOST_COST_SERVICE: &str = "host.cost.v1";

/// Failure of a `host.cost.v1` call. Maps the broker's typed
/// [`ServiceErrorCode`] onto named variants the SDK veneer can surface as
/// distinct exceptions.
#[derive(Debug, thiserror::Error)]
pub enum CostError {
    /// The workload's `ExecutionPlan.services` did not bind `host.cost.v1`.
    #[error("host.cost.v1 not bound to this workload")]
    NotBound,
    /// The verb is not implemented in this build (e.g. `tenant` before the
    /// mvmd-delegated cross-VM verb lands).
    #[error("host.cost.v1 verb not implemented in this build")]
    NotImplemented,
    /// The host could not answer (handler down, mvmd unreachable for the
    /// tenant verb, broker not ready).
    #[error("host.cost.v1 unavailable: {0}")]
    Unavailable(String),
    /// Any other typed broker error code.
    #[error("host.cost.v1 failed [{code:?}]: {message}")]
    Service {
        /// The host's typed error code.
        code: ServiceErrorCode,
        /// Host-authored detail.
        message: String,
    },
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("host.cost.v1 transport error: {0}")]
    Transport(anyhow::Error),
}

impl From<BrokerError> for CostError {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::Transport(e) => CostError::Transport(e),
            BrokerError::Service { code, message } => match code {
                ServiceErrorCode::NotBound => CostError::NotBound,
                ServiceErrorCode::NotImplemented => CostError::NotImplemented,
                ServiceErrorCode::Unavailable | ServiceErrorCode::NotReady => {
                    CostError::Unavailable(message)
                }
                other => CostError::Service {
                    code: other,
                    message,
                },
            },
        }
    }
}

/// Query this workload's spend over an already-open broker stream.
pub fn workload_on(stream: &mut UnixStream) -> Result<CostReport, CostError> {
    call_on(stream, "workload")
}

/// Dial the broker port and query this workload's spend.
pub fn workload(timeout_secs: u64) -> Result<CostReport, CostError> {
    dial(timeout_secs, "workload")
}

/// Query the tenant-aggregated spend over an already-open broker stream.
pub fn tenant_on(stream: &mut UnixStream) -> Result<CostReport, CostError> {
    call_on(stream, "tenant")
}

/// Dial the broker port and query the tenant-aggregated spend.
pub fn tenant(timeout_secs: u64) -> Result<CostReport, CostError> {
    dial(timeout_secs, "tenant")
}

/// Exchange one cost `verb` over an already-open stream.
fn call_on(stream: &mut UnixStream, verb: &str) -> Result<CostReport, CostError> {
    let payload = broker_client::call(stream, &build_call(verb))?;
    decode(payload)
}

/// Dial the broker port and exchange one cost `verb`.
fn dial(timeout_secs: u64, verb: &str) -> Result<CostReport, CostError> {
    let payload = broker_client::broker_call(&build_call(verb), timeout_secs)?;
    decode(payload)
}

/// Build a `host.cost.v1` `ServiceCall` for `verb`. The verb selects the
/// scope, so the payload is empty; the `correlation_id` is a placeholder the
/// host reassigns at ingress.
fn build_call(verb: &str) -> ServiceCall {
    ServiceCall {
        service: host_cost_service(),
        verb: verb.to_string(),
        correlation_id: next_correlation_id(),
        payload: serde_json::json!({}),
    }
}

/// Decode a broker `Ok` payload into [`CostReport`].
fn decode(payload: serde_json::Value) -> Result<CostReport, CostError> {
    serde_json::from_value(payload).map_err(|e| CostError::Transport(anyhow::Error::from(e)))
}

/// The `host.cost.v1` service id.
fn host_cost_service() -> ServiceId {
    ServiceId::parse(HOST_COST_SERVICE).expect("host.cost.v1 is a valid ServiceId")
}

/// Mint a per-call placeholder correlation id. The supervisor reassigns the
/// authoritative id at ingress, so this only distinguishes the guest's own
/// in-flight calls in its logs.
fn next_correlation_id() -> CorrelationId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("wl-cost-{n}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use mvm_core::protocol::broker::ServiceResponse;

    use super::*;
    use crate::vsock::{read_frame, write_frame};

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
    fn workload_sends_host_cost_v1_workload_envelope_and_returns_spend() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"spent_micros_usd": 4_200_000_u64}),
        });

        let report = workload_on(&mut client).expect("workload must succeed");
        assert_eq!(report.spent_micros_usd, 4_200_000);
        handle.join().unwrap();

        let call = captured
            .lock()
            .unwrap()
            .take()
            .expect("server must capture call");
        assert_eq!(call.service.as_str(), "host.cost.v1");
        assert_eq!(call.verb, "workload");
        assert_eq!(call.payload, serde_json::json!({}));
    }

    #[test]
    fn tenant_sends_host_cost_v1_tenant_envelope() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"spent_micros_usd": 9_000_000_u64}),
        });

        let report = tenant_on(&mut client).expect("tenant must succeed");
        assert_eq!(report.spent_micros_usd, 9_000_000);
        handle.join().unwrap();

        let call = captured.lock().unwrap().take().expect("captured");
        assert_eq!(call.verb, "tenant");
    }

    #[test]
    fn tenant_surfaces_not_implemented_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotImplemented,
            message: "verb `tenant` not implemented in this build".into(),
        });

        let err = tenant_on(&mut client).expect_err("must surface NotImplemented");
        assert!(matches!(err, CostError::NotImplemented), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn workload_surfaces_not_bound_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service `host.cost.v1` not bound to workload".into(),
        });

        let err = workload_on(&mut client).expect_err("must surface NotBound");
        assert!(matches!(err, CostError::NotBound), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn workload_surfaces_unavailable_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::Unavailable,
            message: "mvmd unreachable".into(),
        });

        let err = workload_on(&mut client).expect_err("must surface unavailable");
        assert!(matches!(err, CostError::Unavailable(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn workload_maps_other_code_to_service_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::RateLimitExceeded,
            message: "rate limit".into(),
        });

        let err = workload_on(&mut client).expect_err("must surface service error");
        match err {
            CostError::Service { code, .. } => {
                assert_eq!(code, ServiceErrorCode::RateLimitExceeded)
            }
            other => panic!("expected Service, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn workload_surfaces_malformed_payload_as_transport_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"wrong": 1}),
        });

        let err = workload_on(&mut client).expect_err("malformed payload must error");
        assert!(matches!(err, CostError::Transport(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn minted_correlation_ids_are_distinct() {
        assert_ne!(next_correlation_id(), next_correlation_id());
    }
}
