//! In-guest `host.kv.v1` typed methods — the per-workload key-value store.
//!
//! The store lives on the host and is reached over the broker transport
//! ([`crate::broker_client`]), so a workload gets durable storage with no
//! network path and no credential.
//!
//! Like every broker client this runs in the untrusted guest and is advisory:
//! it holds no key, the call carries a bare `ServiceCall`, and the host
//! derives identity from the connection and enforces the
//! `ExecutionPlan.services` binding before dispatch. In particular the guest
//! never names its own namespace — the host takes that from the call context,
//! so a guest cannot reach another workload's keys by asking.

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
use mvm_core::protocol::host_kv::{
    KvDeleteRequest, KvDeleteResponse, KvGetRequest, KvGetResponse, KvListRequest, KvListResponse,
    KvPutRequest, KvPutResponse,
};

use crate::broker_client::{self, BrokerError};

/// The broker service these methods target.
pub const HOST_KV_SERVICE: &str = "host.kv.v1";

/// Failure of a `host.kv.v1` call.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    /// The workload's `ExecutionPlan.services` did not bind `host.kv.v1`.
    #[error("host.kv.v1 not bound to this workload")]
    NotBound,
    /// The request was malformed — an invalid key, or an oversized value.
    #[error("host.kv.v1 rejected the request: {0}")]
    BadRequest(String),
    /// The host could not answer (handler down, broker not ready).
    #[error("host.kv.v1 unavailable: {0}")]
    Unavailable(String),
    /// Any other typed broker error code.
    #[error("host.kv.v1 failed [{code:?}]: {message}")]
    Service {
        /// The host's typed error code.
        code: ServiceErrorCode,
        /// Host-authored detail.
        message: String,
    },
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("host.kv.v1 transport error: {0}")]
    Transport(anyhow::Error),
}

impl From<BrokerError> for KvError {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::Transport(e) => KvError::Transport(e),
            BrokerError::Service { code, message } => match code {
                ServiceErrorCode::NotBound => KvError::NotBound,
                ServiceErrorCode::BadRequest => KvError::BadRequest(message),
                ServiceErrorCode::Unavailable | ServiceErrorCode::NotReady => {
                    KvError::Unavailable(message)
                }
                other => KvError::Service {
                    code: other,
                    message,
                },
            },
        }
    }
}

/// Read a key over an already-open broker stream.
pub fn get_on(stream: &mut UnixStream, key: &str) -> Result<KvGetResponse, KvError> {
    let call = build_call("get", KvGetRequest { key: key.into() })?;
    decode(broker_client::call(stream, &call)?)
}

/// Write a key over an already-open broker stream.
pub fn put_on(stream: &mut UnixStream, key: &str, value: &[u8]) -> Result<KvPutResponse, KvError> {
    let call = build_call(
        "put",
        KvPutRequest {
            key: key.into(),
            value: value.to_vec(),
        },
    )?;
    decode(broker_client::call(stream, &call)?)
}

/// Remove a key over an already-open broker stream.
pub fn delete_on(stream: &mut UnixStream, key: &str) -> Result<KvDeleteResponse, KvError> {
    let call = build_call("delete", KvDeleteRequest { key: key.into() })?;
    decode(broker_client::call(stream, &call)?)
}

/// List keys under a prefix over an already-open broker stream.
pub fn list_on(stream: &mut UnixStream, prefix: &str) -> Result<KvListResponse, KvError> {
    let call = build_call(
        "list",
        KvListRequest {
            prefix: prefix.into(),
        },
    )?;
    decode(broker_client::call(stream, &call)?)
}

/// Dial the broker port and read a key.
pub fn get(key: &str, timeout_secs: u64) -> Result<KvGetResponse, KvError> {
    let call = build_call("get", KvGetRequest { key: key.into() })?;
    decode(broker_client::broker_call(&call, timeout_secs)?)
}

/// Dial the broker port and write a key.
pub fn put(key: &str, value: &[u8], timeout_secs: u64) -> Result<KvPutResponse, KvError> {
    let call = build_call(
        "put",
        KvPutRequest {
            key: key.into(),
            value: value.to_vec(),
        },
    )?;
    decode(broker_client::broker_call(&call, timeout_secs)?)
}

/// Build a `host.kv.v1` `ServiceCall`. The `correlation_id` is a placeholder
/// the host reassigns at ingress.
fn build_call<T: serde::Serialize>(verb: &str, request: T) -> Result<ServiceCall, KvError> {
    Ok(ServiceCall {
        service: kv_service(),
        verb: verb.to_string(),
        correlation_id: next_correlation_id(),
        payload: serde_json::to_value(request)
            .map_err(|e| KvError::Transport(anyhow::Error::from(e)))?,
        capability: None,
    })
}

fn decode<T: serde::de::DeserializeOwned>(payload: serde_json::Value) -> Result<T, KvError> {
    serde_json::from_value(payload).map_err(|e| KvError::Transport(anyhow::Error::from(e)))
}

fn kv_service() -> ServiceId {
    ServiceId::parse(HOST_KV_SERVICE).expect("host.kv.v1 is a valid ServiceId")
}

fn next_correlation_id() -> CorrelationId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("wl-kv-{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_names_the_service_and_verb_and_carries_no_namespace() {
        let call = build_call("get", KvGetRequest { key: "k".into() }).expect("builds");
        assert_eq!(call.service.as_str(), "host.kv.v1");
        assert_eq!(call.verb, "get");
        // The guest never names its own namespace: the host takes that from
        // the call context. A workload_id on the wire would be a request to
        // read someone else's keys.
        assert!(call.payload.get("workload_id").is_none());
        assert_eq!(call.payload.get("key").and_then(|k| k.as_str()), Some("k"));
    }

    #[test]
    fn not_bound_maps_to_its_own_variant() {
        let err: KvError = BrokerError::Service {
            code: ServiceErrorCode::NotBound,
            message: "nope".into(),
        }
        .into();
        assert!(matches!(err, KvError::NotBound));
    }

    /// A refused key and an unavailable host are different problems for a
    /// caller: one is worth retrying, the other is a bug in the request.
    #[test]
    fn bad_request_and_unavailable_stay_distinct() {
        let bad: KvError = BrokerError::Service {
            code: ServiceErrorCode::BadRequest,
            message: "key".into(),
        }
        .into();
        assert!(matches!(bad, KvError::BadRequest(_)));

        let down: KvError = BrokerError::Service {
            code: ServiceErrorCode::Unavailable,
            message: "down".into(),
        }
        .into();
        assert!(matches!(down, KvError::Unavailable(_)));
    }

    #[test]
    fn correlation_ids_are_distinct_per_call() {
        let a = build_call("get", KvGetRequest { key: "a".into() }).expect("builds");
        let b = build_call("get", KvGetRequest { key: "b".into() }).expect("builds");
        assert_ne!(a.correlation_id, b.correlation_id);
    }
}
