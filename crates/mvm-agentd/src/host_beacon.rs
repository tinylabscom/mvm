//! In-guest `host.beacon.v1` typed method — the boot beacon.
//!
//! The platform's own guest agent calls `report` exactly once at boot,
//! over the broker transport ([`crate::broker_client`]), to record on
//! the host's chain-signed audit log that the admitted workload's agent
//! came alive. The payload types ([`BeaconReport`] / [`BeaconAck`]) are
//! the shared wire contract in [`mvm_core::protocol::host_beacon`].
//!
//! The beacon is advisory and fail-open by design: a missing host
//! broker (dev images without an audit signer, boot-time races) must
//! never delay or fail the agent's boot. Callers log and move on.
//!
//! This client is **not a security boundary** — it runs inside the
//! untrusted guest and carries no key. The host stamps the
//! authoritative identity into the chain entry from the connection
//! context; the guest cannot influence the binding.

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
use mvm_core::protocol::host_beacon::{BeaconAck, BeaconReport, HOST_BEACON_SERVICE};

use crate::broker_client::{self, BrokerError};

/// Failure of a `host.beacon.v1` call. The beacon is best-effort, so
/// callers typically log and continue; the typed variants exist so a
/// caller that *does* care can distinguish refusal kinds.
#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    /// The host rejected the report shape.
    #[error("beacon report rejected: {0}")]
    BadRequest(String),
    /// The host audit path is unavailable (signer down).
    #[error("beacon service unavailable: {0}")]
    Unavailable(String),
    /// `host.beacon.v1` is not registered for this workload (no audit
    /// signer configured).
    #[error("beacon service not bound")]
    NotBound,
    /// Any other typed broker error code.
    #[error("beacon failed [{code:?}]: {message}")]
    Service {
        /// The host's typed error code.
        code: ServiceErrorCode,
        /// Host-authored detail.
        message: String,
    },
    /// Connect, framing, or (de)serialization failure on the vsock path.
    #[error("beacon transport error: {0}")]
    Transport(anyhow::Error),
}

impl From<BrokerError> for BeaconError {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::Transport(e) => BeaconError::Transport(e),
            BrokerError::Service { code, message } => match code {
                ServiceErrorCode::BadRequest => BeaconError::BadRequest(message),
                ServiceErrorCode::Unavailable => BeaconError::Unavailable(message),
                ServiceErrorCode::NotBound => BeaconError::NotBound,
                other => BeaconError::Service {
                    code: other,
                    message,
                },
            },
        }
    }
}

/// Report the boot beacon with bounded retries, then give up quietly.
///
/// Called once from the guest agent's boot path. The host broker
/// subprocess can still be starting when the agent comes up, so a
/// small number of spaced retries covers the race; every failure mode
/// is fail-open because a missing beacon must never delay or fail the
/// workload boot.
pub fn report_boot_beacon(boot_unix_ms: u64) {
    let beacon = BeaconReport {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        boot_unix_ms,
    };
    const ATTEMPTS: u32 = 3;
    const BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);
    // The outcome is already logged inside the retry loop; the boot
    // path deliberately ignores it.
    let _ = report_with_retries(&beacon, ATTEMPTS, BACKOFF, |r| report(r, 5));
}

/// Retry wrapper over a `dial` closure, exposed for testing. Returns
/// the final outcome after `attempts` tries spaced by `backoff`.
fn report_with_retries(
    report: &BeaconReport,
    attempts: u32,
    backoff: std::time::Duration,
    mut dial: impl FnMut(&BeaconReport) -> Result<BeaconAck, BeaconError>,
) -> Result<BeaconAck, BeaconError> {
    let mut last = None;
    for attempt in 1..=attempts {
        match dial(report) {
            Ok(ack) => return Ok(ack),
            Err(err) => {
                tracing::debug!(
                    attempt,
                    attempts,
                    error = %err,
                    "boot beacon report failed; the host broker may not be up yet"
                );
                last = Some(err);
                if attempt < attempts {
                    std::thread::sleep(backoff);
                }
            }
        }
    }
    let err = last.expect("at least one attempt always runs");
    tracing::warn!(error = %err, "boot beacon report gave up; continuing without it");
    Err(err)
}

/// Report agent liveness over an already-open broker stream.
pub fn report_on(stream: &mut UnixStream, report: &BeaconReport) -> Result<BeaconAck, BeaconError> {
    let call = build_call(report)?;
    let payload = broker_client::call(stream, &call)?;
    decode(payload)
}

/// Dial the broker port and report agent liveness.
pub fn report(report: &BeaconReport, timeout_secs: u64) -> Result<BeaconAck, BeaconError> {
    let call = build_call(report)?;
    let payload = broker_client::broker_call(&call, timeout_secs)?;
    decode(payload)
}

/// Build the `host.beacon.v1` `ServiceCall`. The `correlation_id` is a
/// placeholder the host reassigns at frame ingress.
fn build_call(report: &BeaconReport) -> Result<ServiceCall, BeaconError> {
    let payload =
        serde_json::to_value(report).map_err(|e| BeaconError::Transport(anyhow::Error::from(e)))?;
    Ok(ServiceCall {
        service: host_beacon_service(),
        verb: "report".to_string(),
        correlation_id: next_correlation_id(),
        payload,
        capability: None,
    })
}

/// Decode a broker `Ok` payload into the typed response `T`.
fn decode<T: serde::de::DeserializeOwned>(payload: serde_json::Value) -> Result<T, BeaconError> {
    serde_json::from_value(payload).map_err(|e| BeaconError::Transport(anyhow::Error::from(e)))
}

/// The `host.beacon.v1` service id.
fn host_beacon_service() -> ServiceId {
    ServiceId::parse(HOST_BEACON_SERVICE).expect("host.beacon.v1 is a valid ServiceId")
}

/// Mint a per-call placeholder correlation id; the supervisor reassigns
/// the authoritative id at ingress.
fn next_correlation_id() -> CorrelationId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("wl-beacon-{n}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use mvm_core::protocol::broker::ServiceResponse;

    use super::*;
    use crate::vsock::{read_frame, write_frame};

    fn sample_report() -> BeaconReport {
        BeaconReport {
            agent_version: "0.17.0".into(),
            boot_unix_ms: 1_787_181_844_000,
        }
    }

    /// Spawn a mock broker on the server half of a socket pair: read the
    /// one `ServiceCall`, hand it to `respond` (which also captures it),
    /// write the returned `ServiceResponse`.
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
    fn report_sends_host_beacon_v1_envelope_and_returns_chain_head() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"chain_head": "head-001"}),
        });

        let ack = report_on(&mut client, &sample_report()).expect("report must succeed");
        assert_eq!(ack.chain_head, "head-001");
        handle.join().unwrap();

        let call = captured
            .lock()
            .unwrap()
            .take()
            .expect("server must capture call");
        assert_eq!(call.service.as_str(), "host.beacon.v1");
        assert_eq!(call.verb, "report");
        assert!(
            call.payload.get("workload_id").is_none(),
            "guest payload must not carry identity fields"
        );
        let report: BeaconReport = serde_json::from_value(call.payload).unwrap();
        assert_eq!(report, sample_report());
    }

    #[test]
    fn report_surfaces_not_bound_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service `host.beacon.v1` not registered".into(),
        });

        let err = report_on(&mut client, &sample_report()).expect_err("must surface NotBound");
        assert!(matches!(err, BeaconError::NotBound), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn report_surfaces_unavailable_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::Unavailable,
            message: "audit-signer transport failed".into(),
        });

        let err = report_on(&mut client, &sample_report()).expect_err("must surface unavailable");
        assert!(matches!(err, BeaconError::Unavailable(_)), "got {err:?}");
        handle.join().unwrap();
    }

    #[test]
    fn report_surfaces_bad_request_as_typed_error() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::BadRequest,
            message: "payload parse failed".into(),
        });

        let err = report_on(&mut client, &sample_report()).expect_err("must surface BadRequest");
        match err {
            BeaconError::BadRequest(msg) => assert!(msg.contains("parse")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn minted_correlation_ids_are_distinct() {
        assert_ne!(next_correlation_id(), next_correlation_id());
    }

    #[test]
    fn retries_return_ack_on_first_success() {
        let report = sample_report();
        let mut calls = 0;
        let outcome = report_with_retries(&report, 3, std::time::Duration::ZERO, |r| {
            calls += 1;
            assert_eq!(r, &sample_report());
            Ok(BeaconAck {
                chain_head: "head-1".into(),
            })
        });
        assert_eq!(outcome.expect("succeeds").chain_head, "head-1");
        assert_eq!(calls, 1, "no retry after success");
    }

    #[test]
    fn retries_exhaust_attempts_and_return_last_error() {
        let report = sample_report();
        let mut calls = 0;
        let outcome = report_with_retries(&report, 3, std::time::Duration::ZERO, |_| {
            calls += 1;
            Err(BeaconError::NotBound)
        });
        assert!(matches!(outcome, Err(BeaconError::NotBound)), "{outcome:?}");
        assert_eq!(calls, 3, "every attempt must run");
    }

    #[test]
    fn retries_succeed_after_transient_failure() {
        let report = sample_report();
        let mut calls = 0;
        let outcome = report_with_retries(&report, 3, std::time::Duration::ZERO, |_| {
            calls += 1;
            if calls == 1 {
                Err(BeaconError::Unavailable("signer starting".into()))
            } else {
                Ok(BeaconAck {
                    chain_head: "head-2".into(),
                })
            }
        });
        assert_eq!(outcome.expect("recovers").chain_head, "head-2");
        assert_eq!(calls, 2);
    }
}
