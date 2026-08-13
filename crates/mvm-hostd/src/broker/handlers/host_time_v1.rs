//! `host.time.v1` — host-authoritative wall-clock queries.

use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_time::TimeNowResponse;

/// Handler for the `host.time.v1` service.
pub struct HostTimeV1Handler;

impl HostTimeV1Handler {
    /// Construct the stateless host-time handler.
    pub fn new() -> Self {
        Self
    }

    fn now(payload: &serde_json::Value) -> ServiceDispatchResult {
        if payload.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                "host.time.v1 now payload must be an empty object",
            ));
        }
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            ServiceError::new(
                ServiceErrorCode::Unavailable,
                "host wall clock is before the Unix epoch",
            )
        })?;
        let wall_ms = u64::try_from(elapsed.as_millis()).map_err(|_| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                "host wall clock does not fit the wire representation",
            )
        })?;
        serde_json::to_value(TimeNowResponse { wall_ms }).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("host.time.v1 response encode failed: {error}"),
            )
        })
    }
}

impl Default for HostTimeV1Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceHandler for HostTimeV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse("host.time.v1").expect("host.time.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        &[
            AgentProfile::SealedProd,
            AgentProfile::Dev,
            AgentProfile::Builder,
        ]
    }

    fn audit_durability(&self) -> AuditDurability {
        AuditDurability::default_batched()
    }

    fn idempotency(&self) -> Idempotency {
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn dispatch<'a>(
        &'a self,
        _ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            match verb {
                "now" => Self::now(&payload),
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("host.time.v1: unknown verb `{other}`"),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: "workload".into(),
            tenant_id: "tenant".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("correlation"),
            session_id: "session".into(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    #[tokio::test]
    async fn now_returns_host_wall_clock_milliseconds() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let response = HostTimeV1Handler::new()
            .dispatch(&context(), "now", serde_json::json!({}))
            .await
            .unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let decoded: TimeNowResponse = serde_json::from_value(response).unwrap();
        assert!((before..=after).contains(&decoded.wall_ms));
    }

    #[tokio::test]
    async fn now_rejects_nonempty_payloads() {
        let error = HostTimeV1Handler::new()
            .dispatch(&context(), "now", serde_json::json!({"timezone": "UTC"}))
            .await
            .unwrap_err();
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn unknown_verb_is_not_implemented() {
        let error = HostTimeV1Handler::new()
            .dispatch(&context(), "tomorrow", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code, ServiceErrorCode::NotImplemented);
    }
}
