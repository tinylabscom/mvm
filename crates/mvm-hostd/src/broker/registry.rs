//! Handler registry — the in-subprocess lookup that dispatches a
//! `ServiceCall` to the right [`ServiceHandler`].
//!
//! W1a ships the registry shape with zero handlers registered (every
//! call returns `Err(NotBound)`). W3 (`host.time.v1`), W4a
//! (`host.cost.v1` workload verb), and the `broker.v1/list_services`
//! introspection verb wire in their handlers via [`Registry::register`].

use std::collections::HashMap;
use std::sync::Arc;

use mvm_core::protocol::broker::{ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};

/// Per-subprocess handler registry. Handlers registered at startup live
/// for the subprocess lifetime; runtime registration is not supported
/// (the static catalog is the Plan 104 contract).
pub struct Registry {
    handlers: HashMap<ServiceId, Arc<dyn ServiceHandler>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler. Replaces any previous handler for the same
    /// `ServiceId` (test convenience; admission rejects duplicate
    /// bindings at the plan-verification layer, not here).
    pub fn register(&mut self, handler: Arc<dyn ServiceHandler>) {
        self.handlers.insert(handler.id(), handler);
    }

    /// Dispatch a call. Returns `Err(NotBound)` for any service not in
    /// the registry. Per-handler `parse_payload` (gate 5) happens
    /// inside the handler's `dispatch`; the registry just routes.
    pub async fn dispatch(
        &self,
        ctx: &ServiceCallCtx,
        service: &ServiceId,
        verb: &str,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let Some(handler) = self.handlers.get(service) else {
            return Err(ServiceError::new(
                ServiceErrorCode::NotBound,
                format!(
                    "service `{}` not bound to workload `{}`",
                    service, ctx.workload_id
                ),
            ));
        };
        handler.dispatch(ctx, verb, payload).await
    }

    /// True if any handler is registered. Useful for the broker's
    /// startup readiness gate.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::time::Duration;

    use mvm_core::policy::security::AgentProfile;
    use mvm_core::protocol::broker::{
        AuditDurability, CorrelationId, Idempotency, ServiceErrorCode, ServiceId,
    };
    use mvm_core::protocol::handler::ServiceCallCtx;

    use super::*;

    struct EchoHandler;

    impl ServiceHandler for EchoHandler {
        fn id(&self) -> ServiceId {
            ServiceId::parse("host.dev.echo.v1").unwrap()
        }
        fn profiles(&self) -> &[AgentProfile] {
            &[AgentProfile::Dev]
        }
        fn audit_durability(&self) -> AuditDurability {
            AuditDurability::default_batched()
        }
        fn idempotency(&self) -> Idempotency {
            Idempotency::MintFresh
        }
        fn call_timeout(&self) -> Duration {
            Duration::from_millis(5)
        }
        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            _verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move { Ok(payload) })
        }
    }

    fn ctx() -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: "wl-test".into(),
            tenant_id: "t-test".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            session_id: "sess-test".into(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    #[tokio::test]
    async fn unbound_service_returns_not_bound() {
        let registry = Registry::new();
        let svc = ServiceId::parse("host.time.v1").unwrap();
        let err = registry
            .dispatch(&ctx(), &svc, "now", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::NotBound);
        assert!(err.message.contains("host.time.v1"));
        assert!(err.message.contains("wl-test"));
    }

    #[tokio::test]
    async fn registered_handler_dispatches() {
        let mut registry = Registry::new();
        registry.register(Arc::new(EchoHandler));
        let svc = ServiceId::parse("host.dev.echo.v1").unwrap();
        let payload = serde_json::json!({"hello": "world"});
        let result = registry
            .dispatch(&ctx(), &svc, "echo", payload.clone())
            .await
            .unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn empty_registry_reports_empty() {
        assert!(Registry::new().is_empty());
    }
}
