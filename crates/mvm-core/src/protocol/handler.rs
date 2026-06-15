//! `ServiceHandler` trait + call-context types.
//!
//! Handlers live inside the per-service subprocess (`mvm-broker` for
//! `host.time.v1` / `host.cost.v1` / `host.audit.v1` / `broker.v1`;
//! there is no secrets dispatcher). The trait is defined in
//! `mvm-core` so each subprocess can implement it without depending on
//! the others' runtime crates. The supervisor's UDS proxies invoke
//! handlers across the process boundary via the
//! [`crate::protocol::broker::ServiceCall`] envelope; in-process
//! composition uses `ServiceCallCtx::invoke` for handler-to-handler
//! calls inside the same subprocess.
//!
//! The three-subprocess architecture this trait carves the seam for,
//! and which capability gates run on the supervisor side vs in the
//! handler subprocess, are part of the broker design.

use std::time::Duration;

use crate::policy::security::AgentProfile;
use crate::protocol::broker::{
    AuditDurability, CorrelationId, Idempotency, ServiceErrorCode, ServiceId,
};

/// Per-call context the supervisor hands to the handler.
///
/// Fields are populated by the supervisor *before* forwarding (the
/// supervisor-side capability gates). The handler must treat them as
/// authoritative; nothing the workload supplied is here.
#[derive(Debug, Clone)]
pub struct ServiceCallCtx {
    /// Workload identifier (assigned at admission, signed in the
    /// ExecutionPlan). Stable across calls within a workload's lifetime.
    pub workload_id: String,
    /// Tenant identifier the workload belongs to. Used by cross-VM
    /// handlers (`host.cost.v1::tenant`) to scope mvmd queries.
    pub tenant_id: String,
    /// Supervisor-assigned correlation id.
    pub correlation_id: CorrelationId,
    /// Workload session identifier (minted at admission, rotates per
    /// session). Audit chain entries carry this so post-hoc forensics
    /// can correlate calls within a session.
    pub session_id: String,
    /// Workload's `AgentProfile`. Handlers may decline certain verbs
    /// outside specific profiles (e.g. `BuilderOnly`).
    pub profile: AgentProfile,
    /// Current composition depth (cap 3). Zero for direct
    /// guest-originated calls; incremented per `invoke` hop.
    pub composition_depth: u8,
    /// Current composition width (cap 5). Resets per top-level call;
    /// incremented per sub-invocation by the same composing handler.
    pub composition_width: u8,
}

/// The result a handler returns from `dispatch`.
///
/// `Ok` carries the typed response payload (will be folded into a
/// `ServiceResponse::Ok` envelope by the broker substrate). `Err`
/// carries a typed error code + a message — the message MUST NOT
/// embed payload-derived data (redaction discipline).
pub type ServiceDispatchResult = Result<serde_json::Value, ServiceError>;

/// A typed handler error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: ServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Shorthand for the common `NotImplemented` case (used by handlers
    /// shipping partial verb sets, e.g. `host.cost.v1::tenant` before
    /// the cross-VM tenant verb lands).
    pub fn not_implemented(verb: impl AsRef<str>) -> Self {
        Self::new(
            ServiceErrorCode::NotImplemented,
            format!("verb `{}` not implemented in this build", verb.as_ref()),
        )
    }
}

/// A handler for one host-side service.
///
/// All four broker subprocesses implement this trait for the services
/// they host. The supervisor's `ServiceRegistry` keeps a
/// `HandlerRef::OutOfProcess(UdsProxy)` per handler under the
/// four-subprocess design; in-subprocess registration uses
/// `HandlerRef::InProcess(Arc<dyn ServiceHandler>)`.
///
/// **Not `async_trait`-only.** The trait is sync-shaped (`dispatch`
/// returns a future via an associated `BoxFuture`-like). This is
/// intentional: it keeps `mvm-core` free of `async-trait`/`tokio`
/// macros (those would force every consumer to drag in `tokio`). The
/// concrete subprocess crates wrap `tokio::spawn` around the future
/// at their dispatch loop.
///
/// **Static metadata.** `id`, `profiles`, `audit_durability`,
/// `response_size_cap`, `idempotency`, and `call_timeout` are
/// per-handler constants — they're read at registration time, not
/// per-call, so they can return cheap clones / values.
pub trait ServiceHandler: Send + Sync + 'static {
    /// The `ServiceId` this handler serves (e.g. `host.secrets.v1`).
    fn id(&self) -> ServiceId;

    /// Agent profiles this handler is callable from. The broker's
    /// gate 4 refuses calls from any profile not in the list.
    fn profiles(&self) -> &[AgentProfile];

    /// Per-call audit durability. `PerCall` blocks the response on
    /// audit fsync; `Batched(window)` enqueues synchronously and
    /// fsyncs on the background flusher.
    fn audit_durability(&self) -> AuditDurability;

    /// Maximum response size in bytes. Default 64 KiB. Larger →
    /// `ServiceErrorCode::ResponseTooLarge`.
    fn response_size_cap(&self) -> usize {
        64 * 1024
    }

    /// Per-handler idempotency contract.
    fn idempotency(&self) -> Idempotency;

    /// Per-handler call timeout. Beyond this →
    /// `ServiceErrorCode::Timeout`.
    fn call_timeout(&self) -> Duration;

    /// Dispatch one call. Implementations receive the supervisor's
    /// `ServiceCallCtx`, the verb name, and the typed payload (the
    /// handler is expected to call its own `parse_payload` on
    /// `payload` — the in-handler payload-parse gate).
    ///
    /// The returned future is boxed so the trait stays object-safe;
    /// concrete subprocess crates `tokio::spawn` it.
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>>;

    /// Services this handler composes with. A CI lint
    /// (`xtask check-handler-composition`) verifies the declared list
    /// matches actual `ctx.invoke(…)` call sites. Default empty (no
    /// composition).
    fn composes_with(&self) -> &[ServiceId] {
        &[]
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyHandler;

    impl ServiceHandler for DummyHandler {
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>>
        {
            Box::pin(async move { Ok(payload) })
        }
    }

    #[test]
    fn dummy_handler_metadata_is_readable() {
        let h = DummyHandler;
        assert_eq!(h.id().as_str(), "host.dev.echo.v1");
        assert_eq!(h.profiles(), &[AgentProfile::Dev]);
        assert_eq!(h.response_size_cap(), 64 * 1024);
        assert_eq!(h.call_timeout(), Duration::from_millis(5));
        assert_eq!(h.composes_with(), &[] as &[ServiceId]);
    }

    #[test]
    fn service_error_not_implemented_shorthand() {
        let e = ServiceError::not_implemented("tenant");
        assert_eq!(e.code, ServiceErrorCode::NotImplemented);
        assert!(e.message.contains("tenant"));
    }

    // `dispatch` is exercised end-to-end by the supervisor proxy crate;
    // the test here is just the trait shape.
}
