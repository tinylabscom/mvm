//! Handler registry — the in-subprocess lookup that dispatches a
//! `ServiceCall` to the right [`ServiceHandler`].
//!
//! The registry starts with zero handlers registered (every call
//! returns `Err(NotBound)`); `host.time.v1` and the `host.cost.v1`
//! workload verb wire in their handlers via [`Registry::register`].
//!
//! [`Registry::admitted_catalog`] is the only projection of this state a
//! guest may be shown.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mvm_contract::protocol::agent_capability::{
    CapabilityAuditEvent, CapabilityBinding, CapabilityDescriptor, CapabilityFailureCode,
    CapabilityId, CapabilityInvocation, evaluate_argument_policy, payload_digest,
};
use mvm_contract::protocol::agent_session::AgentRequestId;
use mvm_core::protocol::broker::{ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};

/// How many times one unbound name may be refused with a teaching message
/// before further attempts are answered tersely.
///
/// A planner that has been told its surface and keeps calling the same absent
/// name is in a loop, and each attempt costs a dispatch and an audit line.
const MAX_UNBOUND_ATTEMPTS_PER_NAME: u32 = 8;

/// How many distinct refused names are tracked at once.
///
/// The counter is keyed by a guest-supplied string, so the counter is itself
/// an exhaustion surface: a guest enumerating names would otherwise grow this
/// map without bound. Past the cap, untracked names are answered as
/// rate-bounded rather than admitted to the map — enumeration on a workload
/// whose real catalog is a handful of entries is already pathological.
const MAX_TRACKED_REFUSAL_NAMES: usize = 64;

/// Minimal cancellation primitive for one host-side capability invocation.
#[derive(Clone, Default)]
pub struct CancellationToken {
    canceled: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl CancellationToken {
    /// Create a token that has not been canceled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel all current and future waiters.
    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Whether cancellation has already been requested.
    pub fn is_cancelled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

/// Host-owned sink for digest-only capability lifecycle evidence.
pub trait CapabilityAuditSink: Send + Sync + 'static {
    /// Record one event without receiving payload or handler error text.
    fn record(&self, event: CapabilityAuditEvent);
}

struct NoopCapabilityAuditSink;

impl CapabilityAuditSink for NoopCapabilityAuditSink {
    fn record(&self, _event: CapabilityAuditEvent) {}
}

struct CapabilityRegistration {
    descriptor: CapabilityDescriptor,
    handler: Arc<dyn ServiceHandler>,
}

/// Per-subprocess handler registry. Handlers registered at startup live
/// for the subprocess lifetime; runtime registration is not supported
/// (the static catalog is the contract).
pub struct Registry {
    handlers: HashMap<ServiceId, Arc<dyn ServiceHandler>>,
    capability_only_services: HashSet<ServiceId>,
    capabilities: HashMap<CapabilityId, CapabilityRegistration>,
    admitted: HashMap<CapabilityId, [u8; 32]>,
    consumed_invocations: std::sync::Mutex<HashSet<(CapabilityId, AgentRequestId)>>,
    refusal_counts: std::sync::Mutex<HashMap<String, u32>>,
    audit: Arc<dyn CapabilityAuditSink>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            capability_only_services: HashSet::new(),
            capabilities: HashMap::new(),
            admitted: HashMap::new(),
            consumed_invocations: std::sync::Mutex::new(HashSet::new()),
            refusal_counts: std::sync::Mutex::new(HashMap::new()),
            audit: Arc::new(NoopCapabilityAuditSink),
        }
    }

    /// Install the host-signed exact bindings for this workload.
    pub fn admit_capabilities<I>(&mut self, bindings: I) -> Result<(), RegistryError>
    where
        I: IntoIterator<Item = CapabilityBinding>,
    {
        for binding in bindings {
            if self
                .admitted
                .insert(binding.capability.clone(), binding.descriptor_digest)
                .is_some()
            {
                return Err(RegistryError::DuplicateAdmission(binding.capability));
            }
            self.audit.record(CapabilityAuditEvent::Admitted {
                capability: binding.capability,
                descriptor_digest: binding.descriptor_digest,
            });
        }
        Ok(())
    }

    /// Replace the audit sink used by typed dispatch.
    pub fn with_capability_audit_sink(mut self, audit: Arc<dyn CapabilityAuditSink>) -> Self {
        self.audit = audit;
        self
    }

    /// Register a handler. Replaces any previous handler for the same
    /// `ServiceId` (test convenience; admission rejects duplicate
    /// bindings at the plan-verification layer, not here).
    pub fn register(&mut self, handler: Arc<dyn ServiceHandler>) {
        self.handlers.insert(handler.id(), handler);
    }

    /// Require every call to `service` to carry admitted typed-capability
    /// metadata. Controller proxies use this so a direct legacy service call
    /// cannot bypass descriptor, replay, and payload gates.
    pub fn require_capability(&mut self, service: ServiceId) {
        self.capability_only_services.insert(service);
    }

    /// Register one explicitly described per-verb capability.
    pub fn register_capability(
        &mut self,
        handler: Arc<dyn ServiceHandler>,
        descriptor: CapabilityDescriptor,
    ) -> Result<(), RegistryError> {
        if handler.id() != descriptor.id.service {
            return Err(RegistryError::HandlerIdentityMismatch {
                handler: handler.id(),
                descriptor: descriptor.id.service,
            });
        }
        let id = descriptor.id.clone();
        if self
            .capabilities
            .insert(
                id.clone(),
                CapabilityRegistration {
                    descriptor: descriptor.clone(),
                    handler,
                },
            )
            .is_some()
        {
            return Err(RegistryError::DuplicateRegistration(id));
        }
        let descriptor_digest = descriptor.digest();
        self.audit.record(CapabilityAuditEvent::Registered {
            capability: descriptor.id.clone(),
            descriptor_digest,
        });
        Ok(())
    }

    /// The capability set a guest may be shown: those registered here whose
    /// descriptor still digests to what the host-signed admission bound.
    ///
    /// The intersection carries the weight. A registration is local to this
    /// subprocess and can drift; an admission is signed and derives from the
    /// workload's plan. Projecting the registered set instead would let a
    /// local registration advertise authority the plan never granted, which
    /// inverts the direction the binding model depends on.
    #[must_use]
    pub fn admitted_catalog(&self) -> Vec<CapabilityDescriptor> {
        let mut catalog: Vec<CapabilityDescriptor> = self
            .capabilities
            .iter()
            .filter(|(id, registration)| {
                self.admitted
                    .get(*id)
                    .is_some_and(|admitted| *admitted == registration.descriptor.digest())
            })
            .map(|(_, registration)| registration.descriptor.clone())
            .collect();
        catalog.sort_by_key(|descriptor| descriptor.id.to_string());
        catalog
    }

    /// Render the admitted catalog as a refusal suffix.
    ///
    /// A refusal that only says "no" leaves a planner guessing, and a guessing
    /// planner retries. Naming the surface it *does* have turns the wall into
    /// a fact it can plan around. This discloses nothing: the catalog is the
    /// projection of the workload's own admission.
    fn surface_hint(&self) -> String {
        let names: Vec<String> = self
            .admitted_catalog()
            .into_iter()
            .map(|descriptor| descriptor.id.to_string())
            .collect();
        if names.is_empty() {
            "this workload has no capabilities bound".to_string()
        } else {
            format!("bound capabilities: {}", names.join(", "))
        }
    }

    /// Count one refusal of `name` and say whether to keep teaching.
    ///
    /// Returns `true` while the caller should still receive the surface hint.
    fn should_still_teach(&self, name: &str) -> bool {
        let mut counts = self.refusal_counts.lock().expect("refusal mutex");
        if let Some(count) = counts.get_mut(name) {
            *count = count.saturating_add(1);
            return *count <= MAX_UNBOUND_ATTEMPTS_PER_NAME;
        }
        if counts.len() < MAX_TRACKED_REFUSAL_NAMES {
            counts.insert(name.to_string(), 1);
            return true;
        }
        // The map is full. Refuse tersely rather than admit another
        // guest-chosen key; see MAX_TRACKED_REFUSAL_NAMES.
        false
    }

    /// Build a refusal that teaches while that is still useful, and stays
    /// terse once the caller has demonstrably stopped listening.
    fn teaching_refusal(
        &self,
        code: ServiceErrorCode,
        subject: &str,
        detail: String,
    ) -> ServiceError {
        if self.should_still_teach(subject) {
            ServiceError::new(code, format!("{detail}; {}", self.surface_hint()))
        } else {
            ServiceError::new(
                code,
                format!("{detail}; further attempts on `{subject}` are rate-bounded"),
            )
        }
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
        if self.capability_only_services.contains(service) {
            return Err(ServiceError::new(
                ServiceErrorCode::CapabilityDenied,
                "this service requires an admitted typed capability invocation",
            ));
        }
        let Some(handler) = self.handlers.get(service) else {
            return Err(self.teaching_refusal(
                ServiceErrorCode::NotBound,
                &service.to_string(),
                format!(
                    "service `{}` not bound to workload `{}`",
                    service, ctx.workload_id
                ),
            ));
        };
        handler.dispatch(ctx, verb, payload).await
    }

    /// Dispatch a typed capability call after every admission and resource
    /// gate has passed. The cancellation token is owned by the host protocol
    /// layer; canceling it drops the handler future before returning.
    pub async fn dispatch_capability(
        &self,
        ctx: &ServiceCallCtx,
        service: &ServiceId,
        verb: &str,
        invocation: &CapabilityInvocation,
        payload: serde_json::Value,
        cancellation: &CancellationToken,
    ) -> ServiceDispatchResult {
        let capability = match CapabilityId::new(service.clone(), verb.to_string()) {
            Ok(capability) => capability,
            Err(_) => return Err(capability_error(CapabilityFailureCode::ProtocolMismatch)),
        };
        // Both misses below are surface-discovery failures rather than
        // malformed requests, so they teach: see `teaching_refusal`.
        let Some(registration) = self.capabilities.get(&capability) else {
            return Err(self.teaching_refusal(
                ServiceErrorCode::NotBound,
                &capability.to_string(),
                format!(
                    "typed capability request refused: {:?}",
                    CapabilityFailureCode::NotRegistered
                ),
            ));
        };
        let Some(admitted_digest) = self.admitted.get(&capability) else {
            self.record_refusal(
                &capability,
                invocation,
                CapabilityFailureCode::AdmissionDenied,
            );
            return Err(self.teaching_refusal(
                ServiceErrorCode::CapabilityDenied,
                &capability.to_string(),
                format!(
                    "typed capability request refused: {:?}",
                    CapabilityFailureCode::AdmissionDenied
                ),
            ));
        };
        if *admitted_digest != invocation.binding.descriptor_digest
            || !invocation.binding.matches(&registration.descriptor)
        {
            self.record_refusal(
                &capability,
                invocation,
                CapabilityFailureCode::BindingMismatch,
            );
            return Err(capability_error(CapabilityFailureCode::BindingMismatch));
        }
        if let Err(code) = invocation.validate_payload(&registration.descriptor, &payload) {
            self.record_refusal(&capability, invocation, code);
            return Err(capability_error(code));
        }
        let input_bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.record_refusal(&capability, invocation, CapabilityFailureCode::InvalidInput);
                return Err(capability_error(CapabilityFailureCode::InvalidInput));
            }
        };
        if input_bytes.len() > registration.descriptor.limits.max_input_bytes as usize {
            self.record_refusal(
                &capability,
                invocation,
                CapabilityFailureCode::InputTooLarge,
            );
            return Err(capability_error(CapabilityFailureCode::InputTooLarge));
        }
        if let Err(refusal) =
            evaluate_argument_policy(&registration.descriptor.argument_policy, &payload)
        {
            self.record_refusal(
                &capability,
                invocation,
                CapabilityFailureCode::ArgumentRefused,
            );
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!(
                    "argument at `{}` refused by the {} policy for {}",
                    refusal.pointer, refusal.kind, capability
                ),
            ));
        }
        let replay_key = (capability.clone(), invocation.invocation_id.clone());
        let inserted = self
            .consumed_invocations
            .lock()
            .expect("capability replay mutex is not poisoned")
            .insert(replay_key);
        if !inserted {
            self.record_refusal(&capability, invocation, CapabilityFailureCode::Replay);
            return Err(capability_error(CapabilityFailureCode::Replay));
        }
        if cancellation.is_cancelled() {
            self.record_canceled(&capability, invocation);
            return Err(capability_error(CapabilityFailureCode::Canceled));
        }

        self.audit.record(CapabilityAuditEvent::Invoked {
            capability: capability.clone(),
            descriptor_digest: registration.descriptor.digest(),
            invocation_id: invocation.invocation_id.clone(),
            input_digest: invocation.input_digest,
        });
        let timeout = Duration::from_millis(u64::from(registration.descriptor.limits.timeout_ms));
        let dispatch = registration.handler.dispatch(ctx, verb, payload);
        tokio::pin!(dispatch);
        let result = tokio::select! {
            _ = cancellation.cancelled() => {
                self.record_canceled(&capability, invocation);
                return Err(capability_error(CapabilityFailureCode::Canceled));
            }
            result = tokio::time::timeout(timeout, &mut dispatch) => result,
        };
        let output = match result {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                let code = if error.code == ServiceErrorCode::BadRequest {
                    CapabilityFailureCode::InvalidInput
                } else {
                    CapabilityFailureCode::HandlerFailed
                };
                self.audit.record(CapabilityAuditEvent::Failed {
                    capability,
                    invocation_id: invocation.invocation_id.clone(),
                    code,
                });
                return Err(capability_error(code));
            }
            Err(_) => {
                self.audit.record(CapabilityAuditEvent::TimedOut {
                    capability,
                    invocation_id: invocation.invocation_id.clone(),
                });
                return Err(capability_error(CapabilityFailureCode::Timeout));
            }
        };
        let output_bytes = match serde_json::to_vec(&output) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.audit.record(CapabilityAuditEvent::Failed {
                    capability,
                    invocation_id: invocation.invocation_id.clone(),
                    code: CapabilityFailureCode::HandlerFailed,
                });
                return Err(capability_error(CapabilityFailureCode::HandlerFailed));
            }
        };
        if output_bytes.len() > registration.descriptor.limits.max_output_bytes as usize {
            self.audit.record(CapabilityAuditEvent::Failed {
                capability,
                invocation_id: invocation.invocation_id.clone(),
                code: CapabilityFailureCode::OutputTooLarge,
            });
            return Err(capability_error(CapabilityFailureCode::OutputTooLarge));
        }
        self.audit.record(CapabilityAuditEvent::Completed {
            capability,
            invocation_id: invocation.invocation_id.clone(),
            output_digest: payload_digest(&output),
        });
        Ok(output)
    }

    fn record_refusal(
        &self,
        capability: &CapabilityId,
        invocation: &CapabilityInvocation,
        code: CapabilityFailureCode,
    ) {
        self.audit.record(CapabilityAuditEvent::Refused {
            capability: capability.clone(),
            invocation_id: Some(invocation.invocation_id.clone()),
            code,
        });
    }

    fn record_canceled(&self, capability: &CapabilityId, invocation: &CapabilityInvocation) {
        self.audit.record(CapabilityAuditEvent::Canceled {
            capability: capability.clone(),
            invocation_id: invocation.invocation_id.clone(),
        });
    }

    /// True if any handler is registered. Useful for the broker's
    /// startup readiness gate.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Registration failures are host configuration errors, never guest data.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("capability {0} was admitted more than once")]
    DuplicateAdmission(CapabilityId),
    #[error("capability {0} was registered more than once")]
    DuplicateRegistration(CapabilityId),
    #[error("handler service {handler} does not own descriptor service {descriptor}")]
    HandlerIdentityMismatch {
        handler: ServiceId,
        descriptor: ServiceId,
    },
}

fn capability_error(code: CapabilityFailureCode) -> ServiceError {
    let service_code = match code {
        CapabilityFailureCode::ProtocolMismatch => ServiceErrorCode::CapabilityProtocolMismatch,
        CapabilityFailureCode::NotRegistered => ServiceErrorCode::NotBound,
        CapabilityFailureCode::AdmissionDenied => ServiceErrorCode::CapabilityDenied,
        CapabilityFailureCode::BindingMismatch | CapabilityFailureCode::InputDigestMismatch => {
            ServiceErrorCode::CapabilityBindingMismatch
        }
        CapabilityFailureCode::InputTooLarge => ServiceErrorCode::CapabilityInputTooLarge,
        CapabilityFailureCode::InvalidInput | CapabilityFailureCode::ArgumentRefused => {
            ServiceErrorCode::BadRequest
        }
        CapabilityFailureCode::OutputTooLarge => ServiceErrorCode::CapabilityOutputTooLarge,
        CapabilityFailureCode::Timeout => ServiceErrorCode::Timeout,
        CapabilityFailureCode::Canceled => ServiceErrorCode::CapabilityCanceled,
        CapabilityFailureCode::Replay => ServiceErrorCode::CapabilityReplay,
        CapabilityFailureCode::HandlerFailed => ServiceErrorCode::CapabilityHandlerFailed,
    };
    ServiceError::new(
        service_code,
        format!("typed capability request refused: {code:?}"),
    )
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
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mvm_contract::protocol::agent_capability::{
        ArgumentConstraint, ArgumentRule, CapabilityAuditEvent, CapabilityDescriptor, CapabilityId,
        CapabilityInvocation, CapabilityLimits, SchemaRef,
    };
    use mvm_contract::protocol::agent_session::AgentRequestId;
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

    struct InvalidInputHandler;

    impl ServiceHandler for InvalidInputHandler {
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
            _payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async {
                Err(ServiceError::new(
                    ServiceErrorCode::BadRequest,
                    "input does not match the capability schema",
                ))
            })
        }
    }

    enum Behavior {
        Delay,
        Expand,
        Fail,
    }

    struct BehaviorHandler {
        behavior: Behavior,
    }

    impl ServiceHandler for BehaviorHandler {
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
            Duration::from_millis(100)
        }
        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            _verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move {
                match self.behavior {
                    Behavior::Delay => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(payload)
                    }
                    Behavior::Expand => Ok(serde_json::json!({
                        "expanded": "x".repeat(200),
                    })),
                    Behavior::Fail => Err(ServiceError::new(
                        ServiceErrorCode::Unavailable,
                        "private handler failure detail",
                    )),
                }
            })
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

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                "echo",
            )
            .expect("capability id"))
            .description("echo a bounded test value")
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(128, 128, 50).expect("limits"))
            .build()
            .expect("descriptor")
    }

    #[derive(Clone, Default)]
    struct TestAudit(Arc<Mutex<Vec<CapabilityAuditEvent>>>);

    impl CapabilityAuditSink for TestAudit {
        fn record(&self, event: CapabilityAuditEvent) {
            self.0.lock().expect("test audit mutex").push(event);
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

    #[tokio::test]
    async fn typed_dispatch_requires_exact_admission_and_rejects_replay() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        let audit = TestAudit::default();
        let mut registry = Registry::new().with_capability_audit_sink(Arc::new(audit.clone()));
        registry
            .register_capability(Arc::new(EchoHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit");
        let payload = serde_json::json!({"hello": "world"});
        let invocation = CapabilityInvocation::from_payload(
            binding.clone(),
            AgentRequestId::parse("typed-request-1").expect("request id"),
            &payload,
        )
        .expect("invocation");
        let cancel = CancellationToken::new();
        let response = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload.clone(),
                &cancel,
            )
            .await
            .expect("typed call succeeds");
        assert_eq!(response, payload);

        let replay = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                serde_json::json!({"hello": "world"}),
                &cancel,
            )
            .await
            .expect_err("replay must fail");
        assert_eq!(replay.code, ServiceErrorCode::CapabilityReplay);
        assert!(
            audit
                .0
                .lock()
                .expect("test audit mutex")
                .iter()
                .any(|event| matches!(event, CapabilityAuditEvent::Completed { .. }))
        );
    }

    #[tokio::test]
    async fn typed_dispatch_rejects_downgrade_oversize_and_cancellation() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(EchoHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit");

        let payload = serde_json::json!({"hello": "world"});
        let mut wrong = CapabilityInvocation::from_payload(
            binding.clone(),
            AgentRequestId::parse("typed-request-2").expect("request id"),
            &payload,
        )
        .expect("invocation");
        wrong.binding.descriptor_digest = [7; 32];
        let error = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &wrong,
                payload.clone(),
                &CancellationToken::new(),
            )
            .await
            .expect_err("downgrade must fail");
        assert_eq!(error.code, ServiceErrorCode::CapabilityBindingMismatch);

        let oversized = serde_json::json!({"hello": "x".repeat(200)});
        let invocation = CapabilityInvocation::from_payload(
            binding.clone(),
            AgentRequestId::parse("typed-request-3").expect("request id"),
            &oversized,
        )
        .expect("invocation");
        let error = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                oversized,
                &CancellationToken::new(),
            )
            .await
            .expect_err("oversize must fail");
        assert_eq!(error.code, ServiceErrorCode::CapabilityInputTooLarge);

        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("typed-request-4").expect("request id"),
            &payload,
        )
        .expect("invocation");
        let canceled = CancellationToken::new();
        canceled.cancel();
        let error = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload,
                &canceled,
            )
            .await
            .expect_err("canceled call must fail");
        assert_eq!(error.code, ServiceErrorCode::CapabilityCanceled);
    }

    #[tokio::test]
    async fn typed_dispatch_accepts_input_at_the_exact_byte_limit() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(EchoHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit");

        let payload = serde_json::Value::String("x".repeat(126));
        assert_eq!(
            serde_json::to_vec(&payload)
                .expect("payload serializes")
                .len(),
            128,
            "the fixture must sit exactly on the descriptor's input limit"
        );
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("typed-request-boundary").expect("request id"),
            &payload,
        )
        .expect("invocation");

        let response = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload.clone(),
                &CancellationToken::new(),
            )
            .await
            .expect("an input exactly at the limit is admitted");
        assert_eq!(response, payload);
    }

    #[tokio::test]
    async fn typed_dispatch_rejects_an_admitted_digest_that_differs_from_the_invocation() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        let mut admitted_binding = binding.clone();
        admitted_binding.descriptor_digest = [9; 32];
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(EchoHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([admitted_binding])
            .expect("admit");
        let payload = serde_json::json!({"hello": "world"});
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("typed-request-admission-digest").expect("request id"),
            &payload,
        )
        .expect("invocation");

        let error = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
            .expect_err("the admitted digest must match the invocation binding");
        assert_eq!(error.code, ServiceErrorCode::CapabilityBindingMismatch);
    }

    #[tokio::test]
    async fn typed_dispatch_classifies_schema_rejection_without_leaking_handler_text() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(InvalidInputHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit");
        let payload = serde_json::json!({"hello": "world"});
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("typed-request-5").expect("request id"),
            &payload,
        )
        .expect("invocation");

        let error = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
            .expect_err("invalid schema must fail");
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
        assert!(
            !error
                .message
                .contains("does not match the capability schema")
        );
    }

    #[tokio::test]
    async fn typed_dispatch_enforces_timeout_output_and_handler_failure() {
        let payload = serde_json::json!({"hello": "world"});

        let mut timeout_descriptor = descriptor();
        timeout_descriptor.limits = CapabilityLimits::new(128, 128, 5).unwrap();
        let timeout_binding = timeout_descriptor.binding();
        let mut timeout_registry = Registry::new();
        timeout_registry
            .register_capability(
                Arc::new(BehaviorHandler {
                    behavior: Behavior::Delay,
                }),
                timeout_descriptor,
            )
            .unwrap();
        timeout_registry
            .admit_capabilities([timeout_binding.clone()])
            .unwrap();
        let timeout_invocation = CapabilityInvocation::from_payload(
            timeout_binding,
            AgentRequestId::parse("typed-request-6").unwrap(),
            &payload,
        )
        .unwrap();
        let timeout_error = timeout_registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").unwrap(),
                "echo",
                &timeout_invocation,
                payload.clone(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(timeout_error.code, ServiceErrorCode::Timeout);

        let mut output_descriptor = descriptor();
        output_descriptor.limits = CapabilityLimits::new(128, 8, 50).unwrap();
        let output_binding = output_descriptor.binding();
        let mut output_registry = Registry::new();
        output_registry
            .register_capability(
                Arc::new(BehaviorHandler {
                    behavior: Behavior::Expand,
                }),
                output_descriptor,
            )
            .unwrap();
        output_registry
            .admit_capabilities([output_binding.clone()])
            .unwrap();
        let output_invocation = CapabilityInvocation::from_payload(
            output_binding,
            AgentRequestId::parse("typed-request-7").unwrap(),
            &payload,
        )
        .unwrap();
        let output_error = output_registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").unwrap(),
                "echo",
                &output_invocation,
                payload.clone(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            output_error.code,
            ServiceErrorCode::CapabilityOutputTooLarge
        );

        let failure_descriptor = descriptor();
        let failure_binding = failure_descriptor.binding();
        let mut failure_registry = Registry::new();
        failure_registry
            .register_capability(
                Arc::new(BehaviorHandler {
                    behavior: Behavior::Fail,
                }),
                failure_descriptor,
            )
            .unwrap();
        failure_registry
            .admit_capabilities([failure_binding.clone()])
            .unwrap();
        let failure_invocation = CapabilityInvocation::from_payload(
            failure_binding,
            AgentRequestId::parse("typed-request-8").unwrap(),
            &payload,
        )
        .unwrap();
        let failure_error = failure_registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").unwrap(),
                "echo",
                &failure_invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            failure_error.code,
            ServiceErrorCode::CapabilityHandlerFailed
        );
        assert!(
            !failure_error
                .message
                .contains("private handler failure detail")
        );
    }

    /// Both directions. Asserting only that a fresh registry is empty
    /// leaves a constant-`true` predicate passing, and the broker's
    /// startup readiness gate reads this — so a fully-populated registry
    /// would report itself as having nothing bound.
    #[test]
    fn registry_reports_empty_only_while_no_handler_is_registered() {
        let mut registry = Registry::new();
        assert!(registry.is_empty());

        registry.register(Arc::new(EchoHandler));
        assert!(
            !registry.is_empty(),
            "a registry holding a handler is not empty"
        );
    }

    fn descriptor_named(verb: &str, description: &str) -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                verb,
            )
            .expect("capability id"))
            .description(description)
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(128, 128, 50).expect("limits"))
            .build()
            .expect("descriptor")
    }

    #[test]
    fn the_catalog_is_admitted_intersected_with_registered() {
        let mut registry = Registry::new();
        let d = descriptor();
        registry
            .register_capability(Arc::new(EchoHandler), d.clone())
            .expect("register");
        registry.admit_capabilities([d.binding()]).expect("admit");

        let catalog = registry.admitted_catalog();
        assert_eq!(
            catalog,
            vec![d],
            "an admitted, registered capability is shown"
        );
    }

    #[test]
    fn a_registered_capability_that_was_not_admitted_is_invisible() {
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(EchoHandler), descriptor())
            .expect("register");

        assert!(
            registry.admitted_catalog().is_empty(),
            "registration is local to this subprocess; only a signed admission may show a tool"
        );
    }

    #[test]
    fn an_admitted_capability_with_no_registered_handler_is_invisible() {
        let mut registry = Registry::new();
        registry
            .admit_capabilities([descriptor().binding()])
            .expect("admit");

        assert!(
            registry.admitted_catalog().is_empty(),
            "a tool with nothing to dispatch to is not a tool"
        );
    }

    #[test]
    fn a_descriptor_that_drifted_from_its_admitted_digest_is_invisible() {
        let mut registry = Registry::new();
        let admitted = descriptor_named("echo", "echo a bounded test value");
        let registered = descriptor_named("echo", "echo a bounded test value, but wider");
        assert_ne!(
            admitted.digest(),
            registered.digest(),
            "the fixture must actually differ or this test proves nothing"
        );

        registry
            .register_capability(Arc::new(EchoHandler), registered)
            .expect("register");
        registry
            .admit_capabilities([admitted.binding()])
            .expect("admit");

        assert!(
            registry.admitted_catalog().is_empty(),
            "a registration may not advertise a descriptor the admission never bound"
        );
    }

    #[test]
    fn the_catalog_is_ordered_deterministically() {
        let mut registry = Registry::new();
        let second = descriptor_named("echo2", "a second verb");
        let first = descriptor_named("echo", "the first verb");
        registry
            .register_capability(Arc::new(EchoHandler), second.clone())
            .expect("register second");
        registry
            .register_capability(Arc::new(EchoHandler), first.clone())
            .expect("register first");
        registry
            .admit_capabilities([second.binding(), first.binding()])
            .expect("admit");

        let verbs: Vec<String> = registry
            .admitted_catalog()
            .into_iter()
            .map(|d| d.id.verb)
            .collect();
        assert_eq!(verbs, vec!["echo".to_string(), "echo2".to_string()]);
    }

    fn descriptor_with_policy(rules: Vec<ArgumentRule>) -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                "echo",
            )
            .expect("capability id"))
            .description("echo a bounded test value")
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(128, 128, 50).expect("limits"))
            .argument_policy(rules)
            .build()
            .expect("descriptor")
    }

    async fn dispatch_with_policy(
        rules: Vec<ArgumentRule>,
        payload: serde_json::Value,
        audit: &TestAudit,
    ) -> ServiceDispatchResult {
        let descriptor = descriptor_with_policy(rules);
        let binding = descriptor.binding();
        let mut registry = Registry::new().with_capability_audit_sink(Arc::new(audit.clone()));
        registry
            .register_capability(Arc::new(EchoHandler), descriptor)
            .expect("register");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit");
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("typed-request-policy").expect("request id"),
            &payload,
        )
        .expect("invocation");
        registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "echo",
                &invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
    }

    #[tokio::test]
    async fn an_argument_outside_the_policy_is_refused_before_the_handler_runs() {
        let audit = TestAudit::default();
        let rules = vec![ArgumentRule {
            pointer: "/destination".into(),
            constraint: ArgumentConstraint::OneOf {
                values: vec!["api.example.com".into()],
            },
        }];
        let err = dispatch_with_policy(
            rules,
            serde_json::json!({"destination": "attacker.example.com"}),
            &audit,
        )
        .await
        .expect_err("an out-of-policy argument is refused");

        assert_eq!(err.code, ServiceErrorCode::BadRequest);
        assert!(
            err.message.contains("/destination"),
            "the refusal names the field: {}",
            err.message
        );
        assert!(
            !err.message.contains("attacker.example.com"),
            "a refusal that quotes the argument republishes whatever it held: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn an_in_policy_argument_still_reaches_the_handler() {
        let audit = TestAudit::default();
        let rules = vec![ArgumentRule {
            pointer: "/destination".into(),
            constraint: ArgumentConstraint::OneOf {
                values: vec!["api.example.com".into()],
            },
        }];
        let payload = serde_json::json!({"destination": "api.example.com"});
        let out = dispatch_with_policy(rules, payload.clone(), &audit)
            .await
            .expect("an in-policy argument dispatches");
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn a_policy_refusal_is_audited_without_the_argument_value() {
        let audit = TestAudit::default();
        let rules = vec![ArgumentRule {
            pointer: "/path".into(),
            constraint: ArgumentConstraint::PathUnder {
                prefixes: vec!["/work/".into()],
            },
        }];
        dispatch_with_policy(rules, serde_json::json!({"path": "/etc/shadow"}), &audit)
            .await
            .expect_err("refused");

        let events = audit.0.lock().expect("audit mutex");
        let refused = events
            .iter()
            .any(|e| matches!(e, CapabilityAuditEvent::Refused { code, .. } if *code == CapabilityFailureCode::ArgumentRefused));
        assert!(
            refused,
            "the refusal is evidence, so it is recorded: {events:?}"
        );
        let rendered = format!("{events:?}");
        assert!(
            !rendered.contains("/etc/shadow"),
            "audit carries the code, never the value: {rendered}"
        );
    }

    #[tokio::test]
    async fn an_unbound_call_names_what_the_workload_does_have() {
        let mut registry = Registry::new();
        let d = descriptor();
        registry
            .register_capability(Arc::new(EchoHandler), d.clone())
            .expect("register");
        registry.admit_capabilities([d.binding()]).expect("admit");

        let err = registry
            .dispatch(
                &ctx(),
                &ServiceId::parse("host.time.v1").unwrap(),
                "now",
                serde_json::json!({}),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code, ServiceErrorCode::NotBound);
        assert!(
            err.message.contains("host.dev.echo.v1::echo"),
            "a refusal that does not say what IS available teaches nothing: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn an_unbound_call_with_an_empty_catalog_says_so_plainly() {
        let registry = Registry::new();
        let err = registry
            .dispatch(
                &ctx(),
                &ServiceId::parse("host.time.v1").unwrap(),
                "now",
                serde_json::json!({}),
            )
            .await
            .unwrap_err();

        assert!(
            err.message.contains("no capabilities"),
            "an empty catalog is a statement, not an empty list: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn repeated_unbound_calls_to_one_name_become_rate_bounded() {
        let registry = Registry::new();
        let svc = ServiceId::parse("host.time.v1").unwrap();
        let mut saw_rate_bound = false;
        for _ in 0..(MAX_UNBOUND_ATTEMPTS_PER_NAME + 2) {
            let err = registry
                .dispatch(&ctx(), &svc, "now", serde_json::json!({}))
                .await
                .unwrap_err();
            if err.message.contains("rate-bounded") {
                saw_rate_bound = true;
            }
        }
        assert!(
            saw_rate_bound,
            "a model retrying one unbound name forever is a denial of service"
        );
    }

    #[test]
    fn unbound_name_teaching_uses_the_exact_attempt_ceiling() {
        let registry = Registry::new();

        for attempt in 1..=MAX_UNBOUND_ATTEMPTS_PER_NAME {
            assert!(
                registry.should_still_teach("host.time.v1"),
                "attempt {attempt} must still teach the admitted surface"
            );
        }
        assert!(
            !registry.should_still_teach("host.time.v1"),
            "the first attempt past the ceiling must be terse"
        );
    }

    #[tokio::test]
    async fn refusal_tracking_cannot_be_grown_without_bound() {
        let registry = Registry::new();
        for i in 0..(MAX_TRACKED_REFUSAL_NAMES * 3) {
            let svc = ServiceId::parse(format!("host.enum{i}.v1")).expect("service");
            let _ = registry
                .dispatch(&ctx(), &svc, "now", serde_json::json!({}))
                .await;
        }
        let tracked = registry.refusal_counts.lock().expect("refusal mutex").len();
        assert!(
            tracked <= MAX_TRACKED_REFUSAL_NAMES,
            "a counter keyed by a guest-supplied name is itself a memory exhaustion \
             surface; tracked {tracked}"
        );
    }

    #[tokio::test]
    async fn a_bound_call_is_unaffected_by_refusal_tracking() {
        let mut registry = Registry::new();
        registry.register(Arc::new(EchoHandler));
        let svc = ServiceId::parse("host.dev.echo.v1").unwrap();
        for _ in 0..(MAX_UNBOUND_ATTEMPTS_PER_NAME + 5) {
            registry
                .dispatch(&ctx(), &svc, "echo", serde_json::json!({"k": "v"}))
                .await
                .expect("a bound call never becomes rate-bounded");
        }
    }

    #[tokio::test]
    async fn a_typed_call_to_an_unregistered_capability_names_the_surface() {
        let mut registry = Registry::new();
        let d = descriptor();
        registry
            .register_capability(Arc::new(EchoHandler), d.clone())
            .expect("register");
        registry.admit_capabilities([d.binding()]).expect("admit");

        let payload = serde_json::json!({});
        let invocation = CapabilityInvocation::from_payload(
            d.binding(),
            AgentRequestId::parse("typed-absent-verb").expect("request id"),
            &payload,
        )
        .expect("invocation");

        let err = registry
            .dispatch_capability(
                &ctx(),
                &ServiceId::parse("host.dev.echo.v1").expect("service"),
                "absent",
                &invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
            .expect_err("an unregistered verb is refused");

        assert!(
            err.message.contains("host.dev.echo.v1::echo"),
            "the typed path is the real one; its refusal must teach too: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn a_capability_only_service_refuses_the_legacy_direct_call_path() {
        let mut registry = Registry::new();
        let handler: Arc<dyn ServiceHandler> = Arc::new(EchoHandler);
        registry.register(Arc::clone(&handler));
        registry.require_capability(handler.id());

        let error = registry
            .dispatch(
                &ctx(),
                &handler.id(),
                "echo",
                serde_json::json!({"value": "synthetic"}),
            )
            .await
            .expect_err("direct calls must not bypass typed capability gates");
        assert_eq!(error.code, ServiceErrorCode::CapabilityDenied);
    }
}
