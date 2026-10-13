//! `host.tool.v1` — guest-origin declared-tool decisions.
//!
//! The in-guest spawn helper asks this service before it executes a declared
//! tool on the workload's behalf. The handler adds nothing to the decision:
//! it forwards the exact guest-reported invocation to this VM's network
//! endpoint connector socket, where the admitted-plan decision gate applies
//! the signed tool rules and records the outcome in the chain-signed audit
//! log. The reply returns untouched.
//!
//! Why the broker is the right seam:
//!
//! - The caller is untrusted by construction — any guest process can dial
//!   the broker port — so the handler holds no key and trusts no field it
//!   forwards. The endpoint re-derives the tool↔executable binding from the
//!   signed plan and refuses a mismatch; the `origin` label the connector
//!   records is chosen here, on the host side, so a guest cannot talk its
//!   way into a host-initiated audit label.
//! - The service binding is the plan's own: the admission path injects
//!   `host.tool.v1` into `plan.services` exactly when tools are declared,
//!   and the registry refuses the service when the binding is absent.
//! - One gate, one audit path: host-initiated (`machine exec --tool`), guest
//!   service (FlowMux `ToolCheck`), and guest workload (this service) all
//!   land in the same per-VM `ToolDecisionGate`, so the chain sees every
//!   decision with an origin label and no decision is ever unaudited.
//!
//! Failure semantics are fail-closed by construction: a missing connector
//! socket, a dial failure, a framing error, or a malformed reply is a typed
//! broker error, and the guest helper treats every error as a denial.

use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use mvm_contract::protocol::network_flow::attribution::ToolInvocationRelease;
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolDecisionReply, ToolOrigin};
use mvm_core::net::session::{read_json_frame, write_json_frame};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_tool::{DECIDE_VERB, RELEASE_VERB, ToolReleaseResponse};

/// Largest tool frame either direction (matches the host-local client's cap).
const MAX_TOOL_FRAME_BYTES: usize = 20 * 1024;
/// Sending the question must not stall the handler's worker.
const TOOL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The endpoint holds an operator approval for at most 120 seconds; answer
/// before the guest helper's own deadline so it never mistakes a slow
/// approval for a transport failure.
const TOOL_READ_TIMEOUT: Duration = Duration::from_secs(125);
/// Registry-level ceiling above the per-hop timeouts.
const TOOL_CALL_TIMEOUT: Duration = Duration::from_secs(130);

/// Handler for the `host.tool.v1` service.
pub struct HostToolV1Handler {
    /// This VM's network endpoint connector socket. Host-local and
    /// supervisor-owned; the handler is only constructed when it exists.
    connector_socket: PathBuf,
}

impl HostToolV1Handler {
    /// New handler forwarding decisions to `connector_socket`.
    pub fn new(connector_socket: PathBuf) -> Self {
        Self { connector_socket }
    }

    fn decide_at(
        connector_socket: &std::path::Path,
        payload: &serde_json::Value,
    ) -> ServiceDispatchResult {
        let request: ToolCheckRequest = serde_json::from_value(payload.clone()).map_err(|_| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                "host.tool.v1 decide payload is not a valid tool question",
            )
        })?;
        if !request.is_valid() {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                "host.tool.v1 decide payload is not a valid tool question",
            ));
        }
        let reply = Self::connector_request(
            connector_socket,
            &serde_json::json!({
                "question": request,
                "origin": ToolOrigin::GuestBroker,
            }),
        )?;
        let decision: ToolDecisionReply = serde_json::from_value(reply).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("host.tool.v1 endpoint reply was not a decision: {error}"),
            )
        })?;
        serde_json::to_value(decision).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("host.tool.v1 decision encode failed: {error}"),
            )
        })
    }

    fn release_at(
        connector_socket: &std::path::Path,
        payload: &serde_json::Value,
    ) -> ServiceDispatchResult {
        let release: ToolInvocationRelease =
            serde_json::from_value(payload.clone()).map_err(|_| {
                ServiceError::new(
                    ServiceErrorCode::BadRequest,
                    "host.tool.v1 release payload is not a valid binding release",
                )
            })?;
        Self::connector_request(
            connector_socket,
            &serde_json::to_value(&release).map_err(|error| {
                ServiceError::new(
                    ServiceErrorCode::InternalError,
                    format!("host.tool.v1 release encode failed: {error}"),
                )
            })?,
        )?;
        serde_json::to_value(ToolReleaseResponse { released: true }).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("host.tool.v1 release response encode failed: {error}"),
            )
        })
    }

    /// One framed connector request/response. One connection per call,
    /// mirroring the host-local client: no multiplexing, no shared state, a
    /// missing or malformed answer is an error, never an approval.
    fn connector_request(
        connector_socket: &std::path::Path,
        frame: &serde_json::Value,
    ) -> ServiceDispatchResult {
        let mut stream =
            std::os::unix::net::UnixStream::connect(connector_socket).map_err(|error| {
                ServiceError::new(
                    ServiceErrorCode::Unavailable,
                    format!("tool decision endpoint unavailable: {error}"),
                )
            })?;
        stream
            .set_write_timeout(Some(TOOL_WRITE_TIMEOUT))
            .map_err(|error| {
                ServiceError::new(
                    ServiceErrorCode::Unavailable,
                    format!("set tool question deadline: {error}"),
                )
            })?;
        stream
            .set_read_timeout(Some(TOOL_READ_TIMEOUT))
            .map_err(|error| {
                ServiceError::new(
                    ServiceErrorCode::Unavailable,
                    format!("set tool decision deadline: {error}"),
                )
            })?;
        write_json_frame(&mut stream, frame, MAX_TOOL_FRAME_BYTES)
            .map_err(|error| unavailable("send tool question", error))?;
        read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES)
            .map_err(|error| unavailable("read tool decision", error))
    }
}

fn unavailable(context: &str, error: mvm_core::net::session::SessionError) -> ServiceError {
    ServiceError::new(ServiceErrorCode::Unavailable, format!("{context}: {error}"))
}

impl ServiceHandler for HostToolV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse(mvm_core::protocol::host_tool::HOST_TOOL_SERVICE)
            .expect("host.tool.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        &[
            AgentProfile::SealedProd,
            AgentProfile::Dev,
            AgentProfile::Builder,
        ]
    }

    fn audit_durability(&self) -> AuditDurability {
        // The decision's chain entry is written (and fsynced) by the
        // endpoint's own recorder before the reply; the broker adds no entry
        // of its own.
        AuditDurability::default_batched()
    }

    fn idempotency(&self) -> Idempotency {
        // Each decide is a distinct invocation with its own audit record.
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        TOOL_CALL_TIMEOUT
    }

    fn dispatch<'a>(
        &'a self,
        _ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        // The connector dial blocks with deadlines, so it runs off the
        // async workers; the socket path is cloned in so the blocking
        // closure owns everything it touches.
        let connector_socket = self.connector_socket.clone();
        Box::pin(async move {
            match verb {
                DECIDE_VERB => tokio::task::spawn_blocking(move || {
                    Self::decide_at(&connector_socket, &payload)
                })
                .await
                .map_err(|error| {
                    ServiceError::new(
                        ServiceErrorCode::InternalError,
                        format!("host.tool.v1 decide task failed: {error}"),
                    )
                })?,
                RELEASE_VERB => tokio::task::spawn_blocking(move || {
                    Self::release_at(&connector_socket, &payload)
                })
                .await
                .map_err(|error| {
                    ServiceError::new(
                        ServiceErrorCode::InternalError,
                        format!("host.tool.v1 release task failed: {error}"),
                    )
                })?,
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("host.tool.v1: unknown verb `{other}`"),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;

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

    fn question() -> serde_json::Value {
        serde_json::to_value(ToolCheckRequest {
            tool: "python".into(),
            executable: Some("/usr/local/bin/python3".into()),
            argv: "python3 -c pass".into(),
        })
        .expect("question serializes")
    }

    /// One-shot connector stub asserting the frame is the guest-broker tool
    /// question and answering `reply`.
    fn connector_stub(
        dir: &std::path::Path,
        expect_origin: Option<ToolOrigin>,
        reply: serde_json::Value,
        seen: Arc<AtomicUsize>,
    ) -> std::path::PathBuf {
        let socket = dir.join("connector.sock");
        let listener = UnixListener::bind(&socket).expect("bind connector stub");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connector question");
            let frame: serde_json::Value =
                read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES).expect("read question");
            let origin = frame
                .get("origin")
                .and_then(|value| serde_json::from_value::<ToolOrigin>(value.clone()).ok());
            assert_eq!(origin, expect_origin);
            // Count before replying: the caller returns as soon as it reads
            // the reply, so a count taken after the write can race its
            // assertion.
            seen.fetch_add(1, Ordering::SeqCst);
            write_json_frame(&mut stream, &reply, MAX_TOOL_FRAME_BYTES).expect("write reply");
        });
        socket
    }

    #[tokio::test]
    async fn decide_forwards_the_question_and_returns_the_decision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seen = Arc::new(AtomicUsize::new(0));
        let socket = connector_stub(
            dir.path(),
            Some(ToolOrigin::GuestBroker),
            serde_json::to_value(ToolDecisionReply::Allow).expect("reply"),
            Arc::clone(&seen),
        );
        let handler = HostToolV1Handler::new(socket);
        let decision: ToolDecisionReply = serde_json::from_value(
            handler
                .dispatch(&context(), DECIDE_VERB, question())
                .await
                .expect("decision"),
        )
        .expect("decision decodes");
        assert_eq!(decision, ToolDecisionReply::Allow);
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn decide_returns_the_bound_reply_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binding = ToolInvocationBinding::from_random([7; 16]);
        let socket = connector_stub(
            dir.path(),
            Some(ToolOrigin::GuestBroker),
            serde_json::to_value(ToolDecisionReply::AllowBound {
                binding: binding.clone(),
            })
            .expect("reply"),
            Arc::new(AtomicUsize::new(0)),
        );
        let handler = HostToolV1Handler::new(socket);
        let decision: ToolDecisionReply = serde_json::from_value(
            handler
                .dispatch(&context(), DECIDE_VERB, question())
                .await
                .expect("decision"),
        )
        .expect("decision decodes");
        assert_eq!(decision, ToolDecisionReply::AllowBound { binding });
    }

    #[tokio::test]
    async fn decide_is_unavailable_without_the_endpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handler = HostToolV1Handler::new(dir.path().join("absent.sock"));
        let error = handler
            .dispatch(&context(), DECIDE_VERB, question())
            .await
            .expect_err("no endpoint is no approval");
        assert_eq!(error.code, ServiceErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn decide_rejects_a_malformed_question() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handler = HostToolV1Handler::new(dir.path().join("unused.sock"));
        let error = handler
            .dispatch(&context(), DECIDE_VERB, serde_json::json!({"tool": 42}))
            .await
            .expect_err("malformed question refused");
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn release_forwards_the_release_and_acks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binding = ToolInvocationBinding::from_random([9; 16]);
        let release = serde_json::to_value(ToolInvocationRelease {
            release: binding.clone(),
        })
        .expect("release serializes");
        let socket = connector_stub(
            dir.path(),
            // A release frame is a bare ToolInvocationRelease; it carries
            // no origin field.
            None,
            serde_json::Value::Null,
            Arc::new(AtomicUsize::new(0)),
        );
        let handler = HostToolV1Handler::new(socket);
        let response: ToolReleaseResponse = serde_json::from_value(
            handler
                .dispatch(&context(), RELEASE_VERB, release)
                .await
                .expect("release ack"),
        )
        .expect("ack decodes");
        assert!(response.released);
    }

    #[tokio::test]
    async fn unknown_verb_is_not_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handler = HostToolV1Handler::new(dir.path().join("unused.sock"));
        let error = handler
            .dispatch(&context(), "mint", serde_json::json!({}))
            .await
            .expect_err("unknown verb refused");
        assert_eq!(error.code, ServiceErrorCode::NotImplemented);
    }
}
