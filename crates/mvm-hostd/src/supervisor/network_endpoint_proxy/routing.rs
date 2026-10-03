//! Endpoint-route enforcement on a request the endpoint has read.
//!
//! The gate's allow-list has already admitted the destination when this runs;
//! a route narrows what the request may do there. Every decision a route makes
//! — allow, deny, or ask — is recorded with the route id and the rule that
//! decided, and an `ask` is put to the configured approver, which refuses when
//! there is none.

use mvm_contract::policy::routes::{DecidedBy, RouteDecision, RouteOutcome};

use super::SubstitutionService;
use crate::supervisor::runtime_approval::{ApprovalSubject, ApprovalVerdict};

/// Why a request a route refused was refused.
const REASON_ROUTE_DENIED: &str = "route_denied";
const REASON_ROUTE_AUDIT_UNAVAILABLE: &str = "route_audit_unavailable";

/// The request method as a fixed audit label: a standard method, or `other`.
/// The method is guest-supplied, so an unrecognised token is not recorded.
pub(crate) fn method_label(method: &str) -> &'static str {
    const METHODS: [&str; 9] = [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
    ];
    METHODS
        .into_iter()
        .find(|m| m.eq_ignore_ascii_case(method))
        .unwrap_or("other")
}

impl SubstitutionService {
    /// Decide `method path` to `host:port` against the plan's routes.
    ///
    /// `Ok(())` lets the request proceed — no route names the destination, a
    /// rule allows it, or an approver approved an `ask`. `Err` carries the
    /// fixed reason it was refused. Every route decision is audited, the
    /// allowed ones included.
    pub(super) async fn enforce_routes(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
    ) -> Result<(), &'static str> {
        let Some(decision) = self.egress_gate.decide_route(host, port, method, path) else {
            return Ok(());
        };
        let destination = format!("{host}:{port}");
        let verdict = self
            .route_verdict(&decision, &destination, method, path)
            .await;
        self.audit_route_decision(&decision, &destination, method_label(method), verdict.err())
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "route decision audit unavailable");
                REASON_ROUTE_AUDIT_UNAVAILABLE
            })?;
        verdict
    }

    async fn route_verdict(
        &self,
        decision: &RouteDecision,
        destination: &str,
        method: &str,
        path: &str,
    ) -> Result<(), &'static str> {
        match decision.outcome {
            RouteOutcome::Allow => Ok(()),
            RouteOutcome::Deny if decision.decided_by == DecidedBy::AmbiguousPath => {
                Err("ambiguous_path")
            }
            RouteOutcome::Deny => Err(REASON_ROUTE_DENIED),
            RouteOutcome::Ask => {
                // The question carries the method and path as the guest sent
                // them; the approval backend shows them only after stripping
                // anything a terminal would interpret.
                let subject = ApprovalSubject::Egress {
                    route_id: decision.route_id.clone(),
                    rule: decision.decided_by.label(),
                    destination: destination.to_string(),
                    method: method.to_string(),
                    path: path.to_string(),
                };
                match self.approver.decide(&subject).await {
                    ApprovalVerdict::Approved => Ok(()),
                    ApprovalVerdict::Denied { reason } => Err(reason),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::{CapturingAuditSigner, NoopAuditSigner};
    use crate::supervisor::audit_recorder::Recorder;
    use crate::supervisor::network_endpoint_proxy::test_support::{
        gate_admitting, service_with_gate,
    };
    use crate::supervisor::runtime_approval::{ApprovalSupervisor, SocketBroker};
    use mvm_contract::policy::approval_prompt::{ApprovalAnswer, ApprovalPrompt, ApprovalScope};
    use mvm_contract::policy::routes::{EgressRoute, EndpointRule, RouteSet};
    use mvm_core::plan::TenantId;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn routed_service(outcome: RouteOutcome) -> Arc<SubstitutionService> {
        let route = EgressRoute {
            id: "api".into(),
            host: "api.example.com".into(),
            port: 443,
            rules: vec![EndpointRule {
                id: Some("read".into()),
                method: Some("GET".into()),
                path: "/v1/**".into(),
                outcome,
            }],
            otherwise: RouteOutcome::Deny,
            intercept: true,
        };
        let routes = RouteSet::new(vec![route]).expect("valid route");
        let gate = Arc::new(
            (*gate_admitting(&[("api.example.com", 443)]))
                .clone()
                .with_routes(routes),
        );
        service_with_gate("secret", &["api.example.com"], gate).0
    }

    #[tokio::test]
    async fn an_allowed_route_refuses_without_a_chain_recorder() {
        let service = routed_service(RouteOutcome::Allow);
        assert_eq!(
            service
                .enforce_routes("api.example.com", 443, "GET", "/v1/models")
                .await,
            Err("route_audit_unavailable"),
        );
    }

    #[tokio::test]
    async fn an_allowed_route_refuses_when_its_chain_write_fails() {
        let service = Arc::try_unwrap(routed_service(RouteOutcome::Allow))
            .ok()
            .expect("test owns the service")
            .with_recorder(Recorder::new(
                Arc::new(NoopAuditSigner),
                TenantId("local".into()),
            ));
        assert_eq!(
            service
                .enforce_routes("api.example.com", 443, "GET", "/v1/models")
                .await,
            Err("route_audit_unavailable"),
        );
    }

    #[tokio::test]
    async fn a_route_ask_traverses_the_supervisor_and_approval_socket() {
        let dir = tempfile::tempdir().expect("socket dir");
        let socket = dir.path().join("approval.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind approval socket");
        let backend = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("approval connection");
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read)
                .read_line(&mut line)
                .await
                .expect("read approval prompt");
            let prompt: ApprovalPrompt = serde_json::from_str(&line).expect("approval prompt");
            let ApprovalSubject::Egress {
                route_id,
                rule,
                method,
                path,
                ..
            } = &prompt.subject
            else {
                panic!("expected route approval question");
            };
            assert_eq!(route_id, "api");
            assert_eq!(rule, "read");
            assert_eq!(method, "GET");
            assert_eq!(path, "/v1/models");
            let answer = ApprovalAnswer::approved(prompt.request_id, ApprovalScope::Once, "test");
            let mut encoded = serde_json::to_vec(&answer).expect("encode answer");
            encoded.push(b'\n');
            write.write_all(&encoded).await.expect("send approval");
        });

        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".into())));
        let approver = ApprovalSupervisor::builder("route-test")
            .recorder(Some(Arc::clone(&recorder)))
            .broker(Arc::new(SocketBroker::new(socket)))
            .build()
            .expect("approval supervisor");
        let service = Arc::try_unwrap(routed_service(RouteOutcome::Ask))
            .ok()
            .expect("test owns service")
            .with_shared_recorder(recorder)
            .with_approver(Arc::new(approver));
        assert_eq!(
            service
                .enforce_routes("api.example.com", 443, "GET", "/v1/models")
                .await,
            Ok(()),
        );
        backend.await.expect("approval backend finishes");
        let events: Vec<_> = signer
            .entries()
            .into_iter()
            .map(|entry| entry.event)
            .collect();
        assert_eq!(
            events,
            [
                "approval.requested",
                "approval.granted",
                "host.route.decided"
            ]
        );
    }

    #[test]
    fn an_unrecognised_method_is_recorded_as_other() {
        assert_eq!(method_label("get"), "GET");
        assert_eq!(method_label("PROPFIND"), "other");
        assert_eq!(method_label("GET\r\nX: y"), "other");
    }
}
