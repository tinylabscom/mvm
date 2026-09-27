//! Endpoint-route enforcement on a request the endpoint has read.
//!
//! The gate's allow-list has already admitted the destination when this runs;
//! a route narrows what the request may do there. Every decision a route makes
//! — allow, deny, or ask — is recorded with the route id and the rule that
//! decided, and an `ask` is put to the configured approver, which refuses when
//! there is none.

use mvm_contract::policy::routes::{DecidedBy, RouteDecision, RouteOutcome};

use super::SubstitutionService;
use crate::supervisor::egress_approval::{ApprovalVerdict, PendingEgressDecision};

/// Why a request a route refused was refused.
const REASON_ROUTE_DENIED: &str = "route_denied";

/// The request method as a fixed audit label: a standard method, or `other`.
/// The method is guest-supplied, so an unrecognised token is not recorded.
pub(super) fn method_label(method: &str) -> &'static str {
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
        let method = method_label(method);
        let verdict = self.route_verdict(&decision, &destination, method).await;
        self.audit_route_decision(&decision, &destination, method, verdict.err())
            .await;
        verdict
    }

    async fn route_verdict(
        &self,
        decision: &RouteDecision,
        destination: &str,
        method: &'static str,
    ) -> Result<(), &'static str> {
        match decision.outcome {
            RouteOutcome::Allow => Ok(()),
            RouteOutcome::Deny if decision.decided_by == DecidedBy::AmbiguousPath => {
                Err("ambiguous_path")
            }
            RouteOutcome::Deny => Err(REASON_ROUTE_DENIED),
            RouteOutcome::Ask => {
                let rule = decision.decided_by.label();
                let pending = PendingEgressDecision {
                    route_id: &decision.route_id,
                    rule: &rule,
                    destination,
                    method,
                };
                match self.approver.decide(&pending).await {
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

    #[test]
    fn an_unrecognised_method_is_recorded_as_other() {
        assert_eq!(method_label("get"), "GET");
        assert_eq!(method_label("PROPFIND"), "other");
        assert_eq!(method_label("GET\r\nX: y"), "other");
    }
}
