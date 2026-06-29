//! Ingress-broker handler: compose decision + trace into an audit record.
//!
//! The per-connection logic the host `mvm-ingress-broker` runs: decide an
//! inbound on a listener port against the workload's declared ingress policy
//! ([`crate::ingress_broker`]) and produce an audit record carrying the verdict
//! plus the [`crate::trace_context`] correlation. The mirror of
//! [`crate::egress_handler`]; the broker process forwards over vsock per the
//! verdict and writes the record to the chain-signed sink.

use crate::ingress_broker::{IngressPolicy, IngressVerdict, decide_ingress};
use crate::trace_context::TraceContext;

/// The audit record for one inbound flow: the listener port, the verdict
/// (admitted + mapped guest port, or denied + reason), and trace correlation.
/// Secret-free by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressFlowAudit {
    pub trace_id: String,
    pub span_id: String,
    pub listen_port: u16,
    pub allowed: bool,
    /// The guest service port the flow maps to, when admitted.
    pub guest_port: Option<u16>,
    /// The deny reason token, if denied.
    pub deny_reason: Option<&'static str>,
}

/// Decide an inbound connection on `listen_port` against `policy` and produce
/// its audit record under `trace`. Returns the verdict (so the broker forwards
/// or drops) and the record (so the broker emits it to the audit sink).
pub fn handle_ingress(
    policy: &IngressPolicy,
    trace: &TraceContext,
    listen_port: u16,
) -> (IngressVerdict, IngressFlowAudit) {
    let verdict = decide_ingress(policy, listen_port);
    let (allowed, guest_port, deny_reason) = match &verdict {
        IngressVerdict::Allowed { route } => (true, Some(route.guest_port), None),
        IngressVerdict::Denied { reason } => (false, None, Some(reason.label())),
    };
    let audit = IngressFlowAudit {
        trace_id: trace.trace_id.to_hex(),
        span_id: trace.span_id.to_hex(),
        listen_port,
        allowed,
        guest_port,
        deny_reason,
    };
    (verdict, audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress_broker::IngressRoute;
    use crate::trace_context::{SpanId, TraceId};

    fn trace() -> TraceContext {
        TraceContext::new(TraceId([0x4b; 16]), SpanId([0x1a; 8]))
    }

    #[test]
    fn handle_ingress_admits_and_records_route_and_trace() {
        let policy = IngressPolicy::with_routes(vec![IngressRoute {
            listen_port: 8080,
            guest_port: 80,
        }]);
        let (verdict, audit) = handle_ingress(&policy, &trace(), 8080);
        assert!(verdict.is_allowed());
        assert!(audit.allowed);
        assert_eq!(audit.guest_port, Some(80));
        assert_eq!(audit.trace_id, trace().trace_id.to_hex());
        assert_eq!(audit.deny_reason, None);
    }

    #[test]
    fn handle_ingress_denies_and_records_reason() {
        let (verdict, audit) = handle_ingress(&IngressPolicy::deny_all(), &trace(), 8080);
        assert!(!verdict.is_allowed());
        assert!(!audit.allowed);
        assert_eq!(audit.guest_port, None);
        assert_eq!(audit.deny_reason, Some("deny_all"));
        assert_eq!(audit.listen_port, 8080);
    }
}
