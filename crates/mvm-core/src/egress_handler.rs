//! Egress-broker handler: compose decision + trace into an audit record.
//!
//! The per-request logic the host `mvm-egress-broker` runs: decide the request
//! against the workload's network policy ([`crate::egress_broker`]), and emit an
//! audit record carrying the verdict plus the [`crate::trace_context`]
//! correlation so the flow is fully traceable in the chain-signed log. This is
//! the pure composition; the broker process forwards/blocks per the verdict and
//! writes the record to the audit sink.

use crate::egress_broker::{EgressRequest, EgressVerdict, decide_egress};
use crate::policy::network_policy::NetworkPolicy;
use crate::trace_context::TraceContext;

/// The audit record for one brokered egress flow: the requested endpoint, the
/// verdict (allowed + matched rule, or denied + reason), and the trace
/// correlation so the flow is linkable across hops in the chain-signed log.
/// Secret-free by construction — it names the endpoint and decision, never
/// payload or credential bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressFlowAudit {
    pub trace_id: String,
    pub span_id: String,
    pub host: String,
    pub port: u16,
    pub allowed: bool,
    /// The allowlist rule that permitted the flow (`host:port`), if any.
    pub matched_rule: Option<String>,
    /// The deny reason token, if denied.
    pub deny_reason: Option<&'static str>,
}

/// Decide a brokered egress request against `policy` and produce its audit
/// record under `trace`. Returns the verdict (so the broker forwards or blocks)
/// and the record (so the broker emits it to the chain-signed audit sink).
pub fn handle_egress(
    policy: &NetworkPolicy,
    trace: &TraceContext,
    req: &EgressRequest,
) -> (EgressVerdict, EgressFlowAudit) {
    let verdict = decide_egress(policy, req);
    let (allowed, matched_rule, deny_reason) = match &verdict {
        EgressVerdict::Allowed { matched } => (
            true,
            matched.as_ref().map(|m| format!("{}:{}", m.host, m.port)),
            None,
        ),
        EgressVerdict::Denied { reason } => (false, None, Some(reason.label())),
    };
    let audit = EgressFlowAudit {
        trace_id: trace.trace_id.to_hex(),
        span_id: trace.span_id.to_hex(),
        host: req.host.clone(),
        port: req.port,
        allowed,
        matched_rule,
        deny_reason,
    };
    (verdict, audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::network_policy::HostPort;
    use crate::trace_context::{SpanId, TraceId};

    #[test]
    fn handle_egress_allows_and_records_trace_and_rule() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let trace = TraceContext::new(TraceId([0x4b; 16]), SpanId([0x1a; 8]));
        let (verdict, audit) =
            handle_egress(&policy, &trace, &EgressRequest::new("api.example.com", 443));
        assert!(verdict.is_allowed());
        assert!(audit.allowed);
        assert_eq!(audit.trace_id, trace.trace_id.to_hex());
        assert_eq!(audit.span_id, trace.span_id.to_hex());
        assert_eq!(audit.matched_rule.as_deref(), Some("api.example.com:443"));
        assert_eq!(audit.deny_reason, None);
    }

    #[test]
    fn handle_egress_denies_and_records_reason() {
        let trace = TraceContext::new(TraceId([0x4b; 16]), SpanId([0x1a; 8]));
        let (verdict, audit) = handle_egress(
            &NetworkPolicy::deny_all(),
            &trace,
            &EgressRequest::new("evil.example.com", 443),
        );
        assert!(!verdict.is_allowed());
        assert!(!audit.allowed);
        assert_eq!(audit.deny_reason, Some("deny_all"));
        assert_eq!(audit.matched_rule, None);
        assert_eq!(audit.host, "evil.example.com");
        assert_eq!(audit.port, 443);
    }
}
