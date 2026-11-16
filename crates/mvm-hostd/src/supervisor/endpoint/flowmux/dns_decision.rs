//! Authorize upstream DNS work before invoking the gate's admitted resolver.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::IpAddr;

use mvm_contract::protocol::dns::{DnsRecordType, MAX_DNS_MESSAGE, decode_query, encode_response};
use mvm_core::audit_sink::AuditSink;
use mvm_vmm::vsock_egress_bridge::egress_gate::{DnsVerdict, EgressGate, TargetDecision};

use super::{FlowMuxError, FlowMuxSession, decision_audit, registry};
use crate::supervisor::datapath::dns_resolver::resolve_hostname_ips;

impl FlowMuxSession {
    pub(super) fn handle_resolve(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len as usize > MAX_DNS_MESSAGE {
            self.record_dns_refusal(stream_id, "malformed");
            self.remove_stream(stream_id);
            return self.send_resolve_refused(stream_id, "DNS query missing or oversized");
        }
        let question = match decode_query(self.frame_payload(payload_len)) {
            Ok(question) => question,
            Err(error) => {
                self.record_dns_refusal(stream_id, "malformed");
                self.remove_stream(stream_id);
                return self
                    .send_resolve_refused(stream_id, &format!("malformed DNS query: {error:?}"));
            }
        };
        let mut labels = BTreeMap::from([
            ("stream_id".to_string(), stream_id.to_string()),
            ("qname".to_string(), question.name.clone()),
            ("qtype".to_string(), question.qtype.to_string()),
        ]);
        if !self.check_connection_rate(registry::FlowClass::Dns) {
            labels.insert("reason".into(), "rate_limited".into());
            self.record_denial("dns.refused", labels);
            self.remove_stream(stream_id);
            return self.send_resolve_refused(stream_id, "rate limited");
        }
        let timeout = self.connect_timeout;
        let verdict = match resolve(
            &self.gate,
            self.audit_sink.as_ref(),
            stream_id,
            &question.name,
            question.qtype,
            |name| resolve_hostname_ips(name, timeout),
        ) {
            Ok(verdict) => verdict,
            Err(_) => {
                self.remove_stream(stream_id);
                return self.send_resolve_refused(stream_id, "audit unavailable");
            }
        };
        let response = match verdict {
            DnsVerdict::Resolved(ips) => {
                labels.insert("resolved_ips".into(), Self::format_ips(&ips));
                if self.record_allow("dns.resolved", labels).is_err() {
                    self.remove_stream(stream_id);
                    return self.send_resolve_refused(stream_id, "audit unavailable");
                }
                encode_response(
                    &question,
                    mvm_contract::protocol::dns::DnsRcode::NoError,
                    &ips,
                )
            }
            DnsVerdict::Refused => {
                labels.insert("reason".into(), "policy_denied".into());
                self.record_denial("dns.refused", labels);
                self.remove_stream(stream_id);
                return self.send_resolve_refused(stream_id, "policy refused");
            }
        };
        self.remove_stream(stream_id);
        self.send_resolved(stream_id, &response)
    }
}

pub(super) fn resolve(
    gate: &EgressGate,
    sink: &dyn AuditSink,
    stream_id: u32,
    name: &str,
    qtype: DnsRecordType,
    resolver: impl Fn(&str) -> std::io::Result<Vec<IpAddr>>,
) -> std::io::Result<DnsVerdict> {
    let audit_error = Cell::new(None);
    let verdict = gate.dns_verdict(name, qtype, |name| {
        if let Err(error) = decision_audit::record(
            sink,
            "dns.admitted",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("qname".into(), name.into()),
                ("qtype".into(), qtype.to_string()),
            ]),
        ) {
            audit_error.set(Some(error));
            return Err(std::io::Error::other("audit unavailable"));
        }
        resolver(name)
    });
    match audit_error.take() {
        Some(error) => Err(error),
        None => Ok(verdict),
    }
}

pub(super) fn decide_target(
    gate: &EgressGate,
    sink: &dyn AuditSink,
    stream_id: u32,
    host: &str,
    port: u16,
    resolver: impl Fn(&str) -> std::io::Result<Vec<IpAddr>>,
) -> std::io::Result<TargetDecision> {
    let audit_error = Cell::new(None);
    let decision = gate.decide_target_with(host, port, |name| {
        if let Err(error) = decision_audit::record(
            sink,
            "dns.admitted",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("qname".into(), name.into()),
            ]),
        ) {
            audit_error.set(Some(error));
            return Err(std::io::Error::other("audit unavailable"));
        }
        resolver(name)
    });
    match audit_error.take() {
        Some(error) => Err(error),
        None => Ok(decision),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::endpoint::flowmux::audit_tests::CapturingSink;
    use mvm_contract::policy::projection::CanonicalEgress;
    use std::sync::atomic::Ordering;

    #[test]
    fn a_failed_tcp_dns_admission_never_resolves_or_allows_the_target() {
        let sink = CapturingSink::default();
        sink.fail.store(true, Ordering::SeqCst);
        let decision = decide_target(
            &EgressGate::new(CanonicalEgress::Unrestricted),
            &sink,
            1,
            "dns.test",
            443,
            |_| panic!("failed authorization must not reach the resolver"),
        );
        assert!(decision.is_err());
        assert!(sink.incomplete.load(Ordering::SeqCst));
        assert_eq!(sink.records.lock().unwrap()[0].0, "dns.admitted");
    }

    #[test]
    fn denied_and_numeric_tcp_targets_do_not_request_live_dns() {
        for gate in [
            EgressGate::default_deny(),
            EgressGate::new(CanonicalEgress::Unrestricted),
        ] {
            let sink = CapturingSink::default();
            decide_target(&gate, &sink, 1, "93.184.216.34", 443, |_| {
                panic!("numeric targets must not resolve")
            })
            .unwrap();
            assert!(sink.records.lock().unwrap().is_empty());
        }
        let sink = CapturingSink::default();
        decide_target(
            &EgressGate::default_deny(),
            &sink,
            1,
            "denied.test",
            443,
            |_| panic!("denied names must not resolve"),
        )
        .unwrap();
        assert!(sink.records.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failed_dns_admission_never_invokes_the_resolver() {
        let sink = CapturingSink::default();
        sink.fail.store(true, Ordering::SeqCst);
        let calls = Cell::new(0);
        let result = resolve(
            &EgressGate::new(CanonicalEgress::Unrestricted),
            &sink,
            1,
            "dns.test",
            DnsRecordType::A,
            |_| {
                calls.set(calls.get() + 1);
                Ok(vec!["93.184.216.34".parse().unwrap()])
            },
        );
        assert!(
            result.is_err(),
            "audit failure must not become a DNS policy refusal"
        );
        assert_eq!(calls.get(), 0);
        assert!(sink.incomplete.load(Ordering::SeqCst));
        assert_eq!(sink.records.lock().unwrap()[0].0, "dns.admitted");
    }

    #[test]
    fn a_resolver_only_runs_after_the_admission_record() {
        let sink = CapturingSink::default();
        let calls = Cell::new(0);
        let result = resolve(
            &EgressGate::new(CanonicalEgress::Unrestricted),
            &sink,
            1,
            "dns.test",
            DnsRecordType::A,
            |_| {
                assert_eq!(sink.records.lock().unwrap()[0].0, "dns.admitted");
                calls.set(calls.get() + 1);
                Ok(vec!["93.184.216.34".parse().unwrap()])
            },
        );
        assert!(matches!(result, Ok(DnsVerdict::Resolved(_))));
        assert_eq!(calls.get(), 1);
    }
}
