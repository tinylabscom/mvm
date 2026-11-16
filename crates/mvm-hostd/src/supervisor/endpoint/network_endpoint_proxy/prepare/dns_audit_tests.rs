use super::*;
use mvm_contract::policy::projection::CanonicalEgress;
use mvm_core::audit_sink::AuditSink;
use mvm_runtime::vmm::egress_gate::EgressGate;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

struct LookupSink {
    fail: bool,
    written: AtomicBool,
    incomplete: AtomicBool,
}

impl AuditSink for LookupSink {
    fn record(&self, event: &str, _: BTreeMap<String, String>) -> std::io::Result<()> {
        assert_eq!(event, "dns.admitted");
        self.written.store(true, Ordering::SeqCst);
        if self.fail {
            self.incomplete.store(true, Ordering::SeqCst);
            Err(std::io::Error::other("injected DNS audit failure"))
        } else {
            Ok(())
        }
    }

    fn suppress_denial(&self) {
        panic!("DNS admission never suppresses a refusal");
    }

    fn flush_health(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn failed_or_missing_http_dns_audit_never_reaches_the_resolver() {
    let sink = LookupSink {
        fail: true,
        written: AtomicBool::new(false),
        incomplete: AtomicBool::new(false),
    };
    let gate = EgressGate::new(CanonicalEgress::Unrestricted);
    for sink in [Some(&sink as &dyn AuditSink), None] {
        assert_eq!(
            claim10_with_resolver(&gate, sink, "dns.test:443", |_| {
                panic!("unauditable DNS must not reach upstream")
            }),
            Err(REASON_AUDIT_UNAVAILABLE),
        );
    }
    assert!(sink.incomplete.load(Ordering::SeqCst));
}

#[test]
fn http_dns_is_authorized_before_resolution() {
    let sink = LookupSink {
        fail: false,
        written: AtomicBool::new(false),
        incomplete: AtomicBool::new(false),
    };
    let admitted = claim10_with_resolver(
        &EgressGate::new(CanonicalEgress::Unrestricted),
        Some(&sink),
        "dns.test:443",
        |_| {
            assert!(sink.written.load(Ordering::SeqCst));
            Ok(vec!["93.184.216.34".parse().unwrap()])
        },
    )
    .unwrap();
    assert_eq!(
        admitted,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
}
