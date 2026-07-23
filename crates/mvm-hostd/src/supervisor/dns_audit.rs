//! Chain-signed DNS decision audit events.

#[cfg(target_os = "linux")]
use std::future::Future;

use mvm_core::protocol::dns::DnsRecordType;
use mvm_runtime::vmm::egress_gate::DnsVerdict;

use crate::supervisor::audit_recorder::{EventCategory, Recorder};

/// Record one policy-gated DNS decision without retaining query or response bytes.
pub async fn emit_dns_query(
    recorder: &Recorder,
    name: &str,
    qtype: DnsRecordType,
    verdict: &DnsVerdict,
) {
    let (event, verdict_label, ips) = match verdict {
        DnsVerdict::Refused => ("dns.refused", "refused", String::new()),
        DnsVerdict::Resolved(ips) => (
            "dns.resolved",
            "resolved",
            ips.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
    };
    emit_dns_event(recorder, name, qtype, event, verdict_label, ips).await;
}

/// Record a DNS query refused before resolution because its workload exceeded a limit.
pub async fn emit_dns_rate_limited(recorder: &Recorder, name: &str, qtype: DnsRecordType) {
    emit_dns_event(
        recorder,
        name,
        qtype,
        "dns.refused",
        "rate_limited",
        String::new(),
    )
    .await;
}

/// Record a DNS query refused because it failed to decode. No qname/qtype is
/// recoverable, so the entry carries the `malformed` verdict with empty
/// name/type — every query, valid or not, leaves a trace in the chain.
pub async fn emit_dns_malformed(recorder: &Recorder) {
    record_dns(recorder, "dns.refused", "", "", "malformed", String::new()).await;
}

/// Record a malformed DNS query from the blocking vsock transport.
#[cfg(target_os = "linux")]
pub fn emit_dns_malformed_blocking(recorder: &Recorder) {
    emit_blocking("", emit_dns_malformed(recorder));
}

async fn emit_dns_event(
    recorder: &Recorder,
    name: &str,
    qtype: DnsRecordType,
    event: &'static str,
    verdict_label: &'static str,
    ips: String,
) {
    let qtype = match qtype {
        DnsRecordType::A => "a",
        DnsRecordType::Aaaa => "aaaa",
    };
    record_dns(recorder, event, name, qtype, verdict_label, ips).await;
}

async fn record_dns(
    recorder: &Recorder,
    event: &'static str,
    qname: &str,
    qtype: &str,
    verdict: &str,
    ips: String,
) {
    let labels = [
        ("qname".to_string(), qname.to_string()),
        ("qtype".to_string(), qtype.to_string()),
        ("verdict".to_string(), verdict.to_string()),
        ("ips".to_string(), ips),
    ];
    if let Err(error) = recorder
        .record_unbound(EventCategory::Dns, event, labels)
        .await
    {
        tracing::warn!(%error, qname = %qname, "DNS audit emit failed");
    }
}

/// Record a DNS decision from the blocking vsock transport.
#[cfg(target_os = "linux")]
pub fn emit_dns_query_blocking(
    recorder: &Recorder,
    name: &str,
    qtype: DnsRecordType,
    verdict: &DnsVerdict,
) {
    emit_blocking(name, emit_dns_query(recorder, name, qtype, verdict));
}

/// Record a rate-limited DNS query from the blocking vsock transport.
#[cfg(target_os = "linux")]
pub fn emit_dns_rate_limited_blocking(recorder: &Recorder, name: &str, qtype: DnsRecordType) {
    emit_blocking(name, emit_dns_rate_limited(recorder, name, qtype));
}

#[cfg(target_os = "linux")]
fn emit_blocking(name: &str, emit: impl Future<Output = ()>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(qname = %name, "DNS audit runtime unavailable");
        return;
    };
    if !matches!(
        handle.runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        tracing::warn!(qname = %name, "DNS audit requires a multi-thread runtime on the blocking transport");
        return;
    }
    tokio::task::block_in_place(|| handle.block_on(emit));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::supervisor::audit::CapturingAuditSigner;
    use crate::supervisor::audit_recorder::Recorder;
    use mvm_core::observability::metrics::Metrics;
    use mvm_core::plan::TenantId;
    use mvm_core::protocol::dns::DnsRecordType;
    use mvm_runtime::vmm::egress_gate::DnsVerdict;

    fn fixture() -> (Recorder, Arc<CapturingAuditSigner>, Arc<Metrics>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let metrics = Arc::new(Metrics::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".into()))
            .with_metrics(Arc::clone(&metrics));
        (recorder, signer, metrics)
    }

    #[tokio::test]
    async fn emits_refused_query_metadata_only() {
        let (recorder, signer, metrics) = fixture();
        emit_dns_query(
            &recorder,
            "evil.test",
            DnsRecordType::A,
            &DnsVerdict::Refused,
        )
        .await;

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.event, "dns.refused");
        assert_eq!(
            entry.labels.get("category").map(String::as_str),
            Some("dns")
        );
        assert_eq!(
            entry.labels.get("qname").map(String::as_str),
            Some("evil.test")
        );
        assert_eq!(entry.labels.get("qtype").map(String::as_str), Some("a"));
        assert_eq!(
            entry.labels.get("verdict").map(String::as_str),
            Some("refused")
        );
        assert_eq!(entry.labels.get("ips").map(String::as_str), Some(""));
        assert_eq!(entry.labels.len(), 5, "only fixed DNS metadata is audited");
        assert_eq!(metrics.snapshot().audit_dns_total, 1);
    }

    #[tokio::test]
    async fn emits_resolved_query_with_ip_list() {
        let (recorder, signer, metrics) = fixture();
        let verdict = DnsVerdict::Resolved(vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ]);
        emit_dns_query(&recorder, "example.com", DnsRecordType::Aaaa, &verdict).await;

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.event, "dns.resolved");
        assert_eq!(entry.labels.get("qtype").map(String::as_str), Some("aaaa"));
        assert_eq!(
            entry.labels.get("verdict").map(String::as_str),
            Some("resolved")
        );
        assert_eq!(
            entry.labels.get("ips").map(String::as_str),
            Some("93.184.216.34,2606:2800:220:1:248:1893:25c8:1946")
        );
        assert_eq!(entry.labels.len(), 5, "no query payload bytes are audited");
        assert_eq!(metrics.snapshot().audit_dns_total, 1);
    }

    #[tokio::test]
    async fn emits_rate_limited_query_as_a_distinct_refusal() {
        let (recorder, signer, metrics) = fixture();
        emit_dns_rate_limited(&recorder, "busy.test", DnsRecordType::A).await;

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "dns.refused");
        assert_eq!(
            entries[0].labels.get("verdict").map(String::as_str),
            Some("rate_limited")
        );
        assert_eq!(entries[0].labels.get("ips").map(String::as_str), Some(""));
        assert_eq!(metrics.snapshot().audit_dns_total, 1);
    }

    #[tokio::test]
    async fn emits_malformed_query_as_a_distinct_refusal() {
        let (recorder, signer, metrics) = fixture();
        emit_dns_malformed(&recorder).await;

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.event, "dns.refused");
        assert_eq!(
            entry.labels.get("verdict").map(String::as_str),
            Some("malformed")
        );
        assert_eq!(entry.labels.get("qname").map(String::as_str), Some(""));
        assert_eq!(
            entry.labels.len(),
            5,
            "malformed keeps the fixed DNS schema"
        );
        assert_eq!(metrics.snapshot().audit_dns_total, 1);
    }
}
