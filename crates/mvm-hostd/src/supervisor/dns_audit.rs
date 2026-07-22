//! Chain-signed DNS decision audit events.

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
    let qtype = match qtype {
        DnsRecordType::A => "a",
        DnsRecordType::Aaaa => "aaaa",
    };
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
    let labels = [
        ("qname".to_string(), name.to_string()),
        ("qtype".to_string(), qtype.to_string()),
        ("verdict".to_string(), verdict_label.to_string()),
        ("ips".to_string(), ips),
    ];
    if let Err(error) = recorder
        .record_unbound(EventCategory::Dns, event, labels)
        .await
    {
        tracing::warn!(%error, qname = %name, "DNS audit emit failed");
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
    tokio::task::block_in_place(|| handle.block_on(emit_dns_query(recorder, name, qtype, verdict)));
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
}
