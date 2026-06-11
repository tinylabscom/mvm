//! End-to-end smoke test for metering → audit chain.
//!
//! Producers (the supervisor's instance sampler, when the daemon
//! integration lands) emit `MeteringSample`s, aggregate into per-
//! minute `MeteringBucket`s, and seal each bucket as one
//! `LocalAuditEvent` with kind `MeteringEpoch` and
//! `detail = Some(json(bucket))`. This test exercises that path
//! without spawning the supervisor.
//!
//! The `LocalAuditLog` writer is exercised via the existing
//! `LocalAuditEvent::now` constructor + serde round-trip; the
//! signing layer (`FileAuditSigner`, mvm-core/src/policy/audit*)
//! is plumbed by downstream callers.

use mvm_core::metering::{MeteringBucket, MeteringSample};
use mvm_core::policy::audit::{LocalAuditEvent, LocalAuditKind};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

fn ts(unix_secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix_secs)
}

#[test]
fn bucket_seals_into_audit_event() {
    let mut tags = BTreeMap::new();
    tags.insert("env".to_string(), "prod".to_string());

    let samples = vec![
        MeteringSample {
            instance_id: "i-abc".to_string(),
            tenant_id: "acme".to_string(),
            tags: tags.clone(),
            ts: ts(0),
            cpu_ns: 1_000_000,
            mem_byte_seconds: 64 * 1024 * 1024,
            storage_byte_seconds_cold: 100,
            storage_byte_seconds_hot: 200,
        },
        MeteringSample {
            instance_id: "i-abc".to_string(),
            tenant_id: "acme".to_string(),
            tags: tags.clone(),
            ts: ts(30),
            cpu_ns: 2_000_000,
            mem_byte_seconds: 64 * 1024 * 1024,
            storage_byte_seconds_cold: 50,
            storage_byte_seconds_hot: 150,
        },
    ];

    let buckets = MeteringBucket::aggregate(&samples);
    assert_eq!(
        buckets.len(),
        1,
        "samples within a minute aggregate to one bucket"
    );
    assert_eq!(buckets[0].cpu_ns, 3_000_000);
    assert_eq!(buckets[0].sample_count, 2);

    // Seal: serialize the bucket and stuff it into a LocalAuditEvent.
    let detail = buckets[0].to_jsonl().expect("bucket serializes");
    let event = LocalAuditEvent::now(
        LocalAuditKind::MeteringEpoch,
        Some(buckets[0].instance_id.clone()),
        Some(detail.clone()),
    );

    // The audit event itself is the load-bearing artifact: the
    // signing layer (FileAuditSigner) will chain this with the prior
    // audit hash so any retroactive tampering breaks the chain.
    assert!(matches!(event.kind, LocalAuditKind::MeteringEpoch));
    assert_eq!(event.vm_name.as_deref(), Some("i-abc"));

    // Round-trip: a downstream forensic pass can reconstruct the
    // bucket from the audit detail without trusting the per-tenant
    // JSONL rollup file.
    let reconstructed: MeteringBucket =
        serde_json::from_str(event.detail.as_deref().unwrap()).expect("bucket round-trips");
    assert_eq!(reconstructed, buckets[0]);
}

#[test]
fn jsonl_rollup_is_one_line_per_bucket() {
    let samples = vec![
        MeteringSample {
            instance_id: "i-1".to_string(),
            tenant_id: "acme".to_string(),
            tags: BTreeMap::new(),
            ts: ts(0),
            cpu_ns: 100,
            mem_byte_seconds: 0,
            storage_byte_seconds_cold: 0,
            storage_byte_seconds_hot: 0,
        },
        MeteringSample {
            instance_id: "i-1".to_string(),
            tenant_id: "acme".to_string(),
            tags: BTreeMap::new(),
            ts: ts(60),
            cpu_ns: 200,
            mem_byte_seconds: 0,
            storage_byte_seconds_cold: 0,
            storage_byte_seconds_hot: 0,
        },
    ];

    let buckets = MeteringBucket::aggregate(&samples);
    let lines: Vec<String> = buckets.iter().map(|b| b.to_jsonl().unwrap()).collect();

    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(!line.contains('\n'), "JSONL lines must be single-line");
    }
}
