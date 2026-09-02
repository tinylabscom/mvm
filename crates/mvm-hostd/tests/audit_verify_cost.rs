//! Measures what full audit-chain verification costs per entry.
//!
//! `verify_audit_chain_entries` re-derives the whole chain from genesis on
//! every call, and the log is append-only with no rotation, so the cost of the
//! `doctor` health check grows with total audit history. Whether that is worth
//! optimizing is a question about a release-build number, so the number is
//! measured here rather than extrapolated from a debug run:
//!
//! ```text
//! cargo test --release -p mvm-hostd --test audit_verify_cost -- --nocapture
//! ```
//!
//! The assertion is a loose ceiling to catch a pathological regression, not a
//! performance pin — the measurement is the point, and it is printed.

use std::collections::BTreeMap;
use std::time::Instant;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::supervisor::{
    AuditSigner, FileAuditSigner, PlanAuditEntry, verify_audit_chain_entries,
};

/// Chain length to measure. Chosen to match the ~3.3k entries a few months of
/// ordinary use produced on a real host, so the per-entry figure is taken at a
/// realistic size rather than extrapolated from a toy chain.
const ENTRIES: usize = 3_289;

/// Ceiling per entry. Generous: a loaded CI box is slow, and this exists to
/// catch a deadlock or quadratic behaviour, not to pin a number.
const MAX_NS_PER_ENTRY: u128 = 5_000_000;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// An entry shaped like a real one: the labels and identifiers are what the
/// launch path actually emits, so the JSON parsed per line is representative
/// in size.
fn entry(seq: usize) -> PlanAuditEntry {
    let mut labels = BTreeMap::new();
    labels.insert("backend".to_string(), "hvf".to_string());
    labels.insert("vm".to_string(), format!("machine-{seq}"));
    PlanAuditEntry {
        timestamp: Utc::now(),
        tenant: TenantId("local".to_string()),
        plan_id: PlanId(format!("plan-{seq}")),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "docker.io/library/alpine:latest".to_string(),
        image_sha256: "e7a1a92a5bfe6a2fdbcbbbd0e0e0b4d7b6a5c4d3e2f1a0b9c8d7e6f5a4b3c2d1"
            .to_string(),
        event: "plan.admitted".to_string(),
        caller_commitment: None,
        labels,
    }
}

#[tokio::test]
#[cfg_attr(debug_assertions, ignore = "release-build performance measurement")]
async fn full_chain_verification_cost_per_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = signing_key();
    let verifying = key.verifying_key();

    let signer = FileAuditSigner::open(key, dir.path()).expect("signer");
    for seq in 0..ENTRIES {
        signer.sign_and_emit(&entry(seq)).await.expect("emit");
    }
    drop(signer);

    let path = dir.path().join("local.jsonl");
    let bytes = std::fs::metadata(&path).expect("stat").len();

    // Verify once untimed so the page cache is warm; the question is compute
    // cost, not first-read I/O.
    let warm = verify_audit_chain_entries(&path, &verifying).expect("warm verify");
    assert_eq!(warm.len(), ENTRIES, "chain should verify end to end");

    let start = Instant::now();
    let entries = verify_audit_chain_entries(&path, &verifying).expect("verify");
    let elapsed = start.elapsed();

    assert_eq!(entries.len(), ENTRIES);
    let per_entry = elapsed.as_nanos() / ENTRIES as u128;
    println!(
        "audit chain verify: {ENTRIES} entries, {} KiB, total {:?}, {per_entry} ns/entry",
        bytes / 1024,
        elapsed,
    );

    assert!(
        per_entry < MAX_NS_PER_ENTRY,
        "{per_entry} ns/entry exceeds the ceiling"
    );
}
