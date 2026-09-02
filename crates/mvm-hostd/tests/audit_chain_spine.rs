//! One provable audit spine across both chain-signed logs.
//!
//! mvm keeps two audit chains that canonicalize differently on purpose (see
//! specs/notes/2026-07-24-audit-chain-two-canonicalizations.md):
//!
//! - the host-lifecycle chain (`FileAuditSigner` / `verify_audit_chain`) signs a
//!   fixed-shape struct in `serde_json` declaration order and has a `no_std`
//!   browser mirror; and
//! - the per-VM workload chain (`Chain` / `verify_workload_chain`) signs a
//!   dynamic field bag through JCS (`serde_jcs`) and is host-only.
//!
//! This test anchors BOTH to the same Ed25519 host key and proves they compose
//! into one coherent, tamper-evident spine: each verifier accepts its valid
//! chain and each rejects a tampered variant.

use rand::Rng;
use std::collections::BTreeMap;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

use mvm_core::plan::{PlanId, TenantId};

use mvm_hostd::audit_signer::canonical::CanonicalEntry;
use mvm_hostd::audit_signer::chain::{Chain, OnDiskEntry};
use mvm_hostd::audit_signer::verify::{WorkloadVerifyError, verify_workload_chain};
use mvm_hostd::supervisor::audit::{AuditSigner, PlanAuditEntry};
use mvm_hostd::supervisor::audit_file::{FileAuditSigner, VerifyError, verify_audit_chain};

/// Fresh host key, following the workspace's explicit seed-fill idiom.
fn host_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn lifecycle_entry(tenant: &str, event: &str) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: Utc::now(),
        tenant: TenantId(tenant.to_string()),
        plan_id: PlanId("plan-1".to_string()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "worker".to_string(),
        image_sha256: "abc123".to_string(),
        event: event.to_string(),
        caller_commitment: None,
        labels: BTreeMap::new(),
    }
}

fn workload_entry(prev_hash: &str, fields: serde_json::Value) -> CanonicalEntry {
    CanonicalEntry {
        category: "workload_audit".into(),
        correlation_id: "01HCORR0000000000000000".into(),
        fields,
        prev_hash: prev_hash.into(),
        session_id: "sess-001".into(),
        tenant_id: "spine-tenant".into(),
        ts: "2026-07-24T00:00:00Z".into(),
        workload_id: "wl-001".into(),
    }
}

/// The spine: both chains, one host key, valid-accept + tamper-reject on each.
#[tokio::test]
async fn both_audit_chains_verify_and_reject_tamper_under_one_host_key() {
    let dir = tempdir().unwrap();
    let key = host_key();
    let verifying_key = key.verifying_key();

    // ---- Chain A: host lifecycle (declaration-order serde_json) ---------------
    let lifecycle_dir = dir.path().join("lifecycle");
    let signer = FileAuditSigner::open(key.clone(), &lifecycle_dir).unwrap();
    for event in ["plan.admitted", "plan.launched", "plan.failed"] {
        signer
            .sign_and_emit(&lifecycle_entry("spine-tenant", event))
            .await
            .unwrap();
    }
    let lifecycle_path = signer.tenant_path("spine-tenant");
    assert_eq!(
        verify_audit_chain(&lifecycle_path, &verifying_key).unwrap(),
        3,
        "valid lifecycle chain must verify all three entries"
    );

    // ---- Chain B: per-VM workload (JCS via serde_jcs), SAME host key ----------
    let workload_path = dir.path().join("spine-tenant.workload.jsonl");
    let head_path = dir.path().join("HEAD");
    let key_path = dir.path().join("chain.key");
    std::fs::write(&key_path, key.to_bytes()).unwrap();
    let mut chain = Chain::open(&workload_path, &head_path, Some(&key_path)).unwrap();
    assert_eq!(
        chain.pub_key(),
        verifying_key.to_bytes().to_vec(),
        "both chains are anchored to the one host key"
    );
    for _ in 0..3 {
        let entry = workload_entry(chain.head(), serde_json::json!({"verb": "now"}));
        chain.append(entry).expect("workload append must succeed");
    }
    assert_eq!(
        verify_workload_chain(&workload_path, &verifying_key).unwrap(),
        3,
        "valid workload chain must verify all three entries"
    );

    // ---- Tamper Chain A: flip the first event; the line must fail closed ------
    let content = std::fs::read_to_string(&lifecycle_path).unwrap();
    // Same-length swap keeps the JSON well-formed but off the signed bytes.
    // The lifecycle chain stores those bytes beside the readable entry, so an
    // in-place edit is caught as the two disagreeing.
    let tampered = content.replacen("plan.admitted", "plan.smuggled", 1);
    std::fs::write(&lifecycle_path, tampered).unwrap();
    let err = verify_audit_chain(&lifecycle_path, &verifying_key)
        .expect_err("tampered lifecycle chain must fail closed");
    assert!(
        matches!(err, VerifyError::EntryCanonicalMismatch { line: 0 }),
        "got {err:?}"
    );

    // ---- Tamper Chain B: rewrite the first entry_hash; chain link must break --
    let mut lines: Vec<String> = std::fs::read_to_string(&workload_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut first: OnDiskEntry = serde_json::from_str(&lines[0]).unwrap();
    first.entry_hash = "0".repeat(64);
    lines[0] = serde_json::to_string(&first).unwrap();
    std::fs::write(&workload_path, format!("{}\n", lines.join("\n"))).unwrap();
    let err = verify_workload_chain(&workload_path, &verifying_key)
        .expect_err("tampered workload chain must fail closed");
    assert!(
        matches!(err, WorkloadVerifyError::EntryHashMismatch { line: 0 }),
        "got {err:?}"
    );
}

/// Workload-chain self-consistency across Unicode key planes.
///
/// The workload chain's dynamic `fields` can carry non-ASCII object keys. Its
/// verifier re-canonicalizes with the same `serde_jcs`, so it stays internally
/// self-consistent regardless of key plane — including astral-plane (> U+FFFF)
/// keys where `serde_jcs`'s UTF-8 sort would diverge from a strict RFC 8785
/// UTF-16 verifier. This pins the "document, don't guard" decision: no mismatch
/// exists inside mvm; the caveat is only for a hypothetical external verifier.
#[test]
fn workload_chain_is_self_consistent_across_unicode_key_planes() {
    let dir = tempdir().unwrap();
    let key = host_key();
    let key_path = dir.path().join("chain.key");
    std::fs::write(&key_path, key.to_bytes()).unwrap();
    let workload_path = dir.path().join("spine-tenant.workload.jsonl");
    let head_path = dir.path().join("HEAD");
    let mut chain = Chain::open(&workload_path, &head_path, Some(&key_path)).unwrap();

    // BMP non-ASCII ("café", "你好") plus an astral-plane key (U+1F600) in one bag.
    let fields = serde_json::json!({
        "café": 1,
        "你好": 2,
        "\u{1F600}": 3,
        "\u{FFFF}": 4,
        "a": 5,
    });
    let entry = workload_entry(chain.head(), fields);
    chain
        .append(entry)
        .expect("append with unicode keys must succeed");

    assert_eq!(
        verify_workload_chain(&workload_path, &key.verifying_key()).unwrap(),
        1,
        "the same serde_jcs writes and re-canonicalizes, so any key plane verifies"
    );
}
