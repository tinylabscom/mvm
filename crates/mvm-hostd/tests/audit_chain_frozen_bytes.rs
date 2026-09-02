//! A frozen audit chain, and the two verifiers that must both accept it.
//!
//! The chain-signed audit log is evidence. Its value rests on a log written by
//! an old binary still verifying under a new one — so the bytes the writer
//! produces for a given `(key, entries)` are a compatibility surface, not an
//! implementation detail, and nothing else in the suite says so. Every other
//! audit test signs and verifies within one process, which passes just as
//! happily if the writer and both verifiers change together.
//!
//! This file pins the bytes themselves. `tests/fixtures/audit_chain_v1.jsonl`
//! was produced by the writer at the commit that added it, and is regenerated
//! only deliberately (see `REGENERATE` below). Three things are asserted
//! against it:
//!
//! 1. The writer still produces those exact bytes for the same key and
//!    entries.
//! 2. `mvm_hostd`'s verifier accepts the committed file.
//! 3. `mvm_contract`'s `no_std` verifier accepts the same bytes, reaching the
//!    same entry count. Two implementations, one answer.
//!
//! Plus a legacy fixture with no `canonical` field, which the code promises to
//! keep verifying "indefinitely" by re-serializing `entry`. That promise is
//! the one thing here that depends on byte-exact serde agreement across
//! crates, and it is the first thing a careless refactor of either
//! `PlanAuditEntry` breaks.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use mvm_core::plan::{PlanId, TenantId};
use mvm_core::policy::PolicyId;
use mvm_hostd::supervisor::audit::{AuditSigner, PlanAuditEntry};
use mvm_hostd::supervisor::audit_file::{FileAuditSigner, VerifyError, verify_audit_chain};

/// Set to regenerate both fixtures in place, then inspect the diff before
/// committing it. A change here is a change to what old evidence verifies
/// against, so it wants a reviewer who has looked at the bytes.
const REGENERATE: bool = false;

/// A fixed signing seed. Ed25519 signatures are deterministic over
/// `(key, message)`, so a fixed seed plus fixed entries is a fixed file —
/// which is the only reason freezing the bytes is possible at all.
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Fixed timestamps. `Utc::now()` would make the bytes unfreezable, which is
/// why the entries are built field-by-field rather than through
/// `PlanAuditEntry::for_plan`.
fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("fixture timestamp parses")
        .with_timezone(&Utc)
}

/// The frozen entry set. Deliberately exercises the shape choices that move
/// bytes: both states of the two `skip_serializing_if` options, an empty and a
/// populated `labels` map (whose `BTreeMap` ordering is the canonical one),
/// and a barrier event alongside a deferred one.
fn frozen_entries() -> Vec<PlanAuditEntry> {
    let mut labels = BTreeMap::new();
    labels.insert("workload".to_string(), "api".to_string());
    // Inserted out of order on purpose: the BTreeMap must emit them sorted, so
    // a switch to a hash-ordered map shows up here as a byte change.
    labels.insert("region".to_string(), "us-east-1".to_string());

    vec![
        PlanAuditEntry {
            timestamp: ts("2026-01-01T00:00:00Z"),
            tenant: TenantId("frozen-tenant".to_string()),
            plan_id: PlanId("plan-frozen-001".to_string()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "worker".to_string(),
            image_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            event: "plan.admitted".to_string(),
            caller_commitment: None,
            labels: BTreeMap::new(),
        },
        PlanAuditEntry {
            timestamp: ts("2026-01-01T00:00:01Z"),
            tenant: TenantId("frozen-tenant".to_string()),
            plan_id: PlanId("plan-frozen-001".to_string()),
            plan_version: 1,
            bundle_id: Some(PolicyId("bundle-frozen".to_string())),
            bundle_version: Some(7),
            image_name: "worker".to_string(),
            image_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            event: "plan.policy_resolved".to_string(),
            caller_commitment: None,
            labels: labels.clone(),
        },
        PlanAuditEntry {
            timestamp: ts("2026-01-01T00:00:02Z"),
            tenant: TenantId("frozen-tenant".to_string()),
            plan_id: PlanId("plan-frozen-001".to_string()),
            plan_version: 1,
            bundle_id: Some(PolicyId("bundle-frozen".to_string())),
            bundle_version: Some(7),
            image_name: "worker".to_string(),
            image_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            event: "plan.launched".to_string(),
            caller_commitment: None,
            labels,
        },
    ]
}

/// Write the frozen entries through the real `FileAuditSigner` and return the
/// file it produced. Using the production writer rather than an in-test
/// reimplementation is the point: a hand-rolled encoder here would freeze the
/// test's idea of the format, not the product's.
async fn write_chain_with_real_signer() -> String {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("frozen.jsonl");
    let signer = FileAuditSigner::open_file(signing_key(), &path).expect("open signer");
    for entry in frozen_entries() {
        signer.sign_and_emit(&entry).await.expect("emit");
    }
    drop(signer);
    std::fs::read_to_string(&path).expect("read produced chain")
}

#[tokio::test]
async fn the_writer_still_produces_the_frozen_bytes() {
    let produced = write_chain_with_real_signer().await;
    let path = fixture_path("audit_chain_v1.jsonl");

    if REGENERATE {
        std::fs::create_dir_all(path.parent().unwrap()).expect("fixture dir");
        std::fs::write(&path, &produced).expect("write fixture");
        panic!("REGENERATE is on — fixture rewritten, now set it back to false");
    }

    let frozen = std::fs::read_to_string(&path).expect("committed fixture is readable");
    assert_eq!(
        produced, frozen,
        "the audit writer's output drifted from the frozen fixture.\n\
         This is not automatically a bug — but it does mean a log written \
         before this change and a log written after it are different bytes \
         for the same entries. Confirm old chains still verify, then \
         regenerate deliberately via REGENERATE."
    );
}

#[test]
fn the_host_verifier_accepts_the_frozen_chain() {
    let path = fixture_path("audit_chain_v1.jsonl");
    let count = verify_audit_chain(&path, &signing_key().verifying_key())
        .expect("the frozen chain must verify under the host verifier");
    assert_eq!(count, frozen_entries().len());
}

#[test]
fn the_no_std_verifier_agrees_with_the_host_verifier() {
    // The property option A's unification has to preserve: two independent
    // implementations, one on `std` and one built for wasm, reach the same
    // verdict on the same bytes. If they ever disagree, the browser is
    // telling visitors something the host does not believe.
    let bytes = std::fs::read_to_string(fixture_path("audit_chain_v1.jsonl")).expect("fixture");
    let key_hex = hex::encode(signing_key().verifying_key().to_bytes());
    let key = mvm_contract::verify::verifying_key_from_hex(&key_hex).expect("key decodes");

    let verified = mvm_contract::verify::verify_audit_chain_bytes(&bytes, &key)
        .expect("the no_std verifier must accept the same chain");
    assert_eq!(verified.count, frozen_entries().len());

    let host_count = verify_audit_chain(
        &fixture_path("audit_chain_v1.jsonl"),
        &signing_key().verifying_key(),
    )
    .expect("host verifier");
    assert_eq!(
        verified.count, host_count,
        "the two verifiers must count the same chain identically"
    );
}

#[test]
fn a_flipped_byte_in_the_frozen_chain_is_caught_at_its_line() {
    // Without this, the fixture could rot into a file that parses and proves
    // nothing. Tampering line 1 must be refused, and refused *there*.
    let bytes = std::fs::read_to_string(fixture_path("audit_chain_v1.jsonl")).expect("fixture");
    let mut lines: Vec<String> = bytes.lines().map(str::to_string).collect();
    lines[1] = lines[1].replace("us-east-1", "eu-west-1");
    assert_ne!(
        lines[1],
        bytes.lines().nth(1).unwrap(),
        "the tamper must actually change the line"
    );

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("tampered.jsonl");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write tampered");

    let err = verify_audit_chain(&path, &signing_key().verifying_key())
        .expect_err("a tampered chain must not verify");
    assert!(
        matches!(
            err,
            VerifyError::SignatureInvalid { line: 1 }
                | VerifyError::EntryCanonicalMismatch { line: 1 }
        ),
        "expected the failure to name line 1, got: {err:?}"
    );
}

/// Build the legacy, pre-`canonical` line form by hand. The writer cannot
/// produce this any more — it always emits `canonical` — so the only way to
/// keep testing the compatibility promise is to author the bytes.
fn legacy_chain_bytes() -> String {
    let key = signing_key();
    let mut prev_hash = [0u8; 32];
    let mut out = String::new();
    for entry in frozen_entries() {
        let entry_bytes = serde_json::to_vec(&entry).expect("serialize entry");
        let mut to_sign = entry_bytes.clone();
        to_sign.extend_from_slice(&prev_hash);
        let signature = key.sign(&to_sign);
        // No `canonical` field: the shape written before it existed.
        let line = serde_json::json!({
            "entry": entry,
            "prev_hash": URL_SAFE_NO_PAD.encode(prev_hash),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        });
        let line = serde_json::to_string(&line).expect("serialize envelope");
        let mut hasher = Sha256::new();
        hasher.update(line.as_bytes());
        prev_hash = hasher.finalize().into();
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[test]
fn a_pre_canonical_chain_still_verifies() {
    let path = fixture_path("audit_chain_legacy_no_canonical_v1.jsonl");

    if REGENERATE {
        std::fs::create_dir_all(path.parent().unwrap()).expect("fixture dir");
        std::fs::write(&path, legacy_chain_bytes()).expect("write legacy fixture");
        panic!("REGENERATE is on — fixture rewritten, now set it back to false");
    }

    let frozen = std::fs::read_to_string(&path).expect("committed legacy fixture is readable");

    // Verification is asserted before the byte comparison on purpose. Both
    // fail if `PlanAuditEntry`'s serde changes, but they say different things and
    // this is the one worth reading first: a pre-`canonical` line carries no
    // signed bytes, so the verifier re-serializes `entry`. A serde change
    // therefore does not merely alter what a *new* writer emits — it stops
    // evidence somebody already holds from verifying at all.
    let count = verify_audit_chain(&path, &signing_key().verifying_key()).expect(
        "a pre-`canonical` chain must keep verifying — the code promises this \
         indefinitely, so a failure here means historical audit logs have just \
         become unverifiable",
    );
    assert_eq!(count, frozen_entries().len());

    // The diagnostic half: which bytes moved.
    assert_eq!(
        legacy_chain_bytes(),
        frozen,
        "`PlanAuditEntry`'s serialized form changed."
    );
}

#[test]
fn the_no_std_verifier_also_accepts_the_pre_canonical_chain() {
    // The mirror carries the heaviest coupling here: with no `canonical` field
    // there are no signed bytes on the line to read, so `MirrorEntry` has to
    // re-serialize to the same bytes `PlanAuditEntry` did, in another crate.
    let bytes =
        std::fs::read_to_string(fixture_path("audit_chain_legacy_no_canonical_v1.jsonl")).unwrap();
    let key_hex = hex::encode(signing_key().verifying_key().to_bytes());
    let key = mvm_contract::verify::verifying_key_from_hex(&key_hex).expect("key decodes");

    let verified = mvm_contract::verify::verify_audit_chain_bytes(&bytes, &key)
        .expect("the no_std verifier must accept a pre-`canonical` chain too");
    assert_eq!(verified.count, frozen_entries().len());
}
