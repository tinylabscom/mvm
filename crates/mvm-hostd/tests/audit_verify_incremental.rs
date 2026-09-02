//! Behaviour of incremental audit-chain verification.
//!
//! Resuming from a checkpoint trades the genesis anchor — the requirement that
//! line 0 claim an all-zero predecessor — for a stored value. These tests pin
//! both halves of that bargain: the speedup it buys, and the properties it
//! must not give up.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::supervisor::{
    AuditSigner, ChainCheckpoint, FileAuditSigner, PlanAuditEntry, VerifyError,
    verify_audit_chain_entries, verify_audit_chain_incremental,
};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn entry(seq: usize) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: Utc::now(),
        tenant: TenantId("local".to_string()),
        plan_id: PlanId(format!("plan-{seq}")),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "img".to_string(),
        image_sha256: "abc123".to_string(),
        event: "plan.admitted".to_string(),
        caller_commitment: None,
        labels: BTreeMap::new(),
    }
}

/// Write an `n`-entry chain and return its path plus the verifying key.
async fn chain(dir: &Path, n: usize) -> (std::path::PathBuf, VerifyingKey) {
    let key = signing_key();
    let verifying = key.verifying_key();
    let signer = FileAuditSigner::open(key, dir).expect("signer");
    for seq in 0..n {
        signer.sign_and_emit(&entry(seq)).await.expect("emit");
    }
    drop(signer);
    (dir.join("local.jsonl"), verifying)
}

/// Append `n` more entries to an existing chain.
async fn append(dir: &Path, from: usize, n: usize) {
    let signer = FileAuditSigner::open(signing_key(), dir).expect("signer");
    for seq in from..from + n {
        signer.sign_and_emit(&entry(seq)).await.expect("emit");
    }
}

#[tokio::test]
async fn without_a_checkpoint_it_walks_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 5).await;

    let out = verify_audit_chain_incremental(&path, &key, None).expect("verify");
    assert!(out.walked_from_genesis);
    assert_eq!(out.verified_now, 5);
    assert_eq!(out.checkpoint.verified_lines, 5);
}

#[tokio::test]
async fn a_checkpoint_verifies_only_the_new_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 5).await;
    let first = verify_audit_chain_incremental(&path, &key, None).expect("first");

    append(dir.path(), 5, 3).await;
    let second =
        verify_audit_chain_incremental(&path, &key, Some(&first.checkpoint)).expect("second");

    assert!(!second.walked_from_genesis, "should have resumed");
    assert_eq!(second.verified_now, 3, "only the appended entries");
    assert_eq!(second.checkpoint.verified_lines, 8);
}

#[tokio::test]
async fn a_current_checkpoint_on_an_unchanged_file_verifies_nothing_new() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 4).await;
    let first = verify_audit_chain_incremental(&path, &key, None).expect("first");

    // verified_lines == total, so there is no resume point and it re-walks.
    // Correct but not free; the value of the checkpoint is in the append case.
    let second =
        verify_audit_chain_incremental(&path, &key, Some(&first.checkpoint)).expect("second");
    assert_eq!(second.checkpoint.verified_lines, 4);
}

#[tokio::test]
async fn tampering_after_the_checkpoint_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 4).await;
    let first = verify_audit_chain_incremental(&path, &key, None).expect("first");
    append(dir.path(), 4, 2).await;

    // Corrupt the last entry's signature.
    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let last = lines.last_mut().unwrap();
    *last = last.replace("\"signature\":\"", "\"signature\":\"AA");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    let err = verify_audit_chain_incremental(&path, &key, Some(&first.checkpoint))
        .expect_err("tampered tail must be refused");
    assert!(
        matches!(
            err,
            VerifyError::SignatureInvalid { .. } | VerifyError::Malformed { .. }
        ),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn a_checkpoint_past_the_end_of_the_file_falls_back_to_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 3).await;

    let bogus = ChainCheckpoint {
        verified_lines: 99,
        chain_hash: "AAAA".to_string(),
    };
    let out = verify_audit_chain_incremental(&path, &key, Some(&bogus)).expect("verify");
    assert!(out.walked_from_genesis, "a short file cannot be resumed");
    assert_eq!(out.verified_now, 3);
}

#[tokio::test]
async fn an_undecodable_checkpoint_falls_back_rather_than_erroring() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 3).await;

    let bogus = ChainCheckpoint {
        verified_lines: 1,
        chain_hash: "!!! not base64 !!!".to_string(),
    };
    let out = verify_audit_chain_incremental(&path, &key, Some(&bogus)).expect("verify");
    assert!(out.walked_from_genesis);
    assert_eq!(out.verified_now, 3);
}

#[tokio::test]
async fn a_checkpoint_with_the_wrong_hash_falls_back_and_still_passes() {
    // A stale checkpoint is not evidence of tampering — it is equally
    // consistent with rotation or a replaced file. It must never produce a
    // "broken chain" verdict on a chain that is in fact intact.
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 5).await;

    let wrong = ChainCheckpoint {
        verified_lines: 2,
        chain_hash: base64_of([9u8; 32]),
    };
    let out = verify_audit_chain_incremental(&path, &key, Some(&wrong)).expect("intact chain");
    assert!(out.walked_from_genesis, "must fall back to a full walk");
    assert_eq!(out.verified_now, 5);
}

#[tokio::test]
async fn a_truncated_prefix_is_refused_by_the_full_verifier() {
    // The property the genesis anchor buys, and the reason `trust audit
    // verify` keeps using the full walk: removing history is detectable.
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 6).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = content.lines().skip(2).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

    let err = verify_audit_chain_entries(&path, &key).expect_err("prefix removal must be caught");
    assert!(
        matches!(err, VerifyError::PrevHashMismatch { line: 0 }),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn a_zero_line_checkpoint_never_suppresses_the_genesis_anchor() {
    // `verified_lines == 0` carries no information and is rejected outright,
    // so the cheapest forgery — "resume at the start with a hash of my
    // choosing" — cannot skip the anchor.
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 6).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = content.lines().skip(2).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

    let forged = ChainCheckpoint {
        verified_lines: 0,
        chain_hash: base64_of([3u8; 32]),
    };
    let err = verify_audit_chain_incremental(&path, &key, Some(&forged))
        .expect_err("a zero-line checkpoint must fall back to the genesis anchor");
    assert!(
        matches!(err, VerifyError::PrevHashMismatch { line: 0 }),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn a_forged_checkpoint_hides_a_truncated_prefix() {
    // The documented cost of resuming, pinned so it cannot be forgotten and
    // cannot regress into something worse without a test turning red.
    //
    // An adversary who can write the checkpoint drops the first k entries and
    // records `(1, hash(new line 0))` — a hash they can compute from the file
    // they just wrote. The resumed walk starts at line 1, whose `prev_hash` is
    // genuinely that value, and every surviving line is genuinely signed, so
    // it has nothing to object to. The removed history is gone silently.
    //
    // This is exactly why the incremental path is confined to the routine
    // health check, why its result must not be reported as a full-chain
    // guarantee, and why `mvmctl trust audit verify` still walks from genesis.
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = chain(dir.path(), 6).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = content.lines().skip(2).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

    // The hash the adversary records: line 0 of the file they just wrote.
    let truncated = std::fs::read_to_string(&path).unwrap();
    let after_new_line_0 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(truncated.lines().next().unwrap().as_bytes());
        let out: [u8; 32] = h.finalize().into();
        out
    };

    let forged = ChainCheckpoint {
        verified_lines: 1,
        chain_hash: base64_of(after_new_line_0),
    };
    let out = verify_audit_chain_incremental(&path, &key, Some(&forged))
        .expect("the truncation is invisible to a resumed walk — this is the cost");
    assert!(
        !out.walked_from_genesis,
        "the forged checkpoint was accepted, which is the point of this test"
    );

    // And the property that makes it survivable: the full walk still catches it.
    let err = verify_audit_chain_entries(&path, &key)
        .expect_err("the genesis-anchored walk must still refuse the truncation");
    assert!(
        matches!(err, VerifyError::PrevHashMismatch { line: 0 }),
        "unexpected error: {err}"
    );
}

fn base64_of(bytes: [u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
