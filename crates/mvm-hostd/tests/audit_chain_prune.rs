//! Accountable pruning of a rotated audit chain.
//!
//! Rotation made removal *detectable*. These tests are about making a
//! deliberate removal *accountable* without reopening the hole rotation was
//! designed to close: a signed "this was intentional" record must not become a
//! way to relabel an edit.

use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::supervisor::audit::{AuditSigner, PlanAuditEntry};
use mvm_hostd::supervisor::audit_file::{FileAuditSigner, RotationPolicy};
use mvm_hostd::supervisor::audit_segment::{LABEL_PRUNED_THROUGH, LABEL_PRUNED_TIP};
use mvm_hostd::supervisor::audit_set::{SegmentSetError, verify_segment_set};
use std::path::Path;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn entry(n: usize) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: TenantId("local".to_string()),
        plan_id: PlanId(format!("plan-{n}")),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "img".to_string(),
        image_sha256: "0".repeat(64),
        event: "plan.launched".to_string(),
        labels: std::collections::BTreeMap::from([("n".to_string(), n.to_string())]),
    }
}

/// A chain rotated into several sealed segments plus a live one.
async fn rotated(dir: &Path, count: usize) -> FileAuditSigner {
    let signer = FileAuditSigner::open(key(), dir)
        .unwrap()
        .with_rotation(RotationPolicy::at_bytes(3072));
    for n in 0..count {
        signer.sign_and_emit(&entry(n)).await.unwrap();
    }
    signer
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::write(path, out).unwrap();
}

fn tenant() -> TenantId {
    TenantId("local".to_string())
}

/// The headline: after an accountable prune the chain verifies, and it reports
/// the gap rather than pretending to be whole.
#[tokio::test]
async fn a_pruned_chain_verifies_and_reports_its_gap() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 90).await;
    assert!(dir.path().join("local.seg-000002.jsonl").exists());

    let expected_entries = u64::try_from(
        verify_segment_set(dir.path(), "local", &key().verifying_key())
            .unwrap()
            .segments
            .iter()
            .filter(|segment| segment.seq <= 2 && !segment.active)
            .filter_map(|segment| segment.entries)
            .sum::<usize>(),
    )
    .expect("fixture entry count fits in u64");

    let pruned = signer.prune_through(&tenant(), 2).unwrap();
    assert_eq!(pruned.through, 2);
    assert_eq!(pruned.entries, expected_entries);

    assert!(!dir.path().join("local.seg-000001.jsonl").exists());
    assert!(!dir.path().join("local.seg-000002.jsonl").exists());

    let verified = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect("a pruned chain still verifies");
    assert!(verified.has_gap(), "the gap must be reported, not hidden");
    assert_eq!(verified.pruned.unwrap().through, 2);
}

/// Without the record, the same deletion is still tampering. This is the
/// property the whole feature is balanced against.
#[tokio::test]
async fn the_same_deletion_without_a_record_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    rotated(dir.path(), 90).await;
    std::fs::remove_file(dir.path().join("local.seg-000001.jsonl")).unwrap();

    match verify_segment_set(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::TruncatedFront { missing, .. }) => assert_eq!(missing, 1),
        other => panic!("an unrecorded deletion must still be refused, got {other:?}"),
    }
}

/// The corroboration rule, which is the security argument: a prune record may
/// only claim what the surviving chain independently attests. Editing the
/// record to over-claim must fail even though it is still a signed line in a
/// chain that otherwise links up.
#[tokio::test]
async fn a_prune_record_that_over_claims_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 120).await;
    signer.prune_through(&tenant(), 2).unwrap();

    // Re-point the record at a segment further along than the survivor's
    // handoff corroborates.
    let active = dir.path().join("local.jsonl");
    let mut all = lines(&active);
    let idx = all
        .iter()
        .position(|l| l.contains("chain.pruned"))
        .expect("prune record is in the active segment");
    let mut env: serde_json::Value = serde_json::from_str(&all[idx]).unwrap();
    env["entry"]["labels"][LABEL_PRUNED_THROUGH] = serde_json::Value::String("9".to_string());
    all[idx] = serde_json::to_string(&env).unwrap();
    write_lines(&active, &all);

    assert!(
        verify_segment_set(dir.path(), "local", &key().verifying_key()).is_err(),
        "an over-claiming prune record must not verify"
    );
}

/// Same shape, but the tip is what is edited rather than the range. The tip is
/// the fact the surviving handoff pins, so this is the case that stops a prune
/// record from being used to cover an *edited* segment rather than a removed
/// one.
#[tokio::test]
async fn a_prune_record_naming_a_tip_the_chain_does_not_confirm_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 120).await;
    signer.prune_through(&tenant(), 2).unwrap();

    let active = dir.path().join("local.jsonl");
    let mut all = lines(&active);
    let idx = all.iter().position(|l| l.contains("chain.pruned")).unwrap();
    let mut env: serde_json::Value = serde_json::from_str(&all[idx]).unwrap();
    env["entry"]["labels"][LABEL_PRUNED_TIP] = serde_json::Value::String("A".repeat(43));
    all[idx] = serde_json::to_string(&env).unwrap();
    write_lines(&active, &all);

    match verify_segment_set(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::UncorroboratedPrune { .. } | SegmentSetError::Segment { .. }) => {}
        other => panic!("a prune record with an unconfirmed tip must be refused, got {other:?}"),
    }
}

/// A record forged by someone without the signing key is refused at the
/// signature, like any other forged line — the record is not a special case
/// that bypasses the chain.
#[tokio::test]
async fn a_prune_record_forged_without_the_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 120).await;
    signer.prune_through(&tenant(), 2).unwrap();

    let active = dir.path().join("local.jsonl");
    let all = lines(&active);
    let idx = all.iter().position(|l| l.contains("chain.pruned")).unwrap();
    let mut env: serde_json::Value = serde_json::from_str(&all[idx]).unwrap();
    // Keep the labels honest but break the signature: a record whose content is
    // plausible and whose signature is not.
    env["signature"] = serde_json::Value::String("B".repeat(86));
    let mut tampered = all.clone();
    tampered[idx] = serde_json::to_string(&env).unwrap();
    write_lines(&active, &tampered);

    assert!(
        verify_segment_set(dir.path(), "local", &key().verifying_key()).is_err(),
        "a prune record must be signed like every other line"
    );
}

/// Pruning a chain that does not verify would destroy the evidence of whatever
/// broke it, so it is refused before anything is unlinked.
#[tokio::test]
async fn pruning_a_broken_chain_is_refused_before_anything_is_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 90).await;

    let seg1 = dir.path().join("local.seg-000001.jsonl");
    let mut all = lines(&seg1);
    let mid = all.len() / 2;
    let mut env: serde_json::Value = serde_json::from_str(&all[mid]).unwrap();
    env["entry"]["image_name"] = serde_json::Value::String("tampered".to_string());
    all[mid] = serde_json::to_string(&env).unwrap();
    write_lines(&seg1, &all);

    let err = signer
        .prune_through(&tenant(), 1)
        .expect_err("a broken chain must not be prunable");
    assert!(
        format!("{err}").contains("does not verify"),
        "the refusal must say why: {err}"
    );
    assert!(seg1.exists(), "nothing may be deleted on a refused prune");
}

/// Only a prefix may be pruned. A range that does not start where the surviving
/// history starts would leave two boundaries, and the chain can only
/// corroborate one.
#[tokio::test]
async fn pruning_past_the_end_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 90).await;

    let err = signer
        .prune_through(&tenant(), 9999)
        .expect_err("pruning everything must be refused");
    assert!(
        format!("{err}").contains("no chain behind"),
        "the refusal must explain: {err}"
    );
    assert!(dir.path().join("local.seg-000001.jsonl").exists());
}

/// Pruning twice is normal housekeeping. The second record restates the whole
/// prefix from segment 1, so it supersedes the first — which matters because
/// the first record may itself have been in a segment the second prune removed.
#[tokio::test]
async fn a_second_prune_supersedes_the_first_and_the_chain_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 200).await;

    signer.prune_through(&tenant(), 1).unwrap();
    let first = verify_segment_set(dir.path(), "local", &key().verifying_key()).unwrap();
    assert_eq!(first.pruned.unwrap().through, 1);

    // Rotate further so there is a new sealed segment to remove.
    for n in 1000..1200 {
        signer.sign_and_emit(&entry(n)).await.unwrap();
    }
    let second_target = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .unwrap()
        .segments
        .iter()
        .filter(|s| !s.active)
        .map(|s| s.seq)
        .max()
        .expect("a sealed segment to prune");

    signer.prune_through(&tenant(), second_target).unwrap();
    let after = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect("a twice-pruned chain still verifies");
    assert_eq!(after.pruned.unwrap().through, second_target);
    assert!(after.pruned.unwrap().entries >= first.pruned.unwrap().entries);
}

/// An unpruned chain reports no gap. The negative case matters: if `has_gap`
/// were true by default every caller would learn to ignore it.
#[tokio::test]
async fn an_unpruned_chain_reports_no_gap() {
    let dir = tempfile::tempdir().unwrap();
    rotated(dir.path(), 90).await;
    let verified = verify_segment_set(dir.path(), "local", &key().verifying_key()).unwrap();
    assert!(!verified.has_gap());
    assert!(verified.pruned.is_none());
}

/// The dry-run contract at the library level: a refused prune leaves the files
/// alone. Checked separately from the broken-chain case because this is the
/// ordinary "you asked for something impossible" path, not the alarming one.
#[tokio::test]
async fn a_refused_prune_leaves_every_segment_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let signer = rotated(dir.path(), 90).await;
    let before: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    let _ = signer.prune_through(&tenant(), 0);

    let after: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert_eq!(before.len(), after.len(), "no file may be removed");
}
