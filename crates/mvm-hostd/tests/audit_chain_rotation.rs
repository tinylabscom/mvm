//! Rotation of the chain-signed audit log.
//!
//! The first test here is the reason the rest exist: it demonstrates, against
//! real bytes rather than in a comment, that the obvious way to rotate a
//! chain-signed log destroys the property the log exists for.

use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::supervisor::audit::{AuditSigner, PlanAuditEntry};
use mvm_hostd::supervisor::audit_file::{
    FileAuditSigner, RotationPolicy, VerifyError, verify_audit_chain,
};
use mvm_hostd::supervisor::audit_segment::{
    CHAIN_CONTINUED, CHAIN_SEALED, LABEL_PREV_TIP, continuation_from_entry, sealed_from_entry,
};
use mvm_hostd::supervisor::audit_set::{
    SegmentSetError, verify_segment_set, verify_segment_topology,
};
use std::path::Path;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
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
        caller_commitment: None,
        labels: std::collections::BTreeMap::from([("n".to_string(), n.to_string())]),
    }
}

/// Emit `count` entries into a signer with rotation set to `policy`.
async fn emit(dir: &Path, policy: RotationPolicy, count: usize) {
    let signer = FileAuditSigner::open(key(), dir)
        .unwrap()
        .with_rotation(policy);
    for n in 0..count {
        signer.sign_and_emit(&entry(n)).await.unwrap();
    }
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

/// The failure mode this whole design exists to avoid, demonstrated rather
/// than described.
///
/// "Rotation" done the obvious way — drop the old entries, keep appending to
/// the same file — leaves a file whose every line is genuinely signed and
/// whose every `prev_hash` genuinely matches its neighbour. It still must not
/// verify, because verification seeds from 32 zero bytes and line 0 no longer
/// claims them. If this ever passes, the genesis anchor has been thrown away
/// and history can be edited by calling the edit a rotation.
#[tokio::test]
async fn naively_dropping_old_entries_fails_verification_at_line_zero() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::never(), 20).await;
    let path = dir.path().join("local.jsonl");

    let all = lines(&path);
    assert_eq!(
        verify_audit_chain(&path, &key().verifying_key()).unwrap(),
        20
    );

    // Keep the newest ten. Every surviving line is untouched and correctly
    // signed; only the front is gone.
    write_lines(&path, &all[10..]);

    match verify_audit_chain(&path, &key().verifying_key()) {
        Err(VerifyError::PrevHashMismatch { line: 0 }) => {}
        other => panic!("front-truncation must fail at line 0, got {other:?}"),
    }
}

/// And the same truncation with a *hand-written* claim that it continues
/// something. Without the signed body naming the identical hash, adopting the
/// claimed predecessor would let anyone restart a chain wherever they liked.
#[tokio::test]
async fn an_unsigned_claim_to_continue_is_not_a_handoff() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::never(), 20).await;
    let path = dir.path().join("local.jsonl");
    let all = lines(&path);

    // Line 10 already claims line 9's hash in its envelope. Presenting it as
    // line 0 is exactly the splice a naive verifier would accept.
    write_lines(&path, &all[10..]);
    match verify_audit_chain(&path, &key().verifying_key()) {
        Err(VerifyError::PrevHashMismatch { line: 0 }) => {}
        other => panic!("an ordinary entry must not seed a chain, got {other:?}"),
    }
}

/// The whole point: a rotated chain verifies, per segment and across the set.
#[tokio::test]
async fn a_rotated_chain_verifies_per_segment_and_across_the_set() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;

    let seg1 = dir.path().join("local.seg-000001.jsonl");
    assert!(
        seg1.exists(),
        "rotation must have produced a sealed segment"
    );

    let vk = key().verifying_key();
    // Each segment verifies on its own — the continuing ones through their
    // authenticated handoff, not by claiming genesis.
    let reports = verify_segment_set(dir.path(), "local", &vk)
        .unwrap()
        .segments;
    assert!(
        reports.len() >= 2,
        "expected several segments, got {reports:?}"
    );
    assert!(reports[0].seq == 1 && !reports[0].active);
    assert!(reports.last().unwrap().active);

    // Every emitted entry is still present exactly once across the set, plus
    // one sealing and one continuation record per boundary.
    let boundaries = reports.len() - 1;
    let total: usize = reports.iter().map(|r| r.entries.unwrap()).sum();
    assert_eq!(total, 60 + 2 * boundaries);
}

/// A sealed segment ends with its sealing record and the next opens with the
/// matching continuation. Checked structurally so the two cannot drift.
#[tokio::test]
async fn each_boundary_is_a_sealing_record_and_a_matching_continuation() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 40).await;

    let seg1 = dir.path().join("local.seg-000001.jsonl");
    let seg1_lines = lines(&seg1);
    let last: mvm_hostd::supervisor::SignedEnvelope =
        serde_json::from_str(seg1_lines.last().unwrap()).unwrap();
    let sealed = sealed_from_entry(&last.entry).expect("segment 1 must end sealed");
    assert_eq!(sealed.segment, 1);
    assert_eq!(sealed.next_segment, 2);
    assert_eq!(sealed.entries as usize, seg1_lines.len());

    let next = dir.path().join("local.seg-000002.jsonl");
    let next = if next.exists() {
        next
    } else {
        dir.path().join("local.jsonl")
    };
    let first: mvm_hostd::supervisor::SignedEnvelope =
        serde_json::from_str(&lines(&next)[0]).unwrap();
    let cont = continuation_from_entry(&first.entry).expect("segment 2 must open continuing");
    assert_eq!(cont.prev_segment, 1);
    assert_eq!(cont.prev_entries, sealed.entries);
    assert_eq!(first.entry.event, CHAIN_CONTINUED);
    assert_eq!(last.entry.event, CHAIN_SEALED);
}

/// Deleting a whole segment is the case rotation makes easy and that the set
/// check exists to catch. It must be *named*, not silently skipped: the point
/// is that an operator learns which history is gone.
#[tokio::test]
async fn a_missing_segment_is_named_not_silently_skipped() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(3072), 90).await;
    let seg2 = dir.path().join("local.seg-000002.jsonl");
    assert!(seg2.exists(), "test needs at least three segments");
    std::fs::remove_file(&seg2).unwrap();

    match verify_segment_set(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::MissingSegment { seq, missing }) => {
            assert_eq!(missing, 2, "must name the segment that is gone");
            assert_eq!(seq, 3, "must name the survivor that points at it");
        }
        other => panic!("a deleted segment must be named, got {other:?}"),
    }
}

/// Deleting the *oldest* segments is the same class of removal and must also
/// be caught: the survivor is honest that it is not the beginning.
#[tokio::test]
async fn deleting_the_earliest_segments_is_caught_at_the_front() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(3072), 90).await;
    std::fs::remove_file(dir.path().join("local.seg-000001.jsonl")).unwrap();

    match verify_segment_set(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::TruncatedFront { seq, missing }) => {
            assert_eq!(seq, 2);
            assert_eq!(missing, 1);
        }
        other => panic!("a removed front must be caught, got {other:?}"),
    }
}

/// Re-ordering segments, or presenting one behind a predecessor it never
/// continued, must fail. This is the property that keeps rotation from being a
/// licence to rearrange history.
#[tokio::test]
async fn a_spliced_segment_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(3072), 90).await;

    // Swap segment 1's contents for segment 2's, keeping both filenames. Both
    // files remain internally valid and correctly signed; only their order
    // relative to one another is a lie.
    let s1 = dir.path().join("local.seg-000001.jsonl");
    let s2 = dir.path().join("local.seg-000002.jsonl");
    let (a, b) = (lines(&s1), lines(&s2));
    write_lines(&s1, &b);
    write_lines(&s2, &a);

    let err = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect_err("a reordered set must not verify");
    assert!(
        matches!(
            err,
            SegmentSetError::TruncatedFront { .. }
                | SegmentSetError::Spliced { .. }
                | SegmentSetError::MissingSegment { .. }
                | SegmentSetError::Unsealed { .. }
        ),
        "unexpected failure for a spliced set: {err:?}"
    );
}

/// Editing the handoff itself — repointing a segment at a different
/// predecessor hash — must not survive, even though it is a one-field change
/// to a file that is otherwise untouched.
#[tokio::test]
async fn an_edited_handoff_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;

    let seg2 = dir.path().join("local.seg-000002.jsonl");
    let target = if seg2.exists() {
        seg2
    } else {
        dir.path().join("local.jsonl")
    };
    let mut all = lines(&target);
    let mut env: serde_json::Value = serde_json::from_str(&all[0]).unwrap();
    env["entry"]["labels"][LABEL_PREV_TIP] = serde_json::Value::String("A".repeat(43));
    all[0] = serde_json::to_string(&env).unwrap();
    write_lines(&target, &all);

    assert!(
        verify_segment_set(dir.path(), "local", &key().verifying_key()).is_err(),
        "an edited handoff must not verify"
    );
}

/// A continuation record is only a chain seed on line 0. Anywhere else it is
/// an ordinary entry, or it would splice a restart into a segment's middle and
/// orphan everything before it.
#[tokio::test]
async fn a_continuation_record_mid_segment_does_not_reseed_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    let seg1 = dir.path().join("local.seg-000001.jsonl");
    let seg2 = dir.path().join("local.seg-000002.jsonl");
    let target = if seg2.exists() {
        seg2
    } else {
        dir.path().join("local.jsonl")
    };

    // Take the genuine, correctly signed continuation line and drop it into
    // the middle of the previous segment.
    let handoff = lines(&target)[0].clone();
    let mut all = lines(&seg1);
    let cut = all.len() / 2;
    all.truncate(cut);
    all.push(handoff);
    write_lines(&seg1, &all);

    match verify_audit_chain(&seg1, &key().verifying_key()) {
        Err(VerifyError::PrevHashMismatch { line }) => assert_eq!(line, cut),
        other => panic!("a mid-file handoff must not reseed, got {other:?}"),
    }
}

/// A crash between the rename and the first write to the fresh file leaves a
/// sealed segment and no active one. Recovery must continue history. Starting
/// a new genesis chain instead would orphan every sealed segment behind it,
/// and — because each orphan still verifies on its own — nothing would ever
/// report it.
#[tokio::test]
async fn an_interrupted_rotation_continues_history_instead_of_restarting_it() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    let active = dir.path().join("local.jsonl");

    // Simulate the crash: the active file never got its continuation record.
    std::fs::remove_file(&active).unwrap();

    emit(dir.path(), RotationPolicy::never(), 5).await;

    let first: mvm_hostd::supervisor::SignedEnvelope =
        serde_json::from_str(&lines(&active)[0]).unwrap();
    let cont = continuation_from_entry(&first.entry)
        .expect("recovery must open with a handoff, not a genesis line");
    assert!(cont.prev_segment >= 1);
    verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect("a recovered chain must verify across the set");
}

/// Two writers appending concurrently across a rotation must produce one
/// coherent set — not two segments both numbered the same, and not a lost
/// entry. The rotation happens under the same lock as the append precisely so
/// this holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_rotate_exactly_once_per_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let a = std::sync::Arc::new(
        FileAuditSigner::open(key(), dir.path())
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(4096)),
    );
    let b = std::sync::Arc::new(
        FileAuditSigner::open(key(), dir.path())
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(4096)),
    );

    const N: usize = 40;
    let ta = {
        let a = a.clone();
        tokio::spawn(async move {
            for n in 0..N {
                a.sign_and_emit(&entry(n)).await.unwrap();
            }
        })
    };
    let tb = {
        let b = b.clone();
        tokio::spawn(async move {
            for n in 0..N {
                b.sign_and_emit(&entry(1000 + n)).await.unwrap();
            }
        })
    };
    ta.await.unwrap();
    tb.await.unwrap();

    let reports = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect("concurrent writers must leave a verifiable set")
        .segments;
    let boundaries = reports.len() - 1;
    let total: usize = reports.iter().map(|r| r.entries.unwrap()).sum();
    assert_eq!(
        total,
        2 * N + 2 * boundaries,
        "no entry may be lost across a concurrent rotation"
    );
    let mut seqs: Vec<u64> = reports.iter().map(|r| r.seq).collect();
    seqs.dedup();
    assert_eq!(seqs.len(), reports.len(), "no duplicate segment numbers");
}

/// The topology check is cheaper because it walks no interior at all — only
/// the boundary lines — and it has to be honest about that. Every report comes
/// back with no entry count, so a caller cannot present an interior it never
/// read as verified. Doctor pairs this with its own incremental walk of the
/// live segment and reports the two separately.
#[tokio::test]
async fn the_topology_check_reports_no_count_for_interiors_it_did_not_walk() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    let vk = key().verifying_key();

    let reports = verify_segment_topology(dir.path(), "local", &vk)
        .unwrap()
        .segments;
    assert!(reports.len() >= 2);
    for r in &reports {
        assert!(
            r.entries.is_none(),
            "topology walks no interior, including the live one"
        );
    }

    // And the full walk does report every count.
    for r in verify_segment_set(dir.path(), "local", &vk)
        .unwrap()
        .segments
    {
        assert!(r.entries.is_some());
    }
}

/// The honest limit of the cheap check, pinned so nobody upgrades the claim by
/// accident: an edit *inside* a sealed segment survives the topology check and
/// is caught by the full walk. The boundary lines and the entry count are
/// still checked, so the edit cannot add or remove a line — only alter one.
#[tokio::test]
async fn an_edited_sealed_interior_passes_topology_and_fails_the_full_walk() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    let vk = key().verifying_key();
    let seg1 = dir.path().join("local.seg-000001.jsonl");

    let mut all = lines(&seg1);
    let mid = all.len() / 2;
    let mut env: serde_json::Value = serde_json::from_str(&all[mid]).unwrap();
    env["entry"]["image_name"] = serde_json::Value::String("tampered".to_string());
    all[mid] = serde_json::to_string(&env).unwrap();
    write_lines(&seg1, &all);

    verify_segment_topology(dir.path(), "local", &vk)
        .expect("topology does not read sealed interiors, so this edit is invisible to it");
    verify_segment_set(dir.path(), "local", &vk)
        .expect_err("the full walk must catch an edited interior");
}

/// Removing a line from a sealed segment changes its length, and the sealing
/// record says how long it was. Caught even by the cheap check.
#[tokio::test]
async fn deleting_a_line_from_a_sealed_segment_is_caught_by_the_entry_count() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    let seg1 = dir.path().join("local.seg-000001.jsonl");
    let mut all = lines(&seg1);
    all.remove(all.len() / 2);
    write_lines(&seg1, &all);

    match verify_segment_topology(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::EntryCountMismatch { .. }) => {}
        other => panic!("a shortened sealed segment must be caught, got {other:?}"),
    }
}

/// Rotation off means one file and no segments — the behaviour every existing
/// caller had before this landed.
#[tokio::test]
async fn rotation_disabled_leaves_a_single_genesis_chain() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::never(), 200).await;
    assert_eq!(
        verify_audit_chain(&dir.path().join("local.jsonl"), &key().verifying_key()).unwrap(),
        200
    );
    assert!(!dir.path().join("local.seg-000001.jsonl").exists());
}

/// An empty chain file is a chain nothing has been written to — a clean state
/// that predates rotation and must keep verifying as zero entries. Reporting
/// it as a break would light up doctor on any host with a touched-but-unused
/// tenant file.
#[test]
fn an_empty_chain_verifies_as_zero_entries_not_as_a_break() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("local.jsonl"), "").unwrap();
    let reports = verify_segment_set(dir.path(), "local", &key().verifying_key())
        .expect("an untouched chain is not a broken one")
        .segments;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].entries, Some(0));
}

/// An empty *sealed* segment is a different matter: a retired segment always
/// carries at least its own sealing record, so emptiness means it was emptied
/// after it was sealed.
#[tokio::test]
async fn an_emptied_sealed_segment_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    std::fs::write(dir.path().join("local.seg-000001.jsonl"), "").unwrap();
    match verify_segment_set(dir.path(), "local", &key().verifying_key()) {
        Err(SegmentSetError::Unsealed { seq, .. }) => assert_eq!(seq, 1),
        other => panic!("an emptied sealed segment must be refused, got {other:?}"),
    }
}

/// Retired segments have to stay in sweep scope, and the lock file has to stay
/// out of it. Both are naming decisions that a sweep silently depends on.
#[tokio::test]
async fn segment_and_lock_filenames_land_on_the_right_side_of_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    emit(dir.path(), RotationPolicy::at_bytes(4096), 60).await;
    assert!(mvm_core::config::is_host_lifecycle_chain(
        &dir.path().join("local.seg-000001.jsonl")
    ));
    let lock = dir.path().join("local.jsonl.lock");
    assert!(
        lock.exists(),
        "the chain lock must be a real file beside the chain"
    );
    assert!(!mvm_core::config::is_host_lifecycle_chain(&lock));
}

/// The threshold is configurable through the environment, and an unparseable
/// value falls back to the default rather than silently disabling rotation.
#[test]
fn the_rotation_threshold_reads_the_environment() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "8192");
    assert_eq!(mvm_core::config::audit_segment_max_bytes(), Some(8192));

    env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "0");
    assert_eq!(mvm_core::config::audit_segment_max_bytes(), None);

    env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "not-a-number");
    assert_eq!(
        mvm_core::config::audit_segment_max_bytes(),
        Some(mvm_core::config::AUDIT_SEGMENT_DEFAULT_BYTES),
        "a typo must not reinstate unbounded growth"
    );

    env.remove(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV);
    assert_eq!(
        mvm_core::config::audit_segment_max_bytes(),
        Some(mvm_core::config::AUDIT_SEGMENT_DEFAULT_BYTES)
    );
}
