//! Behaviour of the host-signed verification head.
//!
//! A head lets a consumer resume chain verification from where a previous load
//! stopped, carrying the state it folded out of the verified prefix. These tests
//! pin both halves of that bargain: a resumed load does work proportional to
//! what was appended, not to the chain; and no head is ever believed over the
//! chain — a head that does not verify, or does not fit, is dropped and the
//! chain is walked from genesis.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::supervisor::audit_head::{self, ChainPosition, Resumed, VerifiedHead};
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry, VerifyError};

/// Plenty of entries to make a from-genesis walk visibly more work than a
/// resumed one, while staying cheap to write under a debug build.
const CHAIN_LEN: usize = 300;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
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

/// An isolated mvm home, so the head cache never touches a real one.
struct World {
    _env: TestEnv,
    home: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        Self { _env: env, home }
    }

    fn audit_dir(&self) -> PathBuf {
        self.home.path().join("audit")
    }

    fn chain(&self) -> PathBuf {
        self.audit_dir().join("local.jsonl")
    }
}

/// Append `n` signed entries numbered from `from` to the chain in `dir`.
async fn append(dir: &Path, from: usize, n: usize) {
    std::fs::create_dir_all(dir).expect("audit dir");
    let signer = FileAuditSigner::open(signing_key(), dir).expect("signer");
    for seq in from..from + n {
        signer.sign_and_emit(&entry(seq)).await.expect("emit");
    }
}

/// The consumer state under test: every plan id seen, in order. A fold that
/// double-counted or skipped an entry shows up as a wrong list.
type Seen = Vec<String>;

fn fold(seen: &mut Seen, entry: &PlanAuditEntry) {
    seen.push(entry.plan_id.0.clone());
}

fn expected(n: usize) -> Seen {
    (0..n).map(|seq| format!("plan-{seq}")).collect()
}

/// One load as the anchor does it: load the head, verify resuming, store the
/// head when the pass advanced.
fn load(chain: &Path, key: &SigningKey) -> Result<Resumed<Seen>, VerifyError> {
    let verifying = key.verifying_key();
    let head = audit_head::load::<Seen>(chain, &verifying);
    let out = audit_head::verify_resuming(chain, &verifying, head, Seen::new, fold)?;
    if out.advanced()
        && let Some(position) = &out.position
    {
        audit_head::store(chain, position, &out.state, key);
    }
    Ok(out)
}

fn stored_head(chain: &Path, verifying: &VerifyingKey) -> Option<VerifiedHead<Seen>> {
    audit_head::load::<Seen>(chain, verifying)
}

#[tokio::test]
async fn the_first_load_walks_from_genesis_and_signs_a_head() {
    let w = World::new();
    append(&w.audit_dir(), 0, 5).await;

    let out = load(&w.chain(), &signing_key()).expect("verify");
    assert!(!out.resumed);
    assert_eq!(out.verified_now, 5);
    assert_eq!(out.state, expected(5));

    let head = stored_head(&w.chain(), &signing_key().verifying_key()).expect("head stored");
    assert_eq!(head.position.verified_lines, 5);
    assert_eq!(
        head.position.verified_bytes,
        std::fs::metadata(w.chain()).unwrap().len()
    );
    assert_eq!(head.state, expected(5));
}

/// The regression witness: a resumed load of an unchanged chain verifies no
/// entry, however long the chain is. The work is in the appended tail, so an
/// unchanged chain costs the head file, one boundary line and a stat.
#[tokio::test]
async fn an_unchanged_chain_is_resumed_with_no_entry_verified() {
    let w = World::new();
    append(&w.audit_dir(), 0, CHAIN_LEN).await;

    let first = load(&w.chain(), &signing_key()).expect("first");
    assert_eq!(first.verified_now, CHAIN_LEN);

    let second = load(&w.chain(), &signing_key()).expect("second");
    assert!(second.resumed, "the stored head fits an unchanged chain");
    assert_eq!(
        second.verified_now, 0,
        "nothing was appended, so nothing is re-verified"
    );
    assert!(!second.advanced(), "an unchanged chain needs no new head");
    assert_eq!(
        second.state,
        expected(CHAIN_LEN),
        "the head carries the state"
    );
}

#[tokio::test]
async fn appending_verifies_only_the_appended_entries() {
    let w = World::new();
    append(&w.audit_dir(), 0, CHAIN_LEN).await;
    load(&w.chain(), &signing_key()).expect("first");

    append(&w.audit_dir(), CHAIN_LEN, 3).await;
    let out = load(&w.chain(), &signing_key()).expect("second");

    assert!(out.resumed);
    assert_eq!(out.verified_now, 3, "only the tail is verified");
    assert!(out.advanced());
    assert_eq!(
        out.state,
        expected(CHAIN_LEN + 3),
        "every entry is folded exactly once across the two loads"
    );

    // The new head stands at the new end, so a third load is again free.
    let third = load(&w.chain(), &signing_key()).expect("third");
    assert_eq!(third.verified_now, 0);
    assert_eq!(third.state, expected(CHAIN_LEN + 3));
}

#[tokio::test]
async fn a_head_signed_by_another_key_is_not_served() {
    let w = World::new();
    append(&w.audit_dir(), 0, 4).await;
    let out = load(&w.chain(), &signing_key()).expect("first");
    let position = out.position.expect("position");

    // Someone with write access to the cache but not the host key plants a
    // head claiming the chain recorded something it did not.
    let forged_state: Seen = vec!["plan-forged".to_string()];
    audit_head::store(
        &w.chain(),
        &position,
        &forged_state,
        &SigningKey::from_bytes(&[99u8; 32]),
    );

    assert!(
        stored_head(&w.chain(), &signing_key().verifying_key()).is_none(),
        "a head not signed by the host key is not a head"
    );
    let again = load(&w.chain(), &signing_key()).expect("reload");
    assert!(!again.resumed, "no usable head: walk from genesis");
    assert_eq!(again.state, expected(4), "the forged state is never served");
}

#[tokio::test]
async fn a_head_whose_body_was_edited_after_signing_is_not_served() {
    let w = World::new();
    append(&w.audit_dir(), 0, 4).await;
    load(&w.chain(), &signing_key()).expect("first");

    let head_path = audit_head::head_path(&w.chain());
    let raw = std::fs::read_to_string(&head_path).unwrap();
    assert!(raw.contains("plan-3"), "fixture carries the folded state");
    std::fs::write(&head_path, raw.replace("plan-3", "plan-X")).unwrap();

    assert!(
        stored_head(&w.chain(), &signing_key().verifying_key()).is_none(),
        "the signature no longer covers the body"
    );
    let again = load(&w.chain(), &signing_key()).expect("reload");
    assert!(!again.resumed);
    assert_eq!(again.state, expected(4));
}

#[tokio::test]
async fn a_head_describes_one_chain_and_cannot_be_moved_to_another() {
    let w = World::new();
    append(&w.audit_dir(), 0, 4).await;
    load(&w.chain(), &signing_key()).expect("first");

    // A second chain with identical bytes, filed under another tenant.
    let other = w.audit_dir().join("other.jsonl");
    std::fs::copy(w.chain(), &other).unwrap();
    std::fs::create_dir_all(audit_head::head_path(&other).parent().unwrap()).unwrap();
    std::fs::copy(
        audit_head::head_path(&w.chain()),
        audit_head::head_path(&other),
    )
    .unwrap();

    assert!(
        stored_head(&other, &signing_key().verifying_key()).is_none(),
        "the signed body names the chain it describes"
    );
    let out = load(&other, &signing_key()).expect("verify other");
    assert!(!out.resumed, "the other chain is walked from genesis");
    assert_eq!(out.state, expected(4));
}

#[tokio::test]
async fn an_edited_boundary_line_drops_the_head_and_reports_the_damage() {
    let w = World::new();
    append(&w.audit_dir(), 0, 4).await;
    load(&w.chain(), &signing_key()).expect("first");

    // Edit the last verified line in place, keeping its length.
    let content = std::fs::read_to_string(w.chain()).unwrap();
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    lines[3] = lines[3].replace("plan-3", "plan-Z");
    std::fs::write(w.chain(), format!("{}\n", lines.join("\n"))).unwrap();

    let err = load(&w.chain(), &signing_key()).expect_err("the chain is damaged");
    assert!(
        matches!(
            err,
            VerifyError::SignatureInvalid { line: 3 }
                | VerifyError::EntryCanonicalMismatch { line: 3 }
        ),
        "the genesis walk names the edited line: {err}"
    );
}

#[tokio::test]
async fn a_forged_tail_is_refused_rather_than_served_from_the_head() {
    let w = World::new();
    append(&w.audit_dir(), 0, 4).await;
    let first = load(&w.chain(), &signing_key()).expect("first");

    // Append a line that is not a signed envelope at all.
    let mut content = std::fs::read_to_string(w.chain()).unwrap();
    content.push_str("{\"event\":\"plan.admitted\",\"forged\":true}\n");
    std::fs::write(w.chain(), content).unwrap();

    let err = load(&w.chain(), &signing_key()).expect_err("the tail does not verify");
    assert!(
        matches!(err, VerifyError::Malformed { line: 4, .. }),
        "the genesis walk reports the forged line: {err}"
    );
    // The stored head is untouched by the refusal: a damaged chain does not
    // get a fresh head signed over it.
    let head = stored_head(&w.chain(), &signing_key().verifying_key()).expect("head kept");
    assert_eq!(Some(head.position), first.position);
}

#[tokio::test]
async fn a_chain_shorter_than_its_head_is_walked_from_genesis() {
    let w = World::new();
    append(&w.audit_dir(), 0, 6).await;
    load(&w.chain(), &signing_key()).expect("first");

    // What rotation leaves behind: a fresh, shorter file under the same name.
    std::fs::remove_file(w.chain()).unwrap();
    append(&w.audit_dir(), 0, 2).await;

    let out = load(&w.chain(), &signing_key()).expect("verify the new chain");
    assert!(!out.resumed, "a head past the end of the file does not fit");
    assert_eq!(out.state, expected(2));
    assert_eq!(out.verified_now, 2);
}

#[tokio::test]
async fn a_truncated_final_record_is_reported_not_resumed_past() {
    let w = World::new();
    append(&w.audit_dir(), 0, 3).await;
    load(&w.chain(), &signing_key()).expect("first");

    let mut content = std::fs::read(w.chain()).unwrap();
    content.extend_from_slice(b"{\"entry\":");
    std::fs::write(w.chain(), content).unwrap();

    let err = load(&w.chain(), &signing_key()).expect_err("half a record is not a record");
    assert!(matches!(err, VerifyError::TruncatedTail { .. }), "{err}");
}

#[tokio::test]
async fn an_empty_chain_has_no_head_to_sign() {
    let w = World::new();
    std::fs::create_dir_all(w.audit_dir()).unwrap();
    std::fs::write(w.chain(), "").unwrap();

    let out = load(&w.chain(), &signing_key()).expect("an empty chain verifies");
    assert_eq!(out.position, None);
    assert!(out.state.is_empty());
    assert!(
        stored_head(&w.chain(), &signing_key().verifying_key()).is_none(),
        "nothing was verified, so nothing is signed"
    );
}

#[tokio::test]
async fn a_head_with_an_undecodable_hash_is_ignored() {
    let w = World::new();
    append(&w.audit_dir(), 0, 3).await;
    let out = load(&w.chain(), &signing_key()).expect("first");
    let mut position = out.position.expect("position");
    position.chain_hash = "not-base64!".to_string();
    let head = Some(VerifiedHead {
        position,
        state: vec!["plan-bogus".to_string()],
    });

    let verifying = signing_key().verifying_key();
    let again =
        audit_head::verify_resuming(&w.chain(), &verifying, head, Seen::new, fold).expect("verify");
    assert!(!again.resumed);
    assert_eq!(again.state, expected(3));
}

/// Pins the on-disk layout the anchor relies on: positions are byte-exact, so
/// a resumed load can seek rather than count lines.
#[tokio::test]
async fn positions_are_byte_exact() {
    let w = World::new();
    append(&w.audit_dir(), 0, 3).await;
    let out = load(&w.chain(), &signing_key()).expect("first");
    let ChainPosition {
        verified_lines,
        verified_bytes,
        last_line_offset,
        ..
    } = out.position.expect("position");

    let content = std::fs::read(w.chain()).unwrap();
    assert_eq!(verified_lines, 3);
    assert_eq!(verified_bytes, content.len() as u64);
    let last_line_start = content[..content.len() - 1]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    assert_eq!(last_line_offset, last_line_start as u64);
}
