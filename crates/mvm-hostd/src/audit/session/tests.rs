use super::*;
use crate::audit::emitter::{AuditEmitter, audit_path_for_tenant};
use crate::supervisor::audit::for_plan;
use ed25519_dalek::SigningKey;
use mvm_core::plan::ExecutionPlan;
use mvm_core::plan::test_support::PlanFixture;

const TENANT: &str = "local";

pub(super) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn plan(id: &str) -> ExecutionPlan {
    PlanFixture::new().tenant(TENANT).plan_id(id).build()
}

pub(super) fn request(plan_id: &str, reason: SealReason) -> SealRequest<'_> {
    SealRequest {
        plan_id,
        reason,
        compute_environment: None,
        snapshot_root: None,
    }
}

pub(super) struct Chain {
    dir: tempfile::TempDir,
    pub(super) emitter: AuditEmitter,
    key: SigningKey,
}

impl Chain {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key(7);
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).expect("emitter");
        Self { dir, emitter, key }
    }

    pub(super) fn vk(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Admit, launch and exit one run, then seal it.
    pub(super) fn run_and_seal(&self, plan: &ExecutionPlan, exit_code: i32) -> SessionSeal {
        self.emitter.emit_admitted(plan, "host:test").unwrap();
        self.emitter.emit_launched(plan, "mock").unwrap();
        self.emitter.emit_exited(plan, exit_code, "mock").unwrap();
        self.emitter
            .seal_session(plan, SealReason::Exited)
            .expect("seal")
    }

    /// Append a seal entry exactly as the host would sign it, but carrying
    /// whatever `seal` says.
    pub(super) fn append_seal(&self, plan: &ExecutionPlan, labels: Vec<(String, String)>) {
        self.emitter
            .emit_entry_for_evidence(
                &for_plan(plan, None, SESSION_SEALED_EVENT, labels),
                crate::audit::evidence::EvidenceReceipt::Omitted,
            )
            .unwrap();
    }

    pub(super) fn path(&self) -> std::path::PathBuf {
        audit_path_for_tenant(self.dir.path(), TENANT)
    }

    pub(super) fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.path())
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub(super) fn write_lines(&self, lines: &[String]) {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(self.path(), body).unwrap();
    }

    pub(super) fn verify(&self, plan_id: &str) -> SessionVerification {
        verify_session(self.dir.path(), TENANT, plan_id, &self.vk())
    }

    pub(super) fn line_index(&self, plan_id: &str, event: &str) -> usize {
        self.lines()
            .iter()
            .position(|line| {
                let env: SignedEnvelope = serde_json::from_str(line).unwrap();
                env.entry.plan_id == plan_id && env.entry.event == event
            })
            .expect("event present")
    }
}

#[test]
fn a_sealed_session_verifies_and_the_seal_describes_it() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    let seal = chain.run_and_seal(&p, 0);

    assert_eq!(seal.reason, SealReason::Exited);
    assert_eq!(seal.exit_code.as_deref(), Some("0"));
    assert!(
        seal.event_count >= 3,
        "admitted, launched and exited at least"
    );
    assert_eq!(seal.prev_seal, GENESIS_SEAL);

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.verdict, Verdict::Verified, "{report:?}");
    assert_eq!(report.event_count, seal.event_count);
    assert_eq!(report.seals.len(), 1);
    assert_eq!(report.seals[0].seal, seal);
    assert_eq!(report.late_entries, 0);
}

/// The durability policy for the records that bound a session and a segment.
/// Each is a completeness claim — "this session had N entries", "this segment
/// ended here" — and a claim that can be lost in a crash while the entries it
/// describes survive would read, afterwards, as a truncation it never was.
#[test]
fn session_and_segment_boundaries_are_sync_barriers() {
    use crate::supervisor::audit_file::{SyncPolicy, sync_policy_for};
    use crate::supervisor::audit_segment::{CHAIN_CONTINUED, CHAIN_PRUNED, CHAIN_SEALED};
    for event in [
        SESSION_SEALED_EVENT,
        "plan.exited",
        CHAIN_SEALED,
        CHAIN_CONTINUED,
        CHAIN_PRUNED,
    ] {
        assert_eq!(
            sync_policy_for(event),
            SyncPolicy::Barrier,
            "{event} must be on disk before the call that wrote it returns"
        );
    }
}

#[test]
fn seals_form_a_hash_chained_ledger() {
    let chain = Chain::new();
    let first = chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    let second = chain.run_and_seal(&plan("sha256:bbbb2222"), 3);
    let seal_line = &chain.lines()[chain.line_index("sha256:aaaa1111", SESSION_SEALED_EVENT)];

    assert_eq!(first.prev_seal, GENESIS_SEAL);
    assert_eq!(second.prev_seal, hex(&hash_line(seal_line.as_bytes())));

    let (sessions, ledger) = list_sessions(&chain.lines(), TimeRange::default()).unwrap();
    assert!(ledger.intact, "{ledger:?}");
    assert_eq!(ledger.seals, 2);
    assert_eq!(
        sessions
            .iter()
            .map(|s| s.plan_id.as_str())
            .collect::<Vec<_>>(),
        ["sha256:aaaa1111", "sha256:bbbb2222"]
    );
    assert!(sessions.iter().all(|s| s.sealed));
    assert_eq!(
        sessions[1].seal.as_ref().unwrap().exit_code.as_deref(),
        Some("3")
    );
}

#[test]
fn interleaved_sessions_each_seal_only_their_own_entries() {
    let chain = Chain::new();
    let a = plan("sha256:aaaa1111");
    let b = plan("sha256:bbbb2222");
    chain.emitter.emit_admitted(&a, "host:test").unwrap();
    chain.emitter.emit_admitted(&b, "host:test").unwrap();
    chain.emitter.emit_launched(&a, "mock").unwrap();
    chain
        .emitter
        .emit_failed(&b, "backend-start", "boom")
        .unwrap();
    let b_seal = chain.emitter.seal_session(&b, SealReason::Failed).unwrap();
    chain.emitter.emit_exited(&a, 0, "mock").unwrap();
    chain.emitter.seal_session(&a, SealReason::Exited).unwrap();

    assert_eq!(b_seal.error_class.as_deref(), Some("backend-start"));
    for id in [&a.plan_id.0, &b.plan_id.0] {
        assert_eq!(chain.verify(id).verdict, Verdict::Verified, "{id}");
    }
}

#[test]
fn an_edited_event_is_a_signature_mismatch() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let mut lines = chain.lines();
    let i = chain.line_index(&p.plan_id.0, "plan.exited");
    let edited = lines[i].replace("\"exit_code\":\"0\"", "\"exit_code\":\"1\"");
    assert_ne!(
        edited, lines[i],
        "the edit must land for this test to mean anything"
    );
    lines[i] = edited;
    chain.write_lines(&lines);

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.verdict, Verdict::Mismatch);
    assert_eq!(report.reason, Some(MismatchReason::Signature), "{report:?}");
}

#[test]
fn a_removed_event_is_a_chain_break() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let mut lines = chain.lines();
    lines.remove(chain.line_index(&p.plan_id.0, "plan.launched"));
    chain.write_lines(&lines);

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.verdict, Verdict::Mismatch);
    assert_eq!(
        report.reason,
        Some(MismatchReason::ChainBreak),
        "{report:?}"
    );
    assert_eq!(report.verdict.exit_code(), 1);
}

#[test]
fn reordered_events_are_a_chain_break() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let mut lines = chain.lines();
    let launched = chain.line_index(&p.plan_id.0, "plan.launched");
    let exited = chain.line_index(&p.plan_id.0, "plan.exited");
    lines.swap(launched, exited);
    chain.write_lines(&lines);

    assert_eq!(
        chain.verify(&p.plan_id.0).reason,
        Some(MismatchReason::ChainBreak)
    );
}

#[test]
fn a_seal_signed_by_another_key_is_a_signature_mismatch() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    let seal = chain.run_and_seal(&p, 0);
    let forged = for_plan(&p, None, SESSION_SEALED_EVENT, seal.to_labels());
    let mut lines = chain.lines();
    let prev = hash_line(lines.last().unwrap().as_bytes());
    let envelope = mvm_contract::verify::seal(&forged, prev, &key(9)).expect("sign");
    lines.push(serde_json::to_string(&envelope).unwrap());
    chain.write_lines(&lines);

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.reason, Some(MismatchReason::Signature), "{report:?}");
}

#[test]
fn a_seal_missing_a_field_is_a_malformed_seal() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.emitter.emit_admitted(&p, "host:test").unwrap();
    chain.append_seal(&p, vec![("seal.event_count".to_string(), "1".to_string())]);
    assert_eq!(
        chain.verify(&p.plan_id.0).reason,
        Some(MismatchReason::MalformedSeal)
    );
}

#[test]
fn truncating_after_the_seal_keeps_the_session_verified() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let later = plan("sha256:bbbb2222");
    chain.emitter.emit_admitted(&later, "host:test").unwrap();
    let mut lines = chain.lines();
    lines.pop();
    chain.write_lines(&lines);

    assert_eq!(chain.verify(&p.plan_id.0).verdict, Verdict::Verified);
}

#[test]
fn a_record_cut_mid_line_is_reported_as_a_truncated_tail() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let body = std::fs::read_to_string(chain.path()).unwrap();
    std::fs::write(chain.path(), &body[..body.len() - 20]).unwrap();

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.verdict, Verdict::Mismatch);
    assert!(
        matches!(
            report.reason,
            Some(MismatchReason::TruncatedTail | MismatchReason::Malformed)
        ),
        "{report:?}"
    );
}

#[test]
fn entries_after_the_seal_are_reported_but_not_a_mismatch() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    chain.emitter.emit_verb_denied(&p, "exec").unwrap();

    let report = chain.verify(&p.plan_id.0);
    assert_eq!(report.verdict, Verdict::Verified);
    assert_eq!(report.late_entries, 1);
}

#[test]
fn an_unknown_session_is_not_found() {
    let chain = Chain::new();
    chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    let report = chain.verify("sha256:ffff0000");
    assert_eq!(report.verdict, Verdict::NotFound);
    assert_eq!(report.verdict.exit_code(), 3);
}

#[test]
fn a_session_without_a_seal_is_unsealed_not_verified() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.emitter.emit_admitted(&p, "host:test").unwrap();
    assert_eq!(chain.verify(&p.plan_id.0).verdict, Verdict::Unsealed);
}

#[test]
fn a_broken_ledger_link_is_reported_by_the_listing() {
    let chain = Chain::new();
    chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    let p = plan("sha256:bbbb2222");
    chain.emitter.emit_admitted(&p, "host:test").unwrap();
    let mut seal =
        compute_seal(&chain.lines(), &request(&p.plan_id.0, SealReason::Stopped)).unwrap();
    seal.prev_seal = GENESIS_SEAL.to_string();
    chain.append_seal(&p, seal.to_labels());

    let (_, ledger) = list_sessions(&chain.lines(), TimeRange::default()).unwrap();
    assert!(!ledger.intact);
    assert!(ledger.detail.unwrap().contains("links to"));
}

#[test]
fn host_entries_under_no_plan_are_not_sessions() {
    let chain = Chain::new();
    chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    // An entry for a plan id that was never admitted, like the host-level
    // command bookends the CLI writes under the nil plan id.
    let stray = plan("00000000-0000-0000-0000-000000000000");
    chain.emitter.emit_verb_denied(&stray, "exec").unwrap();

    let (sessions, _) = list_sessions(&chain.lines(), TimeRange::default()).unwrap();
    assert_eq!(sessions.len(), 1);
}

#[test]
fn time_ranges_select_overlapping_sessions() {
    let chain = Chain::new();
    chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    let lines = chain.lines();
    let past = "2000-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let future = "2999-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();

    let count = |range: TimeRange| list_sessions(&lines, range).unwrap().0.len();
    assert_eq!(count(TimeRange::default()), 1);
    assert_eq!(
        count(TimeRange {
            since: Some(past),
            until: None
        }),
        1
    );
    assert_eq!(
        count(TimeRange {
            since: Some(future),
            until: None
        }),
        0
    );
    assert_eq!(
        count(TimeRange {
            since: None,
            until: Some(past)
        }),
        0
    );
}

#[test]
fn show_filters_events_by_kind_glob_and_time() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let lines = chain.lines();
    let events = |filter: EventFilter| {
        session_events(&lines, &p.plan_id.0, &filter)
            .unwrap()
            .into_iter()
            .map(|e| e.envelope.entry.event)
            .collect::<Vec<_>>()
    };

    let all = events(EventFilter::default());
    assert!(all.contains(&"plan.admitted".to_string()));
    assert_eq!(all.last().map(String::as_str), Some(SESSION_SEALED_EVENT));
    let plan_only = events(EventFilter {
        kind: Some("plan.*".to_string()),
        ..EventFilter::default()
    });
    assert!(!plan_only.is_empty());
    assert!(plan_only.iter().all(|e| e.starts_with("plan.")));
    assert_eq!(
        events(EventFilter {
            kind: Some("*.sealed".to_string()),
            ..EventFilter::default()
        }),
        [SESSION_SEALED_EVENT]
    );
    let future = "2999-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    assert!(
        events(EventFilter {
            kind: None,
            range: TimeRange {
                since: Some(future),
                until: None
            },
        })
        .is_empty()
    );
}

#[test]
fn a_session_resolves_from_a_unique_prefix_and_refuses_ambiguity() {
    let chain = Chain::new();
    chain.run_and_seal(&plan("sha256:aaaa1111ffff"), 0);
    chain.run_and_seal(&plan("sha256:aaaa1111eeee"), 0);
    chain.run_and_seal(&plan("sha256:bbbb2222cccc"), 0);
    let lines = chain.lines();

    assert_eq!(
        resolve_session(&lines, "bbbb2222").unwrap(),
        "sha256:bbbb2222cccc"
    );
    assert_eq!(
        resolve_session(&lines, "sha256:aaaa1111ffff").unwrap(),
        "sha256:aaaa1111ffff"
    );
    let ambiguous = resolve_session(&lines, "aaaa1111").unwrap_err().to_string();
    assert!(ambiguous.contains("matches 2 sessions"), "{ambiguous}");
    assert!(resolve_session(&lines, "abc").is_err(), "too short");
    assert!(resolve_session(&lines, "99999999").is_err());
}

#[test]
fn seal_labels_round_trip_and_refuse_bad_values() {
    let chain = Chain::new();
    let seal = chain.run_and_seal(&plan("sha256:aaaa1111"), 0);
    let labels: BTreeMap<String, String> = seal.to_labels().into_iter().collect();
    assert_eq!(SessionSeal::from_labels(&labels).unwrap(), seal);

    let mut bad = labels.clone();
    bad.insert("seal.session_root".to_string(), "not-hex".to_string());
    assert!(SessionSeal::from_labels(&bad).is_err());
    let mut bad = labels;
    bad.insert("seal.reason".to_string(), "vanished".to_string());
    assert!(SessionSeal::from_labels(&bad).is_err());
}

#[test]
fn the_verification_report_has_a_stable_json_shape() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    chain.run_and_seal(&p, 0);
    let json = serde_json::to_value(chain.verify(&p.plan_id.0)).unwrap();
    assert_eq!(json["verdict"], "VERIFIED");
    assert_eq!(json["plan_id"], "sha256:aaaa1111");
    assert!(json.get("reason").is_none(), "no reason on success: {json}");
    assert!(json["seals"][0]["seal"]["session_root"].is_string());
    assert_eq!(json["seals"][0]["seal"]["reason"], "exited");

    let mut lines = chain.lines();
    lines.remove(1);
    chain.write_lines(&lines);
    let json = serde_json::to_value(chain.verify(&p.plan_id.0)).unwrap();
    assert_eq!(json["verdict"], "MISMATCH");
    assert_eq!(json["reason"], "chain_break");
    assert!(json["detail"].is_string());
}

#[test]
fn a_seal_survives_rotation_between_its_entries() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(7);
    let signer = crate::supervisor::FileAuditSigner::open(key.clone(), dir.path())
        .unwrap()
        .with_rotation(crate::supervisor::RotationPolicy::at_bytes(1024));
    let emitter =
        AuditEmitter::with_primary_signer(key.clone(), dir.path(), std::sync::Arc::new(signer))
            .expect("emitter with a rotating signer");
    let p = plan("sha256:aaaa1111");
    emitter.emit_admitted(&p, "host:test").unwrap();
    for _ in 0..6 {
        emitter.emit_launched(&p, "mock").unwrap();
    }
    emitter.emit_exited(&p, 0, "mock").unwrap();
    emitter.seal_session(&p, SealReason::Exited).unwrap();

    let rotated = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().contains(".seg-"));
    assert!(
        rotated,
        "the chain must have rotated for this test to mean anything"
    );
    let report = verify_session(dir.path(), TENANT, &p.plan_id.0, &key.verifying_key());
    assert_eq!(report.verdict, Verdict::Verified, "{report:?}");
}

#[test]
fn sealing_twice_with_nothing_new_writes_one_seal() {
    let chain = Chain::new();
    let p = plan("sha256:aaaa1111");
    let first = chain.run_and_seal(&p, 0);
    let again = chain.emitter.seal_session(&p, SealReason::Stopped).unwrap();
    assert_eq!(again, first);
    let seals = chain
        .lines()
        .iter()
        .filter(|l| l.contains(SESSION_SEALED_EVENT))
        .count();
    assert_eq!(seals, 1);

    // A new entry reopens it, and the next seal covers that entry too.
    chain.emitter.emit_verb_denied(&p, "exec").unwrap();
    let reseal = chain.emitter.seal_session(&p, SealReason::Stopped).unwrap();
    assert_eq!(reseal.event_count, first.event_count + 1);
    assert_eq!(chain.verify(&p.plan_id.0).verdict, Verdict::Verified);
}
