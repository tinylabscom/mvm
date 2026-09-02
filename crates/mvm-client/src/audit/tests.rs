//! Service-level tests: real chains written through the production
//! signers, then read back through [`LocalAuditReader`]. Covers the full
//! verification-refusal matrix, scope checks, ordering, pagination,
//! filters, and untrusted-input robustness.

use rand::Rng;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::audit_signer::canonical::CanonicalEntry;
use mvm_hostd::audit_signer::chain::Chain;
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};

use super::*;

fn fresh_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn ts(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, hour, minute, 0).unwrap()
}

fn lifecycle_entry(tenant: &str, event: &str, at: DateTime<Utc>) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: at,
        tenant: TenantId(tenant.to_string()),
        plan_id: PlanId("sha256:plan".to_string()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "worker-img".to_string(),
        image_sha256: "abc123".to_string(),
        caller_commitment: None,
        event: event.to_string(),
        labels: BTreeMap::new(),
    }
}

/// Write a lifecycle chain of `entries` under `key` into `audit_dir`.
fn write_lifecycle_chain(audit_dir: &Path, key: &SigningKey, entries: &[PlanAuditEntry]) {
    let signer = FileAuditSigner::open(key.clone(), audit_dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for entry in entries {
        rt.block_on(signer.sign_and_emit(entry)).unwrap();
    }
}

/// Write a workload chain for `tenant`/`vm` signed by `key` into
/// `audit_dir`. Each `(category, ts, tenant_id)` becomes one entry.
fn write_workload_chain(
    audit_dir: &Path,
    scratch: &Path,
    key: &SigningKey,
    tenant: &str,
    vm: &str,
    entries: &[(&str, &str, &str)],
) -> PathBuf {
    let key_path = scratch.join(format!("{tenant}.{vm}.chain.key"));
    std::fs::write(&key_path, key.to_bytes()).unwrap();
    let jsonl = audit_dir.join(format!(
        "{tenant}.{vm}{}",
        mvm_core::config::WORKLOAD_AUDIT_SUFFIX
    ));
    let head = scratch.join(format!("{tenant}.{vm}.HEAD"));
    let mut chain = Chain::open(&jsonl, &head, Some(&key_path)).unwrap();
    for (i, (category, ts, tenant_id)) in entries.iter().enumerate() {
        let entry = CanonicalEntry {
            category: (*category).to_string(),
            correlation_id: format!("corr-{i}"),
            fields: serde_json::json!({"n": i}),
            prev_hash: chain.head().to_string(),
            session_id: "sess-1".to_string(),
            tenant_id: (*tenant_id).to_string(),
            ts: (*ts).to_string(),
            workload_id: format!("wl-{vm}"),
        };
        chain.append(entry).unwrap();
    }
    jsonl
}

struct Fixture {
    _dir: tempfile::TempDir,
    audit_dir: PathBuf,
    scratch: PathBuf,
    key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        Self {
            _dir: dir,
            audit_dir,
            scratch,
            key: fresh_key(),
        }
    }

    fn reader(&self) -> LocalAuditReader {
        LocalAuditReader::new(&self.audit_dir, self.key.verifying_key())
    }

    fn lifecycle_path(&self, tenant: &str) -> PathBuf {
        self.audit_dir.join(format!("{tenant}.jsonl"))
    }
}

fn read_all(reader: &LocalAuditReader) -> AuditReadResponse {
    reader.read(&AuditReadRequest::builder().build()).unwrap()
}

// ─── valid chains ────────────────────────────────────────────────────

#[test]
fn valid_chains_yield_normalized_events_from_both_source_kinds() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "plan.admitted", ts(9, 0)),
            lifecycle_entry("local", "plan.launched", ts(9, 5)),
        ],
    );
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[("plan", "2026-08-01T09:02:00Z", "local")],
    );

    let response = read_all(&fx.reader());
    assert!(response.refusals.is_empty(), "{:?}", response.refusals);
    assert_eq!(response.sources.len(), 2);
    assert_eq!(response.events.len(), 3);
    // Newest first.
    assert_eq!(response.events[0].event, "plan.launched");
    assert_eq!(response.events[0].kind, AuditEventKind::Launch);
    assert_eq!(response.events[1].id.source.kind, AuditSourceKind::Workload);
    assert_eq!(response.events[1].machine.as_deref(), Some("vm1"));
    assert_eq!(response.events[2].event, "plan.admitted");
    assert!(response.next_cursor.is_none());
}

#[test]
fn empty_audit_dir_and_missing_dir_read_as_empty() {
    let fx = Fixture::new();
    let response = read_all(&fx.reader());
    assert!(response.events.is_empty());
    assert!(response.sources.is_empty());
    assert!(response.refusals.is_empty());

    let missing =
        LocalAuditReader::new(fx.audit_dir.join("does-not-exist"), fx.key.verifying_key());
    let response = read_all(&missing);
    assert!(response.events.is_empty());
    assert!(response.refusals.is_empty());
}

// ─── refusal matrix ──────────────────────────────────────────────────

#[test]
fn tampered_signature_refuses_the_source_and_spares_others() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("local", "plan.admitted", ts(9, 0))],
    );
    // A second, clean tenant chain.
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("acme", "plan.admitted", ts(9, 1))],
    );
    // Flip a signed byte in local's chain.
    let path = fx.lifecycle_path("local");
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replacen("plan.admitted", "plan.hijacked", 1)).unwrap();

    let response = read_all(&fx.reader());
    assert_eq!(response.refusals.len(), 1);
    let refusal = &response.refusals[0];
    assert_eq!(refusal.kind, AuditRefusalKind::SignatureInvalid);
    assert_eq!(refusal.source.tenant, "local");
    assert_eq!(refusal.line, Some(0));
    // The tampered source contributed zero events; the clean one is intact.
    assert!(response.events.iter().all(|e| e.tenant == "acme"));
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.sources.len(), 1);
}

#[test]
fn deleted_middle_line_is_a_chain_broken_refusal() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-0", ts(9, 0)),
            lifecycle_entry("local", "e-1", ts(9, 1)),
            lifecycle_entry("local", "e-2", ts(9, 2)),
        ],
    );
    let path = fx.lifecycle_path("local");
    let lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

    let response = read_all(&fx.reader());
    assert!(response.events.is_empty(), "no partial prefix may leak");
    assert_eq!(response.refusals.len(), 1);
    assert_eq!(response.refusals[0].kind, AuditRefusalKind::ChainBroken);
    assert_eq!(response.refusals[0].line, Some(1));
}

#[test]
fn reordered_entries_are_a_chain_broken_refusal() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-0", ts(9, 0)),
            lifecycle_entry("local", "e-1", ts(9, 1)),
        ],
    );
    let path = fx.lifecycle_path("local");
    let lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    std::fs::write(&path, format!("{}\n{}\n", lines[1], lines[0])).unwrap();

    let response = read_all(&fx.reader());
    assert!(response.events.is_empty());
    assert_eq!(response.refusals[0].kind, AuditRefusalKind::ChainBroken);
}

#[test]
fn truncated_tail_refuses_the_whole_source() {
    // A half-written final line must not demote the source to "the valid
    // prefix": the reader fails the source closed until the chain is whole.
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-0", ts(9, 0)),
            lifecycle_entry("local", "e-1", ts(9, 1)),
        ],
    );
    let path = fx.lifecycle_path("local");
    let content = std::fs::read_to_string(&path).unwrap();
    let cut = content.len() - 40;
    std::fs::write(&path, &content[..cut]).unwrap();

    let response = read_all(&fx.reader());
    assert!(response.events.is_empty(), "no partial prefix may leak");
    assert_eq!(response.refusals.len(), 1);
    // Refusing was always right; calling it `Malformed` was not. A half-written
    // line and an edited one are the same bytes on disk, and the operator
    // triaging the refusal is exactly the person who needs to tell a crashed
    // writer from a tampered log. The reader now names which one it saw.
    assert_eq!(response.refusals[0].kind, AuditRefusalKind::Truncated);
    assert_eq!(response.refusals[0].line, Some(1));
}

#[test]
fn wrong_key_refuses_every_source() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("local", "plan.admitted", ts(9, 0))],
    );
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[("plan", "2026-08-01T09:02:00Z", "local")],
    );

    let stranger = LocalAuditReader::new(&fx.audit_dir, fresh_key().verifying_key());
    let response = read_all(&stranger);
    assert!(response.events.is_empty());
    assert!(response.sources.is_empty());
    assert_eq!(response.refusals.len(), 2);
    for refusal in &response.refusals {
        assert_eq!(refusal.kind, AuditRefusalKind::SignatureInvalid);
    }
}

#[test]
fn cross_scope_lifecycle_entry_refuses_the_source() {
    // A genuinely-signed entry for another tenant, spliced into this
    // tenant's file via a fixed-file signer, verifies cryptographically —
    // only the scope check catches it.
    let fx = Fixture::new();
    let path = fx.lifecycle_path("local");
    let signer = FileAuditSigner::open_file(fx.key.clone(), &path).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(signer.sign_and_emit(&lifecycle_entry("local", "e-0", ts(9, 0))))
        .unwrap();
    rt.block_on(signer.sign_and_emit(&lifecycle_entry("other", "e-1", ts(9, 1))))
        .unwrap();

    let response = read_all(&fx.reader());
    assert!(response.events.is_empty(), "no partial prefix may leak");
    assert_eq!(response.refusals.len(), 1);
    let refusal = &response.refusals[0];
    assert_eq!(refusal.kind, AuditRefusalKind::ScopeMismatch);
    assert_eq!(refusal.line, Some(1));
    assert!(refusal.detail.contains("other"), "{}", refusal.detail);
}

#[test]
fn cross_scope_workload_entry_refuses_the_source() {
    let fx = Fixture::new();
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[
            ("plan", "2026-08-01T09:00:00Z", "local"),
            ("plan", "2026-08-01T09:01:00Z", "other"),
        ],
    );
    let response = read_all(&fx.reader());
    assert!(response.events.is_empty());
    assert_eq!(response.refusals.len(), 1);
    assert_eq!(response.refusals[0].kind, AuditRefusalKind::ScopeMismatch);
}

#[test]
fn garbage_file_is_a_malformed_refusal_not_a_panic() {
    let fx = Fixture::new();
    std::fs::write(fx.audit_dir.join("evil.jsonl"), "not json at all\n{}\n").unwrap();
    let response = read_all(&fx.reader());
    assert!(response.events.is_empty());
    assert_eq!(response.refusals.len(), 1);
    assert_eq!(response.refusals[0].kind, AuditRefusalKind::Malformed);
}

/// Property: arbitrary bytes in either chain position never panic the
/// reader and never surface as verified events. Hand-rolled seeded loop,
/// matching the repo's property-test pattern.
#[test]
fn property_untrusted_audit_input_never_yields_events() {
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0xa0d17);
    for i in 0..50 {
        let fx = Fixture::new();
        let len = rng.random_range(1..2048);
        let bytes: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
        let name = if i % 2 == 0 {
            "local.jsonl".to_string()
        } else {
            format!("local.vm{i}{}", mvm_core::config::WORKLOAD_AUDIT_SUFFIX)
        };
        std::fs::write(fx.audit_dir.join(name), &bytes).unwrap();
        let response = read_all(&fx.reader());
        assert!(
            response.events.is_empty(),
            "random bytes must never verify (iteration {i})"
        );
        // Anything beyond bare newlines must be an explicit refusal.
        let has_payload = bytes.iter().any(|b| *b != b'\n' && *b != b'\r');
        if has_payload {
            assert!(!response.refusals.is_empty(), "iteration {i}");
        }
    }
}

// ─── ordering, pagination, filters ───────────────────────────────────

#[test]
fn merged_ordering_is_newest_first_with_stable_tie_breaks() {
    let fx = Fixture::new();
    // Lifecycle and workload entries at the same instant plus around it.
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-old", ts(8, 0)),
            lifecycle_entry("local", "e-tie", ts(9, 0)),
        ],
    );
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[
            ("plan", "2026-08-01T09:00:00Z", "local"),
            ("plan", "2026-08-01T10:00:00Z", "local"),
        ],
    );

    let response = read_all(&fx.reader());
    let order: Vec<(AuditSourceKind, u64)> = response
        .events
        .iter()
        .map(|e| (e.id.source.kind, e.id.seq))
        .collect();
    // 10:00 workload, then the 09:00 tie (workload ranks above lifecycle
    // in the descending ordering), then lifecycle 09:00, then 08:00.
    assert_eq!(
        order,
        vec![
            (AuditSourceKind::Workload, 1),
            (AuditSourceKind::Workload, 0),
            (AuditSourceKind::Lifecycle, 1),
            (AuditSourceKind::Lifecycle, 0),
        ]
    );
}

#[test]
fn pagination_walks_the_stream_without_gaps_or_duplicates() {
    let fx = Fixture::new();
    let entries: Vec<PlanAuditEntry> = (0..7u32)
        .map(|i| lifecycle_entry("local", &format!("e-{i}"), ts(9, i)))
        .collect();
    write_lifecycle_chain(&fx.audit_dir, &fx.key, &entries);
    let reader = fx.reader();

    let full = read_all(&reader);
    assert_eq!(full.events.len(), 7);

    let mut paged: Vec<VerifiedAuditEvent> = Vec::new();
    let mut cursor: Option<AuditCursor> = None;
    let mut pages = 0;
    loop {
        let mut builder = AuditReadRequest::builder().limit(3);
        if let Some(c) = cursor.take() {
            builder = builder.cursor(c);
        }
        let page = reader.read(&builder.build()).unwrap();
        assert!(page.events.len() <= 3);
        paged.extend(page.events.clone());
        pages += 1;
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
        assert!(pages < 10, "cursor walk must terminate");
    }
    assert_eq!(pages, 3);
    assert_eq!(paged, full.events, "paged walk must equal the full read");
}

#[test]
fn machine_filter_selects_one_vm() {
    let fx = Fixture::new();
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[("plan", "2026-08-01T09:00:00Z", "local")],
    );
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm2",
        &[("plan", "2026-08-01T09:01:00Z", "local")],
    );
    let response = fx
        .reader()
        .read(&AuditReadRequest::builder().machine("vm2").build())
        .unwrap();
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].machine.as_deref(), Some("vm2"));
    // Both sources still verified — filtering is presentation, not trust.
    assert_eq!(response.sources.len(), 2);
}

#[test]
fn tenant_filter_scopes_discovery() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("acme", "plan.admitted", ts(9, 0))],
    );
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("beta", "plan.admitted", ts(9, 1))],
    );
    let response = fx
        .reader()
        .read(&AuditReadRequest::builder().tenant("acme").build())
        .unwrap();
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].tenant, "acme");
    assert_eq!(response.sources.len(), 1);
}

#[test]
fn kind_filter_selects_normalized_categories() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "plan.admitted", ts(9, 0)),
            lifecycle_entry("local", "plan.launched", ts(9, 1)),
            lifecycle_entry("local", "plan.failed", ts(9, 2)),
        ],
    );
    let response = fx
        .reader()
        .read(
            &AuditReadRequest::builder()
                .kind(AuditEventKind::Refusal)
                .kind(AuditEventKind::Launch)
                .build(),
        )
        .unwrap();
    assert_eq!(response.events.len(), 2);
    assert_eq!(response.events[0].kind, AuditEventKind::Refusal);
    assert_eq!(response.events[1].kind, AuditEventKind::Launch);
}

#[test]
fn time_window_filter_bounds_the_read() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-0", ts(8, 0)),
            lifecycle_entry("local", "e-1", ts(9, 0)),
            lifecycle_entry("local", "e-2", ts(10, 0)),
        ],
    );
    let response = fx
        .reader()
        .read(
            &AuditReadRequest::builder()
                .since(ts(8, 30))
                .until(ts(9, 30))
                .build(),
        )
        .unwrap();
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].event, "e-1");
}

#[test]
fn verify_sources_reports_summaries_and_refusals() {
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[
            lifecycle_entry("local", "e-0", ts(9, 0)),
            lifecycle_entry("local", "e-1", ts(9, 1)),
        ],
    );
    let workload_path = write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "local",
        "vm1",
        &[("plan", "2026-08-01T09:00:00Z", "local")],
    );

    let outcome = fx.reader().verify_sources(Some("local")).unwrap();
    assert!(outcome.refusals.is_empty());
    assert_eq!(outcome.sources.len(), 2);
    assert_eq!(outcome.sources[0].source.kind, AuditSourceKind::Lifecycle);
    assert_eq!(outcome.sources[0].entries, 2);
    assert_eq!(outcome.sources[1].source.kind, AuditSourceKind::Workload);
    assert_eq!(outcome.sources[1].entries, 1);

    // Tamper the workload chain: it becomes a refusal, the lifecycle
    // summary survives.
    let content = std::fs::read_to_string(&workload_path).unwrap();
    let tampered = content.replacen('A', "B", 1);
    assert_ne!(content, tampered, "fixture must actually change a byte");
    std::fs::write(&workload_path, tampered).unwrap();
    let outcome = fx.reader().verify_sources(Some("local")).unwrap();
    assert_eq!(outcome.sources.len(), 1);
    assert_eq!(outcome.refusals.len(), 1);
    assert_eq!(outcome.refusals[0].source.kind, AuditSourceKind::Workload);
}

#[test]
fn unsigned_secrets_operator_log_is_neither_a_source_nor_a_refusal() {
    // `mvmctl secret …` writes an UNSIGNED plain-JSON operator log at
    // `<audit_dir>/secrets.jsonl`. It is not a chain: it must never
    // surface as events, and its presence must not poison reads or
    // verifies with a permanent refusal.
    let fx = Fixture::new();
    std::fs::write(
        fx.audit_dir.join("secrets.jsonl"),
        r#"{"ts":"2026-08-01T09:00:00Z","action":"put","name":"db"}"#,
    )
    .unwrap();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("local", "plan.admitted", ts(9, 0))],
    );

    let response = read_all(&fx.reader());
    assert!(response.refusals.is_empty(), "{:?}", response.refusals);
    assert_eq!(response.sources.len(), 1);
    assert_eq!(response.events.len(), 1);

    // Even a tenant literally named "secrets" cannot claim the operator
    // log as its lifecycle chain.
    let outcome = fx.reader().verify_sources(Some("secrets")).unwrap();
    assert!(outcome.sources.is_empty());
    assert!(outcome.refusals.is_empty());
}

#[test]
fn dotted_tenant_round_trips_scoped_and_unscoped() {
    // A tenant name may contain dots. Tenant-scoped classification must
    // anchor on the tenant (like the chain writers do) instead of
    // splitting at the first dot, and the unscoped path must recover the
    // same split via the tenant's lifecycle chain.
    let fx = Fixture::new();
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("a.b", "plan.admitted", ts(9, 0))],
    );
    write_workload_chain(
        &fx.audit_dir,
        &fx.scratch,
        &fx.key,
        "a.b",
        "vm1",
        &[("plan", "2026-08-01T09:01:00Z", "a.b")],
    );

    // Scoped verify sees BOTH chains (the old tenant-anchored semantics).
    let outcome = fx.reader().verify_sources(Some("a.b")).unwrap();
    assert!(outcome.refusals.is_empty(), "{:?}", outcome.refusals);
    assert_eq!(outcome.sources.len(), 2, "{:?}", outcome.sources);
    let workload = &outcome.sources[1];
    assert_eq!(workload.source.kind, AuditSourceKind::Workload);
    assert_eq!(workload.source.tenant, "a.b");
    assert_eq!(workload.source.machine.as_deref(), Some("vm1"));

    // Scoped read returns both events under the right identities.
    let scoped = fx
        .reader()
        .read(&AuditReadRequest::builder().tenant("a.b").build())
        .unwrap();
    assert_eq!(scoped.events.len(), 2);
    assert!(scoped.events.iter().all(|e| e.tenant == "a.b"));

    // Unscoped read parses the workload stem via the known tenant, so
    // the scope check passes instead of mis-splitting into tenant "a".
    let unscoped = read_all(&fx.reader());
    assert!(unscoped.refusals.is_empty(), "{:?}", unscoped.refusals);
    assert_eq!(unscoped.events.len(), 2);
    assert!(unscoped.events.iter().all(|e| e.tenant == "a.b"));
}

#[test]
fn discover_source_ids_lists_without_a_key_and_skips_non_chains() {
    let fx = Fixture::new();
    assert!(
        discover_source_ids(&fx.audit_dir, Some("local"))
            .unwrap()
            .is_empty()
    );
    std::fs::write(fx.audit_dir.join("secrets.jsonl"), "{}\n").unwrap();
    assert!(
        discover_source_ids(&fx.audit_dir, None).unwrap().is_empty(),
        "the unsigned operator log must never count as a source"
    );
    write_lifecycle_chain(
        &fx.audit_dir,
        &fx.key,
        &[lifecycle_entry("local", "plan.admitted", ts(9, 0))],
    );
    let ids = discover_source_ids(&fx.audit_dir, Some("local")).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].kind, AuditSourceKind::Lifecycle);
    assert_eq!(ids[0].tenant, "local");
}

#[test]
fn unreadable_audit_dir_is_an_io_error_not_a_refusal() {
    let fx = Fixture::new();
    // A file where the directory should be.
    let bogus = fx.scratch.join("not-a-dir");
    std::fs::write(&bogus, b"x").unwrap();
    let reader = LocalAuditReader::new(&bogus, fx.key.verifying_key());
    let err = reader
        .read(&AuditReadRequest::builder().build())
        .unwrap_err();
    assert!(matches!(err, AuditReadError::Io { .. }), "{err}");
}
