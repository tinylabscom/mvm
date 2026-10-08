//! Frozen telemetry fixtures for mvm studio.
//!
//! `tests/vectors/studio-telemetry/*.jsonl` are the record streams the
//! studio frontend renders against: each line is one `TelemetryRecord` in
//! exactly the JSON the collector's records output carries and the read seam
//! serves, produced by the real builders and serde — never typed by hand, so
//! a fixture cannot drift from the contract without this test going red.
//! Beside them, `collector-status.jsonl` freezes the typed status the seam
//! answers for every coverage state, and `records-page.json` freezes one
//! page cut from `healthy-boot.jsonl` so the cursor semantics are concrete.
//! The companion contract document is `specs/telemetry/studio-contract.md`.
//!
//! The streams are deterministic (fixed epochs, sequences and monotonic
//! timestamps), so the comparison is byte-exact. Regenerate after a
//! deliberate schema change with:
//! `MVM_REGENERATE_VECTORS=1 cargo test -p mvm-core --test studio_telemetry_fixtures -- --ignored`.

use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, Attributes, CollectorStatusSnapshot, CoverageState, GuestLossStage,
    Level, LossReason, ProducerEpoch, RecordBody, SourceKind, TailState, TelemetryPage,
    TelemetryRecord, TelemetryStatus, page_from_jsonl,
};

const VECTOR_DIR: &str = "../../tests/vectors/studio-telemetry";

/// The three scenario streams, in the order studio's fixtures list them.
const SCENARIOS: [&str; 3] = ["healthy-boot", "lossy-flood", "restored-generation"];

fn attr(key: &str, value: AttributeValue) -> Attribute {
    Attribute {
        key: key.try_into().unwrap(),
        value,
    }
}

fn event(
    epoch: ProducerEpoch,
    sequence: u64,
    monotonic_ns: u64,
    level: Level,
    name: &str,
    attributes: Vec<Attribute>,
) -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(epoch)
        .producer(1)
        .sequence(sequence)
        .monotonic_ns(monotonic_ns)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Event {
            context: None,
            level,
            name: name.try_into().unwrap(),
            attributes: Attributes::new(attributes).unwrap(),
        })
        .build()
        .unwrap()
}

fn coverage(
    epoch: ProducerEpoch,
    sequence: u64,
    monotonic_ns: u64,
    state: CoverageState,
) -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(epoch)
        .producer(1)
        .sequence(sequence)
        .monotonic_ns(monotonic_ns)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state,
            code: "guest-agent".try_into().unwrap(),
        })
        .build()
        .unwrap()
}

fn loss(
    epoch: ProducerEpoch,
    sequence: u64,
    monotonic_ns: u64,
    reason: LossReason,
    records: u64,
    bytes: u64,
) -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(epoch)
        .producer(1)
        .sequence(sequence)
        .monotonic_ns(monotonic_ns)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Loss {
            stage: GuestLossStage::Capture,
            reason,
            records,
            bytes,
            tail: TailState::Known,
        })
        .build()
        .unwrap()
}

/// An agent booting cleanly and reporting ordinary diagnostics: the stream a
/// healthy VM's studio view renders. One epoch, gapless sequences, coverage
/// announced first.
fn healthy_boot() -> Vec<TelemetryRecord> {
    let epoch = ProducerEpoch::new([0x11; 16]).unwrap();
    vec![
        coverage(epoch, 1, 1_000_000, CoverageState::Started),
        event(
            epoch,
            2,
            5_250_000,
            Level::Info,
            "vsock control plane bound",
            vec![attr("port", AttributeValue::Unsigned(5253))],
        ),
        event(
            epoch,
            3,
            9_500_000,
            Level::Info,
            "workload entrypoint validated",
            vec![
                attr(
                    "entrypoint",
                    AttributeValue::Text("/usr/bin/app".try_into().unwrap()),
                ),
                attr("cached", AttributeValue::Bool(true)),
            ],
        ),
        event(
            epoch,
            4,
            2_100_000_000,
            Level::Info,
            "warm pool ready",
            vec![
                attr("standby", AttributeValue::Signed(2)),
                attr("fill_ratio", AttributeValue::float(0.5).unwrap()),
            ],
        ),
        event(
            epoch,
            5,
            4_800_000_000,
            Level::Warn,
            "host beacon retry",
            vec![attr("attempt", AttributeValue::Unsigned(2))],
        ),
    ]
}

/// A capture queue under pressure: shed attempts spend sequence numbers, so
/// the visible gap (5 → 43) plus the loss summaries are the evidence studio
/// should surface, not smooth over. Loss records ride the reserved path, so
/// they arrive even while the data queue sheds.
fn lossy_flood() -> Vec<TelemetryRecord> {
    let epoch = ProducerEpoch::new([0x22; 16]).unwrap();
    vec![
        coverage(epoch, 1, 1_000_000, CoverageState::Started),
        event(
            epoch,
            2,
            3_000_000,
            Level::Info,
            "flood begins",
            vec![attr("burst", AttributeValue::Unsigned(1))],
        ),
        event(
            epoch,
            5,
            9_000_000,
            Level::Info,
            "still draining",
            vec![attr("burst", AttributeValue::Unsigned(2))],
        ),
        loss(epoch, 6, 1_000_000_000, LossReason::Capacity, 37, 191_360),
        event(
            epoch,
            43,
            2_000_000_000,
            Level::Warn,
            "pressure easing",
            vec![attr("queued", AttributeValue::Unsigned(3))],
        ),
        loss(epoch, 44, 3_000_000_000, LossReason::Capacity, 12, 61_440),
    ]
}

/// A restore: the new generation mints a fresh epoch and its own coverage
/// announcement, and sequences never continue a donor's run. Studio should
/// treat the epoch change as a hard boundary — ordering across it is not
/// meaningful.
fn restored_generation() -> Vec<TelemetryRecord> {
    let parent = ProducerEpoch::new([0x33; 16]).unwrap();
    let child = ProducerEpoch::new([0x44; 16]).unwrap();
    vec![
        coverage(parent, 1, 1_000_000, CoverageState::Started),
        event(
            parent,
            2,
            6_000_000,
            Level::Info,
            "checkpoint prepared",
            vec![attr("generation", AttributeValue::Unsigned(1))],
        ),
        coverage(parent, 3, 9_000_000, CoverageState::Stopped),
        coverage(child, 4, 1_500_000, CoverageState::Started),
        event(
            child,
            5,
            4_000_000,
            Level::Info,
            "restored from checkpoint",
            vec![attr("generation", AttributeValue::Unsigned(2))],
        ),
    ]
}

fn stream(name: &str) -> Vec<TelemetryRecord> {
    match name {
        "healthy-boot" => healthy_boot(),
        "lossy-flood" => lossy_flood(),
        "restored-generation" => restored_generation(),
        other => panic!("unknown scenario {other}"),
    }
}

fn render(records: &[TelemetryRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&serde_json::to_string(record).unwrap());
        out.push('\n');
    }
    out
}

fn vector_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(VECTOR_DIR).join(format!("{name}.jsonl"))
}

/// The status fixture: every label the collector writes, typed through the
/// same conversion the read seam uses, one `TelemetryStatus` per line.
const STATUS_FIXTURE: &str = "collector-status";

fn on_disk_statuses() -> Vec<CollectorStatusSnapshot> {
    let snapshot = |status: &str, generation, shed| CollectorStatusSnapshot {
        vm_name: "fixture".into(),
        status: status.into(),
        generation,
        shed,
    };
    vec![
        snapshot("connecting", None, 0),
        snapshot("collecting", Some(3), 0),
        snapshot("collecting", Some(3), 37),
        snapshot("degraded:auth_failed", None, 37),
        snapshot("stopped", None, 37),
    ]
}

fn render_statuses() -> String {
    let mut out = String::new();
    // The not-provisioned state has no on-disk form: it is what the seam
    // answers when the collector wrote nothing at all.
    out.push_str(&serde_json::to_string(&TelemetryStatus::not_provisioned()).unwrap());
    out.push('\n');
    for snapshot in on_disk_statuses() {
        let typed = TelemetryStatus::try_from(&snapshot).expect("every written label types");
        out.push_str(&serde_json::to_string(&typed).unwrap());
        out.push('\n');
    }
    out
}

/// The page fixture: the first three records of `healthy-boot`, cut by the
/// seam's own pager, so `next` is the byte position a consumer hands back.
const PAGE_FIXTURE: &str = "records-page";

fn render_page() -> String {
    let stream = render(&healthy_boot());
    let page = page_from_jsonl(stream.as_bytes(), 0, 3).expect("the fixture stream pages");
    assert!(page.more, "three of five records leaves more");
    let mut out = serde_json::to_string_pretty(&page).unwrap();
    out.push('\n');
    out
}

fn page_path() -> std::path::PathBuf {
    std::path::Path::new(VECTOR_DIR).join(format!("{PAGE_FIXTURE}.json"))
}

#[test]
fn studio_fixture_streams_match_the_committed_vectors() {
    for name in SCENARIOS {
        let expected = render(&stream(name));
        let committed = std::fs::read_to_string(vector_path(name))
            .unwrap_or_else(|e| panic!("reading {name}.jsonl: {e}"));
        assert_eq!(
            committed, expected,
            "{name}.jsonl drifted from the generator; regenerate deliberately \
             with MVM_REGENERATE_VECTORS=1 (module docs)"
        );
    }
}

#[test]
fn studio_status_fixture_matches_the_committed_vector() {
    let committed = std::fs::read_to_string(vector_path(STATUS_FIXTURE))
        .unwrap_or_else(|e| panic!("reading {STATUS_FIXTURE}.jsonl: {e}"));
    assert_eq!(
        committed,
        render_statuses(),
        "{STATUS_FIXTURE}.jsonl drifted from the generator; regenerate deliberately \
         with MVM_REGENERATE_VECTORS=1 (module docs)"
    );
    for (index, line) in committed.lines().enumerate() {
        let _: TelemetryStatus = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("{STATUS_FIXTURE}.jsonl line {}: {e}", index + 1));
    }
}

#[test]
fn studio_page_fixture_matches_the_committed_vector_and_continues_the_stream() {
    let committed = std::fs::read_to_string(page_path())
        .unwrap_or_else(|e| panic!("reading {PAGE_FIXTURE}.json: {e}"));
    assert_eq!(
        committed,
        render_page(),
        "{PAGE_FIXTURE}.json drifted from the generator; regenerate deliberately \
         with MVM_REGENERATE_VECTORS=1 (module docs)"
    );
    let page: TelemetryPage = serde_json::from_str(&committed).expect("a page decodes");
    assert_eq!(page.records, healthy_boot()[..3]);

    // Handing `next` back reads exactly the rest of the committed stream.
    let stream = std::fs::read(vector_path("healthy-boot")).unwrap();
    let rest = page_from_jsonl(&stream[page.next.0 as usize..], page.next.0, 10).unwrap();
    assert_eq!(rest.records, healthy_boot()[3..]);
    assert!(!rest.more);
    assert_eq!(rest.next.0 as usize, stream.len());
}

/// Every fixture line must decode back through the real contract — the same
/// property any studio consumer relies on.
#[test]
fn every_committed_fixture_line_decodes_as_a_record() {
    for name in SCENARIOS {
        let committed = std::fs::read_to_string(vector_path(name)).unwrap();
        for (index, line) in committed.lines().enumerate() {
            let record: TelemetryRecord = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{name}.jsonl line {}: {e}", index + 1));
            let _ = record;
        }
    }
}

#[test]
#[ignore = "regenerates committed fixtures; run explicitly"]
fn regenerate_the_frozen_fixture_streams() {
    if std::env::var("MVM_REGENERATE_VECTORS").as_deref() != Ok("1") {
        panic!("set MVM_REGENERATE_VECTORS=1 to regenerate the studio fixtures");
    }
    std::fs::create_dir_all(VECTOR_DIR).unwrap();
    for name in SCENARIOS {
        std::fs::write(vector_path(name), render(&stream(name))).unwrap();
    }
    std::fs::write(vector_path(STATUS_FIXTURE), render_statuses()).unwrap();
    std::fs::write(page_path(), render_page()).unwrap();
}
