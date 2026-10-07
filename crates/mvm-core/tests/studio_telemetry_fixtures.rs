//! Frozen telemetry record streams for mvm studio.
//!
//! `tests/vectors/studio-telemetry/*.jsonl` are the fixture streams the
//! studio frontend renders against before the live read seam exists: each
//! line is one `TelemetryRecord` in exactly the JSON the collector's records
//! output carries, produced by the real builders and serde — never typed by
//! hand, so a fixture cannot drift from the contract without this test going
//! red. The companion contract document is
//! `specs/telemetry/studio-contract.md`.
//!
//! The streams are deterministic (fixed epochs, sequences and monotonic
//! timestamps), so the comparison is byte-exact. Regenerate after a
//! deliberate schema change with:
//! `MVM_REGENERATE_VECTORS=1 cargo test -p mvm-core --test studio_telemetry_fixtures -- --ignored`.

use mvm_core::protocol::telemetry::served::{
    CollectorState, ReceivedRecord, TelemetryCursor, TelemetryReadResponse, TelemetryStatus,
};
use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, Attributes, CoverageState, GuestLossStage, Level, LossReason,
    ProducerEpoch, RecordBody, SourceKind, TailState, TelemetryRecord,
};

const VECTOR_DIR: &str = "../../tests/vectors/studio-telemetry";

/// The three scenario streams, in the order studio's fixtures list them.
const SCENARIOS: [&str; 3] = ["healthy-boot", "lossy-flood", "restored-generation"];

/// The served shapes the read seam answers with, frozen beside the streams:
/// three status snapshots and one page of the healthy-boot stream as a
/// consumer receives it.
const SERVED: [&str; 4] = [
    "status-not-provisioned",
    "status-collecting",
    "status-degraded",
    "page-healthy-boot",
];

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

/// The receive time the fixture page stamps on record `index`: one
/// quarter-second apart, so the UI's wall-clock placement is visible.
fn received_at_ms(index: usize) -> u64 {
    1_700_000_000_000 + index as u64 * 250
}

/// A page of the healthy-boot stream exactly as the seam serves it from the
/// start of the stream: every record in its envelope, the cursor one byte
/// past the last persisted line, nothing undecodable, and the end reached.
fn healthy_boot_page() -> TelemetryReadResponse {
    let records = healthy_boot();
    let persisted: u64 = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            ReceivedRecord::encode_line(received_at_ms(index), record)
                .unwrap()
                .len() as u64
        })
        .sum();
    TelemetryReadResponse {
        records: records
            .into_iter()
            .enumerate()
            .map(|(index, record)| ReceivedRecord {
                received_at_ms: Some(received_at_ms(index)),
                record,
            })
            .collect(),
        next_cursor: TelemetryCursor { offset: persisted },
        undecodable: 0,
        exhausted: true,
    }
}

fn served(name: &str) -> serde_json::Value {
    match name {
        "status-not-provisioned" => serde_json::to_value(TelemetryStatus::NotProvisioned),
        "status-collecting" => serde_json::to_value(TelemetryStatus::Provisioned {
            vm_name: "web".into(),
            state: CollectorState::Collecting { generation: 1 },
            shed: 0,
            snapshot_age_ms: Some(640),
            records_bytes: 1_874,
        }),
        "status-degraded" => serde_json::to_value(TelemetryStatus::Provisioned {
            vm_name: "web".into(),
            state: CollectorState::Degraded {
                code: "authentication-failed".into(),
            },
            shed: 37,
            snapshot_age_ms: Some(1_020),
            records_bytes: 0,
        }),
        "page-healthy-boot" => serde_json::to_value(healthy_boot_page()),
        other => panic!("unknown served fixture {other}"),
    }
    .unwrap()
}

fn render_served(value: &serde_json::Value) -> String {
    let mut out = serde_json::to_string_pretty(value).unwrap();
    out.push('\n');
    out
}

fn served_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(VECTOR_DIR).join(format!("{name}.json"))
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

/// The served shapes are frozen the same way: produced by the contract
/// types' own serde, compared byte-exact.
#[test]
fn studio_fixture_statuses_and_page_match_the_committed_vectors() {
    for name in SERVED {
        let expected = render_served(&served(name));
        let committed = std::fs::read_to_string(served_path(name))
            .unwrap_or_else(|e| panic!("reading {name}.json: {e}"));
        assert_eq!(
            committed, expected,
            "{name}.json drifted from the generator; regenerate deliberately \
             with MVM_REGENERATE_VECTORS=1 (module docs)"
        );
    }
}

/// Every served fixture decodes back through the contract types, and the
/// page's records are the healthy-boot stream in its envelope — the two
/// fixture families describe one stream.
#[test]
fn every_committed_served_fixture_decodes_through_the_contract() {
    for name in SERVED.iter().filter(|n| n.starts_with("status-")) {
        let committed = std::fs::read_to_string(served_path(name)).unwrap();
        let status: TelemetryStatus =
            serde_json::from_str(&committed).unwrap_or_else(|e| panic!("{name}.json: {e}"));
        assert_eq!(serde_json::to_value(status).unwrap(), served(name));
    }
    let committed = std::fs::read_to_string(served_path("page-healthy-boot")).unwrap();
    let page: TelemetryReadResponse = serde_json::from_str(&committed).unwrap();
    let stream: Vec<TelemetryRecord> = page.records.into_iter().map(|r| r.record).collect();
    assert_eq!(stream, healthy_boot());
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
    for name in SERVED {
        std::fs::write(served_path(name), render_served(&served(name))).unwrap();
    }
}
