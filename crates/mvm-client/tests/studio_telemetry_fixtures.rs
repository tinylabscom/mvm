//! The studio telemetry fixtures, replayed through the real local reader.
//!
//! `crates/mvm-core/tests/studio_telemetry_fixtures.rs` generates the served
//! fixtures under `tests/vectors/studio-telemetry/` from the contract types.
//! This test closes the loop from the other side: it stages the files the
//! collector would have written and checks that [`LocalTelemetryReader`]
//! answers with exactly the committed JSON. A fixture a consumer builds
//! against is then something the seam really serves, not merely something
//! that decodes.

use std::path::{Path, PathBuf};

use mvm_client::LocalTelemetryReader;
use mvm_client::telemetry::collector_files;
use mvm_core::protocol::telemetry::served::{
    CollectorState, ReceivedRecord, TelemetryReadRequest, TelemetryReadResponse, TelemetryStatus,
};
use mvm_hostd::telemetry_collector::CollectorStatusSnapshot;

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/studio-telemetry")
        .join(name)
}

fn served_page(name: &str) -> TelemetryReadResponse {
    let path = vector(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn records_key() -> mvm_core::crypto::aead::Key {
    mvm_core::crypto::aead::Key::from_bytes([8; 32])
}

/// Persist `records` the way the collector does and return a reader over
/// the directory holding them.
fn stage_records(dir: &Path, records: &[ReceivedRecord]) -> LocalTelemetryReader {
    let (_, records_path) = collector_files(dir);
    let mut bytes = Vec::new();
    for received in records {
        let at = received
            .received_at_ms
            .expect("the fixture page stamps every receive time");
        bytes.extend(ReceivedRecord::seal_line(&records_key(), at, &received.record).unwrap());
    }
    std::fs::write(records_path, bytes).unwrap();
    LocalTelemetryReader::for_state_dir(dir).with_records_key(records_key())
}

#[test]
fn the_reader_serves_the_committed_pages_and_the_cursor_continues_between_them() {
    let full = served_page("page-healthy-boot.json");
    let partial = served_page("records-page.json");
    let dir = tempfile::tempdir().unwrap();
    let reader = stage_records(dir.path(), &full.records);

    let first = reader
        .read(
            &TelemetryReadRequest::builder()
                .limit(partial.records.len())
                .build(),
        )
        .unwrap();
    assert_eq!(
        first, partial,
        "records-page.json is the reader's first page"
    );

    let rest = reader
        .read(
            &TelemetryReadRequest::builder()
                .cursor(first.next_cursor)
                .build(),
        )
        .unwrap();
    assert_eq!(rest.records, full.records[partial.records.len()..]);
    assert_eq!(rest.next_cursor, full.next_cursor);
    assert!(rest.exhausted);

    let whole = reader.read(&TelemetryReadRequest::default()).unwrap();
    assert_eq!(
        whole, full,
        "page-healthy-boot.json is the reader's whole stream"
    );
}

#[test]
fn the_reader_types_every_collector_snapshot_as_the_committed_status() {
    let path = vector("collector-status.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    for (index, line) in text.lines().enumerate() {
        let expected: TelemetryStatus =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {e}", index + 1));
        let dir = tempfile::tempdir().unwrap();
        let (status_path, _) = collector_files(dir.path());
        if let TelemetryStatus::Provisioned {
            vm_name,
            state,
            shed,
            ..
        } = &expected
        {
            let generation = match state {
                CollectorState::Collecting { generation } => Some(*generation),
                _ => None,
            };
            let snapshot = CollectorStatusSnapshot {
                vm_name: vm_name.clone(),
                status: state.label(),
                generation,
                shed: *shed,
                losses: Default::default(),
            };
            std::fs::write(&status_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        }
        let mut served = LocalTelemetryReader::for_state_dir(dir.path())
            .status()
            .unwrap();
        // The age is measured when the snapshot is read; the fixture leaves
        // it out because no committed value could match it.
        if let TelemetryStatus::Provisioned {
            snapshot_age_ms, ..
        } = &mut served
        {
            *snapshot_age_ms = None;
        }
        assert_eq!(
            served,
            expected,
            "collector-status.jsonl line {}",
            index + 1
        );
    }
}
