use mvm_client::inventory::{InventoryQuery, MachineInventoryRecord, MachineKind, WorkloadPosture};
use mvm_client::{MachineStatus, PortMapping};

use super::super::MachineListArgs;
use super::*;

fn record(name: &str, kind: MachineKind, status: MachineStatus) -> MachineInventoryRecord {
    MachineInventoryRecord::builder(name, kind)
        .status(status)
        .build()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-07-31T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn args() -> MachineListArgs {
    MachineListArgs {
        json: false,
        all: false,
        tags: vec![],
        show_expired: false,
    }
}

/// The CLI flags map one-to-one onto the shared visibility query, so `machine
/// ls` and a non-CLI consumer filtering the same inventory agree exactly.
#[test]
fn flags_map_onto_the_shared_query() {
    let query = query_from_args(&args()).expect("default query");
    assert_eq!(query, InventoryQuery::active());

    let mut all = args();
    all.all = true;
    all.show_expired = true;
    all.tags = vec!["env=prod".to_string()];
    let query = query_from_args(&all).expect("query with flags");
    assert!(query.include_stopped_transient);
    assert!(query.include_expired);
    assert_eq!(query.tags.get("env").map(String::as_str), Some("prod"));
}

#[test]
fn a_malformed_tag_flag_is_rejected() {
    let mut bad = args();
    // Spaces are outside the validated tag-key charset.
    bad.tags = vec!["bad key=1".to_string()];
    let err = query_from_args(&bad).expect_err("invalid tag");
    assert!(err.to_string().contains("Invalid --tag"), "{err}");
}

/// SDK facades parse `machine ls --json`: the Rust `SubprocessBackend` reads
/// `name` + `status`, and `Sandbox.connect(id)` reads `build_mode` to inherit
/// the dev-only exec guard. Those keys ride on the shared inventory record,
/// so the CLI JSON and the mvm-client inventory are one shape.
#[test]
fn json_rows_keep_the_keys_the_sdks_parse() {
    let r = record("web", MachineKind::Persistent, MachineStatus::Running);
    let obj = serde_json::to_value(&r).expect("serialize");

    assert_eq!(obj["name"], "web");
    assert_eq!(
        obj["status"], "running",
        "status is the snake_case wire form"
    );
    assert_eq!(
        obj["build_mode"], "prod",
        "posture is fail-closed prod unless explicitly dev"
    );
    assert_eq!(obj["kind"], "persistent");
}

/// A transient machine carries the same fields — including the fail-closed
/// `build_mode` — with no spec-derived extras.
#[test]
fn json_row_for_a_transient_machine_is_fail_closed() {
    let r = record("adhoc", MachineKind::Transient, MachineStatus::Running);
    let obj = serde_json::to_value(&r).expect("serialize");

    assert_eq!(obj["name"], "adhoc");
    assert_eq!(
        obj["build_mode"], "prod",
        "no runtime meta means no dev exec"
    );
    assert_eq!(obj["kind"], "transient");
    assert!(
        obj["created_at"].is_null(),
        "no definition, no creation time"
    );
}

/// The status cell keeps a failure's reason visible instead of dropping it,
/// while `--json` consumers get the typed `status` + `status_detail` pair.
#[test]
fn status_cell_appends_the_failure_reason() {
    let mut failed = record("adhoc", MachineKind::Transient, MachineStatus::Failed);
    failed.status_detail = Some("boot wedged".to_string());
    assert_eq!(status_cell(&failed), "failed (boot wedged)");

    let paused = record("web", MachineKind::Persistent, MachineStatus::Paused);
    assert_eq!(status_cell(&paused), "paused");

    // A failed machine with no recorded reason renders the bare label.
    let bare = record("adhoc", MachineKind::Transient, MachineStatus::Failed);
    assert_eq!(status_cell(&bare), "failed");
}

#[test]
fn table_renders_a_header_and_one_row_per_machine() {
    let dev = MachineInventoryRecord::builder("web", MachineKind::Persistent)
        .status(MachineStatus::Running)
        .build_mode(WorkloadPosture::Dev)
        .source(Some("alpine:latest".to_string()))
        .backend(Some("firecracker".to_string()))
        .ports(vec![PortMapping {
            host: 8080,
            guest: 80,
        }])
        .build();
    let adhoc = record("adhoc", MachineKind::Transient, MachineStatus::Running);
    let table = format_table(&[dev, adhoc], now());
    let lines: Vec<&str> = table.lines().collect();

    assert_eq!(lines.len(), 3, "header + two machines");
    assert!(lines[0].starts_with("NAME"));
    assert!(lines[0].contains("KIND"));
    assert!(lines[1].contains("web") && lines[1].contains("persistent"));
    assert!(lines[1].contains("8080→80") && lines[1].contains("alpine:latest"));
    assert!(lines[2].contains("adhoc") && lines[2].contains("transient"));
    assert!(lines[2].contains(" - "), "unbooted fields render as dashes");
}

/// Columns pad to their widest cell, so a long name does not ragged the rest.
#[test]
fn table_columns_align_across_rows() {
    let a = record(
        "a-very-long-machine-name",
        MachineKind::Persistent,
        MachineStatus::Stopped,
    );
    let b = record("b", MachineKind::Persistent, MachineStatus::Stopped);
    let table = format_table(&[a, b], now());
    let lines: Vec<&str> = table.lines().collect();

    let kind_col = |line: &str| line.find("persistent").expect("kind cell");
    assert_eq!(kind_col(lines[1]), kind_col(lines[2]));
}
