use std::collections::BTreeMap;

use mvm_client::{MachineId, MachineState, MachineStatus};
use mvm_runtime::machine::persist::{MACHINE_SPEC_SCHEMA_VERSION, MachineSpec};

use super::*;

fn spec(name: &str) -> MachineSpec {
    MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: name.to_string(),
        image: Some("alpine:latest".to_string()),
        manifest: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: vec![],
        init: vec![],
        agent_verb: vec![],
        created_at: None,
        last_started_at: None,
        health_check: None,
    }
}

fn live(name: &str, status: MachineStatus) -> MachineState {
    MachineState {
        id: MachineId(name.to_string()),
        name: name.to_string(),
        status,
        ..Default::default()
    }
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-07-31T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// The whole point of the unified listing: a persistent machine and a
/// transient VM are two stores, and both must appear.
#[test]
fn join_lists_persistent_specs_and_leftover_live_vms() {
    let listed = join_by_name(
        vec![spec("web")],
        vec![
            live("web", MachineStatus::Running),
            live("adhoc", MachineStatus::Running),
        ],
    );

    let kinds: Vec<_> = listed.iter().map(|m| (m.name.as_str(), m.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            ("web", MachineKind::Persistent),
            ("adhoc", MachineKind::Transient)
        ]
    );
}

/// A spec joins to its live row, so a booted persistent machine reports the
/// backend's status rather than defaulting to stopped.
#[test]
fn a_booted_spec_carries_its_live_state() {
    let listed = join_by_name(vec![spec("web")], vec![live("web", MachineStatus::Running)]);

    assert_eq!(listed.len(), 1, "the spec and its live row are one machine");
    assert_eq!(listed[0].status(), "running");
}

/// A persistent machine exists whether or not it is booted; hiding it would
/// lose the only record of it.
#[test]
fn a_stopped_persistent_machine_is_listed_by_default() {
    let listed = join_by_name(vec![spec("web")], vec![]);

    assert!(passes_filters(
        &listed[0],
        false,
        &BTreeMap::new(),
        false,
        now()
    ));
}

/// A transient machine exists only while it runs, so a stopped one is
/// leftover state — hidden unless `--all`.
#[test]
fn a_stopped_transient_machine_is_hidden_without_all() {
    let listed = join_by_name(vec![], vec![live("adhoc", MachineStatus::Stopped)]);

    assert!(!passes_filters(
        &listed[0],
        false,
        &BTreeMap::new(),
        false,
        now()
    ));
    assert!(
        passes_filters(&listed[0], true, &BTreeMap::new(), false, now()),
        "--all reveals it"
    );
}

#[test]
fn a_running_transient_machine_is_listed_by_default() {
    let listed = join_by_name(vec![], vec![live("adhoc", MachineStatus::Running)]);

    assert!(passes_filters(
        &listed[0],
        false,
        &BTreeMap::new(),
        false,
        now()
    ));
}

#[test]
fn tag_filter_drops_a_machine_without_the_tag() {
    let mut tagged = live("adhoc", MachineStatus::Running);
    tagged.tags.insert("env".into(), "prod".into());
    let listed = join_by_name(vec![], vec![tagged]);

    let mut want = BTreeMap::new();
    want.insert("env".to_string(), "prod".to_string());
    assert!(passes_filters(&listed[0], false, &want, false, now()));

    want.insert("env".to_string(), "dev".to_string());
    assert!(!passes_filters(&listed[0], false, &want, false, now()));
}

#[test]
fn an_expired_machine_is_hidden_unless_asked_for() {
    let mut expiring = live("adhoc", MachineStatus::Running);
    expiring.expires_at = Some("2026-07-31T11:00:00Z".to_string());
    let listed = join_by_name(vec![], vec![expiring]);

    assert!(!passes_filters(
        &listed[0],
        false,
        &BTreeMap::new(),
        false,
        now()
    ));
    assert!(passes_filters(
        &listed[0],
        false,
        &BTreeMap::new(),
        true,
        now()
    ));
}

/// SDK facades parse `machine ls --json`: the Rust `SubprocessBackend` reads
/// `name` + `status`, and `Sandbox.connect(id)` reads `build_mode` to inherit
/// the dev-only exec guard. The persisted spec stays flattened at the top
/// level. Breaking any of that breaks attach across all three SDKs.
#[test]
fn json_row_keeps_the_shape_the_sdks_parse() {
    let listed = join_by_name(vec![spec("web")], vec![live("web", MachineStatus::Running)]);
    let row = json_row(&listed[0], now()).expect("serialize");
    let obj = row.as_object().expect("row is an object");

    assert_eq!(obj["name"], "web");
    assert_eq!(
        obj["status"], "running",
        "status is the snake_case wire form"
    );
    assert!(
        obj["build_mode"] == "dev" || obj["build_mode"] == "prod",
        "build_mode gates the dev-only exec path, got {:?}",
        obj["build_mode"]
    );
    // Spec fields are flattened, not nested under a `spec` key.
    assert_eq!(obj["image"], "alpine:latest");
    assert_eq!(obj["schema_version"], MACHINE_SPEC_SCHEMA_VERSION);
    assert!(!obj.contains_key("spec"));
    assert_eq!(obj["kind"], "persistent");
}

/// A transient machine has no spec to flatten, but must still carry the
/// fields the SDKs read — including a fail-closed `build_mode`.
#[test]
fn json_row_for_a_transient_machine_carries_the_common_fields() {
    let listed = join_by_name(vec![], vec![live("adhoc", MachineStatus::Running)]);
    let row = json_row(&listed[0], now()).expect("serialize");
    let obj = row.as_object().expect("row is an object");

    assert_eq!(obj["name"], "adhoc");
    assert_eq!(obj["status"], "running");
    assert_eq!(
        obj["build_mode"], "prod",
        "no runtime meta means no dev exec"
    );
    assert_eq!(obj["kind"], "transient");
    assert!(!obj.contains_key("image"), "there is no spec to flatten");
}

#[test]
fn table_renders_a_header_and_one_row_per_machine() {
    let listed = join_by_name(
        vec![spec("web")],
        vec![
            live("web", MachineStatus::Running),
            live("adhoc", MachineStatus::Running),
        ],
    );
    let table = format_table(&listed, now());
    let lines: Vec<&str> = table.lines().collect();

    assert_eq!(lines.len(), 3, "header + two machines");
    assert!(lines[0].starts_with("NAME"));
    assert!(lines[0].contains("KIND"));
    assert!(lines[1].contains("web") && lines[1].contains("persistent"));
    assert!(lines[2].contains("adhoc") && lines[2].contains("transient"));
}

/// Columns pad to their widest cell, so a long name does not ragged the rest.
#[test]
fn table_columns_align_across_rows() {
    let listed = join_by_name(vec![spec("a-very-long-machine-name"), spec("b")], vec![]);
    let table = format_table(&listed, now());
    let lines: Vec<&str> = table.lines().collect();

    let kind_col = |line: &str| line.find("persistent").expect("kind cell");
    assert_eq!(kind_col(lines[1]), kind_col(lines[2]));
}
