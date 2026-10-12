//! PackScenario wire witnesses. Digests here are shape fixtures.
use mvm_contract::pack_scenario::{PackScenario, PackScenarioError, ScenarioCheck};
use serde_json::{Value, json};

const MINIMAL: &str = include_str!("fixtures/pack-scenario-v1/minimal.json");

fn document() -> Value {
    serde_json::from_str(MINIMAL).unwrap()
}

fn scenario() -> PackScenario {
    serde_json::from_str(MINIMAL).unwrap()
}

/// The validation error a document is refused with. `try_from` carries the
/// typed error's message through serde, so the message names the variant.
fn refused(value: Value) -> PackScenarioError {
    let message = serde_json::from_value::<PackScenario>(value.clone())
        .expect_err("document should be refused")
        .to_string();
    ALL.into_iter()
        .find(|error| message.contains(&error.to_string()))
        .unwrap_or_else(|| panic!("unexpected refusal {message:?} for {value}"))
}

const ALL: [PackScenarioError; 11] = [
    PackScenarioError::Identity,
    PackScenarioError::Environment,
    PackScenarioError::Instructions,
    PackScenarioError::Path,
    PackScenarioError::Outputs,
    PackScenarioError::Limits,
    PackScenarioError::Checks,
    PackScenarioError::Uncollected,
    PackScenarioError::Pointer,
    PackScenarioError::Command,
    PackScenarioError::Serialization,
];

#[test]
fn golden_scenario_round_trips_and_has_a_stable_digest() {
    let scenario = scenario();
    let bytes = scenario.canonical_json().unwrap();
    let decoded: PackScenario = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(scenario, decoded);
    assert_eq!(bytes, decoded.canonical_json().unwrap());
    let digest = scenario.sha256().unwrap();
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(digest, decoded.sha256().unwrap());
}

#[test]
fn the_digest_changes_with_the_bound_environment() {
    let mut other = scenario();
    other.environment.bundle_sha256 = "5".repeat(64);
    assert_ne!(scenario().sha256().unwrap(), other.sha256().unwrap());
}

#[test]
fn every_field_is_required_and_unknown_fields_fail_at_every_level() {
    for field in document().as_object().unwrap().keys() {
        let mut value = document();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<PackScenario>(value).is_err(),
            "{field}"
        );
    }
    for pointer in [
        "",
        "/environment",
        "/limits",
        "/initial_files/0",
        "/checks/0",
        "/checks/3",
    ] {
        let mut value = document();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        assert!(
            serde_json::from_value::<PackScenario>(value).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn the_environment_must_name_an_exact_lowercase_archive_digest() {
    for digest in [
        "",
        "4444",
        &"A".repeat(64),
        &"g".repeat(64),
        &"4".repeat(65),
    ] {
        let mut value = document();
        value["environment"]["bundle_sha256"] = json!(digest);
        assert_eq!(refused(value), PackScenarioError::Environment, "{digest}");
    }
    let mut value = document();
    value["environment"]["identity"]["name"] = json!("no-namespace");
    assert_eq!(refused(value), PackScenarioError::Environment);
}

#[test]
fn every_path_refuses_traversal_absolute_and_host_spellings() {
    for bad in [
        "../x",
        "/etc/passwd",
        "a/../b",
        "a//b",
        "./a",
        "C:/x",
        "a\\b",
        "",
    ] {
        for pointer in [
            "/initial_files/0/source",
            "/initial_files/0/destination",
            "/outputs/0",
            "/checks/2/expected",
        ] {
            let mut value = document();
            *value.pointer_mut(pointer).unwrap() = json!(bad);
            assert!(
                serde_json::from_value::<PackScenario>(value).is_err(),
                "{pointer} = {bad:?}"
            );
        }
    }
}

#[test]
fn a_check_may_only_read_what_the_scenario_collects() {
    let mut value = document();
    value["checks"][0]["path"] = json!("repo/secret.txt");
    assert_eq!(refused(value), PackScenarioError::Uncollected);
    // A sibling whose name shares a prefix is not inside the output.
    let mut value = document();
    value["checks"][0]["path"] = json!("outside/result.json");
    assert_eq!(refused(value), PackScenarioError::Uncollected);
    assert!(scenario().collects("out/deep/file"));
    assert!(!scenario().collects("output"));
}

#[test]
fn outputs_are_required_and_must_not_overlap() {
    let mut value = document();
    value["outputs"] = json!([]);
    assert_eq!(refused(value), PackScenarioError::Outputs);
    let mut value = document();
    value["outputs"] = json!(["out", "out/result.json"]);
    assert_eq!(refused(value), PackScenarioError::Outputs);
}

#[test]
fn limits_must_be_positive_and_bounded() {
    for (field, bad) in [
        ("wall_clock_secs", json!(0)),
        ("wall_clock_secs", json!(86_401)),
        ("max_output_bytes", json!(0)),
        ("max_output_bytes", json!(256u64 * 1024 * 1024 + 1)),
        ("max_output_files", json!(0)),
        ("max_output_files", json!(65_537)),
    ] {
        let mut value = document();
        value["limits"][field] = bad;
        assert_eq!(refused(value), PackScenarioError::Limits, "{field}");
    }
}

#[test]
fn checks_are_required_uniquely_named_and_well_formed() {
    let mut value = document();
    value["checks"] = json!([]);
    assert!(serde_json::from_value::<PackScenario>(value).is_err());

    let mut value = document();
    value["checks"][1]["name"] = json!("wrote-result");
    assert_eq!(refused(value), PackScenarioError::Checks);

    let mut value = document();
    value["checks"][1]["pointer"] = json!("status");
    assert_eq!(refused(value), PackScenarioError::Pointer);

    for argv in [json!([]), json!([" "]), json!(["sh", "a\u{0}b"])] {
        let mut value = document();
        value["checks"][3]["argv"] = argv;
        assert_eq!(refused(value), PackScenarioError::Command);
    }
}

#[test]
fn instructions_are_bounded_and_identity_is_checked() {
    let mut value = document();
    value["instructions"] = json!("x".repeat(64 * 1024 + 1));
    assert_eq!(refused(value), PackScenarioError::Instructions);
    let mut value = document();
    value["version"] = json!("1.0");
    assert_eq!(refused(value), PackScenarioError::Identity);
    let mut value = document();
    value["name"] = json!("has space");
    assert_eq!(refused(value), PackScenarioError::Identity);
}

#[test]
fn the_document_carries_no_runnable_artifact() {
    // A scenario references its environment by digest and nothing else: no
    // kernel, rootfs, image, or bundle member can ride inside it.
    let fields: Vec<String> = document().as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        fields,
        [
            "checks",
            "environment",
            "initial_files",
            "instructions",
            "limits",
            "name",
            "outputs",
            "schema",
            "version"
        ]
    );
    let checks = &scenario().checks;
    assert!(matches!(checks[3], ScenarioCheck::Command { .. }));
    assert_eq!(checks[3].output_path(), None);
    assert_eq!(checks[2].expected_path(), Some("app.py"));
}
