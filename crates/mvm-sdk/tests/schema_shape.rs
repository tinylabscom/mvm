use mvm_sdk::ir::{Workload, canonicalize};
use schemars::schema_for;
use serde_json::Value;

#[test]
fn schema_generation_is_idempotent_under_canonicalize() {
    let a = canonicalize(&schema_for!(Workload)).unwrap();
    let b = canonicalize(&schema_for!(Workload)).unwrap();
    assert_eq!(a, b);
}

#[test]
fn canonical_schema_re_canonicalizes_to_itself() {
    let once = canonicalize(&schema_for!(Workload)).unwrap();
    let parsed: Value = serde_json::from_str(&once).unwrap();
    let twice = canonicalize(&parsed).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn schema_declares_closed_world_at_root() {
    let schema = schema_for!(Workload);
    let json = serde_json::to_value(&schema).unwrap();
    assert_eq!(json["additionalProperties"], Value::Bool(false));
}

#[test]
fn schema_defines_all_top_level_types() {
    let schema = schema_for!(Workload);
    let json = serde_json::to_value(&schema).unwrap();
    let defs = json["definitions"].as_object().expect("definitions object");
    for ty in [
        "App",
        "Source",
        "Image",
        "Entrypoint",
        "EnvValue",
        "Mount",
        "MountSource",
        "MountMode",
        "Network",
        "NetworkMode",
        "PortForward",
        "PortProto",
        "Resources",
        "Volume",
        "SecretRef",
        "SecretMount",
    ] {
        assert!(defs.contains_key(ty), "schema missing definition for {ty}");
    }
}
