//! Schema-shape assertions for the emitted JSON Schemas.
//!
//! Requires the `schema` feature, which is what turns on the `JsonSchema`
//! derives these tests generate from. CI runs it as its own lane.
#![cfg(feature = "schema")]

use mvm_sdk::ir::{Workload, canonicalize};
use mvm_sdk::runtime::{RuntimeFsEntry, RuntimeFsStat, RuntimeProcessEvent, RuntimeProcessResult};
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

#[test]
fn runtime_contract_types_are_closed_and_schemaable() {
    for schema in [
        serde_json::to_value(schema_for!(RuntimeFsEntry)).unwrap(),
        serde_json::to_value(schema_for!(RuntimeFsStat)).unwrap(),
        serde_json::to_value(schema_for!(RuntimeProcessEvent)).unwrap(),
        serde_json::to_value(schema_for!(RuntimeProcessResult)).unwrap(),
    ] {
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
    }
}
