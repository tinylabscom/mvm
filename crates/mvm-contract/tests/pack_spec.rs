//! Shared wire witnesses. No source file is read and no package is installed.
use mvm_contract::pack_spec::PackSpec;
use serde_json::{Value, json};

const MINIMAL: &str = include_str!("fixtures/pack-spec-v1/minimal.json");
const CLAUDE: &str = include_str!("fixtures/pack-spec-v1/claude-style.json");
const PYTHON: &str = include_str!("fixtures/pack-spec-v1/python.json");

fn document() -> Value {
    serde_json::from_str(MINIMAL).unwrap()
}

#[test]
fn golden_documents_round_trip_without_installation_or_python_inference() {
    for fixture in [MINIMAL, CLAUDE, PYTHON] {
        let spec: PackSpec = serde_json::from_str(fixture).unwrap();
        spec.validate().unwrap();
        let bytes = spec.canonical_json().unwrap();
        let decoded: PackSpec = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(spec, decoded);
        assert_eq!(bytes, decoded.canonical_json().unwrap());
    }
    let spec: PackSpec = serde_json::from_str(CLAUDE).unwrap();
    assert!(spec.packages.is_empty());
    assert!(spec.dependencies.is_empty());
    assert_eq!(spec.entrypoint, ["/app/bin/claude", "--version"]);
    let minimal: PackSpec = serde_json::from_str(MINIMAL).unwrap();
    assert!(minimal.dependencies.is_empty());
}

#[test]
fn canonical_bytes_are_language_neutral_and_preserve_semantic_order() {
    let spec: PackSpec = serde_json::from_str(MINIMAL).unwrap();
    assert_eq!(
        String::from_utf8(spec.canonical_json().unwrap()).unwrap(),
        r#"{"copy":[{"destination":"/app/hello.txt","source":"hello.txt"}],"dependencies":[],"entrypoint":["cat","/app/hello.txt"],"identity":{"name":"hello","version":"1.0.0"},"packages":[{"name":"busybox","scope":"runtime"}],"resources":{"cpu_cores":1,"memory_mb":128},"schema":"mvm.pack-spec/v1","source":{"kind":"local","path":"."},"target":"aarch64-linux"}"#
    );
    let mut nullable = document();
    nullable["packages"][0]["version"] = Value::Null;
    assert_eq!(
        spec.canonical_json().unwrap(),
        serde_json::from_value::<PackSpec>(nullable)
            .unwrap()
            .canonical_json()
            .unwrap()
    );
    let original: PackSpec = serde_json::from_str(PYTHON).unwrap();
    for list in ["packages", "dependencies", "copy", "entrypoint"] {
        let mut reversed: Value = serde_json::from_str(PYTHON).unwrap();
        reversed[list].as_array_mut().unwrap().swap(0, 1);
        let reversed: PackSpec = serde_json::from_value(reversed).unwrap();
        assert_ne!(
            original.canonical_json().unwrap(),
            reversed.canonical_json().unwrap(),
            "{list}"
        );
    }
}

#[test]
fn required_and_unknown_fields_are_rejected_at_every_level() {
    for field in document().as_object().unwrap().keys() {
        let mut value = document();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{field}"
        );
    }
    let python: Value = serde_json::from_str(PYTHON).unwrap();
    for pointer in [
        "",
        "/identity",
        "/source",
        "/packages/0",
        "/dependencies/0",
        "/copy/0",
        "/resources",
    ] {
        let mut value = python.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unsupported".into(), json!(true));
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn rejects_invalid_schema_target_identity_packages_argv_and_resources() {
    for (pointer, invalid) in [
        ("/schema", json!("mvm.pack-spec/v2")),
        ("/target", json!("host")),
        ("/source/kind", json!("oci")),
        ("/identity/name", json!("../escape")),
        ("/identity/name", json!("Uppercase")),
        ("/identity/version", json!("latest")),
        ("/identity/version", json!("01.2.3")),
        ("/identity/version", json!("4294967296.0.0")),
        ("/packages/0/name", json!("python3;echo")),
        ("/packages/0/scope", json!("global")),
        ("/entrypoint", json!([])),
        ("/entrypoint", json!([""])),
        ("/entrypoint", json!([" \t"])),
        ("/entrypoint", json!(["echo", "\0"])),
        ("/resources/cpu_cores", json!(0)),
        ("/resources/cpu_cores", json!(65536)),
        ("/resources/cpu_cores", json!(1.5)),
        ("/resources/memory_mb", json!(0)),
        ("/resources/memory_mb", json!(-1)),
        ("/resources/memory_mb", json!(4294967296u64)),
    ] {
        let mut value = document();
        *value.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{pointer}"
        );
    }
    for invalid in ["", "*", ">=3", "1 2", "1;echo", "x".repeat(129).as_str()] {
        let mut value = document();
        value["packages"][0]["version"] = json!(invalid);
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn paths_are_portable_and_fail_closed_without_filesystem_access() {
    for pointer in [
        "/source/path",
        "/copy/0/source",
        "/dependencies/0/manifest",
        "/dependencies/0/lockfile",
    ] {
        for bad in [
            "",
            "/etc/passwd",
            "../escape",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            "C:/a",
            "a\\b",
            "a\0b",
            "a\nb",
        ] {
            let mut value: Value = serde_json::from_str(PYTHON).unwrap();
            *value.pointer_mut(pointer).unwrap() = json!(bad);
            assert!(
                serde_json::from_value::<PackSpec>(value).is_err(),
                "{pointer}: {bad:?}"
            );
        }
    }
    for bad in ["/", "relative", "/../etc", "//app", "/app/./x", "/app\\x"] {
        let mut value = document();
        value["copy"][0]["destination"] = json!(bad);
        assert!(serde_json::from_value::<PackSpec>(value).is_err(), "{bad}");
    }
}

#[test]
fn direct_construction_is_checked_before_normalization() {
    let mut spec: PackSpec = serde_json::from_str(MINIMAL).unwrap();
    spec.resources.cpu_cores = 0;
    assert!(spec.validate().is_err());
    assert!(spec.canonical_json().is_err());
}

#[cfg(feature = "schema")]
#[test]
fn schema_is_closed_and_requires_explicit_target_and_positive_resources() {
    let schema = serde_json::to_value(schemars::schema_for!(PackSpec)).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("target"))
    );
    assert_eq!(
        schema["definitions"]["PackResources"]["properties"]["cpu_cores"]["minimum"],
        1.0
    );
    assert_eq!(
        schema["definitions"]["PackSpecSchema"]["enum"],
        json!(["mvm.pack-spec/v1"])
    );
}
