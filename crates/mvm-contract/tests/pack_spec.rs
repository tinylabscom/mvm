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
        r#"{"copy":[{"destination":"/app/hello.txt","source":"hello.txt"}],"dependencies":[],"entrypoint":["cat","/app/hello.txt"],"identity":{"name":"acme/hello","version":"1.0.0"},"packages":[{"name":"busybox","scope":"runtime"}],"resources":{"cpu_cores":1,"memory_mb":128},"schema":"mvm.pack-spec/v1","source":{"kind":"local","path":"."},"target":"aarch64-linux"}"#
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
fn namespaced_identity_is_preserved_and_unsafe_coordinates_fail_closed() {
    for name in [
        "acme/csv-analysis",
        "runtime/python",
        "a.b/c_d",
        "0/1",
        &format!("{}/{}", "a".repeat(64), "b".repeat(64)),
    ] {
        let mut value = document();
        value["identity"]["name"] = json!(name);
        value["identity"]["version"] = json!("0.1.0");
        let spec: PackSpec = serde_json::from_value(value).unwrap();
        let normalized: Value = serde_json::from_slice(&spec.canonical_json().unwrap()).unwrap();
        assert_eq!(normalized["identity"]["name"], name);
    }
    for name in [
        "",
        "bare",
        "/name",
        "acme/",
        "acme//name",
        "a/b/c",
        "./name",
        "../name",
        "acme/.",
        "acme/..",
        "acme/../name",
        "Acme/name",
        "acme/name@",
        "acme/a\\b",
        "acme/a b",
        "acme/é",
        "acme/-name",
        "acme/name.",
        "acme/name\n",
        &format!("acme/{}", "a".repeat(65)),
    ] {
        let mut value = document();
        value["identity"]["name"] = json!(name);
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{name:?}"
        );
        let mut spec: PackSpec = serde_json::from_str(MINIMAL).unwrap();
        spec.identity.name = name.into();
        assert!(spec.canonical_json().is_err(), "{name:?}");
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
fn semver_accepts_suffixes_without_machine_integer_limits() {
    for version in [
        "0.1.0",
        "1.2.3-rc.1",
        "1.2.3+build.7",
        "1.2.3-0.01a.alpha-beta+001.build-7",
        "4294967296.0.0",
        "18446744073709551616.0.0",
        "1.2.3-18446744073709551616",
        "1.2.3--+--",
        &format!("{}.0.0", "9".repeat(124)),
    ] {
        let mut value = document();
        value["identity"]["version"] = json!(version);
        let spec: PackSpec = serde_json::from_value(value).unwrap();
        let normalized: Value = serde_json::from_slice(&spec.canonical_json().unwrap()).unwrap();
        assert_eq!(normalized["identity"]["version"], version);
    }
    for version in [
        "",
        "latest",
        "1",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-01",
        "1.2.3-rc.01",
        "1.2.3-",
        "1.2.3+",
        "1.2.3-a..b",
        "1.2.3+a..b",
        "1.2.3-.a",
        "1.2.3+a.",
        "1.2.3+a+b",
        "1.2.3-rc_1",
        "1.2.3+é",
        " 1.2.3",
        "1.2.3\n",
        "1.2.3+build\n",
        &format!("{}.0.0", "9".repeat(125)),
    ] {
        let mut value = document();
        value["identity"]["version"] = json!(version);
        assert!(
            serde_json::from_value::<PackSpec>(value).is_err(),
            "{version:?}"
        );
        let mut spec: PackSpec = serde_json::from_str(MINIMAL).unwrap();
        spec.identity.version = version.into();
        assert!(spec.canonical_json().is_err(), "{version:?}");
    }
    // Generic package version requests are deliberately not product SemVer.
    let mut value = document();
    value["packages"][0]["version"] = json!("2026.01-custom");
    assert!(serde_json::from_value::<PackSpec>(value).is_ok());
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
fn path_byte_limits_include_the_destination_root_slash() {
    let mut value = document();
    value["copy"][0]["destination"] = json!(format!("/{}", "é".repeat(2047)));
    assert!(serde_json::from_value::<PackSpec>(value.clone()).is_ok());
    value["copy"][0]["destination"] = json!(format!("/{}", "é".repeat(2048)));
    assert!(serde_json::from_value::<PackSpec>(value).is_err());

    let mut value = document();
    value["copy"][0]["destination"] = json!(format!("/{}", "a".repeat(4095)));
    assert!(serde_json::from_value::<PackSpec>(value.clone()).is_ok());
    value["copy"][0]["destination"] = json!(format!("/{}", "a".repeat(4096)));
    assert!(serde_json::from_value::<PackSpec>(value).is_err());
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
    let memory = &schema["definitions"]["PackResources"]["properties"]["memory_mb"];
    assert_eq!(memory["maximum"], 4294967295.0);
    assert!(
        memory["description"]
            .as_str()
            .unwrap()
            .contains("1_048_576 bytes")
    );
    let identity = &schema["definitions"]["PackIdentity"]["properties"];
    assert_eq!(identity["name"]["maxLength"], 129);
    assert_eq!(identity["version"]["maxLength"], 128);
}
