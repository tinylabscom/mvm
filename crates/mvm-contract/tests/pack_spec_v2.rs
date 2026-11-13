use mvm_contract::pack_spec::PackSpec;
use mvm_contract::pack_spec_v2::{BuildMode, ComposablePackError, ComposablePackSpec};
use serde_json::{Value, json};

fn document() -> Value {
    json!({
        "schema": "mvm.pack-spec/v2",
        "identity": {"name": "agent/example", "version": "1.0.0"},
        "target": "aarch64-linux",
        "source": {"kind": "local", "path": "."},
        "runtimes": ["runtime/python@1.2.0"],
        "copy": [{"source": "main.py", "destination": "/srv/app/main.py"}],
        "entrypoint": ["/usr/bin/python3", "/srv/app/main.py"],
        "resources": {"cpu_cores": 1, "memory_mb": 256}
    })
}

#[test]
fn toml_and_json_are_one_closed_neutral_contract() {
    let spec: ComposablePackSpec = serde_json::from_value(document()).unwrap();
    assert_eq!(spec.check_mode_request(BuildMode::Development), Ok(()));
    assert_eq!(
        spec.check_mode_request(BuildMode::Production),
        Err(ComposablePackError::ProductionNotSelected)
    );
    assert!(serde_json::from_value::<PackSpec>(document()).is_err());
    let mut legacy_schema = document();
    legacy_schema["schema"] = json!("mvm.pack-spec/v1");
    assert!(serde_json::from_value::<ComposablePackSpec>(legacy_schema).is_err());
    let mut foreign_source = document();
    foreign_source["source"] =
        json!({"kind": "yocto", "archive": "rootfs.tar.gz", "inputs": "inputs.json"});
    assert!(serde_json::from_value::<ComposablePackSpec>(foreign_source).is_err());

    let toml = r#"
schema = "mvm.pack-spec/v2"
target = "aarch64-linux"
runtimes = ["runtime/python@1.2.0"]
entrypoint = ["/usr/bin/python3", "/srv/app/main.py"]

[identity]
name = "agent/example"
version = "1.0.0"

[source]
kind = "local"
path = "."

[[copy]]
source = "main.py"
destination = "/srv/app/main.py"

[resources]
cpu_cores = 1
memory_mb = 256
"#;
    let from_toml: ComposablePackSpec = toml::from_str(toml).unwrap();
    assert_eq!(
        from_toml.canonical_json().unwrap(),
        spec.canonical_json().unwrap()
    );
    let selected: ComposablePackSpec = toml::from_str(&format!("{toml}\n[production]\n")).unwrap();
    assert_eq!(selected.check_mode_request(BuildMode::Production), Ok(()));
    assert_eq!(selected.check_mode_request(BuildMode::Development), Ok(()));
    assert!(serde_json::from_value::<PackSpec>(serde_json::to_value(selected).unwrap()).is_err());
}

#[test]
fn unknown_authority_and_unsafe_application_paths_are_refused() {
    for key in ["net", "ssh", "host_mount", "port_forward", "signing_key"] {
        let mut value = document();
        value[key] = json!(true);
        assert!(
            serde_json::from_value::<ComposablePackSpec>(value).is_err(),
            "{key}"
        );
    }
    for bad in [
        "/etc/mvm/entrypoint",
        "/srv/app/../main.py",
        "srv/app/main.py",
        "/srv/app/",
    ] {
        let mut value = document();
        value["copy"][0]["destination"] = json!(bad);
        assert!(
            serde_json::from_value::<ComposablePackSpec>(value).is_err(),
            "{bad}"
        );
    }
    for bad in ["python3", "/usr/bin/../bin/sh", "/", "//usr/bin/python3"] {
        let mut value = document();
        value["entrypoint"][0] = json!(bad);
        assert!(
            serde_json::from_value::<ComposablePackSpec>(value).is_err(),
            "{bad}"
        );
    }
    let mut value = document();
    value["production"] = json!({"net": true});
    assert!(serde_json::from_value::<ComposablePackSpec>(value).is_err());
    let mut value = document();
    value["identity"]["version"] = json!("1.0.0+local");
    assert!(serde_json::from_value::<ComposablePackSpec>(value).is_err());
}

#[test]
fn runtime_coordinates_remain_requests_until_exact_pins_are_resolved() {
    for runtimes in [
        json!(["agent/claude@1.0.0"]),
        json!(["runtime/python@latest"]),
        json!(["runtime/python@1.0.0+local"]),
        json!(["runtime/python", "runtime/python@2.0.0"]),
        json!(
            (0..17)
                .map(|i| format!("runtime/lang{i}"))
                .collect::<Vec<_>>()
        ),
    ] {
        let mut value = document();
        value["runtimes"] = runtimes.clone();
        assert!(
            serde_json::from_value::<ComposablePackSpec>(value).is_err(),
            "{runtimes}"
        );
    }
    let mut value = document();
    value["runtimes"] = json!(["runtime/python"]);
    assert!(serde_json::from_value::<ComposablePackSpec>(value).is_ok());
}

#[test]
fn directly_constructed_specs_keep_resource_bounds() {
    let mut spec: ComposablePackSpec = serde_json::from_value(document()).unwrap();
    spec.copy = vec![spec.copy[0].clone(); 1025];
    assert_eq!(spec.validate(), Err(ComposablePackError::Path));
    spec.copy.clear();
    spec.entrypoint = vec!["/usr/bin/python3".into(); 129];
    assert_eq!(spec.validate(), Err(ComposablePackError::Entrypoint));
    spec.entrypoint = vec!["/usr/bin/python3".into(), "x".repeat(16 * 1024)];
    assert_eq!(spec.validate(), Err(ComposablePackError::Entrypoint));
}
