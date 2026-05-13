use mvm_ir::{
    App, Concurrency, Entrypoint, Format, Image, InProcessMode, Resources, Source,
    WarmProcessConfig, Workload, canonicalize, validate_schema_version,
};

fn sample_workload() -> Workload {
    Workload {
        schema_version: "0.1".to_string(),
        id: "hello".to_string(),
        apps: vec![App {
            name: "hello".to_string(),
            source: Source::LocalPath {
                path: ".".to_string(),
                include: vec!["**".to_string()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".to_string()],
            },
            entrypoints: vec![Entrypoint::Command {
                command: vec!["python".to_string(), "-m".to_string(), "hello".to_string()],
                working_dir: "/app".to_string(),
                env: Default::default(),
            }],
            env: Default::default(),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 256,
                rootfs_size_mb: 512,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
        }],
        volumes: vec![],
        extensions: Default::default(),
    }
}

#[test]
fn round_trip_is_byte_identical_after_canonicalize() {
    let w = sample_workload();
    let once = canonicalize(&w).expect("canonicalize");
    let parsed: Workload = serde_json::from_str(&once).expect("deserialize");
    let twice = canonicalize(&parsed).expect("canonicalize");
    assert_eq!(once, twice);
}

#[test]
fn sample_workload_declares_supported_version() {
    let w = sample_workload();
    validate_schema_version(&w.schema_version).expect("version supported");
}

#[test]
fn rejects_unknown_fields_at_root() {
    let bad = r#"{
        "schema_version": "0.1",
        "id": "x",
        "apps": [],
        "nope": true
    }"#;
    let err = serde_json::from_str::<Workload>(bad).unwrap_err();
    assert!(
        err.to_string().contains("unknown field"),
        "expected unknown-field error, got: {err}"
    );
}

#[test]
fn rejects_unknown_fields_in_nested_types() {
    let bad = r#"{
        "schema_version": "0.1",
        "id": "x",
        "apps": [{
            "name": "a",
            "source": { "kind": "local_path", "path": "." },
            "image": { "kind": "nix_packages", "packages": [] },
            "entrypoints": [{ "kind": "command", "command": ["true"], "bogus": 1 }],
            "resources": { "cpu_cores": 1, "memory_mb": 64, "rootfs_size_mb": 128 }
        }]
    }"#;
    let err = serde_json::from_str::<Workload>(bad).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn rejects_reserved_source_kind_is_handled_by_host_not_serde() {
    let reserved = r#"{
        "schema_version": "0.1",
        "id": "x",
        "apps": [{
            "name": "a",
            "source": { "kind": "nix_derivation", "expr": "..." },
            "image": { "kind": "nix_packages", "packages": [] },
            "entrypoints": [{ "kind": "command", "command": ["true"] }],
            "resources": { "cpu_cores": 1, "memory_mb": 64, "rootfs_size_mb": 128 }
        }]
    }"#;
    let w: Workload = serde_json::from_str(reserved).expect("reserved source kinds parse");
    match &w.apps[0].source {
        Source::NixDerivation { .. } => {}
        other => panic!("expected NixDerivation variant, got {other:?}"),
    }
}

fn warm_process_workload() -> Workload {
    Workload {
        schema_version: "0.1".to_string(),
        id: "adder".to_string(),
        apps: vec![App {
            name: "adder".to_string(),
            source: Source::LocalPath {
                path: ".".to_string(),
                include: vec!["**".to_string()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".to_string()],
            },
            entrypoints: vec![Entrypoint::Function {
                language: "python".to_string(),
                module: "adder".to_string(),
                function: "add".to_string(),
                format: Format::Json,
                working_dir: "/app".to_string(),
                env: Default::default(),
                args_schema: None,
                return_schema: None,
                extra_imports: vec![],
                primary: true,
                concurrency: Some(Concurrency::WarmProcess(WarmProcessConfig {
                    max_calls_per_worker: 1000,
                    max_rss_mb: 256,
                    pool_size: 1,
                    in_process: InProcessMode::Serial,
                    max_queue_depth: None,
                })),
            }],
            env: Default::default(),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 512,
                rootfs_size_mb: 1024,
            },
            dependencies: Some(mvm_ir::Dependencies::None),
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
        }],
        volumes: vec![],
        extensions: Default::default(),
    }
}

#[test]
fn warm_process_round_trip_is_byte_identical() {
    let w = warm_process_workload();
    let once = canonicalize(&w).expect("canonicalize");
    let parsed: Workload = serde_json::from_str(&once).expect("deserialize");
    let twice = canonicalize(&parsed).expect("canonicalize");
    assert_eq!(once, twice);
}

#[test]
fn warm_process_concurrency_emits_canonical_block() {
    let canonical = canonicalize(&warm_process_workload()).expect("canonicalize");
    assert!(
        canonical.contains("\"concurrency\""),
        "canonical={canonical}"
    );
    assert!(canonical.contains("\"kind\":\"warm_process\""));
    assert!(canonical.contains("\"max_calls_per_worker\":1000"));
    assert!(canonical.contains("\"in_process\":\"serial\""));
    assert!(
        !canonical.contains("\"max_queue_depth\""),
        "max_queue_depth=None must skip-serialize: {canonical}"
    );
}

#[test]
fn rejects_unknown_field_in_concurrency_block() {
    let bad = r#"{
        "schema_version": "0.1",
        "id": "x",
        "apps": [{
            "name": "a",
            "source": { "kind": "local_path", "path": "." },
            "image": { "kind": "nix_packages", "packages": [] },
            "entrypoints": [{
                "kind": "function",
                "language": "python",
                "module": "m",
                "function": "f",
                "format": "json",
                "primary": true,
                "concurrency": {
                    "kind": "warm_process",
                    "max_calls_per_worker": 1000,
                    "max_rss_mb": 256,
                    "pool_size": 1,
                    "in_process": "serial",
                    "bogus": 42
                }
            }],
            "resources": { "cpu_cores": 1, "memory_mb": 512, "rootfs_size_mb": 1024 },
            "dependencies": { "kind": "none" }
        }]
    }"#;
    let err = serde_json::from_str::<Workload>(bad).unwrap_err();
    assert!(
        err.to_string().contains("unknown field"),
        "expected unknown-field error, got: {err}"
    );
}

#[test]
fn rejects_unknown_concurrency_kind() {
    let bad = r#"{
        "schema_version": "0.1",
        "id": "x",
        "apps": [{
            "name": "a",
            "source": { "kind": "local_path", "path": "." },
            "image": { "kind": "nix_packages", "packages": [] },
            "entrypoints": [{
                "kind": "function",
                "language": "python",
                "module": "m",
                "function": "f",
                "format": "json",
                "primary": true,
                "concurrency": { "kind": "future_tier" }
            }],
            "resources": { "cpu_cores": 1, "memory_mb": 512, "rootfs_size_mb": 1024 },
            "dependencies": { "kind": "none" }
        }]
    }"#;
    let err = serde_json::from_str::<Workload>(bad).unwrap_err();
    assert!(
        err.to_string().contains("unknown variant")
            || err.to_string().contains("did not match any variant"),
        "expected unknown-variant error, got: {err}"
    );
}

#[test]
fn canonical_output_sorts_keys_across_nested_maps() {
    let w = sample_workload();
    let canonical = canonicalize(&w).unwrap();
    let schema_pos = canonical.find("\"schema_version\"").unwrap();
    let apps_pos = canonical.find("\"apps\"").unwrap();
    let id_pos = canonical.find("\"id\"").unwrap();
    assert!(
        apps_pos < id_pos && id_pos < schema_pos,
        "expected alphabetical key order in canonical output, got:\n{canonical}"
    );
}
