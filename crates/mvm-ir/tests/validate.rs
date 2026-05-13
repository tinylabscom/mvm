use mvm_ir::{
    App, Concurrency, Entrypoint, EnvValue, ErrorCode, Format, HostPort, Image, InProcessMode,
    Network, NetworkEgress, NetworkMode, PortForward, PortProto, Resources, SecretMount, SecretRef,
    Source, Volume, WarmProcessConfig, Workload, validate,
};

fn base_app() -> App {
    App {
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
    }
}

fn base_workload() -> Workload {
    Workload {
        schema_version: "0.1".to_string(),
        id: "hello".to_string(),
        apps: vec![base_app()],
        volumes: vec![],
        extensions: Default::default(),
    }
}

#[test]
fn base_workload_validates() {
    validate(&base_workload()).unwrap();
}

#[test]
fn rejects_unsupported_major() {
    let mut w = base_workload();
    w.schema_version = "1.0".to_string();
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].code, ErrorCode::UnsupportedMajor);
    assert_eq!(errs[0].path, ".schema_version");
}

#[test]
fn rejects_minor_too_high() {
    let mut w = base_workload();
    w.schema_version = "0.9".to_string();
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::MinorTooHigh);
}

#[test]
fn rejects_malformed_version() {
    let mut w = base_workload();
    w.schema_version = "not-a-version".to_string();
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::MalformedVersion);
}

#[test]
fn rejects_empty_apps() {
    let mut w = base_workload();
    w.apps.clear();
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::EmptyApps);
    assert_eq!(errs[0].path, ".apps");
}

#[test]
fn rejects_multi_app() {
    let mut w = base_workload();
    w.apps.push(base_app());
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::MultiAppDeferred);
}

#[test]
fn rejects_reserved_source_kinds() {
    for reserved in [
        Source::NixDerivation {
            expr: "x".to_string(),
        },
        Source::OciImage {
            reference: "r".to_string(),
            digest: "d".to_string(),
        },
    ] {
        let mut w = base_workload();
        w.apps[0].source = reserved;
        let errs = validate(&w).unwrap_err();
        assert_eq!(errs[0].code, ErrorCode::SourceKindDeferred);
        assert_eq!(errs[0].path, ".apps[0].source.kind");
    }
}

#[test]
fn rejects_secret_ref_in_app_env() {
    let mut w = base_workload();
    w.apps[0].env.insert(
        "TOKEN".to_string(),
        EnvValue::SecretRef {
            reference: SecretRef {
                name: "api-token".to_string(),
                mount: SecretMount::Env {
                    var: "TOKEN".to_string(),
                },
            },
        },
    );
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::SecretsNotImplemented);
    assert_eq!(errs[0].path, ".apps[0].env.TOKEN");
}

#[test]
fn rejects_secret_ref_in_entrypoint_env() {
    let mut w = base_workload();
    let env = match &mut w.apps[0].entrypoints[0] {
        Entrypoint::Command { env, .. } => env,
        Entrypoint::Function { env, .. } => env,
    };
    env.insert(
        "KEY".to_string(),
        EnvValue::SecretRef {
            reference: SecretRef {
                name: "k".to_string(),
                mount: SecretMount::File {
                    path: "/run/k".to_string(),
                },
            },
        },
    );
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::SecretsNotImplemented);
    assert_eq!(errs[0].path, ".apps[0].entrypoint.env.KEY");
}

#[test]
fn rejects_persist_volume() {
    let mut w = base_workload();
    w.volumes.push(Volume {
        name: "data".to_string(),
        size_mb: 100,
        persist: true,
    });
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::PersistDeferred);
    assert_eq!(errs[0].path, ".volumes[0].persist");
}

#[test]
fn rejects_network_none_with_ports() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::None,
        ports: vec![PortForward {
            guest: 8080,
            host: 8080,
            proto: PortProto::Tcp,
        }],
        egress: None,
        peers: vec![],
        dns: None,
    });
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::NetworkPortsWithNone);
}

#[test]
fn accepts_network_none_with_empty_ports() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::None,
        ports: vec![],
        egress: None,
        peers: vec![],
        dns: None,
    });
    validate(&w).unwrap();
}

#[test]
fn accepts_bridge_network_with_ports() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![PortForward {
            guest: 8080,
            host: 18080,
            proto: PortProto::Tcp,
        }],
        egress: None,
        peers: vec![],
        dns: None,
    });
    validate(&w).unwrap();
}

fn function_app() -> App {
    App {
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
            concurrency: None,
        }],
        dependencies: Some(mvm_ir::Dependencies::None),
        ..base_app()
    }
}

#[test]
fn function_workload_rejects_host_network_mode() {
    let mut w = base_workload();
    w.apps[0] = function_app();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Host,
        ports: vec![],
        peers: vec![],
        egress: None,
        dns: None,
    });
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::FunctionNetworkHostForbidden),
        "expected E_FUNCTION_NETWORK_HOST_FORBIDDEN, got {errs:?}"
    );
}

#[test]
fn rejects_unsupported_language() {
    let mut w = base_workload();
    w.apps[0] = function_app();
    if let Entrypoint::Function { language, .. } = &mut w.apps[0].entrypoints[0] {
        *language = "ruby".to_string();
    }
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::UnsupportedLanguage)
        .expect("expected E_UNSUPPORTED_LANGUAGE");
    assert_eq!(err.path, ".apps[0].entrypoint.language");
    assert!(
        err.detail.contains("ruby"),
        "detail should mention rejected language: {}",
        err.detail
    );
}

#[test]
fn accepts_supported_languages() {
    for lang in ["python", "node", "wasm"] {
        let mut w = base_workload();
        w.apps[0] = function_app();
        if let Entrypoint::Function { language, .. } = &mut w.apps[0].entrypoints[0] {
            *language = lang.to_string();
        }
        validate(&w)
            .unwrap_or_else(|errs| panic!("language {lang:?} should validate, got: {errs:?}"));
    }
}

#[test]
fn function_workload_with_no_network_validates() {
    let mut w = base_workload();
    w.apps[0] = function_app();
    w.apps[0].network = None;
    validate(&w).unwrap();
}

#[test]
fn function_workload_with_bridge_network_validates() {
    let mut w = base_workload();
    w.apps[0] = function_app();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![],
        peers: vec![],
        egress: None,
        dns: None,
    });
    validate(&w).unwrap();
}

#[test]
fn command_workload_with_host_network_still_validates() {
    // The host-mode rejection is scoped to function-call workloads.
    // ADR-0009's deny-default invariant is function-specific; existing
    // command-style workloads keep their current network surface.
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Host,
        ports: vec![],
        peers: vec![],
        egress: None,
        dns: None,
    });
    validate(&w).unwrap();
}

#[test]
fn rejects_invalid_workload_id() {
    for bad in [
        "",                 // empty
        "-leading-hyphen",  // starts with -
        "1numeric-leading", // starts with digit
        "Has Uppercase",    // uppercase + space
        "has spaces",       // space
        "has_underscore",   // underscore
        "has.dot",          // dot
        &"a".repeat(64),    // too long
    ] {
        let mut w = base_workload();
        w.id = bad.to_string();
        let errs = validate(&w).unwrap_err();
        assert!(
            errs.iter().any(|e| e.code == ErrorCode::InvalidId),
            "expected E_INVALID_ID for id={bad:?}, got {errs:?}"
        );
    }
}

#[test]
fn rejects_invalid_app_name() {
    let mut w = base_workload();
    w.apps[0].name = "Bad Name".to_string();
    let errs = validate(&w).unwrap_err();
    assert!(errs.iter().any(|e| e.code == ErrorCode::InvalidId));
    assert!(errs.iter().any(|e| e.path == ".apps[0].name"));
}

#[test]
fn accepts_well_formed_ids() {
    for good in ["a", "hello", "adder-v2", "x42", "abc-123-def"] {
        let mut w = base_workload();
        w.id = good.to_string();
        w.apps[0].name = good.to_string();
        validate(&w).expect("valid id should pass");
    }
}

#[test]
fn rejects_host_network_on_function_entrypoint() {
    let mut w = base_workload();
    w.apps[0].entrypoints = vec![Entrypoint::Function {
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
        concurrency: None,
    }];
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Host,
        ports: vec![],
        egress: None,
        peers: vec![],
        dns: None,
    });
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::FunctionNetworkHostForbidden)
    );
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::FunctionNetworkHostForbidden)
        .unwrap();
    assert_eq!(err.path, ".apps[0].network.mode");
}

#[test]
fn allows_host_network_on_command_entrypoint() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Host,
        ports: vec![],
        egress: None,
        peers: vec![],
        dns: None,
    });
    validate(&w).unwrap();
}

#[test]
fn rejects_secret_named_field_in_args_schema() {
    use mvm_ir::JsonSchemaShape;
    let mut w = base_workload();
    let mut props = serde_json::Map::new();
    props.insert("username".into(), serde_json::json!({"type": "string"}));
    props.insert("api_key".into(), serde_json::json!({"type": "string"}));
    let mut schema = serde_json::Map::new();
    schema.insert("type".into(), serde_json::json!("object"));
    schema.insert("properties".into(), serde_json::Value::Object(props));
    w.apps[0].entrypoints = vec![Entrypoint::Function {
        language: "python".to_string(),
        module: "x".into(),
        function: "f".into(),
        format: Format::Json,
        working_dir: "/app".into(),
        env: Default::default(),
        args_schema: Some(JsonSchemaShape(schema)),
        return_schema: None,
        extra_imports: vec![],
        primary: true,
        concurrency: None,
    }];
    w.apps[0].dependencies = Some(mvm_ir::Dependencies::None);
    let errs = validate(&w).unwrap_err();
    let secret_err = errs
        .iter()
        .find(|e| e.code == ErrorCode::SecretInSchema)
        .expect("expected E_SECRET_IN_SCHEMA");
    assert!(
        secret_err.path.contains("api_key"),
        "expected api_key in path, got: {}",
        secret_err.path
    );
}

#[test]
fn rejects_secret_named_field_under_nested_properties() {
    use mvm_ir::JsonSchemaShape;
    let mut w = base_workload();
    let schema_json = serde_json::json!({
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "auth_token": {"type": "string"}
                }
            }
        }
    });
    let serde_json::Value::Object(map) = schema_json else {
        unreachable!()
    };
    w.apps[0].entrypoints = vec![Entrypoint::Function {
        language: "python".to_string(),
        module: "x".into(),
        function: "f".into(),
        format: Format::Json,
        working_dir: "/app".into(),
        env: Default::default(),
        args_schema: Some(JsonSchemaShape(map)),
        return_schema: None,
        extra_imports: vec![],
        primary: true,
        concurrency: None,
    }];
    w.apps[0].dependencies = Some(mvm_ir::Dependencies::None);
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::SecretInSchema && e.path.contains("auth_token"))
    );
}

#[test]
fn rejects_financial_identifier_field_names_in_schema() {
    use mvm_ir::JsonSchemaShape;
    let mut w = base_workload();
    let schema_json = serde_json::json!({
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "ssn": {"type": "string"},
            "customer_credit_card": {"type": "string"}
        }
    });
    let serde_json::Value::Object(map) = schema_json else {
        unreachable!()
    };
    w.apps[0].entrypoints = vec![Entrypoint::Function {
        language: "python".to_string(),
        module: "x".into(),
        function: "f".into(),
        format: Format::Json,
        working_dir: "/app".into(),
        env: Default::default(),
        args_schema: Some(JsonSchemaShape(map)),
        return_schema: None,
        extra_imports: vec![],
        primary: true,
        concurrency: None,
    }];
    w.apps[0].dependencies = Some(mvm_ir::Dependencies::None);
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::SecretInSchema && e.path.contains("ssn")),
        "expected E_SECRET_IN_SCHEMA for `ssn`, got: {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.code == ErrorCode::SecretInSchema && e.path.contains("customer_credit_card")),
        "expected E_SECRET_IN_SCHEMA for `customer_credit_card` (suffix match on `credit_card`), got: {errs:?}"
    );
}

#[test]
fn accepts_innocent_field_names_in_schema() {
    use mvm_ir::JsonSchemaShape;
    let mut w = base_workload();
    let schema_json = serde_json::json!({
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "auth_strategy_name": {"type": "string"},
            "count": {"type": "integer"}
        }
    });
    let serde_json::Value::Object(map) = schema_json else {
        unreachable!()
    };
    w.apps[0].entrypoints = vec![Entrypoint::Function {
        language: "python".to_string(),
        module: "x".into(),
        function: "f".into(),
        format: Format::Json,
        working_dir: "/app".into(),
        env: Default::default(),
        args_schema: Some(JsonSchemaShape(map)),
        return_schema: None,
        extra_imports: vec![],
        primary: true,
        concurrency: None,
    }];
    w.apps[0].dependencies = Some(mvm_ir::Dependencies::None);
    validate(&w).expect("innocent field names should pass");
}

#[test]
fn rejects_wildcard_host_in_egress_allowlist() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![],
        egress: Some(NetworkEgress {
            allowlist: vec![
                HostPort {
                    host: "api.openai.com".into(),
                    port: 443,
                },
                HostPort {
                    host: "0.0.0.0".into(),
                    port: 80,
                },
            ],
        }),
        peers: vec![],
        dns: None,
    });
    let errs = validate(&w).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| e.code == ErrorCode::NetworkWildcard
            && e.path.contains("egress.allowlist[1]")));
}

#[test]
fn rejects_invalid_peer_id() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![],
        egress: None,
        peers: vec!["Bad Peer".to_string()],
        dns: None,
    });
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::InvalidId && e.path.contains("peers[0]"))
    );
}

#[test]
fn accepts_well_formed_egress_and_peers() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![],
        egress: Some(NetworkEgress {
            allowlist: vec![HostPort {
                host: "api.openai.com".into(),
                port: 443,
            }],
        }),
        peers: vec!["sibling-worker".into()],
        dns: None,
    });
    validate(&w).expect("well-formed granular grants should pass");
}

#[test]
fn collects_multiple_errors() {
    let mut w = base_workload();
    w.schema_version = "1.0".to_string();
    w.apps.clear();
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs.len(), 2);
    assert!(errs.iter().any(|e| e.code == ErrorCode::UnsupportedMajor));
    assert!(errs.iter().any(|e| e.code == ErrorCode::EmptyApps));
}

// ---------- ADR-0011 warm-process concurrency validation ----------

fn warm_process_app(cfg: WarmProcessConfig) -> App {
    let mut app = function_app();
    if let Some(Entrypoint::Function { concurrency, .. }) = app.entrypoints.first_mut() {
        *concurrency = Some(Concurrency::WarmProcess(cfg));
    }
    app
}

fn default_warm_process_config() -> WarmProcessConfig {
    WarmProcessConfig {
        max_calls_per_worker: 1000,
        max_rss_mb: 128,
        pool_size: 1,
        in_process: InProcessMode::Serial,
        max_queue_depth: None,
    }
}

#[test]
fn accepts_valid_warm_process_config() {
    let mut w = base_workload();
    w.apps[0] = warm_process_app(default_warm_process_config());
    validate(&w).expect("valid warm-process config should pass");
}

#[test]
fn rejects_concurrency_pool_size_zero() {
    let mut w = base_workload();
    let cfg = WarmProcessConfig {
        pool_size: 0,
        ..default_warm_process_config()
    };
    w.apps[0] = warm_process_app(cfg);
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::InvalidConcurrencyPoolSize)
        .expect("expected E_INVALID_CONCURRENCY_POOL_SIZE");
    assert_eq!(err.path, ".apps[0].entrypoint.concurrency.pool_size");
}

#[test]
fn rejects_concurrency_pool_size_too_large() {
    let mut w = base_workload();
    let cfg = WarmProcessConfig {
        pool_size: 65,
        ..default_warm_process_config()
    };
    w.apps[0] = warm_process_app(cfg);
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::InvalidConcurrencyPoolSize),
        "expected E_INVALID_CONCURRENCY_POOL_SIZE, got: {errs:?}"
    );
}

#[test]
fn rejects_concurrency_max_calls_per_worker_below_floor() {
    let mut w = base_workload();
    let cfg = WarmProcessConfig {
        max_calls_per_worker: 99,
        ..default_warm_process_config()
    };
    w.apps[0] = warm_process_app(cfg);
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::InvalidConcurrencyMaxCallsPerWorker)
        .expect("expected E_INVALID_CONCURRENCY_MAX_CALLS_PER_WORKER");
    assert_eq!(
        err.path,
        ".apps[0].entrypoint.concurrency.max_calls_per_worker"
    );
}

#[test]
fn rejects_concurrency_max_rss_mb_exceeds_resources_memory_mb() {
    let mut w = base_workload();
    let cfg = WarmProcessConfig {
        max_rss_mb: 1024,
        ..default_warm_process_config()
    };
    w.apps[0] = warm_process_app(cfg);
    // base_app() has resources.memory_mb = 256.
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::InvalidConcurrencyMaxRssMb)
        .expect("expected E_INVALID_CONCURRENCY_MAX_RSS_MB");
    assert_eq!(err.path, ".apps[0].entrypoint.concurrency.max_rss_mb");
}

#[test]
fn rejects_concurrency_in_process_concurrent_mode() {
    let mut w = base_workload();
    let cfg = WarmProcessConfig {
        in_process: InProcessMode::Concurrent,
        ..default_warm_process_config()
    };
    w.apps[0] = warm_process_app(cfg);
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::UnsupportedConcurrencyInProcessMode)
        .expect("expected E_UNSUPPORTED_CONCURRENCY_IN_PROCESS_MODE");
    assert_eq!(err.path, ".apps[0].entrypoint.concurrency.in_process");
}

#[test]
fn rejects_concurrency_for_wasm_language() {
    let mut w = base_workload();
    w.apps[0] = warm_process_app(default_warm_process_config());
    if let Some(Entrypoint::Function { language, .. }) = w.apps[0].entrypoints.first_mut() {
        *language = "wasm".to_string();
    }
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::UnsupportedConcurrencyForLanguage)
        .expect("expected E_UNSUPPORTED_CONCURRENCY_FOR_LANGUAGE");
    assert_eq!(err.path, ".apps[0].entrypoint.concurrency");
}
