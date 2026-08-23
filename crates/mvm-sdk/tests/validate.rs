use mvm_sdk::ir::{
    App, AuthType, Concurrency, Entrypoint, EnvValue, ErrorCode, Format, HostPort, Image,
    InProcessMode, Network, NetworkEgress, NetworkMode, PortForward, PortProto, PortTransform,
    Resources, SecretMount, SecretRef, Source, Volume, WarmProcessConfig, Workload, validate,
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
        files: vec![],
        health_check: None,
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
fn rejects_direct_shell_command_entrypoint() {
    let mut w = base_workload();
    w.apps[0].entrypoints = vec![Entrypoint::Command {
        command: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo no".to_string(),
        ],
        working_dir: "/app".to_string(),
        env: Default::default(),
    }];
    let errs = validate(&w).unwrap_err();
    let err = errs
        .iter()
        .find(|e| e.code == ErrorCode::ShellEntrypointForbidden)
        .expect("expected E_SHELL_ENTRYPOINT_FORBIDDEN");
    assert_eq!(err.path, ".apps[0].entrypoint.command");
    assert!(err.detail.contains("sh"));
}

#[test]
fn rejects_indirect_shell_command_entrypoint() {
    let mut w = base_workload();
    w.apps[0].entrypoints = vec![Entrypoint::Command {
        command: vec![
            "/usr/bin/env".to_string(),
            "bash".to_string(),
            "-lc".to_string(),
            "echo no".to_string(),
        ],
        working_dir: "/app".to_string(),
        env: Default::default(),
    }];
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::ShellEntrypointForbidden),
        "expected E_SHELL_ENTRYPOINT_FORBIDDEN, got {errs:?}"
    );
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
fn admits_secret_ref_with_a_binding() {
    // A SecretRef that declares allowed_hosts is admitted (the
    // SecretsNotImplemented gate is gone).
    let mut w = base_workload();
    w.apps[0].env.insert(
        "TOKEN".to_string(),
        EnvValue::SecretRef {
            reference: SecretRef {
                name: "api-token".to_string(),
                mount: SecretMount::Env {
                    var: "TOKEN".to_string(),
                },
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.example.com".to_string()],
                sigv4: None,
            },
        },
    );
    assert!(validate(&w).is_ok());
}

#[test]
fn rejects_unbound_secret_ref() {
    // A secret with no allowed_hosts is unbound; refuse it.
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
                auth_type: AuthType::Bearer,
                allowed_hosts: vec![],
                sigv4: None,
            },
        },
    );
    let errs = validate(&w).unwrap_err();
    assert_eq!(errs[0].code, ErrorCode::SecretWithoutBinding);
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
            mapping_id: 1,
            host_addr: "127.0.0.1".to_string(),
            guest: 8080,
            host: 8080,
            proto: PortProto::Tcp,
            guest_addr: "127.0.0.1".to_string(),
            transform: PortTransform::Opaque,
            tls_secret: None,
        }],
        egress: None,
        peers: vec![],
        dns: None,
        ai: None,
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
        ai: None,
    });
    validate(&w).unwrap();
}

#[test]
fn accepts_bridge_network_with_ports() {
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports: vec![PortForward {
            mapping_id: 1,
            host_addr: "127.0.0.1".to_string(),
            guest: 8080,
            host: 18080,
            proto: PortProto::Tcp,
            guest_addr: "127.0.0.1".to_string(),
            transform: PortTransform::Opaque,
            tls_secret: None,
        }],
        egress: None,
        peers: vec![],
        dns: None,
        ai: None,
    });
    validate(&w).unwrap();
}

fn ingress_mapping(mapping_id: u16, host: u16) -> PortForward {
    PortForward {
        mapping_id,
        host_addr: "127.0.0.1".to_string(),
        guest: 8080,
        host,
        proto: PortProto::Tcp,
        guest_addr: "127.0.0.1".to_string(),
        transform: PortTransform::Opaque,
        tls_secret: None,
    }
}

fn workload_with_ingress(ports: Vec<PortForward>) -> Workload {
    let mut workload = base_workload();
    workload.apps[0].network = Some(Network {
        mode: NetworkMode::Bridge,
        ports,
        egress: None,
        peers: vec![],
        dns: None,
        ai: None,
    });
    workload
}

#[test]
fn rejects_duplicate_ingress_mapping_id() {
    let workload =
        workload_with_ingress(vec![ingress_mapping(1, 18080), ingress_mapping(1, 18081)]);
    let errors = validate(&workload).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.code == ErrorCode::IngressDuplicateMapping),
        "{errors:?}"
    );
}

#[test]
fn rejects_duplicate_ingress_bind() {
    let workload =
        workload_with_ingress(vec![ingress_mapping(1, 18080), ingress_mapping(2, 18080)]);
    let errors = validate(&workload).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.code == ErrorCode::IngressDuplicateBind),
        "{errors:?}"
    );
}

#[test]
fn rejects_non_loopback_ingress_guest_target() {
    let mut mapping = ingress_mapping(1, 18080);
    mapping.guest_addr = "10.0.0.2".to_string();
    let errors = validate(&workload_with_ingress(vec![mapping])).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.code == ErrorCode::IngressGuestNotLoopback),
        "{errors:?}"
    );
}

#[test]
fn rejects_typed_udp_ingress() {
    let mut mapping = ingress_mapping(1, 18080);
    mapping.proto = PortProto::Udp;
    mapping.transform = PortTransform::Tls;
    let errors = validate(&workload_with_ingress(vec![mapping])).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.code == ErrorCode::IngressUnsupportedTransform),
        "{errors:?}"
    );
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
        dependencies: Some(mvm_sdk::ir::Dependencies::None),
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
        ai: None,
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
        ai: None,
    });
    validate(&w).unwrap();
}

#[test]
fn command_workload_with_host_network_still_validates() {
    // The host-mode rejection is scoped to function-call workloads.
    // The deny-default invariant is function-specific; existing
    // command-style workloads keep their current network surface.
    let mut w = base_workload();
    w.apps[0].network = Some(Network {
        mode: NetworkMode::Host,
        ports: vec![],
        peers: vec![],
        egress: None,
        dns: None,
        ai: None,
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
        ai: None,
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
        ai: None,
    });
    validate(&w).unwrap();
}

#[test]
fn rejects_secret_named_field_in_args_schema() {
    use mvm_sdk::ir::JsonSchemaShape;
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
    w.apps[0].dependencies = Some(mvm_sdk::ir::Dependencies::None);
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
    use mvm_sdk::ir::JsonSchemaShape;
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
    w.apps[0].dependencies = Some(mvm_sdk::ir::Dependencies::None);
    let errs = validate(&w).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.code == ErrorCode::SecretInSchema && e.path.contains("auth_token"))
    );
}

#[test]
fn rejects_financial_identifier_field_names_in_schema() {
    use mvm_sdk::ir::JsonSchemaShape;
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
    w.apps[0].dependencies = Some(mvm_sdk::ir::Dependencies::None);
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
    use mvm_sdk::ir::JsonSchemaShape;
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
    w.apps[0].dependencies = Some(mvm_sdk::ir::Dependencies::None);
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
        ai: None,
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
        ai: None,
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
        ai: None,
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

// ---------- warm-process concurrency validation ----------

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

#[test]
fn stale_raw_ip_stack_input_names_the_supported_migration() {
    let json = r#"{
        "mode":"bridge",
        "ports":[],
        "peers":[],
        "raw_ip_stack":false
    }"#;
    let err = serde_json::from_str::<mvm_sdk::ir::Network>(json)
        .expect_err("the retired field must not enter the IR");
    let message = err.to_string();
    assert!(
        message.contains("raw_ip_stack has been retired"),
        "{message}"
    );
    assert!(message.contains("SOCKS5h/UDP"), "{message}");
    assert!(message.contains("typed connector"), "{message}");
}

// ────────────────────────────────────────────────────────────────────
// Shared network-constructor verdict corpus.
//
// `features/suites/s27_sdk/fixtures/network_constraints.json` states, once,
// whether each `host_port` / `dns_resolver` argument pair may survive into a
// valid workload document. This asserts the Rust surface agrees; the s27
// scenario asserts Python does, against the same file. Neither language owns
// the answer, so neither can drift without failing a gate.
// ────────────────────────────────────────────────────────────────────

/// One golden case: constructor, its two arguments, and the verdict every
/// surface must reach.
#[derive(Debug, serde::Deserialize)]
struct ConstraintCase {
    id: String,
    ctor: String,
    host: String,
    port: u32,
    verdict: String,
}

#[derive(Debug, serde::Deserialize)]
struct ConstraintCorpus {
    cases: Vec<ConstraintCase>,
}

/// Repo root, resolved from this crate rather than the process cwd:
/// mvm-sdk/ -> crates/ -> repo root.
fn constraint_corpus_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("features/suites/s27_sdk/fixtures/network_constraints.json")
}

/// Build the case's workload the way a user would — through the public
/// constructors, not by hand-filling the IR structs. A constraint enforced
/// only on a hand-built document would not be the one users meet.
fn workload_for_constraint_case(case: &ConstraintCase) -> Workload {
    use mvm_sdk::{NetworkExt, dns_resolver, egress, host_port, network};

    // A corpus port outside `u16` clamps rather than panics, so adding one
    // yields a meaningful (still invalid) case instead of aborting the run.
    let port = u16::try_from(case.port).unwrap_or(u16::MAX);
    let net = match case.ctor.as_str() {
        "host_port" => {
            network(NetworkMode::Bridge).with_egress(egress([host_port(&case.host, port)]))
        }
        "dns_resolver" => network(NetworkMode::Bridge).with_dns(dns_resolver(&case.host, port)),
        other => panic!("corpus names constructor {other:?}, which this test cannot build"),
    };
    let mut workload = base_workload();
    workload.apps[0].network = Some(net);
    workload
}

#[test]
fn rust_network_constructors_match_the_shared_verdict_corpus() {
    let path = constraint_corpus_path();
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let corpus: ConstraintCorpus =
        serde_json::from_slice(&bytes).expect("network_constraints.json is not the expected shape");
    assert!(!corpus.cases.is_empty(), "the verdict corpus is empty");

    let mut disagreements = Vec::new();
    for case in &corpus.cases {
        let result = validate(&workload_for_constraint_case(case));
        let actual = if result.is_ok() { "valid" } else { "invalid" };
        if actual != case.verdict {
            disagreements.push(format!(
                "{}: corpus says {}, `validate` says {} ({:?})",
                case.id,
                case.verdict,
                actual,
                result.err().unwrap_or_default()
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "the Rust surface disagrees with {} on {} case(s):\n  {}",
        path.display(),
        disagreements.len(),
        disagreements.join("\n  ")
    );
}
