use std::collections::BTreeMap;

use mvm_core::{WorkloadAddress, workload_address};
use mvm_sdk::ir::{App, Entrypoint, EnvValue, Image, Resources, Source, Workload};

const EXPECTED_WORKLOAD_ADDRESS: &str =
    "sha256:b7106af4133c7d678744adb3b617e7289bc3f4c131b2df03a8e9cc49aac90037";

fn rust_fixture() -> Workload {
    Workload {
        schema_version: "0.1".to_string(),
        id: "hello-parity".to_string(),
        apps: vec![App {
            name: "greeter".to_string(),
            source: Source::LocalPath {
                path: ".".to_string(),
                include: vec!["**".to_string()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".to_string()],
            },
            entrypoints: vec![Entrypoint::Command {
                command: vec![
                    "python".to_string(),
                    "-m".to_string(),
                    "greeter".to_string(),
                ],
                working_dir: "/app".to_string(),
                env: BTreeMap::new(),
            }],
            env: BTreeMap::from([(
                "GREETING".to_string(),
                EnvValue::Literal {
                    value: "hello".to_string(),
                },
            )]),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 2,
                memory_mb: 512,
                rootfs_size_mb: 1024,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
            files: vec![],
            health_check: None,
        }],
        volumes: vec![],
        extensions: BTreeMap::new(),
    }
}

fn emitted_fixture(source: &str, json: &str) -> Workload {
    serde_json::from_str(json)
        .unwrap_or_else(|error| panic!("invalid {source} IR fixture: {error}"))
}

#[test]
fn python_typescript_and_rust_resolve_to_one_workload_address() {
    let rust = rust_fixture();
    let python = emitted_fixture(
        "Python",
        include_str!("../../../tests/ir-parity-fixtures/hello-parity.python.ir.json"),
    );
    let typescript = emitted_fixture(
        "TypeScript",
        include_str!("../../../tests/ir-parity-fixtures/hello-parity.typescript.ir.json"),
    );

    assert_eq!(python, rust, "Python SDK changed the shared IR value");
    assert_eq!(
        typescript, rust,
        "TypeScript SDK changed the shared IR value"
    );

    for (source, workload) in [
        ("Rust", &rust),
        ("Python", &python),
        ("TypeScript", &typescript),
    ] {
        let address: WorkloadAddress = workload_address(workload)
            .unwrap_or_else(|error| panic!("addressing {source} fixture failed: {error}"));
        assert_eq!(address.as_str(), EXPECTED_WORKLOAD_ADDRESS, "{source}");
    }
}
