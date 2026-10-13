use super::*;

fn golden(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../mvm-contract/tests/fixtures/pack-spec-v1/canonical/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn minimal() -> PackBuilder {
    pack("acme/hello", "1.0.0")
        .target(PackTarget::Aarch64Linux)
        .source(".")
        .package("busybox")
        .copy("hello.txt", "/app/hello.txt")
        .entrypoint(["cat", "/app/hello.txt"])
        .resources(1, 128)
}

#[test]
fn minimal_builder_emits_the_shared_golden() {
    assert_eq!(minimal().to_canonical_json().unwrap(), golden("minimal"));
}

#[test]
fn python_builder_emits_the_shared_golden() {
    let bytes = pack("acme/csv-analysis", "0.1.0")
        .target(PackTarget::Aarch64Linux)
        .source("app")
        .package(Package::runtime("python3").version("3.13.1"))
        .package(Package::build("pkg-config"))
        .dependencies(Dependencies::python(
            PythonTool::Uv,
            "pyproject.toml",
            "uv.lock",
        ))
        .dependencies(Dependencies::python(
            PythonTool::PipTools,
            "tools/requirements.in",
            "tools/requirements.txt",
        ))
        .copy("main.py", "/app/main.py")
        .copy("data", "/app/data")
        .entrypoint(["python3", "/app/main.py", "one argument", ""])
        .resources(1, 256)
        .to_canonical_json()
        .unwrap();
    assert_eq!(bytes, golden("python"));
}

#[test]
fn claude_style_builder_emits_the_shared_golden() {
    let bytes = pack("acme/claude-style", "1.2.3-rc.1+build.7")
        .target(PackTarget::X86_64Linux)
        .source("app")
        .copy("bin/claude", "/app/bin/claude")
        .entrypoint(["/app/bin/claude", "--version"])
        .resources(2, 1024)
        .to_canonical_json()
        .unwrap();
    assert_eq!(bytes, golden("claude-style"));
}

#[test]
fn missing_required_fields_are_named() {
    let cases: [(PackBuilder, &str); 4] = [
        (
            pack("acme/x", "1.0.0")
                .source(".")
                .entrypoint(["x"])
                .resources(1, 1),
            "target",
        ),
        (
            pack("acme/x", "1.0.0")
                .target(PackTarget::Aarch64Linux)
                .entrypoint(["x"])
                .resources(1, 1),
            "source",
        ),
        (
            pack("acme/x", "1.0.0")
                .target(PackTarget::Aarch64Linux)
                .source(".")
                .resources(1, 1),
            "entrypoint",
        ),
        (
            pack("acme/x", "1.0.0")
                .target(PackTarget::Aarch64Linux)
                .source(".")
                .entrypoint(["x"]),
            "resources",
        ),
    ];
    for (builder, field) in cases {
        let error = builder.build().unwrap_err();
        assert_eq!(error.code(), "missing");
        assert_eq!(error.field(), Some(field));
    }
}

/// The same table the Kotlin suite (and, when they land, the Python and
/// TypeScript suites) check: one mistake, one stable code.
#[test]
fn invalid_input_reports_the_shared_failure_codes() {
    let cases: [(PackBuilder, &str); 7] = [
        (
            pack("no-namespace", "1.0.0")
                .target(PackTarget::Aarch64Linux)
                .source(".")
                .entrypoint(["x"])
                .resources(1, 1),
            "identity",
        ),
        (
            pack("acme/x", "1.0")
                .target(PackTarget::Aarch64Linux)
                .source(".")
                .entrypoint(["x"])
                .resources(1, 1),
            "identity",
        ),
        (minimal().package("has space"), "package"),
        (
            minimal().package(Package::runtime("ok").version(">=1")),
            "package",
        ),
        (minimal().copy("../escape", "/app/x"), "path"),
        (minimal().entrypoint(Vec::<String>::new()), "entrypoint"),
        (minimal().resources(0, 128), "resources"),
    ];
    for (builder, code) in cases {
        assert_eq!(builder.build().unwrap_err().code(), code);
    }
}

#[test]
fn additions_keep_call_order() {
    let spec = minimal()
        .package(Package::build("zlib"))
        .package("aaa")
        .build()
        .unwrap();
    let names: Vec<_> = spec.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["busybox", "zlib", "aaa"]);
}

fn wire(value: impl serde::Serialize) -> String {
    serde_json::to_string(&value).unwrap()
}

fn object_keys(value: &serde_json::Value, keys: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                keys.insert(key.clone());
                object_keys(child, keys);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| object_keys(i, keys)),
        _ => {}
    }
}

/// The Kotlin models are hand-mirrored from the Rust contract. This fails when
/// the contract grows a field or a variant the Kotlin SDK does not spell, so
/// the two cannot drift silently.
#[test]
fn kotlin_models_spell_every_wire_field_and_variant() {
    let kotlin = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sdks/kotlin/src/main/kotlin/com/runmvm/packs/PackSpec.kt"
    ))
    .unwrap();
    let mut spelled = std::collections::BTreeSet::new();
    for name in ["minimal", "python", "claude-style"] {
        let value: serde_json::Value = serde_json::from_slice(&golden(name)).unwrap();
        object_keys(&value, &mut spelled);
    }
    // Every enum variant, by exhaustive match so a new one fails to compile.
    for target in [PackTarget::Aarch64Linux, PackTarget::X86_64Linux] {
        match target {
            PackTarget::Aarch64Linux | PackTarget::X86_64Linux => {}
        }
        spelled.insert(wire(target).trim_matches('"').to_string());
    }
    for scope in [PackageScope::Build, PackageScope::Runtime] {
        match scope {
            PackageScope::Build | PackageScope::Runtime => {}
        }
        spelled.insert(wire(scope).trim_matches('"').to_string());
    }
    for tool in [PythonTool::Uv, PythonTool::PipTools] {
        match tool {
            PythonTool::Uv | PythonTool::PipTools => {}
        }
        spelled.insert(wire(tool).trim_matches('"').to_string());
    }
    spelled.insert(wire(PackSpecSchema::V1).trim_matches('"').to_string());
    for token in &spelled {
        let literal = format!("\"{token}\"");
        assert!(
            kotlin.contains(&literal),
            "Kotlin models do not spell {literal}"
        );
    }
}
