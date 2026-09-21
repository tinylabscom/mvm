use std::path::PathBuf;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn qemu_builder_imports_only_generic_builder_modules() {
    let source = std::fs::read_to_string(crate_root().join("src/qemu_builder.rs")).unwrap();
    assert!(source.contains("crate::builder_vm_image"));
    assert!(source.contains("crate::builder_vm_transport"));
    assert!(
        !source.contains("crate::libkrun_builder"),
        "the QEMU backend must compile without the optional libkrun module"
    );
}

#[test]
fn libkrun_is_an_optional_backend_not_a_generic_capability_switch() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml")).unwrap();
    assert!(manifest.contains("libkrun-sys = { workspace = true, optional = true }"));
    assert!(manifest.contains("mvm-net = { workspace = true, optional = true }"));
    assert!(manifest.contains("builder-libkrun = [\"dep:libkrun-sys\", \"dep:mvm-net\"]"));
    assert!(
        !manifest
            .lines()
            .any(|line| line.starts_with("builder-vm =")),
        "generic builder capability is unconditional"
    );

    let lib = std::fs::read_to_string(crate_root().join("src/lib.rs")).unwrap();
    for module in ["libkrun_builder", "libkrun_network_provider"] {
        let gated = format!("#[cfg(feature = \"builder-libkrun\")]\npub mod {module};");
        assert!(lib.contains(&gated), "{module} must stay feature-gated");
    }
}
