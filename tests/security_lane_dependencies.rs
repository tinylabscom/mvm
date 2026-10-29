use std::path::Path;

fn workspace_lockfile() -> toml::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&contents).expect("Cargo.lock must parse as TOML")
}

fn workspace_manifest(relative: &str) -> toml::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&contents)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn chacha20_uses_the_non_yanked_patch_release() {
    let lockfile = workspace_lockfile();
    let versions = lockfile["package"]
        .as_array()
        .expect("Cargo.lock package list")
        .iter()
        .filter(|package| package["name"].as_str() == Some("chacha20"))
        .filter_map(|package| package["version"].as_str())
        .collect::<Vec<_>>();

    assert_eq!(versions, ["0.10.2"]);
}

#[test]
fn hostd_uses_contract_ir_without_the_authoring_sdk() {
    let manifest = workspace_manifest("crates/mvm-hostd/Cargo.toml");
    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("mvm-hostd dependencies must be a table");

    assert!(dependencies.contains_key("mvm-contract"));
    assert!(
        !dependencies.contains_key("mvm-sdk"),
        "mvm-hostd must import runtime IR from mvm-contract instead of pulling in the authoring SDK"
    );
}

#[test]
fn guest_builder_excludes_the_host_keyring_feature() {
    let core = workspace_manifest("crates/mvm-core/Cargo.toml");
    assert_eq!(
        core["features"]["os-keyring"][0].as_str(),
        Some("dep:keyring"),
        "mvm-core must keep the OS keyring behind its host-only feature"
    );

    let guest = workspace_manifest("crates/mvm-builder-guest/Cargo.toml");
    let core_dependency = &guest["dependencies"]["mvm-core"];
    let guest_features = core_dependency
        .as_table()
        .and_then(|dependency| dependency.get("features"))
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    assert!(
        !guest_features
            .iter()
            .any(|feature| feature.as_str() == Some("os-keyring")),
        "the guest builder must not restore the host OS-keyring dependency"
    );

    for host_manifest in [
        "crates/mvm-client/Cargo.toml",
        "crates/mvm-runtime/Cargo.toml",
    ] {
        let manifest = workspace_manifest(host_manifest);
        let features = manifest["dependencies"]["mvm-core"]["features"]
            .as_array()
            .expect("host mvm-core dependency must declare features");
        assert!(
            features
                .iter()
                .any(|feature| feature.as_str() == Some("os-keyring")),
            "{host_manifest} must retain OS-native key storage"
        );
    }
}
