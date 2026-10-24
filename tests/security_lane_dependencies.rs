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
