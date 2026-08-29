use std::path::Path;

fn workspace_lockfile() -> toml::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&contents).expect("Cargo.lock must parse as TOML")
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
