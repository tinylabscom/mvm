use std::path::Path;

const ARRAYREF_REVISION: &str = "f8d0299d863922db6c409d08098941e833b70d69";
const ARRAYREF_REPOSITORY: &str = "https://github.com/droundy/arrayref";

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn assert_arrayref_patch(manifest_path: &Path) {
    let manifest: toml::Value =
        toml::from_str(&read(manifest_path)).expect("Cargo.toml must parse");
    let patch = &manifest["patch"]["crates-io"]["arrayref"];

    assert_eq!(patch["git"].as_str(), Some(ARRAYREF_REPOSITORY));
    assert_eq!(patch["rev"].as_str(), Some(ARRAYREF_REVISION));
}

fn assert_arrayref_lock(lockfile_path: &Path) {
    let expected_source =
        format!("git+{ARRAYREF_REPOSITORY}?rev={ARRAYREF_REVISION}#{ARRAYREF_REVISION}");
    assert!(
        read(lockfile_path).contains(&expected_source),
        "{} must resolve arrayref from the reviewed revision",
        lockfile_path.display()
    );
}

#[test]
fn every_arrayref_graph_uses_the_reviewed_upstream_revision() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let graphs = [
        (workspace.join("Cargo.toml"), workspace.join("Cargo.lock")),
        (
            workspace.join("crates/mvm-hostd/fuzz/Cargo.toml"),
            workspace.join("crates/mvm-hostd/fuzz/Cargo.lock"),
        ),
    ];

    for (manifest, lockfile) in graphs {
        assert_arrayref_patch(&manifest);
        assert_arrayref_lock(&lockfile);
    }
}

#[test]
fn deny_policy_allows_only_the_pinned_repository() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy: toml::Value =
        toml::from_str(&read(&workspace.join("deny.toml"))).expect("deny.toml must parse");
    let allowed = policy["sources"]["allow-git"]
        .as_array()
        .expect("sources.allow-git must be an array");

    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0].as_str(), Some(ARRAYREF_REPOSITORY));
}
