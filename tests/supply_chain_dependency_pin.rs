use std::path::Path;

const ARRAYREF_REVISION: &str = "f8d0299d863922db6c409d08098941e833b70d69";
const ARRAYREF_REPOSITORY: &str = "https://github.com/droundy/arrayref";
const FUZZ_MANIFESTS: &[&str] = &[
    "crates/mvm-agentd/fuzz/Cargo.toml",
    "crates/mvm-contract/fuzz/Cargo.toml",
    "crates/mvm-core/fuzz/Cargo.toml",
    "crates/mvm-fs/fuzz-ext4/Cargo.toml",
    "crates/mvm-fs/fuzz-oci/Cargo.toml",
    "crates/mvm-hostd/fuzz/Cargo.toml",
    "crates/mvm-http/fuzz/Cargo.toml",
    "crates/mvm-runtime/fuzz-backend/Cargo.toml",
    "crates/mvm-sdk/fuzz/Cargo.toml",
    "crates/deps/libkrun-sys/fuzz/Cargo.toml",
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn assert_arrayref_patch(manifest: &toml::Value) {
    let patch = &manifest["patch"]["crates-io"]["arrayref"];
    assert_eq!(patch["git"].as_str(), Some(ARRAYREF_REPOSITORY));
    assert_eq!(patch["rev"].as_str(), Some(ARRAYREF_REVISION));
}

#[test]
fn every_workspace_uses_the_reviewed_arrayref_revision() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_manifest: toml::Value = toml::from_str(&read(&workspace.join("Cargo.toml")))
        .expect("workspace Cargo.toml must parse");
    assert_arrayref_patch(&root_manifest);

    for relative_path in FUZZ_MANIFESTS {
        let manifest: toml::Value = toml::from_str(&read(&workspace.join(relative_path)))
            .unwrap_or_else(|error| panic!("{relative_path} must parse: {error}"));
        assert_arrayref_patch(&manifest);
    }

    let lockfile = read(&workspace.join("Cargo.lock"));
    let expected_source =
        format!("git+{ARRAYREF_REPOSITORY}?rev={ARRAYREF_REVISION}#{ARRAYREF_REVISION}");
    assert!(
        lockfile.contains(&expected_source),
        "Cargo.lock must resolve arrayref from the reviewed revision"
    );
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

#[test]
fn ci_checks_standalone_fuzz_workspaces_without_resolving() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    for workflow in [".github/workflows/ci.yml", ".github/workflows/ci-full.yml"] {
        let source = read(&workspace.join(workflow));
        assert!(
            source.contains("cargo check --locked --manifest-path \"$manifest\" --all-targets"),
            "{workflow} must consume the reviewed fuzz lockfiles"
        );
    }
}
