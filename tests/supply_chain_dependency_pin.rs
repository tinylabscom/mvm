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

fn collect_lockfiles(directory: &Path, lockfiles: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
    for entry in entries {
        let entry = entry.expect("directory entry must be readable");
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
        if file_type.is_dir() {
            collect_lockfiles(&path, lockfiles);
        } else if path.file_name().is_some_and(|name| name == "Cargo.lock") {
            lockfiles.push(path);
        }
    }
}

#[test]
fn every_arrayref_graph_uses_the_reviewed_upstream_revision() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut lockfiles = vec![workspace.join("Cargo.lock")];
    collect_lockfiles(&workspace.join("crates"), &mut lockfiles);
    let affected: Vec<_> = lockfiles
        .into_iter()
        .filter(|lockfile| read(lockfile).contains("name = \"arrayref\""))
        .collect();

    assert!(!affected.is_empty(), "the workspace must contain arrayref");
    for lockfile in affected {
        let manifest = lockfile
            .parent()
            .expect("a lockfile has a containing directory")
            .join("Cargo.toml");
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
