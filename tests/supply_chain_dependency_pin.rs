use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const ARRAYREF_REVISION: &str = "f8d0299d863922db6c409d08098941e833b70d69";
const ARRAYREF_REPOSITORY: &str = "https://github.com/droundy/arrayref";
const CARGO_TOML_SHA256: &str = "122da2bce2d1aea793e4dc4d38a98966c67f3339a4db2f8fc740bd74ce97e668";
const LICENSE_SHA256: &str = "1bc7e6f475b3ec99b7e2643411950ae2368c250dd4c5c325f80f9811362a94a1";
const LIB_SHA256: &str = "b74872c9bb2b836132817e024a3f9205f83a6864de1a9bfb46acc1bfbbc1873a";

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn parse_toml(path: &Path) -> toml::Value {
    toml::from_str(&read(path))
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn assert_arrayref_patch(manifest_path: &Path, vendored: &Path) {
    let manifest = parse_toml(manifest_path);
    let patch = &manifest["patch"]["crates-io"]["arrayref"];
    let relative = patch["path"]
        .as_str()
        .unwrap_or_else(|| panic!("{} must use a path patch", manifest_path.display()));
    let resolved = manifest_path
        .parent()
        .expect("a manifest has a containing directory")
        .join(relative)
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!(
                "failed to resolve arrayref patch from {}: {error}",
                manifest_path.display()
            )
        });

    assert_eq!(resolved, vendored);
    assert!(patch.get("git").is_none());
    assert!(patch.get("rev").is_none());
}

fn arrayref_package(lockfile_path: &Path) -> toml::Value {
    let lock = parse_toml(lockfile_path);
    let matches: Vec<_> = lock["package"]
        .as_array()
        .expect("Cargo.lock package must be an array")
        .iter()
        .filter(|package| package["name"].as_str() == Some("arrayref"))
        .cloned()
        .collect();

    assert_eq!(
        matches.len(),
        1,
        "{} must resolve exactly one arrayref package",
        lockfile_path.display()
    );
    matches.into_iter().next().expect("one package was found")
}

fn assert_arrayref_lock(lockfile_path: &Path) {
    let package = arrayref_package(lockfile_path);
    assert_eq!(package["version"].as_str(), Some("0.3.9"));
    assert!(
        package.get("source").is_none(),
        "{} must resolve arrayref from the vendored path",
        lockfile_path.display()
    );
    assert!(package.get("checksum").is_none());
}

fn collect_lockfiles(directory: &Path, lockfiles: &mut Vec<PathBuf>) {
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

fn sha256(path: &Path) -> String {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn nix_filter_list(name: &str) -> Vec<String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = workspace.join("nix/lib/workspace-filter.nix");
    let body = read(&path);
    let start = body
        .find(&format!("{name} = ["))
        .unwrap_or_else(|| panic!("{name} list not found in {}", path.display()));
    let rest = &body[start..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("{name} list is unterminated in {}", path.display()));
    rest[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn every_arrayref_graph_uses_the_vendored_reviewed_source() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vendored = workspace
        .join("third_party/arrayref")
        .canonicalize()
        .expect("vendored arrayref directory must exist");
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
        assert_arrayref_patch(&manifest, &vendored);
        assert_arrayref_lock(&lockfile);
    }
}

#[test]
fn vendored_arrayref_matches_the_reviewed_upstream_revision() {
    let vendored = Path::new(env!("CARGO_MANIFEST_DIR")).join("third_party/arrayref");
    let origin = parse_toml(&vendored.join("ORIGIN.toml"));

    assert_eq!(origin["repository"].as_str(), Some(ARRAYREF_REPOSITORY));
    assert_eq!(origin["revision"].as_str(), Some(ARRAYREF_REVISION));
    assert_eq!(
        origin["cargo_toml_sha256"].as_str(),
        Some(CARGO_TOML_SHA256)
    );
    assert_eq!(origin["license_sha256"].as_str(), Some(LICENSE_SHA256));
    assert_eq!(origin["lib_sha256"].as_str(), Some(LIB_SHA256));
    assert_eq!(sha256(&vendored.join("Cargo.toml")), CARGO_TOML_SHA256);
    assert_eq!(sha256(&vendored.join("LICENSE")), LICENSE_SHA256);
    assert_eq!(sha256(&vendored.join("src/lib.rs")), LIB_SHA256);
}

#[test]
fn nix_workspace_filter_includes_the_vendored_arrayref_source() {
    let included = nix_filter_list("includedTopLevel");

    assert!(
        included.iter().any(|entry| entry == "third_party"),
        "Nix image builds must include the top-level directory containing the vendored arrayref path dependency"
    );
}

#[test]
fn deny_policy_rejects_git_sources() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy = parse_toml(&workspace.join("deny.toml"));
    let allowed = policy["sources"]["allow-git"]
        .as_array()
        .expect("sources.allow-git must be an array");

    assert!(allowed.is_empty());
}
