//! The workspace's crate graph, read from its manifests, and content hashes of
//! a crate's sources.
//!
//! Two consumers need "every workspace crate this binary is built from":
//! `mvm-cli`'s build script, which keys its content-addressed store of embedded
//! binaries on that closure, and the builder image's cache keys (the Stage 0
//! fingerprint and the local image cache key), which have to change when a
//! binary the builder image compiles from workspace source changes. One copy,
//! so they cannot disagree about what a closure is. The build script reaches
//! this file through a `#[path]` include, since a build script cannot depend on
//! a workspace crate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Workspace members, by package name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorkspaceGraph {
    /// package name -> the crate directory holding its `src/`.
    pub dirs: BTreeMap<String, PathBuf>,
    /// package name -> the workspace packages it depends on.
    pub edges: BTreeMap<String, Vec<String>>,
}

/// Workspace-internal dependency closure of `roots`, inclusive of the roots.
///
/// Derived from the real manifest graph, never a hand-written list: a list
/// cannot be kept correct against a dependency graph. The watch list this
/// replaces named `mvm-build` only, while `mvm-egress-client` — the guest's
/// entire egress path — lives in `mvm-agentd`, so an edit there embedded the
/// previous binary and nothing said so.
pub fn workspace_closure(graph: &WorkspaceGraph, roots: &[&str]) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for root in roots {
        if seen.insert((*root).to_string()) {
            queue.push_back((*root).to_string());
        }
    }

    while let Some(package) = queue.pop_front() {
        let Some(deps) = graph.edges.get(&package) else {
            continue;
        };
        for dep in deps {
            if seen.insert(dep.clone()) {
                queue.push_back(dep.clone());
            }
        }
    }

    seen.into_iter().collect()
}

/// The package name declared by a crate manifest.
pub fn parse_package_name(manifest: &str) -> Option<String> {
    manifest
        .parse::<toml::Value>()
        .ok()?
        .get("package")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// Every dependency name a manifest declares, across normal, build and
/// target-conditional tables.
///
/// Deliberately includes `[build-dependencies]` and every
/// `[target.'cfg(..)'.dependencies]`: a build-dependency generates code, and a
/// target-gated dependency is exactly how the macOS libkrun path is wired, so
/// omitting either would key a binary on an incomplete closure.
///
/// Dev-dependencies are excluded — they cannot reach a `[[bin]]`.
pub fn parse_manifest_deps(manifest: &str) -> Vec<String> {
    let Ok(value) = manifest.parse::<toml::Value>() else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();

    let mut collect = |table: Option<&toml::Value>| {
        if let Some(toml::Value::Table(table)) = table {
            names.extend(table.keys().cloned());
        }
    };

    collect(value.get("dependencies"));
    collect(value.get("build-dependencies"));

    if let Some(toml::Value::Table(targets)) = value.get("target") {
        for spec in targets.values() {
            collect(spec.get("dependencies"));
            collect(spec.get("build-dependencies"));
        }
    }

    names.into_iter().collect()
}

/// Read every workspace member under `crates/` (descending one extra level
/// into `crates/deps/`, which is where vendored FFI crates live) and build the
/// package-name graph.
pub fn read_workspace_graph(workspace_root: &Path) -> WorkspaceGraph {
    let mut dirs = BTreeMap::new();
    let mut manifests = Vec::new();

    let crates_dir = workspace_root.join("crates");
    let mut candidates = Vec::new();
    push_child_dirs(&crates_dir, &mut candidates);
    push_child_dirs(&crates_dir.join("deps"), &mut candidates);

    for dir in candidates {
        let manifest_path = dir.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let Some(name) = parse_package_name(&text) else {
            continue;
        };
        dirs.insert(name.clone(), dir);
        manifests.push((name, text));
    }

    let members: BTreeSet<String> = dirs.keys().cloned().collect();
    let mut edges = BTreeMap::new();
    for (name, text) in manifests {
        let deps = parse_manifest_deps(&text)
            .into_iter()
            .filter(|dep| members.contains(dep))
            .collect();
        edges.insert(name, deps);
    }

    WorkspaceGraph { dirs, edges }
}

fn push_child_dirs(parent: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.push(path);
        }
    }
}

/// `(workspace-relative path, SHA-256)` for every file under `dir`, sorted.
///
/// Sorted so the key is stable regardless of directory iteration order, which
/// is not guaranteed and differs between filesystems.
pub fn hash_tree(workspace_root: &Path, dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_file_hashes(workspace_root, dir, &mut out);
    out.sort();
    out
}

fn collect_file_hashes(workspace_root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_file_hashes(workspace_root, &path, out);
        } else {
            push_file_hash(workspace_root, &path, out);
        }
    }
}

fn push_file_hash(workspace_root: &Path, path: &Path, out: &mut Vec<(String, String)>) {
    let rel = path
        .strip_prefix(workspace_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    out.push((rel, hash_file(path)));
}

/// Top-level crate directories that hold only targets a library or binary
/// never links: integration tests, benchmarks, examples, and fuzz harnesses.
const UNLINKED_TARGET_DIRS: &[&str] = &["tests", "benches", "examples", "fuzz"];

/// Every hashed input for one workspace member: everything under its crate
/// directory except the target directories in [`UNLINKED_TARGET_DIRS`],
/// hidden entries, and `target/`.
///
/// Not just `src/` and the manifest: a crate compiles files from beside its
/// `src/` too — `include_str!("../../data/…")`, a `build.rs` — and a key that
/// skips them keeps serving a binary built from the old contents.
///
/// The manifest has to go through a file hash, not `hash_tree` — `hash_tree`
/// lists a directory, so handing it a file path silently contributes nothing
/// and a feature or dependency edit would not move the key.
pub fn hash_member(workspace_root: &Path, dir: &Path) -> Vec<(String, String)> {
    let mut hashes = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hashes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        if path.is_dir() {
            if !UNLINKED_TARGET_DIRS.contains(&name.as_ref()) {
                hashes.extend(hash_tree(workspace_root, &path));
            }
        } else {
            push_file_hash(workspace_root, &path, &mut hashes);
        }
    }
    hashes.sort();
    hashes
}

/// Hash one file, or the empty string when it cannot be read.
pub fn hash_file(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| hex(Sha256::digest(&bytes).as_slice()))
        .unwrap_or_default()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
