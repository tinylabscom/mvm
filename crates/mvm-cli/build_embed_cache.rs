//! Content-addressed store for the binaries mvm-cli's build script produces.
//!
//! The script has two nested legs — the musl cross-compile of the embedded
//! host binaries, and the native per-VM helpers — and neither could tell a
//! fresh artifact from a stale one. The embedded leg keyed reuse on
//! `PROFILE == "debug"` plus "does the file exist", so it handed back whatever
//! bytes were on disk and rebuilt from scratch under every other profile,
//! target triple and worktree. The helper leg had no reuse at all and so ran
//! four to six nested `cargo build`s on every `cargo check`.
//!
//! Measured on a fresh worktree before this existed: the script was 332.7s of
//! a 359s cold build (93%), and 14.3s of an 18s rebuild after a one-line
//! `mvm-core` edit (79%).
//!
//! Keying on content fixes both halves with one mechanism. A key derived from
//! the binary's real dependency closure *proves* freshness, so reuse stops
//! being a bet that a stale artifact is tolerable and becomes sound
//! everywhere — which is what lets the store sit outside the target directory
//! and be shared across worktrees, profiles and triples.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Workspace members, by package name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceGraph {
    /// package name -> the crate directory holding its `src/`.
    pub dirs: BTreeMap<String, PathBuf>,
    /// package name -> the workspace packages it depends on.
    pub edges: BTreeMap<String, Vec<String>>,
}

/// The inputs that decide whether two builds of one binary are the same build.
///
/// Anything that can change the produced bytes belongs here; anything that
/// cannot must stay out, because every field widens the set of edits that
/// force a rebuild. `mvm-cli`'s own sources are the motivating exclusion —
/// it *links* these binaries rather than being linked by them, so its 251
/// files cannot affect them, yet the old watch list rebuilt on every one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct KeyInputs {
    pub package: String,
    pub binary: String,
    pub features: String,
    pub target: String,
    /// Pinned zig / cargo-zigbuild / rustc identity, whichever the leg uses.
    pub toolchain: String,
    /// Which leg produced it — a musl static and a native host build of the
    /// same package are different artifacts and must not share a key.
    pub flavor: String,
    /// SHA-256 of `Cargo.lock`.
    pub lockfile: String,
    /// `(workspace-relative path, SHA-256)` for every source file in the
    /// dependency closure, sorted by path.
    pub sources: Vec<(String, String)>,
}

/// Workspace-internal dependency closure of `roots`, inclusive of the roots.
///
/// Derived from the real manifest graph, never a hand-written list: a list
/// cannot be kept correct against a dependency graph. The watch list this
/// replaces named `mvm-build` only, while `mvm-egress-client` — the guest's
/// entire egress path — lives in `mvm-agentd`, so an edit there embedded the
/// previous binary and nothing said so.
pub(crate) fn workspace_closure(graph: &WorkspaceGraph, roots: &[&str]) -> Vec<String> {
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
pub(crate) fn parse_package_name(manifest: &str) -> Option<String> {
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
pub(crate) fn parse_manifest_deps(manifest: &str) -> Vec<String> {
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
pub(crate) fn read_workspace_graph(workspace_root: &Path) -> WorkspaceGraph {
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
pub(crate) fn hash_tree(workspace_root: &Path, dir: &Path) -> Vec<(String, String)> {
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
        } else if let Ok(bytes) = std::fs::read(&path) {
            let rel = path
                .strip_prefix(workspace_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((rel, hex(Sha256::digest(&bytes).as_slice())));
        }
    }
}

/// Every hashed input for one workspace member: its `src/` tree plus its
/// manifest.
///
/// The manifest has to go through `hash_file`, not `hash_tree` — `hash_tree`
/// lists a directory, so handing it a file path silently contributes nothing
/// and a feature or dependency edit would not move the key.
pub(crate) fn hash_member(workspace_root: &Path, dir: &Path) -> Vec<(String, String)> {
    let mut hashes = hash_tree(workspace_root, &dir.join("src"));
    let manifest = dir.join("Cargo.toml");
    if manifest.is_file() {
        let rel = manifest
            .strip_prefix(workspace_root)
            .unwrap_or(&manifest)
            .to_string_lossy()
            .into_owned();
        hashes.push((rel, hash_file(&manifest)));
    }
    hashes.sort();
    hashes
}

/// Hash one file, or the empty string when it cannot be read.
pub(crate) fn hash_file(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| hex(Sha256::digest(&bytes).as_slice()))
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The cache key for one artifact.
///
/// Every field is length-prefixed before hashing. Plain concatenation would
/// let two different input sets collide by shifting a boundary — a binary
/// named `ab` with feature `c` would hash identically to one named `a` with
/// feature `bc` — and a collision here silently ships the wrong bytes.
pub(crate) fn artifact_key(inputs: &KeyInputs) -> String {
    let mut hasher = Sha256::new();
    let mut field = |value: &str| {
        hasher.update(value.len().to_le_bytes());
        hasher.update(value.as_bytes());
    };

    field("mvm-embed-cache-v1");
    field(&inputs.package);
    field(&inputs.binary);
    field(&inputs.features);
    field(&inputs.target);
    field(&inputs.toolchain);
    field(&inputs.flavor);
    field(&inputs.lockfile);
    for (path, sha) in &inputs.sources {
        field(path);
        field(sha);
    }

    hex(hasher.finalize().as_slice())
}

/// Resolve the store root from an explicit override, else a home directory.
///
/// Returns `None` when neither is available, and the caller then builds
/// without caching. A missing cache is a slow build; a cache rooted somewhere
/// unexpected is a wrong one.
pub(crate) fn cache_root_from(
    override_dir: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(dir) = override_dir.filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let home = home.filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".cache/mvm/embed"))
}

/// `cache_root_from` against this process's environment.
pub(crate) fn cache_root() -> Option<PathBuf> {
    if std::env::var_os("MVM_EMBED_NO_CACHE").is_some_and(|v| !v.is_empty()) {
        return None;
    }
    cache_root_from(
        std::env::var_os("MVM_EMBED_CACHE_DIR"),
        std::env::var_os("HOME"),
    )
}

/// Where one artifact lives inside the store.
pub(crate) fn artifact_path(root: &Path, key: &str, binary: &str) -> PathBuf {
    root.join(key).join(binary)
}

/// Copy a cached artifact into place, if the store has it.
pub(crate) fn lookup(root: &Path, key: &str, binary: &str, dest: &Path) -> bool {
    let cached = artifact_path(root, key, binary);
    if !cached.is_file() {
        return false;
    }
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::copy(&cached, dest).is_ok()
}

/// Publish a freshly built artifact into the store.
///
/// Writes to a temporary name and renames, because concurrent worktree builds
/// race this directory and a half-copied binary that looks complete is worse
/// than no cache at all. Failures are swallowed: an unwritable store must slow
/// the build down, not break it.
pub(crate) fn install(root: &Path, key: &str, binary: &str, source: &Path) {
    let dir = root.join(key);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let staged = dir.join(format!(".tmp-{}-{binary}", std::process::id()));
    if std::fs::copy(source, &staged).is_err() {
        let _ = std::fs::remove_file(&staged);
        return;
    }
    if std::fs::rename(&staged, dir.join(binary)).is_err() {
        let _ = std::fs::remove_file(&staged);
    }
}
