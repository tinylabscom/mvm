//! The identity of a Rust binary compiled from workspace source.
//!
//! An image that compiles a workspace package itself, rather than taking its
//! bytes from `mvmctl`'s embedded payload, has to be keyed on what those bytes
//! are compiled from: `mvm-setpriv`, which every Nix-built image builds with
//! `cargo build --package mvm-setpriv`, and the builder host binaries a paired
//! image checkout compiles from the `mvm-build` package.
//!
//! The inputs are derived, not listed: the workspace crates the package
//! reaches through its manifests, the `Cargo.lock` entries those crates'
//! non-dev dependencies resolve to, and the parts of the root manifest that
//! change how they compile. A dependency bump outside that closure — the reason
//! the whole lockfile is not hashed — leaves the key alone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::workspace_graph::{
    WorkspaceGraph, hash_member, parse_manifest_deps, read_workspace_graph, workspace_closure,
};

/// The workspace package whose `mvm-setpriv` binary every Nix-built image,
/// the builder image included, compiles from source
/// (`nix/packages/mvm-setpriv.nix`).
pub const SETPRIV_PACKAGE: &str = "mvm-setpriv";

/// Fold the identity of every input `package` is compiled from.
///
/// Fails rather than hashing less than it should: a workspace without the
/// package, or a lockfile without an entry for a crate in its closure, is not
/// a tree the image could be built from, and a key computed from part of it
/// would serve a stale image.
pub fn fold_package_source_identity(
    hasher: &mut Sha256,
    workspace_root: &Path,
    package: &str,
) -> Result<()> {
    let inputs = PackageInputs::read(workspace_root, package)?;
    fold_entry(hasher, "package", package);
    for (path, sha) in &inputs.sources {
        fold_entry(hasher, "package-src", &format!("{path}\0{sha}"));
    }
    for entry in &inputs.locked {
        fold_entry(hasher, "package-lock", entry);
    }
    for entry in &inputs.build_settings {
        fold_entry(hasher, "package-manifest", entry);
    }
    Ok(())
}

/// One entry under a domain tag, length-prefixed so neither the tag boundary
/// nor the entry boundary can be shifted to produce the same digest.
fn fold_entry(hasher: &mut Sha256, domain: &str, entry: &str) {
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update((entry.len() as u64).to_le_bytes());
    hasher.update(entry.as_bytes());
}

/// Everything a package's bytes depend on, each list sorted.
#[derive(Debug, Default, PartialEq, Eq)]
struct PackageInputs {
    /// `(workspace-relative path, SHA-256)` of every source file in the
    /// workspace crates and path-patched crates it is built from.
    sources: Vec<(String, String)>,
    /// `name version source checksum` of every locked external crate.
    locked: Vec<String>,
    /// The root-manifest tables that change how the closure compiles.
    build_settings: Vec<String>,
}

impl PackageInputs {
    fn read(workspace_root: &Path, package: &str) -> Result<Self> {
        let graph = read_workspace_graph(workspace_root);
        if !graph.dirs.contains_key(package) {
            anyhow::bail!(
                "no `{package}` crate under {}/crates, but the image being keyed compiles it \
                 from there",
                workspace_root.display()
            );
        }
        let members = workspace_closure(&graph, &[package]);
        let declared = declared_dependencies(&graph, &members)?;

        let lock_path = workspace_root.join("Cargo.lock");
        let lock_text = std::fs::read_to_string(&lock_path)
            .with_context(|| format!("reading {}", lock_path.display()))?;
        let lock = CargoLock::parse(&lock_text)?;
        let root_manifest_path = workspace_root.join("Cargo.toml");
        let root_manifest = std::fs::read_to_string(&root_manifest_path)
            .with_context(|| format!("reading {}", root_manifest_path.display()))?;
        let root_manifest: toml::Table = root_manifest
            .parse()
            .with_context(|| format!("parsing {}", root_manifest_path.display()))?;

        let closure = lock.external_closure(&members, &declared)?;
        let patched = patched_paths(&root_manifest);

        let mut sources = Vec::new();
        for member in &members {
            sources.extend(hash_member(workspace_root, &graph.dirs[member]));
        }
        for name in &closure.path_packages {
            let dir = patched.get(name).with_context(|| {
                format!(
                    "Cargo.lock resolves `{name}` to a path, but it is neither a workspace \
                     crate nor a `[patch]` entry in the root manifest"
                )
            })?;
            sources.extend(hash_member(workspace_root, &workspace_root.join(dir)));
        }
        sources.sort();

        let direct: BTreeSet<&str> = declared.values().flatten().map(String::as_str).collect();
        Ok(Self {
            sources,
            locked: closure.locked,
            build_settings: build_settings(&root_manifest, &direct)?,
        })
    }
}

/// Non-dev dependency names each workspace crate in `members` declares.
fn declared_dependencies(
    graph: &WorkspaceGraph,
    members: &[String],
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut declared = BTreeMap::new();
    for member in members {
        let manifest = graph.dirs[member].join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .with_context(|| format!("reading {}", manifest.display()))?;
        declared.insert(member.clone(), parse_manifest_deps(&text));
    }
    Ok(declared)
}

/// `[patch.<registry>]` entries that point at a directory, by crate name.
fn patched_paths(root_manifest: &toml::Table) -> BTreeMap<String, PathBuf> {
    let mut paths = BTreeMap::new();
    let Some(toml::Value::Table(registries)) = root_manifest.get("patch") else {
        return paths;
    };
    for patches in registries.values() {
        let toml::Value::Table(patches) = patches else {
            continue;
        };
        for (name, spec) in patches {
            if let Some(path) = spec.get("path").and_then(toml::Value::as_str) {
                paths.insert(name.clone(), PathBuf::from(path));
            }
        }
    }
    paths
}

/// The root-manifest tables that change the compiled bytes: the release
/// profile the flake builds under, the `[patch]` overrides, and the
/// `[workspace.dependencies]` entries — which carry features — for the crates
/// the closure declares. Entries for any other crate are left out, for the same
/// reason the rest of the lockfile is.
fn build_settings(root_manifest: &toml::Table, direct: &BTreeSet<&str>) -> Result<Vec<String>> {
    let mut settings = Vec::new();
    if let Some(release) = root_manifest.get("profile").and_then(|p| p.get("release")) {
        settings.push(render_table_entry("profile.release", release)?);
    }
    if let Some(patch) = root_manifest.get("patch") {
        settings.push(render_table_entry("patch", patch)?);
    }
    if let Some(toml::Value::Table(dependencies)) = root_manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
    {
        for (name, spec) in dependencies {
            if direct.contains(name.as_str()) {
                settings.push(render_table_entry(
                    &format!("workspace.dependencies.{name}"),
                    spec,
                )?);
            }
        }
    }
    Ok(settings)
}

/// Render `value` as TOML under `key`, so a value that is a bare string (`foo =
/// "1"`) and one that is a table serialise through the same path.
fn render_table_entry(key: &str, value: &toml::Value) -> Result<String> {
    let mut table = toml::Table::new();
    table.insert(key.to_string(), value.clone());
    toml::to_string(&table).with_context(|| format!("rendering root manifest entry {key}"))
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Debug, Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// What a set of workspace crates resolves to outside the workspace.
#[derive(Debug, Default, PartialEq, Eq)]
struct ExternalClosure {
    /// `name version source checksum`, one per locked registry or git crate.
    locked: Vec<String>,
    /// Crates the lock resolves to a local path that are not workspace members.
    path_packages: Vec<String>,
}

impl CargoLock {
    fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("parsing Cargo.lock")
    }

    /// The workspace crate named `name`: the one entry with no `source`.
    fn workspace_entry(&self, name: &str) -> Result<&LockedPackage> {
        self.package
            .iter()
            .find(|p| p.name == name && p.source.is_none())
            .with_context(|| {
                format!(
                    "Cargo.lock has no entry for workspace crate `{name}`, so it is out of \
                     date with the manifests; run `cargo check` to refresh it"
                )
            })
    }

    /// Resolve a lock dependency spec — `name`, `name version`, or
    /// `name version (source)` — to its entry.
    fn resolve(&self, spec: &str) -> Result<&LockedPackage> {
        let mut parts = spec.split_whitespace();
        let name = parts.next().unwrap_or_default();
        let version = parts.next();
        let mut matches = self
            .package
            .iter()
            .filter(|p| p.name == name && version.is_none_or(|v| p.version == v));
        let first = matches.next().with_context(|| {
            format!("Cargo.lock names dependency `{spec}` but has no entry for it")
        })?;
        if matches.next().is_some() {
            anyhow::bail!("Cargo.lock dependency `{spec}` matches more than one entry");
        }
        Ok(first)
    }

    /// Every external crate reachable from `members` through the dependencies
    /// each member declares outside `[dev-dependencies]`.
    ///
    /// A workspace crate's lock entry lists its dev-dependencies alongside the
    /// rest, and nothing a test pulls in reaches a binary, so the walk starts
    /// only from the names the manifest declares for building. External
    /// crates' own lock entries carry no dev-dependencies, so from there the
    /// walk follows the lock as written.
    fn external_closure(
        &self,
        members: &[String],
        declared: &BTreeMap<String, Vec<String>>,
    ) -> Result<ExternalClosure> {
        let member_set: BTreeSet<&str> = members.iter().map(String::as_str).collect();
        let mut queue = Vec::new();
        for member in members {
            let entry = self.workspace_entry(member)?;
            let names = declared.get(member).map(Vec::as_slice).unwrap_or_default();
            for spec in &entry.dependencies {
                let name = spec.split_whitespace().next().unwrap_or_default();
                if names.iter().any(|n| n == name) && !member_set.contains(name) {
                    queue.push(self.resolve(spec)?);
                }
            }
        }

        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        let mut closure = ExternalClosure::default();
        while let Some(package) = queue.pop() {
            if !seen.insert((&package.name, &package.version)) {
                continue;
            }
            match &package.source {
                Some(source) => closure.locked.push(format!(
                    "{} {} {} {}",
                    package.name,
                    package.version,
                    source,
                    package.checksum.as_deref().unwrap_or("-")
                )),
                None => closure.path_packages.push(package.name.clone()),
            }
            for spec in &package.dependencies {
                queue.push(self.resolve(spec)?);
            }
        }
        closure.locked.sort();
        closure.path_packages.sort();
        Ok(closure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 4

[[package]]
name = "mvm-agentd"
version = "0.1.0"
dependencies = ["libc", "mvm-core", "tempfile"]

[[package]]
name = "mvm-core"
version = "0.1.0"
dependencies = ["serde 1.0.0", "arrayref"]

[[package]]
name = "libc"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"

[[package]]
name = "serde"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccc"

[[package]]
name = "arrayref"
version = "0.3.9"

[[package]]
name = "tempfile"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddd"
"#;

    fn declared() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([
            (
                "mvm-agentd".to_string(),
                vec!["libc".to_string(), "mvm-core".to_string()],
            ),
            (
                "mvm-core".to_string(),
                vec!["arrayref".to_string(), "serde".to_string()],
            ),
        ])
    }

    fn members() -> Vec<String> {
        vec!["mvm-agentd".to_string(), "mvm-core".to_string()]
    }

    #[test]
    fn the_closure_follows_declared_dependencies_and_resolves_versions() {
        let lock = CargoLock::parse(LOCK).expect("parse");
        let closure = lock
            .external_closure(&members(), &declared())
            .expect("closure");

        let names: Vec<&str> = closure
            .locked
            .iter()
            .map(|entry| entry.split(' ').next().unwrap_or_default())
            .collect();
        assert_eq!(names, vec!["libc", "serde"]);
        assert!(
            closure.locked.iter().any(|e| e.contains("serde 1.0.0")),
            "a versioned spec must pick that version, not another of the same name: {:?}",
            closure.locked
        );
        assert_eq!(closure.path_packages, vec!["arrayref".to_string()]);
    }

    #[test]
    fn a_dev_only_dependency_is_not_in_the_closure() {
        let lock = CargoLock::parse(LOCK).expect("parse");
        let closure = lock
            .external_closure(&members(), &declared())
            .expect("closure");
        assert!(
            !closure.locked.iter().any(|e| e.starts_with("tempfile ")),
            "tempfile is only a dev-dependency of mvm-agentd: {:?}",
            closure.locked
        );
    }

    #[test]
    fn a_member_missing_from_the_lock_is_refused() {
        let lock = CargoLock::parse("version = 4\n").expect("parse");
        let err = lock
            .external_closure(&members(), &declared())
            .expect_err("a lock without the member cannot be the one the flake builds against");
        assert!(err.to_string().contains("mvm-agentd"), "{err}");
    }

    #[test]
    fn an_ambiguous_unversioned_spec_is_refused() {
        let lock = CargoLock::parse(LOCK).expect("parse");
        let err = lock.resolve("serde").expect_err("two serde entries");
        assert!(err.to_string().contains("more than one"), "{err}");
    }

    #[test]
    fn build_settings_keep_only_the_closures_workspace_dependencies() {
        let manifest: toml::Table = r#"
[workspace.dependencies]
libc = "0.2"
serde = { version = "1", features = ["derive"] }
unrelated = "9"

[profile.release]
lto = true

[profile.dev]
opt-level = 0

[patch.crates-io]
arrayref = { path = "third_party/arrayref" }
"#
        .parse()
        .expect("manifest");
        let direct = BTreeSet::from(["libc", "serde"]);

        let settings = build_settings(&manifest, &direct).expect("settings");
        let joined = settings.join("\n");

        assert!(joined.contains("libc"), "{joined}");
        assert!(joined.contains("derive"), "{joined}");
        assert!(joined.contains("lto"), "{joined}");
        assert!(joined.contains("third_party/arrayref"), "{joined}");
        assert!(!joined.contains("unrelated"), "{joined}");
        assert!(
            !joined.contains("opt-level"),
            "the dev profile does not build the image: {joined}"
        );
        assert_eq!(
            patched_paths(&manifest).get("arrayref"),
            Some(&PathBuf::from("third_party/arrayref"))
        );
    }

    fn shipped_workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root")
    }

    /// The real tree resolves to the leaf and nothing else: its own source and
    /// `libc`. A workspace crate or a second external crate in the closure is
    /// one whose every edit rebuilds the builder image again.
    #[test]
    fn the_shipped_setpriv_closure_is_the_leaf_and_libc() {
        let inputs = PackageInputs::read(&shipped_workspace(), SETPRIV_PACKAGE)
            .expect("the shipped workspace resolves");

        let paths: Vec<&str> = inputs.sources.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            paths.contains(&"crates/mvm-setpriv/src/lib.rs"),
            "the helper's own source must be hashed: {paths:?}"
        );
        let outside: Vec<&&str> = paths
            .iter()
            .filter(|p| !p.starts_with("crates/mvm-setpriv/"))
            .collect();
        assert!(
            outside.is_empty(),
            "the setpriv closure reaches beyond its leaf: {outside:?}"
        );
        let external: Vec<&str> = inputs
            .locked
            .iter()
            .map(|e| e.split(' ').next().unwrap_or_default())
            .collect();
        assert_eq!(external, vec!["libc"], "{:?}", inputs.locked);
    }

    /// The key hashes the package the recipe compiles. A recipe pointed at
    /// another package would build bytes the key never looked at.
    #[test]
    fn the_nix_recipe_builds_the_package_the_key_hashes() {
        let recipe =
            std::fs::read_to_string(shipped_workspace().join("nix/packages/mvm-setpriv.nix"))
                .expect("read the setpriv recipe");
        let flags: Vec<&str> = recipe
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('"') && line.ends_with('"'))
            .map(|line| line.trim_matches('"'))
            .collect();
        let package = flags
            .iter()
            .position(|flag| *flag == "--package")
            .and_then(|at| flags.get(at + 1))
            .expect("the recipe names a --package");
        assert_eq!(*package, SETPRIV_PACKAGE);
        let bin = flags
            .iter()
            .position(|flag| *flag == "--bin")
            .and_then(|at| flags.get(at + 1))
            .expect("the recipe names a --bin");
        assert_eq!(*bin, "mvm-setpriv");

        let manifest: toml::Table = std::fs::read_to_string(
            shipped_workspace().join(format!("crates/{SETPRIV_PACKAGE}/Cargo.toml")),
        )
        .expect("read the package manifest")
        .parse()
        .expect("parse the package manifest");
        let bins: Vec<&str> = manifest
            .get("bin")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|target| target.get("name").and_then(toml::Value::as_str))
            .collect();
        assert!(
            bins.contains(bin),
            "{SETPRIV_PACKAGE} declares no `{bin}` binary: {bins:?}"
        );
    }

    #[test]
    fn fold_entry_boundaries_are_unambiguous() {
        let digest = |domain: &str, entry: &str| {
            let mut h = Sha256::new();
            fold_entry(&mut h, domain, entry);
            hex::encode(h.finalize())
        };
        assert_ne!(digest("package-src", "ab"), digest("package-sr", "cab"));
        assert_ne!(digest("package-src", "a"), digest("package-lock", "a"));
    }
}
