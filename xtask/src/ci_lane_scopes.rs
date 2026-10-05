//! `xtask ci-lane-scopes`
//!
//! Decide which specialist CI lanes a change can affect.
//!
//! `ci.yml`'s `scope` job decides with path regexes whether a change touches
//! code at all. That decision is deliberately broad: a regex cannot follow a
//! dependency edge, and a lane skipped by a regex that missed one is a lane the
//! `Test` aggregate then accepts as correctly skipped. This narrows `code` per
//! lane from the cargo graph instead.
//!
//! A lane is described by what it builds — root packages, the features it
//! enables, the platform it runs on — plus a hand-maintained list of the
//! non-Cargo files it reads: its workflow, recipes, scripts, and anything its
//! tests open at runtime. The lane's local package closure comes from
//! `cargo metadata` resolved with exactly those features and that platform,
//! following normal and build edges everywhere and dev edges only from the
//! roots whose tests the lane builds. Files a closure package compiles in from
//! outside its own directory (`include_str!`, `include_bytes!`, `#[path]`) are
//! added to the lane's inputs mechanically, because those are exactly the
//! edges a package-directory rule misses.
//!
//! A changed file runs a lane when it is a global input, one of the lane's
//! inputs, or part of a package in the lane's closure. A file that belongs to a
//! package outside the closure does not, nor does a file on the short list of
//! paths no specialist lane reads. Anything else is unclassified and runs every
//! lane, as does an empty change list.
//!
//! Output is one `<lane>=<true|false>` line per lane on stdout, ready to append
//! to `$GITHUB_OUTPUT`; the reason for each decision goes to stderr so the CI
//! log records what put a lane in scope.

use crate::fs_walk;
use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// A package a lane builds, and whether it builds that package's tests — which
/// is what brings the package's dev-dependencies into the closure.
struct Root {
    package: &'static str,
    tests: bool,
}

/// One specialist lane, described by what it compiles and what else it reads.
struct Lane {
    /// The `ci-lane-scopes` output key.
    name: &'static str,
    /// The target triple the lane's runner builds for.
    platform: &'static str,
    /// Features the lane enables, as `package/feature`.
    features: &'static [&'static str],
    roots: &'static [Root],
    /// Non-Cargo inputs. An entry ending in `/` is a directory prefix; any
    /// other entry is one file.
    inputs: &'static [&'static str],
}

/// Inputs every lane reads: the dependency lock and workspace manifest, the
/// toolchain pin, cargo and nextest configuration, the composite actions and
/// the workflow that runs every lane, the root recipe file every `just`
/// module hangs off, and this classifier.
const GLOBAL_INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/",
    ".config/",
    ".github/actions/",
    ".github/workflows/ci.yml",
    "Justfile",
    "xtask/src/ci_lane_scopes.rs",
];

/// Paths no specialist lane reads. A lane that does read one lists it in its
/// own inputs, which are consulted first, so this list only decides what an
/// otherwise unclassified file means.
const INERT: &[&str] = &["specs/", "public/"];

/// `just bdd::run` followed by `just sdk::test`, as `bdd.yml` runs them.
const BDD: Lane = Lane {
    name: "bdd",
    platform: "x86_64-unknown-linux-gnu",
    features: &[
        "mvmctl/user",
        "mvm-sdk/schema",
        "mvm-agentd/schema",
        "mvm-core/schema",
        "mvm-conformance/bdd",
    ],
    roots: &[
        Root {
            package: "mvmctl",
            tests: false,
        },
        Root {
            package: "xtask",
            tests: false,
        },
        Root {
            package: "mvm-sdk",
            tests: false,
        },
        Root {
            package: "mvm-agentd",
            tests: false,
        },
        Root {
            package: "mvm-core",
            tests: false,
        },
        Root {
            package: "mvm-conformance",
            tests: true,
        },
    ],
    inputs: &[
        // The claim scenarios resolve every `fn:` witness by scanning each
        // crate's `src/` and `tests/`, and every `ci:` witness by scanning the
        // workflows, so both trees are read whole whatever the closure says.
        "crates/",
        ".github/workflows/",
        "features/",
        "just/bdd/",
        "just/sdk/",
        "scripts/cargo-fast.sh",
        "scripts/cargo-target-dir-guard.sh",
        // The documentation scenarios and the conformance build script read
        // the published documentation set.
        "README.md",
        "AGENTS.md",
        "public/src/content/docs/",
        "examples/",
        "model/",
        "schema/",
        "nix/",
        "install.sh",
        "specs/adrs/001-microvm-security-posture.md",
    ],
};

const LANES: &[Lane] = &[BDD];

pub fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let changed = match args {
        [flag] if flag == "--all" => None,
        [] => {
            let mut raw = Vec::new();
            std::io::stdin()
                .read_to_end(&mut raw)
                .context("read the changed paths from stdin")?;
            Some(parse_changed(&raw))
        }
        _ => bail!("usage: ci-lane-scopes [--all] < changed-paths"),
    };
    let decisions = match &changed {
        None => LANES
            .iter()
            .map(|lane| (lane.name, Some(Trigger::Requested)))
            .collect(),
        Some(changed) => decide(workspace, changed)?,
    };
    for (name, trigger) in &decisions {
        match trigger {
            Some(trigger) => eprintln!("{name}: runs — {trigger}"),
            None => eprintln!("{name}: skips — no changed path reaches it"),
        }
        println!("{name}={}", trigger.is_some());
    }
    Ok(())
}

/// Split `git diff --name-only` output, NUL- or newline-separated.
fn parse_changed(raw: &[u8]) -> Vec<String> {
    raw.split(|byte| *byte == 0 || *byte == b'\n')
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect()
}

fn decide<'a>(
    workspace: &Path,
    changed: &'a [String],
) -> Result<Vec<(&'static str, Option<Trigger<'a>>)>> {
    LANES
        .iter()
        .map(|lane| {
            let metadata = Metadata::load(workspace, lane)?;
            let owners = Owners::from_metadata(&metadata)?;
            let model = LaneModel::build(&metadata, &owners, lane)?;
            Ok((lane.name, model.first_trigger(&owners, changed)))
        })
        .collect()
}

/// Why a lane is in scope.
#[derive(Debug, PartialEq, Eq)]
enum Trigger<'a> {
    Requested,
    NothingChanged,
    Global(&'a str),
    Input(&'a str),
    Package(&'a str, String),
    Unclassified(&'a str),
}

impl fmt::Display for Trigger<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => write!(f, "every lane was requested"),
            Self::NothingChanged => write!(f, "the change list was empty"),
            Self::Global(path) => write!(f, "{path} is read by every lane"),
            Self::Input(path) => write!(f, "{path} is one of the lane's inputs"),
            Self::Package(path, package) => {
                write!(f, "{path} belongs to {package}, in the lane's closure")
            }
            Self::Unclassified(path) => write!(f, "{path} is not classified"),
        }
    }
}

/// Whether `entry` (a `dir/` prefix or one file) covers `path`.
fn covers(entry: &str, path: &str) -> bool {
    if entry.ends_with('/') {
        path.starts_with(entry)
    } else {
        path == entry
    }
}

fn listed(entries: &[&str], path: &str) -> bool {
    entries.iter().any(|entry| covers(entry, path))
}

/// Which local package owns each workspace path.
struct Owners {
    /// `(prefix, package)`, longest prefix first so a nested package wins.
    prefixes: Vec<(String, String)>,
}

impl Owners {
    fn new(mut prefixes: Vec<(String, String)>) -> Self {
        prefixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        Self { prefixes }
    }

    /// Every local package owns its directory. The root package's directory
    /// is the whole workspace, so it owns only what its targets are built
    /// from: `src/`, `tests/`, `build.rs`.
    fn from_metadata(metadata: &Metadata) -> Result<Self> {
        let mut prefixes = Vec::new();
        for package in metadata.packages.iter().filter(|p| p.source.is_none()) {
            let dir = package
                .manifest_path
                .parent()
                .with_context(|| format!("{} has no manifest directory", package.name))?;
            let relative = relative_to(&metadata.workspace_root, dir)?;
            if !relative.is_empty() {
                prefixes.push((format!("{relative}/"), package.name.clone()));
                continue;
            }
            let mut owned = BTreeSet::new();
            for target in &package.targets {
                let source = relative_to(&metadata.workspace_root, &target.src_path)?;
                owned.insert(match source.split_once('/') {
                    Some((top, _)) => format!("{top}/"),
                    None => source,
                });
            }
            prefixes.extend(
                owned
                    .into_iter()
                    .map(|prefix| (prefix, package.name.clone())),
            );
        }
        Ok(Self::new(prefixes))
    }

    fn owner(&self, path: &str) -> Option<&str> {
        self.prefixes
            .iter()
            .find(|(prefix, _)| covers(prefix, path))
            .map(|(_, package)| package.as_str())
    }
}

/// A lane's resolved scope: its package closure and every non-package input.
struct LaneModel {
    closure: BTreeSet<String>,
    inputs: Vec<String>,
}

impl LaneModel {
    fn build(metadata: &Metadata, owners: &Owners, lane: &Lane) -> Result<Self> {
        let closure = metadata.closure(lane.roots)?;
        let mut inputs: Vec<String> = lane.inputs.iter().map(|entry| entry.to_string()).collect();
        inputs.extend(escaping_sources(
            &metadata.workspace_root,
            owners,
            &closure,
        )?);
        Ok(Self { closure, inputs })
    }

    /// The first changed path that puts the lane in scope, if any does.
    fn first_trigger<'a>(&self, owners: &Owners, changed: &'a [String]) -> Option<Trigger<'a>> {
        if changed.is_empty() {
            return Some(Trigger::NothingChanged);
        }
        changed.iter().find_map(|path| self.trigger(owners, path))
    }

    fn trigger<'a>(&self, owners: &Owners, path: &'a str) -> Option<Trigger<'a>> {
        if listed(GLOBAL_INPUTS, path) {
            return Some(Trigger::Global(path));
        }
        if self.inputs.iter().any(|entry| covers(entry, path)) {
            return Some(Trigger::Input(path));
        }
        if let Some(package) = owners.owner(path) {
            return self
                .closure
                .contains(package)
                .then(|| Trigger::Package(path, package.to_string()));
        }
        if listed(INERT, path) {
            return None;
        }
        Some(Trigger::Unclassified(path))
    }
}

/// Workspace files a closure package compiles in from outside its own
/// directory. Each literal `include_str!`, `include_bytes!` or `#[path]`
/// argument is resolved against the directory of the file naming it; the ones
/// that land outside every closure package are returned as file inputs.
fn escaping_sources(
    workspace_root: &Path,
    owners: &Owners,
    closure: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    static REFERENCE: OnceLock<Regex> = OnceLock::new();
    let reference = REFERENCE.get_or_init(|| {
        Regex::new(r#"(?:include_str!|include_bytes!)\(\s*"([^"]+)"|#\[path\s*=\s*"([^"]+)"\]"#)
            .expect("the source-reference pattern is a valid regex")
    });
    let mut found = BTreeSet::new();
    let mut scan = |file: &Path, text: &str| {
        let Ok(relative) = relative_to(workspace_root, file) else {
            return;
        };
        let dir = Path::new(&relative).parent().unwrap_or(Path::new(""));
        for captures in reference.captures_iter(text) {
            let Some(literal) = captures.get(1).or_else(|| captures.get(2)) else {
                continue;
            };
            if let Some(target) = normalize(&dir.join(literal.as_str()))
                && !owners
                    .owner(&target)
                    .is_some_and(|owner| closure.contains(owner))
            {
                found.insert(target);
            }
        }
    };
    for (prefix, package) in &owners.prefixes {
        if !closure.contains(package) {
            continue;
        }
        let path = workspace_root.join(prefix);
        if path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                scan(&path, &text);
            }
        } else {
            fs_walk::for_each_file(&path, Some("rs"), &mut scan)?;
        }
    }
    Ok(found)
}

/// Resolve `.` and `..` lexically. `None` when the path climbs out of the
/// workspace, where no change in this repository can reach it.
fn normalize(path: &Path) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

fn relative_to(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    normalize(relative).with_context(|| format!("cannot normalise {}", relative.display()))
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
    workspace_root: PathBuf,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    source: Option<String>,
    manifest_path: PathBuf,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    src_path: PathBuf,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<NodeDep>,
}

#[derive(Deserialize)]
struct NodeDep {
    pkg: String,
    dep_kinds: Vec<DepKind>,
}

#[derive(Deserialize)]
struct DepKind {
    kind: Option<String>,
}

impl Metadata {
    /// The graph exactly as the lane resolves it.
    fn load(workspace: &Path, lane: &Lane) -> Result<Self> {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let features = lane.features.join(",");
        let mut command = Command::new(cargo);
        command.current_dir(workspace).args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            lane.platform,
        ]);
        if !features.is_empty() {
            command.args(["--features", &features]);
        }
        let output = command
            .output()
            .with_context(|| format!("run cargo metadata for the {} lane", lane.name))?;
        ensure!(
            output.status.success(),
            "cargo metadata for the {} lane failed: {}",
            lane.name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        serde_json::from_slice(&output.stdout).context("parse cargo metadata")
    }

    /// Local packages reachable from `roots`. External packages are walked
    /// through rather than collected, because a patched crate (`third_party/`)
    /// is local yet reached only through registry crates that depend on it.
    fn closure(&self, roots: &[Root]) -> Result<BTreeSet<String>> {
        let packages: HashMap<&str, &Package> =
            self.packages.iter().map(|p| (p.id.as_str(), p)).collect();
        let nodes: HashMap<&str, &Node> = self
            .resolve
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n))
            .collect();
        let mut queue = VecDeque::new();
        for root in roots {
            let package = self
                .packages
                .iter()
                .find(|p| p.source.is_none() && p.name == root.package)
                .with_context(|| format!("lane root {} is not a local package", root.package))?;
            queue.push_back((package.id.as_str(), root.tests));
        }
        let mut seen = BTreeSet::new();
        while let Some((id, tests)) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            let node = nodes
                .get(id)
                .with_context(|| format!("{id} is missing from the resolved graph"))?;
            for dep in &node.deps {
                if tests
                    || dep
                        .dep_kinds
                        .iter()
                        .any(|k| k.kind.as_deref() != Some("dev"))
                {
                    queue.push_back((dep.pkg.as_str(), false));
                }
            }
        }
        Ok(seen
            .into_iter()
            .filter_map(|id| packages.get(id))
            .filter(|p| p.source.is_none())
            .map(|p| p.name.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives inside the workspace")
            .to_path_buf()
    }

    /// Two packages in the closure, one outside it, and the root package.
    fn owners() -> Owners {
        Owners::new(vec![
            ("crates/in-lane/".into(), "in-lane".into()),
            ("crates/in-lane/nested/".into(), "nested".into()),
            ("crates/off-lane/".into(), "off-lane".into()),
            ("src/".into(), "root".into()),
            ("build.rs".into(), "root".into()),
        ])
    }

    fn model() -> LaneModel {
        LaneModel {
            closure: ["in-lane", "root"].into_iter().map(String::from).collect(),
            inputs: vec!["features/".into(), "scripts/lane.sh".into()],
        }
    }

    fn runs(paths: &[&str]) -> bool {
        let changed: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
        model().first_trigger(&owners(), &changed).is_some()
    }

    #[test]
    fn a_change_inside_the_closure_runs_the_lane() {
        assert!(runs(&["crates/in-lane/src/lib.rs"]));
        assert!(runs(&["crates/in-lane/Cargo.toml"]));
        assert!(runs(&["src/main.rs"]));
        assert!(runs(&["build.rs"]));
    }

    #[test]
    fn a_change_outside_the_closure_skips_the_lane() {
        assert!(!runs(&["crates/off-lane/src/lib.rs"]));
        assert!(!runs(&["crates/off-lane/Cargo.toml"]));
        assert!(!runs(&["crates/off-lane/src/lib.rs", "specs/plans/x.md"]));
    }

    #[test]
    fn the_longest_owning_prefix_decides() {
        // `nested` sits inside `in-lane`'s directory but is its own package.
        assert!(!runs(&["crates/in-lane/nested/src/lib.rs"]));
        assert!(runs(&["crates/in-lane/src/nested.rs"]));
    }

    #[test]
    fn a_lane_input_runs_the_lane() {
        assert!(runs(&["features/suites/s0_cli/cli.feature"]));
        assert!(runs(&["scripts/lane.sh"]));
        assert_eq!(
            model().trigger(&owners(), "scripts/lane.sh.bak"),
            Some(Trigger::Unclassified("scripts/lane.sh.bak")),
            "a file entry is not a prefix"
        );
    }

    #[test]
    fn an_unclassified_file_runs_every_lane() {
        for path in [
            "scripts/other.sh",
            "assets/logo.svg",
            "Cargo.toml.orig",
            ".gitignore",
        ] {
            assert_eq!(
                model().trigger(&owners(), path),
                Some(Trigger::Unclassified(path)),
                "{path} must fail closed"
            );
        }
        assert!(runs(&["crates/off-lane/src/lib.rs", "assets/logo.svg"]));
    }

    #[test]
    fn global_inputs_run_every_lane_even_with_an_empty_closure() {
        let empty = LaneModel {
            closure: BTreeSet::new(),
            inputs: Vec::new(),
        };
        for path in [
            "Cargo.lock",
            "Cargo.toml",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            ".github/workflows/ci.yml",
            "xtask/src/ci_lane_scopes.rs",
        ] {
            assert_eq!(
                empty.trigger(&owners(), path),
                Some(Trigger::Global(path)),
                "{path} must run every lane"
            );
        }
    }

    #[test]
    fn a_member_manifest_is_owned_by_its_package_not_global() {
        assert_eq!(
            model().trigger(&owners(), "crates/off-lane/Cargo.toml"),
            None,
            "a member's manifest belongs to that member; only the workspace manifest is global"
        );
    }

    #[test]
    fn an_empty_change_list_runs_the_lane() {
        assert_eq!(
            model().first_trigger(&owners(), &[]),
            Some(Trigger::NothingChanged)
        );
    }

    #[test]
    fn changed_paths_parse_from_nul_or_newline_separated_diffs() {
        assert_eq!(
            parse_changed(b"a.rs\0crates/b c.rs\0\0"),
            vec!["a.rs".to_string(), "crates/b c.rs".to_string()]
        );
        assert_eq!(parse_changed(b"a.rs\nb.rs\n"), vec!["a.rs", "b.rs"]);
        assert!(parse_changed(b"").is_empty());
    }

    #[test]
    fn normalize_resolves_parents_and_refuses_to_leave_the_workspace() {
        assert_eq!(
            normalize(Path::new("crates/mvm-cli/src/../../../install.sh")).as_deref(),
            Some("install.sh")
        );
        assert_eq!(normalize(Path::new("./a/./b")).as_deref(), Some("a/b"));
        assert_eq!(normalize(Path::new("a/../../b")), None);
    }

    fn metadata(json: &str) -> Metadata {
        serde_json::from_str(json).expect("fixture metadata parses")
    }

    /// `app` tests with `fixture` (dev), builds with `codegen` (build), and
    /// reaches the patched `patched` only through the registry crate `ext`.
    /// `lib` dev-depends on `lib-dev`, which the lane never builds.
    const GRAPH: &str = r#"{
        "workspace_root": "/w",
        "packages": [
            {"id": "app", "name": "app", "source": null, "manifest_path": "/w/app/Cargo.toml", "targets": []},
            {"id": "lib", "name": "lib", "source": null, "manifest_path": "/w/lib/Cargo.toml", "targets": []},
            {"id": "lib-dev", "name": "lib-dev", "source": null, "manifest_path": "/w/lib-dev/Cargo.toml", "targets": []},
            {"id": "fixture", "name": "fixture", "source": null, "manifest_path": "/w/fixture/Cargo.toml", "targets": []},
            {"id": "codegen", "name": "codegen", "source": null, "manifest_path": "/w/codegen/Cargo.toml", "targets": []},
            {"id": "ext", "name": "ext", "source": "registry+https://example", "manifest_path": "/r/ext/Cargo.toml", "targets": []},
            {"id": "patched", "name": "patched", "source": null, "manifest_path": "/w/third_party/patched/Cargo.toml", "targets": []},
            {"id": "unrelated", "name": "unrelated", "source": null, "manifest_path": "/w/unrelated/Cargo.toml", "targets": []}
        ],
        "resolve": {"nodes": [
            {"id": "app", "deps": [
                {"pkg": "lib", "dep_kinds": [{"kind": null}]},
                {"pkg": "fixture", "dep_kinds": [{"kind": "dev"}]},
                {"pkg": "codegen", "dep_kinds": [{"kind": "build"}]}
            ]},
            {"id": "lib", "deps": [
                {"pkg": "ext", "dep_kinds": [{"kind": null}]},
                {"pkg": "lib-dev", "dep_kinds": [{"kind": "dev"}]}
            ]},
            {"id": "lib-dev", "deps": []},
            {"id": "fixture", "deps": []},
            {"id": "codegen", "deps": []},
            {"id": "ext", "deps": [{"pkg": "patched", "dep_kinds": [{"kind": null}]}]},
            {"id": "patched", "deps": []},
            {"id": "unrelated", "deps": []}
        ]}
    }"#;

    fn closure_of(roots: &[Root]) -> Vec<String> {
        metadata(GRAPH)
            .closure(roots)
            .expect("closure resolves")
            .into_iter()
            .collect()
    }

    #[test]
    fn the_closure_follows_build_edges_and_registry_crates_and_dev_edges_only_from_tested_roots() {
        assert_eq!(
            closure_of(&[Root {
                package: "app",
                tests: true,
            }]),
            vec!["app", "codegen", "fixture", "lib", "patched"]
        );
        assert_eq!(
            closure_of(&[Root {
                package: "app",
                tests: false,
            }]),
            vec!["app", "codegen", "lib", "patched"]
        );
    }

    #[test]
    fn an_unknown_root_is_an_error_not_an_empty_closure() {
        assert!(
            metadata(GRAPH)
                .closure(&[Root {
                    package: "renamed",
                    tests: false,
                }])
                .is_err()
        );
    }

    #[test]
    fn the_root_package_owns_only_what_its_targets_build_from() {
        let owners = Owners::from_metadata(&metadata(
            r#"{
                "workspace_root": "/w",
                "packages": [
                    {"id": "root", "name": "root", "source": null, "manifest_path": "/w/Cargo.toml", "targets": [
                        {"src_path": "/w/src/main.rs"},
                        {"src_path": "/w/src/lib.rs"},
                        {"src_path": "/w/tests/cli.rs"},
                        {"src_path": "/w/build.rs"}
                    ]},
                    {"id": "member", "name": "member", "source": null, "manifest_path": "/w/crates/member/Cargo.toml", "targets": []},
                    {"id": "ext", "name": "ext", "source": "registry+https://example", "manifest_path": "/r/ext/Cargo.toml", "targets": []}
                ],
                "resolve": {"nodes": []}
            }"#,
        ))
        .expect("owners resolve");
        assert_eq!(owners.owner("src/commands/x.rs"), Some("root"));
        assert_eq!(owners.owner("tests/fixtures/a.json"), Some("root"));
        assert_eq!(owners.owner("build.rs"), Some("root"));
        assert_eq!(owners.owner("crates/member/src/lib.rs"), Some("member"));
        assert_eq!(owners.owner("scripts/x.sh"), None);
        assert_eq!(owners.owner("Cargo.lock"), None);
    }

    #[test]
    fn sources_compiled_in_from_outside_a_closure_package_become_inputs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("crates/in-lane/src/bin")).expect("mkdir");
        std::fs::create_dir_all(root.join("crates/off-lane/src")).expect("mkdir");
        std::fs::write(
            root.join("crates/in-lane/src/lib.rs"),
            concat!(
                "const A: &str = include_str!(\"../../../install.sh\");\n",
                "const B: &[u8] = include_bytes!(\n    \"../../off-lane/src/data.bin\"\n);\n",
                "const C: &str = include_str!(\"own.txt\");\n",
                "#[path = \"../../../shared/module.rs\"]\nmod shared;\n",
                "const D: &str = include_str!(\"../../../../outside\");\n",
            ),
        )
        .expect("write lib.rs");
        std::fs::write(
            root.join("crates/in-lane/src/bin/tool.rs"),
            "#[path = \"../helper.rs\"]\nmod helper;\n",
        )
        .expect("write tool.rs");
        std::fs::write(
            root.join("crates/off-lane/src/lib.rs"),
            "const E: &str = include_str!(\"../../../never.txt\");\n",
        )
        .expect("write off-lane");
        let owners = Owners::new(vec![
            ("crates/in-lane/".into(), "in-lane".into()),
            ("crates/off-lane/".into(), "off-lane".into()),
        ]);
        let closure = ["in-lane".to_string()].into_iter().collect();
        let found = escaping_sources(root, &owners, &closure).expect("scan");
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            vec![
                "crates/off-lane/src/data.bin",
                "install.sh",
                "shared/module.rs",
            ],
            "in-package references, out-of-closure scanners and paths outside the \
             workspace must not be reported"
        );
    }

    /// Every hand-listed path must name something that exists, so a rename
    /// cannot quietly turn an input into an entry that matches nothing.
    #[test]
    fn every_hand_listed_path_exists() {
        let root = workspace();
        let lists = [("global", GLOBAL_INPUTS), ("inert", INERT)]
            .into_iter()
            .chain(LANES.iter().map(|lane| (lane.name, lane.inputs)));
        for (list, entries) in lists {
            for entry in entries {
                let path = root.join(entry.trim_end_matches('/'));
                let exists = if entry.ends_with('/') {
                    path.is_dir()
                } else {
                    path.is_file()
                };
                assert!(exists, "{list} entry {entry:?} does not exist");
            }
        }
    }

    /// The lane description must match the recipe the lane runs.
    #[test]
    fn the_bdd_lane_matches_its_recipe() {
        let recipe = std::fs::read_to_string(workspace().join("just/bdd/mod.just"))
            .expect("read just/bdd/mod.just");
        let run = recipe
            .split_once("\nrun:\n")
            .and_then(|(_, rest)| rest.split("\n\n").next())
            .expect("just/bdd/mod.just must keep its run recipe");
        for expected in [
            "cargo build --bin mvmctl --features user",
            "build -p xtask",
            "-p mvm-sdk --features schema",
            "-p mvm-agentd --features schema",
            "-p mvm-core --features schema",
            "-p mvm-conformance --test conformance --features bdd",
        ] {
            assert!(
                run.contains(expected),
                "the bdd lane's roots and features were derived from {expected:?}; \
                 update BDD in ci_lane_scopes.rs alongside the recipe"
            );
        }
        let workflow = std::fs::read_to_string(workspace().join(".github/workflows/bdd.yml"))
            .expect("read bdd.yml");
        assert!(workflow.contains("runs-on: ubuntu-latest"));
        assert_eq!(BDD.platform, "x86_64-unknown-linux-gnu");
    }

    /// The real graph, for the crates a path-regex scope was found to miss.
    #[test]
    fn the_bdd_closure_holds_the_transitive_crates_a_path_regex_missed() {
        let root = workspace();
        let metadata = Metadata::load(&root, &BDD).expect("cargo metadata");
        let owners = Owners::from_metadata(&metadata).expect("owners");
        let model = LaneModel::build(&metadata, &owners, &BDD).expect("model");
        for package in ["mvmctl", "mvm-http", "mvm-net", "mvm-setpriv", "xtask"] {
            assert!(
                model.closure.contains(package),
                "{package} must be in the bdd closure"
            );
        }
        assert!(
            model.inputs.iter().any(|input| input == "install.sh"),
            "mvm-cli's include_str! of install.sh must surface as an input"
        );
        assert_eq!(owners.owner("src/main.rs"), Some("mvmctl"));
    }
}
