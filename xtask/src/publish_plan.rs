//! `xtask publish-plan` and `xtask check-publish-readiness`
//!
//! Which workspace crates go to crates.io, and in what order, derived from the
//! manifests instead of written down by hand. The hand-written list in
//! `publish-crates.yml` named four crates out of a 22-crate closure, left out
//! `mvm-contract` although `mvm-core` depends on it, and so could never have
//! published anything a crates.io consumer could build.
//!
//! The publish set is the normal- and build-dependency closure of the roots
//! in `[workspace.metadata.mvm.publish]`, ordered so every crate follows each
//! workspace crate it depends on. crates.io resolves a published crate's
//! dependencies from the registry, so publishing out of that order fails
//! mid-run with half the set uploaded.
//!
//! Some crates in the closure cannot be published yet. Each is declared under
//! `[workspace.metadata.mvm.publish.blocked]` with the reason, and the plan
//! withholds it together with every crate that depends on it, so a publish
//! run uploads the part of the set that works and says what it held back
//! instead of failing half way.
//!
//! `check-publish-readiness` holds the manifests to what publishing needs:
//!
//! - every workspace member outside the closure says `publish = false`, and
//!   nothing inside it does, so the closure and the published set agree;
//! - every crate in the closure has the `description`, `license` and
//!   `repository` crates.io requires or shows;
//! - no crate in the closure has a path-only dependency on a workspace crate,
//!   which cannot be rewritten to a registry dependency at publish time;
//! - no crate's library or build script reads source from outside its own
//!   directory (`include_str!`, `include_bytes!`, `#[path]`): `cargo package`
//!   ships only the crate's directory, so the published crate cannot build.
//!   A crate with such a read must be declared blocked for that reason, and a
//!   crate declared blocked for that reason must still have one, so the
//!   declaration cannot outlive the problem.
//!
//! A blocker of another kind, such as a crate name already owned by an
//! unrelated project, is a registry fact this offline gate cannot observe; it
//! is taken from the declaration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

/// The declared reason a crate cannot be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    /// `out-of-crate-source`, which this gate verifies, or any other kind,
    /// which it takes on trust.
    pub kind: String,
    pub reason: String,
}

/// The blocker kind this gate can see for itself.
const OUT_OF_CRATE_SOURCE: &str = "out-of-crate-source";

/// One workspace dependency edge of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Dep {
    name: String,
    /// `None` for a normal dependency, `Some("build")`/`Some("dev")` otherwise.
    kind: Option<String>,
    /// Whether the declaration carries a version requirement.
    versioned: bool,
}

/// What the gate and the plan need to know about a workspace member.
#[derive(Debug, Clone)]
struct Package {
    dir: PathBuf,
    publishable: bool,
    description: bool,
    license: bool,
    repository: bool,
    /// Edges to other workspace members.
    deps: Vec<Dep>,
}

/// The workspace as the plan sees it.
struct Workspace {
    packages: BTreeMap<String, Package>,
    roots: Vec<String>,
    blocked: BTreeMap<String, Blocker>,
}

/// The ordered publish set and what was held back.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// Crates to publish, dependencies first.
    pub publish: Vec<String>,
    /// Crates withheld, each with the reason.
    pub withheld: Vec<(String, String)>,
}

pub fn run_plan(workspace: &Path) -> Result<()> {
    let ws = load(workspace)?;
    let plan = plan(&ws)?;
    for name in &plan.publish {
        println!("{name}");
    }
    for (name, why) in &plan.withheld {
        eprintln!("publish-plan: withholding {name}: {why}");
    }
    Ok(())
}

pub fn run_check(workspace: &Path) -> Result<()> {
    let ws = load(workspace)?;
    let escapes = ws
        .packages
        .iter()
        .filter(|(name, _)| closure(&ws).contains(*name))
        .map(|(name, pkg)| Ok((name.clone(), out_of_crate_reads(&pkg.dir)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let problems = audit(&ws, &escapes);
    if !problems.is_empty() {
        bail!("check-publish-readiness:\n  {}", problems.join("\n  "));
    }
    let plan = plan(&ws)?;
    println!(
        "check-publish-readiness: clean ({} crates in the closure, {} publishable, {} withheld)",
        plan.publish.len() + plan.withheld.len(),
        plan.publish.len(),
        plan.withheld.len()
    );
    Ok(())
}

fn load(workspace: &Path) -> Result<Workspace> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("running `cargo metadata --no-deps`")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let meta: Value = serde_json::from_slice(&output.stdout).context("parsing cargo metadata")?;
    parse(&meta)
}

/// The workspace from `cargo metadata --no-deps` output. Pure, for testing.
fn parse(meta: &Value) -> Result<Workspace> {
    let raw = meta
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata has no `packages`")?;
    let names: BTreeSet<&str> = raw
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .collect();

    let mut packages = BTreeMap::new();
    for p in raw {
        let name = p
            .get("name")
            .and_then(Value::as_str)
            .context("package without a name")?;
        let manifest = p
            .get("manifest_path")
            .and_then(Value::as_str)
            .context("package without a manifest_path")?;
        let present = |key: &str| {
            p.get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
        };
        // `publish = false` is reported as an empty registry list.
        let publishable = !p
            .get("publish")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        let deps = p
            .get("dependencies")
            .and_then(Value::as_array)
            .map(|deps| {
                deps.iter()
                    .filter_map(|d| {
                        let dep = d.get("name")?.as_str()?;
                        names.contains(dep).then(|| Dep {
                            name: dep.to_string(),
                            kind: d.get("kind").and_then(Value::as_str).map(str::to_string),
                            versioned: d.get("req").and_then(Value::as_str) != Some("*"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        packages.insert(
            name.to_string(),
            Package {
                dir: Path::new(manifest)
                    .parent()
                    .context("manifest_path has no parent")?
                    .to_path_buf(),
                publishable,
                description: present("description"),
                license: present("license") || present("license_file"),
                repository: present("repository"),
                deps,
            },
        );
    }

    let config = meta
        .pointer("/metadata/mvm/publish")
        .context("the root Cargo.toml has no [workspace.metadata.mvm.publish]")?;
    let roots = config
        .get("roots")
        .and_then(Value::as_array)
        .context("[workspace.metadata.mvm.publish] has no `roots`")?
        .iter()
        .map(|r| {
            r.as_str()
                .map(str::to_string)
                .context("a root is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut blocked = BTreeMap::new();
    if let Some(table) = config.get("blocked").and_then(Value::as_object) {
        for (name, entry) in table {
            let field = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .with_context(|| format!("blocked crate `{name}` has no `{key}`"))
            };
            blocked.insert(
                name.clone(),
                Blocker {
                    kind: field("kind")?,
                    reason: field("reason")?,
                },
            );
        }
    }
    Ok(Workspace {
        packages,
        roots,
        blocked,
    })
}

/// Edges that ship with a published crate: normal and build dependencies.
/// Dev-dependencies are not needed to build the crate and do not count.
fn shipped_deps(pkg: &Package) -> impl Iterator<Item = &Dep> {
    pkg.deps.iter().filter(|d| d.kind.as_deref() != Some("dev"))
}

/// The shipped-dependency closure of the roots.
fn closure(ws: &Workspace) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = ws.roots.clone();
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(pkg) = ws.packages.get(&name) {
            stack.extend(shipped_deps(pkg).map(|d| d.name.clone()));
        }
    }
    seen
}

/// The closure in dependency order, then split into publishable and withheld.
fn plan(ws: &Workspace) -> Result<Plan> {
    let mut order = Vec::new();
    let mut state: BTreeMap<String, bool> = BTreeMap::new(); // false = visiting
    let mut roots = ws.roots.clone();
    roots.sort();
    for root in &roots {
        visit(ws, root, &mut state, &mut order)?;
    }

    let mut withheld = Vec::new();
    let mut held: BTreeSet<String> = BTreeSet::new();
    let mut publish = Vec::new();
    for name in order {
        let pkg = &ws.packages[&name];
        if let Some(blocker) = ws.blocked.get(&name) {
            withheld.push((name.clone(), blocker.reason.clone()));
            held.insert(name);
            continue;
        }
        let waiting: BTreeSet<&str> = shipped_deps(pkg)
            .filter(|d| held.contains(&d.name))
            .map(|d| d.name.as_str())
            .collect();
        if waiting.is_empty() {
            publish.push(name);
        } else {
            withheld.push((
                name.clone(),
                format!(
                    "depends on withheld {}",
                    waiting.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
            held.insert(name);
        }
    }
    Ok(Plan { publish, withheld })
}

fn visit(
    ws: &Workspace,
    name: &str,
    state: &mut BTreeMap<String, bool>,
    order: &mut Vec<String>,
) -> Result<()> {
    match state.get(name) {
        Some(true) => return Ok(()),
        Some(false) => bail!("dependency cycle through `{name}`"),
        None => {}
    }
    let pkg = ws
        .packages
        .get(name)
        .with_context(|| format!("publish root `{name}` is not a workspace package"))?;
    state.insert(name.to_string(), false);
    let mut deps: Vec<&str> = shipped_deps(pkg).map(|d| d.name.as_str()).collect();
    deps.sort();
    deps.dedup();
    for dep in deps {
        visit(ws, dep, state, order)?;
    }
    state.insert(name.to_string(), true);
    order.push(name.to_string());
    Ok(())
}

/// Every manifest problem, given each closure crate's out-of-crate reads.
/// Pure, for testing.
fn audit(ws: &Workspace, escapes: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut problems = Vec::new();
    let closure = closure(ws);

    for root in &ws.roots {
        if !ws.packages.contains_key(root) {
            problems.push(format!("publish root `{root}` is not a workspace package"));
        }
    }
    for (name, pkg) in &ws.packages {
        let inside = closure.contains(name);
        if inside && !pkg.publishable {
            problems.push(format!(
                "`{name}` is in the publish closure but says `publish = false`"
            ));
        }
        if !inside && pkg.publishable {
            problems.push(format!(
                "`{name}` is outside the publish closure; set `publish = false` or add a root \
                 that needs it"
            ));
        }
        if !inside {
            continue;
        }
        for (field, present) in [
            ("description", pkg.description),
            ("license", pkg.license),
            ("repository", pkg.repository),
        ] {
            if !present {
                problems.push(format!("`{name}` has no `{field}`"));
            }
        }
        for dep in shipped_deps(pkg).filter(|d| !d.versioned) {
            problems.push(format!(
                "`{name}` depends on workspace crate `{}` by path alone; give it a version \
                 (inherit it from [workspace.dependencies])",
                dep.name
            ));
        }
    }

    for (name, blocker) in &ws.blocked {
        if !closure.contains(name) {
            problems.push(format!(
                "`{name}` is declared blocked but is not in the publish closure"
            ));
        }
        if blocker.kind == OUT_OF_CRATE_SOURCE && escapes.get(name).is_none_or(Vec::is_empty) {
            problems.push(format!(
                "`{name}` is declared blocked for {OUT_OF_CRATE_SOURCE}, but reads nothing \
                 outside its directory any more; remove the declaration"
            ));
        }
    }
    for (name, reads) in escapes {
        let declared = ws
            .blocked
            .get(name)
            .is_some_and(|b| b.kind == OUT_OF_CRATE_SOURCE);
        if !reads.is_empty() && !declared {
            problems.push(format!(
                "`{name}` reads source outside its directory, which `cargo package` does not \
                 ship:\n      {}",
                reads.join("\n      ")
            ));
        }
    }
    problems
}

/// Files the crate at `dir` compiles from outside `dir`: the library and the
/// build script, test-only code excluded. Each as `<file>: <path>`.
fn out_of_crate_reads(dir: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    collect_rs(&dir.join("src"), &mut files)?;
    let build = dir.join("build.rs");
    if build.is_file() {
        files.push(build);
    }
    files.sort();

    let mut reads = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let base = file.parent().unwrap_or(dir);
        for target in referenced_paths(&text) {
            let resolved = normalize(&base.join(&target));
            if !resolved.starts_with(dir) {
                let shown = file.strip_prefix(dir).unwrap_or(&file);
                reads.push(format!("{}: {target}", shown.display()));
            }
        }
    }
    Ok(reads)
}

/// The literal paths `source` reads through `include_str!`, `include_bytes!`
/// and `#[path]`, outside comments and outside its inline test module.
fn referenced_paths(source: &str) -> Vec<String> {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r#"(?:include_str!|include_bytes!)\(\s*"([^"]+)"|#\[path\s*=\s*"([^"]+)"\]"#)
            .expect("static regex")
    });
    let production = match source.find("#[cfg(test)]\nmod tests") {
        Some(at) => &source[..at],
        None => source,
    };
    production
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(|line| {
            pattern
                .captures_iter(line)
                .filter_map(|c| c.get(1).or_else(|| c.get(2)))
                .map(|m| m.as_str().to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// `a/b/../c` -> `a/c`, without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package(name: &str, deps: &[(&str, Option<&str>, bool)]) -> Value {
        json!({
            "name": name,
            "manifest_path": format!("/ws/crates/{name}/Cargo.toml"),
            "publish": null,
            "description": "d",
            "license": "Apache-2.0",
            "repository": "https://example.invalid/r",
            "dependencies": deps.iter().map(|(dep, kind, versioned)| json!({
                "name": dep,
                "kind": kind,
                "req": if *versioned { "^0.1.0" } else { "*" },
            })).collect::<Vec<_>>(),
        })
    }

    fn workspace(packages: Vec<Value>, roots: &[&str], blocked: Value) -> Workspace {
        parse(&json!({
            "packages": packages,
            "metadata": { "mvm": { "publish": { "roots": roots, "blocked": blocked } } },
        }))
        .expect("fixture parses")
    }

    fn chain() -> Vec<Value> {
        vec![
            package("leaf", &[("serde", None, true)]),
            package("mid", &[("leaf", None, true), ("tool", Some("dev"), false)]),
            package("top", &[("mid", None, true), ("gen", Some("build"), true)]),
            package("gen", &[]),
            package("tool", &[]),
        ]
    }

    #[test]
    fn dependencies_are_published_before_their_dependents() {
        let mut packages = chain();
        packages[4]["publish"] = json!([]);
        let ws = workspace(packages, &["top"], json!({}));
        let plan = plan(&ws).expect("plan");
        assert_eq!(plan.publish, ["gen", "leaf", "mid", "top"]);
        assert!(plan.withheld.is_empty());
    }

    #[test]
    fn dev_dependencies_are_neither_published_nor_ordered() {
        let mut packages = chain();
        packages[4]["publish"] = json!([]);
        let ws = workspace(packages, &["top"], json!({}));
        assert!(!closure(&ws).contains("tool"));
        assert!(audit(&ws, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_blocked_crate_withholds_everything_above_it() {
        let mut packages = chain();
        packages[4]["publish"] = json!([]);
        let blocked =
            json!({ "mid": { "kind": "name-taken", "reason": "name is owned elsewhere" } });
        let ws = workspace(packages, &["top"], blocked);
        let plan = plan(&ws).expect("plan");
        assert_eq!(plan.publish, ["gen", "leaf"]);
        assert_eq!(
            plan.withheld,
            [
                ("mid".to_string(), "name is owned elsewhere".to_string()),
                ("top".to_string(), "depends on withheld mid".to_string()),
            ]
        );
    }

    #[test]
    fn a_publishable_crate_outside_the_closure_is_flagged() {
        let ws = workspace(chain(), &["top"], json!({}));
        let problems = audit(&ws, &BTreeMap::new());
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`tool` is outside the publish closure")),
            "{problems:?}"
        );
    }

    #[test]
    fn missing_metadata_and_path_only_edges_are_flagged() {
        let mut packages = chain();
        packages[4]["publish"] = json!([]);
        packages[0]["description"] = Value::Null;
        packages[2]["dependencies"][0]["req"] = json!("*");
        let ws = workspace(packages, &["top"], json!({}));
        let problems = audit(&ws, &BTreeMap::new());
        assert!(
            problems.iter().any(|p| p == "`leaf` has no `description`"),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`top` depends on workspace crate `mid` by path")),
            "{problems:?}"
        );
    }

    #[test]
    fn out_of_crate_reads_must_be_declared_and_declarations_must_stay_true() {
        let mut packages = chain();
        packages[4]["publish"] = json!([]);
        let escapes = BTreeMap::from([("top".to_string(), vec!["build.rs: ../x.rs".to_string()])]);

        let ws = workspace(packages.clone(), &["top"], json!({}));
        let problems = audit(&ws, &escapes);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`top` reads source outside its directory")),
            "{problems:?}"
        );

        let declared = json!({ "top": { "kind": OUT_OF_CRATE_SOURCE, "reason": "r" } });
        let ws = workspace(packages.clone(), &["top"], declared.clone());
        assert!(audit(&ws, &escapes).is_empty());

        let ws = workspace(packages, &["top"], declared);
        let problems = audit(&ws, &BTreeMap::new());
        assert!(
            problems
                .iter()
                .any(|p| p.contains("remove the declaration")),
            "{problems:?}"
        );
    }

    #[test]
    fn referenced_paths_skip_comments_and_the_test_module() {
        let source = concat!(
            "#[path = \"../other/src/a.rs\"]\nmod a;\n",
            "const B: &str = include_str!(\"../../data/b.txt\");\n",
            "/// include_str!(\"../../doc/only.txt\")\n",
            "#[cfg(test)]\nmod tests {\n    const C: &[u8] = include_bytes!(\"../../../fixture\");\n}\n",
        );
        assert_eq!(
            referenced_paths(source),
            ["../other/src/a.rs", "../../data/b.txt"]
        );
    }

    #[test]
    fn normalize_resolves_parent_components() {
        assert_eq!(
            normalize(Path::new("/ws/crates/a/src/../../b/x.rs")),
            PathBuf::from("/ws/crates/b/x.rs")
        );
    }

    /// The checked-in manifests satisfy the gate, and the plan they produce
    /// starts at the bottom of the graph.
    #[test]
    fn the_real_workspace_is_publish_ready() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent");
        run_check(root).expect("the workspace passes check-publish-readiness");
        let plan = plan(&load(root).expect("load")).expect("plan");
        assert_eq!(
            plan.publish.first().map(String::as_str),
            Some("mvm-contract")
        );
    }
}
