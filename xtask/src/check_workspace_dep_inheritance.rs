//! `xtask check-workspace-dep-inheritance`
//!
//! Assert every member-manifest dependency edge is visible to the workspace
//! table, and that the table carries no entry nobody inherits.
//!
//! Two failure modes, both invisible to `check-closure-budget` (which measures
//! resolved closures, not manifests):
//!
//! 1. **Version drift.** A member pins a version requirement that differs from
//!    `[workspace.dependencies]`. Cargo happily resolves both, so the binary
//!    compiles two majors of one crate — an extra supply-chain unit and, for a
//!    proc-macro, an extra build. This is not hypothetical: `mvm-build` pinned
//!    `thiserror = "1"` while the workspace was on 2, and it shipped that way
//!    until someone read the manifests by hand.
//!
//! 2. **Dead table entries.** A `[workspace.dependencies]` entry no member
//!    inherits. It compiles nothing, so no closure gate can see it, but it is
//!    live configuration any crate can pick up by accident — and it accretes a
//!    justification comment that outlives the truth. `memchr` sat in the table
//!    with a comment describing a launch-path scan that did not exist.
//!
//! What this gate deliberately **permits**: a member that matches the table's
//! version requirement but narrows its features. `mvm-contract` is `no_std` +
//! `alloc` and builds on `wasm32-unknown-unknown`, so it declares
//! `serde`/`serde_json`/`chrono`/`ipnet` with `default-features = false` and
//! `alloc` where the workspace table asks for `std`. Forcing those to inherit
//! would turn on `std` in a `no_std` crate and break the wasm target. Narrowing
//! is the intended escape hatch; a *different version* is the bug.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A dependency declaration reduced to what this gate reasons about.
#[derive(Debug, PartialEq, Eq)]
struct DepSpec {
    /// The semver requirement, if the declaration states one literally.
    /// `None` for `foo.workspace = true` (which is the compliant form).
    version: Option<String>,
    /// Whether the declaration inherits from the workspace table.
    inherits: bool,
}

/// One flagged declaration.
struct Finding {
    manifest: String,
    dep: String,
    member_req: String,
    workspace_req: String,
}

/// Everything the gate found, separated from how it is reported so the
/// classification is testable without a process exit.
#[derive(Default)]
struct Audit {
    drift: Vec<Finding>,
    dead: Vec<String>,
    table_len: usize,
}

pub fn run(workspace: &Path) -> Result<()> {
    report(audit(workspace)?)
}

fn audit(workspace: &Path) -> Result<Audit> {
    let root = read_manifest(&workspace.join("Cargo.toml"))?;
    let table = workspace_table(&root)?;
    let mut drift = Vec::new();
    let mut inherited = BTreeSet::new();

    for manifest in member_manifests(workspace)? {
        let rel = manifest
            .strip_prefix(workspace)
            .unwrap_or(&manifest)
            .display()
            .to_string();
        let doc = read_manifest(&manifest)?;
        for (dep, spec) in member_deps(&doc) {
            classify(&rel, &dep, &spec, &table, &mut inherited, &mut drift);
        }
    }

    let dead = table
        .keys()
        .filter(|k| !inherited.contains(*k))
        .cloned()
        .collect();
    Ok(Audit {
        drift,
        dead,
        table_len: table.len(),
    })
}

/// Sort one declaration into inherited / drifting / irrelevant.
fn classify(
    manifest: &str,
    dep: &str,
    spec: &DepSpec,
    table: &BTreeMap<String, String>,
    inherited: &mut BTreeSet<String>,
    drift: &mut Vec<Finding>,
) {
    // Not in the table: a genuinely single-consumer dep, nothing to inherit.
    let Some(workspace_req) = table.get(dep) else {
        return;
    };
    if spec.inherits {
        inherited.insert(dep.to_string());
        return;
    }
    // A declaration with no literal version states no requirement to drift.
    let Some(member_req) = spec.version.as_deref() else {
        return;
    };
    // Features may narrow; the version requirement may not differ.
    if member_req != workspace_req {
        drift.push(Finding {
            manifest: manifest.to_string(),
            dep: dep.to_string(),
            member_req: member_req.to_string(),
            workspace_req: workspace_req.clone(),
        });
    }
}

fn report(audit: Audit) -> Result<()> {
    if audit.drift.is_empty() && audit.dead.is_empty() {
        eprintln!(
            "check-workspace-dep-inheritance: clean ({} table entries, all inherited; \
             no version drift)",
            audit.table_len
        );
        return Ok(());
    }
    let mut msg = String::from("check-workspace-dep-inheritance failed:\n");
    for f in &audit.drift {
        msg.push_str(&format!(
            "  {}: `{}` pins {:?} but [workspace.dependencies] says {:?} — Cargo will compile \
             both. Use `{}.workspace = true` (narrowing features is fine; a different version \
             requirement is not).\n",
            f.manifest, f.dep, f.member_req, f.workspace_req, f.dep
        ));
    }
    for d in &audit.dead {
        msg.push_str(&format!(
            "  Cargo.toml: [workspace.dependencies] `{d}` has no inheritor — delete the entry \
             (and its justification comment) or wire it to the crate that needs it.\n"
        ));
    }
    bail!(msg.trim_end().to_string());
}

fn read_manifest(path: &Path) -> Result<toml::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// `[workspace.dependencies]` reduced to `name -> version requirement`.
/// Path deps (the intra-workspace crates) are excluded: they carry a `version`
/// for publishing, not for resolution, and every member links them by path.
fn workspace_table(root: &toml::Value) -> Result<BTreeMap<String, String>> {
    let Some(deps) = root
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        bail!("root Cargo.toml has no [workspace.dependencies]");
    };
    Ok(deps
        .iter()
        .filter(|(_, v)| v.get("path").is_none())
        .filter_map(|(k, v)| version_req(v).map(|r| (k.clone(), r)))
        .collect())
}

/// The literal version requirement in a declaration, if it states one.
fn version_req(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => t.get("version")?.as_str().map(str::to_string),
        _ => None,
    }
}

/// Every dependency declaration in a member manifest, across the normal, dev,
/// build, and `[target.'cfg(...)'.*]` tables.
fn member_deps(doc: &toml::Value) -> Vec<(String, DepSpec)> {
    let mut out = Vec::new();
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_table(doc.get(kind), &mut out);
    }
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for (_, cfg) in targets {
            for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
                collect_table(cfg.get(kind), &mut out);
            }
        }
    }
    out
}

fn collect_table(table: Option<&toml::Value>, out: &mut Vec<(String, DepSpec)>) {
    let Some(table) = table.and_then(toml::Value::as_table) else {
        return;
    };
    for (name, value) in table {
        let inherits = value
            .get("workspace")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        out.push((
            name.clone(),
            DepSpec {
                version: if inherits { None } else { version_req(value) },
                inherits,
            },
        ));
    }
}

/// Member manifests, discovered by directory rather than a hardcoded list so a
/// new crate is covered the day it lands.
///
/// The root `Cargo.toml` is included: it is both the workspace root *and* the
/// `mvmctl` package, so its own `[dependencies]`/`[dev-dependencies]` inherit
/// from the table like any member's. Omitting it reports every table entry
/// only the root uses — `predicates`, `assert_cmd` — as dead.
fn member_manifests(workspace: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = vec![workspace.join("Cargo.toml")];
    for dir in ["crates", "crates/deps"] {
        let Ok(entries) = std::fs::read_dir(workspace.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let manifest = entry.path().join("Cargo.toml");
            if manifest.is_file() {
                out.push(manifest);
            }
        }
    }
    let xtask = workspace.join("xtask/Cargo.toml");
    if xtask.is_file() {
        out.push(xtask);
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(s: &str) -> toml::Value {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn plain_string_declaration_yields_its_version() {
        assert_eq!(
            version_req(&val("v = \"1.2\"").get("v").unwrap().clone()).as_deref(),
            Some("1.2")
        );
    }

    #[test]
    fn table_declaration_yields_its_version() {
        let v = val("v = { version = \"0.8\", features = [\"x\"] }");
        assert_eq!(version_req(v.get("v").unwrap()).as_deref(), Some("0.8"));
    }

    #[test]
    fn workspace_inheritance_is_recorded_as_inheriting_with_no_version() {
        let doc = val("[dependencies]\nserde = { workspace = true }\n");
        let deps = member_deps(&doc);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].1.inherits);
        assert_eq!(deps[0].1.version, None);
    }

    #[test]
    fn dotted_workspace_form_is_also_inheritance() {
        // `serde.workspace = true` parses to the same table as the braced form.
        let doc = val("[dependencies]\nserde.workspace = true\n");
        let deps = member_deps(&doc);
        assert!(deps[0].1.inherits);
    }

    #[test]
    fn target_gated_tables_are_collected() {
        let doc = val("[target.'cfg(target_os = \"linux\")'.dependencies]\nlandlock = \"0.4\"\n");
        let deps = member_deps(&doc);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "landlock");
        assert_eq!(deps[0].1.version.as_deref(), Some("0.4"));
    }

    #[test]
    fn dev_and_build_tables_are_collected() {
        let doc = val("[dev-dependencies]\na = \"1\"\n[build-dependencies]\nb = \"2\"\n");
        let mut names: Vec<_> = member_deps(&doc).into_iter().map(|(n, _)| n).collect();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn path_deps_are_excluded_from_the_table() {
        let root = val(
            "[workspace.dependencies]\nmvm-core = { path = \"crates/mvm-core\", version = \"0.1\" }\nserde = \"1\"\n",
        );
        let table = workspace_table(&root).unwrap();
        assert_eq!(table.keys().collect::<Vec<_>>(), vec!["serde"]);
    }

    #[test]
    fn narrowing_features_at_the_same_version_is_not_drift() {
        // mvm-contract's no_std posture: same req, fewer features.
        let ws = val("[workspace.dependencies]\nserde = { version = \"1\", features = [\"std\"] }");
        let table = workspace_table(&ws).unwrap();
        let member = val("[dependencies]\nserde = { version = \"1\", default-features = false }");
        let (_, spec) = member_deps(&member).pop().unwrap();
        assert_eq!(spec.version.as_deref(), Some("1"));
        assert_eq!(table.get("serde").map(String::as_str), Some("1"));
        // Equal requirements -> the gate records no finding.
    }

    fn classify_one(
        table: &[(&str, &str)],
        spec: DepSpec,
        dep: &str,
    ) -> (Vec<String>, Vec<Finding>) {
        let table: BTreeMap<String, String> = table
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let mut inherited = BTreeSet::new();
        let mut drift = Vec::new();
        classify(
            "m/Cargo.toml",
            dep,
            &spec,
            &table,
            &mut inherited,
            &mut drift,
        );
        (inherited.into_iter().collect(), drift)
    }

    #[test]
    fn same_version_different_features_is_not_drift() {
        // mvm-contract's no_std posture must stay legal.
        let (inh, drift) = classify_one(
            &[("serde", "1")],
            DepSpec {
                version: Some("1".into()),
                inherits: false,
            },
            "serde",
        );
        assert!(drift.is_empty(), "narrowing features must not be flagged");
        assert!(inh.is_empty());
    }

    #[test]
    fn differing_version_is_flagged_with_both_requirements() {
        let (_, drift) = classify_one(
            &[("thiserror", "2")],
            DepSpec {
                version: Some("1".into()),
                inherits: false,
            },
            "thiserror",
        );
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].member_req, "1");
        assert_eq!(drift[0].workspace_req, "2");
    }

    #[test]
    fn inheriting_declaration_marks_the_entry_used() {
        let (inh, drift) = classify_one(
            &[("serde", "1")],
            DepSpec {
                version: None,
                inherits: true,
            },
            "serde",
        );
        assert_eq!(inh, vec!["serde".to_string()]);
        assert!(drift.is_empty());
    }

    #[test]
    fn dep_absent_from_the_table_is_ignored_entirely() {
        let (inh, drift) = classify_one(
            &[("serde", "1")],
            DepSpec {
                version: Some("0.18".into()),
                inherits: false,
            },
            "virtio-queue",
        );
        assert!(inh.is_empty() && drift.is_empty());
    }

    #[test]
    fn the_root_manifest_is_scanned_as_a_member() {
        // The root is workspace root AND the `mvmctl` package; its own
        // dev-dependencies are the only inheritors of some table entries.
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask/ has a parent");
        let manifests = member_manifests(workspace).unwrap();
        assert!(
            manifests.contains(&workspace.join("Cargo.toml")),
            "root manifest missing from the scanned set: {manifests:?}"
        );
    }

    #[test]
    fn a_differing_major_is_drift() {
        let ws = val("[workspace.dependencies]\nthiserror = \"2\"");
        let table = workspace_table(&ws).unwrap();
        let member = val("[dependencies]\nthiserror = \"1\"");
        let (_, spec) = member_deps(&member).pop().unwrap();
        assert_ne!(
            spec.version.as_deref(),
            table.get("thiserror").map(String::as_str)
        );
    }
}
