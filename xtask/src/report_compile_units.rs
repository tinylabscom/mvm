//! `xtask report-compile-units --build "<label>=<cargo build args>" ... [--asset PATH ...]`
//!
//! Attribute the repeated-looking work in a release. Each `--build` is one of the
//! `cargo build` invocations the release workflow runs; this asks Cargo for its
//! unit graph (`--unit-graph`, no compilation) and prints Markdown that says, per
//! invocation, how many compilation units there are, and across all of them which
//! packages are compiled more than once and which profile, feature or target
//! difference forces it. `--asset` adds the byte size of each shipped file.
//!
//! The report is informational: it never fails a release for a number. A
//! nested `cargo zigbuild` run by `crates/mvm-cli/build.rs` is a separate
//! Cargo invocation with its own target directory and is not in these graphs.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::process::Command;

/// Profile fields that make Cargo compile a package again.
const PROFILE_FIELDS: [&str; 7] = [
    "opt_level",
    "lto",
    "codegen_units",
    "panic",
    "strip",
    "debug_assertions",
    "overflow_checks",
];

pub fn run(args: &[String]) -> Result<()> {
    let builds = flag_values(args, "--build");
    if builds.is_empty() {
        bail!("report-compile-units: pass at least one --build \"<label>=<cargo build args>\"");
    }
    let mut graphs = Vec::new();
    for spec in &builds {
        let (label, cargo_args) = spec
            .split_once('=')
            .with_context(|| format!("--build {spec:?} is not <label>=<cargo build args>"))?;
        graphs.push(Graph::parse(label, &unit_graph(cargo_args)?)?);
    }
    let assets = flag_values(args, "--asset")
        .into_iter()
        .map(|path| {
            let bytes = std::fs::metadata(&path)
                .with_context(|| format!("cannot stat asset {path}"))?
                .len();
            Ok((path, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    print!("{}", render(&graphs, &assets));
    Ok(())
}

/// `cargo <args> --unit-graph`, which the pinned nightly accepts and which
/// compiles nothing.
fn unit_graph(cargo_args: &str) -> Result<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(cargo_args.split_whitespace())
        .args(["--unit-graph", "-Z", "unstable-options"])
        .output()
        .context("spawn cargo")?;
    if !out.status.success() {
        bail!(
            "cargo {cargo_args} --unit-graph failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8(out.stdout).context("unit graph is not UTF-8")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Lib,
    ProcMacro,
    BuildScriptCompile,
    BuildScriptRun,
    Bin,
}

/// What Cargo compiles: one package at one profile, feature set and platform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Variant {
    profile: Vec<String>,
    features: Vec<String>,
    platform: String,
}

#[derive(Debug)]
struct Unit {
    package: String,
    kind: Kind,
    variant: Variant,
    profile_name: String,
}

#[derive(Debug)]
struct Graph {
    label: String,
    units: Vec<Unit>,
}

impl Graph {
    fn parse(label: &str, json: &str) -> Result<Self> {
        let doc: Value = serde_json::from_str(json).context("unit graph is not JSON")?;
        let units = doc["units"]
            .as_array()
            .context("unit graph has no `units`")?
            .iter()
            .map(parse_unit)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            label: label.to_string(),
            units,
        })
    }

    fn count(&self, kind: Kind) -> usize {
        self.units.iter().filter(|u| u.kind == kind).count()
    }

    fn packages(&self) -> BTreeSet<&str> {
        self.units.iter().map(|u| u.package.as_str()).collect()
    }
}

fn parse_unit(unit: &Value) -> Result<Unit> {
    let id = unit["pkg_id"].as_str().context("unit has no pkg_id")?;
    let target_kinds: Vec<&str> = unit["target"]["kind"]
        .as_array()
        .map(|k| k.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let kind = if unit["mode"] == "run-custom-build" {
        Kind::BuildScriptRun
    } else if target_kinds.contains(&"custom-build") {
        Kind::BuildScriptCompile
    } else if target_kinds.contains(&"proc-macro") {
        Kind::ProcMacro
    } else if target_kinds.contains(&"bin") {
        Kind::Bin
    } else {
        Kind::Lib
    };
    let profile = &unit["profile"];
    let mut features: Vec<String> = unit["features"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    features.sort();
    Ok(Unit {
        package: package_name(id),
        kind,
        profile_name: profile["name"].as_str().unwrap_or("?").to_string(),
        variant: Variant {
            profile: PROFILE_FIELDS
                .iter()
                .map(|f| format!("{f}={}", profile[f]))
                .collect(),
            features,
            platform: unit["platform"].as_str().unwrap_or("host").to_string(),
        },
    })
}

/// `name@version` from a Cargo package id, for both the registry form
/// (`...#name@1.2.3`) and the path form (`file:///x/crates/name#1.2.3`).
fn package_name(id: &str) -> String {
    let (head, tail) = id.rsplit_once('#').unwrap_or((id, ""));
    if tail.contains('@') {
        return tail.to_string();
    }
    let name = head.rsplit('/').next().unwrap_or(head);
    format!("{name}@{tail}")
}

/// Packages compiled under more than one variant, with the fields that differ.
fn repeated(graphs: &[Graph]) -> BTreeMap<String, BTreeSet<String>> {
    let mut variants: BTreeMap<&str, BTreeSet<&Variant>> = BTreeMap::new();
    for unit in graphs.iter().flat_map(|g| &g.units) {
        if matches!(unit.kind, Kind::Lib | Kind::ProcMacro) {
            variants
                .entry(&unit.package)
                .or_default()
                .insert(&unit.variant);
        }
    }
    variants
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(package, v)| (package.to_string(), differing_fields(&v)))
        .collect()
}

fn differing_fields(variants: &BTreeSet<&Variant>) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    let first = variants.iter().next().expect("at least two variants");
    for other in variants.iter().skip(1) {
        for (a, b) in first.profile.iter().zip(&other.profile) {
            if a != b {
                fields.insert(a.split('=').next().unwrap_or(a).to_string());
            }
        }
        if first.features != other.features {
            fields.insert("features".to_string());
        }
        if first.platform != other.platform {
            fields.insert("target".to_string());
        }
    }
    fields
}

fn render(graphs: &[Graph], assets: &[(String, u64)]) -> String {
    let mut out = String::from("### Compilation units\n\n");
    out.push_str(
        "| build | profile | units | packages | libs | proc-macros | build scripts (compile / run) | bins |\n",
    );
    out.push_str("|---|---|---:|---:|---:|---:|---:|---:|\n");
    for g in graphs {
        let profile = g
            .units
            .iter()
            .find(|u| u.kind == Kind::Bin || u.kind == Kind::Lib)
            .map_or("?", |u| u.profile_name.as_str());
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} / {} | {} |",
            g.label,
            profile,
            g.units.len(),
            g.packages().len(),
            g.count(Kind::Lib),
            g.count(Kind::ProcMacro),
            g.count(Kind::BuildScriptCompile),
            g.count(Kind::BuildScriptRun),
            g.count(Kind::Bin),
        );
    }
    let all: BTreeSet<&str> = graphs.iter().flat_map(Graph::packages).collect();
    let _ = writeln!(
        out,
        "\n{} unique packages across {} builds.\n",
        all.len(),
        graphs.len()
    );

    let repeated = repeated(graphs);
    out.push_str("### Packages compiled more than once\n\n");
    if repeated.is_empty() {
        out.push_str("None.\n");
    } else {
        let mut by_cause: BTreeMap<String, Vec<&str>> = BTreeMap::new();
        for (package, fields) in &repeated {
            let cause = fields.iter().cloned().collect::<Vec<_>>().join(", ");
            by_cause.entry(cause).or_default().push(package);
        }
        let _ = writeln!(out, "{} packages, by what differs:\n", repeated.len());
        out.push_str("| differs | packages | examples |\n|---|---:|---|\n");
        for (cause, packages) in &by_cause {
            let examples = packages
                .iter()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "| {cause} | {} | {examples} |", packages.len());
        }
    }
    if !assets.is_empty() {
        out.push_str("\n### Shipped asset bytes\n\n| asset | bytes |\n|---|---:|\n");
        for (path, bytes) in assets {
            let _ = writeln!(out, "| {path} | {bytes} |");
        }
    }
    out
}

/// Every value of a repeated `--flag value`.
fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(pkg: &str, kind: &str, mode: &str, opt: &str, panic: &str, features: &[&str]) -> Value {
        serde_json::json!({
            "pkg_id": pkg,
            "target": { "kind": [kind] },
            "mode": mode,
            "features": features,
            "platform": null,
            "profile": {
                "name": "release", "opt_level": opt, "lto": "false", "codegen_units": 16,
                "panic": panic, "strip": "none", "debug_assertions": false,
                "overflow_checks": true
            }
        })
    }

    fn graph(label: &str, units: Vec<Value>) -> Graph {
        Graph::parse(label, &serde_json::json!({ "units": units }).to_string()).unwrap()
    }

    const REG: &str = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0";

    #[test]
    fn package_name_reads_registry_and_path_ids() {
        assert_eq!(package_name(REG), "serde@1.0.0");
        assert_eq!(
            package_name("path+file:///w/crates/mvm-core#0.24.1"),
            "mvm-core@0.24.1"
        );
    }

    #[test]
    fn same_variant_in_two_builds_is_reuse_not_repetition() {
        let a = graph("a", vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        let b = graph("b", vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        assert!(repeated(&[a, b]).is_empty());
    }

    #[test]
    fn a_panic_strategy_difference_is_named_as_the_cause() {
        let a = graph("a", vec![unit(REG, "lib", "build", "z", "abort", &[])]);
        let b = graph("b", vec![unit(REG, "lib", "build", "z", "unwind", &[])]);
        let found = repeated(&[a, b]);
        assert_eq!(found["serde@1.0.0"].iter().collect::<Vec<_>>(), ["panic"]);
    }

    #[test]
    fn a_feature_difference_is_named_as_the_cause() {
        let a = graph(
            "a",
            vec![unit(REG, "lib", "build", "3", "unwind", &["std"])],
        );
        let b = graph("b", vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        assert!(repeated(&[a, b])["serde@1.0.0"].contains("features"));
    }

    #[test]
    fn build_scripts_are_counted_apart_from_libs() {
        let g = graph(
            "g",
            vec![
                unit(REG, "custom-build", "build", "0", "unwind", &[]),
                unit(REG, "custom-build", "run-custom-build", "0", "unwind", &[]),
                unit(REG, "lib", "build", "3", "unwind", &[]),
            ],
        );
        assert_eq!(
            (
                g.count(Kind::BuildScriptCompile),
                g.count(Kind::BuildScriptRun),
                g.count(Kind::Lib)
            ),
            (1, 1, 1)
        );
        assert_eq!(g.packages().len(), 1);
    }

    #[test]
    fn render_lists_repetition_and_asset_bytes() {
        let a = graph("mvmctl", vec![unit(REG, "lib", "build", "z", "abort", &[])]);
        let b = graph(
            "daemons",
            vec![unit(REG, "lib", "build", "3", "unwind", &[])],
        );
        let text = render(&[a, b], &[("mvmctl.tar.gz".to_string(), 42)]);
        assert!(text.contains("| mvmctl | release | 1 | 1 |"), "{text}");
        assert!(text.contains("opt_level, panic"), "{text}");
        assert!(text.contains("| mvmctl.tar.gz | 42 |"), "{text}");
    }

    #[test]
    fn flag_values_collects_every_occurrence() {
        let args: Vec<String> = ["--build", "a=x", "--asset", "f", "--build", "b=y"]
            .map(String::from)
            .to_vec();
        assert_eq!(flag_values(&args, "--build"), ["a=x", "b=y"]);
    }

    #[test]
    fn a_malformed_graph_is_an_error() {
        assert!(Graph::parse("x", "{}").is_err());
    }
}
