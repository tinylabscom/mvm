//! `xtask report-compile-units --build "<label>=<cargo build args>" ... [--asset PATH ...]`
//!
//! Attribute the repeated-looking work in a release. Each `--build` is one of
//! the `cargo build` invocations the release workflow runs; this asks Cargo
//! for its unit graph (`--unit-graph`, no compilation) and prints Markdown
//! that says, per invocation, how many compilation units there are, and across
//! all of them which packages are compiled more than once and which profile,
//! feature or target difference forces it. `--asset` adds the byte size of
//! each shipped file.
//!
//! The embedded payload builds join the `--build` rows automatically: the
//! nested `cargo zigbuild` per host binary that `crates/mvm-cli/build.rs` runs
//! is a separate Cargo invocation with its own target directory, so it never
//! appears in the outer builds' graphs. The report derives one row per payload
//! binary from the same plan the build script consumes — the manifest and the
//! `zigbuild` argument vector are the shared `payload_build_plan` module, the
//! pinned musl target is `embed_toolchain`'s — so the report cannot describe a
//! payload the release does not build. Payload graphs are probed as
//! `cargo build`: cargo-zigbuild passes the selection through unchanged and
//! its own CLI does not accept the unstable graph flags.
//!
//! The report is informational: it never fails a release for a number. An
//! outer `--build` whose graph cannot be resolved is a hard error — that row
//! is the report's subject — while a payload failure degrades to a note,
//! because the payload is the addition and the release must not hinge on it.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

// The payload's build plan and pinned toolchain are shared by path with the
// payload's producers — the mvm-cli build script and `mvmctl` — the same way
// they share with each other: a build script cannot depend on the crate it
// builds, and xtask cannot depend on mvm-cli either, because building that
// dependency runs the build script that *is* the payload build.
use mvm_core::env_hygiene::helper_command;

#[path = "../../crates/mvm-build/src/embed_toolchain.rs"]
#[allow(dead_code)] // the report reads the pin; the compile/probe arms serve the producers
mod embed_toolchain;

#[path = "../../crates/mvm-cli/src/host_binaries/payload_build_plan.rs"]
mod payload_build_plan;

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
    let mut rows = Vec::new();
    for spec in &builds {
        let (label, cargo_args) = spec
            .split_once('=')
            .with_context(|| format!("--build {spec:?} is not <label>=<cargo build args>"))?;
        let graph = Graph::parse(&unit_graph(cargo_args)?)?;
        rows.push(Row {
            kind: BuildKind::Outer,
            label: label.to_string(),
            args: cargo_args.to_string(),
            outcome: RowOutcome::Resolved(graph),
        });
    }
    let payload = payload_rows(&crate::workspace_root());
    let toolchain = payload.toolchain;
    rows.extend(payload.rows);
    let assets = flag_values(args, "--asset")
        .into_iter()
        .map(|path| {
            let bytes = std::fs::metadata(&path)
                .with_context(|| format!("cannot stat asset {path}"))?
                .len();
            Ok((path, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    print!("{}", render(&rows, &assets, toolchain.as_ref()));
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

/// Which side of the release build a row reports on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildKind {
    /// One of the release workflow's own `cargo build` invocations.
    Outer,
    /// A nested `cargo zigbuild` the mvm-cli build script runs while the outer
    /// mvmctl build is in flight.
    Payload,
}

impl BuildKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Outer => "outer",
            Self::Payload => "payload",
        }
    }
}

/// One row of the report: a resolved graph, or the reason there is none.
struct Row {
    kind: BuildKind,
    label: String,
    /// The cargo arguments the graph was resolved with, after the program name.
    args: String,
    outcome: RowOutcome,
}

enum RowOutcome {
    Resolved(Graph),
    Unavailable(String),
}

/// The pinned toolchain facts a payload build carries and a unit graph cannot
/// show.
struct PayloadToolchain {
    target: String,
    rust: String,
    zig: String,
    cargo_zigbuild: String,
}

/// The payload section of the report: one row per embedded binary, plus the
/// toolchain facts the rows carry.
struct PayloadRows {
    rows: Vec<Row>,
    toolchain: Option<PayloadToolchain>,
}

/// The payload rows, best-effort: the release step that runs this report is
/// `continue-on-error`, and a payload graph that cannot be resolved degrades
/// to a note here rather than a nonzero exit — the payload is the addition,
/// the release must not hinge on it. The outer rows keep their hard failure,
/// because a wrong number there is the report's subject lying.
///
/// The pinned target is indexed by the arch this binary runs on, which is the
/// arch the release runner builds mvmctl for — the build script's
/// `CARGO_CFG_TARGET_ARCH` resolves to the same one.
fn payload_rows(workspace_root: &Path) -> PayloadRows {
    payload_rows_with(workspace_root, unit_graph)
}

fn payload_rows_with(workspace_root: &Path, probe: impl Fn(&str) -> Result<String>) -> PayloadRows {
    let pin =
        match embed_toolchain::try_read_pinned_toolchain(workspace_root, std::env::consts::ARCH) {
            Ok(pin) => pin,
            Err(reason) => {
                return PayloadRows {
                    rows: vec![unavailable_payload_row("embedded payload", &reason)],
                    toolchain: None,
                };
            }
        };
    let toolchain = PayloadToolchain {
        target: pin.target.clone(),
        rust: pin.rust.clone(),
        zig: pin.zig.clone(),
        cargo_zigbuild: pin.cargo_zigbuild.clone(),
    };
    let binaries = match payload_build_plan::read_manifest(workspace_root) {
        Ok(binaries) => binaries,
        Err(reason) => {
            return PayloadRows {
                rows: vec![unavailable_payload_row("embedded payload", &reason)],
                toolchain: Some(toolchain),
            };
        }
    };
    let rows = binaries
        .into_iter()
        .map(|binary| {
            let label = format!("{} ({})", binary.name, pin.target);
            let probe_args = probe_args(&payload_build_plan::zigbuild_args(
                &binary,
                &pin.target,
                false,
            ));
            let outcome = match probe(&probe_args).and_then(|json| Graph::parse(&json)) {
                Ok(graph) => RowOutcome::Resolved(graph),
                Err(error) => RowOutcome::Unavailable(format!("{error:#}")),
            };
            Row {
                kind: BuildKind::Payload,
                label,
                args: probe_args,
                outcome,
            }
        })
        .collect();
    PayloadRows {
        rows,
        toolchain: Some(toolchain),
    }
}

fn unavailable_payload_row(label: &str, reason: &str) -> Row {
    Row {
        kind: BuildKind::Payload,
        label: label.to_string(),
        args: String::new(),
        outcome: RowOutcome::Unavailable(reason.to_string()),
    }
}

/// The probe is `cargo build` even though the build is `cargo zigbuild`:
/// cargo-zigbuild's own CLI does not accept the unstable graph flags, and it
/// hands target, feature and profile selection to `cargo build` unchanged, so
/// the graphs are the same.
fn probe_args(args: &[String]) -> String {
    let mut probe = args.to_vec();
    if let Some(first) = probe.first_mut() {
        *first = "build".to_string();
    }
    probe.join(" ")
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
    units: Vec<Unit>,
}

impl Graph {
    fn parse(json: &str) -> Result<Self> {
        let doc: Value = serde_json::from_str(json).context("unit graph is not JSON")?;
        let units = doc["units"]
            .as_array()
            .context("unit graph has no `units`")?
            .iter()
            .map(parse_unit)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { units })
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
fn repeated(graphs: &[&Graph]) -> BTreeMap<String, BTreeSet<String>> {
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

/// The parts of a cargo invocation that decide what gets compiled: profile,
/// target, features.
#[derive(Debug, PartialEq, Eq)]
struct Selection {
    profile: String,
    target: String,
    features: String,
}

fn selection(args: &str) -> Selection {
    let mut selection = Selection {
        profile: String::new(),
        target: String::new(),
        features: String::new(),
    };
    let mut it = args.split_whitespace();
    while let Some(token) = it.next() {
        match token {
            "--release" => selection.profile = "release".to_string(),
            "--profile" => selection.profile = it.next().unwrap_or("?").to_string(),
            "--target" => selection.target = it.next().unwrap_or("?").to_string(),
            "--features" => selection.features = it.next().unwrap_or("?").to_string(),
            _ => {}
        }
    }
    selection
}

fn render(rows: &[Row], assets: &[(String, u64)], toolchain: Option<&PayloadToolchain>) -> String {
    let mut out = String::from("### Compilation units\n\n");
    out.push_str(
        "| build | kind | profile | units | packages | libs | proc-macros | build scripts (compile / run) | bins |\n",
    );
    out.push_str("|---|---|---|---:|---:|---:|---:|---:|---:|\n");
    for row in rows {
        match &row.outcome {
            RowOutcome::Resolved(graph) => {
                let profile = graph
                    .units
                    .iter()
                    .find(|u| u.kind == Kind::Bin || u.kind == Kind::Lib)
                    .map_or("?", |u| u.profile_name.as_str());
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} | {} | {} / {} | {} |",
                    row.label,
                    row.kind.as_str(),
                    profile,
                    graph.units.len(),
                    graph.packages().len(),
                    graph.count(Kind::Lib),
                    graph.count(Kind::ProcMacro),
                    graph.count(Kind::BuildScriptCompile),
                    graph.count(Kind::BuildScriptRun),
                    graph.count(Kind::Bin),
                );
            }
            RowOutcome::Unavailable(_) => {
                let _ = writeln!(
                    out,
                    "| {} | {} | — | — | — | — | — | — / — | — |",
                    row.label,
                    row.kind.as_str(),
                );
            }
        }
    }
    for row in rows {
        if let RowOutcome::Unavailable(reason) = &row.outcome {
            let _ = writeln!(
                out,
                "\n- `{}`: no unit graph — {reason}. The build still runs in the release; \
                 only its attribution here is missing.",
                row.label
            );
        }
    }

    let resolved: Vec<&Graph> = rows
        .iter()
        .filter_map(|row| match &row.outcome {
            RowOutcome::Resolved(graph) => Some(graph),
            RowOutcome::Unavailable(_) => None,
        })
        .collect();
    let all: BTreeSet<&str> = resolved.iter().flat_map(|g| g.packages()).collect();
    let resolved_of = |kind: BuildKind| {
        rows.iter()
            .filter(|row| row.kind == kind && matches!(row.outcome, RowOutcome::Resolved(_)))
            .count()
    };
    let _ = writeln!(
        out,
        "\n{} unique packages across {} resolved build graphs ({} outer, {} embedded payload).\n",
        all.len(),
        resolved.len(),
        resolved_of(BuildKind::Outer),
        resolved_of(BuildKind::Payload),
    );

    let repeated = repeated(&resolved);
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

    render_payload(&mut out, rows, toolchain);

    if !assets.is_empty() {
        out.push_str("\n### Shipped asset bytes\n\n| asset | bytes |\n|---|---:|\n");
        for (path, bytes) in assets {
            let _ = writeln!(out, "| {path} | {bytes} |");
        }
    }
    out
}

/// The differences a unit graph cannot show — the nested target dir and the
/// pinned toolchain — and the ones it can: how each payload build's selection
/// differs from the outer mvmctl build's.
fn render_payload(out: &mut String, rows: &[Row], toolchain: Option<&PayloadToolchain>) {
    if !rows.iter().any(|row| row.kind == BuildKind::Payload) {
        return;
    }
    out.push_str("\n### Embedded payload builds\n\n");
    out.push_str(
        "The `payload` rows are the nested `cargo zigbuild` invocations the mvm-cli build \
         script runs while the outer mvmctl build is in flight — one per binary the released \
         mvmctl embeds. Two differences a graph cannot show apply to every payload row: each \
         builds into its own nested target dir, because the outer build holds the workspace \
         `target/` lock for its whole run,",
    );
    match toolchain {
        Some(toolchain) => {
            let _ = writeln!(
                out,
                " and each compiles for `{}` under the payload's pinned toolchain (rust {}, \
                 zig {}, cargo-zigbuild {}), not the workspace toolchain the outer builds — and \
                 this probe — use.",
                toolchain.target, toolchain.rust, toolchain.zig, toolchain.cargo_zigbuild,
            );
        }
        None => {
            out.push_str(
                " and each compiles under the payload's pinned toolchain, not the workspace \
                 toolchain the outer builds — and this probe — use.\n",
            );
        }
    }

    let reference = rows
        .iter()
        .find(|row| row.kind == BuildKind::Outer && row.label.starts_with("mvmctl"))
        .or_else(|| rows.iter().find(|row| row.kind == BuildKind::Outer));
    let Some(reference) = reference else {
        return;
    };
    let want = selection(&reference.args);
    let _ = writeln!(
        out,
        "\nVersus the outer `{}` build, each payload build differs in:",
        reference.label
    );
    for row in rows.iter().filter(|row| row.kind == BuildKind::Payload) {
        if row.args.is_empty() {
            continue;
        }
        let got = selection(&row.args);
        let mut differs = Vec::new();
        if got.profile != want.profile {
            differs.push(format!("profile `{}` vs `{}`", got.profile, want.profile));
        }
        if got.target != want.target {
            differs.push(format!("target `{}` vs `{}`", got.target, want.target));
        }
        if got.features != want.features {
            differs.push(format!(
                "features `{}` vs `{}`",
                display_features(&got.features),
                display_features(&want.features),
            ));
        }
        let _ = match differs.is_empty() {
            true => writeln!(out, "- `{}`: the same selection", row.label),
            false => writeln!(out, "- `{}`: {}", row.label, differs.join("; ")),
        };
    }
}

fn display_features(features: &str) -> String {
    if features.is_empty() {
        "none".to_string()
    } else {
        features.to_string()
    }
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

    fn graph(units: Vec<Value>) -> Graph {
        Graph::parse(&serde_json::json!({ "units": units }).to_string()).unwrap()
    }

    fn outer_row(label: &str, args: &str, units: Vec<Value>) -> Row {
        let graph = graph(units);
        Row {
            kind: BuildKind::Outer,
            label: label.to_string(),
            args: args.to_string(),
            outcome: RowOutcome::Resolved(graph),
        }
    }

    fn payload_row(label: &str, args: &str, units: Vec<Value>) -> Row {
        let graph = graph(units);
        Row {
            kind: BuildKind::Payload,
            label: label.to_string(),
            args: args.to_string(),
            outcome: RowOutcome::Resolved(graph),
        }
    }

    const REG: &str = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0";
    const MVMCTL_ARGS: &str =
        "build --profile release-min --target aarch64-apple-darwin --features host,user";

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
        let a = graph(vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        let b = graph(vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        assert!(repeated(&[&a, &b]).is_empty());
    }

    #[test]
    fn a_panic_strategy_difference_is_named_as_the_cause() {
        let a = graph(vec![unit(REG, "lib", "build", "z", "abort", &[])]);
        let b = graph(vec![unit(REG, "lib", "build", "z", "unwind", &[])]);
        let found = repeated(&[&a, &b]);
        assert_eq!(found["serde@1.0.0"].iter().collect::<Vec<_>>(), ["panic"]);
    }

    #[test]
    fn a_feature_difference_is_named_as_the_cause() {
        let a = graph(vec![unit(REG, "lib", "build", "3", "unwind", &["std"])]);
        let b = graph(vec![unit(REG, "lib", "build", "3", "unwind", &[])]);
        assert!(repeated(&[&a, &b])["serde@1.0.0"].contains("features"));
    }

    #[test]
    fn build_scripts_are_counted_apart_from_libs() {
        let g = graph(vec![
            unit(REG, "custom-build", "build", "0", "unwind", &[]),
            unit(REG, "custom-build", "run-custom-build", "0", "unwind", &[]),
            unit(REG, "lib", "build", "3", "unwind", &[]),
        ]);
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
        let a = outer_row(
            "mvmctl",
            MVMCTL_ARGS,
            vec![unit(REG, "lib", "build", "z", "abort", &[])],
        );
        let b = outer_row(
            "daemons",
            "build --release",
            vec![unit(REG, "lib", "build", "3", "unwind", &[])],
        );
        let text = render(&[a, b], &[("mvmctl.tar.gz".to_string(), 42)], None);
        assert!(
            text.contains("| mvmctl | outer | release | 1 | 1 |"),
            "{text}"
        );
        assert!(text.contains("opt_level, panic"), "{text}");
        assert!(text.contains("| mvmctl.tar.gz | 42 |"), "{text}");
    }

    #[test]
    fn payload_rows_are_marked_and_counted_apart() {
        let a = outer_row(
            "mvmctl",
            MVMCTL_ARGS,
            vec![unit(REG, "lib", "build", "z", "abort", &[])],
        );
        let p = payload_row(
            "mvm-host-vm-init (aarch64-unknown-linux-musl)",
            "build --release --target aarch64-unknown-linux-musl -p mvm-builder-guest --bin mvm-host-vm-init",
            vec![unit(REG, "lib", "build", "3", "unwind", &[])],
        );
        let text = render(&[a, p], &[], None);
        assert!(
            text.contains("| mvm-host-vm-init (aarch64-unknown-linux-musl) | payload |"),
            "{text}"
        );
        assert!(
            text.contains("2 resolved build graphs (1 outer, 1 embedded payload)"),
            "{text}"
        );
        // The graph-visible difference is named, against the outer mvmctl build.
        assert!(text.contains("### Embedded payload builds"), "{text}");
        assert!(
            text.contains("profile `release` vs `release-min`"),
            "{text}"
        );
        assert!(
            text.contains("target `aarch64-unknown-linux-musl` vs `aarch64-apple-darwin`"),
            "{text}"
        );
        assert!(text.contains("features `none` vs `host,user`"), "{text}");
    }

    #[test]
    fn a_payload_graph_that_cannot_be_resolved_degrades_to_a_note() {
        let a = outer_row(
            "mvmctl",
            MVMCTL_ARGS,
            vec![unit(REG, "lib", "build", "z", "abort", &[])],
        );
        let mut p = payload_row("mvm-builderd (aarch64-unknown-linux-musl)", "", vec![]);
        p.outcome =
            RowOutcome::Unavailable("cargo build ... --unit-graph failed: boom".to_string());
        let text = render(&[a, p], &[], None);
        assert!(
            text.contains("| mvm-builderd (aarch64-unknown-linux-musl) | payload | — |"),
            "{text}"
        );
        assert!(
            text.contains("`mvm-builderd (aarch64-unknown-linux-musl)`: no unit graph — cargo build ... --unit-graph failed: boom."),
            "{text}"
        );
        assert!(
            text.contains("1 resolved build graphs (1 outer, 0 embedded payload)"),
            "{text}"
        );
    }

    #[test]
    fn the_payload_section_states_the_toolchain_when_the_pin_is_known() {
        let a = outer_row("mvmctl", MVMCTL_ARGS, vec![]);
        let p = payload_row(
            "mvm-setpriv (x86_64-unknown-linux-musl)",
            "build --release --target x86_64-unknown-linux-musl -p mvm-setpriv --bin mvm-setpriv",
            vec![],
        );
        let toolchain = PayloadToolchain {
            target: "x86_64-unknown-linux-musl".to_string(),
            rust: "1.91.1".to_string(),
            zig: "0.13.0".to_string(),
            cargo_zigbuild: "0.23.0".to_string(),
        };
        let text = render(&[a, p], &[], Some(&toolchain));
        assert!(
            text.contains("rust 1.91.1, zig 0.13.0, cargo-zigbuild 0.23.0"),
            "{text}"
        );
        assert!(text.contains("nested target dir"), "{text}");
    }

    #[test]
    fn probe_args_swaps_zigbuild_for_build() {
        assert_eq!(
            probe_args(&[
                "zigbuild".to_string(),
                "--release".to_string(),
                "--target".to_string(),
                "aarch64-unknown-linux-musl".to_string(),
            ]),
            "build --release --target aarch64-unknown-linux-musl"
        );
    }

    #[test]
    fn selection_reads_profile_target_and_features() {
        assert_eq!(
            selection(
                "build --profile release-min --target aarch64-apple-darwin --features host,user"
            ),
            Selection {
                profile: "release-min".to_string(),
                target: "aarch64-apple-darwin".to_string(),
                features: "host,user".to_string(),
            }
        );
        assert_eq!(
            selection(
                "zigbuild --release --target aarch64-unknown-linux-musl -p mvm-builder-guest --bin mvm-host-vm-init"
            ),
            Selection {
                profile: "release".to_string(),
                target: "aarch64-unknown-linux-musl".to_string(),
                features: String::new(),
            }
        );
    }

    /// The report's payload rows are the plan the build script consumes: the
    /// real manifest and the real pinned target, not a copy.
    #[test]
    fn the_payload_rows_come_from_the_shared_plan() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives in the workspace");
        let probed: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let payload = payload_rows_with(workspace, |args| {
            probed.lock().unwrap().push(args.to_string());
            Ok(serde_json::json!({ "units": [] }).to_string())
        });
        let toolchain = payload.toolchain.expect("the workspace pins a toolchain");
        let rows = payload.rows;
        assert!(toolchain.target.ends_with("-musl"), "{}", toolchain.target);

        let manifest = payload_build_plan::read_manifest(workspace).expect("the manifest reads");
        assert_eq!(rows.len(), manifest.len());
        assert!(
            manifest.len() >= 3,
            "the manifest carries the payload set, found {}",
            manifest.len()
        );
        for (row, binary) in rows.iter().zip(&manifest) {
            assert_eq!(row.kind, BuildKind::Payload);
            assert_eq!(row.label, format!("{} ({})", binary.name, toolchain.target));
            assert!(
                matches!(row.outcome, RowOutcome::Resolved(_)),
                "a working probe resolves the row"
            );
        }
        for (args, binary) in probed.lock().unwrap().iter().zip(&manifest) {
            let expected = payload_build_plan::zigbuild_args(binary, &toolchain.target, false)
                .join(" ")
                .replacen("zigbuild", "build", 1);
            assert_eq!(args, &expected);
            assert!(args.starts_with("build --release --target "), "{args}");
            assert!(args.contains(&format!("--bin {}", binary.name)), "{args}");
        }
    }

    /// A probe that fails fails the row, not the report.
    #[test]
    fn a_failed_payload_probe_degrades_the_row_not_the_report() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives in the workspace");
        let payload = payload_rows_with(workspace, |_| bail!("nightly missing"));
        assert!(payload.toolchain.is_some());
        assert!(!payload.rows.is_empty());
        for row in &payload.rows {
            let RowOutcome::Unavailable(reason) = &row.outcome else {
                panic!("a failed probe must degrade the row: {}", row.label);
            };
            assert!(reason.contains("nightly missing"), "{reason}");
        }
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
        assert!(Graph::parse("{}").is_err());
    }
}
