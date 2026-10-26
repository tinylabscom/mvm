//! `xtask check-compile-report-sync`
//!
//! CI lint — holds the release workflow's `Report compilation units` step to
//! the release build steps it mirrors. The report's `--build` rows are the
//! `cargo build` invocations of the `Build release binary` and
//! `Build per-VM host binaries` steps with `zigbuild` spelled `build`
//! (cargo-zigbuild delegates selection to `cargo build` unchanged and its own
//! CLI does not accept the unstable graph flags); the embedded payload rows
//! carry no mirror risk, because the report derives them from the same payload
//! build plan the mvm-cli build script consumes.
//!
//! Why a gate rather than the comment that used to guard this: the workflow
//! runs on tags, so a report row that drifted from its build step skews the
//! attribution of every release until someone reads the commands side by
//! side — which is what the comment asked and nobody did. Here the comparison
//! is mechanical: a report row must name a build the release actually runs,
//! and the three builds the report exists for must each be reported.
//!
//! The platform-conditional `mvm-hvf-supervisor` leg is deliberately outside
//! the report: it is one extra bin target of `mvm-hostd` on one matrix leg,
//! and mirroring it would resolve a graph on the Linux legs for a build that
//! does not run there.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

/// One `cargo build`-shaped invocation, reduced to what decides what compiles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BuildCommand {
    profile: String,
    target: String,
    packages: BTreeSet<String>,
    bins: BTreeSet<String>,
    features: String,
}

impl BuildCommand {
    fn is_hostlib(&self) -> bool {
        self.packages.len() == 1 && self.packages.contains("mvm-hostlib")
    }
}

/// The report step derives `hostlib_target` as exactly the substitution the
/// build step's musl leg spells out, and as `${BUILD_TARGET}` elsewhere; the
/// gate pins that derivation below, so the three spellings are one value.
const HOSTLIB_TARGET_ALIASES: [&str; 3] = [
    "${BUILD_TARGET}",
    "${hostlib_target}",
    "${BUILD_TARGET/-unknown-linux-musl/-unknown-linux-gnu}",
];

/// How to recognize one of the builds the report exists to attribute.
type BuildPredicate = fn(&BuildCommand) -> bool;

/// The builds the report exists to attribute, by how to recognize them.
const REPORTED_BUILDS: [(&str, BuildPredicate); 3] = [
    ("the release mvmctl build", |cmd| {
        cmd.profile == "release-min" && cmd.packages.is_empty()
    }),
    ("the per-VM daemon build", |cmd| {
        cmd.packages.len() == 2
            && cmd.packages.contains("mvm-hostd")
            && cmd.packages.contains("mvm-gpu")
    }),
    ("the mvm-hostlib build", BuildCommand::is_hostlib),
];

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(".github/workflows/release.yml");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let problems = check_release_workflow(&src);
    if !problems.is_empty() {
        bail!(
            "check-compile-report-sync: the report step drifted from the release builds:\n  {}\n\n\
             Fix: the `Report compilation units` step's `--build` rows are the `Build release \
             binary` and `Build per-VM host binaries` invocations with `zigbuild` spelled \
             `build` and the hostlib target named `${{hostlib_target}}`. Change the rows with \
             the build steps, in the same commit.",
            problems.join("\n  ")
        );
    }
    eprintln!(
        "check-compile-report-sync: the report step mirrors the {} reported release builds",
        REPORTED_BUILDS.len()
    );
    Ok(())
}

fn check_release_workflow(src: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(report) = step_body(src, "Report compilation units") else {
        return vec![
            "release.yml has no `Report compilation units` step — the release's compile \
             attribution is gone"
                .to_string(),
        ];
    };
    if !report.contains("continue-on-error: true") {
        problems.push(
            "the report step lost `continue-on-error: true` — the report must never fail \
             a release"
                .to_string(),
        );
    }
    if !report.contains("GITHUB_STEP_SUMMARY") {
        problems.push(
            "the report step no longer writes to $GITHUB_STEP_SUMMARY — the table must land \
             in the job summary"
                .to_string(),
        );
    }
    for pinned in [
        "hostlib_target=\"${BUILD_TARGET/-unknown-linux-musl/-unknown-linux-gnu}\"",
        "[[ \"${BUILD_TARGET}\" == *-unknown-linux-musl ]] || hostlib_target=\"${BUILD_TARGET}\"",
    ] {
        if !report.contains(pinned) {
            problems.push(format!(
                "the report step must derive the hostlib target as `{pinned}` — the hostlib \
                 row is mirrored against that value"
            ));
        }
    }
    let rows = report_rows(report);

    let mut built = Vec::new();
    for step in ["Build release binary", "Build per-VM host binaries"] {
        match step_body(src, step) {
            Some(body) => built.extend(build_commands(body)),
            None => problems.push(format!(
                "release.yml has no `{step}` step — the report's mirror has nothing to mirror"
            )),
        }
    }
    if built.is_empty() {
        return problems;
    }

    // A row the release does not build is a stale mirror or an invention.
    for (label, row) in &rows {
        if !built.iter().any(|b| same_command(row, b)) {
            problems.push(format!(
                "the report row `{label}` mirrors no cargo build in the release steps"
            ));
        }
    }

    // And each build the report exists for is reported.
    for (name, matches) in REPORTED_BUILDS {
        let built_matching: Vec<&BuildCommand> = built.iter().filter(|cmd| matches(cmd)).collect();
        if built_matching.is_empty() {
            problems.push(format!(
                "no cargo build in the release steps is {name} — the workflow changed shape \
                 and this gate must be re-taught"
            ));
            continue;
        }
        let reported = rows
            .iter()
            .any(|(_, row)| matches(row) && built_matching.iter().any(|b| same_command(row, b)));
        if !reported {
            problems.push(format!(
                "{name} is not mirrored by any `--build` row of the report step"
            ));
        }
    }
    problems
}

/// The body of one `- name: <name>` step, up to the next sibling step.
fn step_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("- name: {name}\n");
    let start = src.find(&marker)? + marker.len();
    let rest = &src[start..];
    let end = rest.find("\n      - ").map_or(rest.len(), |i| i + 1);
    Some(&rest[..end])
}

/// Shell line continuations joined, so one invocation is one line.
fn join_continuations(src: &str) -> String {
    src.replace("\\\n", " ")
}

/// The report step's `--build "<label>=<args>"` rows.
fn report_rows(step: &str) -> Vec<(String, BuildCommand)> {
    let joined = join_continuations(step);
    let mut rows = Vec::new();
    let mut rest = joined.as_str();
    while let Some(i) = rest.find("--build \"") {
        let after = &rest[i + "--build \"".len()..];
        let Some(end) = after.find('"') else { break };
        let spec = &after[..end];
        match spec.split_once('=') {
            Some((label, args)) => rows.push((label.to_string(), parse_build_command(args))),
            None => rows.push((spec.to_string(), BuildCommand::default())),
        }
        rest = &after[end + 1..];
    }
    rows
}

/// Every `cargo build` / `cargo zigbuild` invocation in a step body.
fn build_commands(step: &str) -> Vec<BuildCommand> {
    join_continuations(step)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo build ") || line.starts_with("cargo zigbuild "))
        .map(|line| {
            parse_build_command(
                line.strip_prefix("cargo ")
                    .unwrap_or(line)
                    .trim_start_matches("zigbuild ")
                    .trim_start_matches("build "),
            )
        })
        .collect()
}

/// Profile, target, packages, bins and features out of an argument string.
fn parse_build_command(args: &str) -> BuildCommand {
    let mut command = BuildCommand::default();
    let mut tokens = args
        .split_whitespace()
        .map(|token| token.trim_matches(['"', '\'']).to_string());
    let mut profile = None;
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--release" => profile = Some("release".to_string()),
            "--profile" => profile = tokens.next(),
            "--target" => command.target = tokens.next().unwrap_or_default(),
            "-p" | "--package" => {
                if let Some(package) = tokens.next() {
                    command.packages.insert(package);
                }
            }
            "--bin" => {
                if let Some(bin) = tokens.next() {
                    command.bins.insert(bin);
                }
            }
            "--features" => command.features = tokens.next().unwrap_or_default(),
            _ => {}
        }
    }
    command.profile = profile.unwrap_or_default();
    command
}

fn same_command(a: &BuildCommand, b: &BuildCommand) -> bool {
    a.profile == b.profile
        && a.packages == b.packages
        && a.bins == b.bins
        && a.features == b.features
        && (a.target == b.target || same_hostlib_target(a, b))
}

fn same_hostlib_target(a: &BuildCommand, b: &BuildCommand) -> bool {
    a.is_hostlib()
        && b.is_hostlib()
        && HOSTLIB_TARGET_ALIASES.contains(&a.target.as_str())
        && HOSTLIB_TARGET_ALIASES.contains(&b.target.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        let manifest = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        manifest
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(manifest)
    }

    const RELEASE_BUILD_STEP: &str = "\
          if [[ \"${BUILD_TARGET}\" == *-unknown-linux-musl ]]; then
            cargo zigbuild --profile release-min --target \"${BUILD_TARGET}\" --features \"${MVMCTL_RELEASE_FEATURES}\"
          else
            cargo build --profile release-min --target \"${BUILD_TARGET}\" --features \"${MVMCTL_RELEASE_FEATURES}\"
          fi
";

    const PER_VM_BUILD_STEP: &str = "\
          if [[ \"${BUILD_TARGET}\" == *apple-darwin ]]; then
            cargo build --release --target \"${BUILD_TARGET}\" -p mvm-hostd \\
              --bin mvm-hvf-supervisor
          fi
          if [[ \"${BUILD_TARGET}\" == *-unknown-linux-musl ]]; then
            cargo zigbuild --release --target \"${BUILD_TARGET}\" -p mvm-hostd -p mvm-gpu \\
              --bin mvm-host-agent \\
              --bin mvm-signer-helper
            cargo zigbuild --release --target \"${BUILD_TARGET/-unknown-linux-musl/-unknown-linux-gnu}\" \\
              -p mvm-hostlib --features mvm-client/release-channel
          else
            cargo build --release --target \"${BUILD_TARGET}\" -p mvm-hostd -p mvm-gpu \\
              --bin mvm-host-agent \\
              --bin mvm-signer-helper
            cargo build --release --target \"${BUILD_TARGET}\" -p mvm-hostlib \\
              --features mvm-client/release-channel
          fi
";

    const REPORT_ROWS: &str = "\
          cargo run --package xtask -- report-compile-units \\
            --build \"mvmctl (release-min)=build --profile release-min --target ${BUILD_TARGET} --features ${MVMCTL_RELEASE_FEATURES}\" \\
            --build \"daemons (release)=build --release --target ${BUILD_TARGET} -p mvm-hostd -p mvm-gpu --bin mvm-host-agent --bin mvm-signer-helper\" \\
            --build \"mvm-hostlib (release)=build --release --target ${hostlib_target} -p mvm-hostlib --features mvm-client/release-channel\" \\
            | tee -a \"${GITHUB_STEP_SUMMARY}\"
";

    fn workflow(report_step: &str) -> String {
        format!(
            "jobs:\n  build:\n    steps:\n      - name: Build release binary\n        run: |\n{RELEASE_BUILD_STEP}      - name: Build per-VM host binaries\n        run: |\n{PER_VM_BUILD_STEP}      - name: Report compilation units\n        continue-on-error: true\n        run: |\n          hostlib_target=\"${{BUILD_TARGET/-unknown-linux-musl/-unknown-linux-gnu}}\"\n          [[ \"${{BUILD_TARGET}}\" == *-unknown-linux-musl ]] || hostlib_target=\"${{BUILD_TARGET}}\"\n{report_step}"
        )
    }

    #[test]
    fn the_current_release_workflow_is_in_sync() {
        run(&workspace_root()).expect("release.yml's report step must mirror its build steps");
    }

    #[test]
    fn an_in_sync_fixture_passes() {
        assert!(check_release_workflow(&workflow(REPORT_ROWS)).is_empty());
    }

    #[test]
    fn a_drifted_report_row_is_named() {
        let drifted = REPORT_ROWS.replace(
            "--features ${MVMCTL_RELEASE_FEATURES}\"",
            "--features host\"",
        );
        let problems = check_release_workflow(&workflow(&drifted));
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("mvmctl (release-min)"), "{problems:?}");
        assert!(
            problems[1].contains("the release mvmctl build"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_build_nobody_reports_is_named() {
        let missing = REPORT_ROWS.replace(
            "            --build \"daemons (release)=build --release --target ${BUILD_TARGET} -p mvm-hostd -p mvm-gpu --bin mvm-host-agent --bin mvm-signer-helper\" \\\n",
            "",
        );
        let problems = check_release_workflow(&workflow(&missing));
        assert_eq!(
            problems,
            vec![
                "the per-VM daemon build is not mirrored by any `--build` row of the report step"
                    .to_string()
            ]
        );
    }

    #[test]
    fn an_invented_row_is_named() {
        let invented = format!(
            "{REPORT_ROWS}            --build \"mvmctl (debug)=build --target ${{BUILD_TARGET}}\" \\\n"
        );
        let problems = check_release_workflow(&workflow(&invented));
        assert_eq!(
            problems,
            vec![
                "the report row `mvmctl (debug)` mirrors no cargo build in the release steps"
                    .to_string()
            ]
        );
    }

    #[test]
    fn dropping_continue_on_error_or_the_summary_write_is_caught() {
        let src = workflow(REPORT_ROWS)
            .replace("        continue-on-error: true\n", "")
            .replace(" | tee -a \"${GITHUB_STEP_SUMMARY}\"", "");
        let problems = check_release_workflow(&src);
        assert!(
            problems.iter().any(|p| p.contains("continue-on-error")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("GITHUB_STEP_SUMMARY")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_missing_report_step_is_caught() {
        let problems = check_release_workflow("jobs:\n  build:\n    steps: []\n");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("Report compilation units"));
    }

    #[test]
    fn a_report_step_without_a_build_step_is_caught() {
        let src = "      - name: Report compilation units\n        run: cargo run\n";
        let problems = check_release_workflow(src);
        assert!(
            problems.iter().any(|p| p.contains("Build release binary")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Build per-VM host binaries")),
            "{problems:?}"
        );
        // With no build step there is nothing to compare rows against: the
        // gate reports the missing steps, not a pile of secondary mismatches.
        assert!(
            !problems
                .iter()
                .any(|p| p.contains("mirrors no cargo build")),
            "{problems:?}"
        );
    }

    #[test]
    fn continuations_quotes_and_zigbuild_parse() {
        let commands = build_commands(PER_VM_BUILD_STEP);
        let daemons = commands
            .iter()
            .find(|c| c.packages.contains("mvm-gpu"))
            .expect("the daemons invocation parses");
        assert_eq!(daemons.profile, "release");
        assert_eq!(daemons.target, "${BUILD_TARGET}");
        assert_eq!(
            daemons.bins.iter().map(String::as_str).collect::<Vec<_>>(),
            ["mvm-host-agent", "mvm-signer-helper"]
        );
        let hostlib = commands
            .iter()
            .find(|c| c.is_hostlib() && c.target.contains("/-unknown-linux-musl/"))
            .expect("the musl hostlib invocation parses");
        let reported = parse_build_command(
            "build --release --target ${hostlib_target} -p mvm-hostlib --features mvm-client/release-channel",
        );
        assert!(
            same_command(&reported, hostlib),
            "the hostlib target alias holds: {reported:?} vs {hostlib:?}"
        );
    }
}
