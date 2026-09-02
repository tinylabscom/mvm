//! `xtask record-release-evidence` / `xtask check-release-evidence`
//!
//! A release must not be cut without evidence that the documented surface
//! boots. `release.yml` gets that evidence from the `e2e-docs` lanes — except
//! on macOS, where no GitHub-hosted runner can produce it: `macos-latest` is
//! arm64 with a nested Hypervisor.framework that reports `HV_UNSUPPORTED`, and
//! on `macos-15-intel` the HVF supervisor is Apple-Silicon-only and links as a
//! stub while the libkrun formula is ARM-only. Issue #3011 tracks the
//! self-hosted Apple Silicon runner that fixes this properly.
//!
//! Until that runner exists the run happens on a maintainer's machine. This
//! module is what stops "we ran it locally" from being a promise. The run
//! writes a record naming the commit it ran at and the tree it ran against;
//! this gate refuses to let a release claim that evidence unless the tree being
//! tagged is the *same* tree, byte for byte, in every path that could change
//! what the suite proves.
//!
//! ## Why a digest and not a date
//!
//! A timestamp says when someone ran something, not what they ran. A commit
//! SHA alone is nearly as weak: a rebase, a squash-merge or a force-push moves
//! history under it, and the ancestry test then passes over a tree nobody
//! tested. So the authority here is a digest over the *content* of every
//! material path, taken from git's own object ids. Two trees with the same
//! digest cannot differ in anything the suite exercises; a single changed byte
//! in `crates/`, `features/`, `examples/`, `nix/`, `src/`, the README, the
//! lockfile or the harness scripts produces a different digest and the gate
//! fails.
//!
//! The commit SHA is still recorded, but only so a failure can *explain*
//! itself by diffing the two trees and naming the files that moved. It is
//! never what the gate trusts.
//!
//! ## What is deliberately not material
//!
//! `specs/`, `public/`, `.github/`, `.agent-memory/`, `CHANGELOG.md`, the
//! workspace-root `tests/` directory, and `xtask/` itself. None of them can
//! change what a booted guest does, and including them would invalidate the
//! evidence every time the release notes were written — which is the commit
//! immediately before the tag. An evidence scheme that a release cannot satisfy
//! is one that gets switched off.
//!
//! Root `tests/` is the near miss worth naming: it holds the workflow-structure
//! tests that pin this very mechanism, so it looks like it belongs. It does
//! not. Those tests assert things about YAML and never reach a guest, and
//! putting them in would mean a release could not both tighten its own gate and
//! keep its evidence.
//!
//! Note the consequence, because it is the honest limit of this gate: it
//! proves the tested tree and the tagged tree are identical where it looks. It
//! does not prove the run was clean on a host that matters, beyond the host
//! metadata the record carries, and it cannot detect a maintainer who edits
//! the record by hand. It raises the cost of a false claim from zero to
//! forging a digest; it does not make one impossible.
//!
//! ## Retirement
//!
//! This is scaffolding for a missing runner, not a destination. When
//! `e2e-docs.yml`'s macOS host check starts reporting `supported=true` — that
//! is, when the lane runs on hardware that can boot a guest — the evidence job
//! stops running and this gate goes quiet on its own. Nothing has to be
//! remembered and flipped back.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every path whose content can change what the documented-surface suite
/// proves.
///
/// Over-inclusive on purpose. A path listed here that turns out not to matter
/// costs one extra suite run; a path missing from here lets a real change ride
/// in under evidence that predates it. The two errors are not symmetric, so
/// the list errs toward the cheap one.
const MATERIAL_PATHSPECS: &[&str] = &[
    "crates",
    "src",
    "features",
    "examples",
    "nix",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "Justfile",
    "README.md",
    "scripts",
];

/// The lanes a record can describe.
///
/// A free-form string would let a typo write `macos-hfv.json`, which no gate
/// then reads and no release then misses — a silent hole exactly where the
/// point is to close one.
const KNOWN_LANES: &[&str] = &["macos-hvf", "linux-firecracker"];

fn evidence_path(workspace: &Path, lane: &str) -> PathBuf {
    workspace
        .join("specs/evidence/e2e")
        .join(format!("{lane}.json"))
}

fn validate_lane(lane: &str) -> Result<()> {
    if KNOWN_LANES.contains(&lane) {
        return Ok(());
    }
    bail!(
        "unknown lane {lane:?}; known lanes: {}",
        KNOWN_LANES.join(", ")
    )
}

/// What a run recorded about itself.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Which documented-surface lane this run was.
    pub lane: String,
    /// The commit the tree was at. Explanatory only — see the module docs.
    pub commit: String,
    /// The authority: a digest over every material path's git object id.
    pub material_digest: String,
    /// When the run finished, ISO-8601 UTC.
    pub recorded_at: String,
    /// Where it ran. Carried so a reader can tell an Apple Silicon run from a
    /// run on a host that could not have booted the backend it claims.
    pub host: HostFacts,
    /// The suite's own summary, parsed from its output.
    pub suite: SuiteSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostFacts {
    pub os: String,
    pub os_version: String,
    pub arch: String,
}

/// The `[Summary]` block cucumber prints when a run completes.
///
/// A run that produced no such block proved nothing, whatever its exit status
/// says — the conformance binary refuses to start against a stale `mvmctl`,
/// and that refusal prints zero scenarios, which reads as zero failures.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuiteSummary {
    pub features: u32,
    pub scenarios_total: u32,
    pub scenarios_passed: u32,
    pub scenarios_skipped: u32,
    pub steps_total: u32,
    pub steps_passed: u32,
}

fn git(workspace: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(workspace)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("git emitted non-UTF-8 output")
}

fn head_commit(workspace: &Path) -> Result<String> {
    Ok(git(workspace, &["rev-parse", "HEAD"])?.trim().to_string())
}

/// Material paths with uncommitted changes.
///
/// Both recording and checking refuse while this is non-empty. The digest is
/// taken from git's index, so an unstaged edit would be invisible to it: the
/// record would describe a tree that was never the tree under test.
fn dirty_material_paths(workspace: &Path) -> Result<Vec<String>> {
    let mut args = vec!["status", "--porcelain", "--"];
    args.extend_from_slice(MATERIAL_PATHSPECS);
    let out = git(workspace, &args)?;
    Ok(out
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// A digest over every material path's git blob id.
///
/// `git ls-files -s` emits `<mode> <object> <stage>\t<path>` in path order, so
/// the input to the hash is already deterministic without sorting here.
fn material_digest(workspace: &Path) -> Result<String> {
    let mut args = vec!["ls-files", "-s", "--"];
    args.extend_from_slice(MATERIAL_PATHSPECS);
    let listing = git(workspace, &args)?;
    if listing.trim().is_empty() {
        bail!("no material paths are tracked — refusing to digest an empty tree");
    }
    let mut hasher = Sha256::new();
    hasher.update(listing.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn host_facts() -> HostFacts {
    let uname = |arg: &str| {
        Command::new("uname")
            .arg(arg)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };
    let os_version = if cfg!(target_os = "macos") {
        Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|| uname("-r"))
    } else {
        uname("-r")
    };
    HostFacts {
        os: uname("-s"),
        os_version,
        arch: uname("-m"),
    }
}

/// Pull the counts out of cucumber's `[Summary]` block.
///
/// The block looks like:
///
/// ```text
/// [Summary]
/// 78 features
/// 295 scenarios (295 passed)
/// 4310 steps (4310 passed)
/// ```
///
/// with the parenthesised breakdown gaining `failed` and `skipped` terms as
/// they occur. Everything before `[Summary]` is ignored, so a scenario whose
/// captured output happens to contain the word "scenarios" cannot be mistaken
/// for the tally.
fn parse_summary(log: &str) -> Result<SuiteSummary> {
    let summary_start = log
        .lines()
        .position(|line| line.trim_start().starts_with("[Summary]"))
        .context(
            "the run produced no [Summary] block — it proved nothing, whatever its exit status \
             said. A conformance binary that refuses to start against a stale mvmctl prints zero \
             scenarios, which is not the same as zero failures.",
        )?;
    let tail: Vec<&str> = log.lines().skip(summary_start).collect();

    let features = parse_count_line(&tail, "features")
        .context("no `N features` line in the [Summary] block")?
        .0;
    let (scenarios_total, scenario_terms) = parse_count_line(&tail, "scenarios")
        .context("no `N scenarios` line in the [Summary] block")?;
    let (steps_total, step_terms) =
        parse_count_line(&tail, "steps").context("no `N steps` line in the [Summary] block")?;

    let failed = term(&scenario_terms, "failed");
    if failed > 0 {
        bail!(
            "the run had {failed} failing scenario(s); evidence is only recorded for a clean run"
        );
    }

    Ok(SuiteSummary {
        features,
        scenarios_total,
        scenarios_passed: term(&scenario_terms, "passed"),
        scenarios_skipped: term(&scenario_terms, "skipped"),
        steps_total,
        steps_passed: term(&step_terms, "passed"),
    })
}

/// Find `N <noun>` in the summary block and return `N` plus the `(a passed, b
/// failed)` breakdown that follows it, as `(count, word)` pairs.
fn parse_count_line(lines: &[&str], noun: &str) -> Option<(u32, Vec<(u32, String)>)> {
    for line in lines {
        let trimmed = line.trim();
        let mut words = trimmed.split_whitespace();
        let Some(total) = words.next().and_then(|w| w.parse::<u32>().ok()) else {
            continue;
        };
        if words.next() != Some(noun) {
            continue;
        }
        let terms = match (trimmed.find('('), trimmed.rfind(')')) {
            (Some(open), Some(close)) if close > open + 1 => trimmed[open + 1..close]
                .split(',')
                .filter_map(|term| {
                    let mut parts = term.split_whitespace();
                    let count = parts.next()?.parse::<u32>().ok()?;
                    Some((count, parts.next()?.to_string()))
                })
                .collect(),
            _ => Vec::new(),
        };
        return Some((total, terms));
    }
    None
}

fn term(terms: &[(u32, String)], name: &str) -> u32 {
    terms
        .iter()
        .find(|(_, word)| word == name)
        .map(|(count, _)| *count)
        .unwrap_or(0)
}

/// Write the evidence record for a lane, given the log of the run that earned
/// it.
pub fn record(workspace: &Path, lane: &str, log: &Path) -> Result<()> {
    validate_lane(lane)?;

    let dirty = dirty_material_paths(workspace)?;
    if !dirty.is_empty() {
        bail!(
            "refusing to record evidence from a dirty tree — the digest comes from git's index, \
             so these edits were never part of what ran:\n  {}",
            dirty.join("\n  ")
        );
    }

    let text = std::fs::read_to_string(log)
        .with_context(|| format!("reading the suite log at {}", log.display()))?;
    let suite = parse_summary(&text)?;

    let record = EvidenceRecord {
        lane: lane.to_string(),
        commit: head_commit(workspace)?,
        material_digest: material_digest(workspace)?,
        recorded_at: iso8601_now()?,
        host: host_facts(),
        suite,
    };

    let path = evidence_path(workspace, lane);
    let parent = path
        .parent()
        .context("evidence path has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut json = serde_json::to_string_pretty(&record).context("serialising the record")?;
    json.push('\n');
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;

    println!(
        "recorded {lane} evidence at {}\n  commit  {}\n  digest  {}\n  suite   {} scenarios ({} \
         passed, {} skipped) across {} features",
        path.display(),
        record.commit,
        record.material_digest,
        record.suite.scenarios_total,
        record.suite.scenarios_passed,
        record.suite.scenarios_skipped,
        record.suite.features,
    );
    Ok(())
}

/// Fail unless every named lane has a record covering the current tree.
pub fn check(workspace: &Path, lanes: &[String]) -> Result<()> {
    let lanes: Vec<String> = if lanes.is_empty() {
        KNOWN_LANES.iter().map(|l| (*l).to_string()).collect()
    } else {
        lanes.to_vec()
    };
    for lane in &lanes {
        validate_lane(lane)?;
    }

    let dirty = dirty_material_paths(workspace)?;
    if !dirty.is_empty() {
        bail!(
            "the working tree has uncommitted material changes, so no evidence can describe it:\n  \
             {}",
            dirty.join("\n  ")
        );
    }

    let actual = material_digest(workspace)?;
    let head = head_commit(workspace)?;
    let mut failures = Vec::new();

    for lane in &lanes {
        let path = evidence_path(workspace, lane);
        let Ok(text) = std::fs::read_to_string(&path) else {
            failures.push(format!(
                "{lane}: no evidence at {}. Run `just e2e-docs` on a host that can boot this \
                 backend, then `just record-e2e-evidence {lane}`.",
                path.display()
            ));
            continue;
        };
        let record: EvidenceRecord =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        if record.lane != *lane {
            failures.push(format!(
                "{lane}: {} records lane {:?} — the file and its contents disagree.",
                path.display(),
                record.lane
            ));
            continue;
        }
        if record.material_digest == actual {
            println!(
                "check-release-evidence: {lane} ok — {} scenarios on {} {} ({}), recorded {}",
                record.suite.scenarios_total,
                record.host.os,
                record.host.os_version,
                record.host.arch,
                record.recorded_at,
            );
            continue;
        }

        let changed = changed_material_paths(workspace, &record.commit, &head).unwrap_or_default();
        let detail = if changed.is_empty() {
            "  (could not diff the two trees — is the recorded commit still present?)".to_string()
        } else {
            let shown: Vec<String> = changed.iter().take(20).cloned().collect();
            let more = changed.len().saturating_sub(shown.len());
            let mut lines = shown.join("\n  ");
            if more > 0 {
                lines.push_str(&format!("\n  … and {more} more"));
            }
            format!("  {lines}")
        };
        failures.push(format!(
            "{lane}: the evidence describes a different tree.\n    recorded at commit {} (digest \
             {})\n    HEAD is {} (digest {})\n  material paths that changed since the run:\n{}",
            record.commit, record.material_digest, head, actual, detail
        ));
    }

    if !failures.is_empty() {
        bail!(
            "check-release-evidence: {} lane(s) without current evidence\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
    println!("check-release-evidence: clean ({} lane(s))", lanes.len());
    Ok(())
}

fn changed_material_paths(workspace: &Path, from: &str, to: &str) -> Result<Vec<String>> {
    let mut args = vec!["diff", "--name-only", from, to, "--"];
    args.extend_from_slice(MATERIAL_PATHSPECS);
    let out = git(workspace, &args)?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// `date -u +%Y-%m-%dT%H:%M:%SZ`, without pulling `chrono` into xtask for one
/// string.
fn iso8601_now() -> Result<String> {
    let out = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .context("running date")?;
    if !out.status.success() {
        bail!("date failed");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN_LOG: &str = "\
running 1 test
   ✔  Given something
[Summary]
78 features
295 scenarios (295 passed)
4310 steps (4310 passed)
";

    #[test]
    fn parses_a_clean_summary() {
        let summary = parse_summary(CLEAN_LOG).expect("clean log parses");
        assert_eq!(summary.features, 78);
        assert_eq!(summary.scenarios_total, 295);
        assert_eq!(summary.scenarios_passed, 295);
        assert_eq!(summary.scenarios_skipped, 0);
        assert_eq!(summary.steps_total, 4310);
        assert_eq!(summary.steps_passed, 4310);
    }

    #[test]
    fn parses_skipped_scenarios() {
        let log = "[Summary]\n2 features\n10 scenarios (8 passed, 2 skipped)\n40 steps (40 passed)";
        let summary = parse_summary(log).expect("log with skips parses");
        assert_eq!(summary.scenarios_passed, 8);
        assert_eq!(summary.scenarios_skipped, 2);
    }

    /// A failing run must not be able to mint evidence. This is the whole
    /// point of parsing the summary rather than trusting an exit status.
    #[test]
    fn refuses_a_run_with_failures() {
        let log = "[Summary]\n2 features\n10 scenarios (9 passed, 1 failed)\n40 steps (39 passed)";
        let error = parse_summary(log).expect_err("a failing run is refused");
        assert!(
            error.to_string().contains("1 failing scenario"),
            "unexpected error: {error}"
        );
    }

    /// The shape that fooled a reader once already: the suite was invoked, it
    /// refused to start, and the log showed zero failures because it showed
    /// zero scenarios.
    #[test]
    fn refuses_a_log_with_no_summary_block() {
        let error = parse_summary("error: mvmctl is older than its sources\n")
            .expect_err("a log with no summary is refused");
        assert!(
            error.to_string().contains("no [Summary] block"),
            "unexpected error: {error}"
        );
    }

    /// Text before the summary must not be mistaken for the tally — a
    /// scenario's own captured output can say almost anything.
    #[test]
    fn ignores_counts_printed_before_the_summary() {
        let log = "\
999 scenarios (999 passed)
[Summary]
1 features
3 scenarios (3 passed)
9 steps (9 passed)
";
        let summary = parse_summary(log).expect("parses");
        assert_eq!(summary.scenarios_total, 3);
    }

    #[test]
    fn rejects_an_unknown_lane() {
        let error = validate_lane("macos-hfv").expect_err("a typo is refused");
        assert!(error.to_string().contains("unknown lane"));
    }

    #[test]
    fn accepts_the_known_lanes() {
        for lane in KNOWN_LANES {
            validate_lane(lane).expect("known lane is accepted");
        }
    }
}
