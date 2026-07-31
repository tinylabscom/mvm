//! `xtask check-mutation-witnesses`
//!
//! `check-claim-catalog` proves a claim's witness *exists*. Nothing
//! proves it *bites*: a test can name the right symbol, exercise the
//! happy path, pass forever, and never have had the power to fail. The
//! claim stays green while the property rots.
//!
//! This gate breaks the enforcement code on purpose and asks whether a
//! witness notices. A surviving mutant is a claim whose witness cannot
//! detect its own property being violated.
//!
//! The surface is derived from the ledger, never hand-listed. Each `fn:`
//! witness resolves to the file declaring it, and this repo keeps
//! `#[cfg(test)] mod tests` beside the implementation, so a witness
//! lands on the enforcement code it guards.
//!
//! Three modes:
//!
//! - default — resolve the surface and compare it against the committed
//!   surface. Milliseconds, no cargo-mutants needed, safe on a PR. This
//!   is what stops a claim from silently dropping out of the expensive
//!   lane's scope: the surface is a committed file, so a claim leaving
//!   coverage is a reviewable diff.
//! - `--run` — additionally run cargo-mutants over the surface and
//!   ratchet observed misses against the baseline. Hours; nightly.
//! - `--write-baseline` — re-pin the surface, keeping the stated reasons
//!   on existing accepted misses. Cheap: a witness moving should not
//!   cost a mutation run. Add `--run` to also re-record the misses,
//!   which discards those reasons and so is a deliberate reset.

use crate::claims_ledger::{self, Witness};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where the pinned surface and accepted misses live.
const BASELINE_REL: &str = "xtask/mutation-witness-baseline.json";

/// Per-mutant test timeout handed to cargo-mutants. A mutant that hangs
/// is a caught mutant as far as this gate cares, but without a bound a
/// single infinite loop stalls the whole lane.
const MUTANT_TIMEOUT_SECS: u32 = 300;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Resolve the surface and compare against the committed pin.
    /// Milliseconds; needs no cargo-mutants.
    PinOnly,
    /// Also run cargo-mutants and ratchet against accepted misses.
    Run,
    /// Re-pin the surface, keeping the accepted misses. Cheap, and the
    /// common maintenance case: a witness moved and the pin needs to
    /// catch up, which should not cost a mutation run.
    RepinSurface,
    /// Re-pin the surface *and* re-record accepted misses from a fresh
    /// run. Hours, and it forgets previously stated reasons, so it is
    /// the rare deliberate reset rather than the routine fix.
    RewriteBaseline,
}

/// A file carrying at least one claim witness.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SurfaceFile {
    /// Workspace-relative, forward-slashed.
    pub path: String,
    /// The cargo package that owns it.
    pub package: String,
    /// Claim numbers whose witnesses resolve here.
    pub claims: Vec<u32>,
}

/// A mutant that survived, with a stated reason for tolerating it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AcceptedMiss {
    pub file: String,
    /// Description with `line:col` stripped — see [`mutant_identity`].
    pub mutant: String,
    /// Why this hole is tolerated. Empty is a gate failure: an
    /// unexplained entry is how a baseline turns into a dumping ground.
    pub reason: String,
}

/// A claim that contributes nothing to the mutation surface.
///
/// Not a failure: a claim witnessed only by a CI lane (a symbol grep, a
/// fuzz job) has no function to mutate. But it must be *stated*, because
/// "the mutation lane is green" over 12 of 16 claims reads as coverage it
/// does not have. Pinned alongside the surface so a newly added claim
/// with no coverage shows up in review instead of passing unnoticed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UncoveredClaim {
    pub number: u32,
    pub why: String,
}

/// Why a claim's `fn:` witnesses yield nothing mutable.
const WHY_NO_FN_WITNESS: &str = "no fn: witness — witnessed by CI lanes only, nothing to mutate";
const WHY_ONLY_INTEGRATION_TESTS: &str =
    "every fn: witness lives in crates/*/tests/, which cargo-mutants does not mutate";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub surface: Vec<SurfaceFile>,
    pub uncovered_claims: Vec<UncoveredClaim>,
    pub accepted_misses: Vec<AcceptedMiss>,
}

/// The resolved mutation surface plus the claims it does not reach.
#[derive(Debug, Default)]
pub struct Surface {
    pub files: Vec<SurfaceFile>,
    pub uncovered: Vec<UncoveredClaim>,
}

/// One observed surviving mutant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Miss {
    pub file: String,
    pub mutant: String,
}

pub fn run(workspace: &Path, mode: Mode) -> Result<()> {
    let Surface {
        files: resolved,
        uncovered,
    } = resolve_surface(workspace)?;
    if resolved.is_empty() {
        bail!(
            "check-mutation-witnesses: the claims ledger resolved to no mutable files at all — \
             either every `fn:` witness is missing from the tree (run check-claim-catalog) or the \
             ledger is empty"
        );
    }

    let baseline_path = workspace.join(BASELINE_REL);

    if matches!(mode, Mode::RepinSurface | Mode::RewriteBaseline) {
        // Re-pinning keeps the stated reasons; a full rewrite discards
        // them on purpose, having just re-observed the ground truth.
        let accepted_misses = if mode == Mode::RewriteBaseline {
            seed_accepted(&run_mutants_over(workspace, &resolved)?)
        } else {
            read_baseline(&baseline_path)
                .map(|b| b.accepted_misses)
                .unwrap_or_default()
        };
        let baseline = Baseline {
            surface: resolved,
            uncovered_claims: uncovered,
            accepted_misses,
        };
        write_baseline(&baseline_path, &baseline)?;
        eprintln!(
            "check-mutation-witnesses: wrote {} ({} surface files, {} accepted misses)",
            BASELINE_REL,
            baseline.surface.len(),
            baseline.accepted_misses.len()
        );
        return Ok(());
    }

    let baseline = read_baseline(&baseline_path)?;
    let mut errors = check_accepted_reasons(&baseline.accepted_misses);
    errors.extend(diff_surface(&baseline.surface, &resolved));
    errors.extend(diff_uncovered(&baseline.uncovered_claims, &uncovered));

    for u in &uncovered {
        eprintln!(
            "[note] claim {} has no mutation surface: {}",
            u.number, u.why
        );
    }

    if mode == Mode::Run {
        let observed = run_mutants_over(workspace, &resolved)?;
        let verdict = ratchet(&baseline.accepted_misses, &observed);
        for m in &verdict.new_misses {
            errors.push(format!(
                "new surviving mutant in {}: {} — a claim witness does not detect this change",
                m.file, m.mutant
            ));
        }
        for m in &verdict.now_caught {
            eprintln!(
                "[note] {} :: {} is now caught — drop it from {BASELINE_REL}",
                m.file, m.mutant
            );
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-mutation-witnesses: {} problem(s); if the surface moved on purpose, \
             re-pin with `cargo run -p xtask -- check-mutation-witnesses --write-baseline`",
            errors.len()
        );
    }

    eprintln!(
        "check-mutation-witnesses: surface pinned and clean ({} files across {} packages, {} accepted misses)",
        resolved.len(),
        resolved
            .iter()
            .map(|s| s.package.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        baseline.accepted_misses.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Surface resolution
// ---------------------------------------------------------------------

/// Map every `fn:` witness in the ledger to the file that declares it.
pub fn resolve_surface(workspace: &Path) -> Result<Surface> {
    let rows = claims_ledger::load(workspace)?;

    // fn name -> claim numbers naming it.
    let mut wanted: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    // Claims with no `fn:` witness at all have nothing to resolve.
    let mut claims_with_fn_witness: BTreeSet<u32> = BTreeSet::new();
    for row in &rows {
        for w in &row.witnesses {
            if let Witness::Fn(name) = w {
                wanted.entry(name.clone()).or_default().insert(row.number);
                claims_with_fn_witness.insert(row.number);
            }
        }
    }

    // path -> claim numbers whose witnesses live there. Integration-test
    // paths are collected too, so a claim witnessed *only* by an
    // integration test can be reported as uncovered rather than
    // silently vanishing.
    let mut hits: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let crates = workspace.join("crates");
    claims_ledger::for_each_file(&crates, Some("rs"), &mut |path, content| {
        for (name, claims) in &wanted {
            if content.contains(&format!("fn {name}(")) {
                let Some(rel) = workspace_relative(workspace, path) else {
                    continue;
                };
                hits.entry(rel).or_default().extend(claims.iter().copied());
            }
        }
    })?;

    let mut files: Vec<SurfaceFile> = hits
        .iter()
        .filter(|(path, _)| !is_integration_test(path))
        .filter_map(|(path, claims)| {
            Some(SurfaceFile {
                path: path.clone(),
                package: package_for(path)?,
                claims: claims.iter().copied().collect(),
            })
        })
        .collect();
    files.sort();

    let covered: BTreeSet<u32> = files
        .iter()
        .flat_map(|f| f.claims.iter().copied())
        .collect();
    let uncovered = rows
        .iter()
        .map(|r| r.number)
        .filter(|n| !covered.contains(n))
        .map(|number| UncoveredClaim {
            why: if claims_with_fn_witness.contains(&number) {
                WHY_ONLY_INTEGRATION_TESTS.to_string()
            } else {
                WHY_NO_FN_WITNESS.to_string()
            },
            number,
        })
        .collect();

    Ok(Surface { files, uncovered })
}

/// `crates/mvm-protocol/src/policy/network_policy.rs` -> `mvm-protocol`.
pub fn package_for(rel_path: &str) -> Option<String> {
    let mut parts = rel_path.split('/');
    if parts.next()? != "crates" {
        return None;
    }
    let first = parts.next()?;
    // `crates/deps/libkrun-sys/...` nests one level deeper.
    if first == "deps" {
        return parts.next().map(str::to_string);
    }
    Some(first.to_string())
}

/// True for `crates/<pkg>/tests/...`, which cargo-mutants never mutates.
pub fn is_integration_test(rel_path: &str) -> bool {
    rel_path.split('/').nth(2) == Some("tests")
}

fn workspace_relative(workspace: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(workspace).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Human-readable differences between the pinned and resolved surfaces.
pub fn diff_surface(committed: &[SurfaceFile], resolved: &[SurfaceFile]) -> Vec<String> {
    let mut errors = Vec::new();
    let by_path = |v: &[SurfaceFile]| -> BTreeMap<String, SurfaceFile> {
        v.iter().map(|s| (s.path.clone(), s.clone())).collect()
    };
    let old = by_path(committed);
    let new = by_path(resolved);

    for path in new.keys() {
        if !old.contains_key(path) {
            errors.push(format!("surface gained {path} (not in the committed pin)"));
        }
    }
    for (path, was) in &old {
        match new.get(path) {
            None => errors.push(format!(
                "surface lost {path} — claim(s) {:?} no longer resolve there, so they have \
                 dropped out of mutation coverage",
                was.claims
            )),
            Some(now) if now.claims != was.claims => errors.push(format!(
                "surface {path} changed claims {:?} -> {:?}",
                was.claims, now.claims
            )),
            Some(now) if now.package != was.package => errors.push(format!(
                "surface {path} changed package {} -> {}",
                was.package, now.package
            )),
            Some(_) => {}
        }
    }
    errors
}

/// Differences between the pinned and resolved uncovered-claim sets.
///
/// A claim gaining coverage is progress and only worth re-pinning; a
/// claim *losing* it means the nightly lane silently stopped asking
/// anything about that claim.
pub fn diff_uncovered(committed: &[UncoveredClaim], resolved: &[UncoveredClaim]) -> Vec<String> {
    let old: BTreeSet<u32> = committed.iter().map(|u| u.number).collect();
    let mut errors = Vec::new();
    for u in resolved {
        if !old.contains(&u.number) {
            errors.push(format!(
                "claim {} lost its mutation surface ({}) — the nightly lane no longer asks \
                 anything about it",
                u.number, u.why
            ));
        }
    }
    let now: BTreeSet<u32> = resolved.iter().map(|u| u.number).collect();
    for n in old.difference(&now) {
        errors.push(format!(
            "claim {n} gained a mutation surface — re-pin so the baseline records it"
        ));
    }
    errors
}

/// Every accepted miss must say why. An unexplained entry is how a
/// ratchet baseline degrades into a suppression list.
pub fn check_accepted_reasons(accepted: &[AcceptedMiss]) -> Vec<String> {
    accepted
        .iter()
        .filter(|a| a.reason.trim().is_empty())
        .map(|a| {
            format!(
                "accepted miss {} :: {} has no reason — state why the hole is tolerable",
                a.file, a.mutant
            )
        })
        .collect()
}

// ---------------------------------------------------------------------
// Ratchet
// ---------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Survived, and not in the baseline. These fail the gate.
    pub new_misses: Vec<Miss>,
    /// In the baseline, but caught now. Reported so the baseline shrinks.
    pub now_caught: Vec<AcceptedMiss>,
}

pub fn ratchet(accepted: &[AcceptedMiss], observed: &[Miss]) -> Verdict {
    let accepted_keys: BTreeSet<(&str, &str)> = accepted
        .iter()
        .map(|a| (a.file.as_str(), a.mutant.as_str()))
        .collect();
    let observed_keys: BTreeSet<(&str, &str)> = observed
        .iter()
        .map(|m| (m.file.as_str(), m.mutant.as_str()))
        .collect();

    Verdict {
        new_misses: observed
            .iter()
            .filter(|m| !accepted_keys.contains(&(m.file.as_str(), m.mutant.as_str())))
            .cloned()
            .collect(),
        now_caught: accepted
            .iter()
            .filter(|a| !observed_keys.contains(&(a.file.as_str(), a.mutant.as_str())))
            .cloned()
            .collect(),
    }
}

fn seed_accepted(misses: &[Miss]) -> Vec<AcceptedMiss> {
    misses
        .iter()
        .map(|m| AcceptedMiss {
            file: m.file.clone(),
            mutant: m.mutant.clone(),
            reason: "untriaged: seeded from the first observed run".to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------
// cargo-mutants invocation and output parsing
// ---------------------------------------------------------------------

/// Split a cargo-mutants report line into (file, description), dropping
/// `line:col`. Identity without position survives edits elsewhere in the
/// same file, so an unrelated change above a mutant does not invalidate
/// the baseline.
///
/// `crates/a/src/b.rs:23:5: replace f -> bool with true`
///   -> ("crates/a/src/b.rs", "replace f -> bool with true")
pub fn mutant_identity(line: &str) -> Option<Miss> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // Walk from the left: path, then two numeric fields, then the rest.
    // A description can itself contain colons (`Foo::bar`), so splitting
    // naively on ':' and taking a fixed field count is wrong.
    let mut rest = line;
    let mut fields = Vec::new();
    for _ in 0..3 {
        let (head, tail) = rest.split_once(':')?;
        fields.push(head);
        rest = tail;
    }
    let (line_no, col_no) = (fields[1], fields[2]);
    if line_no.parse::<u32>().is_err() || col_no.parse::<u32>().is_err() {
        return None;
    }
    let description = rest.trim();
    if description.is_empty() {
        return None;
    }
    Some(Miss {
        file: fields[0].to_string(),
        mutant: description.to_string(),
    })
}

pub fn parse_missed(report: &str) -> Vec<Miss> {
    let mut out: Vec<Miss> = report.lines().filter_map(mutant_identity).collect();
    out.sort();
    out.dedup();
    out
}

/// Run cargo-mutants once per surface file and collect the misses.
///
/// Scoped per file with `-p <package> --file <path>`: the package scope
/// keeps each invocation from re-testing the whole workspace, and it is
/// the stricter question — the owning crate's own tests must catch the
/// tampering.
fn run_mutants_over(workspace: &Path, surface: &[SurfaceFile]) -> Result<Vec<Miss>> {
    ensure_cargo_mutants()?;
    let out_root = std::env::temp_dir().join("mvm-mutation-witnesses");
    std::fs::create_dir_all(&out_root)
        .with_context(|| format!("creating {}", out_root.display()))?;
    let sandbox = Sandbox::new()?;
    eprintln!(
        "mutation run confined to {} (HOME + MVM_HOME)",
        sandbox.root.display()
    );

    let mut all = Vec::new();
    for (i, file) in surface.iter().enumerate() {
        eprintln!(
            "[{}/{}] mutating {} (package {}, claims {:?})",
            i + 1,
            surface.len(),
            file.path,
            file.package,
            file.claims
        );
        let out_dir = out_root.join(file.path.replace('/', "_"));
        all.extend(run_mutants_for_file(workspace, file, &out_dir, &sandbox)?);
    }
    all.sort();
    all.dedup();
    Ok(all)
}

/// A throwaway state root for the mutation run.
///
/// A mutant is the enforcement code with a check removed, and the suite is
/// then run against it — so the run can write audit chains, mint a signer
/// key at whatever path or mode the mutated logic picks, and leave state
/// behind. None of that may touch the invoking user's `~/.mvm` or `$HOME`.
///
/// `CARGO_HOME` and `RUSTUP_HOME` are carried across explicitly: moving
/// `HOME` alone would send cargo looking for a registry and a toolchain
/// under the sandbox, re-downloading both on a run that already costs
/// hours.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    mvm_home: PathBuf,
    cargo_home: PathBuf,
    rustup_home: PathBuf,
    // Deleted on drop; the run's state must not outlive it.
    _dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("mvm-mutation-sandbox-")
            .tempdir()
            .context("creating the mutation-run sandbox")?;
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        let mvm_home = root.join("mvm");
        for p in [&home, &mvm_home] {
            std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
        }
        let real_home = std::env::var_os("HOME").map(PathBuf::from);
        let inherited = |var: &str, fallback: &str| -> Result<PathBuf> {
            if let Some(v) = std::env::var_os(var) {
                return Ok(PathBuf::from(v));
            }
            real_home
                .as_ref()
                .map(|h| h.join(fallback))
                .with_context(|| format!("neither {var} nor HOME is set; cannot locate {fallback}"))
        };
        Ok(Self {
            cargo_home: inherited("CARGO_HOME", ".cargo")?,
            rustup_home: inherited("RUSTUP_HOME", ".rustup")?,
            root,
            home,
            mvm_home,
            _dir: dir,
        })
    }

    fn apply(&self, cmd: &mut std::process::Command) {
        cmd.env("HOME", &self.home)
            .env("MVM_HOME", &self.mvm_home)
            .env("CARGO_HOME", &self.cargo_home)
            .env("RUSTUP_HOME", &self.rustup_home);
    }
}

fn run_mutants_for_file(
    workspace: &Path,
    file: &SurfaceFile,
    out_dir: &Path,
    sandbox: &Sandbox,
) -> Result<Vec<Miss>> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(workspace)
        .arg("mutants")
        .args(["-p", &file.package])
        .args(["--file", &file.path])
        .args(["--test-tool", "nextest"])
        .args(["--timeout", &MUTANT_TIMEOUT_SECS.to_string()])
        .arg("--output")
        .arg(out_dir)
        // The embedded host-vm binaries are cross-compiled by
        // mvm-cli's build.rs; a mutation run rebuilds per mutant and
        // does not boot a VM, so paying that cost every time is waste.
        .env("MVM_SKIP_EMBED_BINARIES", "1");
    sandbox.apply(&mut cmd);
    let status = cmd.status().context("spawning `cargo mutants`")?;

    // Exit status is deliberately not the signal: cargo-mutants exits
    // nonzero merely because mutants survived, which is the case this
    // gate exists to report. The report files are the signal, and their
    // absence means the run genuinely failed.
    let missed = out_dir.join("mutants.out").join("missed.txt");
    let caught = out_dir.join("mutants.out").join("caught.txt");
    if !missed.exists() && !caught.exists() {
        bail!(
            "cargo mutants produced no report for {} (exit {:?}); expected {} or {}",
            file.path,
            status.code(),
            missed.display(),
            caught.display()
        );
    }
    let report = if missed.exists() {
        std::fs::read_to_string(&missed).with_context(|| format!("reading {}", missed.display()))?
    } else {
        String::new()
    };
    Ok(parse_missed(&report))
}

fn ensure_cargo_mutants() -> Result<()> {
    let ok = std::process::Command::new("cargo")
        .args(["mutants", "--version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        bail!("cargo-mutants is not installed — `cargo install cargo-mutants --locked`");
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Baseline I/O
// ---------------------------------------------------------------------

fn read_baseline(path: &Path) -> Result<Baseline> {
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} — seed it with `cargo run -p xtask -- check-mutation-witnesses \
             --write-baseline`",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn write_baseline(path: &Path, baseline: &Baseline) -> Result<()> {
    let mut json = serde_json::to_string_pretty(baseline)
        .context("serializing the mutation-witness baseline")?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_strips_line_and_column() {
        let m = mutant_identity("crates/a/src/b.rs:23:5: replace f -> bool with true").unwrap();
        assert_eq!(m.file, "crates/a/src/b.rs");
        assert_eq!(m.mutant, "replace f -> bool with true");
    }

    #[test]
    fn identity_keeps_colons_inside_the_description() {
        let m = mutant_identity("crates/a/src/b.rs:9:1: replace == with != in Foo::bar").unwrap();
        assert_eq!(m.mutant, "replace == with != in Foo::bar");
    }

    #[test]
    fn identity_rejects_non_report_lines() {
        assert!(mutant_identity("").is_none());
        assert!(mutant_identity("just prose").is_none());
        assert!(mutant_identity("path:notanumber:5: replace x").is_none());
        assert!(mutant_identity("crates/a.rs:1:2: ").is_none());
    }

    #[test]
    fn identity_collapses_two_positions_of_the_same_change() {
        // Same description at different positions is one identity: that
        // is what keeps the baseline stable under code motion.
        let a = mutant_identity("f.rs:1:1: replace == with !=").unwrap();
        let b = mutant_identity("f.rs:90:7: replace == with !=").unwrap();
        assert_eq!(a, b);
    }

    /// Verbatim `mutants.out/missed.txt` from a real cargo-mutants 27.1
    /// run over the claim-10 anchor. A hand-written fixture would only
    /// prove the parser matches my assumption about the format; this
    /// proves it matches the tool.
    const REAL_MISSED_REPORT: &str = "\
crates/mvm-protocol/src/policy/network_policy.rs:92:5: replace is_banned_ssh_port -> bool with false
crates/mvm-protocol/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with false
crates/mvm-protocol/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with true
crates/mvm-protocol/src/policy/network_policy.rs:271:9: replace NetworkPolicy::trusted_build_egress -> Self with Default::default()
";

    #[test]
    fn real_tool_output_parses_into_four_distinct_identities() {
        let misses = parse_missed(REAL_MISSED_REPORT);
        assert_eq!(
            misses.len(),
            4,
            "two is_deny_all mutants differ by replacement"
        );
        assert!(
            misses
                .iter()
                .all(|m| m.file == "crates/mvm-protocol/src/policy/network_policy.rs")
        );
        // The `-> Self with Default::default()` form carries both `::`
        // and `()`; a naive field split would truncate it.
        assert!(misses.iter().any(|m| m.mutant
            == "replace NetworkPolicy::trusted_build_egress -> Self with Default::default()"));
    }

    #[test]
    fn real_tool_output_ratchets_clean_against_matching_accepted_entries() {
        let observed = parse_missed(REAL_MISSED_REPORT);
        let accepted: Vec<AcceptedMiss> = observed
            .iter()
            .map(|m| AcceptedMiss {
                file: m.file.clone(),
                mutant: m.mutant.clone(),
                reason: "triaged".into(),
            })
            .collect();
        let v = ratchet(&accepted, &observed);
        assert!(v.new_misses.is_empty(), "identities must round-trip");
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn parse_missed_sorts_and_dedupes() {
        let report = "\
z.rs:2:1: replace b with c
a.rs:1:1: replace x with y
a.rs:5:1: replace x with y
";
        let misses = parse_missed(report);
        assert_eq!(misses.len(), 2);
        assert_eq!(misses[0].file, "a.rs");
        assert_eq!(misses[1].file, "z.rs");
    }

    #[test]
    fn package_derivation_handles_flat_and_nested_crates() {
        assert_eq!(
            package_for("crates/mvm-protocol/src/policy/network_policy.rs").as_deref(),
            Some("mvm-protocol")
        );
        assert_eq!(
            package_for("crates/deps/libkrun-sys/src/sys.rs").as_deref(),
            Some("libkrun-sys")
        );
        assert_eq!(package_for("src/lib.rs"), None);
        assert_eq!(package_for("xtask/src/main.rs"), None);
    }

    #[test]
    fn integration_tests_are_not_part_of_the_surface() {
        assert!(is_integration_test("crates/mvm-cli/tests/cli.rs"));
        assert!(!is_integration_test("crates/mvm-cli/src/lib.rs"));
    }

    fn miss(file: &str, mutant: &str) -> Miss {
        Miss {
            file: file.into(),
            mutant: mutant.into(),
        }
    }

    fn accepted(file: &str, mutant: &str) -> AcceptedMiss {
        AcceptedMiss {
            file: file.into(),
            mutant: mutant.into(),
            reason: "known".into(),
        }
    }

    #[test]
    fn ratchet_flags_a_new_miss() {
        let v = ratchet(&[], &[miss("a.rs", "replace x")]);
        assert_eq!(v.new_misses, vec![miss("a.rs", "replace x")]);
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn ratchet_accepts_a_baselined_miss() {
        let v = ratchet(
            &[accepted("a.rs", "replace x")],
            &[miss("a.rs", "replace x")],
        );
        assert!(v.new_misses.is_empty());
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn ratchet_reports_a_baselined_miss_that_is_now_caught() {
        let v = ratchet(&[accepted("a.rs", "replace x")], &[]);
        assert!(v.new_misses.is_empty());
        assert_eq!(v.now_caught.len(), 1);
    }

    #[test]
    fn ratchet_distinguishes_same_mutant_in_different_files() {
        let v = ratchet(
            &[accepted("a.rs", "replace x")],
            &[miss("b.rs", "replace x")],
        );
        assert_eq!(v.new_misses, vec![miss("b.rs", "replace x")]);
    }

    fn surface(path: &str, claims: Vec<u32>) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims,
        }
    }

    #[test]
    fn surface_diff_is_empty_when_pinned() {
        let s = vec![surface("crates/a/src/l.rs", vec![1])];
        assert!(diff_surface(&s, &s).is_empty());
    }

    #[test]
    fn surface_diff_reports_a_lost_file_as_lost_coverage() {
        let old = vec![surface("crates/a/src/l.rs", vec![10])];
        let errs = diff_surface(&old, &[]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("surface lost"));
        assert!(errs[0].contains("dropped out of mutation coverage"));
    }

    #[test]
    fn surface_diff_reports_a_gained_file() {
        let new = vec![surface("crates/a/src/l.rs", vec![1])];
        let errs = diff_surface(&[], &new);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("surface gained"));
    }

    #[test]
    fn surface_diff_reports_a_claim_set_change() {
        let old = vec![surface("crates/a/src/l.rs", vec![1])];
        let new = vec![surface("crates/a/src/l.rs", vec![1, 2])];
        let errs = diff_surface(&old, &new);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("changed claims"));
    }

    #[test]
    fn accepted_misses_must_state_a_reason() {
        let bad = vec![AcceptedMiss {
            file: "a.rs".into(),
            mutant: "replace x".into(),
            reason: "  ".into(),
        }];
        let errs = check_accepted_reasons(&bad);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("no reason"));
        assert!(check_accepted_reasons(&[accepted("a.rs", "replace x")]).is_empty());
    }

    #[test]
    fn seeded_misses_carry_a_reason_so_the_gate_accepts_them() {
        let seeded = seed_accepted(&[miss("a.rs", "replace x")]);
        assert!(check_accepted_reasons(&seeded).is_empty());
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");
        let baseline = Baseline {
            surface: vec![surface("crates/a/src/l.rs", vec![1, 2])],
            uncovered_claims: vec![uncovered(7)],
            accepted_misses: vec![accepted("crates/a/src/l.rs", "replace x")],
        };
        write_baseline(&path, &baseline).unwrap();
        let back = read_baseline(&path).unwrap();
        assert_eq!(back.surface, baseline.surface);
        assert_eq!(back.uncovered_claims, baseline.uncovered_claims);
        assert_eq!(back.accepted_misses, baseline.accepted_misses);
    }

    #[test]
    fn missing_baseline_names_the_command_that_seeds_it() {
        let err = read_baseline(Path::new("/nonexistent/baseline.json")).unwrap_err();
        assert!(format!("{err}").contains("--write-baseline"));
    }

    /// A temp workspace carrying just a claims ledger with `rows`.
    fn ledger_tree(rows: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let adr = tmp.path().join("specs").join("adrs");
        std::fs::create_dir_all(&adr).unwrap();
        std::fs::write(
            adr.join("001-microvm-security-posture.md"),
            format!(
                "<!-- claims-catalog:begin -->\n\
                 | # | Claim | Witnesses | Authority | Status |\n\
                 |---|-------|-----------|-----------|--------|\n\
                 {rows}<!-- claims-catalog:end -->\n"
            ),
        )
        .unwrap();
        tmp
    }

    #[test]
    fn surface_resolves_witnesses_to_their_declaring_file() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it, ci:some-lane | auth | Shipped |
| 2 | two | fn:elsewhere | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(src.join("other.rs"), "fn elsewhere() {}\n").unwrap();
        // An integration test naming the same witness must not widen
        // the surface: cargo-mutants never mutates a test target.
        let itest = tmp.path().join("crates").join("demo").join("tests");
        std::fs::create_dir_all(&itest).unwrap();
        std::fs::write(itest.join("it.rs"), "fn enforces_it() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        let paths: Vec<&str> = surface.files.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(
            paths,
            ["crates/demo/src/lib.rs", "crates/demo/src/other.rs"]
        );
        assert_eq!(surface.files[0].claims, vec![1]);
        assert_eq!(surface.files[0].package, "demo");
        assert_eq!(surface.files[1].claims, vec![2]);
        assert!(surface.uncovered.is_empty());
    }

    /// A claim witnessed only by a CI lane has nothing to mutate. That is
    /// legitimate, but it must be reported rather than silently absent.
    #[test]
    fn a_ci_only_claim_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | ci:some-lane | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn enforces_it() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.files.len(), 1);
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_NO_FN_WITNESS);
    }

    /// A claim whose only `fn:` witnesses are integration tests gets no
    /// mutation surface, because cargo-mutants does not mutate test
    /// targets. Distinguished from the CI-only case so the report says
    /// which fix applies.
    #[test]
    fn an_integration_test_only_claim_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | fn:only_in_a_test | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo");
        std::fs::create_dir_all(demo.join("src")).unwrap();
        std::fs::create_dir_all(demo.join("tests")).unwrap();
        std::fs::write(demo.join("src").join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(demo.join("tests").join("it.rs"), "fn only_in_a_test() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_ONLY_INTEGRATION_TESTS);
    }

    fn uncovered(number: u32) -> UncoveredClaim {
        UncoveredClaim {
            number,
            why: WHY_NO_FN_WITNESS.to_string(),
        }
    }

    #[test]
    fn uncovered_diff_fails_when_a_claim_loses_its_surface() {
        let errs = diff_uncovered(&[], &[uncovered(10)]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("claim 10 lost its mutation surface"));
    }

    #[test]
    fn uncovered_diff_asks_for_a_repin_when_a_claim_gains_a_surface() {
        let errs = diff_uncovered(&[uncovered(10)], &[]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("gained a mutation surface"));
    }

    #[test]
    fn uncovered_diff_is_empty_when_pinned() {
        let pinned = [uncovered(4), uncovered(5)];
        assert!(diff_uncovered(&pinned, &pinned).is_empty());
    }

    #[test]
    fn one_file_serving_two_claims_records_both() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:alpha | auth | Shipped |
| 2 | two | fn:beta | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn alpha() {}\nfn beta() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.files.len(), 1);
        assert_eq!(surface.files[0].claims, vec![1, 2]);
    }

    #[test]
    fn sandbox_moves_home_and_mvm_home_off_the_real_roots() {
        let sb = Sandbox::new().unwrap();
        let mut cmd = std::process::Command::new("true");
        sb.apply(&mut cmd);
        let env: std::collections::BTreeMap<_, _> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();

        assert_eq!(env["HOME"], sb.home.to_str().unwrap());
        assert_eq!(env["MVM_HOME"], sb.mvm_home.to_str().unwrap());
        // The point of the sandbox: neither root may be the caller's.
        if let Some(real) = std::env::var_os("HOME") {
            let real = PathBuf::from(real);
            assert_ne!(sb.home, real);
            assert_ne!(sb.mvm_home, real.join(".mvm"));
        }
    }

    #[test]
    fn sandbox_keeps_cargo_and_rustup_on_the_real_roots() {
        // Moving HOME without pinning these sends cargo hunting for a
        // registry and a toolchain inside the sandbox, re-downloading both.
        let sb = Sandbox::new().unwrap();
        let mut cmd = std::process::Command::new("true");
        sb.apply(&mut cmd);
        let env: std::collections::BTreeMap<_, _> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();

        for var in ["CARGO_HOME", "RUSTUP_HOME"] {
            let v = PathBuf::from(&env[var]);
            assert!(
                !v.starts_with(&sb.root),
                "{var} must not resolve inside the sandbox, got {}",
                v.display()
            );
        }
    }

    #[test]
    fn sandbox_state_does_not_outlive_the_run() {
        let path = {
            let sb = Sandbox::new().unwrap();
            std::fs::write(sb.mvm_home.join("audit.jsonl"), b"x").unwrap();
            sb.root.clone()
        };
        assert!(!path.exists(), "sandbox must be removed on drop");
    }
}
