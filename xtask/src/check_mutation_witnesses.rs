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
use std::path::Path;

/// Where the pinned surface and accepted misses live.
const BASELINE_REL: &str = "xtask/mutation-witness-baseline.json";

/// Per-mutant test timeout, as a multiple of the package's own measured
/// baseline. A mutant that hangs is a caught mutant as far as this gate
/// cares, but without a bound a single infinite loop stalls the lane.
///
/// Relative rather than absolute because the packages on this surface
/// differ by two orders of magnitude in suite time, and one fixed number
/// is wrong for all of them in both directions at once. A flat 300s was
/// **too short** for the packages whose own suite runs longer than that —
/// their baseline timed out, so no mutant was ever tested and the file
/// read as covered — and **five times too long** for a package whose
/// suite takes fourteen seconds, where every hanging mutant burned the
/// full five minutes.
const MUTANT_TIMEOUT_MULTIPLIER: u32 = 5;

/// Floor under the derived timeout, so a package whose suite runs in
/// milliseconds does not get a timeout measured in milliseconds and start
/// reporting scheduler noise as caught mutants.
const MUTANT_MINIMUM_TIMEOUT_SECS: u32 = 60;

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
    /// Optionally restrict which mutants in this file are in claim scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SurfaceScope>,
    /// Cargo features the mutation build must enable for this file.
    ///
    /// cargo-mutants generates mutants by parsing source, and `syn` does
    /// not evaluate `cfg`. A function behind a feature the run does not
    /// enable is therefore mutated, never compiled, and reported as a
    /// survivor that no test could ever kill. Naming the feature here is
    /// the difference between measuring the code and tolerating a mutant
    /// nothing can reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// A narrowing of one file's mutation surface.
///
/// The surface is resolved by mapping each `fn:` witness to its declaring
/// file, which assumes the file is the enforcement code the witness
/// guards. That holds for a cohesive module and fails for a large
/// multi-purpose binary, where the witness guards one function and the
/// other few thousand lines answer to no claim at all.
///
/// Narrowing a claim's surface is a weakening move, and one that reads as
/// routine in a diff — so it is deliberately expensive here. Resolution
/// never produces a scope, so one can only arrive by hand, in the
/// committed baseline, as a reviewable diff. It carries a mandatory `why`,
/// enforced exactly as an accepted miss's reason is, and must name where
/// the excluded code's coverage is tracked, so narrowing records a debt
/// rather than discharging one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SurfaceScope {
    /// Regex handed to `cargo mutants --re`, matched against mutant names.
    pub examine_re: String,
    /// Why the rest of the file is not this claim's surface.
    pub why: String,
    /// Where the excluded code's own coverage gap is tracked.
    pub excluded_tracked_by: String,
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
const WHY_ONLY_INTEGRATION_TESTS: &str = "every fn: witness lives in test-only code (crates/*/tests/, or a #![cfg(test)] \
     module file), which cargo-mutants does not mutate";

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

/// Restrict a `--run` to one cargo package.
///
/// The whole surface takes about six hours end to end, and a
/// GitHub-hosted job is killed at six. Split per package the slowest is
/// well under two and a half, so the lane is one job per package rather
/// than one job that cannot reliably finish.
///
/// Only the mutation step narrows. The surface pin and the uncovered-claim
/// diff still run over the *whole* ledger in every job, so a claim
/// dropping out of coverage fails every shard rather than only the one
/// that happens to own it.
pub fn run(workspace: &Path, mode: Mode, shard: Option<&ShardSpec>) -> Result<()> {
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
        let previous = read_baseline(&baseline_path).ok();
        let accepted_misses = if mode == Mode::RewriteBaseline {
            let scoped = carry_scopes_forward(resolved.clone(), previous.as_ref());
            seed_accepted(&run_mutants_over(
                workspace,
                &for_shard(workspace, &scoped, shard),
            )?)
        } else {
            previous
                .as_ref()
                .map(|b| b.accepted_misses.clone())
                .unwrap_or_default()
        };
        // Re-pinning must never silently widen a scope back out: that
        // would look like routine maintenance and quietly re-admit
        // hundreds of out-of-claim mutants.
        let surface = carry_scopes_forward(resolved, previous.as_ref());
        let baseline = Baseline {
            surface,
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
    errors.extend(check_accepted_files_on_surface(
        &baseline.surface,
        &baseline.accepted_misses,
    ));
    errors.extend(check_scope_reasons(&baseline.surface));
    errors.extend(check_shard_matrix(workspace, &baseline.surface));
    errors.extend(diff_surface(&baseline.surface, &resolved));
    errors.extend(diff_uncovered(&baseline.uncovered_claims, &uncovered));

    for u in &uncovered {
        eprintln!(
            "[note] claim {} has no mutation surface: {}",
            u.number, u.why
        );
    }

    if mode == Mode::Run {
        // The committed surface, not the freshly resolved one: resolution
        // cannot know about scopes, and running the unscoped surface would
        // report every out-of-claim mutant as a new miss.
        let surface = for_shard(workspace, &baseline.surface, shard);
        if surface.is_empty() {
            bail!(
                "check-mutation-witnesses: --package {} matches no surface file. A shard that \
                 measures nothing must fail rather than pass silently.",
                shard.map_or("<none>".to_string(), ToString::to_string)
            );
        }
        if let Some(spec) = shard {
            eprintln!(
                "check-mutation-witnesses: shard {spec} ({} of {} surface files)",
                surface.len(),
                baseline.surface.len()
            );
        }
        let observed = run_mutants_over(workspace, &surface)?;
        // The accepted set narrows with the surface, or every other
        // package's entries would be reported as "now caught" by a shard
        // that never looked at them.
        let paths: BTreeSet<&str> = surface.iter().map(|s| s.path.as_str()).collect();
        let accepted: Vec<AcceptedMiss> = baseline
            .accepted_misses
            .iter()
            .filter(|a| paths.contains(a.file.as_str()))
            .cloned()
            .collect();
        let verdict = ratchet(&accepted, &observed);
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
    // Files that resolved but hold nothing cargo-mutants would mutate, kept
    // apart from the ones that do so the uncovered-claim accounting can tell
    // "no witness resolved here" from "a witness resolved into test code".
    let mut unmutatable: BTreeSet<String> = BTreeSet::new();
    let crates = workspace.join("crates");
    claims_ledger::for_each_file(&crates, Some("rs"), &mut |path, content| {
        for (name, claims) in &wanted {
            if content.contains(&format!("fn {name}(")) {
                let Some(rel) = workspace_relative(workspace, path) else {
                    continue;
                };
                if is_test_only_module(content) {
                    unmutatable.insert(rel.clone());
                }
                hits.entry(rel).or_default().extend(claims.iter().copied());
            }
        }
    })?;

    let mut files: Vec<SurfaceFile> = hits
        .iter()
        .filter(|(path, _)| !is_integration_test(path) && !unmutatable.contains(*path))
        .filter_map(|(path, claims)| {
            Some(SurfaceFile {
                path: path.clone(),
                package: package_for(path)?,
                claims: claims.iter().copied().collect(),
                // Resolution never narrows. A scope can only be added by
                // hand to the committed baseline, which is what makes it
                // a reviewable act rather than a silent one.
                scope: None,
                features: Vec::new(),
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

/// `crates/mvm-contract/src/policy/network_policy.rs` -> `mvm-contract`.
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

/// True for a module file that is compiled only under `cfg(test)`.
///
/// Resolution maps a `fn:` witness to the file declaring it and assumes that
/// file is the enforcement code the witness guards — which holds because this
/// repo keeps `#[cfg(test)] mod tests` inline, beside the implementation. It
/// does not hold when the tests are a *separate* module file: there the
/// resolved file is the tests themselves, and the code they guard is
/// elsewhere.
///
/// The cost of not noticing is not a weak measurement, it is a dead shard.
/// cargo-mutants does not mutate test code, so such a file yields zero mutants
/// and cargo-mutants writes no `outcomes.json` at all — the gate then died
/// reading a missing path under a temp directory, taking the whole package's
/// run with it and reporting nothing about the files that did have mutants.
/// `crates/mvm-cli/src/commands/tests.rs` is the case in point: 165 KB behind
/// `#![cfg(test)]`, reached because `commands/mod.rs` declares `mod tests;`.
///
/// Matched on the inner attribute rather than the filename, because it is the
/// attribute and not the name that decides whether anything compiles outside
/// test.
fn is_test_only_module(content: &str) -> bool {
    content
        .lines()
        .map(str::trim)
        .any(|line| line == "#![cfg(test)]")
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

/// Where the nightly lane declares its per-package shards.
const SECURITY_WORKFLOW_REL: &str = ".github/workflows/security.yml";

/// The lane's shard matrix must name exactly the packages on the surface.
///
/// The shards exist because the whole surface cannot finish inside a
/// GitHub job's six-hour cap. That makes the matrix a second place the
/// surface is written down, and a package that joins the ledger but not
/// the matrix is simply never mutated — while every shard stays green.
/// That is the same silent-loss failure the committed surface pin exists
/// to prevent, one level out, so it is checked the same way.
pub fn check_shard_matrix(workspace: &Path, surface: &[SurfaceFile]) -> Vec<String> {
    let path = workspace.join(SECURITY_WORKFLOW_REL);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return vec![format!(
            "cannot read {SECURITY_WORKFLOW_REL} to verify the mutation shard matrix"
        )];
    };
    let entries = shard_entries(&text);
    if entries.is_empty() {
        return vec![format!(
            "{SECURITY_WORKFLOW_REL} declares no mutation shard matrix; the nightly lane would \
             measure nothing"
        )];
    }
    let mut errors = Vec::new();
    let mut declared: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for raw in &entries {
        match parse_shard_spec(raw) {
            Ok(spec) => {
                let slot = declared.entry(spec.package).or_default();
                if let Some(pair) = spec.shard {
                    slot.push(pair);
                }
            }
            Err(err) => errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares an unparseable mutation shard {raw:?}: {err}"
            )),
        }
    }

    let wanted: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
    for pkg in &wanted {
        if !declared.contains_key(*pkg) {
            errors.push(format!(
                "package {pkg} is on the mutation surface but has no shard in \
                 {SECURITY_WORKFLOW_REL}, so nothing ever mutates it"
            ));
        }
    }
    for pkg in declared.keys() {
        if !wanted.contains(pkg.as_str()) {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares a mutation shard for {pkg}, which owns no \
                 surface file; the shard would fail on an empty surface"
            ));
        }
    }

    // A package cut into shards must be cut completely. A missing or repeated
    // index is the same silent loss the package check above exists to catch —
    // the files that shard owned are simply never mutated, and every remaining
    // shard still goes green.
    for (pkg, shards) in &declared {
        if shards.is_empty() {
            continue;
        }
        let count = entries
            .iter()
            .filter(|raw| parse_shard_spec(raw).is_ok_and(|s| &s.package == pkg))
            .count();
        if count != shards.len() {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} mixes sharded and unsharded entries for {pkg}; the \
                 unsharded one re-runs work a shard already owns"
            ));
            continue;
        }
        let total = shards[0].1;
        if shards.iter().any(|(_, t)| *t != total) {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares shards of {pkg} with disagreeing totals; the \
                 surface would be split more than one way at once"
            ));
            continue;
        }
        let seen: BTreeSet<usize> = shards.iter().map(|(i, _)| *i).collect();
        let expected: BTreeSet<usize> = (1..=total).collect();
        if seen != expected {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares shards {seen:?} of {total} for {pkg}; the \
                 missing ones own surface files nothing would mutate"
            ));
        }
    }
    errors
}

/// The raw `package:` entries under the mutation job's matrix.
///
/// Text-scanned rather than YAML-parsed, matching the sibling gates and
/// the workspace's deliberate dependency floor.
pub fn shard_entries(workflow: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_job = false;
    let mut in_list = false;
    for line in workflow.lines() {
        if line.starts_with("  mutation-witnesses:") {
            in_job = true;
            continue;
        }
        if in_job && line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':') {
            break; // next job at the same indent
        }
        if !in_job {
            continue;
        }
        let t = line.trim();
        if t == "package:" {
            in_list = true;
            continue;
        }
        if in_list {
            if let Some(name) = t.strip_prefix("- ") {
                out.push(name.trim().to_string());
            } else if !t.is_empty() && !t.starts_with('#') {
                // A comment between entries is not the end of the list.
                // Treating it as one truncates the matrix silently, and
                // every package below the comment reads as unsharded.
                in_list = false;
            }
        }
    }
    out
}

/// Which slice of the surface one CI job is responsible for.
///
/// A package is the coarsest useful unit and was the only one for a long
/// time, but `mvm-hostd` alone outgrew the six-hour cap: it owns the most
/// surface files, and a job that dies mid-run reports nothing about the
/// files it never reached. So a package may additionally be cut into
/// numbered shards, spelled `mvm-hostd/1of2` wherever a package name is
/// accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSpec {
    pub package: String,
    /// `(index, total)`, one-based, or `None` for the whole package.
    pub shard: Option<(usize, usize)>,
}

impl std::fmt::Display for ShardSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.shard {
            None => write!(f, "{}", self.package),
            Some((i, n)) => write!(f, "{}/{i}of{n}", self.package),
        }
    }
}

/// Parse `mvm-hostd` or `mvm-hostd/1of2`.
///
/// Rejects rather than rounds: a typo that silently selected the whole
/// package would double the work and hide the shard that vanished, and a
/// zero or out-of-range index would quietly measure nothing.
pub fn parse_shard_spec(raw: &str) -> Result<ShardSpec> {
    let raw = raw.trim();
    let Some((package, shard)) = raw.split_once('/') else {
        return Ok(ShardSpec {
            package: raw.to_string(),
            shard: None,
        });
    };
    let Some((index, total)) = shard.split_once("of") else {
        bail!("malformed shard {raw:?}: expected <package>/<index>of<total>, e.g. mvm-hostd/1of2");
    };
    let index: usize = index
        .parse()
        .with_context(|| format!("malformed shard index in {raw:?}"))?;
    let total: usize = total
        .parse()
        .with_context(|| format!("malformed shard total in {raw:?}"))?;
    if total == 0 || index == 0 || index > total {
        bail!("malformed shard {raw:?}: index must be within 1..={total}");
    }
    Ok(ShardSpec {
        package: package.to_string(),
        shard: Some((index, total)),
    })
}

/// The surface files this shard owns, or all of them when unfiltered.
///
/// Files are ordered by path before packing, so which shard owns a file
/// is a property of the committed surface rather than of resolution
/// order — otherwise a file could migrate between shards without the
/// baseline changing, and a survivor would appear and vanish by shard.
///
/// Shards are packed longest-first by source size rather than sliced by
/// stride. Mutation cost spans more than an order of magnitude across one
/// package's surface, and a cost-blind split parks the expensive files
/// together: `mvm-hostd` shards 2 and 4 were killed at the lane's timeout
/// nightly, each holding two ~150-minute files, while shard 3 finished its
/// three cheapest in 24 minutes. Size is a coarse stand-in for cost, but
/// any cost-aware packing beats a blind one, and it needs nothing recorded
/// or maintained alongside the surface.
pub fn for_shard(
    workspace: &Path,
    surface: &[SurfaceFile],
    spec: Option<&ShardSpec>,
) -> Vec<SurfaceFile> {
    for_shard_by_weight(surface, spec, &|f| source_weight(workspace, f))
}

/// A surface file's stand-in for mutation cost.
///
/// Never zero: a file the workspace cannot stat still has to land
/// somewhere, and equal weights make the packing fall back to plain
/// round-robin rather than piling every file onto the first shard.
fn source_weight(workspace: &Path, file: &SurfaceFile) -> u64 {
    std::fs::metadata(workspace.join(&file.path))
        .map(|m| m.len())
        .unwrap_or(0)
        .max(1)
}

/// [`for_shard`] against a caller-supplied cost, so the packing can be
/// tested without a workspace on disk.
fn for_shard_by_weight(
    surface: &[SurfaceFile],
    spec: Option<&ShardSpec>,
    weight: &dyn Fn(&SurfaceFile) -> u64,
) -> Vec<SurfaceFile> {
    let Some(spec) = spec else {
        return surface.to_vec();
    };
    let mut owned: Vec<SurfaceFile> = surface
        .iter()
        .filter(|s| s.package == spec.package)
        .cloned()
        .collect();
    owned.sort_by(|a, b| a.path.cmp(&b.path));
    let Some((index, total)) = spec.shard else {
        return owned;
    };

    // Heaviest file onto the lightest shard, ties by path then by shard
    // index, so the assignment is a pure function of the surface.
    let mut ordered: Vec<(u64, SurfaceFile)> = owned.into_iter().map(|f| (weight(&f), f)).collect();
    ordered.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.path.cmp(&b.1.path)));

    let mut loads = vec![0u64; total];
    let mut mine = Vec::new();
    for (w, file) in ordered {
        let target = loads
            .iter()
            .enumerate()
            .min_by_key(|(i, load)| (**load, *i))
            .map(|(i, _)| i)
            .expect("a shard total of zero is rejected when the spec is parsed");
        loads[target] += w;
        if target == index - 1 {
            mine.push(file);
        }
    }
    mine.sort_by(|a, b| a.path.cmp(&b.path));
    mine
}

/// Copy each committed file's `scope` onto the freshly resolved surface.
///
/// Resolution cannot derive a scope, so without this every re-pin would
/// drop the narrowings and silently re-admit the code they exclude.
pub fn carry_scopes_forward(
    mut resolved: Vec<SurfaceFile>,
    previous: Option<&Baseline>,
) -> Vec<SurfaceFile> {
    let Some(previous) = previous else {
        return resolved;
    };
    let scopes: BTreeMap<&str, &SurfaceScope> = previous
        .surface
        .iter()
        .filter_map(|s| s.scope.as_ref().map(|sc| (s.path.as_str(), sc)))
        .collect();
    let features: BTreeMap<&str, &Vec<String>> = previous
        .surface
        .iter()
        .filter(|s| !s.features.is_empty())
        .map(|s| (s.path.as_str(), &s.features))
        .collect();
    for file in &mut resolved {
        if let Some(scope) = scopes.get(file.path.as_str()) {
            file.scope = Some((*scope).clone());
        }
        if let Some(f) = features.get(file.path.as_str()) {
            file.features = (*f).clone();
        }
    }
    resolved
}

/// Every narrowed surface must say why, and where the excluded code's
/// coverage is tracked. A scope without either is a claim quietly
/// shrinking to fit its evidence.
pub fn check_scope_reasons(surface: &[SurfaceFile]) -> Vec<String> {
    let mut errors = Vec::new();
    for file in surface {
        let Some(scope) = &file.scope else { continue };
        if scope.examine_re.trim().is_empty() {
            errors.push(format!(
                "surface {} has an empty scope regex — remove the scope rather than                  narrowing to nothing",
                file.path
            ));
        }
        if scope.why.trim().is_empty() {
            errors.push(format!(
                "surface {} is scoped with no stated reason — say why the rest of the                  file is not claim {:?}'s surface",
                file.path, file.claims
            ));
        }
        if scope.excluded_tracked_by.trim().is_empty() {
            errors.push(format!(
                "surface {} is scoped without naming where the excluded code's coverage                  is tracked — narrowing must record the debt, not discharge it",
                file.path
            ));
        }
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

/// Every accepted miss must belong to a file on the pinned mutation surface.
///
/// Without this check, moving enforcement code to another crate leaves the old
/// entries inert: package shards filter accepted misses by their current files,
/// so the moved mutants are reported as new while the stale debt remains hidden.
pub fn check_accepted_files_on_surface(
    surface: &[SurfaceFile],
    accepted: &[AcceptedMiss],
) -> Vec<String> {
    let surface_paths: BTreeSet<&str> = surface.iter().map(|file| file.path.as_str()).collect();
    accepted
        .iter()
        .map(|miss| miss.file.as_str())
        .filter(|file| !surface_paths.contains(file))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|file| {
            format!(
                "accepted misses for {file} are outside the pinned mutation surface — remove them or migrate them to the current enforcement file"
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
    let isolation = MutationIsolation::establish(&out_root)?;

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
        all.extend(run_mutants_for_file(workspace, file, &out_dir, &isolation)?);
    }
    all.sort();
    all.dedup();
    Ok(all)
}

/// The state roots a mutation run is confined to.
///
/// `--run` executes security code with its check removed: plan verification
/// that no longer verifies, the host signer, seccomp construction. It must
/// not reach a real mvm state root — the mutation may be *in* the path or
/// mode logic, so it can mint a key at the wrong path or leave firewall
/// rules behind.
///
/// Applied here, at the one place cargo-mutants is spawned, rather than in
/// each caller's shell. A caller that forgets is the whole failure mode,
/// and there is no reason for the nightly lane, the Justfile recipe and a
/// bare `cargo run -p xtask` to each carry their own copy of it.
struct MutationIsolation {
    home: std::path::PathBuf,
    cargo_home: std::path::PathBuf,
    rustup_home: std::path::PathBuf,
}

impl MutationIsolation {
    fn establish(under: &Path) -> Result<Self> {
        // Resolve the toolchain roots from the *real* home before
        // redirecting: `~` follows `HOME`, so a subprocess whose `HOME`
        // moved would look for cargo and rustup inside the empty temp
        // root and find no toolchain at all.
        let real_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| real_home.as_ref().map(|h| h.join(".cargo")))
            .context("resolving CARGO_HOME: neither CARGO_HOME nor HOME is set")?;
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| real_home.as_ref().map(|h| h.join(".rustup")))
            .context("resolving RUSTUP_HOME: neither RUSTUP_HOME nor HOME is set")?;

        let home = under.join("state-root");
        std::fs::create_dir_all(&home)
            .with_context(|| format!("creating the isolated state root {}", home.display()))?;

        // A reachable keystore under the redirected root means the
        // redirect did not take. Refuse rather than mutate against keys.
        let keys = home.join(".mvm").join("keys");
        if keys.exists() {
            bail!(
                "refusing to mutate against a reachable keystore at {} — the isolated \
                 state root is supposed to be empty",
                keys.display()
            );
        }
        eprintln!(
            "check-mutation-witnesses: mutating under an isolated HOME/MVM_HOME at {}",
            home.display()
        );
        Ok(Self {
            home,
            cargo_home,
            rustup_home,
        })
    }

    fn apply(&self, cmd: &mut std::process::Command) {
        // Both roots move together. `MVM_HOME` alone is not enough:
        // `default_mvm_cache_dir` deliberately reads the home directory to
        // seed from the shared cache, which is the one door `MVM_HOME`
        // does not close.
        cmd.env("MVM_HOME", &self.home)
            .env("HOME", &self.home)
            .env("CARGO_HOME", &self.cargo_home)
            .env("RUSTUP_HOME", &self.rustup_home);
    }
}

fn run_mutants_for_file(
    workspace: &Path,
    file: &SurfaceFile,
    out_dir: &Path,
    isolation: &MutationIsolation,
) -> Result<Vec<Miss>> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(workspace)
        .arg("mutants")
        .args(["-p", &file.package])
        .args(["--file", &file.path])
        .args(["--test-tool", "nextest"])
        .args([
            "--timeout-multiplier",
            &MUTANT_TIMEOUT_MULTIPLIER.to_string(),
        ])
        .args([
            "--minimum-test-timeout",
            &MUTANT_MINIMUM_TIMEOUT_SECS.to_string(),
        ])
        .arg("--output")
        .arg(out_dir);
    if !file.features.is_empty() {
        let joined = file.features.join(",");
        eprintln!("      features {joined}");
        cmd.args(["--features", &joined]);
    }
    if let Some(scope) = &file.scope {
        eprintln!(
            "      scoped to /{}/ — {}",
            scope.examine_re, scope.excluded_tracked_by
        );
        cmd.args(["--re", &scope.examine_re]);
    }
    isolation.apply(&mut cmd);
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
    // Both report files exist and are empty when the baseline failed, so
    // their presence proves nothing. The counts do.
    let outcomes_path = out_dir.join("mutants.out").join("outcomes.json");
    if !outcomes_path.exists() {
        // A partial run: cargo-mutants left the report files but no outcomes.
        // Say which surface file and what it exited with, because the bare
        // read error names only a path under a temp directory and reads as a
        // missing file rather than as a run that did not finish. That cost a
        // maintainer a search for absent tests when the coverage was fine and
        // the harness was not.
        bail!(
            "cargo mutants wrote no outcomes for {} (exit {:?}); {} is missing \
             while the report files are present, so the run did not complete. \
             This is a harness failure, not a witness gap — check whether the \
             surface file has anything mutable in it before looking for \
             missing tests.",
            file.path,
            status.code(),
            outcomes_path.display(),
        );
    }
    let outcomes = std::fs::read_to_string(&outcomes_path)
        .with_context(|| format!("reading {}", outcomes_path.display()))?;
    ensure_mutants_actually_ran(&outcomes, &file.path)?;

    let report = if missed.exists() {
        std::fs::read_to_string(&missed).with_context(|| format!("reading {}", missed.display()))?
    } else {
        String::new()
    };
    Ok(parse_missed(&report))
}

/// Reject a run that never tested a mutant.
///
/// When the unmutated tree does not build or its tests fail,
/// cargo-mutants stops before mutating anything and reports
/// `cargo test failed in an unmutated tree, so no mutants were tested`.
/// It still writes `missed.txt` and `caught.txt` — both **empty** — so the
/// obvious "did it produce a report" guard passes and `parse_missed` on an
/// empty file yields zero misses. A surface file that contributed no
/// coverage then reads exactly like one that is fully covered.
///
/// That is the failure this whole gate exists to prevent, one level up: a
/// green result standing in for evidence that was never collected. So the
/// counts in `outcomes.json` are the signal, not the presence of a file.
///
/// There are two ways to arrive here having tested nothing, and both have
/// been observed on this repo's own claim surface:
///
/// - The baseline fails to build or fails its tests, giving a `Baseline`
///   outcome summarised `Failure`.
/// - The baseline **times out**, giving one summarised `Timeout`. That is
///   what a package whose own suite runs longer than the per-test budget
///   produces, and it is indistinguishable from the above in every way
///   that matters here.
///
/// So the check is that the summary *is* `Success`, rather than that it is
/// one of a list of known failures. A summary this code has not seen
/// before is not evidence that anything ran. `total_mutants` is checked
/// for being **nonzero** for the same reason: cargo-mutants writes the key
/// as `0` on an aborted run, so its mere presence proves nothing.
fn ensure_mutants_actually_ran(outcomes_json: &str, path: &str) -> Result<u64> {
    let v: serde_json::Value = serde_json::from_str(outcomes_json)
        .with_context(|| format!("parsing cargo-mutants outcomes.json for {path}"))?;

    let baseline_verdict = v
        .get("outcomes")
        .and_then(|o| o.as_array())
        .and_then(|entries| {
            entries
                .iter()
                .find(|e| e.get("scenario").and_then(|s| s.as_str()) == Some("Baseline"))
        })
        .and_then(|e| e.get("summary").and_then(|s| s.as_str()));
    if let Some(verdict) = baseline_verdict
        && verdict != "Success"
    {
        bail!(
            "{path}: the unmutated tree did not pass its own tests (baseline \
             {verdict}), so cargo-mutants tested no mutants. This file contributed \
             no coverage — it is not clean, it is unmeasured. Fix its package's \
             suite, or raise the per-test timeout if the suite is merely slow, then \
             re-run."
        );
    }

    let Some(total) = v.get("total_mutants").and_then(|t| t.as_u64()) else {
        bail!(
            "{path}: cargo-mutants wrote no `total_mutants` count, so the run did not \
             complete. Treating this as clean would report coverage that was never \
             measured."
        );
    };
    if total == 0 {
        bail!(
            "{path}: cargo-mutants tested zero mutants. A claim-surface file with \
             nothing to mutate is not covered, it is unmeasured — either the run \
             aborted before mutating anything, or `--file` matched no code."
        );
    }
    Ok(total)
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
crates/mvm-contract/src/policy/network_policy.rs:92:5: replace is_banned_ssh_port -> bool with false
crates/mvm-contract/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with false
crates/mvm-contract/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with true
crates/mvm-contract/src/policy/network_policy.rs:271:9: replace NetworkPolicy::trusted_build_egress -> Self with Default::default()
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
                .all(|m| m.file == "crates/mvm-contract/src/policy/network_policy.rs")
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
            package_for("crates/mvm-contract/src/policy/network_policy.rs").as_deref(),
            Some("mvm-contract")
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

    #[test]
    fn accepted_misses_must_belong_to_the_pinned_surface() {
        let pinned = vec![surface("crates/a/src/live.rs", vec![1])];
        let accepted = vec![
            accepted("crates/a/src/live.rs", "replace live"),
            accepted("crates/a/src/moved.rs", "replace moved one"),
            accepted("crates/a/src/moved.rs", "replace moved two"),
        ];

        let errors = check_accepted_files_on_surface(&pinned, &accepted);

        assert_eq!(
            errors.len(),
            1,
            "one error per stale file keeps output concise"
        );
        assert!(errors[0].contains("crates/a/src/moved.rs"));
        assert!(errors[0].contains("outside the pinned mutation surface"));
    }

    #[test]
    fn accepted_misses_on_the_pinned_surface_are_valid() {
        let pinned = vec![surface("crates/a/src/live.rs", vec![1])];
        let accepted = vec![accepted("crates/a/src/live.rs", "replace live")];

        assert!(check_accepted_files_on_surface(&pinned, &accepted).is_empty());
    }

    fn surface(path: &str, claims: Vec<u32>) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims,
            scope: None,
            features: Vec::new(),
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

    fn scoped(path: &str, examine_re: &str, why: &str, tracked: &str) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims: vec![2],
            features: Vec::new(),
            scope: Some(SurfaceScope {
                examine_re: examine_re.into(),
                why: why.into(),
                excluded_tracked_by: tracked.into(),
            }),
        }
    }

    #[test]
    fn an_unscoped_surface_file_needs_no_justification() {
        assert!(check_scope_reasons(&[surface("crates/a/src/l.rs", vec![1])]).is_empty());
    }

    #[test]
    fn a_scope_must_state_why_and_where_the_rest_is_tracked() {
        let ok = scoped(
            "crates/a/src/l.rs",
            "virtiofs",
            "one witness, big file",
            "#123",
        );
        assert!(check_scope_reasons(&[ok]).is_empty());

        let no_why = scoped("crates/a/src/l.rs", "virtiofs", "   ", "#123");
        let errs = check_scope_reasons(&[no_why]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("no stated reason"), "{}", errs[0]);

        let no_tracking = scoped("crates/a/src/l.rs", "virtiofs", "because", "");
        let errs = check_scope_reasons(&[no_tracking]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("record the debt"), "{}", errs[0]);

        let empty_re = scoped("crates/a/src/l.rs", "", "because", "#123");
        let errs = check_scope_reasons(&[empty_re]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("narrowing to nothing"), "{}", errs[0]);
    }

    /// A re-pin resolves the surface afresh, and resolution never yields a
    /// scope. Without carrying them forward, routine maintenance would
    /// silently widen every narrowed file back out.
    #[test]
    fn repinning_carries_a_scope_forward() {
        let previous = Baseline {
            surface: vec![scoped("crates/a/src/l.rs", "virtiofs", "why", "#123")],
            uncovered_claims: vec![],
            accepted_misses: vec![],
        };
        let resolved = vec![surface("crates/a/src/l.rs", vec![2])];
        assert!(resolved[0].scope.is_none());

        let carried = carry_scopes_forward(resolved, Some(&previous));
        assert_eq!(
            carried[0].scope.as_ref().map(|s| s.examine_re.as_str()),
            Some("virtiofs")
        );
    }

    #[test]
    fn carrying_forward_leaves_unscoped_files_alone() {
        let previous = Baseline {
            surface: vec![scoped("crates/a/src/l.rs", "virtiofs", "why", "#123")],
            uncovered_claims: vec![],
            accepted_misses: vec![],
        };
        let carried = carry_scopes_forward(
            vec![surface("crates/b/src/other.rs", vec![9])],
            Some(&previous),
        );
        assert!(carried[0].scope.is_none());
    }

    const SHARD_WORKFLOW: &str = "\
jobs:
  other-job:
    name: not this one
    strategy:
      matrix:
        package:
          - not-a-real-package
  mutation-witnesses:
    name: Claim witnesses
    strategy:
      fail-fast: false
      matrix:
        package:
          - mvm-cli
          - mvm-hostd
    steps:
      - run: true
  later-job:
    name: after
";

    #[test]
    fn a_comment_between_entries_does_not_truncate_the_matrix() {
        let workflow = "\
jobs:
  mutation-witnesses:
    strategy:
      matrix:
        package:
          - mvm-cli
          # why this one is split
          - mvm-hostd/1of2
          - mvm-hostd/2of2
  later-job:
    name: after
";
        assert_eq!(
            shard_entries(workflow),
            vec![
                "mvm-cli".to_string(),
                "mvm-hostd/1of2".to_string(),
                "mvm-hostd/2of2".to_string(),
            ],
            "a comment must not end the list and silently unshard everything below it"
        );
    }

    #[test]
    fn shard_entries_read_only_the_mutation_jobs_matrix() {
        let got = shard_entries(SHARD_WORKFLOW);
        assert_eq!(
            got,
            vec!["mvm-cli".to_string(), "mvm-hostd".to_string()],
            "a sibling job's matrix must not leak into the mutation shard list"
        );
    }

    #[test]
    fn a_surface_package_with_no_shard_is_reported() {
        let declared: BTreeSet<String> = shard_entries(SHARD_WORKFLOW).into_iter().collect();
        // mvm-core is on the surface but absent from the matrix above.
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-core/src/b.rs", vec![2]),
        ];
        let missing: Vec<&str> = surface
            .iter()
            .map(|s| s.package.as_str())
            .filter(|p| !declared.contains(*p))
            .collect();
        assert_eq!(
            missing,
            vec!["mvm-core"],
            "a package on the surface with no shard must be visible"
        );
    }

    #[test]
    fn a_shard_for_a_package_with_no_surface_file_is_reported() {
        let declared: BTreeSet<String> = shard_entries(SHARD_WORKFLOW).into_iter().collect();
        let surface = [surface("crates/mvm-cli/src/a.rs", vec![1])];
        let wanted: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
        let extra: Vec<&String> = declared
            .iter()
            .filter(|p| !wanted.contains(p.as_str()))
            .collect();
        assert_eq!(
            extra.len(),
            1,
            "a shard whose package owns no surface file must be visible"
        );
    }

    /// Shard a surface at uniform cost. The packing degenerates to
    /// round-robin when every file weighs the same, which is what these
    /// tests pin: membership, disjointness, coverage, order-independence.
    fn even(surface: &[SurfaceFile], spec: Option<&ShardSpec>) -> Vec<SurfaceFile> {
        for_shard_by_weight(surface, spec, &|_| 1)
    }

    #[test]
    fn a_package_shard_selects_only_that_packages_files() {
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-cli/src/b.rs", vec![2]),
            surface("crates/mvm-hostd/src/c.rs", vec![3]),
        ];
        let cli = even(
            &surface,
            Some(&ShardSpec {
                package: "mvm-cli".to_string(),
                shard: None,
            }),
        );
        assert_eq!(cli.len(), 2);
        assert!(cli.iter().all(|s| s.package == "mvm-cli"));

        assert_eq!(
            even(
                &surface,
                Some(&ShardSpec {
                    package: "mvm-hostd".to_string(),
                    shard: None,
                })
            )
            .len(),
            1
        );
        // Unfiltered is the whole surface, so a non-sharded run is
        // unchanged.
        assert_eq!(even(&surface, None).len(), 3);
        // A package with no surface files yields nothing, which the caller
        // turns into a failure rather than a silent pass.
        assert!(
            even(
                &surface,
                Some(&ShardSpec {
                    package: "mvm-sdk".to_string(),
                    shard: None,
                })
            )
            .is_empty()
        );
    }

    /// Every shard together must cover the surface exactly once. A package
    /// dropped from the matrix would otherwise go unmeasured while every
    /// job stayed green.
    #[test]
    fn the_shards_partition_the_surface() {
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-hostd/src/c.rs", vec![3]),
            surface("crates/mvm-core/src/d.rs", vec![4]),
        ];
        let packages: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
        let mut seen: Vec<String> = Vec::new();
        for p in &packages {
            let spec = ShardSpec {
                package: (*p).to_string(),
                shard: None,
            };
            for f in even(&surface, Some(&spec)) {
                seen.push(f.path);
            }
        }
        seen.sort();
        let mut all: Vec<String> = surface.iter().map(|s| s.path.clone()).collect();
        all.sort();
        assert_eq!(seen, all, "the shards must cover every file exactly once");
    }

    #[test]
    fn a_shard_spec_round_trips_and_rejects_nonsense() {
        assert_eq!(
            parse_shard_spec("mvm-hostd").unwrap(),
            ShardSpec {
                package: "mvm-hostd".to_string(),
                shard: None
            }
        );
        let sharded = parse_shard_spec("mvm-hostd/2of3").unwrap();
        assert_eq!(sharded.package, "mvm-hostd");
        assert_eq!(sharded.shard, Some((2, 3)));
        // Display is what the matrix and the log line both print, so it has
        // to be the form the parser accepts back.
        assert_eq!(sharded.to_string(), "mvm-hostd/2of3");
        assert_eq!(parse_shard_spec(&sharded.to_string()).unwrap(), sharded);

        // A shard that names no valid slice must fail rather than quietly
        // widening to the whole package and doubling the run.
        for bad in [
            "mvm-hostd/",
            "mvm-hostd/0of2",
            "mvm-hostd/3of2",
            "mvm-hostd/xofy",
        ] {
            assert!(
                parse_shard_spec(bad).is_err(),
                "{bad} must not parse as a shard"
            );
        }
    }

    /// The whole point of splitting a package: every file it owns is still
    /// mutated exactly once, across the shards rather than within one job.
    #[test]
    fn the_shards_of_one_package_partition_its_files() {
        let surface: Vec<SurfaceFile> = ["e", "a", "d", "b", "c"]
            .iter()
            .map(|n| surface(&format!("crates/mvm-hostd/src/{n}.rs"), vec![8]))
            .collect();

        let one = even(&surface, Some(&parse_shard_spec("mvm-hostd/1of2").unwrap()));
        let two = even(&surface, Some(&parse_shard_spec("mvm-hostd/2of2").unwrap()));

        // Disjoint.
        let a: BTreeSet<&str> = one.iter().map(|f| f.path.as_str()).collect();
        let b: BTreeSet<&str> = two.iter().map(|f| f.path.as_str()).collect();
        assert!(
            a.is_disjoint(&b),
            "no file may be mutated twice: {a:?} overlaps {b:?}"
        );

        // Complete.
        let mut seen: Vec<&str> = a.union(&b).copied().collect();
        seen.sort_unstable();
        let mut all: Vec<&str> = surface.iter().map(|f| f.path.as_str()).collect();
        all.sort_unstable();
        assert_eq!(seen, all, "every file must land in exactly one shard");

        // Balanced to within one file, or the split has not bought anything.
        assert!(one.len().abs_diff(two.len()) <= 1);
    }

    /// The regression this packing exists for.
    ///
    /// These are the measured per-file costs of `mvm-hostd`'s surface from
    /// the nightly of 2026-08-21 (Security run 32448509693), in minutes.
    /// Round-robin over the path-sorted surface put `network/stages.rs` with
    /// `plan_admission.rs` on one shard and `audit_file.rs` with
    /// `network_endpoint_proxy.rs` on another; both ran past the lane's
    /// 330-minute timeout and were killed, nightly, while a third shard
    /// finished its three cheapest files in 24 minutes.
    ///
    /// The assertion is on balance, not on wall-clock minutes. Two of the
    /// costs above are lower bounds — those shards were killed part-way
    /// through a file, so the real number is higher — which makes any
    /// absolute budget compared against them meaningless: round-robin's
    /// worst shard measures 324, and would slip under a literal 330. Against
    /// the ideal even split it is 1.70x, and that ratio is what separates a
    /// cost-blind split from a cost-aware one.
    #[test]
    fn cost_packing_balances_a_surface_that_round_robin_left_lopsided() {
        // (path, measured minutes)
        let measured: [(&str, u64); 11] = [
            ("crates/mvm-hostd/src/supervisor/network/stages.rs", 163),
            ("crates/mvm-hostd/src/plan_admission.rs", 161),
            ("crates/mvm-hostd/src/supervisor/audit_file.rs", 141),
            (
                "crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs",
                132,
            ),
            ("crates/mvm-hostd/src/stream/input_gate.rs", 61),
            ("crates/mvm-hostd/src/broker/registry.rs", 50),
            ("crates/mvm-hostd/src/supervisor/network_endpoint.rs", 22),
            ("crates/mvm-hostd/src/supervisor/wall_clock.rs", 9),
            ("crates/mvm-hostd/src/keyholder/substitution.rs", 9),
            ("crates/mvm-hostd/src/admission_budget.rs", 7),
            ("crates/mvm-hostd/src/supervisor/dns_audit.rs", 6),
        ];
        let cost: BTreeMap<&str, u64> = measured.iter().copied().collect();
        let surface: Vec<SurfaceFile> = measured
            .iter()
            .map(|(path, _)| surface(path, vec![8]))
            .collect();

        let total = 4;
        let sum: u64 = measured.iter().map(|(_, c)| c).sum();
        // Half again the ideal even split. Round-robin lands at 1.70x of it,
        // longest-first at 1.01x, so the bound discriminates while leaving
        // room for the surface to drift.
        let ceiling = sum * 3 / (total as u64 * 2);

        let mut covered: Vec<String> = Vec::new();
        for index in 1..=total {
            let spec = ShardSpec {
                package: "mvm-hostd".to_string(),
                shard: Some((index, total)),
            };
            let files = for_shard_by_weight(&surface, Some(&spec), &|f| cost[f.path.as_str()]);
            let load: u64 = files.iter().map(|f| cost[f.path.as_str()]).sum();
            assert!(
                load <= ceiling,
                "shard {index}of{total} carries {load} minutes against a {ceiling} \
                 ceiling — the split is not cost-aware: {:?}",
                files.iter().map(|f| &f.path).collect::<Vec<_>>()
            );
            covered.extend(files.into_iter().map(|f| f.path));
        }

        // Still a partition: a cheap shard must not come from dropped work.
        covered.sort();
        let mut all: Vec<String> = surface.iter().map(|f| f.path.clone()).collect();
        all.sort();
        assert_eq!(covered, all, "every file must land in exactly one shard");
    }

    /// Which shard owns a file must not depend on the order resolution
    /// happened to emit, or a survivor would move between shards without
    /// the baseline changing.
    #[test]
    fn shard_membership_follows_the_path_not_the_input_order() {
        let names = ["c", "a", "b", "d"];
        let forward: Vec<SurfaceFile> = names
            .iter()
            .map(|n| surface(&format!("crates/mvm-hostd/src/{n}.rs"), vec![8]))
            .collect();
        let mut backward = forward.clone();
        backward.reverse();

        let spec = parse_shard_spec("mvm-hostd/1of2").unwrap();
        let a: Vec<String> = even(&forward, Some(&spec))
            .into_iter()
            .map(|f| f.path)
            .collect();
        let b: Vec<String> = even(&backward, Some(&spec))
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(a, b, "shard membership must be a property of the surface");
    }

    /// A package cut into shards must be cut completely. Dropping `2of2`
    /// leaves its files unmutated while `1of2` still reports success — the
    /// silent loss this gate exists to prevent, one level in.
    #[test]
    fn an_incomplete_shard_set_is_reported() {
        let entries = ["mvm-hostd/1of2".to_string()];
        let mut shards: Vec<(usize, usize)> = Vec::new();
        for raw in &entries {
            if let Some(pair) = parse_shard_spec(raw).unwrap().shard {
                shards.push(pair);
            }
        }
        let total = shards[0].1;
        let seen: BTreeSet<usize> = shards.iter().map(|(i, _)| *i).collect();
        let expected: BTreeSet<usize> = (1..=total).collect();
        assert_ne!(
            seen, expected,
            "a half-declared split must not look complete"
        );
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

    /// A `#![cfg(test)]` module file stays off the surface, and a claim that
    /// has other witnesses keeps its coverage.
    ///
    /// Resolution assumes the file declaring a witness is the enforcement code
    /// the witness guards. A separate tests module breaks that assumption, and
    /// the failure is not a weak measurement but a dead shard: cargo-mutants
    /// mutates no test code, so it writes no `outcomes.json`, and the gate used
    /// to die reading that missing path — losing every other file in the same
    /// package's run along with it.
    #[test]
    fn a_test_only_module_file_is_not_mutation_surface() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it, fn:also_checked_in_the_tests_module | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&demo).unwrap();
        std::fs::write(demo.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(
            demo.join("tests.rs"),
            "#![cfg(test)]\nfn also_checked_in_the_tests_module() {}\n",
        )
        .unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        let paths: Vec<&str> = surface.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["crates/demo/src/lib.rs"],
            "the tests module has nothing cargo-mutants would mutate"
        );
        assert!(
            surface.uncovered.is_empty(),
            "claim 1 still resolves to enforcement code, so it is not uncovered"
        );
    }

    /// A claim witnessed *only* from a tests module has no surface at all, and
    /// says which kind of test-only code it landed in.
    #[test]
    fn a_claim_witnessed_only_from_a_tests_module_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | fn:only_in_the_tests_module | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&demo).unwrap();
        std::fs::write(demo.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(
            demo.join("tests.rs"),
            "#![cfg(test)]\nfn only_in_the_tests_module() {}\n",
        )
        .unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_ONLY_INTEGRATION_TESTS);
    }

    /// Only the inner attribute counts. A file with ordinary `#[cfg(test)] mod
    /// tests` beside its implementation is exactly the shape resolution is
    /// built around, and dropping it would silently delete real surface.
    #[test]
    fn an_inline_test_module_does_not_make_the_file_test_only() {
        assert!(is_test_only_module("#![cfg(test)]\nfn a() {}\n"));
        assert!(is_test_only_module("//! docs\n\n  #![cfg(test)]\n"));
        assert!(!is_test_only_module(
            "fn enforce() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n"
        ));
        assert!(!is_test_only_module("fn enforce() {}\n"));
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
}

#[cfg(test)]
mod baseline_guard_tests {
    use super::*;

    /// Verbatim shape cargo-mutants 27.1 writes when the unmutated tree
    /// fails its own tests: an `outcomes` array carrying only the failed
    /// Baseline scenario, and no counts at all.
    const BASELINE_FAILED: &str = r#"{
  "outcomes": [
    {
      "scenario": "Baseline",
      "summary": "Failure",
      "log_path": "log/baseline.log"
    }
  ]
}"#;

    /// The same file from a completed run, trimmed to its counts.
    const COMPLETED: &str = r#"{
  "outcomes": [],
  "total_mutants": 17,
  "missed": 0,
  "caught": 17,
  "timeout": 0,
  "unviable": 0
}"#;

    /// Verbatim shape observed running this gate's own surface over
    /// `crates/mvm-build/src/app_deps_gate.rs`: three of that package's
    /// tests outran the per-test budget, so the *baseline* timed out.
    /// cargo-mutants found 33 mutants, tested none of them, and still
    /// wrote every count as zero.
    const BASELINE_TIMED_OUT: &str = r#"{
  "outcomes": [
    {
      "scenario": "Baseline",
      "summary": "Timeout",
      "log_path": "log/baseline.log"
    }
  ],
  "total_mutants": 0,
  "missed": 0,
  "caught": 0,
  "timeout": 0,
  "unviable": 0
}"#;

    #[test]
    fn a_failed_baseline_is_an_error_not_a_clean_file() {
        let err = ensure_mutants_actually_ran(BASELINE_FAILED, "crates/x/src/y.rs")
            .expect_err("a run that tested no mutants must not read as clean");
        let msg = err.to_string();
        assert!(msg.contains("crates/x/src/y.rs"), "{msg}");
        assert!(msg.contains("unmeasured"), "{msg}");
    }

    #[test]
    fn a_completed_run_reports_its_mutant_count() {
        assert_eq!(
            ensure_mutants_actually_ran(COMPLETED, "crates/x/src/y.rs").unwrap(),
            17
        );
    }

    /// A run that stopped before writing counts, without a Baseline entry
    /// to explain why, is still unmeasured.
    #[test]
    fn missing_counts_are_an_error() {
        let err = ensure_mutants_actually_ran(r#"{"outcomes": []}"#, "crates/x/src/y.rs")
            .expect_err("no total_mutants means the run did not complete");
        assert!(err.to_string().contains("total_mutants"), "{err}");
    }

    #[test]
    fn unparseable_outcomes_are_an_error() {
        assert!(ensure_mutants_actually_ran("not json", "crates/x/src/y.rs").is_err());
    }

    /// Zero surviving mutants out of a real total is the genuinely clean
    /// case and must stay distinguishable from the two above.
    #[test]
    fn a_clean_file_is_still_accepted() {
        assert_eq!(ensure_mutants_actually_ran(COMPLETED, "p").unwrap(), 17);
        assert!(parse_missed("").is_empty());
    }

    /// A timed-out baseline tested nothing, exactly like a failed one. It
    /// was not caught while the check enumerated known failure summaries,
    /// which is why the check now asks for `Success` instead.
    #[test]
    fn a_timed_out_baseline_is_an_error_not_a_clean_file() {
        let err = ensure_mutants_actually_ran(BASELINE_TIMED_OUT, "crates/x/src/y.rs")
            .expect_err("a baseline that timed out tested no mutants");
        let msg = err.to_string();
        assert!(msg.contains("Timeout"), "{msg}");
        assert!(msg.contains("unmeasured"), "{msg}");
    }

    /// Any baseline verdict other than success is unmeasured, including
    /// one this code has never seen. Enumerating known failures would let
    /// a new cargo-mutants summary read as coverage.
    #[test]
    fn an_unrecognised_baseline_verdict_is_an_error() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "SomeFutureVerdict"}],
  "total_mutants": 0
}"#;
        let err = ensure_mutants_actually_ran(json, "crates/x/src/y.rs")
            .expect_err("an unknown baseline verdict is not evidence anything ran");
        assert!(err.to_string().contains("SomeFutureVerdict"), "{err}");
    }

    /// A run that completed its baseline but mutated nothing is also
    /// unmeasured: a claim-surface file with no mutants tells you nothing
    /// about its witness.
    #[test]
    fn zero_mutants_tested_is_an_error_even_with_a_passing_baseline() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Success"}],
  "total_mutants": 0,
  "missed": 0,
  "caught": 0
}"#;
        let err = ensure_mutants_actually_ran(json, "crates/x/src/y.rs")
            .expect_err("zero mutants is not coverage");
        assert!(err.to_string().contains("zero mutants"), "{err}");
    }

    /// A successful baseline alongside a real total is still accepted —
    /// the new checks must not reject the shape a healthy run writes.
    #[test]
    fn a_successful_baseline_with_mutants_is_accepted() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Success"}],
  "total_mutants": 33,
  "missed": 2,
  "caught": 31
}"#;
        assert_eq!(
            ensure_mutants_actually_ran(json, "crates/x/src/y.rs").unwrap(),
            33
        );
    }
}
