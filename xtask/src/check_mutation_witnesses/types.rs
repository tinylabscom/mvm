//! Data types and pinned constants shared across the mutation-witness gate.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Where the pinned surface and accepted misses live.
pub(crate) const BASELINE_REL: &str = "xtask/mutation-witness-baseline.json";

/// The key under `[workspace.metadata.mvm.toolchain]` holding the exact
/// cargo-mutants version the baseline was recorded with.
pub(crate) const MUTATOR_PIN_KEY: &str = "cargo-mutants";

/// Where CI workflows live, each scanned for a cargo-mutants install.
pub(crate) const WORKFLOWS_REL: &str = ".github/workflows";

/// Where the nightly lane declares its per-package shards.
pub(crate) const SECURITY_WORKFLOW_REL: &str = ".github/workflows/security.yml";

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
pub(crate) const MUTANT_TIMEOUT_MULTIPLIER: u32 = 5;

/// Floor under the derived timeout, so a package whose suite runs in
/// milliseconds does not get a timeout measured in milliseconds and start
/// reporting scheduler noise as caught mutants.
pub(crate) const MUTANT_MINIMUM_TIMEOUT_SECS: u32 = 60;

/// Why a claim's `fn:` witnesses yield nothing mutable.
pub(crate) const WHY_NO_FN_WITNESS: &str =
    "no fn: witness — witnessed by CI lanes only, nothing to mutate";
pub(crate) const WHY_ONLY_INTEGRATION_TESTS: &str = "every fn: witness lives in test-only code (crates/*/tests/, or a #![cfg(test)] \
     module file), which cargo-mutants does not mutate";

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Judge the cargo-mutants output a `--run` left in this directory,
    /// without mutating anything. What a shard stopped by its timeout still
    /// has: a verdict on the files it reached and the names of those it did
    /// not.
    VerifyOutcomes(PathBuf),
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
    /// Description with `line:col` stripped — see [`super::ratchet::mutant_identity`].
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Survived, and not in the baseline. These fail the gate.
    pub new_misses: Vec<Miss>,
    /// In the baseline, but caught now. Reported so the baseline shrinks.
    pub now_caught: Vec<AcceptedMiss>,
}

/// What one surface file's cargo-mutants output directory proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvidence {
    /// The run for this file finished under the pinned mutator and tested
    /// at least one mutant; these are its survivors.
    Measured(Vec<Miss>),
    /// No finished result. `misses` holds any survivors the run reported
    /// before it stopped: they are real, but they are not the whole file.
    Unmeasured { reason: String, misses: Vec<Miss> },
}

/// A surface file with no finished mutation result, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmeasuredFile {
    pub file: String,
    pub reason: String,
}

/// The ratchet over one shard, plus the files it has no result for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ShardVerdict {
    pub new_misses: Vec<Miss>,
    pub now_caught: Vec<AcceptedMiss>,
    pub unmeasured: Vec<UnmeasuredFile>,
}
