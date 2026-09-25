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
//! - `--verify-outcomes <dir>` — judge the cargo-mutants output a run left
//!   in `<dir>` without mutating anything. Every surface file the shard
//!   owns must have a finished result there, so a run that stopped part-way
//!   fails on the files it never reached instead of reading as clean.
//!
//! The gate's implementation is split into cohesive submodules:
//! [`types`] (the data model and pinned constants), [`surface`] (resolving
//! the surface from the ledger and diffing it against the pin), [`shard`]
//! (per-package shard selection and the CI matrix cross-check), [`ratchet`]
//! (comparing survivors against the accepted set), [`runner`] (invoking
//! cargo-mutants and reading its output), [`mutator_pin`] (the mutator
//! version pin) and [`baseline_io`] (the committed baseline file).

mod baseline_io;
mod mutator_pin;
mod ratchet;
mod runner;
mod shard;
mod surface;
mod types;

use baseline_io::*;
pub use mutator_pin::*;
pub use ratchet::*;
pub use runner::*;
pub use shard::*;
pub use surface::*;
pub use types::*;

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

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
    let pinned = pinned_mutator_version(workspace)?;

    if matches!(mode, Mode::RepinSurface | Mode::RewriteBaseline) {
        // Re-pinning keeps the stated reasons; a full rewrite discards
        // them on purpose, having just re-observed the ground truth.
        let previous = read_baseline(&baseline_path).ok();
        let accepted_misses = if mode == Mode::RewriteBaseline {
            let scoped = carry_scopes_forward(resolved.clone(), previous.as_ref());
            let surface = for_shard(workspace, &scoped, shard);
            let out_root = run_mutants_over(workspace, &surface, &pinned)?;
            seed_accepted(&observed_misses(&collect_evidence(
                &out_root, &surface, &pinned,
            )))
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
    errors.extend(check_mutator_installs_pinned(workspace, &pinned)?);

    for u in &uncovered {
        eprintln!(
            "[note] claim {} has no mutation surface: {}",
            u.number, u.why
        );
    }

    if matches!(mode, Mode::Run | Mode::VerifyOutcomes(_)) {
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
        // One judgement for both modes: a finished run is read back from
        // the directory it just wrote, exactly as a stopped one is read from
        // what it left behind.
        let out_root = match &mode {
            Mode::VerifyOutcomes(dir) => dir.clone(),
            _ => run_mutants_over(workspace, &surface, &pinned)?,
        };
        let verdict = judge_shard(
            &baseline.accepted_misses,
            &collect_evidence(&out_root, &surface, &pinned),
        );
        for u in &verdict.unmeasured {
            errors.push(format!(
                "unmeasured surface file {}: {} — its witnesses were not mutation-tested \
                 by this run, which is not the same as clean",
                u.file, u.reason
            ));
        }
        if !verdict.unmeasured.is_empty() {
            errors.push(format!(
                "{} of {} surface files in this shard have no finished result under \
                 cargo-mutants {pinned}; any survivors reported cover only the files that were \
                 measured",
                verdict.unmeasured.len(),
                surface.len()
            ));
        }
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
