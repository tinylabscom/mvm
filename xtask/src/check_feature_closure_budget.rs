//! `xtask check-feature-closure-budget`
//!
//! Sibling ratchet to `check-closure-budget`. That one bounds what ships in a
//! **default** `mvmctl`; this one bounds what **any feature** can pull in
//! across the whole workspace.
//!
//! The gap between them is where an off-by-default feature hides. `wasm-backend`
//! is the standing example: it is not in the default binary, so the closure
//! budget never sees its ~62-crate `wasmtime`/`cranelift` family — but those
//! crates are resolved, compiled by `--all-features` CI lanes, and scanned by
//! `cargo deny` and `cargo audit`. Without this gate, a feature could grow an
//! arbitrarily large tree and nothing would notice.
//!
//! ## Why not just count `Cargo.lock`
//!
//! Because it does not respond to change. Cargo retains entries for packages no
//! longer reachable from any target, feature, or dev-dependency: measured on
//! this workspace, the lockfile holds 672 packages while only 552 are reachable
//! even with every feature and all dev-dependencies enabled. Removing a real
//! dependency can leave the lockfile count untouched — which was verified here
//! by dropping one and re-resolving. A ratchet on that number would give
//! false comfort in both directions, so this gate measures the resolved graph
//! instead.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Same pinned target as the default-closure gate, for the same reason: the
/// graph is platform-sensitive and a gate that answers differently per
/// contributor host is not a gate.
const BUDGET_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Max distinct crates reachable from any workspace member with **every**
/// feature enabled, excluding dev-dependencies.
///
/// 468: measured 2026-08-10, after `reqwest` was retired. The number is
/// substantially larger than the 242 default closure, and most of the
/// difference is the `wasm-backend` feature's `wasmtime`/`cranelift` family —
/// which is the point of measuring it separately rather than folding it in.
/// Lower it freely as deps drop; raising it must be justified in the change
/// that does.
///
/// 469 (was 476): deleting the superseded L3 stack and its unused direct
/// dependencies removes eight crates, while the first-party `mvm-mcp` crate
/// adds one. Its
/// only dependencies are workspace crates already in this closure
/// (`mvm-client`, `chrono`, `serde`, `serde_json`, `thiserror`, `tokio`), so it
/// pulls in no third-party graph. That is the distinction this budget exists to
/// police: it ratchets against *dependency* growth, and a new crate of ours that
/// vendors nothing is not that.
///
/// 470 (was 469): the first-party `mvm-capture` workspace crate. Its third-party
/// dependencies were already present; the single new closure node is the crate
/// itself, compiled by the all-features workspace lanes.
///
/// 471 (was 470): `async-trait`'s nightly-Clippy compatibility release moves
/// its compile-time parser to `syn` 3, the same measured +1 as the default tree.
///
/// 483 (was 471): the opt-in `tpm2` attestation provider requires the
/// `tss-esapi` TPM command stack; the default `mvmctl` closure is unchanged.
///
/// 484 (was 483): the first-party `mvm-host-services` workspace crate, split
/// out of `mvm-sdk` so the in-guest cdylib stops being compiled from a crate
/// carrying the decorator parser. It vendors nothing — its dependencies were
/// already present — so the single new closure node is the crate itself.
const FEATURE_CLOSURE_BUDGET: usize = 484;

/// The two gates measure nested sets — everything in the default closure is
/// reachable with all features on — so a feature budget at or below the default
/// one would mean one of them is measuring the wrong thing. Checked at compile
/// time rather than in a test, because both values are constants and a ratchet
/// edit that inverts them should not build.
const _: () = assert!(
    FEATURE_CLOSURE_BUDGET > crate::check_closure_budget::CLOSURE_BUDGET,
    "the all-features closure budget must exceed the default-closure budget"
);

pub fn run(workspace: &Path) -> Result<()> {
    let count = feature_closure_crate_count(workspace)?;
    if count > FEATURE_CLOSURE_BUDGET {
        bail!(
            "check-feature-closure-budget: the workspace's all-features {BUDGET_TARGET} closure \
             is {count} crates, over the budget of {FEATURE_CLOSURE_BUDGET} — an optional \
             feature grew its dependency tree. These crates do not ship in a default mvmctl, \
             but they are compiled by --all-features lanes and scanned by cargo-deny and \
             cargo-audit. Drop the dependency, or, if it is genuinely required, bump \
             FEATURE_CLOSURE_BUDGET in xtask/src/check_feature_closure_budget.rs with a \
             one-line justification in the PR."
        );
    }
    if count < FEATURE_CLOSURE_BUDGET {
        eprintln!(
            "check-feature-closure-budget: {count} crates (budget {FEATURE_CLOSURE_BUDGET}); \
             deps dropped — ratchet FEATURE_CLOSURE_BUDGET down to {count}."
        );
    } else {
        eprintln!(
            "check-feature-closure-budget: {count} crates (at budget {FEATURE_CLOSURE_BUDGET})"
        );
    }
    Ok(())
}

fn feature_closure_crate_count(workspace: &Path) -> Result<usize> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "--workspace",
            "-e",
            "no-dev",
            "--all-features",
            "--prefix",
            "none",
            "--locked",
            "--target",
            BUDGET_TARGET,
        ])
        .output()
        .context("running `cargo tree --workspace -e no-dev --all-features --target ...`")?;
    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(unique_crate_count(&String::from_utf8_lossy(&output.stdout)))
}

/// Count distinct `(name, version)` pairs in `cargo tree --prefix none` output.
/// Two majors of one crate count as two — they are two compilations.
fn unique_crate_count(tree: &str) -> usize {
    tree.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let version = it.next().unwrap_or("");
            Some((name.to_string(), version.to_string()))
        })
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::unique_crate_count;

    #[test]
    fn counts_distinct_name_version_pairs() {
        let tree = "mvmctl v0.18.0\nserde v1.0.0\nanyhow v1.0.99\nserde v1.0.0\n";
        assert_eq!(unique_crate_count(tree), 3);
    }

    #[test]
    fn two_majors_count_as_two() {
        assert_eq!(unique_crate_count("bitflags v1.3.2\nbitflags v2.6.0\n"), 2);
    }

    #[test]
    fn repeated_subtree_marker_is_ignored() {
        // `cargo tree` marks a repeated subtree with a trailing `(*)`.
        assert_eq!(unique_crate_count("serde v1.0.0\nserde v1.0.0 (*)\n"), 1);
    }

    #[test]
    fn blank_lines_are_skipped() {
        assert_eq!(unique_crate_count("mvmctl v0.18.0\n\nserde v1.0.0\n\n"), 2);
    }
}
