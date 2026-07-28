//! `xtask check-closure-budget`
//!
//! Assert the **default** `mvmctl` binary closure stays within a committed
//! crate budget (a ratchet). Dependency weight is a first-class DX/security
//! goal: every crate in the default no-dev closure is code that ships in the
//! binary and is a supply-chain + attack-surface unit. This gate makes a *new*
//! default dependency a deliberate, reviewed choice rather than a silent
//! accretion.
//!
//! The closure is platform-sensitive (macOS pulls libkrun/objc2; Linux pulls
//! firecracker/passt), so the gate pins the primary release/CI target
//! (`x86_64-unknown-linux-gnu`) for a deterministic count regardless of the
//! host running it — `cargo tree --target` resolves without building.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Deployment/CI target the budget is measured against (deterministic across
/// hosts).
const BUDGET_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Max distinct crates allowed in `mvmctl`'s default no-dev closure on
/// [`BUDGET_TARGET`]. Baseline measured 2026-06-17 against the audited default
/// closure. The Linux KVM backend adds one audited ioctl-wrapper crate to the
/// default Linux release path. Lower it freely as deps drop; raising it must be
/// justified in the change that does.
///
/// 271 (was 267): remeasured 2026-07-09 after the production-readiness
/// closeout branch; the vsock-only builder/runtime path now ships a slightly
/// larger audited default closure. Lower it freely as deps drop; raising it
/// must be justified in the change that does.
///
/// 263 (was 270): deleting the obsolete L3 egress stack removed seven crates
/// from the default closure.
///
/// 266 (was 263): the mandatory authenticated control session uses
/// `x25519-dalek` for ephemeral host↔guest key agreement; the three-crate
/// increase is the measured cost of keeping that security boundary in the
/// default control path.
///
/// 267 (was 266): consolidating the guest's three hand-rolled AF_VSOCK sites
/// onto one `nix::sys::socket` leaf enables nix's `socket` feature, whose lone
/// build-time transitive (`memoffset`, an `offset_of!` helper with no further
/// deps) enters the default Linux closure. That one crate is the cost of
/// deleting the hand-rolled `sockaddr_vm` + raw-`libc`
/// socket/connect/bind/listen/accept boilerplate — nix exposes no AF_VSOCK API
/// without the `socket` feature. Lower it freely as deps drop.
const CLOSURE_BUDGET: usize = 267;

pub fn run(workspace: &Path) -> Result<()> {
    let count = default_closure_crate_count(workspace)?;
    if count > CLOSURE_BUDGET {
        bail!(
            "check-closure-budget: mvmctl's default {BUDGET_TARGET} closure is {count} crates, \
             over the budget of {CLOSURE_BUDGET} — a new dependency entered the default binary. \
             Drop it, gate it behind an off-by-default feature, or, if it is genuinely required, \
             bump CLOSURE_BUDGET in xtask/src/check_closure_budget.rs with a one-line \
             justification in the PR."
        );
    }
    if count < CLOSURE_BUDGET {
        eprintln!(
            "check-closure-budget: {count} crates (budget {CLOSURE_BUDGET}); deps dropped — \
             ratchet CLOSURE_BUDGET down to {count}."
        );
    } else {
        eprintln!("check-closure-budget: {count} crates (at budget {CLOSURE_BUDGET})");
    }
    Ok(())
}

fn default_closure_crate_count(workspace: &Path) -> Result<usize> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "-p",
            "mvmctl",
            "-e",
            "no-dev",
            "--prefix",
            "none",
            "--locked",
            "--target",
            BUDGET_TARGET,
        ])
        .output()
        .context("running `cargo tree -p mvmctl -e no-dev --target ...`")?;
    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(unique_crate_count(&String::from_utf8_lossy(&output.stdout)))
}

/// Count distinct crates in `cargo tree --prefix none` output. Each non-empty
/// line begins with `name vX.Y.Z`; a crate recurs across the tree (and a
/// repeated subtree is marked `(*)`), so dedup by `(name, version)` to count
/// each compiled crate once. Two majors of the same crate count as two — they
/// are two compilations in the binary.
fn unique_crate_count(tree: &str) -> usize {
    let mut crates: Vec<(&str, &str)> = tree
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let version = it.next().unwrap_or("");
            Some((name, version))
        })
        .collect();
    crates.sort_unstable();
    crates.dedup();
    crates.len()
}

#[cfg(test)]
mod tests {
    use super::unique_crate_count;

    #[test]
    fn counts_distinct_name_version_pairs() {
        let tree = "mvmctl v0.16.1\nserde v1.0.0\nanyhow v1.0.99\nserde v1.0.0\n";
        // serde appears twice but is one crate.
        assert_eq!(unique_crate_count(tree), 3);
    }

    #[test]
    fn two_majors_count_as_two() {
        let tree = "mvmctl v0.16.1\nbitflags v1.3.2\nbitflags v2.6.0\n";
        assert_eq!(unique_crate_count(tree), 3);
    }

    #[test]
    fn repeated_subtree_marker_is_ignored() {
        // `cargo tree` marks a repeated subtree with a trailing `(*)`.
        let tree = "mvmctl v0.16.1\nserde v1.0.0\nserde v1.0.0 (*)\n";
        assert_eq!(unique_crate_count(tree), 2);
    }

    #[test]
    fn blank_lines_are_skipped() {
        let tree = "mvmctl v0.16.1\n\nserde v1.0.0\n\n";
        assert_eq!(unique_crate_count(tree), 2);
    }
}
