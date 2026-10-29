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
//! firecracker), so the gate pins explicit targets for a deterministic count
//! regardless of the host running it — `cargo tree --target` resolves without
//! building.
//!
//! **Both** shipped targets are budgeted. Measuring only Linux left the macOS
//! closure unobserved, and that is not a hypothetical gap: `mvm-hostd`
//! declared `hickory-proto` unconditionally while every consumer in
//! `supervisor/raw_egress.rs` was `cfg(target_os = "linux")`, so a macOS
//! `mvmctl` linked it — plus `rand` 0.10, `chacha20` and `data-encoding` —
//! with no consumer at all. A Linux-only gate cannot see that class of defect,
//! and macOS is the primary contributor and HVF-workload platform.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// One budgeted target: the triple `cargo tree` resolves against, and the max
/// distinct crates allowed in `mvmctl`'s default no-dev closure there.
struct ClosureBudget {
    target: &'static str,
    max: usize,
}

/// Both shipped targets. Lower a budget freely as deps drop; raising one must
/// be justified in the change that does.
const BUDGETS: &[ClosureBudget] = &[
    ClosureBudget {
        target: "x86_64-unknown-linux-gnu",
        max: CLOSURE_BUDGET,
    },
    ClosureBudget {
        target: "aarch64-apple-darwin",
        max: MACOS_CLOSURE_BUDGET,
    },
];

/// macOS omits the Linux-only confinement and networking dependencies.
const MACOS_CLOSURE_BUDGET: usize = 350;

/// Maximum distinct packages in the default Linux closure.
pub(crate) const CLOSURE_BUDGET: usize = 353;

pub fn run(workspace: &Path) -> Result<()> {
    for budget in BUDGETS {
        check_one(workspace, budget)?;
    }
    Ok(())
}

fn check_one(workspace: &Path, budget: &ClosureBudget) -> Result<()> {
    let ClosureBudget { target, max } = *budget;
    let count = default_closure_crate_count(workspace, target)?;
    if count > max {
        bail!(
            "check-closure-budget: mvmctl's default {target} closure is {count} crates, \
             over the budget of {max} — a new dependency entered the default binary. \
             Drop it, gate it behind an off-by-default feature (or a \
             `[target.'cfg(...)'.dependencies]` table if it is platform-specific), or, if it \
             is genuinely required, bump the budget in xtask/src/check_closure_budget.rs with \
             a one-line justification in the PR."
        );
    }
    if count < max {
        eprintln!(
            "check-closure-budget: {target} {count} crates (budget {max}); deps dropped — \
             ratchet the budget down to {count}."
        );
    } else {
        eprintln!("check-closure-budget: {target} {count} crates (at budget {max})");
    }
    Ok(())
}

fn default_closure_crate_count(workspace: &Path, target: &str) -> Result<usize> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", "mvmctl", "-e", "no-dev", "--prefix", "none", "--locked", "--target",
            target,
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
