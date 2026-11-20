//! `xtask check-closure-budget`
//!
//! Bound default CLI, release CLI, and guest normal/build dependency graphs.
//! Each package/version is a build trust input, not necessarily linked code.
//! A new dependency must be a deliberate, reviewed choice.
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

/// One package, feature set, and target's maximum distinct dependency count.
struct ClosureBudget {
    package: &'static str,
    target: &'static str,
    features: &'static str,
    max: usize,
}

const RELEASE_FEATURES: &str =
    "host,user,release-artifact-bootstrap,release-channel,embed-host-bins";

/// Lower a budget freely as deps drop; raising one must
/// be justified in the change that does.
const BUDGETS: &[ClosureBudget] = &[
    ClosureBudget {
        package: "mvmctl",
        target: "x86_64-unknown-linux-gnu",
        features: "",
        max: CLOSURE_BUDGET,
    },
    ClosureBudget {
        package: "mvmctl",
        target: "aarch64-apple-darwin",
        features: "",
        max: MACOS_CLOSURE_BUDGET,
    },
    ClosureBudget {
        package: "mvmctl",
        target: "aarch64-apple-darwin",
        features: RELEASE_FEATURES,
        max: 372,
    },
    ClosureBudget {
        package: "mvmctl",
        target: "x86_64-unknown-linux-gnu",
        features: RELEASE_FEATURES,
        max: 381,
    },
    ClosureBudget {
        package: "mvmctl",
        target: "aarch64-unknown-linux-gnu",
        features: RELEASE_FEATURES,
        max: 380,
    },
    ClosureBudget {
        package: "mvm-builder-guest",
        target: "aarch64-unknown-linux-musl",
        features: "",
        max: 88,
    },
    ClosureBudget {
        package: "mvm-agentd",
        target: "aarch64-unknown-linux-musl",
        features: "",
        max: 84,
    },
    ClosureBudget {
        package: "mvm-host-services",
        target: "aarch64-unknown-linux-musl",
        features: "",
        max: 85,
    },
];

/// macOS omits the Linux-only confinement and networking dependencies.
const MACOS_CLOSURE_BUDGET: usize = 346;

/// Maximum distinct packages in the default Linux closure.
/// Includes the shared authored-policy crate used by client and host admission;
/// the extraction adds one first-party package and no third-party dependencies.
/// Native user-manager observation adds eleven packages, ten in release
/// closures where futures-core is already present; no guest or macOS increase.
pub(crate) const CLOSURE_BUDGET: usize = 362;

pub(crate) fn run(workspace: &Path) -> Result<()> {
    for budget in BUDGETS {
        check_one(workspace, budget)?;
    }
    Ok(())
}

fn check_one(workspace: &Path, budget: &ClosureBudget) -> Result<()> {
    let ClosureBudget {
        package,
        target,
        features,
        max,
    } = *budget;
    let count = closure_crate_count(workspace, budget)?;
    let surface = if features.is_empty() {
        "default"
    } else {
        features
    };
    if count > max {
        bail!(
            "check-closure-budget: {package} ({surface}) {target} closure is {count} crates, \
             over the budget of {max} — a new dependency entered the measured graph. \
             Drop it, gate it behind an off-by-default feature (or a \
             `[target.'cfg(...)'.dependencies]` table if it is platform-specific), or, if it \
             is genuinely required, bump the budget in xtask/src/check_closure_budget.rs with \
             a one-line justification in the PR."
        );
    }
    if count < max {
        eprintln!(
            "check-closure-budget: {package} ({surface}) {target} {count} crates (budget {max}); deps dropped — \
             ratchet the budget down to {count}."
        );
    } else {
        eprintln!(
            "check-closure-budget: {package} ({surface}) {target} {count} crates (at budget {max})"
        );
    }
    Ok(())
}

fn closure_crate_count(workspace: &Path, budget: &ClosureBudget) -> Result<usize> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(&cargo);
    command.current_dir(workspace).args([
        "tree",
        "-p",
        budget.package,
        "-e",
        "normal,build",
        "--prefix",
        "none",
        "--locked",
        "--target",
        budget.target,
    ]);
    if !budget.features.is_empty() {
        command.args(["--features", budget.features]);
    }
    let output = command
        .output()
        .context("running budgeted `cargo tree -e normal,build --target ...`")?;
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
    use super::{RELEASE_FEATURES, unique_crate_count};

    #[test]
    fn release_budget_matches_workflow_features() {
        let workflow = include_str!("../../.github/workflows/release.yml");
        let features = workflow
            .lines()
            .find_map(|line| line.strip_prefix("  MVMCTL_RELEASE_FEATURES: "))
            .expect("release workflow declares its feature set");
        assert_eq!(
            features, RELEASE_FEATURES,
            "budget the exact shipped feature set"
        );
    }

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
