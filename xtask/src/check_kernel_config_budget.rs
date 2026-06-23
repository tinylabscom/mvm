//! `xtask check-kernel-config-budget <configfile>`
//!
//! Assert the slim microVM kernel's built-in (`=y`) symbol count stays within
//! a committed budget (a ratchet). Every `=y` is a compiled-in subsystem — a
//! supply-chain + attack-surface unit and a class of kernel CVEs that can
//! apply to a booted guest. This gate makes a *new* built-in a deliberate,
//! reviewed choice rather than silent accretion, and keeps the "tiny kernel"
//! property true over time instead of only at landing.
//!
//! Takes the path to a resolved kernel `.config` (the `workload-config-<arch>`
//! flake output). The budget is **per-arch** — aarch64 carries more
//! arch/platform built-ins than x86_64, so a single ceiling at the aarch64
//! figure is slack for x86_64 and would miss an x86_64-only regression. The
//! arch is inferred from the config path (`…-aarch64` / `…-x86_64`). CI builds
//! the config on a Linux runner and hands the path here, so the gate does no
//! Nix evaluation and runs anywhere.

use anyhow::{Result, bail};
use std::path::Path;

/// Per-arch max built-in (`=y`) symbol counts. Tighten on every shrink; raising
/// one must be justified in the PR that does. Tracks the audit-subtraction pass
/// that took the baseline 1716 → these figures (PCI / EFI / MFD / I2C / GPIO /
/// NFS / VFIO / IPMI / cpufreq / SPI / CORESIGHT / KVM / IOMMU / squashfs /
/// suspend / SoC-errata and other off-the-boot-path subsystems), each cut
/// boot-validated under libkrun.
const BUDGET_AARCH64: usize = 1327;
const BUDGET_X86_64: usize = 1130;

/// Resolve the budget for a config path by the arch in its name. Unknown →
/// the larger budget (fail-open on the ceiling, never a false pass on a real
/// regression: an unrecognised arch still can't exceed the most generous bound).
fn budget_for_path(path: &str) -> usize {
    if path.contains("x86_64") {
        BUDGET_X86_64
    } else if path.contains("aarch64") {
        BUDGET_AARCH64
    } else {
        BUDGET_AARCH64.max(BUDGET_X86_64)
    }
}

pub fn run(args: &[String]) -> Result<()> {
    let Some(path) = args.first() else {
        bail!(
            "check-kernel-config-budget: needs a path to a resolved kernel .config \
             (build the `workload-config-<arch>` flake output and pass its path)"
        );
    };
    let content = std::fs::read_to_string(Path::new(path))
        .map_err(|e| anyhow::anyhow!("reading kernel config {path}: {e}"))?;
    let budget = budget_for_path(path);
    let count = count_builtins(&content);
    evaluate_budget(&content, budget)?;
    if count < budget {
        eprintln!(
            "check-kernel-config-budget: {count} built-in (=y) symbols \
             (budget {budget}); ratchet the matching BUDGET_* down to {count}."
        );
    } else {
        eprintln!("check-kernel-config-budget: {count} built-in symbols (at budget {budget})");
    }
    Ok(())
}

/// Count `CONFIG_*=y` lines (built-in symbols). `=m` and `# … is not set`
/// don't count — only what is compiled into the image.
fn count_builtins(config: &str) -> usize {
    config
        .lines()
        .filter(|l| l.trim_end().ends_with("=y"))
        .count()
}

/// Pure budget check — separated from I/O so it is trivially unit-testable.
pub fn evaluate_budget(config: &str, budget: usize) -> Result<()> {
    let count = count_builtins(config);
    if count > budget {
        bail!(
            "check-kernel-config-budget: {count} built-in (=y) kernel symbols exceeds the \
             budget of {budget} — a new subsystem was compiled in. Drop it (each `=y` is \
             attack surface), or, if genuinely required, bump the matching BUDGET_<arch> in \
             xtask/src/check_kernel_config_budget.rs with a one-line justification in the PR."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_builtins() {
        let cfg = "CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\nCONFIG_D=y\nCONFIG_E=\"str\"\n";
        assert_eq!(count_builtins(cfg), 2);
    }

    #[test]
    fn over_budget_is_rejected() {
        let cfg = "CONFIG_A=y\nCONFIG_B=y\nCONFIG_C=y\n";
        assert!(evaluate_budget(cfg, 2).is_err());
    }

    #[test]
    fn within_budget_passes() {
        let cfg = "CONFIG_A=y\n# CONFIG_X is not set\nCONFIG_Y=m\n";
        assert!(evaluate_budget(cfg, 5).is_ok());
    }

    #[test]
    fn at_budget_passes() {
        let cfg = "CONFIG_A=y\nCONFIG_B=y\n";
        assert!(evaluate_budget(cfg, 2).is_ok());
    }

    #[test]
    fn budget_resolves_per_arch_from_path() {
        assert_eq!(
            budget_for_path("staging/workload-config-aarch64"),
            BUDGET_AARCH64
        );
        assert_eq!(
            budget_for_path("staging/workload-config-x86_64"),
            BUDGET_X86_64
        );
        // Unknown arch → the larger ceiling (never a false pass).
        assert_eq!(
            budget_for_path("/tmp/some.config"),
            BUDGET_AARCH64.max(BUDGET_X86_64)
        );
    }
}
