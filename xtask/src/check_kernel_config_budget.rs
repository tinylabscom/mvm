//! `xtask check-kernel-config-budget <configfile>`
//!
//! Assert the slim microVM kernel's built-in (`=y`) symbol count stays within
//! a committed budget (a ratchet). Every `=y` is a compiled-in subsystem — a
//! supply-chain + attack-surface unit and a class of kernel CVEs that can
//! apply to a booted guest. This gate makes a *new* built-in a deliberate,
//! reviewed choice rather than silent accretion, and keeps the "tiny kernel"
//! property true over time instead of only at landing.
//!
//! Takes the path to a resolved kernel `.config` (the `workload-configfile`
//! flake output). CI builds that output on a Linux runner and hands the path
//! here, so the gate itself does no Nix evaluation and runs anywhere.

use anyhow::{Result, bail};
use std::path::Path;

/// Max built-in (`=y`) symbols allowed in the workload kernel config.
///
/// Provisional ceiling: the workload `.config` cannot be realised on a
/// non-Linux host, so this starts loose and PRINTS the measured count. Ratchet
/// it down to the value the first kernel-build CI run reports, then tighten on
/// every shrink. Raising it must be justified in the PR that does.
const KERNEL_Y_BUDGET: usize = 4096;

pub fn run(args: &[String]) -> Result<()> {
    let Some(path) = args.first() else {
        bail!(
            "check-kernel-config-budget: needs a path to a resolved kernel .config \
             (build the `workload-configfile` flake output and pass its path)"
        );
    };
    let content = std::fs::read_to_string(Path::new(path))
        .map_err(|e| anyhow::anyhow!("reading kernel config {path}: {e}"))?;
    let count = count_builtins(&content);
    evaluate_budget(&content, KERNEL_Y_BUDGET)?;
    if count < KERNEL_Y_BUDGET {
        eprintln!(
            "check-kernel-config-budget: {count} built-in (=y) symbols \
             (budget {KERNEL_Y_BUDGET}); ratchet KERNEL_Y_BUDGET down to {count}."
        );
    } else {
        eprintln!("check-kernel-config-budget: {count} built-in symbols (at budget)");
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
             attack surface), or, if genuinely required, bump KERNEL_Y_BUDGET in \
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
}
