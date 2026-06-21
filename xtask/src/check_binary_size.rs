//! `xtask check-binary-size --path <bin> --budget-bytes <N>`
//!
//! Assert a built release `mvmctl` binary stays within a byte budget (a
//! ratchet). Binary size is the user-facing weight of every install and a
//! direct function of the dependency closure; this gate makes a size jump a
//! deliberate, reviewed choice. It complements `check-closure-budget` (crate
//! count, no build) and `check-duplicate-majors` (no build) — those run per-PR
//! from `cargo` metadata, while this one needs an actual release binary, so it
//! runs in the release workflow where the binary already exists rather than
//! adding a release build to the PR lane.
//!
//! Budgets are per-target (a macOS aarch64 binary differs from a Linux x86_64
//! one), so the caller passes `--budget-bytes` for the target it just built
//! rather than baking a single number in here.

use anyhow::{Result, bail};
use std::path::Path;

pub fn run(args: &[String]) -> Result<()> {
    let path = arg_value(args, "--path")
        .or_else(|| std::env::var("MVM_BINARY_SIZE_PATH").ok())
        .ok_or_else(|| anyhow::anyhow!("check-binary-size: missing --path <binary>"))?;
    let budget = arg_value(args, "--budget-bytes")
        .or_else(|| std::env::var("MVM_BINARY_SIZE_BUDGET").ok())
        .ok_or_else(|| anyhow::anyhow!("check-binary-size: missing --budget-bytes <N>"))?
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("check-binary-size: --budget-bytes is not a u64: {e}"))?;

    let size = file_size(Path::new(&path))?;
    report(&path, size, budget)
}

/// Compare a measured size against the budget and emit the same ratchet hints
/// `check-closure-budget` uses. Pure so it is unit-tested without a real file.
fn report(path: &str, size: u64, budget: u64) -> Result<()> {
    if size > budget {
        bail!(
            "check-binary-size: {path} is {size} bytes, over the budget of {budget} \
             ({} KiB over). A dependency or feature grew the binary. Drop it, gate it behind \
             an off-by-default feature, or, if it is genuinely required, raise the budget for \
             this target in .github/workflows/release.yml with a one-line justification.",
            (size - budget).div_ceil(1024)
        );
    }
    let headroom = budget - size;
    if headroom >= 1024 * 1024 {
        eprintln!(
            "check-binary-size: {path} is {size} bytes ({} MiB under the {budget}-byte budget); \
             ratchet the budget down toward {size} as it shrinks.",
            headroom / (1024 * 1024)
        );
    } else {
        eprintln!("check-binary-size: {path} is {size} bytes (within the {budget}-byte budget)");
    }
    Ok(())
}

fn file_size(path: &Path) -> Result<u64> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("check-binary-size: cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        bail!("check-binary-size: {} is not a file", path.display());
    }
    Ok(meta.len())
}

/// `--flag value` lookup over a raw arg slice.
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_budget_passes() {
        assert!(report("bin", 1000, 2000).is_ok());
    }

    #[test]
    fn exactly_at_budget_passes() {
        assert!(report("bin", 2000, 2000).is_ok());
    }

    #[test]
    fn over_budget_fails() {
        let err = report("bin", 2001, 2000).unwrap_err().to_string();
        assert!(err.contains("over the budget"), "got: {err}");
    }

    #[test]
    fn arg_value_reads_flag_pair() {
        let args = vec![
            "--path".to_string(),
            "/tmp/mvmctl".to_string(),
            "--budget-bytes".to_string(),
            "42".to_string(),
        ];
        assert_eq!(arg_value(&args, "--path").as_deref(), Some("/tmp/mvmctl"));
        assert_eq!(arg_value(&args, "--budget-bytes").as_deref(), Some("42"));
        assert_eq!(arg_value(&args, "--missing"), None);
    }
}
