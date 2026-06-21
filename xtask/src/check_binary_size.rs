//! `xtask check-binary-size`
//!
//! Assert the shipped `mvmctl` binary stays within a committed size budget (a
//! ratchet). The binary is the artifact users download; the cross-compiled musl
//! host-vm binaries (`mvm-host-vm-init` + `mvm-egress-proxy`) are baked into it
//! as data, so their weight counts here too. This gate makes a size regression
//! a deliberate, reviewed choice rather than silent accretion — the size
//! counterpart to `check-closure-budget`'s crate-count cap.
//!
//! The gate measures an **already-built** release artifact (it does not build —
//! the build is the CI/release lane's job). By default it reads
//! `target/release/mvmctl`; set `MVM_BINARY_SIZE_PATH` to point at a per-target
//! artifact (e.g. the Linux release binary the release workflow produces).

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Env override for the artifact to measure — the release lane points this at
/// the per-target binary it just built.
const BINARY_PATH_ENV: &str = "MVM_BINARY_SIZE_PATH";

/// Max size (bytes) of the release `mvmctl` binary. Baseline measured
/// 2026-06-21 on macOS arm64 under the release profile (`opt-level=3`,
/// `lto=true`, `codegen-units=1`, `strip=true`) with the real embedded musl
/// host-vm binaries: 25,324,512 bytes (24.15 MiB). Budget = baseline + ~5%
/// headroom. See `docs/investigations/binary-size-baseline.md`. Lower it freely
/// as the binary shrinks; raising it needs a one-line justification in the PR.
const BINARY_SIZE_BUDGET_BYTES: u64 = 26_600_000; // 25.37 MiB

/// Outcome of comparing a measured size to the budget. Pure so the gate logic
/// is unit-tested without a build.
#[derive(Debug, PartialEq, Eq)]
enum SizeVerdict {
    Over { by: u64 },
    At,
    Under { by: u64 },
}

fn evaluate(actual: u64, budget: u64) -> SizeVerdict {
    match actual.cmp(&budget) {
        std::cmp::Ordering::Greater => SizeVerdict::Over {
            by: actual - budget,
        },
        std::cmp::Ordering::Equal => SizeVerdict::At,
        std::cmp::Ordering::Less => SizeVerdict::Under {
            by: budget - actual,
        },
    }
}

pub fn run(workspace: &Path) -> Result<()> {
    let path = binary_path(workspace);
    let actual = std::fs::metadata(&path)
        .with_context(|| {
            format!(
                "check-binary-size: no release binary at {} — build it first \
                 (`cargo build --release -p mvmctl`) or set {BINARY_PATH_ENV}; this gate \
                 measures the shipped artifact, it does not build it",
                path.display()
            )
        })?
        .len();
    match evaluate(actual, BINARY_SIZE_BUDGET_BYTES) {
        SizeVerdict::Over { by } => bail!(
            "check-binary-size: mvmctl is {} (over the {} budget by {}) — a size regression \
             entered the shipped binary. Trim it, gate a dep behind an off-by-default feature, \
             or, if genuinely required, bump BINARY_SIZE_BUDGET_BYTES in \
             xtask/src/check_binary_size.rs with a one-line justification in the PR.",
            human(actual),
            human(BINARY_SIZE_BUDGET_BYTES),
            human(by),
        ),
        SizeVerdict::Under { by } => eprintln!(
            "check-binary-size: mvmctl {} (budget {}); {} headroom — ratchet \
             BINARY_SIZE_BUDGET_BYTES down toward {actual} as it shrinks.",
            human(actual),
            human(BINARY_SIZE_BUDGET_BYTES),
            human(by),
        ),
        SizeVerdict::At => eprintln!("check-binary-size: mvmctl {} (at budget)", human(actual)),
    }
    Ok(())
}

fn binary_path(workspace: &Path) -> PathBuf {
    if let Ok(p) = std::env::var(BINARY_PATH_ENV)
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    workspace.join("target/release/mvmctl")
}

fn human(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_classifies_over_at_under() {
        assert_eq!(evaluate(100, 90), SizeVerdict::Over { by: 10 });
        assert_eq!(evaluate(90, 90), SizeVerdict::At);
        assert_eq!(evaluate(80, 90), SizeVerdict::Under { by: 10 });
    }

    #[test]
    fn human_formats_mib() {
        assert_eq!(human(10 * 1024 * 1024), "10.00 MiB");
    }

    #[test]
    fn run_errors_clearly_when_the_artifact_is_absent() {
        // No env override and no built binary under the temp workspace → a clear
        // "build it first" error, not a panic or a false pass.
        let tmp = tempfile::tempdir().unwrap();
        // Ensure the env override does not leak from the host into the test.
        unsafe { std::env::remove_var(BINARY_PATH_ENV) };
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no release binary"), "{err}");
    }
}
