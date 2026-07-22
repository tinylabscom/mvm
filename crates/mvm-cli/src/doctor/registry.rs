//! Registry/runtime dry-run convergence drift.

use super::Check;

/// One-line summary of a dry-run convergence report for `doctor`.
/// Pure so it's testable without touching the registry.
fn registry_drift_summary(report: &mvm_runtime::vm::reconcile::ConvergeReport) -> String {
    let n = report.reconciled_count();
    if n == 0 {
        "clean".to_string()
    } else {
        format!("{n} record(s) would be reconciled (run `mvmctl reconcile`)")
    }
}

/// Surface registry/runtime drift without
/// healing it: a dry-run convergence pass, reported as `clean` or a
/// count. Informational — drift self-heals at the next state-touching
/// command, so `ok` is always true.
pub(super) fn registry_drift_check() -> Check {
    let report = mvm_runtime::vm::reconcile::converge(&mvm_runtime::vm::reconcile::ConvergeOpts {
        dry_run: true,
    });
    Check {
        name: "registry drift",
        category: "platform",
        ok: true,
        info: registry_drift_summary(&report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_drift_summary_reports_clean_and_counts() {
        use mvm_runtime::vm::reconcile::ConvergeReport;
        let clean = ConvergeReport::default();
        assert_eq!(registry_drift_summary(&clean), "clean");

        let mut drifted = ConvergeReport::default();
        drifted.dead_process_reaped.push("vm1".to_string());
        drifted.orphan_state_reaped.push("ghost".to_string());
        let s = registry_drift_summary(&drifted);
        assert!(s.starts_with("2 record(s) would be reconciled"), "{s}");
        assert!(s.contains("mvmctl reconcile"));
    }
}
