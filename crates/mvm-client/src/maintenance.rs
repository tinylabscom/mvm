//! Host-local registry maintenance shared by command and embedding surfaces.

pub mod cache;
pub mod cleanup;
pub mod environment;
pub mod sign;

use serde::{Deserialize, Serialize};

/// Preview drift unless the caller explicitly authorizes applying repairs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    #[serde(default)]
    pub apply: bool,
}

/// Observed drift and non-fatal errors, with the CLI's established JSON shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReconcileReport {
    pub live: Vec<String>,
    pub dead_process_reaped: Vec<String>,
    pub stale_record_dropped: Vec<String>,
    pub orphan_state_reaped: Vec<String>,
    pub unadmitted_resume_stopped: Vec<String>,
    pub errors: Vec<String>,
}

impl ReconcileReport {
    pub fn reconciled_count(&self) -> usize {
        self.dead_process_reaped.len()
            + self.stale_record_dropped.len()
            + self.orphan_state_reaped.len()
            + self.unadmitted_resume_stopped.len()
    }

    pub fn is_clean(&self) -> bool {
        self.reconciled_count() == 0 && self.errors.is_empty()
    }
}

impl From<mvm_runtime::vm::reconcile::ConvergeReport> for ReconcileReport {
    fn from(report: mvm_runtime::vm::reconcile::ConvergeReport) -> Self {
        Self {
            live: report.live,
            dead_process_reaped: report.dead_process_reaped,
            stale_record_dropped: report.stale_record_dropped,
            orphan_state_reaped: report.orphan_state_reaped,
            unadmitted_resume_stopped: report.unadmitted_resume_stopped,
            errors: report.errors,
        }
    }
}

/// Inspect or repair the configured local registry using the authoritative
/// runtime liveness and admission rules. Applying retains the runtime's
/// lifecycle locks, audit emission, and abandoned-restore cleanup.
///
/// Errors are reported as data: automatic maintenance must never prevent the
/// requested foreground command from running.
pub fn reconcile(request: &ReconcileRequest) -> ReconcileReport {
    mvm_runtime::vm::reconcile::converge(&mvm_runtime::vm::reconcile::ConvergeOpts {
        dry_run: !request.apply,
    })
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::vm::name_registry::{RegisterParams, VmNameRegistry, registry_path};

    #[test]
    fn requests_default_to_preview_and_reject_unknown_fields() {
        let request: ReconcileRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        assert!(!ReconcileRequest::default().apply);
        assert!(
            serde_json::from_str::<ReconcileRequest>(r#"{"apply":true,"force":true}"#).is_err()
        );
        assert!(serde_json::from_str::<ReconcileRequest>(r#"{"apply":"yes"}"#).is_err());
        let request = ReconcileRequest { apply: true };
        let roundtrip: ReconcileRequest =
            serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(roundtrip.apply);
    }

    #[test]
    fn report_preserves_every_runtime_category_and_wire_field() {
        let runtime = mvm_runtime::vm::reconcile::ConvergeReport {
            live: vec!["live".into()],
            dead_process_reaped: vec!["dead".into()],
            stale_record_dropped: vec!["stale".into()],
            orphan_state_reaped: vec!["orphan".into()],
            unadmitted_resume_stopped: vec!["unadmitted".into()],
            errors: vec!["cannot stop".into()],
        };
        let report = ReconcileReport::from(runtime.clone());
        assert_eq!(report.reconciled_count(), runtime.reconciled_count());
        assert_eq!(report.is_clean(), runtime.is_clean());
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::to_value(runtime).unwrap()
        );
        let roundtrip: ReconcileReport =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(roundtrip, report);
        assert!(ReconcileReport::default().is_clean());
    }

    #[test]
    fn preview_preserves_registry_and_apply_repairs_and_audits() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let missing = mvm_core::config::vm_state_dir("stale");
        let mut registry = VmNameRegistry::default();
        registry
            .register(RegisterParams::minimal(
                "stale",
                missing.to_str().unwrap(),
                "default",
            ))
            .unwrap();
        registry.save(&registry_path()).unwrap();
        let before = std::fs::read(registry_path()).unwrap();

        let preview = reconcile(&ReconcileRequest::default());
        assert_eq!(preview.stale_record_dropped, ["stale"]);
        assert!(preview.errors.is_empty(), "{preview:?}");
        assert_eq!(std::fs::read(registry_path()).unwrap(), before);

        let applied = reconcile(&ReconcileRequest { apply: true });
        assert_eq!(applied.stale_record_dropped, ["stale"]);
        assert!(applied.errors.is_empty(), "{applied:?}");
        assert!(
            VmNameRegistry::load(&registry_path())
                .unwrap()
                .lookup("stale")
                .is_none()
        );
        let audit = std::fs::read_to_string(home.path().join("state/log/audit.jsonl")).unwrap();
        assert!(audit.contains("registry_reconcile"), "{audit}");
        assert!(reconcile(&ReconcileRequest { apply: true }).is_clean());
    }

    #[test]
    fn corrupt_registry_is_reported_without_failing_the_caller() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let path = registry_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not a registry").unwrap();
        let report = reconcile(&ReconcileRequest { apply: true });
        assert!(!report.is_clean());
        assert!(!report.errors.is_empty());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "not a registry");
    }
}
