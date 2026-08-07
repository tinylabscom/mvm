//! Target metadata describing the host processes to observe.
//!
//! This is a mirror of `mvm_runtime::base::observability_target::VmObservabilityTarget`
//! kept here so the telemetry subsystem does not need to depend on the full
//! runtime crate just for the metadata shape.

use std::path::PathBuf;

use mvm_core::vm_backend::BackendKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityTarget {
    pub vm_name: String,
    pub backend_kind: BackendKind,
    pub tenant_id: Option<String>,
    pub plan_id: Option<String>,
    pub substitution_pid: Option<u32>,
    pub state_dir: PathBuf,
}

impl ObservabilityTarget {
    pub fn new(vm_name: impl Into<String>) -> Self {
        Self {
            vm_name: vm_name.into(),
            backend_kind: BackendKind::Mock,
            tenant_id: None,
            plan_id: None,
            substitution_pid: None,
            state_dir: PathBuf::new(),
        }
    }

    pub fn with_backend(mut self, kind: BackendKind) -> Self {
        self.backend_kind = kind;
        self
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_plan(mut self, plan_id: impl Into<String>) -> Self {
        self.plan_id = Some(plan_id.into());
        self
    }

    pub fn with_substitution_pid(mut self, pid: u32) -> Self {
        self.substitution_pid = Some(pid);
        self
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = state_dir.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_target_builder_chains() {
        let target = ObservabilityTarget::new("vm-1")
            .with_backend(mvm_core::vm_backend::BackendKind::Libkrun)
            .with_tenant("tenant-a")
            .with_plan("plan-42")
            .with_substitution_pid(1234)
            .with_state_dir("/tmp/state");

        assert_eq!(target.vm_name, "vm-1");
        assert_eq!(
            target.backend_kind,
            mvm_core::vm_backend::BackendKind::Libkrun
        );
        assert_eq!(target.tenant_id, Some("tenant-a".to_string()));
        assert_eq!(target.plan_id, Some("plan-42".to_string()));
        assert_eq!(target.substitution_pid, Some(1234));
        assert_eq!(target.state_dir, std::path::PathBuf::from("/tmp/state"));
    }
}
