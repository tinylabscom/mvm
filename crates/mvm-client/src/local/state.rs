//! Mapping backend VM state into the client-facing machine inventory.

use mvm_core::client::dto::{MachineId, MachineState, MachineStatus, PortMapping};
use mvm_core::protocol::vm_backend::{VmInfo, VmStatus};
use mvm_runtime::AnyBackend;
use mvm_runtime::vm::name_registry::VmRegistration;

pub(crate) fn map_status(s: &VmStatus) -> MachineStatus {
    match s {
        VmStatus::Running => MachineStatus::Running,
        VmStatus::Starting => MachineStatus::Starting,
        VmStatus::Stopped => MachineStatus::Stopped,
        // A paused VM stays distinct from stopped so it remains visible in a
        // default listing rather than folding away.
        VmStatus::Paused => MachineStatus::Paused,
        VmStatus::Failed { .. } => MachineStatus::Failed,
    }
}

/// The detail behind a non-happy status — currently the failure reason, which
/// rides on [`MachineState::status_detail`] because [`MachineStatus::Failed`]
/// is a unit variant.
fn status_detail(s: &VmStatus) -> Option<String> {
    match s {
        VmStatus::Failed { reason } => Some(reason.clone()),
        VmStatus::Running | VmStatus::Starting | VmStatus::Stopped | VmStatus::Paused => None,
    }
}

/// Resolve the backend that owns a started VM by its state-dir marker, falling
/// back to the platform default so the column is accurate for a marker-less VM.
fn resolve_backend_name(vm_name: &str) -> String {
    AnyBackend::for_started_vm(vm_name)
        .map(|b| b.name().to_string())
        .unwrap_or_else(|| {
            if mvm_core::platform::current().is_hvf_default_tier() {
                "hvf".to_string()
            } else {
                "firecracker".to_string()
            }
        })
}

/// Build a [`MachineState`] from a backend `VmInfo` joined with its optional
/// registry entry (tags / TTL / readiness) and its resolved owning backend.
pub(super) fn to_state(info: VmInfo, reg: Option<&VmRegistration>) -> MachineState {
    let backend = resolve_backend_name(&info.name);
    MachineState {
        id: MachineId(info.id.0),
        status: map_status(&info.status),
        status_detail: status_detail(&info.status),
        backend,
        guest_ip: info.guest_ip,
        cpus: info.cpus,
        memory_mib: info.memory_mib,
        profile: info.profile,
        revision: info.revision,
        flake_ref: info.flake_ref,
        ports: info
            .ports
            .into_iter()
            .map(|p| PortMapping {
                host: p.host,
                guest: p.guest,
            })
            .collect(),
        tags: reg.map(|r| r.tags.clone()).unwrap_or_default(),
        expires_at: reg.and_then(|r| r.expires_at.clone()),
        auto_resume: reg.map(|r| r.auto_resume).unwrap_or(true),
        readiness: reg.and_then(|r| r.readiness.clone()),
        last_readiness_change_at: reg.and_then(|r| r.last_readiness_change_at.clone()),
        name: info.name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::vm_backend::VmId;
    use mvm_runtime::vm::name_registry::VmNameRegistry;

    #[test]
    fn status_maps_all_variants() {
        assert_eq!(map_status(&VmStatus::Running), MachineStatus::Running);
        assert_eq!(map_status(&VmStatus::Starting), MachineStatus::Starting);
        assert_eq!(map_status(&VmStatus::Stopped), MachineStatus::Stopped);
        assert_eq!(map_status(&VmStatus::Paused), MachineStatus::Paused);
        assert_eq!(
            map_status(&VmStatus::Failed {
                reason: "boom".into()
            }),
            MachineStatus::Failed
        );
    }

    #[test]
    fn status_detail_carries_only_failure_reason() {
        assert_eq!(
            status_detail(&VmStatus::Failed {
                reason: "boom".into()
            }),
            Some("boom".to_string())
        );
        assert_eq!(status_detail(&VmStatus::Running), None);
        assert_eq!(status_detail(&VmStatus::Paused), None);
    }

    #[test]
    fn to_state_joins_backend_info_with_registry_metadata() {
        let info = VmInfo {
            id: VmId("vm-1".into()),
            name: "web".into(),
            status: VmStatus::Running,
            guest_ip: Some("172.16.0.2".into()),
            cpus: 2,
            memory_mib: 512,
            profile: Some("worker".into()),
            revision: None,
            flake_ref: Some(".#worker".into()),
            ports: vec![mvm_core::protocol::vm_backend::VmPortMapping {
                host: 8080,
                guest: 80,
            }],
        };
        let mut registry = VmNameRegistry::default();
        let mut tags = std::collections::BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        registry
            .register(mvm_runtime::vm::name_registry::RegisterParams {
                name: "web",
                vm_dir: "/tmp/web",
                network: "default",
                guest_ip: Some("172.16.0.2"),
                slot_index: 0,
                tags,
                expires_at: Some("2099-01-01T00:00:00Z".into()),
                auto_resume: false,
            })
            .unwrap();

        let state = to_state(info, registry.lookup("web"));
        assert_eq!(state.name, "web");
        assert_eq!(state.status, MachineStatus::Running);
        assert_eq!(state.cpus, 2);
        assert_eq!(state.memory_mib, 512);
        assert_eq!(state.flake_ref.as_deref(), Some(".#worker"));
        assert_eq!(
            state.ports,
            vec![PortMapping {
                host: 8080,
                guest: 80
            }]
        );
        assert_eq!(state.tags.get("env").map(String::as_str), Some("prod"));
        assert_eq!(state.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert!(!state.auto_resume);
        let bare = to_state(
            VmInfo {
                id: VmId("vm-2".into()),
                name: "solo".into(),
                status: VmStatus::Stopped,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            },
            None,
        );
        assert!(bare.tags.is_empty() && bare.auto_resume && bare.expires_at.is_none());
    }
}
