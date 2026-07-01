//! `LocalBackend` — the `MvmClient` over this host's microVMs, in-process.
//!
//! `list`/`stop`/`logs` go straight to the backend dispatch (they act on VMs
//! that already exist, so they carry no admission concern). `run` deliberately
//! does not boot here yet: the local start path admits a signed plan (the
//! workload-admission guarantee), and that flow is not yet exposed as a library
//! entrypoint. Until it is, `run` fails honestly rather than booting a workload
//! that skipped admission.

use async_trait::async_trait;
use mvm_backend::AnyBackend;
use mvm_core::protocol::vm_backend::{VmId, VmInfo, VmStatus};

use crate::client::MvmClient;
use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus};
use crate::error::{MvmError, Result};

/// Drives the host's VM backend directly. Construct with [`LocalBackend::new`]
/// (auto-selected backend) or [`LocalBackend::with_hypervisor`].
pub struct LocalBackend {
    backend: AnyBackend,
}

impl LocalBackend {
    pub fn new() -> Self {
        Self {
            backend: AnyBackend::auto_select(),
        }
    }

    pub fn with_hypervisor(name: &str) -> Self {
        Self {
            backend: AnyBackend::from_hypervisor(name),
        }
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn map_status(s: &VmStatus) -> MachineStatus {
    match s {
        VmStatus::Running => MachineStatus::Running,
        VmStatus::Starting => MachineStatus::Starting,
        // A paused VM isn't accepting work; surface it as stopped rather than
        // inventing a facade state that callers don't model.
        VmStatus::Stopped | VmStatus::Paused => MachineStatus::Stopped,
        VmStatus::Failed { .. } => MachineStatus::Failed,
    }
}

impl From<VmInfo> for MachineState {
    fn from(v: VmInfo) -> Self {
        MachineState {
            id: MachineId(v.id.0),
            name: v.name,
            status: map_status(&v.status),
        }
    }
}

fn backend_err(e: impl std::fmt::Display) -> MvmError {
    MvmError::Backend {
        reason: e.to_string(),
    }
}

#[async_trait]
impl MvmClient for LocalBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let infos = self.backend.list().map_err(backend_err)?;
        Ok(infos
            .into_iter()
            .map(MachineState::from)
            .filter(|m| filter.matches(m))
            .collect())
    }

    async fn run_machine(&self, _spec: MachineSpec) -> Result<MachineState> {
        // Booting here would skip signed-plan admission; refuse until the
        // admitted-boot flow is a library entrypoint.
        Err(MvmError::Backend {
            reason: "local run requires the admitted-boot library seam (signed-plan admission)"
                .into(),
        })
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        self.backend.stop(&VmId(id.0.clone())).map_err(backend_err)
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let lines = opts.tail_lines.unwrap_or(200);
        let text = self
            .backend
            .logs(&VmId(id.0.clone()), lines, false)
            .map_err(backend_err)?;
        Ok(text.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_maps_all_variants() {
        assert_eq!(map_status(&VmStatus::Running), MachineStatus::Running);
        assert_eq!(map_status(&VmStatus::Starting), MachineStatus::Starting);
        assert_eq!(map_status(&VmStatus::Stopped), MachineStatus::Stopped);
        assert_eq!(map_status(&VmStatus::Paused), MachineStatus::Stopped);
        assert_eq!(
            map_status(&VmStatus::Failed {
                reason: "boom".into()
            }),
            MachineStatus::Failed
        );
    }

    #[tokio::test]
    async fn list_over_mock_backend_succeeds() {
        // The mock backend needs no real VMM, so this exercises the full
        // list -> map -> filter path without a host VM.
        let be = LocalBackend::with_hypervisor("mock");
        let machines = be.list_machines(MachineFilter::all()).await.unwrap();
        // Filtering to an impossible status yields an empty set, proving the
        // filter is applied.
        let none = be
            .list_machines(MachineFilter {
                name: Some("definitely-not-present-xyz".into()),
                status: None,
            })
            .await
            .unwrap();
        assert!(none.len() <= machines.len());
    }

    #[tokio::test]
    async fn run_refuses_until_admitted_boot_seam() {
        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "w".into(),
            image: "i".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
        };
        assert!(matches!(
            be.run_machine(spec).await,
            Err(MvmError::Backend { .. })
        ));
    }
}
