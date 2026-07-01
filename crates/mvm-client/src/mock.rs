//! An in-memory `MvmClient` for tests and for callers to develop against before
//! a real backend exists. Not a production path.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::client::MvmClient;
use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus};
use crate::error::{MvmError, Result};

#[derive(Default)]
pub struct MockBackend {
    machines: Mutex<Vec<MachineState>>,
    next: Mutex<u64>,
}

#[async_trait]
impl MvmClient for MockBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let all = self.machines.lock().unwrap();
        Ok(all
            .iter()
            .filter(|m| filter.name.as_ref().is_none_or(|n| *n == m.name))
            .filter(|m| filter.status.is_none_or(|s| s == m.status))
            .cloned()
            .collect())
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        if spec.name.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "name must not be empty".into(),
            });
        }
        let mut n = self.next.lock().unwrap();
        *n += 1;
        let state = MachineState {
            id: MachineId(format!("m{n}")),
            name: spec.name,
            status: MachineStatus::Running,
        };
        self.machines.lock().unwrap().push(state.clone());
        Ok(state)
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.status = MachineStatus::Stopped;
        Ok(())
    }

    async fn machine_logs(&self, id: &MachineId, _opts: LogOpts) -> Result<Vec<u8>> {
        let all = self.machines.lock().unwrap();
        if all.iter().any(|m| m.id == *id) {
            Ok(Vec::new())
        } else {
            Err(MvmError::NotFound { id: id.0.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::*;

    #[tokio::test]
    async fn run_then_list_then_stop_roundtrips() {
        let mock = MockBackend::default();

        let spec = MachineSpec {
            name: "web".into(),
            image: "img".into(),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
        };
        let started = mock.run_machine(spec).await.unwrap();
        assert_eq!(started.status, MachineStatus::Running);

        let listed = mock.list_machines(MachineFilter::all()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "web");

        mock.stop_machine(&started.id).await.unwrap();
        let after = mock.list_machines(MachineFilter::all()).await.unwrap();
        assert_eq!(after[0].status, MachineStatus::Stopped);
    }

    #[tokio::test]
    async fn stop_unknown_is_not_found() {
        let mock = MockBackend::default();
        let err = mock
            .stop_machine(&MachineId("nope".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, MvmError::NotFound { .. }));
    }
}
