//! An in-memory `MvmClient` for tests and for callers to develop against before
//! a real backend exists. Not a production path.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::client::MvmClient;
use crate::client::dto::{
    LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus, PauseOpts,
    PauseOutcome, ReconfigureRequest, ResumeOpts, ResumeOutcome,
};
use crate::client::error::{MvmError, Result};
use crate::protocol::telemetry::{
    TelemetryCursor, TelemetryPage, TelemetryReadOpts, TelemetryRecord, TelemetryStatus,
};
use mvm_contract::protocol::capability_negotiation::{
    BackendCapabilityReport, ClientOperationCapabilities,
};
use mvm_contract::protocol::vm_backend::{BackendKind, VmCapabilities};

pub struct MockBackend {
    machines: Mutex<Vec<MachineState>>,
    next: Mutex<u64>,
    /// What this mock advertises. Default is the all-false matrix, so a test
    /// that forgets to set it sees refusals rather than a backend that
    /// silently claims to do everything.
    capabilities: Mutex<VmCapabilities>,
    operations: Mutex<ClientOperationCapabilities>,
    /// What the collector would have persisted per machine id. A machine
    /// with no entry reads as not provisioned, like a real boot nobody asked
    /// to observe; a cursor is the index into its record list.
    telemetry: Mutex<BTreeMap<String, MockTelemetry>>,
}

/// One machine's mock collector state.
#[derive(Debug, Clone, Default)]
struct MockTelemetry {
    status: Option<TelemetryStatus>,
    records: Vec<TelemetryRecord>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            machines: Mutex::new(Vec::new()),
            next: Mutex::new(0),
            capabilities: Mutex::new(VmCapabilities::default()),
            operations: Mutex::new(all_mock_operations()),
            telemetry: Mutex::new(BTreeMap::new()),
        }
    }
}

fn all_mock_operations() -> ClientOperationCapabilities {
    ClientOperationCapabilities::builder()
        .list(true)
        .inspect(true)
        .create(true)
        .run(true)
        .start(true)
        .stop(true)
        .pause(true)
        .resume(true)
        .remove(true)
        .logs(true)
        .exec(true)
        .reconfigure(true)
        .set_ttl(true)
        .telemetry(true)
        .build()
}

impl MockBackend {
    /// Set the capability matrix this mock reports, for driving negotiation
    /// paths a real backend would need hardware to reach.
    pub fn with_capabilities(self, capabilities: VmCapabilities) -> Self {
        *self.capabilities.lock().unwrap() = capabilities;
        self
    }

    /// Override the operation surface this test double advertises.
    #[must_use]
    pub fn with_operations(self, operations: ClientOperationCapabilities) -> Self {
        *self
            .operations
            .lock()
            .expect("mock operation capability lock poisoned") = operations;
        self
    }

    /// Set what `telemetry_status` answers for machine `id`.
    pub fn set_telemetry_status(&self, id: &MachineId, status: TelemetryStatus) {
        self.telemetry
            .lock()
            .expect("mock telemetry lock poisoned")
            .entry(id.0.clone())
            .or_default()
            .status = Some(status);
    }

    /// Append records to what `telemetry_records` pages for machine `id`,
    /// as if the collector had just received them.
    pub fn push_telemetry_records(
        &self,
        id: &MachineId,
        records: impl IntoIterator<Item = TelemetryRecord>,
    ) {
        self.telemetry
            .lock()
            .expect("mock telemetry lock poisoned")
            .entry(id.0.clone())
            .or_default()
            .records
            .extend(records);
    }

    /// Drop machine `id`'s records, as a reboot resets the real stream, so
    /// a cursor into the old stream is refused.
    pub fn reset_telemetry_records(&self, id: &MachineId) {
        if let Some(entry) = self
            .telemetry
            .lock()
            .expect("mock telemetry lock poisoned")
            .get_mut(&id.0)
        {
            entry.records.clear();
        }
    }
}

impl MockBackend {
    /// Insert a new machine with the given initial status (create → Stopped,
    /// run → Running).
    fn insert(&self, spec: MachineSpec, status: MachineStatus) -> Result<MachineState> {
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
            status,
            ..Default::default()
        };
        self.machines.lock().unwrap().push(state.clone());
        Ok(state)
    }
}

#[async_trait]
impl MvmClient for MockBackend {
    async fn backend_capabilities(&self) -> Result<BackendCapabilityReport> {
        Ok(BackendCapabilityReport::new(
            BackendKind::Mock,
            self.capabilities.lock().unwrap().clone(),
        )
        .with_operations(
            self.operations
                .lock()
                .expect("mock operation capability lock poisoned")
                .clone(),
        ))
    }

    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let all = self.machines.lock().unwrap();
        Ok(all
            .iter()
            .filter(|m| filter.name.as_ref().is_none_or(|n| *n == m.name))
            .filter(|m| filter.status.is_none_or(|s| s == m.status))
            .cloned()
            .collect())
    }

    async fn inspect_machine(&self, id: &MachineId) -> Result<MachineState> {
        self.machines
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })
    }

    async fn create_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        self.insert(spec, MachineStatus::Stopped)
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        self.insert(spec, MachineStatus::Running)
    }

    async fn start_machine(&self, id: &MachineId) -> Result<MachineState> {
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.status = MachineStatus::Running;
        Ok(m.clone())
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

    async fn remove_machine(&self, id: &MachineId) -> Result<()> {
        // Idempotent: removing an absent machine is Ok (per the trait contract).
        self.machines.lock().unwrap().retain(|m| m.id != *id);
        Ok(())
    }

    async fn pause_machine(&self, id: &MachineId, _opts: PauseOpts) -> Result<PauseOutcome> {
        // In-memory paused flag; no real snapshot substrate. Returns a zeroed
        // outcome so pure trait-level tests exercise the pause→resume flow.
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.status = MachineStatus::Paused;
        Ok(PauseOutcome::default())
    }

    async fn resume_machine(&self, id: &MachineId, _opts: ResumeOpts) -> Result<ResumeOutcome> {
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.status = MachineStatus::Running;
        // No real snapshot substrate — a zeroed outcome keeps trait-level tests
        // exercising the pause→resume flow without asserting snapshot detail.
        Ok(ResumeOutcome::default())
    }

    async fn machine_logs(&self, id: &MachineId, _opts: LogOpts) -> Result<Vec<u8>> {
        let all = self.machines.lock().unwrap();
        if all.iter().any(|m| m.id == *id) {
            Ok(Vec::new())
        } else {
            Err(MvmError::NotFound { id: id.0.clone() })
        }
    }

    async fn exec_machine(
        &self,
        id: &MachineId,
        _command: Vec<String>,
    ) -> Result<crate::client::dto::ExecResult> {
        let all = self.machines.lock().unwrap();
        if all.iter().any(|m| m.id == *id) {
            Ok(crate::client::dto::ExecResult {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        } else {
            Err(MvmError::NotFound { id: id.0.clone() })
        }
    }

    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        _cfg: ReconfigureRequest,
    ) -> Result<MachineState> {
        let all = self.machines.lock().unwrap();
        all.iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })
    }

    async fn telemetry_status(&self, id: &MachineId) -> Result<TelemetryStatus> {
        self.inspect_machine(id).await?;
        Ok(self
            .telemetry
            .lock()
            .expect("mock telemetry lock poisoned")
            .get(&id.0)
            .and_then(|t| t.status.clone())
            .unwrap_or_else(TelemetryStatus::not_provisioned))
    }

    async fn telemetry_records(
        &self,
        id: &MachineId,
        opts: TelemetryReadOpts,
    ) -> Result<TelemetryPage> {
        self.inspect_machine(id).await?;
        let telemetry = self.telemetry.lock().expect("mock telemetry lock poisoned");
        let records = telemetry
            .get(&id.0)
            .map(|t| t.records.as_slice())
            .unwrap_or_default();
        let start = opts.after.map_or(0, |c| c.0 as usize);
        if start > records.len() {
            return Err(MvmError::Rejected {
                reason: format!(
                    "telemetry cursor {start} is past the end of {}'s record stream ({} records); \
                     the stream was reset, read again from the start",
                    id.0,
                    records.len()
                ),
            });
        }
        let end = start
            .saturating_add(opts.effective_limit())
            .min(records.len());
        Ok(TelemetryPage {
            records: records[start..end].to_vec(),
            next: TelemetryCursor(end as u64),
            more: end < records.len(),
        })
    }

    async fn set_ttl(&self, id: &MachineId, expires_at: Option<String>) -> Result<()> {
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.expires_at = expires_at;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::dto::*;

    #[tokio::test]
    async fn mock_reports_every_facade_operation_it_implements() {
        let operations = MockBackend::default()
            .backend_capabilities()
            .await
            .expect("mock capabilities")
            .operations;
        assert!(operations.list);
        assert!(operations.inspect);
        assert!(operations.create);
        assert!(operations.run);
        assert!(operations.start);
        assert!(operations.stop);
        assert!(operations.pause);
        assert!(operations.resume);
        assert!(operations.remove);
        assert!(operations.logs);
        assert!(operations.exec);
        assert!(operations.reconfigure);
        assert!(operations.set_ttl);
        assert!(operations.telemetry);
    }

    fn telemetry_record(sequence: u64) -> TelemetryRecord {
        use crate::protocol::telemetry::{
            Attributes, Level, ProducerEpoch, RecordBody, SourceKind,
        };
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([9; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: "tick".try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn telemetry_reads_not_provisioned_until_set_and_unknown_is_not_found() {
        let mock = MockBackend::default();
        let spec = MachineSpec::builder("quiet", "oci:alpine:3.20")
            .unwrap()
            .build();
        let machine = mock.run_machine(spec).await.unwrap();

        let status = mock.telemetry_status(&machine.id).await.unwrap();
        assert_eq!(status, TelemetryStatus::not_provisioned());
        let page = mock
            .telemetry_records(&machine.id, TelemetryReadOpts::from_start())
            .await
            .unwrap();
        assert!(page.records.is_empty());
        assert_eq!(page.next, TelemetryCursor(0));
        assert!(!page.more);

        let collecting = TelemetryStatus {
            coverage: crate::protocol::telemetry::TelemetryCoverage::Collecting { generation: 2 },
            shed: 1,
        };
        mock.set_telemetry_status(&machine.id, collecting.clone());
        assert_eq!(
            mock.telemetry_status(&machine.id).await.unwrap(),
            collecting
        );

        let ghost = MachineId("ghost".into());
        assert!(matches!(
            mock.telemetry_status(&ghost).await,
            Err(MvmError::NotFound { .. })
        ));
        assert!(matches!(
            mock.telemetry_records(&ghost, TelemetryReadOpts::from_start())
                .await,
            Err(MvmError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn telemetry_records_page_by_cursor_and_refuse_a_cursor_past_a_reset() {
        let mock = MockBackend::default();
        let spec = MachineSpec::builder("chatty", "oci:alpine:3.20")
            .unwrap()
            .build();
        let machine = mock.run_machine(spec).await.unwrap();
        mock.push_telemetry_records(&machine.id, (1..=3).map(telemetry_record));

        let first = mock
            .telemetry_records(
                &machine.id,
                TelemetryReadOpts {
                    after: None,
                    limit: Some(2),
                },
            )
            .await
            .unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.more);
        assert_eq!(first.next, TelemetryCursor(2));

        let second = mock
            .telemetry_records(&machine.id, TelemetryReadOpts::after(first.next))
            .await
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(!second.more);
        assert_eq!(second.next, TelemetryCursor(3));

        let idle = mock
            .telemetry_records(&machine.id, TelemetryReadOpts::after(second.next))
            .await
            .unwrap();
        assert!(idle.records.is_empty());
        assert_eq!(idle.next, second.next);

        mock.reset_telemetry_records(&machine.id);
        let err = mock
            .telemetry_records(&machine.id, TelemetryReadOpts::after(second.next))
            .await
            .unwrap_err();
        assert!(matches!(err, MvmError::Rejected { .. }), "{err}");
        let fresh = mock
            .telemetry_records(&machine.id, TelemetryReadOpts::from_start())
            .await
            .unwrap();
        assert!(fresh.records.is_empty());
    }

    #[tokio::test]
    async fn run_then_list_then_stop_roundtrips() {
        let mock = MockBackend::default();

        let spec = MachineSpec {
            name: "web".into(),
            image: "img".parse().unwrap(),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
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
    async fn create_inspect_start_remove_lifecycle() {
        let mock = MockBackend::default();
        let spec = MachineSpec {
            name: "db".into(),
            image: "img".parse().unwrap(),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };

        // create → stopped (not started).
        let created = mock.create_machine(spec).await.unwrap();
        assert_eq!(created.status, MachineStatus::Stopped);

        // inspect returns it.
        let got = mock.inspect_machine(&created.id).await.unwrap();
        assert_eq!(got.name, "db");
        assert_eq!(got.status, MachineStatus::Stopped);

        // start → running.
        let started = mock.start_machine(&created.id).await.unwrap();
        assert_eq!(started.status, MachineStatus::Running);
        assert_eq!(
            mock.inspect_machine(&created.id).await.unwrap().status,
            MachineStatus::Running
        );

        // remove → gone; inspect now NotFound; remove is idempotent.
        mock.remove_machine(&created.id).await.unwrap();
        assert!(matches!(
            mock.inspect_machine(&created.id).await,
            Err(MvmError::NotFound { .. })
        ));
        mock.remove_machine(&created.id).await.unwrap(); // idempotent
    }

    #[tokio::test]
    async fn inspect_and_start_unknown_are_not_found() {
        let mock = MockBackend::default();
        let missing = MachineId("nope".into());
        assert!(matches!(
            mock.inspect_machine(&missing).await,
            Err(MvmError::NotFound { .. })
        ));
        assert!(matches!(
            mock.start_machine(&missing).await,
            Err(MvmError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn pause_flips_paused_resume_flips_running_unknown_is_not_found() {
        let mock = MockBackend::default();
        let started = mock
            .run_machine(MachineSpec {
                name: "web".into(),
                image: "i".parse().unwrap(),
                cpus: 1,
                memory_mib: 64,
                env: vec![],
                grants: None,
                assurance_campaign: None,
            })
            .await
            .unwrap();

        let outcome = mock
            .pause_machine(&started.id, PauseOpts::default())
            .await
            .unwrap();
        assert_eq!(outcome, PauseOutcome::default());
        assert_eq!(
            mock.inspect_machine(&started.id).await.unwrap().status,
            MachineStatus::Paused
        );

        mock.resume_machine(&started.id, ResumeOpts::default())
            .await
            .unwrap();
        assert_eq!(
            mock.inspect_machine(&started.id).await.unwrap().status,
            MachineStatus::Running
        );

        let missing = MachineId("nope".into());
        assert!(matches!(
            mock.pause_machine(&missing, PauseOpts::default()).await,
            Err(MvmError::NotFound { .. })
        ));
        assert!(matches!(
            mock.resume_machine(&missing, ResumeOpts::default()).await,
            Err(MvmError::NotFound { .. })
        ));
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

    #[tokio::test]
    async fn exec_on_known_machine_returns_result_else_not_found() {
        let mock = MockBackend::default();
        let started = mock
            .run_machine(MachineSpec {
                name: "web".into(),
                image: "i".parse().unwrap(),
                cpus: 1,
                memory_mib: 64,
                env: vec![],
                grants: None,
                assurance_campaign: None,
            })
            .await
            .unwrap();
        let res = mock
            .exec_machine(&started.id, vec!["echo".into(), "hi".into()])
            .await
            .unwrap();
        assert_eq!(res.exit_code, 0);
        assert!(
            mock.exec_machine(&MachineId("nope".into()), vec![])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reconfigure_known_returns_state_unknown_is_not_found() {
        let mock = MockBackend::default();
        let started = mock
            .run_machine(MachineSpec {
                name: "web".into(),
                image: "i".parse().unwrap(),
                cpus: 1,
                memory_mib: 64,
                env: vec![],
                grants: None,
                assurance_campaign: None,
            })
            .await
            .unwrap();
        let out = mock
            .reconfigure_machine(
                &started.id,
                ReconfigureRequest {
                    cpus: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(out.name, "web");
        assert!(
            mock.reconfigure_machine(&MachineId("nope".into()), ReconfigureRequest::default())
                .await
                .is_err()
        );
    }
}
