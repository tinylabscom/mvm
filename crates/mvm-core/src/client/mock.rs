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
use crate::client::{
    ReceivedRecord, TelemetryCursor, TelemetryReadRequest, TelemetryReadResponse, TelemetryStatus,
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
    /// What each machine's collector would have left, by machine id. A
    /// machine with no entry reads as one booted without a collector.
    telemetry: Mutex<BTreeMap<String, MockTelemetry>>,
}

/// One machine's mock collector outputs: the status it answers and, once
/// seeded, its record stream.
#[derive(Debug, Default)]
struct MockTelemetry {
    status: Option<TelemetryStatus>,
    /// `None` until records are pushed or the stream is reset, mirroring a
    /// machine with no collector files: such a stream echoes any cursor.
    stream: Option<MockStream>,
}

/// A record stream positioned the way the collector persists it: each
/// record's cursor end is the byte offset past its persisted line.
#[derive(Debug, Default)]
struct MockStream {
    records: Vec<ReceivedRecord>,
    /// `ends[i]` is the offset just past record `i`'s line.
    ends: Vec<u64>,
}

impl MockStream {
    fn len(&self) -> u64 {
        self.ends.last().copied().unwrap_or(0)
    }

    fn push(&mut self, record: ReceivedRecord) {
        let end = self.len() + persisted_line_len(&record);
        self.records.push(record);
        self.ends.push(end);
    }

    /// The index of the first record at `cursor`, or `None` when the cursor
    /// is not a line boundary of this stream.
    fn index_at(&self, cursor: TelemetryCursor) -> Option<usize> {
        if cursor.offset == 0 {
            return Some(0);
        }
        self.ends
            .binary_search(&cursor.offset)
            .ok()
            .map(|index| index + 1)
    }

    fn page(&self, request: &TelemetryReadRequest) -> Result<TelemetryReadResponse> {
        let cursor = request.cursor();
        let start = self.index_at(cursor).ok_or_else(|| MvmError::InvalidSpec {
            reason: format!(
                "telemetry cursor offset {} is not a line boundary of a {}-byte stream",
                cursor.offset,
                self.len()
            ),
        })?;
        let end = start
            .saturating_add(request.effective_limit())
            .min(self.records.len());
        let next_cursor = match end {
            0 => TelemetryCursor::START,
            end => TelemetryCursor {
                offset: self.ends[end - 1],
            },
        };
        Ok(TelemetryReadResponse {
            records: self.records[start..end].to_vec(),
            next_cursor,
            undecodable: 0,
            exhausted: end == self.records.len(),
        })
    }
}

/// The length of the sealed line the collector persists for `record`, so the
/// mock's cursors are the byte offsets the real reader hands out.
fn persisted_line_len(record: &ReceivedRecord) -> u64 {
    ReceivedRecord::sealed_line_len(record.received_at_ms.unwrap_or(0), &record.record)
        .expect("a built telemetry record serializes")
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
        self.with_telemetry(id, |telemetry| telemetry.status = Some(status));
    }

    /// Append records to what `telemetry_records` pages for machine `id`, as
    /// if the collector had just persisted them. Cursors advance by each
    /// record's persisted line length, exactly as the real reader's do.
    pub fn push_telemetry_records(
        &self,
        id: &MachineId,
        records: impl IntoIterator<Item = ReceivedRecord>,
    ) {
        self.with_telemetry(id, |telemetry| {
            let stream = telemetry.stream.get_or_insert_with(MockStream::default);
            records.into_iter().for_each(|record| stream.push(record));
        });
    }

    /// Empty machine `id`'s record stream, as removing and recreating the
    /// machine does to the real one: a cursor into the old stream is then
    /// refused rather than rebased.
    pub fn reset_telemetry_records(&self, id: &MachineId) {
        self.with_telemetry(id, |telemetry| {
            telemetry.stream = Some(MockStream::default());
        });
    }

    fn with_telemetry(&self, id: &MachineId, update: impl FnOnce(&mut MockTelemetry)) {
        update(
            self.telemetry
                .lock()
                .expect("mock telemetry lock poisoned")
                .entry(id.0.clone())
                .or_default(),
        );
    }

    fn require_machine(&self, id: &MachineId) -> Result<()> {
        if self.machines.lock().unwrap().iter().any(|m| m.id == *id) {
            Ok(())
        } else {
            Err(MvmError::NotFound { id: id.0.clone() })
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

    async fn telemetry_status(&self, id: &MachineId) -> Result<TelemetryStatus> {
        // A machine nobody seeded was booted without a collector; an unknown
        // one is not found.
        self.require_machine(id)?;
        Ok(self
            .telemetry
            .lock()
            .expect("mock telemetry lock poisoned")
            .get(&id.0)
            .and_then(|telemetry| telemetry.status.clone())
            .unwrap_or(TelemetryStatus::NotProvisioned))
    }

    async fn telemetry_records(
        &self,
        id: &MachineId,
        request: TelemetryReadRequest,
    ) -> Result<TelemetryReadResponse> {
        self.require_machine(id)?;
        let telemetry = self.telemetry.lock().expect("mock telemetry lock poisoned");
        match telemetry.get(&id.0).and_then(|t| t.stream.as_ref()) {
            Some(stream) => stream.page(&request),
            // No collector files: an empty page echoing the cursor, as the
            // local seam answers for a machine with no state directory.
            None => Ok(TelemetryReadResponse {
                records: Vec::new(),
                next_cursor: request.cursor(),
                undecodable: 0,
                exhausted: true,
            }),
        }
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
    use crate::client::CollectorState;
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

    fn telemetry_record(sequence: u64) -> ReceivedRecord {
        use crate::protocol::telemetry::{
            Attributes, Level, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
        };
        let record = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([9; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence * 1_000)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: "tick".try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap();
        ReceivedRecord {
            received_at_ms: Some(1_700_000_000_000 + sequence),
            record,
        }
    }

    fn page(cursor: u64, limit: usize) -> TelemetryReadRequest {
        TelemetryReadRequest::builder()
            .cursor(TelemetryCursor { offset: cursor })
            .limit(limit)
            .build()
    }

    async fn running(mock: &MockBackend, name: &str) -> MachineId {
        mock.run_machine(
            MachineSpec::builder(name, "oci:alpine:3.20")
                .unwrap()
                .build(),
        )
        .await
        .unwrap()
        .id
    }

    #[tokio::test]
    async fn telemetry_status_answers_what_was_set_and_unknown_is_not_found() {
        let mock = MockBackend::default();
        let id = running(&mock, "quiet").await;
        assert_eq!(
            mock.telemetry_status(&id).await.unwrap(),
            TelemetryStatus::NotProvisioned,
            "nothing set reads as no collector provisioned"
        );

        let collecting = TelemetryStatus::Provisioned {
            vm_name: "quiet".into(),
            state: CollectorState::Collecting { generation: 2 },
            shed: 1,
            losses: Default::default(),
            snapshot_age_ms: Some(400),
            records_bytes: 0,
        };
        mock.set_telemetry_status(&id, collecting.clone());
        assert_eq!(mock.telemetry_status(&id).await.unwrap(), collecting);

        let ghost = MachineId("ghost".into());
        assert!(matches!(
            mock.telemetry_status(&ghost).await,
            Err(MvmError::NotFound { .. })
        ));
        assert!(matches!(
            mock.telemetry_records(&ghost, TelemetryReadRequest::default())
                .await,
            Err(MvmError::NotFound { .. })
        ));
    }

    /// Cursors are the byte offsets the real reader hands out: each record
    /// advances the cursor by the length of the line the collector persists
    /// for it, so a consumer developed against the mock sees real values.
    #[tokio::test]
    async fn telemetry_records_page_by_the_persisted_byte_offset() {
        let mock = MockBackend::default();
        let id = running(&mock, "chatty").await;
        let records: Vec<ReceivedRecord> = (1..=3).map(telemetry_record).collect();
        let line_len = |r: &ReceivedRecord| {
            ReceivedRecord::sealed_line_len(r.received_at_ms.unwrap(), &r.record).unwrap()
        };
        let ends: Vec<u64> = records
            .iter()
            .scan(0, |end, r| {
                *end += line_len(r);
                Some(*end)
            })
            .collect();
        mock.push_telemetry_records(&id, records.clone());

        let first = mock.telemetry_records(&id, page(0, 2)).await.unwrap();
        assert_eq!(first.records, records[..2]);
        assert_eq!(first.next_cursor.offset, ends[1]);
        assert!(!first.exhausted);
        assert_eq!(first.undecodable, 0);

        let second = mock
            .telemetry_records(&id, page(first.next_cursor.offset, 10))
            .await
            .unwrap();
        assert_eq!(second.records, records[2..]);
        assert_eq!(second.next_cursor.offset, ends[2]);
        assert!(second.exhausted);

        let idle = mock
            .telemetry_records(&id, page(second.next_cursor.offset, 10))
            .await
            .unwrap();
        assert!(idle.records.is_empty());
        assert_eq!(idle.next_cursor, second.next_cursor, "an idle poll echoes");
        assert!(idle.exhausted);

        // More arrive; the held cursor picks them up.
        mock.push_telemetry_records(&id, [telemetry_record(4)]);
        let more = mock
            .telemetry_records(&id, page(idle.next_cursor.offset, 10))
            .await
            .unwrap();
        assert_eq!(more.records, [telemetry_record(4)]);
    }

    /// The real seam refuses a cursor that is not a line boundary of the
    /// current stream as `InvalidSpec`; the mock refuses it the same way, for
    /// a cursor inside a line, past the end, or into a stream since reset.
    #[tokio::test]
    async fn telemetry_records_refuse_a_cursor_off_a_line_boundary_or_past_a_reset() {
        let mock = MockBackend::default();
        let id = running(&mock, "rebooted").await;
        mock.push_telemetry_records(&id, (1..=2).map(telemetry_record));
        let all = mock.telemetry_records(&id, page(0, 10)).await.unwrap();
        let end = all.next_cursor.offset;

        for offset in [1, end + 1] {
            let err = mock
                .telemetry_records(&id, page(offset, 10))
                .await
                .unwrap_err();
            assert!(
                matches!(err, MvmError::InvalidSpec { .. }),
                "{offset}: {err}"
            );
        }

        mock.reset_telemetry_records(&id);
        let err = mock
            .telemetry_records(&id, page(end, 10))
            .await
            .unwrap_err();
        assert!(matches!(err, MvmError::InvalidSpec { .. }), "{err}");
        let fresh = mock.telemetry_records(&id, page(0, 10)).await.unwrap();
        assert!(fresh.records.is_empty());
        assert_eq!(fresh.next_cursor, TelemetryCursor::START);
        assert!(fresh.exhausted);
    }

    /// A machine nobody seeded behaves as one with no collector files at
    /// all: an empty page that echoes whatever cursor it was given.
    #[tokio::test]
    async fn telemetry_records_for_an_unseeded_machine_echo_the_cursor() {
        let mock = MockBackend::default();
        let id = running(&mock, "unseeded").await;
        let empty = mock.telemetry_records(&id, page(96, 10)).await.unwrap();
        assert!(empty.records.is_empty());
        assert_eq!(empty.next_cursor.offset, 96);
        assert!(empty.exhausted);
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
