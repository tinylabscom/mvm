use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use chrono::{Duration, TimeZone};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, StateCell, TOPOLOGY_SCHEMA_VERSION, Unit,
    UnitResources, UnitRole,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::host_interface::workload::WorkloadLedger;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::host_keypair::HostSigner;
use crate::policy_generation::workload_store::OwnedWorkloadStore;
use crate::state_cells::{CellCaller, CellRefusal, StateCells};
use crate::topology_admission::{
    HostCpus, RefusalStage, TopologyAdmission, TopologyAdmissionRequest, TopologyRefused,
    admit_topology, sign_topology_as_host,
};

const TENANT: &str = "acme";
const PERIOD_MS: u32 = 1_000;

/// A clock the test moves by hand.
struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn advance_ms(&self, ms: i64) {
        let mut now = self.0.lock().unwrap();
        *now += Duration::milliseconds(ms);
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap()
}

fn id(name: &str) -> WorkloadId {
    WorkloadId(name.to_string())
}

fn epoch(n: u64) -> ExecutionEpoch {
    ExecutionEpoch::new(n).unwrap()
}

fn tenant() -> TenantId {
    TenantId(TENANT.to_string())
}

fn unit(name: &str, period_ms: Option<u32>) -> Unit {
    Unit {
        workload: id(name),
        role: UnitRole::Worker,
        recipe: Sha256Digest::from_bytes(&[7; 32]),
        resources: UnitResources {
            cpus: 1,
            mem_mib: 64,
            disk_mib: 64,
        },
        placement: CorePlacement::Floating,
        min_isolation: None,
        permits: SealedTransitions::default(),
        liveness_period_ms: period_ms.and_then(NonZeroU32::new),
        require_isolated_cores: false,
    }
}

/// `controller` declares a liveness period and writes cell `setpoint`;
/// `reader` declares none.
fn topology(generation: u64, period_ms: u32) -> Topology {
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: tenant(),
        generation,
        valid_from: t0(),
        valid_until: t0() + Duration::days(30),
        suite: CryptoSuite::CLASSICAL,
        units: vec![unit("controller", Some(period_ms)), unit("reader", None)],
        standby_pairs: Vec::new(),
        cells: vec![StateCell {
            name: "setpoint".to_string(),
            writer: id("controller"),
            readers: Vec::new(),
            size_bytes: NonZeroU64::new(16).unwrap(),
            update: Default::default(),
            per_write_audit: false,
        }],
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// A host with its own `MVM_HOME`, signer, chain and clock. One per test: the
/// test environment lock is not reentrant.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
    _signer: HostSigner,
    emitter: AuditEmitter,
    clock: TestClock,
}

impl Host {
    fn new() -> Self {
        let (env, home) = crate::test_fixtures::isolated_mvm_home();
        let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(home.path()))
            .expect("host signer");
        let emitter = AuditEmitter::with_dir(signer.signing.clone(), &home.path().join("audit"))
            .expect("emitter");
        Self {
            _env: env,
            home,
            _signer: signer,
            emitter,
            clock: TestClock(Mutex::new(t0() + Duration::days(1))),
        }
    }

    /// A host with [`topology`] admitted on the mock backend.
    fn admitted() -> Self {
        let host = Self::new();
        host.admit(&topology(1, PERIOD_MS), BackendKind::Mock)
            .expect("admits");
        host
    }

    fn admit(&self, topology: &Topology, backend: BackendKind) -> Result<TopologyAdmission> {
        let keys = keys_dir(self.home.path());
        admit_topology(&TopologyAdmissionRequest {
            tenant: &tenant(),
            signed: &sign_topology_as_host(topology, Some(&keys)).unwrap(),
            backend,
            measured_failover: None,
            host_cpus: &HostCpus {
                scope_cpuset: false,
                online: None,
                isolated: None,
                live: Vec::new(),
            },
            clock: &self.clock,
            host_signer_keys_dir: Some(&keys),
            emitter: &self.emitter,
        })
    }

    fn deadlines(&self) -> LivenessDeadlines<'_> {
        LivenessDeadlines {
            host_signer_keys_dir: None,
            emitter: &self.emitter,
            clock: &self.clock,
        }
    }

    fn store(&self) -> OwnedWorkloadStore {
        OwnedWorkloadStore::open(self.home.path()).unwrap()
    }

    fn signal(&self, unit: &str, at: u64) -> Result<()> {
        let (t, u) = (tenant(), id(unit));
        self.deadlines().signal(&LivenessCaller {
            tenant: &t,
            unit: &u,
            epoch: epoch(at),
        })
    }

    fn expire(&self) -> Vec<Expiry> {
        let pass = self
            .deadlines()
            .expire(&self.store())
            .expect("the pass runs");
        assert!(pass.failures.is_empty(), "{:?}", pass.failures);
        pass.expired
    }

    fn current(&self, unit: &str) -> ExecutionEpoch {
        WorkloadLedger::load_at(self.home.path())
            .unwrap()
            .entry(unit)
            .epoch
    }

    fn events(&self, event: &str) -> Vec<serde_json::Value> {
        let path = self
            .home
            .path()
            .join("audit")
            .join(format!("{TENANT}.jsonl"));
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .filter(|entry| entry["event"] == event)
            .collect()
    }

    fn path(&self) -> PathBuf {
        tenant_path(self.home.path(), &tenant())
    }
}

fn keys_dir(home: &Path) -> PathBuf {
    mvm_core::config::mvm_keys_dir_at(home)
}

fn refusal(err: &anyhow::Error) -> &LivenessRefusal {
    err.downcast_ref::<LivenessRefusal>()
        .unwrap_or_else(|| panic!("expected a liveness refusal, got {err:#}"))
}

#[test]
fn each_signal_moves_the_deadline_a_period_on() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    for _ in 0..3 {
        host.clock.advance_ms(i64::from(PERIOD_MS) - 1);
        assert!(host.expire().is_empty(), "the deadline has not passed");
        host.signal("controller", 1).unwrap();
    }
    assert_eq!(host.current("controller"), epoch(1));
    assert!(host.events(LIVENESS_SIGNAL_REFUSED_EVENT).is_empty());
    let dir = mvm_core::config::liveness_dir_at(host.home.path());
    assert_eq!(
        std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn a_missed_deadline_fences_the_epoch_for_every_gate_and_is_audited_once() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS));

    let expired = host.expire();
    assert_eq!(
        expired,
        vec![Expiry {
            tenant: tenant(),
            unit: id("controller"),
            fenced: epoch(1),
            current: epoch(2),
        }]
    );
    assert_eq!(host.current("controller"), epoch(2));
    assert_eq!(host.current("reader"), epoch(1), "a bystander is untouched");

    let err = host.signal("controller", 1).unwrap_err();
    assert!(matches!(
        refusal(&err),
        LivenessRefusal::Epoch {
            denial: Denial::StaleEpoch { got: 1, current: 2 },
            ..
        }
    ));
    let (t, controller) = (tenant(), id("controller"));
    let cells = StateCells {
        host_signer_keys_dir: None,
        emitter: &host.emitter,
    };
    let err = cells
        .write(
            &CellCaller {
                tenant: &t,
                unit: &controller,
                epoch: epoch(1),
                cell: "setpoint",
            },
            1,
            b"x",
        )
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<CellRefusal>(),
        Some(CellRefusal::Epoch {
            denial: Denial::StaleEpoch { got: 1, current: 2 },
            ..
        })
    ));

    let events = host.events(LIVENESS_EPOCH_REPLACED_EVENT);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["labels"]["unit"], "controller");
    assert_eq!(events[0]["labels"]["fenced_epoch"], "1");
    assert_eq!(events[0]["labels"]["epoch"], "2");
}

#[test]
fn repeated_passes_and_a_restart_commit_the_expiry_once() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) * 5);
    assert_eq!(host.expire().len(), 1);
    assert!(host.expire().is_empty());

    // A restarted host process holds nothing in memory.
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path())).unwrap();
    let emitter = AuditEmitter::with_dir(signer.signing, &host.home.path().join("audit")).unwrap();
    let restarted = LivenessDeadlines {
        host_signer_keys_dir: None,
        emitter: &emitter,
        clock: &host.clock,
    };
    let pass = restarted.expire(&host.store()).unwrap();
    assert!(pass.expired.is_empty() && pass.failures.is_empty());
    assert_eq!(host.current("controller"), epoch(2));
    assert_eq!(host.events(LIVENESS_EPOCH_REPLACED_EVENT).len(), 1);
}

#[test]
fn a_restarted_host_keeps_a_running_deadline_rather_than_restarting_it() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) / 2);

    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path())).unwrap();
    let emitter = AuditEmitter::with_dir(signer.signing, &host.home.path().join("audit")).unwrap();
    let restarted = LivenessDeadlines {
        host_signer_keys_dir: None,
        emitter: &emitter,
        clock: &host.clock,
    };
    assert!(restarted.expire(&host.store()).unwrap().expired.is_empty());
    host.clock.advance_ms(i64::from(PERIOD_MS) / 2);
    assert_eq!(restarted.expire(&host.store()).unwrap().expired.len(), 1);
}

#[test]
fn a_pass_interrupted_after_its_commit_reports_on_the_next_pass_without_committing_again() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    // What a pass leaves when it stops between the commit and the chain entry.
    let mut deadlines = load(&host.path()).unwrap();
    deadlines.get_mut("controller").unwrap().state = State::Fencing;
    store(&host.path(), &deadlines).unwrap();
    host.store()
        .commit(&WorkloadChange::Replace {
            workload: "controller".to_string(),
            from_epoch: epoch(1),
        })
        .unwrap();

    let expired = host.expire();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].current, epoch(2));
    assert_eq!(
        host.current("controller"),
        epoch(2),
        "no second replacement"
    );
    assert_eq!(host.events(LIVENESS_EPOCH_REPLACED_EVENT).len(), 1);
    assert!(load(&host.path()).unwrap().is_empty());
}

#[test]
fn a_late_signal_is_refused_and_the_next_pass_still_fences() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS));
    let err = host.signal("controller", 1).unwrap_err();
    assert_eq!(
        refusal(&err),
        &LivenessRefusal::DeadlinePassed {
            unit: id("controller")
        }
    );
    assert_eq!(host.expire().len(), 1);
    assert_eq!(host.events(LIVENESS_SIGNAL_REFUSED_EVENT).len(), 1);
}

#[test]
fn a_clock_found_behind_the_last_signal_counts_as_expired() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(-1);
    assert_eq!(host.expire().len(), 1);
}

#[test]
fn the_replacement_epoch_is_armed_by_its_own_first_signal() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS));
    assert_eq!(host.expire().len(), 1);

    host.signal("controller", 2).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS));
    let expired = host.expire();
    assert_eq!(expired.len(), 1);
    assert_eq!(
        (expired[0].fenced, expired[0].current),
        (epoch(2), epoch(3))
    );
}

#[test]
fn stale_standby_and_undeclared_signals_are_refused_and_audited() {
    let host = Host::admitted();
    let err = host.signal("controller", 2).unwrap_err();
    assert!(matches!(
        refusal(&err),
        LivenessRefusal::Epoch {
            denial: Denial::EpochNotPromoted { got: 2, current: 1 },
            ..
        }
    ));
    let err = host.signal("reader", 1).unwrap_err();
    assert_eq!(
        refusal(&err),
        &LivenessRefusal::NoPeriod { unit: id("reader") }
    );
    let err = host.signal("stranger", 1).unwrap_err();
    assert!(matches!(refusal(&err), LivenessRefusal::NoPeriod { .. }));

    let events = host.events(LIVENESS_SIGNAL_REFUSED_EVENT);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["labels"]["unit"], "controller");
    assert_eq!(events[0]["labels"]["epoch"], "2");
    assert!(!host.path().exists(), "no refused signal arms a deadline");
}

#[test]
fn a_quarantined_unit_cannot_signal_and_its_expiry_does_not_lift_the_quarantine() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.store()
        .commit(&WorkloadChange::Quarantine {
            workload: "controller".to_string(),
        })
        .unwrap();
    let err = host.signal("controller", 1).unwrap_err();
    assert!(matches!(
        refusal(&err),
        LivenessRefusal::Epoch {
            denial: Denial::WorkloadQuarantined(_),
            ..
        }
    ));
    assert_eq!(host.events(LIVENESS_SIGNAL_REFUSED_EVENT).len(), 1);

    host.clock.advance_ms(i64::from(PERIOD_MS) * 2);
    assert!(host.expire().is_empty());
    let entry = WorkloadLedger::load_at(host.home.path())
        .unwrap()
        .entry("controller");
    assert!(entry.quarantined);
    assert_eq!(entry.epoch, epoch(1));
}

#[test]
fn a_unit_replaced_by_someone_else_is_not_reported_as_expired() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    host.store()
        .commit(&WorkloadChange::Replace {
            workload: "controller".to_string(),
            from_epoch: epoch(1),
        })
        .unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) * 2);
    assert!(host.expire().is_empty());
    assert_eq!(host.current("controller"), epoch(2));
    assert!(host.events(LIVENESS_EPOCH_REPLACED_EVENT).is_empty());
}

#[test]
fn a_generation_that_drops_the_period_stops_watching_the_unit() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    let mut next = topology(2, PERIOD_MS);
    next.units[0].liveness_period_ms = None;
    host.admit(&next, BackendKind::Mock).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) * 2);
    assert!(host.expire().is_empty());
    assert_eq!(host.current("controller"), epoch(1));
    assert!(load(&host.path()).unwrap().is_empty());
}

#[test]
fn admission_refuses_a_period_no_backend_deadline_or_host_range_serves() {
    let host = Host::new();
    let stage_and_reason = |result: Result<TopologyAdmission>| {
        let err = result.unwrap_err();
        let refused = err
            .downcast_ref::<TopologyRefused>()
            .unwrap_or_else(|| panic!("expected a refusal, got {err:#}"));
        (refused.stage, refused.reason.clone())
    };
    let (stage, reason) =
        stage_and_reason(host.admit(&topology(1, PERIOD_MS), BackendKind::Firecracker));
    assert_eq!(stage, RefusalStage::Requirements);
    assert!(reason.contains("holds no liveness deadline"), "{reason}");

    let (stage, reason) = stage_and_reason(host.admit(&topology(1, 99), BackendKind::Mock));
    assert_eq!(stage, RefusalStage::Requirements);
    assert!(reason.contains("99 ms liveness period"), "{reason}");

    assert!(matches!(
        host.admit(&topology(1, PERIOD_MS), BackendKind::Mock),
        Ok(TopologyAdmission::Admitted(_))
    ));
}
