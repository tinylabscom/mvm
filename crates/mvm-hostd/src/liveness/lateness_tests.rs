//! How late a unit's liveness expiry is on this host.
//!
//! Each sample arms a deadline with one accepted signal, one shortest admitted
//! period ahead, and lets the unit timer a supervisor runs find it: the same
//! thread and wait, the system clocks, the deadline file on disk, and the
//! fence committed by a policy coordinator over its socket. Two instants are
//! taken against the stored deadline: when the coordinator's commit returned,
//! from which every gate refuses the epoch, and when the timer finished, with
//! the expiry on the tenant's chain and the deadline removed.
//!
//! A bare wait is timed beside them, so the part of the lateness that is the
//! scheduler waking a sleeping thread can be told from the part that is the
//! pass's own reads and durable writes. The lateness does not depend on the
//! period; the shortest one is used because it is the one the figure decides.
//!
//! [`MIN_LIVENESS_PERIOD_MS`] is derived from the fence figure. A sample
//! waits one period, so the run takes several minutes.
//!
//! A measurement, not a pin, and only meaningful from an optimised build:
//!
//! ```text
//! cargo test --release -p mvm-hostd --lib liveness::lateness_tests -- --nocapture
//! ```
//!
//! The scratch home is created under `TMPDIR`; point it at the disk the host
//! keeps its state on, since a memory-backed one makes every sync free.

use std::num::NonZeroU32;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::requirements::MIN_LIVENESS_PERIOD_MS;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Unit, UnitResources,
    UnitRole,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_contract::timestamp::UtcTimestamp;
use mvm_core::host_interface::workload::{WorkloadCommit, WorkloadLedger};
use mvm_core::time::SystemClock;

use super::*;
use crate::containment::CoordinatorWorkloads;
use crate::supervisor::lifecycle::liveness_expiry::{LivenessWatch, SystemMonotonic, UnitTimer};
use crate::topology_admission::{
    HostCpus, TopologyAdmissionRequest, admit_topology, sign_topology_as_host,
};

const TENANT: &str = "local";
const UNIT: &str = "controller";
const SAMPLES: usize = 200;
const WARMUP: usize = 3;
/// The bare wait timed for comparison.
const BARE_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

fn topology() -> Topology {
    let now = mvm_core::util::time::utc_timestamp_now();
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        generation: 1,
        valid_from: now
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap(),
        valid_until: now
            .checked_add(std::time::Duration::from_secs(86_400))
            .unwrap(),
        suite: CryptoSuite::CLASSICAL,
        units: vec![Unit {
            workload: WorkloadId(UNIT.to_string()),
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
            liveness_period_ms: NonZeroU32::new(MIN_LIVENESS_PERIOD_MS),
            require_isolated_cores: false,
        }],
        standby_pairs: Vec::new(),
        cells: Vec::new(),
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// The coordinator, noting when its commit returned.
struct Timed {
    inner: CoordinatorWorkloads,
    committed: Arc<Mutex<Option<UtcTimestamp>>>,
}

impl WorkloadAuthority for Timed {
    fn ledger(&self) -> Result<WorkloadLedger> {
        self.inner.ledger()
    }

    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        let commit = self.inner.commit(change)?;
        *self.committed.lock().unwrap() = Some(mvm_core::util::time::utc_timestamp_now());
        Ok(commit)
    }
}

/// Milliseconds from `from` to `to`.
fn ms_between(from: UtcTimestamp, to: UtcTimestamp) -> f64 {
    to.duration_since(from).unwrap().as_secs_f64() * 1e3
}

/// Nearest-rank percentile of sorted samples.
fn rank(sorted: &[f64], p: f64) -> f64 {
    let at = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[at - 1]
}

fn row(what: &str, samples: &[f64]) {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    println!(
        "| {what} | {} | {:.3} | {:.3} | {:.3} | {:.3} |",
        sorted.len(),
        rank(&sorted, 0.50),
        rank(&sorted, 0.95),
        rank(&sorted, 0.99),
        sorted[sorted.len() - 1],
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "a latency measurement; run with --release")]
fn report_how_late_an_expiry_fences_past_its_deadline() {
    let (_env, home) = crate::test_fixtures::isolated_mvm_home();
    let keys = mvm_core::config::mvm_keys_dir_at(home.path());
    let signer = crate::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
    let audit = Arc::new(
        AuditEmitter::with_dir(signer.signing.clone(), &home.path().join("audit"))
            .expect("emitter"),
    );
    let tenant = TenantId(TENANT.to_string());
    let unit = WorkloadId(UNIT.to_string());
    admit_topology(&TopologyAdmissionRequest {
        tenant: &tenant,
        signed: &sign_topology_as_host(&topology(), Some(&keys)).unwrap(),
        backend: BackendKind::Mock,
        measured_failover: None,
        host_cpus: &HostCpus {
            scope_cpuset: false,
            online: None,
            isolated: None,
            live: Vec::new(),
        },
        clock: &SystemClock,
        host_signer_keys_dir: Some(&keys),
        emitter: &audit,
    })
    .expect("admits");
    let socket = crate::policy_generation::coordinator::serve_in_process(home.path())
        .expect("a coordinator");
    let period = std::time::Duration::from_millis(u64::from(MIN_LIVENESS_PERIOD_MS));
    let signals = LivenessSignals {
        host_signer_keys_dir: None,
        audit: audit.as_ref(),
        clock: &SystemClock,
    };

    let (mut fenced, mut recorded) = (Vec::new(), Vec::new());
    for sample in 0..WARMUP + SAMPLES {
        let epoch = WorkloadLedger::load_at(home.path())
            .unwrap()
            .entry(UNIT)
            .epoch;
        signals
            .signal(&LivenessCaller {
                tenant: &tenant,
                unit: &unit,
                epoch,
            })
            .expect("the current epoch signals");
        let deadline = load(&tenant_path(home.path(), &tenant)).unwrap()[UNIT].deadline;
        let committed = Arc::new(Mutex::new(None));
        let timer = UnitTimer {
            liveness: Some(LivenessWatch {
                tenant: tenant.clone(),
                unit: unit.clone(),
                epoch,
                period,
                host_signer_keys_dir: None,
                emitter: Arc::clone(&audit),
                clock: Arc::new(SystemClock),
                authority: Box::new(Timed {
                    inner: CoordinatorWorkloads::new(socket.clone()),
                    committed: Arc::clone(&committed),
                }),
            }),
            digest: None,
            monotonic: Arc::new(SystemMonotonic::new()),
        };
        let (_stop, thread) = timer.spawn().expect("the timer thread");
        // The timer ends by itself once its epoch is fenced.
        thread.join().expect("the timer thread");
        let done = mvm_core::util::time::utc_timestamp_now();
        let committed = committed.lock().unwrap().expect("the expiry fenced");
        if sample >= WARMUP {
            fenced.push(ms_between(deadline, committed));
            recorded.push(ms_between(deadline, done));
        }
    }

    // The same wait the timer makes, with nothing to do when it returns.
    let (_idle, never) = channel::<()>();
    let wakes: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            assert_eq!(
                never.recv_timeout(BARE_WAIT),
                Err(RecvTimeoutError::Timeout)
            );
            (start.elapsed().as_secs_f64() - BARE_WAIT.as_secs_f64()) * 1e3
        })
        .collect();

    println!(
        "expiry lateness past a {MIN_LIVENESS_PERIOD_MS} ms deadline, {}",
        std::env::consts::ARCH
    );
    println!("| instant | samples | p50 ms | p95 ms | p99 ms | max ms |");
    println!("| --- | --- | --- | --- | --- | --- |");
    row("a 100 ms wait alone returns", &wakes);
    row("the epoch is fenced", &fenced);
    row("the expiry is recorded", &recorded);
}
