use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Unit, UnitResources,
    UnitRole,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_contract::timestamp::UtcTimestamp;
use mvm_core::host_interface::workload::WorkloadChange;
use mvm_core::time::Clock;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::emitter::AuditEmitter;
use crate::audit::host_keypair::HostSigner;
use crate::topology_admission::{
    HostCpus, RefusalStage, TopologyAdmission, TopologyAdmissionRequest, TopologyRefused,
    admit_topology, sign_topology_as_host,
};

const TENANT: &str = "acme";
const CELL: &str = "setpoint";

struct FixedClock(UtcTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> UtcTimestamp {
        self.0
    }
}

fn t0() -> UtcTimestamp {
    "2026-11-01T00:00:00Z".parse::<UtcTimestamp>().unwrap()
}

fn id(name: &str) -> WorkloadId {
    WorkloadId(name.to_string())
}

fn unit(name: &str) -> Unit {
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
        liveness_period_ms: None,
        require_isolated_cores: false,
    }
}

/// Units `controller`, `reader` and `stranger`; one 16-byte cell the
/// controller writes and `reader` reads.
fn topology(generation: u64, size: u64) -> Topology {
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        generation,
        valid_from: t0(),
        valid_until: t0()
            .checked_add(std::time::Duration::from_secs(2_592_000))
            .unwrap(),
        suite: CryptoSuite::CLASSICAL,
        units: vec![unit("controller"), unit("reader"), unit("stranger")],
        standby_pairs: Vec::new(),
        cells: vec![StateCell {
            name: CELL.to_string(),
            writer: id("controller"),
            readers: vec![id("reader")],
            size_bytes: NonZeroU64::new(size).unwrap(),
            update: Default::default(),
            per_write_audit: false,
        }],
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// A host with its own `MVM_HOME`, signer and chain, so nothing here reaches
/// the real home.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
    _signer: HostSigner,
    emitter: AuditEmitter,
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
        }
    }

    /// A host with [`topology`] admitted at generation 1.
    fn admitted() -> Self {
        let host = Self::new();
        host.admit(&topology(1, 16)).expect("admits");
        host
    }

    fn admit(&self, topology: &Topology) -> Result<TopologyAdmission> {
        let keys = keys_dir(self.home.path());
        admit_topology(&TopologyAdmissionRequest {
            tenant: &TenantId(TENANT.to_string()),
            signed: &sign_topology_as_host(topology, Some(&keys)).unwrap(),
            backend: BackendKind::Mock,
            measured_failover: None,
            host_cpus: &HostCpus {
                scope_cpuset: false,
                online: None,
                isolated: None,
                live: Vec::new(),
            },
            clock: &FixedClock(
                t0().checked_add(std::time::Duration::from_secs(86_400))
                    .unwrap(),
            ),
            host_signer_keys_dir: Some(&keys),
            emitter: &self.emitter,
        })
    }

    fn cells(&self) -> StateCells<'_> {
        StateCells {
            host_signer_keys_dir: None,
            audit: &self.emitter,
        }
    }

    fn path(&self) -> PathBuf {
        cell_path(self.home.path(), &TenantId(TENANT.to_string()), CELL)
    }

    fn commit(&self, change: WorkloadChange) {
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(self.home.path())
            .unwrap()
            .commit(&change)
            .unwrap();
    }

    fn replace(&self, workload: &str, from: u64) {
        self.commit(WorkloadChange::Replace {
            workload: workload.to_string(),
            from_epoch: epoch(from),
        });
    }

    fn refused_events(&self) -> Vec<serde_json::Value> {
        let path = self
            .home
            .path()
            .join("audit")
            .join(format!("{TENANT}.jsonl"));
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .filter(|entry| entry["event"] == STATE_CELL_REFUSED_EVENT)
            .collect()
    }
}

fn keys_dir(home: &Path) -> PathBuf {
    mvm_core::config::mvm_keys_dir_at(home)
}

fn epoch(n: u64) -> ExecutionEpoch {
    ExecutionEpoch::new(n).unwrap()
}

fn tenant() -> TenantId {
    TenantId(TENANT.to_string())
}

fn as_unit<'a>(tenant: &'a TenantId, unit: &'a WorkloadId, at: u64) -> CellCaller<'a> {
    CellCaller {
        tenant,
        unit,
        epoch: epoch(at),
        cell: CELL,
    }
}

fn refusal(err: &anyhow::Error) -> &CellRefusal {
    err.downcast_ref::<CellRefusal>()
        .unwrap_or_else(|| panic!("expected a cell refusal, got {err:#}"))
}

fn value(version: u64, bytes: &[u8]) -> CellValue {
    CellValue {
        version,
        value: bytes.to_vec(),
    }
}

#[test]
fn admission_reserves_each_cell_privately_at_full_size() {
    let host = Host::admitted();
    let path = host.path();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.len(), slots::file_len(16));
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let dir = mvm_core::config::state_cells_dir_at(host.home.path());
    assert_eq!(
        std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let (t, controller) = (tenant(), id("controller"));
    assert_eq!(
        host.cells().read(&as_unit(&t, &controller, 1)).unwrap(),
        value(0, b""),
        "a reserved cell holds the empty value at version 0"
    );
}

#[test]
fn the_writer_writes_and_the_writer_and_readers_read_it_back_after_a_restart() {
    let host = Host::admitted();
    let (t, controller, reader) = (tenant(), id("controller"), id("reader"));
    host.cells()
        .write(&as_unit(&t, &controller, 1), 1, b"open")
        .unwrap();
    host.cells()
        .write(&as_unit(&t, &controller, 1), 5, b"closed")
        .unwrap();

    // Nothing is held in memory between calls; a new service over a new
    // emitter is what a restarted host process has.
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path())).unwrap();
    let emitter = AuditEmitter::with_dir(signer.signing, &host.home.path().join("audit")).unwrap();
    let restarted = StateCells {
        host_signer_keys_dir: None,
        audit: &emitter,
    };
    for unit in [&controller, &reader] {
        assert_eq!(
            restarted.read(&as_unit(&t, unit, 1)).unwrap(),
            value(5, b"closed")
        );
    }
    assert!(host.refused_events().is_empty());
}

#[test]
fn a_reader_cannot_write_and_a_stranger_cannot_read_and_both_are_audited() {
    let host = Host::admitted();
    let (t, reader, stranger) = (tenant(), id("reader"), id("stranger"));

    let err = host
        .cells()
        .write(&as_unit(&t, &reader, 1), 1, b"x")
        .unwrap_err();
    assert_eq!(
        refusal(&err),
        &CellRefusal::NotWriter {
            cell: CELL.into(),
            unit: reader.clone()
        }
    );
    let err = host.cells().read(&as_unit(&t, &stranger, 1)).unwrap_err();
    assert_eq!(
        refusal(&err),
        &CellRefusal::NotReader {
            cell: CELL.into(),
            unit: stranger.clone()
        }
    );

    let events = host.refused_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["labels"]["operation"], "write");
    assert_eq!(events[0]["labels"]["unit"], "reader");
    assert_eq!(events[1]["labels"]["operation"], "read");
    assert_eq!(events[1]["labels"]["unit"], "stranger");
    assert_eq!(events[1]["labels"]["cell"], CELL);
}

#[test]
fn a_cell_the_topology_does_not_declare_is_refused() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    let caller = CellCaller {
        cell: "elsewhere",
        ..as_unit(&t, &controller, 1)
    };
    let err = host.cells().write(&caller, 1, b"x").unwrap_err();
    assert_eq!(
        refusal(&err),
        &CellRefusal::UnknownCell {
            cell: "elsewhere".into()
        }
    );

    // The test environment lock is not reentrant: one host at a time.
    drop(host);
    let none = Host::new();
    let err = none.cells().read(&as_unit(&t, &controller, 1)).unwrap_err();
    assert!(matches!(refusal(&err), CellRefusal::UnknownCell { .. }));
    assert_eq!(none.refused_events().len(), 1);
}

#[test]
fn a_standby_epoch_is_refused_until_promoted() {
    let host = Host::admitted();
    let (t, controller, reader) = (tenant(), id("controller"), id("reader"));
    let err = host
        .cells()
        .write(&as_unit(&t, &controller, 2), 1, b"x")
        .unwrap_err();
    assert!(matches!(
        refusal(&err),
        CellRefusal::Epoch {
            denial: Denial::EpochNotPromoted { got: 2, current: 1 },
            ..
        }
    ));
    let err = host.cells().read(&as_unit(&t, &reader, 2)).unwrap_err();
    assert!(matches!(
        refusal(&err),
        CellRefusal::Epoch {
            denial: Denial::EpochNotPromoted { .. },
            ..
        }
    ));
    assert_eq!(host.refused_events().len(), 2);
}

#[test]
fn a_replaced_writer_epoch_is_fenced_and_its_successor_reads_and_writes_on() {
    let host = Host::admitted();
    let (t, controller, reader) = (tenant(), id("controller"), id("reader"));
    host.cells()
        .write(&as_unit(&t, &controller, 1), 3, b"before")
        .unwrap();

    host.replace("controller", 1);

    let err = host
        .cells()
        .write(&as_unit(&t, &controller, 1), 4, b"late")
        .unwrap_err();
    assert!(matches!(
        refusal(&err),
        CellRefusal::Epoch {
            denial: Denial::StaleEpoch { got: 1, current: 2 },
            ..
        }
    ));
    assert!(host.cells().read(&as_unit(&t, &controller, 1)).is_err());

    let successor = as_unit(&t, &controller, 2);
    assert_eq!(
        host.cells().read(&successor).unwrap(),
        value(3, b"before"),
        "the cell survives the epoch"
    );
    host.cells().write(&successor, 4, b"after").unwrap();
    assert_eq!(
        host.cells().read(&as_unit(&t, &reader, 1)).unwrap(),
        value(4, b"after"),
        "a reader's own epoch is untouched by the writer's replacement"
    );
}

#[test]
fn a_quarantined_writer_is_refused_at_its_current_epoch() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    host.commit(WorkloadChange::Quarantine {
        workload: "controller".to_string(),
    });
    let err = host
        .cells()
        .write(&as_unit(&t, &controller, 1), 1, b"x")
        .unwrap_err();
    assert!(matches!(
        refusal(&err),
        CellRefusal::Epoch {
            denial: Denial::WorkloadQuarantined(_),
            ..
        }
    ));
}

#[test]
fn a_version_that_does_not_rise_or_a_value_over_the_size_is_refused_unaudited() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    let writer = as_unit(&t, &controller, 1);
    host.cells().write(&writer, 2, b"two").unwrap();
    for version in [0, 1, 2] {
        let err = host.cells().write(&writer, version, b"x").unwrap_err();
        assert_eq!(
            refusal(&err),
            &CellRefusal::VersionNotIncreasing {
                cell: CELL.into(),
                got: version,
                stored: 2
            }
        );
    }
    host.cells().write(&writer, 3, &[1; 16]).unwrap();
    let err = host.cells().write(&writer, 4, &[1; 17]).unwrap_err();
    assert_eq!(
        refusal(&err),
        &CellRefusal::TooLarge {
            cell: CELL.into(),
            len: 17,
            size: 16
        }
    );
    assert_eq!(host.cells().read(&writer).unwrap(), value(3, &[1; 16]));
    assert!(host.refused_events().is_empty());
}

fn overwrite(path: &Path, at: u64, bytes: &[u8]) {
    use std::io::{Seek as _, Write as _};
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(std::io::SeekFrom::Start(at)).unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn a_torn_write_leaves_the_last_value_and_a_corrupt_file_is_refused() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    let writer = as_unit(&t, &controller, 1);
    // Version 1 lands in the second slot, so the next write targets the first.
    host.cells().write(&writer, 1, b"kept").unwrap();
    let path = host.path();
    overwrite(&path, 10, b"half a write");
    assert_eq!(host.cells().read(&writer).unwrap(), value(1, b"kept"));
    host.cells().write(&writer, 2, b"next").unwrap();
    assert_eq!(host.cells().read(&writer).unwrap(), value(2, b"next"));

    let half = slots::file_len(16) / 2;
    overwrite(&path, 10, b"torn");
    overwrite(&path, half + 10, b"torn");
    let err = host.cells().read(&writer).unwrap_err();
    assert!(format!("{err:#}").contains("neither slot"), "{err:#}");
    assert!(host.cells().write(&writer, 3, b"x").is_err());

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(half)
        .unwrap();
    let err = host.cells().read(&writer).unwrap_err();
    assert!(format!("{err:#}").contains("reserved for it"), "{err:#}");
}

#[test]
fn concurrent_writers_are_serialised_by_the_cell_lock() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    let writer = as_unit(&t, &controller, 1);
    let cells = host.cells();
    let accepted: Vec<u64> = std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=16u64)
            .map(|version| {
                let cells = &cells;
                scope.spawn(
                    move || match cells.write(&writer, version, &version.to_le_bytes()) {
                        Ok(()) => Some(version),
                        Err(err) => {
                            assert!(
                                matches!(refusal(&err), CellRefusal::VersionNotIncreasing { .. }),
                                "{err:#}"
                            );
                            None
                        }
                    },
                )
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .collect()
    });
    assert!(accepted.contains(&16), "the highest version always lands");
    assert_eq!(
        cells.read(&writer).unwrap(),
        value(16, &16u64.to_le_bytes())
    );
}

#[test]
fn a_later_generation_inherits_a_cell_and_a_resized_one_is_refused() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    host.cells()
        .write(&as_unit(&t, &controller, 1), 1, b"kept")
        .unwrap();
    host.admit(&topology(2, 16)).expect("same size admits");
    assert_eq!(
        host.cells().read(&as_unit(&t, &controller, 1)).unwrap(),
        value(1, b"kept")
    );

    let err = host.admit(&topology(3, 32)).unwrap_err();
    let refused = err.downcast_ref::<TopologyRefused>().unwrap();
    assert_eq!(refused.stage, RefusalStage::StateCells);
    assert!(
        refused.reason.contains("another size"),
        "{}",
        refused.reason
    );
    assert_eq!(
        host.cells().read(&as_unit(&t, &controller, 1)).unwrap(),
        value(1, b"kept"),
        "the refused generation changed nothing"
    );
}

#[test]
fn admission_refuses_a_cell_it_cannot_reserve_and_keeps_nothing() {
    let host = Host::new();
    let err = host.admit(&topology(1, MAX_CELL_BYTES + 1)).unwrap_err();
    assert_eq!(
        err.downcast_ref::<TopologyRefused>().unwrap().stage,
        RefusalStage::StateCells
    );

    // A file where the tenant's directory belongs: nothing can be reserved.
    drop(host);
    let host = Host::new();
    let root = mvm_core::config::state_cells_dir_at(host.home.path());
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(TENANT), b"").unwrap();
    let err = host.admit(&topology(1, 16)).unwrap_err();
    assert_eq!(
        err.downcast_ref::<TopologyRefused>().unwrap().stage,
        RefusalStage::StateCells
    );
    assert!(
        !mvm_core::config::topologies_dir_at(host.home.path())
            .join(TENANT)
            .exists(),
        "no generation was sealed"
    );
}

fn named_cell(name: &str, size: u64) -> StateCell {
    StateCell {
        name: name.to_string(),
        writer: id("controller"),
        readers: Vec::new(),
        size_bytes: NonZeroU64::new(size).unwrap(),
        update: Default::default(),
        per_write_audit: false,
    }
}

#[test]
fn a_topology_over_the_cell_count_or_byte_ceiling_is_refused_by_name() {
    let mut many = topology(1, 16);
    many.cells = (0..=MAX_CELLS_PER_TOPOLOGY)
        .map(|n| named_cell(&format!("c{n:03}"), 1))
        .collect();
    assert_eq!(
        check_limits(&many),
        Err(ReservationLimit::TooManyCells {
            count: MAX_CELLS_PER_TOPOLOGY + 1
        })
    );

    let mut large = topology(1, 16);
    large.cells = (0..32)
        .map(|n| named_cell(&format!("c{n:02}"), MAX_CELL_BYTES))
        .collect();
    assert_eq!(
        check_limits(&large),
        Err(ReservationLimit::TooManyBytes {
            bytes: 32 * slots::file_len(MAX_CELL_BYTES)
        })
    );
    assert_eq!(
        check_limits(&topology(1, MAX_CELL_BYTES + 1)),
        Err(ReservationLimit::CellTooLarge {
            cell: CELL.into(),
            size: MAX_CELL_BYTES + 1
        })
    );

    let host = Host::new();
    let err = host.admit(&large).unwrap_err();
    let refused = err.downcast_ref::<TopologyRefused>().unwrap();
    assert_eq!(refused.stage, RefusalStage::StateCells);
    assert!(refused.reason.contains("per tenant"), "{}", refused.reason);
    assert!(
        !mvm_core::config::state_cells_dir_at(host.home.path()).exists(),
        "nothing was reserved"
    );
}

#[test]
fn a_generation_that_drops_a_cell_removes_it_and_refuses_its_use() {
    let host = Host::admitted();
    let (t, controller) = (tenant(), id("controller"));
    host.cells()
        .write(&as_unit(&t, &controller, 1), 1, b"old")
        .unwrap();
    let dropped = host.path();

    let mut next = topology(2, 16);
    next.cells = vec![named_cell("other", 8)];
    host.admit(&next).expect("admits");

    assert!(!dropped.exists(), "the dropped cell's storage is released");
    assert!(cell_path(host.home.path(), &t, "other").exists());
    let err = host.cells().read(&as_unit(&t, &controller, 1)).unwrap_err();
    assert!(matches!(refusal(&err), CellRefusal::UnknownCell { .. }));
}
