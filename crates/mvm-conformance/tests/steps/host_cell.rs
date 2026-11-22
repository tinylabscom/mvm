//! Steps for host-held state cells on a real backend.
//!
//! The topology is admitted and the workload ledger is advanced by the test,
//! through the same host functions an operator path would call; nothing here
//! is reachable from the CLI. The guest side is a fixture script that speaks
//! the broker framing itself, since no guest library exports the service.

use std::path::Path;
use std::time::{Duration, Instant};

use cucumber::{given, when};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, StateCell, TOPOLOGY_SCHEMA_VERSION, Topology,
    Unit, UnitResources, UnitRole,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::host_interface::workload::WorkloadChange;
use mvm_core::plan::{TenantId, WorkloadId};
use mvm_hostd::topology_admission::{
    HostCpus, TopologyAdmissionRequest, admit_topology, sign_topology_as_host,
};

use crate::support::service_plane_fixture;
use crate::world::CliWorld;

/// The tenant every local launch runs under.
const TENANT: &str = "local";
const CELL: &str = "setpoint";
const CPUS: u32 = 1;
const MEMORY_MIB: u64 = 256;
/// Writes the writer makes after its first before the replace is committed,
/// so the reader has a later value to see.
const WRITES_BEFORE_FENCE: usize = 2;
const FENCE_DEADLINE: Duration = Duration::from_secs(300);

fn id(name: &str) -> WorkloadId {
    WorkloadId(name.to_string())
}

fn unit(name: &str, recipe: &Sha256Digest) -> Unit {
    Unit {
        workload: id(name),
        role: UnitRole::Worker,
        recipe: recipe.clone(),
        resources: UnitResources {
            cpus: CPUS,
            mem_mib: MEMORY_MIB,
            disk_mib: 0,
        },
        placement: CorePlacement::Floating,
        min_isolation: None,
        permits: SealedTransitions::default(),
        liveness_period_ms: None,
        require_isolated_cores: false,
    }
}

fn topology(writer: &str, reader: &str, recipe: &Sha256Digest) -> Topology {
    let now = mvm_core::time::Clock::now(&mvm_core::time::SystemClock);
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        // A live home may be reused across runs, and each admission must
        // carry a generation above the last.
        generation: now.timestamp().unsigned_abs(),
        valid_from: now - Duration::from_secs(3600),
        valid_until: now + Duration::from_secs(86_400),
        suite: CryptoSuite::CLASSICAL,
        units: vec![unit(writer, recipe), unit(reader, recipe)],
        standby_pairs: Vec::new(),
        cells: vec![StateCell {
            name: CELL.to_string(),
            writer: id(writer),
            readers: vec![id(reader)],
            size_bytes: std::num::NonZeroU64::new(64).unwrap(),
            update: Default::default(),
            per_write_audit: false,
        }],
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// The recipe a plan for the prepared image carries: the digest of the root
/// filesystem the launch boots.
///
/// shortcut: takes the only root filesystem under the home's OCI cache, so
/// the home must hold one prepared image; resolve the image reference to its
/// root filesystem if a scenario ever prepares two.
fn image_recipe(home: &Path) -> Sha256Digest {
    let root = mvm_core::config::mvm_cache_dir_at(home).join("oci/rootfs");
    let rootfs: Vec<_> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .filter_map(|entry| Some(entry.ok()?.path().join("rootfs.ext4")))
        .filter(|path| path.is_file())
        .collect();
    let [rootfs] = rootfs.as_slice() else {
        panic!(
            "expected one prepared root filesystem under {}, found {}",
            root.display(),
            rootfs.len()
        );
    };
    let hex = mvm_core::crypto::image_verify::sha256_file(rootfs)
        .unwrap_or_else(|error| panic!("hash {}: {error}", rootfs.display()));
    Sha256Digest::parse(format!("sha256:{hex}")).expect("sha256_file returns a hex digest")
}

#[given("the state-cell fixture is materialized as a read-only disk image")]
fn materialize_cell_fixture(world: &mut CliWorld) {
    let fixture_root =
        crate::steps::cli::workspace_root().join("features/suites/s30_service_plane/cell_fixtures");
    world.service_plane_fixture_disk = Some(service_plane_fixture::materialize(&fixture_root));
}

#[given(
    regex = r#"^the live home admits a topology where "([^"]+)" writes cell "setpoint" and "([^"]+)" reads it$"#
)]
fn admit_cell_topology(world: &mut CliWorld, writer: String, reader: String) {
    let home = crate::steps::cli::selected_live_home(world);
    let keys = mvm_core::config::mvm_keys_dir_at(&home);
    let signer = mvm_hostd::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
    let emitter =
        mvm_hostd::audit::emitter::AuditEmitter::with_dir(signer.signing, &home.join("audit"))
            .expect("audit emitter");
    let recipe = image_recipe(&home);
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(&home);
    admit_topology(&TopologyAdmissionRequest {
        tenant: &TenantId(TENANT.to_string()),
        signed: &sign_topology_as_host(&topology(&writer, &reader, &recipe), Some(&keys))
            .expect("sign the topology"),
        backend: BackendKind::Firecracker,
        measured_failover: None,
        host_cpus: &HostCpus::probe(&home),
        clock: &mvm_core::time::SystemClock,
        host_signer_keys_dir: Some(&keys),
        emitter: &emitter,
    })
    .expect("the topology is admitted");
}

fn cell_run_argv(world: &CliWorld, unit: &str, mode: &str) -> Vec<String> {
    let disk = world
        .service_plane_fixture_disk
        .as_ref()
        .expect("the fixture disk must be materialized before the live run");
    let image = service_plane_fixture::image_path(disk);
    [
        "machine",
        "run",
        "--name",
        unit,
        "--hypervisor",
        "firecracker",
        "--image",
        "python:3.12-alpine",
        "--cpus",
        &CPUS.to_string(),
        "--memory",
        &format!("{MEMORY_MIB}M"),
        "--host-service",
        "host.cell.v1",
        "--volume",
        &format!("{}:/work/fixtures:64M:ro", image.display()),
        "--timeout",
        "300",
        "--",
        "python3",
        "/work/fixtures/cell_probe.py",
        mode,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// How many later writes the writer has reported.
fn writes(stdout: &Path) -> usize {
    std::fs::read_to_string(stdout).map_or(0, |out| out.matches("CELL-WRITER-WROTE").count())
}

/// Advance `unit` from its current epoch in `home`'s ledger, through the
/// resident coordinator when one owns the ledger.
fn replace(home: &Path, unit: &str) {
    let current = mvm_core::host_interface::workload::WorkloadLedger::load_at(home)
        .expect("read the workload ledger")
        .entry(unit)
        .epoch;
    let change = WorkloadChange::Replace {
        workload: unit.to_string(),
        from_epoch: current,
    };
    match mvm_hostd::policy_generation::workload_store::OwnedWorkloadStore::open(home) {
        Ok(store) => drop(store.commit(&change).expect("commit the replace")),
        Err(_) => drop(
            mvm_hostd::policy_generation::coordinator::commit_workload(
                &mvm_hostd::policy_generation::coordinator::socket_path(home),
                &change,
            )
            .expect("commit the replace through the coordinator"),
        ),
    }
}

#[when(regex = r#"^the writer "([^"]+)" runs the cell fixture and its epoch is replaced mid-run$"#)]
fn run_writer_then_replace(world: &mut CliWorld, writer: String) {
    let argv = cell_run_argv(world, &writer, "writer");
    crate::steps::cli::run_mvmctl_isolated_live_home_during(world, argv, &mut |home, stdout| {
        let deadline = Instant::now() + FENCE_DEADLINE;
        while writes(stdout) < WRITES_BEFORE_FENCE {
            assert!(
                Instant::now() < deadline,
                "the writer did not report {WRITES_BEFORE_FENCE} writes in time"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        replace(home, &writer);
    });
}

#[when(regex = r#"^the reader "([^"]+)" runs the cell fixture$"#)]
fn run_reader(world: &mut CliWorld, reader: String) {
    let argv = cell_run_argv(world, &reader, "reader");
    crate::steps::cli::run_mvmctl_isolated_live_home_argv(world, argv);
}
