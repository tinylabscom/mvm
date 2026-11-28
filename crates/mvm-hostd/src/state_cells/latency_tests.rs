//! What one state-cell write and read cost on this host.
//!
//! The end-to-end figure is taken through the broker path a guest call takes
//! once the backend has spliced its vsock stream onto the broker's socket: a
//! fresh connection, one framed call, the server's epoch check, dispatch, the
//! store's topology read and verification, its own epoch check, the cell lock,
//! the slot write and its sync, and the framed reply. Transit across the guest
//! boundary is not included; it is the backend's, not the cell service's.
//!
//! The same operations are then timed piece by piece, in process, so the
//! end-to-end figure can be attributed. The sync is timed on a scratch file
//! of one slot's length in the cell directory, since a commit cannot be timed
//! without its sync.
//!
//! A measurement, not a pin, and only meaningful from an optimised build:
//!
//! ```text
//! cargo test --release -p mvm-hostd --lib state_cells::latency_tests -- --nocapture
//! ```
//!
//! With `MVM_STATE_CELL_LATENCY_OUT=<file>` it also writes the largest cell's
//! end-to-end write samples, which `mvmctl bench report --state-cell-latency`
//! folds into the resource report.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Unit, UnitResources,
    UnitRole,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::protocol::handler::CallEpoch;
use mvm_core::protocol::host_cell::{CellReadRequest, CellWriteRequest, HOST_CELL_SERVICE};

use super::*;
use crate::audit::emitter::AuditEmitter;
use crate::broker::epoch::BrokerEpochGate;
use crate::broker::registry::Registry;
use crate::topology_admission::{
    HostCpus, TopologyAdmissionRequest, admit_topology, sign_topology_as_host,
};

const TENANT: &str = "local";
const WRITER: &str = "controller";
const SAMPLES: usize = 200;
const SIZES: [u64; 4] = [64, 1024, 8 * 1024, MAX_CELL_BYTES];
const OUT_ENV: &str = "MVM_STATE_CELL_LATENCY_OUT";

/// Zero-padded, so the names sort in [`SIZES`] order as a topology requires.
fn cell_name(size: u64) -> String {
    format!("cell-{size:05}")
}

/// One writer unit and one cell per measured size.
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
            workload: WorkloadId(WRITER.to_string()),
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
        }],
        standby_pairs: Vec::new(),
        cells: SIZES
            .iter()
            .map(|&size| StateCell {
                name: cell_name(size),
                writer: WorkloadId(WRITER.to_string()),
                readers: Vec::new(),
                size_bytes: std::num::NonZeroU64::new(size).unwrap(),
                update: Default::default(),
                per_write_audit: false,
            })
            .collect(),
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// Milliseconds since `start`.
fn ms_since(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

/// Nearest-rank percentile of sorted samples.
fn rank(sorted: &[f64], p: f64) -> f64 {
    let at = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[at - 1]
}

fn row(op: &str, size: u64, samples: &[f64]) {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    println!(
        "| {op} | {size} | {} | {:.3} | {:.3} | {:.3} | {:.3} |",
        sorted.len(),
        rank(&sorted, 0.50),
        rank(&sorted, 0.95),
        rank(&sorted, 0.99),
        sorted[sorted.len() - 1],
    );
}

/// Time `op` [`SAMPLES`] times.
fn time(mut op: impl FnMut()) -> Vec<f64> {
    (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            op();
            ms_since(start)
        })
        .collect()
}

/// One framed call over a fresh connection, as a guest makes it. The body is
/// encoded by the caller, outside the timed region.
fn call(socket: &Path, body: &[u8]) -> ServiceResponse {
    let mut stream = UnixStream::connect(socket).expect("connect to the broker");
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    let mut len = [0; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn encoded_call(verb: &str, payload: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&ServiceCall {
        service: ServiceId::parse(HOST_CELL_SERVICE).unwrap(),
        verb: verb.into(),
        correlation_id: CorrelationId::new("latency"),
        payload,
        capability: None,
    })
    .unwrap()
}

fn expect_ok(response: ServiceResponse) {
    if let ServiceResponse::Err { code, message, .. } = response {
        panic!("refused: {code:?} {message}");
    }
}

/// A broker serving `host.cell.v1` to [`WRITER`] at its first epoch, wired
/// the way `mvm-broker` wires a registration, on a socket under `home`.
fn serve_broker(
    runtime: &tokio::runtime::Runtime,
    home: &Path,
    audit: Arc<AuditEmitter>,
) -> PathBuf {
    let socket = home.join("broker.sock");
    let listener = runtime
        .block_on(async { tokio::net::UnixListener::bind(&socket) })
        .expect("bind the broker socket");
    let mut registry = Registry::new();
    registry.bind_epoch_gate(Some(BrokerEpochGate::new(
        home.to_path_buf(),
        CallEpoch {
            unit: WRITER.into(),
            epoch: ExecutionEpoch::FIRST,
        },
    )));
    crate::broker::handlers::register_bound_handlers(
        &mut registry,
        &[ServiceId::parse(HOST_CELL_SERVICE).unwrap()],
        Some(audit as Arc<dyn RefusalAudit>),
    );
    runtime.spawn(crate::broker::server::serve_on_listener(
        listener,
        Arc::new(registry),
        "latency-vm".into(),
        TENANT.into(),
        mvm_core::framing::DEFAULT_MAX_FRAME_BYTES,
    ));
    socket
}

/// The pieces of one write, timed in process for the cell of `size` bytes,
/// whose stored version is `version` on entry.
fn breakdown(home: &Path, audit: &AuditEmitter, size: u64, mut version: u64) {
    let tenant = TenantId(TENANT.to_string());
    let unit = WorkloadId(WRITER.to_string());
    let name = cell_name(size);
    let path = cell_path(home, &tenant, &name);
    let value = vec![0x5a; size as usize];

    row(
        "topology read and verify",
        size,
        &time(|| {
            crate::topology_admission::last_admitted_topology(home, &tenant, None)
                .unwrap()
                .unwrap();
        }),
    );
    row(
        "epoch gate ledger load",
        size,
        &time(|| {
            CommandGate::load_at(home).unwrap();
        }),
    );
    row(
        "cell lock",
        size,
        &time(|| drop(FileLock::acquire(&path).unwrap())),
    );
    row(
        "cell open and verify",
        size,
        &time(|| drop(slots::CellFile::open(&path, size).unwrap())),
    );
    let commits: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let file = slots::CellFile::open(&path, size).unwrap();
            version += 1;
            let start = Instant::now();
            file.commit(version, &value).unwrap();
            ms_since(start)
        })
        .collect();
    row("slot write and sync", size, &commits);

    let scratch = path.with_extension("scratch");
    let slot = vec![0xa5; (slots::file_len(size) / 2) as usize];
    let mut file = std::fs::File::create(&scratch).unwrap();
    let syncs: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            file.write_all(&slot).unwrap();
            let start = Instant::now();
            file.sync_data().unwrap();
            ms_since(start)
        })
        .collect();
    drop(file);
    std::fs::remove_file(&scratch).unwrap();
    row("sync alone (scratch slot)", size, &syncs);

    let store = StateCells {
        host_signer_keys_dir: None,
        audit,
    };
    let caller = CellCaller {
        tenant: &tenant,
        unit: &unit,
        epoch: ExecutionEpoch::FIRST,
        cell: &name,
    };
    let writes: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            version += 1;
            let start = Instant::now();
            store.write(&caller, version, &value).unwrap();
            ms_since(start)
        })
        .collect();
    row("store write, no broker", size, &writes);
    row(
        "store read, no broker",
        size,
        &time(|| {
            store.read(&caller).unwrap();
        }),
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-build performance measurement")]
fn state_cell_write_and_read_latency() {
    let (_env, home) = crate::test_fixtures::isolated_mvm_home();
    let keys = mvm_core::config::mvm_keys_dir_at(home.path());
    let signer = crate::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
    let audit = Arc::new(
        AuditEmitter::with_dir(signer.signing.clone(), &home.path().join("audit"))
            .expect("emitter"),
    );
    admit_topology(&TopologyAdmissionRequest {
        tenant: &TenantId(TENANT.to_string()),
        signed: &sign_topology_as_host(&topology(), Some(&keys)).unwrap(),
        backend: BackendKind::Mock,
        measured_failover: None,
        host_cpus: &HostCpus {
            scope_cpuset: false,
            online: None,
            isolated: None,
            live: Vec::new(),
        },
        clock: &mvm_core::time::SystemClock,
        host_signer_keys_dir: Some(&keys),
        emitter: &audit,
    })
    .expect("admits");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let socket = serve_broker(&runtime, home.path(), Arc::clone(&audit));

    println!("| operation | cell bytes | samples | p50 ms | p95 ms | p99 ms | max ms |");
    println!("| --- | --- | --- | --- | --- | --- | --- |");
    let mut largest_writes = Vec::new();
    for size in SIZES {
        let name = cell_name(size);
        let value = vec![0x5a; size as usize];
        // Warm the page cache and the broker's first connection.
        for version in 1..=3 {
            let body = encoded_call(
                "write",
                serde_json::to_value(CellWriteRequest {
                    cell: name.clone(),
                    version,
                    value: value.clone(),
                })
                .unwrap(),
            );
            expect_ok(call(&socket, &body));
        }
        let writes: Vec<f64> = (4..4 + SAMPLES as u64)
            .map(|version| {
                let body = encoded_call(
                    "write",
                    serde_json::to_value(CellWriteRequest {
                        cell: name.clone(),
                        version,
                        value: value.clone(),
                    })
                    .unwrap(),
                );
                let start = Instant::now();
                expect_ok(call(&socket, &body));
                ms_since(start)
            })
            .collect();
        row("write through the broker", size, &writes);
        let read = encoded_call(
            "read",
            serde_json::to_value(CellReadRequest { cell: name.clone() }).unwrap(),
        );
        row(
            "read through the broker",
            size,
            &time(|| expect_ok(call(&socket, &read))),
        );
        breakdown(home.path(), &audit, size, 3 + SAMPLES as u64);
        if size == MAX_CELL_BYTES {
            largest_writes = writes;
        }
    }

    if let Some(out) = std::env::var_os(OUT_ENV) {
        let report = serde_json::json!({
            "architecture": std::env::consts::ARCH,
            "cell_bytes": MAX_CELL_BYTES,
            "write_ms": largest_writes,
        });
        std::fs::write(&out, serde_json::to_vec_pretty(&report).unwrap())
            .expect("write the latency samples");
    }
    runtime.shutdown_background();
}
