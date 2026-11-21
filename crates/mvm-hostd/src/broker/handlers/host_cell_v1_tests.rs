use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Mutex;

use chrono::{DateTime, Duration as Days, TimeZone, Utc};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, StateCell, TOPOLOGY_SCHEMA_VERSION, Topology,
    Unit, UnitResources, UnitRole,
};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceResponse};
use mvm_core::protocol::handler::CallEpoch;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::host_keypair::HostSigner;
use crate::broker::epoch::tests::{gate_at, quarantine, replace};
use crate::broker::registry::Registry;
use crate::policy_generation::workload_store::OwnedWorkloadStore;
use crate::topology_admission::{
    HostCpus, TopologyAdmissionRequest, admit_topology, sign_topology_as_host,
};

const TENANT: &str = "acme";
const PERIOD_MS: u32 = 1_000;

struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn advance_ms(&self, ms: i64) {
        *self.0.lock().unwrap() += Days::milliseconds(ms);
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

/// `controller` writes `setpoint` and declares a liveness period, `reader`
/// reads it, and `stranger` does neither.
fn topology() -> Topology {
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        generation: 1,
        valid_from: t0(),
        valid_until: t0() + Days::days(30),
        suite: CryptoSuite::CLASSICAL,
        units: vec![
            unit("controller", Some(PERIOD_MS)),
            unit("reader", None),
            unit("stranger", None),
        ],
        standby_pairs: Vec::new(),
        cells: vec![StateCell {
            name: "setpoint".to_string(),
            writer: id("controller"),
            readers: vec![id("reader")],
            size_bytes: NonZeroU64::new(16).unwrap(),
            update: Default::default(),
            per_write_audit: false,
        }],
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// A host with its own `MVM_HOME`, signer, chain and clock, and [`topology`]
/// admitted. One per test: the environment lock is not reentrant.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
    _signer: HostSigner,
    emitter: Arc<AuditEmitter>,
    clock: Arc<TestClock>,
}

impl Host {
    fn admitted() -> Self {
        let (env, home) = crate::test_fixtures::isolated_mvm_home();
        let keys = mvm_core::config::mvm_keys_dir_at(home.path());
        let signer = crate::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
        let emitter = Arc::new(
            AuditEmitter::with_dir(signer.signing.clone(), &home.path().join("audit"))
                .expect("emitter"),
        );
        let clock = Arc::new(TestClock(Mutex::new(t0() + Days::days(1))));
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
            clock: &*clock,
            host_signer_keys_dir: Some(&keys),
            emitter: &emitter,
        })
        .expect("admits");
        Self {
            _env: env,
            home,
            _signer: signer,
            emitter,
            clock,
        }
    }

    fn handler(&self) -> HostCellV1Handler {
        HostCellV1Handler::new(Arc::clone(&self.emitter), self.clock.clone())
    }

    async fn call(
        &self,
        unit: Option<(&str, u64)>,
        verb: &str,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let ctx = ServiceCallCtx {
            workload_id: "vm".into(),
            tenant_id: TENANT.into(),
            correlation_id: CorrelationId::new("correlation"),
            session_id: "vm".into(),
            profile: AgentProfile::SealedProd,
            composition_depth: 0,
            composition_width: 0,
            epoch: unit.map(|(unit, n)| CallEpoch {
                unit: unit.into(),
                epoch: ExecutionEpoch::new(n).unwrap(),
            }),
        };
        self.handler().dispatch(&ctx, verb, payload).await
    }

    async fn write(&self, unit: &str, n: u64, version: u64, value: &[u8]) -> ServiceDispatchResult {
        self.call(
            Some((unit, n)),
            "write",
            serde_json::json!({"cell": "setpoint", "version": version, "value": value}),
        )
        .await
    }

    async fn read(&self, unit: &str, n: u64) -> ServiceDispatchResult {
        self.call(
            Some((unit, n)),
            "read",
            serde_json::json!({"cell": "setpoint"}),
        )
        .await
    }

    async fn signal(&self, unit: &str, n: u64) -> ServiceDispatchResult {
        self.call(Some((unit, n)), "signal", serde_json::json!({}))
            .await
    }

    fn expire(&self) -> usize {
        let deadlines = LivenessDeadlines {
            host_signer_keys_dir: None,
            emitter: &self.emitter,
            clock: &*self.clock,
        };
        let pass = deadlines
            .expire(&OwnedWorkloadStore::open(self.home.path()).unwrap())
            .expect("the pass runs");
        assert!(pass.failures.is_empty(), "{:?}", pass.failures);
        pass.expired.len()
    }
}

fn code(result: ServiceDispatchResult) -> ServiceErrorCode {
    match result {
        Err(error) => error.code,
        Ok(payload) => panic!("expected a refusal, got {payload}"),
    }
}

fn read_back(result: ServiceDispatchResult) -> CellReadResponse {
    serde_json::from_value(result.expect("the read is served")).unwrap()
}

#[tokio::test]
async fn the_writer_writes_and_the_writer_and_reader_read_it_back() {
    let host = Host::admitted();
    let written: CellWriteResponse =
        serde_json::from_value(host.write("controller", 1, 1, b"on").await.unwrap()).unwrap();
    assert_eq!(written.version, 1);
    for unit in ["controller", "reader"] {
        let value = read_back(host.read(unit, 1).await);
        assert_eq!((value.version, value.value.as_slice()), (1, &b"on"[..]));
    }
    assert_eq!(
        code(host.write("controller", 1, 1, b"again").await),
        ServiceErrorCode::BadRequest,
        "a version that does not increase"
    );
}

#[tokio::test]
async fn a_reader_cannot_write_and_a_stranger_can_do_neither() {
    let host = Host::admitted();
    assert_eq!(
        code(host.write("reader", 1, 1, b"x").await),
        ServiceErrorCode::CapabilityDenied
    );
    assert_eq!(
        code(host.write("stranger", 1, 1, b"x").await),
        ServiceErrorCode::CapabilityDenied
    );
    assert_eq!(
        code(host.read("stranger", 1).await),
        ServiceErrorCode::CapabilityDenied
    );
    assert_eq!(read_back(host.read("reader", 1).await).version, 0);
}

#[tokio::test]
async fn a_replaced_or_quarantined_epoch_is_refused() {
    let host = Host::admitted();
    replace(host.home.path(), "controller");
    assert_eq!(
        code(host.write("controller", 1, 1, b"x").await),
        ServiceErrorCode::SessionRevoked
    );
    host.write("controller", 2, 1, b"x")
        .await
        .expect("the new epoch writes");
    quarantine(host.home.path(), "reader");
    assert_eq!(
        code(host.read("reader", 1).await),
        ServiceErrorCode::SessionRevoked
    );
}

#[tokio::test]
async fn a_registration_without_a_unit_and_epoch_is_refused() {
    let host = Host::admitted();
    for (verb, payload) in [
        (
            "write",
            serde_json::json!({"cell": "setpoint", "version": 1, "value": [1]}),
        ),
        ("read", serde_json::json!({"cell": "setpoint"})),
        ("signal", serde_json::json!({})),
    ] {
        assert_eq!(
            code(host.call(None, verb, payload).await),
            ServiceErrorCode::CapabilityDenied,
            "{verb}"
        );
    }
    assert_eq!(read_back(host.read("controller", 1).await).version, 0);
}

#[tokio::test]
async fn oversized_and_malformed_requests_are_refused_before_the_store() {
    let host = Host::admitted();
    let too_big = vec![0u8; MAX_CELL_BYTES as usize + 1];
    assert_eq!(
        code(host.write("controller", 1, 1, &too_big).await),
        ServiceErrorCode::BadRequest
    );
    assert_eq!(
        code(host.write("controller", 1, 1, &[0; 17]).await),
        ServiceErrorCode::BadRequest,
        "larger than the cell"
    );
    let long_name = "c".repeat(MAX_CELL_NAME_LEN + 1);
    for (verb, payload) in [
        (
            "write",
            serde_json::json!({"cell": "setpoint", "version": 1, "value": [], "epoch": 9}),
        ),
        (
            "read",
            serde_json::json!({"cell": "setpoint", "unit": "controller"}),
        ),
        ("read", serde_json::json!({"cell": long_name})),
        ("signal", serde_json::json!({"unit": "controller"})),
    ] {
        assert_eq!(
            code(host.call(Some(("controller", 1)), verb, payload).await),
            ServiceErrorCode::BadRequest,
            "{verb}"
        );
    }
    assert_eq!(
        code(
            host.call(Some(("controller", 1)), "delete", serde_json::json!({}))
                .await
        ),
        ServiceErrorCode::NotImplemented
    );
    assert_eq!(read_back(host.read("controller", 1).await).version, 0);
}

#[tokio::test]
async fn a_liveness_signal_is_accepted_from_the_current_epoch_only() {
    let host = Host::admitted();
    host.signal("controller", 1)
        .await
        .expect("current epoch signals");
    assert_eq!(
        code(host.signal("reader", 1).await),
        ServiceErrorCode::CapabilityDenied,
        "no period declared"
    );
    replace(host.home.path(), "controller");
    assert_eq!(
        code(host.signal("controller", 1).await),
        ServiceErrorCode::SessionRevoked
    );
}

#[tokio::test]
async fn a_cell_write_resets_the_liveness_deadline() {
    let host = Host::admitted();
    host.signal("controller", 1).await.unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) - 1);
    host.write("controller", 1, 1, b"x").await.unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS) - 1);
    assert_eq!(host.expire(), 0, "the write moved the deadline on");
    host.clock.advance_ms(1);
    assert_eq!(host.expire(), 1);
}

/// One call through the broker's accept loop, registry and epoch gate.
async fn over_the_socket(
    socket: &std::path::Path,
    registry: Registry,
    verb: &str,
    payload: serde_json::Value,
) -> ServiceResponse {
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let server = tokio::spawn(crate::broker::server::serve_on_listener(
        listener,
        Arc::new(registry),
        "vm".into(),
        TENANT.into(),
        64 * 1024,
    ));
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    crate::broker::server::write_frame(
        &mut stream,
        &ServiceCall {
            service: ServiceId::parse(HOST_CELL_SERVICE).unwrap(),
            verb: verb.into(),
            correlation_id: CorrelationId::new("guest"),
            payload,
            capability: None,
        },
    )
    .await
    .unwrap();
    let response = crate::broker::server::read_frame(&mut stream, 1024 * 1024)
        .await
        .unwrap();
    server.abort();
    response
}

fn bound_registry(host: &Host, unit: &str, n: u64, bindings: &[ServiceId]) -> Registry {
    let mut registry = Registry::new();
    crate::broker::handlers::register_cell_handler(
        &mut registry,
        bindings,
        Arc::clone(&host.emitter),
        host.clock.clone(),
    );
    registry.bind_epoch_gate(Some(gate_at(host.home.path(), unit, n)));
    registry
}

fn refused_with(response: ServiceResponse) -> ServiceErrorCode {
    match response {
        ServiceResponse::Err { code, .. } => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn over_the_broker_socket_only_a_bound_current_epoch_is_served() {
    let host = Host::admitted();
    let socket = host.home.path().join("b.sock");
    let bound = [ServiceId::parse(HOST_CELL_SERVICE).unwrap()];
    let write = || serde_json::json!({"cell": "setpoint", "version": 1, "value": [7]});

    let unbound = bound_registry(&host, "controller", 1, &[]);
    assert_eq!(
        refused_with(over_the_socket(&socket, unbound, "write", write()).await),
        ServiceErrorCode::NotBound
    );

    let registry = bound_registry(&host, "controller", 1, &bound);
    assert!(matches!(
        over_the_socket(&socket, registry, "write", write()).await,
        ServiceResponse::Ok { .. }
    ));
    let registry = bound_registry(&host, "reader", 1, &bound);
    match over_the_socket(
        &socket,
        registry,
        "read",
        serde_json::json!({"cell": "setpoint"}),
    )
    .await
    {
        ServiceResponse::Ok { payload, .. } => {
            let value: CellReadResponse = serde_json::from_value(payload).unwrap();
            assert_eq!((value.version, value.value), (1, vec![7]));
        }
        other => panic!("expected the read to be served, got {other:?}"),
    }

    replace(host.home.path(), "controller");
    let stale = bound_registry(&host, "controller", 1, &bound);
    assert_eq!(
        refused_with(over_the_socket(&socket, stale, "signal", serde_json::json!({})).await),
        ServiceErrorCode::SessionRevoked
    );
}
