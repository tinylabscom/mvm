use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Mutex;
use std::time::Duration;

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, StateCell, TOPOLOGY_SCHEMA_VERSION, Topology,
    Unit, UnitResources, UnitRole,
};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_contract::timestamp::UtcTimestamp;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceResponse};
use mvm_core::protocol::handler::CallEpoch;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::emitter::AuditEmitter;
use crate::audit::host_keypair::HostSigner;
use crate::broker::epoch::tests::{gate_at, quarantine, replace};
use crate::broker::registry::Registry;
use crate::liveness::LivenessDeadlines;
use crate::policy_generation::workload_store::OwnedWorkloadStore;
use crate::topology_admission::{
    HostCpus, TopologyAdmissionRequest, admit_topology, sign_topology_as_host,
};

const TENANT: &str = "acme";
const PERIOD_MS: u32 = 2_000;

struct TestClock(Mutex<UtcTimestamp>);

impl TestClock {
    fn advance_ms(&self, ms: u64) {
        let mut now = self.0.lock().unwrap();
        *now = now.checked_add(Duration::from_millis(ms)).unwrap();
    }
}

impl Clock for TestClock {
    fn now(&self) -> UtcTimestamp {
        *self.0.lock().unwrap()
    }
}

fn t0() -> UtcTimestamp {
    "2026-11-01T00:00:00Z".parse::<UtcTimestamp>().unwrap()
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
        valid_until: t0().checked_add_secs(30 * 86_400).unwrap(),
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
        let clock = Arc::new(TestClock(Mutex::new(
            t0().checked_add_secs(86_400).unwrap(),
        )));
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
        HostCellV1Handler::new(self.emitter.clone(), self.clock.clone())
    }

    async fn call(
        &self,
        unit: Option<(&str, u64)>,
        verb: &str,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        self.call_on(&self.handler(), unit, verb, payload).await
    }

    async fn call_on(
        &self,
        handler: &HostCellV1Handler,
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
        handler.dispatch(&ctx, verb, payload).await
    }

    async fn write(&self, unit: &str, n: u64, version: u64, value: &[u8]) -> ServiceDispatchResult {
        self.call(
            Some((unit, n)),
            "write",
            serde_json::to_value(CellWriteRequest {
                cell: "setpoint".into(),
                version,
                value: value.to_vec(),
            })
            .unwrap(),
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
            serde_json::json!({"cell": "setpoint", "version": 1, "value": "AQ=="}),
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
            serde_json::json!({"cell": "setpoint", "version": 1, "value": "", "epoch": 9}),
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
    host.clock.advance_ms(u64::from(PERIOD_MS) - 1);
    host.write("controller", 1, 1, b"x").await.unwrap();
    host.clock.advance_ms(u64::from(PERIOD_MS) - 1);
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
        mvm_core::framing::DEFAULT_MAX_FRAME_BYTES,
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
    let response =
        crate::broker::server::read_frame(&mut stream, mvm_core::framing::DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap();
    server.abort();
    response
}

fn bound_registry(host: &Host, unit: &str, n: u64, bindings: &[ServiceId]) -> Registry {
    let mut registry = Registry::new();
    registry.bind_epoch_gate(Some(gate_at(host.home.path(), unit, n)));
    crate::broker::handlers::register_bound_handlers(
        &mut registry,
        bindings,
        Some(host.emitter.clone()),
    );
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
    let write = || serde_json::json!({"cell": "setpoint", "version": 1, "value": "Bw=="});

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

/// The largest call and the largest answer the service can produce both fit
/// the broker's default frame, so `MAX_CELL_BYTES` cannot outgrow the wire.
#[test]
fn a_full_cell_fits_one_broker_frame_both_ways() {
    let cap = mvm_core::framing::DEFAULT_MAX_FRAME_BYTES;
    let value = vec![0xff; MAX_CELL_BYTES as usize];
    let call = ServiceCall {
        service: ServiceId::parse(HOST_CELL_SERVICE).unwrap(),
        verb: "write".into(),
        correlation_id: CorrelationId::new("c".repeat(128)),
        payload: serde_json::to_value(CellWriteRequest {
            cell: "c".repeat(MAX_CELL_NAME_LEN),
            version: u64::MAX,
            value: value.clone(),
        })
        .unwrap(),
        capability: None,
    };
    let response = ServiceResponse::Ok {
        correlation_id: CorrelationId::new("brk-4294967295-ffffffffffffffff"),
        payload: serde_json::to_value(CellReadResponse {
            version: u64::MAX,
            value,
        })
        .unwrap(),
    };
    for (what, len) in [
        ("call", serde_json::to_vec(&call).unwrap().len()),
        ("response", serde_json::to_vec(&response).unwrap().len()),
    ] {
        assert!(len <= cap, "a full-cell {what} is {len} bytes, over {cap}");
    }
}

/// Through the host-agent daemon's real registration: a helper-backed VM whose
/// plan binds the service and whose registration names its unit and epoch.
/// A refused write lands one `state_cell.refused` entry on the tenant chain,
/// written by the signer helper beside the host's own entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_write_through_the_daemon_lands_on_the_tenant_chain() {
    use crate::audit_signer::helper::{SignerHelper, serve_on_listener as serve_helper};
    use mvm_core::protocol::broker_control::{ControlRequest, RegisterVm};

    let host = Host::admitted();
    let audit = host.home.path().join("audit");
    let key_path = mvm_core::config::mvm_keys_dir_at(host.home.path()).join("host-signer.ed25519");
    let helper_sock = host.home.path().join("h.sock");
    let helper = Arc::new(tokio::sync::Mutex::new(SignerHelper::new(
        TENANT,
        Some(key_path),
    )));
    let helper_task = tokio::spawn(serve_helper(
        tokio::net::UnixListener::bind(&helper_sock).unwrap(),
        helper,
        65_536,
    ));

    let verifying = host._signer.signing.verifying_key();
    let mut daemon = crate::broker::daemon::HostAgentDaemon::new(TENANT, verifying, 64 * 1024)
        .with_signer_helper(&helper_sock);
    let path = |name: &str| host.home.path().join(name).to_string_lossy().into_owned();
    let registration = |vm: &str, unit: Option<&str>| RegisterVm {
        vm_id: vm.into(),
        workload_id: Some(format!("wl-{vm}")),
        tenant_id: TENANT.into(),
        broker_listen_socket: path(&format!("{vm}.sock")),
        workload_chain_path: audit
            .join(format!("{TENANT}.{vm}.workload.jsonl"))
            .to_string_lossy()
            .into_owned(),
        workload_chain_head_path: Some(path(&format!("{vm}.head"))),
        audit_signer_uds_path: None,
        services_bindings: vec![ServiceId::parse(HOST_CELL_SERVICE).unwrap()],
        capability_bindings: vec![],
        assurance: None,
        service_proxies: vec![],
        workload: unit.map(str::to_string),
        execution_epoch: unit.map(|_| ExecutionEpoch::FIRST),
    };
    daemon
        .apply(&ControlRequest::Register(Box::new(registration(
            "vm-r",
            Some("reader"),
        ))))
        .unwrap();
    daemon
        .apply(&ControlRequest::Register(Box::new(registration(
            "vm-u", None,
        ))))
        .unwrap();
    let before = refusals(&host).len();

    let call = |vm: &str| {
        let socket = host.home.path().join(format!("{vm}.sock"));
        async move {
            let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
            crate::broker::server::write_frame(
                &mut stream,
                &ServiceCall {
                    service: ServiceId::parse(HOST_CELL_SERVICE).unwrap(),
                    verb: "write".into(),
                    correlation_id: CorrelationId::new("guest"),
                    payload: serde_json::json!({"cell": "setpoint", "version": 1, "value": "eA=="}),
                    capability: None,
                },
            )
            .await
            .unwrap();
            crate::broker::server::read_frame::<ServiceResponse>(
                &mut stream,
                mvm_core::framing::DEFAULT_MAX_FRAME_BYTES,
            )
            .await
            .unwrap()
        }
    };
    assert_eq!(
        refused_with(call("vm-r").await),
        ServiceErrorCode::CapabilityDenied,
        "a reader may not write"
    );
    assert_eq!(
        refused_with(call("vm-u").await),
        ServiceErrorCode::NotBound,
        "a registration without a unit and epoch is not served"
    );

    let after = refusals(&host);
    assert_eq!(after.len(), before + 1);
    let entry = after.last().unwrap();
    assert_eq!(entry["labels"]["unit"], "reader");
    assert_eq!(entry["labels"]["operation"], "write");
    let chain = audit.join(format!("{TENANT}.jsonl"));
    assert!(crate::audit::audit_file::verify_audit_chain(&chain, &verifying).is_ok());
    helper_task.abort();
}

fn refusals(host: &Host) -> Vec<serde_json::Value> {
    let chain = host
        .home
        .path()
        .join("audit")
        .join(format!("{TENANT}.jsonl"));
    std::fs::read_to_string(chain)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
        .filter(|entry| entry["event"] == crate::state_cells::STATE_CELL_REFUSED_EVENT)
        .collect()
}

/// The guest is refused every time; the chain gets the first refusal and then
/// one per interval carrying the count it stood for.
#[tokio::test]
async fn repeated_refusals_are_all_answered_but_recorded_at_a_bounded_rate() {
    use crate::audit::refusal::{REFUSAL_AUDIT_INTERVAL, ThrottledRefusals};
    let host = Host::admitted();
    let handler = HostCellV1Handler::new(
        Arc::new(ThrottledRefusals::new(
            host.emitter.clone(),
            host.clock.clone(),
        )),
        host.clock.clone(),
    );
    let write = || serde_json::json!({"cell": "setpoint", "version": 1, "value": "eA=="});
    for _ in 0..5 {
        assert_eq!(
            code(
                host.call_on(&handler, Some(("reader", 1)), "write", write())
                    .await
            ),
            ServiceErrorCode::CapabilityDenied
        );
    }
    assert_eq!(refusals(&host).len(), 1);
    host.clock
        .advance_ms(u64::try_from(REFUSAL_AUDIT_INTERVAL.as_millis()).unwrap());
    assert_eq!(
        code(
            host.call_on(&handler, Some(("reader", 1)), "write", write())
                .await
        ),
        ServiceErrorCode::CapabilityDenied
    );
    let recorded = refusals(&host);
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[1]["labels"]["suppressed"], "4");
}
