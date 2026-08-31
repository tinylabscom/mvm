//! Steps for the workload service plane: peer addressing, the host key-value
//! store, and catalog-declared bindings.
//!
//! These drive the real `EgressGate`, the real broker registry and handler, and
//! the real runtime catalog. No VM starts, so they run in the hermetic BDD gate
//! and cannot pass because a developer's machine happened to be in some state.

use cucumber::{given, then, when};
use mvm_contract::peer::{PeerBinding, PeerName};
use mvm_contract::protocol::broker::{ServiceErrorCode, ServiceId};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::handler::ServiceCallCtx;
use mvm_core::runtime_catalog::{RuntimeCatalog, RuntimeEntry};
use mvm_hostd::broker::handlers::host_kv_v1::HostKvV1Handler;
use mvm_hostd::broker::registry::Registry;
use mvm_vmm::vsock_egress_bridge::egress_gate::{EgressGate, EgressVerdict, Route};

use crate::support::service_plane_fixture;
use crate::world::CliWorld;

#[given("the SDK service-plane fixture is materialized as a read-only disk image")]
fn materialize_service_plane_fixture(world: &mut CliWorld) {
    let fixture_root =
        crate::steps::cli::workspace_root().join("features/suites/s30_service_plane/fixtures");
    world.service_plane_fixture_disk = Some(service_plane_fixture::materialize(&fixture_root));
}

#[when(
    regex = r#"^I run the SDK service-plane fixture in an isolated live home binding service "([^"]+)"$"#
)]
fn run_service_plane_fixture(world: &mut CliWorld, service: String) {
    let args = {
        let disk_root = world
            .service_plane_fixture_disk
            .as_ref()
            .expect("fixture disk must be materialized before the live run");
        service_plane_fixture::command(&service, &service_plane_fixture::image_path(disk_root))
    };
    crate::steps::cli::run_mvmctl_isolated_live_home(world, args);
}

fn ctx(workload_id: &str) -> ServiceCallCtx {
    ServiceCallCtx {
        workload_id: workload_id.into(),
        tenant_id: "bdd".into(),
        correlation_id: mvm_core::protocol::broker::CorrelationId::new("bdd"),
        session_id: "bdd".into(),
        profile: AgentProfile::Dev,
        composition_depth: 0,
        composition_width: 0,
    }
}

// ---- peer addressing ----

#[given("a workload gate with no peer bindings")]
async fn gate_without_peers(world: &mut CliWorld) {
    world.peer_gate = Some(EgressGate::default_deny());
}

#[given(regex = r#"^a workload gate binding peer "([^"]+)" port (\d+) to "([^"]+):(\d+)"$"#)]
async fn gate_with_peer(
    world: &mut CliWorld,
    name: String,
    port: u16,
    host_addr: String,
    host_port: u16,
) {
    let binding = PeerBinding {
        name: PeerName::parse(&name).expect("scenario peer name is valid"),
        port,
        host_addr,
        host_port,
    };
    binding.validate().expect("scenario binding is well formed");
    world.peer_gate = Some(EgressGate::default_deny().with_peers(vec![binding]));
}

#[when(regex = r#"^the workload dials (?:peer|host) "([^"]+)" on port (\d+)$"#)]
async fn dial(world: &mut CliWorld, target: String, port: u16) {
    let gate = world.peer_gate.as_ref().expect("a gate was established");
    world.peer_decision = Some(gate.decide_target(&target, port));
}

#[then(regex = r#"^the (?:peer|egress) dial is refused$"#)]
async fn dial_refused(world: &mut CliWorld) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    assert!(
        matches!(d.verdict, EgressVerdict::Deny(_)),
        "expected a refusal, got {:?}",
        d.verdict
    );
}

#[then("the peer dial is malformed")]
async fn dial_malformed(world: &mut CliWorld) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    assert_eq!(d.verdict, EgressVerdict::Malformed);
}

#[then(regex = r#"^the peer dial is allowed to "([^"]+)" port (\d+)$"#)]
async fn dial_allowed(world: &mut CliWorld, ip: String, port: u16) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    match &d.verdict {
        EgressVerdict::Allow { ips, port: got } => {
            let expected: std::net::IpAddr = ip.parse().expect("scenario ip parses");
            assert_eq!(ips, &vec![expected]);
            assert_eq!(*got, port);
        }
        other => panic!("expected an allow, got {other:?}"),
    }
}

#[then("the refusal says no peers are admitted")]
async fn refusal_says_none_admitted(world: &mut CliWorld) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    let EgressVerdict::Deny(reason) = &d.verdict else {
        panic!("expected a refusal");
    };
    assert!(
        reason.to_string().contains("no peers are admitted"),
        "refusal was: {reason}"
    );
}

#[then(regex = r#"^the refusal names the admitted route "([^"]+)"$"#)]
async fn refusal_names_route(world: &mut CliWorld, route: String) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    let EgressVerdict::Deny(reason) = &d.verdict else {
        panic!("expected a refusal");
    };
    assert!(
        reason.to_string().contains(&route),
        "refusal {reason} does not name {route}"
    );
}

#[then(regex = r#"^the decision is attributed to the "([^"]+)" route$"#)]
async fn decision_route(world: &mut CliWorld, route: String) {
    let d = world.peer_decision.as_ref().expect("a dial was decided");
    let expected = match route.as_str() {
        "peer" => Route::Peer,
        "egress" => Route::Egress,
        other => panic!("unknown route {other}"),
    };
    assert_eq!(d.route, expected);
}

// ---- the host key-value store ----

fn kv_registry(world: &mut CliWorld, bind: bool) {
    let dir = tempfile::tempdir().expect("kv tempdir");
    let mut registry = Registry::default();
    if bind {
        registry.register(std::sync::Arc::new(HostKvV1Handler::with_root(dir.path())));
    }
    world.kv_root = Some(dir);
    world.broker_registry = Some(registry);
}

#[given("a broker registry with no bound services")]
async fn registry_unbound(world: &mut CliWorld) {
    kv_registry(world, false);
}

#[given(regex = r#"^a broker registry binding "host\.kv\.v1"$"#)]
async fn registry_bound(world: &mut CliWorld) {
    kv_registry(world, true);
}

async fn kv_call(world: &mut CliWorld, workload: &str, verb: &str, payload: serde_json::Value) {
    let registry = world.broker_registry.as_ref().expect("a registry");
    let service = ServiceId::parse("host.kv.v1").expect("valid service id");
    world.kv_result = Some(
        registry
            .dispatch(&ctx(workload), &service, verb, payload)
            .await,
    );
}

#[when(regex = r#"^the workload calls "host\.kv\.v1" verb "([^"]+)"$"#)]
async fn call_verb(world: &mut CliWorld, verb: String) {
    kv_call(world, "w1", &verb, serde_json::json!({"key": "k"})).await;
}

#[when(regex = r#"^the workload puts key "([^"]+)" with (\d+) bytes$"#)]
async fn put_key(world: &mut CliWorld, key: String, len: usize) {
    kv_call(
        world,
        "w1",
        "put",
        serde_json::json!({"key": key, "value": vec![7u8; len]}),
    )
    .await;
}

#[when(regex = r#"^workload "([^"]+)" puts key "([^"]+)" with (\d+) bytes$"#)]
async fn put_key_as(world: &mut CliWorld, who: String, key: String, len: usize) {
    kv_call(
        world,
        &who,
        "put",
        serde_json::json!({"key": key, "value": vec![7u8; len]}),
    )
    .await;
}

#[when(regex = r#"^the workload gets key "([^"]+)"$"#)]
async fn get_key(world: &mut CliWorld, key: String) {
    kv_call(world, "w1", "get", serde_json::json!({"key": key})).await;
}

#[when(regex = r#"^workload "([^"]+)" gets key "([^"]+)"$"#)]
async fn get_key_as(world: &mut CliWorld, who: String, key: String) {
    kv_call(world, &who, "get", serde_json::json!({"key": key})).await;
}

#[when("the workload sends a get request carrying an unknown field")]
async fn get_unknown_field(world: &mut CliWorld) {
    kv_call(
        world,
        "w1",
        "get",
        serde_json::json!({"key": "k", "workload_id": "w2"}),
    )
    .await;
}

fn kv_error(world: &CliWorld) -> ServiceErrorCode {
    world
        .kv_result
        .as_ref()
        .expect("a call was made")
        .as_ref()
        .expect_err("expected a refusal")
        .code
}

#[then("the service call is refused as not bound")]
async fn refused_not_bound(world: &mut CliWorld) {
    assert_eq!(kv_error(world), ServiceErrorCode::NotBound);
}

#[then("the service call is refused as a bad request")]
async fn refused_bad_request(world: &mut CliWorld) {
    assert_eq!(kv_error(world), ServiceErrorCode::BadRequest);
}

#[then("the stored value is returned")]
async fn value_returned(world: &mut CliWorld) {
    let value = world
        .kv_result
        .as_ref()
        .expect("a call")
        .as_ref()
        .expect("the read succeeded");
    let decoded: mvm_core::protocol::host_kv::KvGetResponse =
        serde_json::from_value(value.clone()).expect("decodes");
    assert!(decoded.value.is_some(), "expected the stored bytes back");
}

#[then("the read reports the key absent")]
async fn key_absent(world: &mut CliWorld) {
    let value = world
        .kv_result
        .as_ref()
        .expect("a call")
        .as_ref()
        .expect("the read succeeded");
    let decoded: mvm_core::protocol::host_kv::KvGetResponse =
        serde_json::from_value(value.clone()).expect("decodes");
    assert_eq!(decoded.value, None);
}

// ---- catalog-declared bindings ----

fn declaring_catalog(service: &str) -> RuntimeCatalog {
    RuntimeCatalog {
        schema_version: 1,
        entries: vec![RuntimeEntry {
            name: "bdd".to_string(),
            description: "bdd entry".to_string(),
            image: "example:1".to_string(),
            commands: vec!["bdd".to_string()],
            project_files: vec!["bdd.toml".to_string()],
            tags: Vec::new(),
            services: vec![service.to_string()],
            peers: Vec::new(),
        }],
    }
}

#[given("the built-in runtime catalog")]
async fn builtin_catalog(world: &mut CliWorld) {
    world.runtime_catalog = Some(RuntimeCatalog::builtin());
}

#[given(regex = r#"^a runtime catalog whose entry declares service "([^"]+)"$"#)]
async fn catalog_declaring(world: &mut CliWorld, service: String) {
    world.runtime_catalog = Some(declaring_catalog(&service));
}

#[then("no bundled runtime declares a host-service binding")]
async fn no_builtin_declares(world: &mut CliWorld) {
    let catalog = world.runtime_catalog.as_ref().expect("a catalog");
    for entry in &catalog.entries {
        assert!(
            entry.services.is_empty() && entry.peers.is_empty(),
            "{} declares a binding nobody opted into",
            entry.name
        );
    }
}

#[when("the runtime is resolved by name")]
async fn resolve_by_name(world: &mut CliWorld) {
    let catalog = world.runtime_catalog.as_ref().expect("a catalog");
    world.runtime_resolution = Some(catalog.resolve_named("bdd").map_err(|e| e.to_string()));
}

#[when("the runtime is detected by its command")]
async fn detect_by_command(world: &mut CliWorld) {
    let catalog = world.runtime_catalog.as_ref().expect("a catalog");
    world.runtime_detection = Some(
        catalog
            .detect(Some("bdd"), &[])
            .map(|d| d.is_some())
            .map_err(|e| e.to_string()),
    );
}

#[then(regex = r#"^the resolved runtime carries service "([^"]+)"$"#)]
async fn resolved_carries(world: &mut CliWorld, service: String) {
    let detection = world
        .runtime_resolution
        .as_ref()
        .expect("a resolution")
        .as_ref()
        .expect("resolution succeeded");
    assert!(
        detection.services.iter().any(|s| s.as_str() == service),
        "resolved runtime does not carry {service}"
    );
}

#[then("resolution is refused naming the entry")]
async fn resolution_refused(world: &mut CliWorld) {
    let err = world
        .runtime_resolution
        .as_ref()
        .expect("a resolution")
        .as_ref()
        .expect_err("expected a refusal");
    assert!(err.contains("bdd"), "refusal {err} does not name the entry");
}

#[then("detection is refused rather than reporting no match")]
async fn detection_refused(world: &mut CliWorld) {
    let outcome = world.runtime_detection.as_ref().expect("a detection");
    assert!(
        outcome.is_err(),
        "a matched entry with malformed bindings must error, got {outcome:?}"
    );
}
