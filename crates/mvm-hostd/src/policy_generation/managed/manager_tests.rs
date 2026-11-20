use super::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UnixStream, sync::Notify, time::Instant};
use zbus::connection::Builder;

const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/fixture";

struct State {
    id: String,
    path: String,
    load: String,
    active: String,
    pid: u32,
    invocation: Vec<u8>,
    unloaded: bool,
    mutations: usize,
    queries: usize,
    query_seen: Arc<Notify>,
    query_gate: Option<Arc<Notify>>,
}

struct UnitFixture(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl UnitFixture {
    #[zbus(property)]
    fn id(&self) -> String {
        self.0.lock().unwrap().id.clone()
    }
    #[zbus(property)]
    fn load_state(&self) -> String {
        self.0.lock().unwrap().load.clone()
    }
    #[zbus(property)]
    fn active_state(&self) -> String {
        self.0.lock().unwrap().active.clone()
    }
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        self.0.lock().unwrap().invocation.clone()
    }
}

struct ServiceFixture(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl ServiceFixture {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        self.0.lock().unwrap().pid
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.systemd1", impl_display = true)]
enum UnitError {
    NoSuchUnit(String),
}

struct ManagerFixture(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl ManagerFixture {
    async fn get_unit(&self, name: &str) -> Result<OwnedObjectPath, UnitError> {
        let (path, gate) = {
            let mut state = self.0.lock().unwrap();
            assert!(name.starts_with(super::super::UNIT_PREFIX));
            state.queries += 1;
            state.query_seen.notify_one();
            if state.unloaded {
                return Err(UnitError::NoSuchUnit("not loaded".into()));
            }
            (state.path.clone(), state.query_gate.clone())
        };
        if let Some(gate) = gate {
            gate.notified().await;
        }
        Ok(path.try_into().unwrap())
    }

    fn load_unit(&self, _name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.lock().unwrap().mutations += 1;
        Err(zbus::fdo::Error::AccessDenied("observation only".into()))
    }

    fn start_unit(&self, _name: &str, _mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.lock().unwrap().mutations += 1;
        Err(zbus::fdo::Error::AccessDenied("observation only".into()))
    }
}

fn identity() -> ManagedIdentity {
    ManagedIdentity {
        uid: rustix::process::geteuid().as_raw(),
        home: "/home/operator/.state".into(),
        unit: "mvm-policy-coordinator@home-operator-.state.service".into(),
    }
}

async fn fixture(
    identity: &ManagedIdentity,
    deadline: Instant,
) -> (
    zbus::Connection,
    native_bus::NativeConnection,
    Arc<Mutex<State>>,
) {
    let state = Arc::new(Mutex::new(State {
        id: identity.unit().to_string(),
        path: UNIT_PATH.into(),
        load: "loaded".into(),
        active: "active".into(),
        pid: std::process::id(),
        invocation: vec![1; 16],
        unloaded: false,
        mutations: 0,
        queries: 0,
        query_seen: Arc::new(Notify::new()),
        query_gate: None,
    }));
    let (server, client) = UnixStream::pair().unwrap();
    let server = Builder::unix_stream(server.into_std().unwrap())
        .p2p()
        .server(zbus::Guid::generate())
        .serve_at(MANAGER_PATH, ManagerFixture(state.clone()))
        .serve_at(UNIT_PATH, UnitFixture(state.clone()))
        .serve_at(UNIT_PATH, ServiceFixture(state.clone()))
        .build();
    let (server, client) = tokio::join!(server, native_bus::connect(client, deadline));
    (server.unwrap(), client.unwrap(), state)
}

#[tokio::test]
async fn native_observation_is_typed_and_never_loads_or_starts_a_unit() {
    let identity = identity();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (_server, bus, state) = fixture(&identity, deadline).await;
    assert_eq!(
        observe(&bus, &identity, deadline).await.unwrap(),
        UnitObservation {
            main_pid: std::process::id(),
            invocation: "01".repeat(16),
        }
    );
    state.lock().unwrap().load = "not-found".into();
    assert!(matches!(
        observe(&bus, &identity, deadline).await,
        Err(ManagedRefusal::NotProvisioned { load_state, .. }) if load_state == "not-found"
    ));
    state.lock().unwrap().load = "loaded".into();
    for active in ["inactive", "failed", "activating", "deactivating"] {
        state.lock().unwrap().active = active.into();
        assert!(matches!(
            observe(&bus, &identity, deadline).await,
            Err(ManagedRefusal::NotRunning { active_state, .. }) if active_state == active
        ));
    }
    state.lock().unwrap().unloaded = true;
    assert!(matches!(
        observe(&bus, &identity, deadline).await,
        Err(ManagedRefusal::Unknown { detail, .. }) if detail.contains("not loaded")
    ));
    assert_eq!(state.lock().unwrap().mutations, 0);
}

#[tokio::test]
async fn malformed_paths_properties_and_incarnations_are_not_observations() {
    let identity = identity();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (_server, bus, state) = fixture(&identity, deadline).await;
    for path in ["/org/freedesktop/systemd1", "/elsewhere"] {
        state.lock().unwrap().path = path.into();
        assert!(matches!(
            observe(&bus, &identity, deadline).await,
            Err(ManagedRefusal::Unknown { .. })
        ));
    }
    state.lock().unwrap().path = UNIT_PATH.into();
    state.lock().unwrap().id = "other.service".into();
    assert!(matches!(
        observe(&bus, &identity, deadline).await,
        Err(ManagedRefusal::IdentityMismatch { .. })
    ));
    state.lock().unwrap().id = identity.unit().to_string();
    for pid in [0, 1] {
        state.lock().unwrap().pid = pid;
        assert!(matches!(
            observe(&bus, &identity, deadline).await,
            Err(ManagedRefusal::Unknown { .. })
        ));
    }
    state.lock().unwrap().pid = std::process::id();
    for invocation in [vec![], vec![1; 15], vec![1; 17], vec![0; 16]] {
        state.lock().unwrap().invocation = invocation;
        assert!(matches!(
            observe(&bus, &identity, deadline).await,
            Err(ManagedRefusal::Unknown { .. })
        ));
    }
    let path: OwnedObjectPath = UNIT_PATH.try_into().unwrap();
    let error = property::<String>(&bus, &path, SERVICE, "MainPID", &identity)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wrong type"), "{error}");
    assert!(
        property::<String>(&bus, &path, UNIT, "Missing", &identity)
            .await
            .is_err()
    );
    assert_eq!(state.lock().unwrap().mutations, 0);
}

#[tokio::test]
async fn one_manager_connection_cannot_turn_into_its_replacement() {
    let identity = identity();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (server, bus, state) = fixture(&identity, deadline).await;
    let before = observe(&bus, &identity, deadline).await.unwrap();
    state.lock().unwrap().invocation = vec![2; 16];
    let after = observe(&bus, &identity, deadline).await.unwrap();
    assert_ne!(
        before, after,
        "a restart remains visible on the same connection"
    );
    server.close().await.unwrap();
    assert!(matches!(
        observe(&bus, &identity, deadline).await,
        Err(ManagedRefusal::Unknown { .. })
    ));
}

#[tokio::test]
async fn expired_budget_sends_no_query_and_blocked_query_releases_its_reader() {
    let identity = identity();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (server, mut bus, state) = fixture(&identity, deadline).await;
    assert!(observe(&bus, &identity, Instant::now()).await.is_err());
    assert_eq!(state.lock().unwrap().queries, 0);
    let released = bus.reader_released.take().unwrap();
    let gate = Arc::new(Notify::new());
    let seen = {
        let mut state = state.lock().unwrap();
        state.query_gate = Some(gate.clone());
        state.query_seen.clone()
    };
    let request = tokio::spawn(async move { observe(&bus, &identity, deadline).await });
    tokio::time::timeout_at(deadline, seen.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    let error = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, ManagedRefusal::Unknown { .. }), "{error}");
    tokio::time::timeout(Duration::from_secs(1), released)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), server.closed())
        .await
        .unwrap();
    assert_eq!(state.lock().unwrap().queries, 1, "no retry after expiry");
    assert_eq!(state.lock().unwrap().mutations, 0);
    gate.notify_one();
}

#[test]
fn manager_credentials_must_match_the_user_before_authentication() {
    let identity = identity();
    let peer = PeerProcess {
        uid: identity.uid(),
        pid: 42,
    };
    verify_manager_peer(&identity, peer).unwrap();
    for peer in [
        PeerProcess {
            uid: identity.uid() + 1,
            ..peer
        },
        PeerProcess { pid: 0, ..peer },
        PeerProcess { pid: 1, ..peer },
    ] {
        assert!(matches!(
            verify_manager_peer(&identity, peer),
            Err(ManagedRefusal::ManagerUnavailable { .. })
        ));
    }
}

fn observe_through_sync_bridge() {
    crate::blocking::block_on_anywhere(async {
        let identity = identity();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (_server, bus, _) = fixture(&identity, deadline).await;
        assert!(observe(&bus, &identity, deadline).await.is_ok());
    })
    .unwrap();
}

#[test]
fn observation_bridge_works_without_a_runtime() {
    observe_through_sync_bridge();
}

#[tokio::test]
async fn observation_bridge_works_inside_a_current_thread_runtime() {
    observe_through_sync_bridge();
}

#[tokio::test(flavor = "multi_thread")]
async fn observation_bridge_works_inside_a_multi_thread_runtime() {
    observe_through_sync_bridge();
}

#[cfg(target_os = "linux")]
mod composed {
    use super::*;
    use crate::policy_generation::{
        coordinator::{Request, Response, socket_path},
        managed::{CoordinatorStatus, Lifetime, STATUS_PROTOCOL, status_with_observer},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn through_bridge() {
        crate::blocking::block_on_anywhere(async {
            let directory = tempfile::tempdir().unwrap();
            let home = directory.path().canonicalize().unwrap();
            let identity =
                ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), &home).unwrap();
            let socket = socket_path(&home);
            std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let (server, bus, state) = fixture(&identity, deadline).await;
            let progress = bus.connection.clone();
            let unit = identity.unit().to_string();
            let status = CoordinatorStatus {
                protocol: STATUS_PROTOCOL,
                pid: std::process::id(),
                uid: identity.uid(),
                home: home.clone(),
                lifetime: Lifetime::Managed {
                    unit: unit.clone(),
                    invocation: "01".repeat(16),
                },
            };
            let responder = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32().await.unwrap() as usize;
                assert!(length <= 16 * 1024);
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).await.unwrap();
                assert!(matches!(
                    serde_json::from_slice::<Request>(&bytes).unwrap(),
                    Request::Status
                ));
                // Reply only after the bounded native reader has progressed
                // while the blocking coordinator exchange is awaiting bytes.
                let reply = progress
                    .call_method(
                        None::<&str>,
                        MANAGER_PATH,
                        Some(MANAGER),
                        "GetUnit",
                        &(unit,),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    reply
                        .body()
                        .deserialize::<OwnedObjectPath>()
                        .unwrap()
                        .as_str(),
                    UNIT_PATH
                );
                let response = serde_json::to_vec(&Response::Status { status }).unwrap();
                stream
                    .write_u32(u32::try_from(response.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&response).await.unwrap();
            });
            let result = status_with_observer(&identity, deadline.into_std(), || {
                observe(&bus, &identity, deadline)
            })
            .await;
            tokio::time::timeout_at(deadline, responder)
                .await
                .unwrap()
                .unwrap();
            let reported = result.unwrap();
            assert_eq!(reported.unit, identity.unit());
            assert_eq!(reported.invocation, "01".repeat(16));
            assert_eq!(reported.pid, std::process::id());
            assert_eq!(state.lock().unwrap().queries, 3);
            assert_eq!(state.lock().unwrap().mutations, 0);
            drop(bus);
            tokio::time::timeout_at(deadline, server.closed())
                .await
                .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn native_coordinator_native_exchange_from_sync_code() {
        through_bridge();
    }

    #[tokio::test]
    async fn native_coordinator_native_exchange_inside_current_thread_runtime() {
        through_bridge();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_coordinator_native_exchange_inside_multi_thread_runtime() {
        through_bridge();
    }
}
