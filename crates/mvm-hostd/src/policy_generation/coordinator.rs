//! Resident local policy-generation owner over an owner-only Unix socket.
//!
//! Initial activation serializes with the shared launch/restore barrier,
//! proves whole-host quiescence, and publishes generation 1 durably. No
//! workload effects, signers, or guest traffic are served on this socket.
//!
//! The process is started one of two ways: detached by a launcher that writes
//! its config to stdin, or by a systemd user manager as the fixed unit
//! [`super::managed`] names. `Status` says which, and nothing more: it is not
//! readiness, current authority, or permission to commit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use mvm_core::host_interface::workload::{
    DestinationCommit, DestinationEnrollment, SignedPreparedHead, WorkloadChange, WorkloadCommit,
};

use super::managed::CoordinatorStatus;
#[cfg(unix)]
use super::managed::Lifetime;
#[cfg(unix)]
use super::store::PublicationUnresolved;
#[cfg(unix)]
use super::workload_store::{CommitUnresolved, DestinationRefusal, WorkloadStore};
use super::{GenerationStore, ProjectPolicyCandidate, prepare_initial};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// What a frame that does not decode is reported under; a coordinator too old
/// to know a request answers `Refused` with this in the message.
const FRAME_DECODE_CONTEXT: &str = "decoding policy coordinator frame";
/// Refusals that say the request was never looked at, so a caller may send it again.
const CONNECTION_LIMIT_MESSAGE: &str = "policy coordinator is at its connection limit";
const WAITING_ACTIVATIONS_MESSAGE: &str = "too many activations are waiting";
const WAITING_DESTINATIONS_MESSAGE: &str = "too many destination requests are waiting";
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(any(test, target_os = "linux"))]
const MAX_STATUS_BYTES: usize = 4 * 1024;
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) const STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Handler threads alive at once; a connection past this is refused. An
/// activation can hold its thread for as long as a launch holds the shared
/// barrier, so the count needs a ceiling, and it stays well under the default
/// soft file-descriptor limit of 1024.
const MAX_CONNECTIONS: usize = 256;
/// Handler slots waiting activations cannot take, so a workload commit is not
/// refused for want of a connection slot by activations alone.
const CONTAINMENT_RESERVE: usize = 32;
const MAX_ACTIVATIONS: usize = MAX_CONNECTIONS - CONTAINMENT_RESERVE;

/// A local request to the resident lifecycle owner.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Versioned, side-effect-free readiness check.
    Ping,
    /// Who is answering: process, user, home and how it was started.
    Status,
    /// Commit generation one for a project while the entire host is idle.
    Activate { project: PathBuf },
    /// Return a validated committed generation, if one exists.
    Read { project: PathBuf },
    /// Resolve an interrupted publication if no activation is running now,
    /// and an interrupted workload ledger commit.
    Recover,
    /// Durably apply one change to the workload containment ledger.
    CommitWorkload { change: WorkloadChange },
    /// Record a mailbox destination under a workload epoch.
    EnrollDestination { enrollment: DestinationEnrollment },
    /// Move an enrolled destination's tip one step, ordered against containment.
    CommitDestination { prepared: SignedPreparedHead },
}

/// Response from the owner. An absent `Read` result is an ordinary,
/// non-activated project; a corrupt or missing *activated* record is an error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ready,
    Status {
        status: CoordinatorStatus,
    },
    Policy {
        candidate: Option<Box<ProjectPolicyCandidate>>,
    },
    Workload {
        commit: WorkloadCommit,
    },
    Destination {
        commit: DestinationCommit,
    },
    Refused {
        message: String,
    },
    /// A destination request named a destination the ledger does not hold.
    Unenrolled {
        message: String,
    },
    /// An activation's, workload commit's or destination commit's outcome is unknown; reads stay refused until the
    /// coordinator recovers the interrupted publication.
    Unresolved {
        message: String,
    },
}

/// The owner-only socket corresponding to this MVM home, using the existing
/// short private `/tmp` fallback when the home path exceeds the UDS limit.
#[must_use]
pub fn socket_path(home: &Path) -> PathBuf {
    let dir = mvm_core::config::policy_generations_dir_at(home);
    mvm_core::config::host_agent_socket_dir_in(&dir).join("control.sock")
}

/// The request frame was written but no usable reply came back, so the owner
/// may or may not have acted on it.
#[derive(Debug)]
pub struct ReplyLost(String);

impl std::fmt::Display for ReplyLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no reply from the policy coordinator after the request was sent: {}",
            self.0
        )
    }
}

impl std::error::Error for ReplyLost {}

/// Take the lock that makes this process the one owner of the coordinator's
/// stores for its home. Held for as long as the owner serves.
pub(super) fn acquire_owner(home: &Path) -> Result<mvm_core::util::atomic_io::FileLock> {
    let socket = socket_path(home);
    let dir = socket
        .parent()
        .context("policy coordinator socket has no parent")?;
    mvm_core::private_fs::create_owned_private_dir(dir)?;
    mvm_core::util::atomic_io::FileLock::try_acquire(&dir.join("owner"))?
        .context("policy coordinator is already running")
}

/// Everything a bound coordinator owns besides its socket.
#[cfg(unix)]
pub(in crate::policy_generation) struct Bound {
    pub(in crate::policy_generation) listener: std::os::unix::net::UnixListener,
    pub(in crate::policy_generation) generations: std::sync::Arc<GenerationStore>,
    pub(in crate::policy_generation) workloads: std::sync::Arc<WorkloadStore>,
    pub(in crate::policy_generation) owner: mvm_core::util::atomic_io::FileLock,
}

#[cfg(unix)]
mod unix {
    use std::{
        io::{Read, Write},
        os::unix::{
            fs::{FileTypeExt as _, PermissionsExt as _},
            net::{UnixListener, UnixStream},
        },
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[cfg(any(test, target_os = "linux"))]
    use std::time::Instant;

    use super::*;

    static ACTIVATIONS: Mutex<()> = Mutex::new(());
    /// Activations holding a handler thread, whether running or waiting.
    static WAITING_ACTIVATIONS: AtomicUsize = AtomicUsize::new(0);

    /// One non-containment request's claim on the waiting count, released on
    /// drop. Activations and destination requests share it, so neither can use
    /// the handler slots a workload commit needs.
    struct NonContainmentClaim;

    impl NonContainmentClaim {
        fn take() -> Option<Self> {
            if WAITING_ACTIVATIONS.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVATIONS {
                WAITING_ACTIVATIONS.fetch_sub(1, Ordering::SeqCst);
                return None;
            }
            Some(Self)
        }
    }

    impl Drop for NonContainmentClaim {
        fn drop(&mut self) {
            WAITING_ACTIVATIONS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(super) fn ensure(home: &Path) -> Result<PathBuf> {
        use mvm_vmm::host::{
            aux_bin::AuxBin,
            broker_services_spawn::{resolve_subprocess_bin_to_spawn, spawn_detached_with_config},
        };

        anyhow::ensure!(
            home.is_absolute(),
            "MVM_HOME must be absolute for policy activation"
        );
        mvm_core::private_fs::create_owned_private_dir(home)?;
        let dir = mvm_core::config::policy_generations_dir_at(home);
        mvm_core::private_fs::create_owned_private_dir(&dir)?;
        let socket = socket_path(home);
        mvm_core::private_fs::create_owned_private_dir(
            socket
                .parent()
                .context("policy coordinator socket has no parent")?,
        )?;
        let _spawn_lock = mvm_core::util::atomic_io::FileLock::acquire(&dir.join("spawn"))?;
        match UnixStream::connect(&socket) {
            Ok(_) => {
                ping(&socket)?;
                return Ok(socket);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("connecting to policy coordinator {}", socket.display())
                });
            }
        }
        let bin = resolve_subprocess_bin_to_spawn(&AuxBin::new(
            "mvm-policy-coordinator",
            "MVM_POLICY_COORDINATOR_PATH",
            "mvm-hostd",
        ))?;
        let mut child = spawn_detached_with_config(
            &bin,
            &serde_json::json!({"home": home}),
            "mvm-policy-coordinator",
        )?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(()) = ping(&socket) {
                return Ok(socket);
            }
            if let Some(status) = child.try_wait()? {
                anyhow::bail!("policy coordinator exited before readiness: {status}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        anyhow::bail!(
            "policy coordinator did not become ready at {}",
            socket.display()
        )
    }

    fn ping(socket: &Path) -> Result<()> {
        match call(socket, &Request::Ping)? {
            Response::Ready => Ok(()),
            Response::Refused { message } => {
                anyhow::bail!("policy coordinator refused readiness: {message}")
            }
            Response::Policy { .. }
            | Response::Status { .. }
            | Response::Workload { .. }
            | Response::Destination { .. }
            | Response::Unenrolled { .. }
            | Response::Unresolved { .. } => {
                anyhow::bail!("policy coordinator answered a ping with something else")
            }
        }
    }

    fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read, max: usize) -> Result<T> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(length <= max, "policy coordinator frame exceeds its limit");
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes)?;
        serde_json::from_slice(&bytes).context(FRAME_DECODE_CONTEXT)
    }

    fn write_frame<T: Serialize>(stream: &mut impl Write, value: &T, max: usize) -> Result<()> {
        let bytes = serde_json::to_vec(value).context("encoding policy coordinator frame")?;
        ensure!(
            bytes.len() <= max,
            "policy coordinator response exceeds its limit"
        );
        let length = u32::try_from(bytes.len()).context("coordinator frame length overflow")?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(&bytes)?;
        Ok(())
    }

    pub(super) fn call(socket: &Path, request: &Request) -> Result<Response> {
        let mut stream = UnixStream::connect(socket)
            .with_context(|| format!("connecting to policy coordinator {}", socket.display()))?;
        // Activation waits for in-flight launches to release their shared
        // guards. A client-side timeout would report failure while the owner
        // could still commit after the caller has gone away.
        if !matches!(request, Request::Activate { .. }) {
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        }
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        write_frame(&mut stream, request, MAX_REQUEST_BYTES)?;
        read_frame(&mut stream, MAX_RESPONSE_BYTES)
            .map_err(|error| anyhow::Error::new(ReplyLost(format!("{error:#}"))))
    }

    /// Ask the process on this connection who it is, within a short deadline
    /// and a small reply. The caller decides whether to believe it.
    #[cfg(any(test, target_os = "linux"))]
    pub(in crate::policy_generation) fn exchange_status(
        stream: UnixStream,
        deadline: Instant,
    ) -> Result<CoordinatorStatus> {
        // The shared I/O wrapper keeps partial reads and writes on one budget.
        let mut stream = mvm_core::net::actor_session::ActorDeadlineStream::new(stream, deadline)?;
        write_frame(&mut stream, &Request::Status, MAX_REQUEST_BYTES)?;
        match read_frame(&mut stream, MAX_STATUS_BYTES)? {
            Response::Status { status } => Ok(status),
            Response::Refused { message } => {
                anyhow::bail!("policy coordinator refused a status request: {message}")
            }
            Response::Ready
            | Response::Policy { .. }
            | Response::Workload { .. }
            | Response::Destination { .. }
            | Response::Unenrolled { .. }
            | Response::Unresolved { .. } => {
                anyhow::bail!("policy coordinator answered a status request with something else")
            }
        }
    }

    /// Refuse a connection from another user before reading anything from it.
    /// The socket's mode already excludes them; this asks the kernel instead
    /// of trusting the filesystem alone.
    fn require_same_user(stream: &mut UnixStream) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let peer = super::super::managed::peer_credentials(stream)
                .context("reading the caller's kernel credentials")?;
            if peer.uid != rustix::process::geteuid().as_raw() {
                let message = "policy coordinator serves only its own user";
                let refused = Response::Refused {
                    message: message.into(),
                };
                let _ = write_frame(stream, &refused, MAX_RESPONSE_BYTES);
                anyhow::bail!(message);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = stream;
        Ok(())
    }

    fn handle(
        request: Request,
        store: &GenerationStore,
        workloads: &WorkloadStore,
        status: &CoordinatorStatus,
    ) -> Result<Response> {
        if let Request::Activate { project } | Request::Read { project } = &request {
            ensure!(
                project.is_absolute(),
                "policy project identity must be absolute"
            );
        }
        let source = mvm_policy::PolicyStore::from_config();
        let candidate = match request {
            Request::Ping => return Ok(Response::Ready),
            Request::Status => {
                return Ok(Response::Status {
                    status: status.clone(),
                });
            }
            Request::Recover => {
                // Never wait: the caller may hold the shared barrier an
                // activation is waiting on.
                let ledger = workloads.recover();
                if let Ok(_one_activation) = ACTIVATIONS.try_lock() {
                    store.recover()?;
                }
                ledger?;
                return Ok(Response::Ready);
            }
            // The ledger changes no launch authorization the barrier guards,
            // so it neither takes the barrier nor waits on an activation.
            Request::CommitWorkload { change } => {
                return Ok(Response::Workload {
                    commit: workloads.commit(&change)?,
                });
            }
            // Ordered by the ledger's lane alone; it must not wait on an activation.
            Request::EnrollDestination { enrollment } => {
                let Some(_claim) = NonContainmentClaim::take() else {
                    return Ok(Response::Refused {
                        message: WAITING_DESTINATIONS_MESSAGE.into(),
                    });
                };
                return Ok(destination_response(
                    workloads.enroll_destination(&enrollment),
                ));
            }
            Request::CommitDestination { prepared } => {
                let Some(_claim) = NonContainmentClaim::take() else {
                    return Ok(Response::Refused {
                        message: WAITING_DESTINATIONS_MESSAGE.into(),
                    });
                };
                return Ok(destination_response(
                    workloads.commit_destination(&prepared),
                ));
            }
            Request::Activate { project } => {
                let Some(_claim) = NonContainmentClaim::take() else {
                    return Ok(Response::Refused {
                        message: WAITING_ACTIVATIONS_MESSAGE.into(),
                    });
                };
                ensure!(
                    cfg!(target_os = "linux"),
                    "committed project policy initially supports Firecracker on Linux only"
                );
                // Exclusive file locks are process-reentrant so nested launch
                // guards can share an open descriptor. Serialize requests
                // within this resident owner as well as across processes.
                let _one_activation = ACTIVATIONS
                    .lock()
                    .expect("policy activation mutex poisoned");
                store.recover()?;
                let _barrier =
                    mvm_core::host_interface::activation_barrier::ActivationBarrier::exclusive()?;
                mvm_runtime::AnyBackend::probe_host_quiescence()?;
                let candidate = prepare_initial(&project)?;
                candidate.revalidate(&source)?;
                candidate
                    .built_manifest_slot()
                    .context("activation requires a matching prebuilt Firecracker project slot")?;
                store.publish_initial(&candidate, &source)?;
                Some(
                    store
                        .load(&project, &source)?
                        .context("published generation vanished")?,
                )
            }
            Request::Read { project } => {
                // Never wait here: the caller may hold the shared barrier an
                // activation is waiting on. If recovery cannot run now, the
                // load below refuses.
                if store.has_obligation()?
                    && let Ok(_one_activation) = ACTIVATIONS.try_lock()
                {
                    store.recover()?;
                }
                let loaded = store.load(&project, &source)?;
                if let Some(candidate) = &loaded {
                    ensure!(
                        candidate.platform
                            == mvm_policy::Platform::current(Some(
                                mvm_contract::protocol::vm_backend::BackendKind::Firecracker
                            )),
                        "committed project policy platform differs from this host"
                    );
                }
                loaded
            }
        };
        Ok(Response::Policy {
            candidate: candidate.map(Box::new),
        })
    }

    /// A handler error as the wire reply: an ambiguous publication is
    /// reported as such rather than as an ordinary refusal.
    fn error_response(error: &anyhow::Error) -> Response {
        let message = format!("{error:#}");
        if error.downcast_ref::<PublicationUnresolved>().is_some()
            || error.downcast_ref::<CommitUnresolved>().is_some()
        {
            Response::Unresolved { message }
        } else {
            Response::Refused { message }
        }
    }

    /// A destination request's reply. Only a refusal of the request itself is
    /// definite; any other failure leaves the outcome unknown, so the caller
    /// is never told "nothing happened" about a ledger it could not read.
    fn destination_response(result: Result<DestinationCommit>) -> Response {
        match result {
            Ok(commit) => Response::Destination { commit },
            Err(error) => {
                let message = format!("{error:#}");
                match error.downcast_ref::<DestinationRefusal>() {
                    Some(refusal) if refusal.is_not_enrolled() => Response::Unenrolled { message },
                    Some(_) => Response::Refused { message },
                    None => Response::Unresolved { message },
                }
            }
        }
    }

    /// Bind under the spawn lock a detached launcher holds while it waits for
    /// its child, so a unit start and a detached start cannot both claim the
    /// socket. The detached arm must not take it: its launcher already does.
    pub(super) fn serve_managed(home: &Path) -> Result<()> {
        let lifetime = super::super::managed::bind_managed(home)?;
        let dir = mvm_core::config::policy_generations_dir_at(home);
        mvm_core::private_fs::create_owned_private_dir(home)?;
        mvm_core::private_fs::create_owned_private_dir(&dir)?;
        let Bound {
            listener,
            generations,
            workloads,
            owner: _owner,
        } = {
            let _spawn_lock = mvm_core::util::atomic_io::FileLock::acquire(&dir.join("spawn"))?;
            bind(home)?
        };
        serve_on(
            &listener,
            &generations,
            &workloads,
            &CoordinatorStatus::of_this_process(home, lifetime),
        )
    }

    pub(super) fn serve(home: &Path, lifetime: Lifetime) -> Result<()> {
        let Bound {
            listener,
            generations,
            workloads,
            owner: _owner,
        } = bind(home)?;
        serve_on(
            &listener,
            &generations,
            &workloads,
            &CoordinatorStatus::of_this_process(home, lifetime),
        )
    }

    /// A coordinator on a thread of this process, for tests that need a real
    /// socket for the ledger's owner. It serves until the process exits.
    #[cfg(test)]
    pub(crate) fn serve_in_process(home: &Path) -> Result<PathBuf> {
        let status = CoordinatorStatus::of_this_process(home, Lifetime::Detached);
        let bound = bind(home)?;
        std::thread::spawn(move || {
            let _owner = bound.owner;
            serve_on(
                &bound.listener,
                &bound.generations,
                &bound.workloads,
                &status,
            )
        });
        Ok(socket_path(home))
    }

    pub(in crate::policy_generation) fn bind(home: &Path) -> Result<Bound> {
        ensure!(
            home.is_absolute(),
            "policy coordinator home must be absolute"
        );
        ensure!(
            Path::new(&mvm_core::config::mvm_home()) == home,
            "policy coordinator home does not match its launch configuration"
        );
        let store = Arc::new(GenerationStore::open(home.to_path_buf())?);
        let socket = socket_path(home);
        // Held for the listener's lifetime: recovery is only safe for the one
        // process that owns the store, and the socket probe below can race.
        let owner = acquire_owner(home)?;
        let workloads = Arc::new(WorkloadStore::open(home)?);
        if let Ok(meta) = std::fs::symlink_metadata(&socket) {
            mvm_core::private_fs::require_current_owner(&meta)?;
            ensure!(
                meta.file_type().is_socket(),
                "policy coordinator path is not a socket"
            );
            ensure!(
                UnixStream::connect(&socket).is_err(),
                "policy coordinator is already running"
            );
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("binding policy coordinator {}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        // Only the process that holds the socket may recover: an obligation
        // seen before that point can belong to a coordinator still publishing.
        // A failed recovery leaves the store refusing through its index; the
        // coordinator still serves so the refusal is reported, not a dead socket.
        if let Err(error) = store.recover() {
            tracing::warn!(%error, "policy coordinator could not recover an interrupted publication");
        }
        if let Err(error) = workloads.recover() {
            tracing::warn!(%error, "policy coordinator could not recover an interrupted workload ledger commit");
        }
        Ok(Bound {
            listener,
            generations: store,
            workloads,
            owner,
        })
    }

    /// An in-flight slot, returned when dropped so a panicking handler
    /// cannot leak it.
    struct Slot(Arc<AtomicUsize>);

    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(in crate::policy_generation) fn serve_on(
        listener: &UnixListener,
        store: &Arc<GenerationStore>,
        workloads: &Arc<WorkloadStore>,
        status: &CoordinatorStatus,
    ) -> Result<()> {
        let in_flight = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    // The pause keeps EMFILE from turning into a busy loop.
                    tracing::warn!(%error, "policy coordinator could not accept a request");
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            if let Err(error) = require_same_user(&mut stream) {
                tracing::warn!(%error, "policy coordinator dropped a connection");
                continue;
            }
            if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let busy = Response::Refused {
                    message: CONNECTION_LIMIT_MESSAGE.into(),
                };
                let _ = write_frame(&mut stream, &busy, MAX_RESPONSE_BYTES);
                continue;
            }
            let store = Arc::clone(store);
            let workloads = Arc::clone(workloads);
            let status = status.clone();
            let slot = Slot(Arc::clone(&in_flight));
            // An activation can wait on a caller's shared launch guard.
            // Accepting pings and reads on independent connections is
            // necessary: making the waiting activation block the listener
            // would deadlock a launcher that holds that guard and connects.
            let spawned = std::thread::Builder::new().spawn(move || {
                let _slot = slot;
                let reply = match read_frame(&mut stream, MAX_REQUEST_BYTES)
                    .and_then(|request| handle(request, &store, &workloads, &status))
                {
                    Ok(response) => response,
                    Err(error) => error_response(&error),
                };
                if let Err(error) = write_frame(&mut stream, &reply, MAX_RESPONSE_BYTES) {
                    tracing::warn!(%error, "policy coordinator could not return a response");
                }
            });
            if let Err(error) = spawned {
                // The closure, and with it the slot and the connection, was dropped.
                tracing::warn!(%error, "policy coordinator could not start a handler");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn relative_project_requests_are_refused_before_any_state_change() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let store = GenerationStore::open(home.path().to_path_buf()).unwrap();
            let workloads = WorkloadStore::open(home.path()).unwrap();
            for request in [
                Request::Activate {
                    project: PathBuf::from("."),
                },
                Request::Read {
                    project: PathBuf::from("."),
                },
            ] {
                let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
                let error = handle(request, &store, &workloads, &status).unwrap_err();
                assert!(error.to_string().contains("must be absolute"), "{error}");
            }
            assert!(!store.has_active_generation().unwrap());
        }

        #[test]
        fn a_served_socket_reports_who_answers_and_keeps_answering_pings() {
            use mvm_core::util::test_env::TestEnv;

            let mut environment = TestEnv::new();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().canonicalize().unwrap();
            environment.isolate_mvm_home(&home);
            let status = CoordinatorStatus::of_this_process(&home, Lifetime::Detached);
            let bound = bind(&home).unwrap();
            let served = status.clone();
            std::thread::spawn(move || {
                let _owner = bound.owner;
                serve_on(
                    &bound.listener,
                    &bound.generations,
                    &bound.workloads,
                    &served,
                )
            });

            let socket = socket_path(&home);
            let stream = UnixStream::connect(&socket).unwrap();
            assert_eq!(
                exchange_status(stream, Instant::now() + STATUS_TIMEOUT).unwrap(),
                status
            );
            assert!(matches!(
                call(&socket, &Request::Ping).unwrap(),
                Response::Ready
            ));
            let error = bind(&home)
                .err()
                .expect("a second coordinator must not bind");
            assert!(error.to_string().contains("already running"), "{error}");
        }

        #[test]
        fn binding_recovers_a_publication_that_can_be_rolled_back() {
            use mvm_core::util::test_env::TestEnv;

            let mut environment = TestEnv::new();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().canonicalize().unwrap();
            environment.isolate_mvm_home(&home);
            let store = GenerationStore::open(home.clone()).unwrap();
            store
                .write_obligation(&"a".repeat(64), &"b".repeat(64))
                .unwrap();
            assert!(store.has_obligation().unwrap());
            let _bound = bind(&home).unwrap();
            assert!(!store.has_obligation().unwrap());
        }

        /// The two tests below contend for the process-wide activation mutex.
        static MUTEX_TESTS: Mutex<()> = Mutex::new(());

        #[test]
        fn recover_clears_a_roll_back_able_obligation_and_replies_ready() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let store = GenerationStore::open(home.path().to_path_buf()).unwrap();
            let workloads = WorkloadStore::open(home.path()).unwrap();
            store
                .write_obligation(&"a".repeat(64), &"b".repeat(64))
                .unwrap();
            let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
            let reply = handle(Request::Recover, &store, &workloads, &status).unwrap();
            assert!(matches!(reply, Response::Ready));
            assert!(!store.has_obligation().unwrap());
        }

        #[test]
        fn a_read_with_an_obligation_never_waits_on_an_activation() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let project = home.path().join("project");
            std::fs::create_dir(&project).unwrap();
            let store = GenerationStore::open(home.path().join("state")).unwrap();
            let workloads = WorkloadStore::open(&home.path().join("state")).unwrap();
            store
                .write_obligation(&"a".repeat(64), &"b".repeat(64))
                .unwrap();
            let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
            let (held, release) = std::sync::mpsc::channel::<()>();
            let (ready, acquired) = std::sync::mpsc::channel::<()>();
            let holder = std::thread::spawn(move || {
                let _activation = ACTIVATIONS.lock().unwrap();
                ready.send(()).unwrap();
                let _ = release.recv();
            });
            acquired.recv().unwrap();
            let error = handle(Request::Read { project }, &store, &workloads, &status).unwrap_err();
            assert!(matches!(
                error_response(&error),
                Response::Unresolved { .. }
            ));
            held.send(()).unwrap();
            holder.join().unwrap();
        }

        struct Served {
            _environment: mvm_core::util::test_env::TestEnv,
            _root: tempfile::TempDir,
            home: PathBuf,
            socket: PathBuf,
            workloads: Arc<WorkloadStore>,
        }

        fn serve_workloads() -> Served {
            let mut environment = mvm_core::util::test_env::TestEnv::new();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().canonicalize().unwrap();
            environment.isolate_mvm_home(&home);
            let status = CoordinatorStatus::of_this_process(&home, Lifetime::Detached);
            let bound = bind(&home).unwrap();
            let workloads = Arc::clone(&bound.workloads);
            std::thread::spawn(move || {
                let _owner = bound.owner;
                serve_on(
                    &bound.listener,
                    &bound.generations,
                    &bound.workloads,
                    &status,
                )
            });
            Served {
                _environment: environment,
                _root: root,
                socket: socket_path(&home),
                home,
                workloads,
            }
        }

        fn quarantine(name: &str) -> WorkloadChange {
            WorkloadChange::Quarantine {
                workload: name.into(),
            }
        }

        #[test]
        fn workload_commits_over_the_socket_reach_the_readers_ledger() {
            use mvm_contract::protocol::mailbox::ExecutionEpoch;
            use mvm_core::host_interface::{Denial, workload::WorkloadLedger};
            let _serial = MUTEX_TESTS.lock().unwrap();
            let served = serve_workloads();
            let commit = commit_workload(&served.socket, &quarantine("suspect")).unwrap();
            assert_eq!(commit.sequence, 1);
            let ledger = WorkloadLedger::load_at(&served.home).unwrap();
            assert_eq!(
                ledger.authorize("suspect", ExecutionEpoch::new(1).unwrap()),
                Err(Denial::WorkloadQuarantined("suspect".into()))
            );
            assert!(
                ledger
                    .authorize("other", ExecutionEpoch::new(1).unwrap())
                    .is_ok()
            );

            let replaced = commit_workload(
                &served.socket,
                &WorkloadChange::Replace {
                    workload: "suspect".into(),
                    from_epoch: ExecutionEpoch::new(1).unwrap(),
                },
            )
            .unwrap();
            assert_eq!(replaced.entry.epoch, ExecutionEpoch::new(2).unwrap());
            let ledger = WorkloadLedger::load_at(&served.home).unwrap();
            assert!(
                ledger
                    .authorize("suspect", ExecutionEpoch::new(2).unwrap())
                    .is_ok()
            );
            assert_eq!(
                ledger.authorize("suspect", ExecutionEpoch::new(1).unwrap()),
                Err(Denial::StaleEpoch { got: 1, current: 2 })
            );
        }

        #[test]
        fn a_workload_commit_completes_while_another_activation_holds_the_activation_lock() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let served = serve_workloads();
            let _activation = ACTIVATIONS.lock().unwrap();
            let started = std::time::Instant::now();
            commit_workload(&served.socket, &quarantine("suspect")).unwrap();
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn an_unresolved_workload_commit_is_reported_and_recover_clears_it() {
            use crate::policy_generation::workload_store::Step;
            let _serial = MUTEX_TESTS.lock().unwrap();
            let served = serve_workloads();
            served.workloads.fail_after(Step::CommitObligation);
            let error = commit_workload(&served.socket, &quarantine("suspect")).unwrap_err();
            assert!(error.to_string().contains("unknown"), "{error:#}");
            assert!(
                mvm_core::host_interface::workload::WorkloadLedger::load_at(&served.home).is_err()
            );
            assert!(matches!(
                call(&served.socket, &Request::Recover).unwrap(),
                Response::Ready
            ));
            assert_eq!(
                commit_workload(&served.socket, &quarantine("suspect"))
                    .unwrap()
                    .sequence,
                1
            );
        }

        #[test]
        fn a_commit_unresolved_error_is_reported_as_unresolved() {
            let unresolved = anyhow::Error::new(CommitUnresolved::new("x"));
            assert!(matches!(
                error_response(&unresolved),
                Response::Unresolved { .. }
            ));
        }

        #[test]
        fn handle_refuses_an_activate_over_the_cap_and_still_commits_a_workload() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let store = GenerationStore::open(home.path().to_path_buf()).unwrap();
            let workloads = WorkloadStore::open(home.path()).unwrap();
            let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
            WAITING_ACTIVATIONS.store(MAX_ACTIVATIONS, Ordering::SeqCst);
            let activate = handle(
                Request::Activate {
                    project: home.path().to_path_buf(),
                },
                &store,
                &workloads,
                &status,
            );
            let commit = handle(
                Request::CommitWorkload {
                    change: quarantine("suspect"),
                },
                &store,
                &workloads,
                &status,
            );
            WAITING_ACTIVATIONS.store(0, Ordering::SeqCst);
            assert!(matches!(
                activate.unwrap(),
                Response::Refused { message } if message.contains("too many activations")
            ));
            assert!(matches!(commit.unwrap(), Response::Workload { .. }));
        }

        fn destination_fixtures() -> (
            ed25519_dalek::SigningKey,
            mvm_core::host_interface::workload::DestinationEnrollment,
        ) {
            use mvm_contract::protocol::mailbox::ExecutionEpoch;
            use mvm_core::host_interface::workload::{DestinationEnrollment, DestinationTip};
            let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
            let enrollment = DestinationEnrollment {
                destination: "ab".repeat(32),
                workload: "w".into(),
                epoch: ExecutionEpoch::new(1).unwrap(),
                key: hex::encode(key.verifying_key().to_bytes()),
                tip: DestinationTip {
                    cursor: 0,
                    head: "0".repeat(64),
                },
            };
            (key, enrollment)
        }

        fn step(
            key: &ed25519_dalek::SigningKey,
            enrollment: &mvm_core::host_interface::workload::DestinationEnrollment,
        ) -> mvm_core::host_interface::workload::SignedPreparedHead {
            use mvm_core::host_interface::workload::{DestinationTip, PreparedHead};
            PreparedHead {
                destination: enrollment.destination.clone(),
                workload: enrollment.workload.clone(),
                epoch: enrollment.epoch,
                expected: enrollment.tip.clone(),
                next: DestinationTip {
                    cursor: 1,
                    head: "1".repeat(64),
                },
            }
            .sign(key)
            .unwrap()
        }

        fn disk_destination_tip(home: &Path, id: &str) -> u64 {
            let bytes = mvm_core::host_interface::workload::read_ledger_bytes_at(home)
                .unwrap()
                .unwrap();
            serde_json::from_slice::<mvm_core::host_interface::workload::CanonicalLedger>(&bytes)
                .unwrap()
                .destinations[id]
                .tip
                .cursor
        }

        #[test]
        fn destination_requests_over_the_socket_reach_the_ledger() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let served = serve_workloads();
            let (key, enrollment) = destination_fixtures();
            assert!(matches!(
                enroll_destination(&served.socket, &enrollment),
                DestinationOutcome::Committed(_)
            ));
            let prepared = step(&key, &enrollment);
            let DestinationOutcome::Committed(commit) =
                commit_destination(&served.socket, &prepared)
            else {
                panic!("the prepared head must commit");
            };
            assert_eq!(commit.tip.cursor, 1);
            assert_eq!(
                disk_destination_tip(&served.home, &enrollment.destination),
                1
            );

            commit_workload(&served.socket, &quarantine("w")).unwrap();
            assert!(matches!(
                commit_destination(&served.socket, &prepared),
                DestinationOutcome::Committed(_)
            ));
            let mut next = step(&key, &enrollment);
            next.head.expected = prepared.head.next.clone();
            next.head.next.cursor = 2;
            let next = next.head.sign(&key).unwrap();
            assert!(matches!(
                commit_destination(&served.socket, &next),
                DestinationOutcome::Refused(_)
            ));
            assert_eq!(
                disk_destination_tip(&served.home, &enrollment.destination),
                1
            );
        }

        #[test]
        fn a_destination_commit_completes_while_an_activation_holds_the_activation_lock() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let served = serve_workloads();
            let (key, enrollment) = destination_fixtures();
            let _activation = ACTIVATIONS.lock().unwrap();
            let started = std::time::Instant::now();
            assert!(matches!(
                enroll_destination(&served.socket, &enrollment),
                DestinationOutcome::Committed(_)
            ));
            assert!(matches!(
                commit_destination(&served.socket, &step(&key, &enrollment)),
                DestinationOutcome::Committed(_)
            ));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn handle_refuses_a_destination_commit_over_the_cap_and_still_quarantines() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let store = GenerationStore::open(home.path().to_path_buf()).unwrap();
            let workloads = WorkloadStore::open(home.path()).unwrap();
            let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
            let (key, enrollment) = destination_fixtures();
            let prepared = step(&key, &enrollment);
            WAITING_ACTIVATIONS.store(MAX_ACTIVATIONS, Ordering::SeqCst);
            let enroll = handle(
                Request::EnrollDestination { enrollment },
                &store,
                &workloads,
                &status,
            );
            let commit = handle(
                Request::CommitDestination { prepared },
                &store,
                &workloads,
                &status,
            );
            let quarantined = handle(
                Request::CommitWorkload {
                    change: quarantine("suspect"),
                },
                &store,
                &workloads,
                &status,
            );
            WAITING_ACTIVATIONS.store(0, Ordering::SeqCst);
            for refused in [enroll, commit] {
                assert!(matches!(
                    refused.unwrap(),
                    Response::Refused { message } if message == WAITING_DESTINATIONS_MESSAGE
                ));
            }
            assert!(matches!(quarantined.unwrap(), Response::Workload { .. }));
        }

        fn handle_destination(request: Request, home: &Path) -> Response {
            let store = GenerationStore::open(home.to_path_buf()).unwrap();
            let workloads = WorkloadStore::open(home).unwrap();
            let status = CoordinatorStatus::of_this_process(home, Lifetime::Detached);
            handle(request, &store, &workloads, &status).unwrap()
        }

        #[test]
        fn a_destination_nobody_enrolled_is_answered_unenrolled_and_a_refusal_as_refused() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let (key, enrollment) = destination_fixtures();
            assert!(matches!(
                handle_destination(
                    Request::CommitDestination {
                        prepared: step(&key, &enrollment)
                    },
                    home.path()
                ),
                Response::Unenrolled { .. }
            ));
            let mut malformed = enrollment;
            malformed.key = "zz".into();
            assert!(matches!(
                handle_destination(
                    Request::EnrollDestination {
                        enrollment: malformed
                    },
                    home.path()
                ),
                Response::Refused { .. }
            ));
        }

        #[test]
        fn an_unreadable_ledger_is_answered_unresolved_to_a_destination_request_not_refused() {
            let _serial = MUTEX_TESTS.lock().unwrap();
            let home = tempfile::tempdir().unwrap();
            let (key, enrollment) = destination_fixtures();
            {
                let workloads = WorkloadStore::open(home.path()).unwrap();
                workloads.enroll_destination(&enrollment).unwrap();
            }
            std::fs::write(
                mvm_core::host_interface::workload::canonical_dir_at(home.path())
                    .join(mvm_core::host_interface::workload::LEDGER_FILE),
                b"{",
            )
            .unwrap();
            for request in [
                Request::EnrollDestination { enrollment },
                Request::CommitDestination {
                    prepared: step(&key, &destination_fixtures().1),
                },
            ] {
                assert!(matches!(
                    handle_destination(request, home.path()),
                    Response::Unresolved { .. }
                ));
            }
        }

        #[test]
        fn a_busy_or_older_coordinator_is_unknown_and_a_refusal_is_definite() {
            let (_key, enrollment) = destination_fixtures();
            let socket_dir = tempfile::tempdir().unwrap();
            let socket = socket_dir.path().join("s.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let replies = [
                Response::Refused {
                    message: CONNECTION_LIMIT_MESSAGE.into(),
                },
                Response::Refused {
                    message: format!(
                        "{FRAME_DECODE_CONTEXT}: unknown variant `enroll_destination`"
                    ),
                },
                Response::Refused {
                    message: "workload is quarantined".into(),
                },
                Response::Unresolved {
                    message: "x".into(),
                },
            ];
            let serving = std::thread::spawn(move || {
                for reply in replies {
                    let (mut stream, _) = listener.accept().unwrap();
                    let _ = read_frame::<Request>(&mut stream, MAX_REQUEST_BYTES);
                    write_frame(&mut stream, &reply, MAX_RESPONSE_BYTES).unwrap();
                }
            });
            let outcomes: Vec<_> = (0..4)
                .map(|_| enroll_destination(&socket, &enrollment))
                .collect();
            serving.join().unwrap();
            assert!(matches!(
                outcomes[0],
                DestinationOutcome::Unknown {
                    needs_recovery: false,
                    ..
                }
            ));
            assert!(matches!(
                outcomes[1],
                DestinationOutcome::Unknown {
                    needs_recovery: false,
                    ..
                }
            ));
            assert!(matches!(outcomes[2], DestinationOutcome::Refused(_)));
            assert!(matches!(
                outcomes[3],
                DestinationOutcome::Unknown {
                    needs_recovery: true,
                    ..
                }
            ));
            assert!(matches!(
                enroll_destination(&socket_dir.path().join("none.sock"), &enrollment),
                DestinationOutcome::Unknown { .. }
            ));
        }

        #[test]
        fn destination_requests_round_trip_and_refuse_unknown_fields() {
            let (key, enrollment) = destination_fixtures();
            for request in [
                Request::CommitDestination {
                    prepared: step(&key, &enrollment),
                },
                Request::EnrollDestination { enrollment },
            ] {
                let bytes = serde_json::to_vec(&request).unwrap();
                serde_json::from_slice::<Request>(&bytes).unwrap();
            }
            assert!(
                serde_json::from_slice::<Request>(
                    br#"{"op":"commit_destination","prepared":{},"x":1}"#
                )
                .is_err()
            );
        }

        #[test]
        fn a_recover_request_round_trips() {
            let bytes = serde_json::to_vec(&Request::Recover).unwrap();
            assert!(matches!(
                serde_json::from_slice::<Request>(&bytes).unwrap(),
                Request::Recover
            ));
        }

        #[test]
        fn an_unresolved_publication_is_reported_apart_from_an_ordinary_refusal() {
            let unresolved = anyhow::Error::new(PublicationUnresolved::new("index write failed"))
                .context("activating");
            assert!(matches!(
                error_response(&unresolved),
                Response::Unresolved { .. }
            ));
            assert!(matches!(
                error_response(&anyhow::anyhow!("plain failure")),
                Response::Refused { .. }
            ));
        }

        #[test]
        fn the_unresolved_response_round_trips() {
            let reply = Response::Unresolved {
                message: "unknown".into(),
            };
            let bytes = serde_json::to_vec(&reply).unwrap();
            assert!(matches!(
                serde_json::from_slice::<Response>(&bytes).unwrap(),
                Response::Unresolved { message } if message == "unknown"
            ));
        }

        #[test]
        fn trickled_status_bytes_do_not_renew_the_exchange_deadline() {
            let status = CoordinatorStatus {
                protocol: super::super::super::managed::STATUS_PROTOCOL,
                pid: 42,
                uid: 1000,
                home: PathBuf::from("/home/operator/.state"),
                lifetime: Lifetime::Detached,
            };
            let body = serde_json::to_vec(&Response::Status { status }).unwrap();
            let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            frame.extend(body);
            let (client, mut server) = UnixStream::pair().unwrap();
            let (stop, stopped) = std::sync::mpsc::sync_channel(1);
            let answering = std::thread::spawn(move || {
                server.set_read_timeout(Some(STATUS_TIMEOUT)).unwrap();
                let request = read_frame::<Request>(&mut server, MAX_REQUEST_BYTES).unwrap();
                assert!(matches!(request, Request::Status));
                for chunk in frame.chunks(frame.len().div_ceil(12)) {
                    if server.write_all(chunk).is_err()
                        || stopped.recv_timeout(STATUS_TIMEOUT / 8).is_ok()
                    {
                        break;
                    }
                }
            });
            let result = exchange_status(client, Instant::now() + STATUS_TIMEOUT);
            let _ = stop.send(());
            answering.join().unwrap();
            let error = result.expect_err("partial progress must not renew the status budget");
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::TimedOut,
                "{error:#}"
            );
        }

        #[test]
        fn an_expired_status_deadline_closes_without_sending() {
            let (client, mut server) = UnixStream::pair().unwrap();
            let error = exchange_status(client, Instant::now()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::TimedOut
            );
            server.set_nonblocking(true).unwrap();
            assert_eq!(server.read(&mut [0]).unwrap(), 0, "no request bytes sent");
        }

        #[test]
        fn a_status_reply_is_bounded_and_must_be_a_status() {
            for reply in [
                Response::Ready,
                Response::Refused {
                    message: "unknown variant `status`".into(),
                },
            ] {
                let (client, mut server) = UnixStream::pair().unwrap();
                let answering = std::thread::spawn(move || {
                    let request = read_frame::<Request>(&mut server, MAX_REQUEST_BYTES).unwrap();
                    assert!(matches!(request, Request::Status));
                    write_frame(&mut server, &reply, MAX_RESPONSE_BYTES).unwrap();
                });
                assert!(exchange_status(client, Instant::now() + STATUS_TIMEOUT).is_err());
                answering.join().unwrap();
            }
            let (client, mut server) = UnixStream::pair().unwrap();
            server
                .write_all(&u32::try_from(MAX_STATUS_BYTES + 1).unwrap().to_be_bytes())
                .unwrap();
            let error = exchange_status(client, Instant::now() + STATUS_TIMEOUT).unwrap_err();
            assert!(error.to_string().contains("exceeds its limit"), "{error}");
        }

        #[test]
        fn frame_length_is_checked_before_allocating_or_parsing() {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            sender
                .write_all(&u32::try_from(MAX_REQUEST_BYTES + 1).unwrap().to_be_bytes())
                .unwrap();
            let error = read_frame::<Request>(&mut receiver, MAX_REQUEST_BYTES).unwrap_err();
            assert!(error.to_string().contains("exceeds its limit"), "{error}");
        }

        #[test]
        fn requests_reject_unknown_fields_and_round_trip() {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            write_frame(
                &mut sender,
                &Request::Read {
                    project: PathBuf::from("/project"),
                },
                MAX_REQUEST_BYTES,
            )
            .unwrap();
            let received = read_frame::<Request>(&mut receiver, MAX_REQUEST_BYTES).unwrap();
            assert!(matches!(received, Request::Read { .. }));
            assert!(
                serde_json::from_slice::<Request>(
                    br#"{"op":"activate","project":"/project","skip_quiescence":true}"#
                )
                .is_err()
            );
        }
    }
}

/// Serve the resident host-only coordinator.
///
/// With no arguments the MVM home is the one a launcher passed on stdin, and
/// the process outlives that launcher detached. With `--managed-home HOME` it
/// is the fixed unit of a systemd user manager for that home, and refuses to
/// serve unless the manager really did start it as that unit.
///
/// # Errors
///
/// The arguments, config, owner-only socket, committed state, or listener is
/// unusable, or a managed start is not the unit it claims to be.
pub fn serve() -> Result<()> {
    #[cfg(unix)]
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            home: PathBuf,
        }
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        match arguments.as_slice() {
            [] => {
                let bytes = crate::read_launch_config("mvm-policy-coordinator")?;
                let config: Config = serde_json::from_slice(&bytes)?;
                unix::serve(&config.home, Lifetime::Detached)
            }
            [flag, home] if flag == super::managed::MANAGED_HOME_FLAG => {
                let home = Path::new(home);
                unix::serve_managed(home)
            }
            _ => anyhow::bail!(
                "usage: mvm-policy-coordinator [{} HOME]",
                super::managed::MANAGED_HOME_FLAG
            ),
        }
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("policy coordinator is supported only on Linux and macOS")
    }
}

#[cfg(target_os = "linux")]
pub(super) use unix::exchange_status;
#[cfg(all(test, unix))]
pub(crate) use unix::serve_in_process;
#[cfg(all(test, target_os = "linux"))]
pub(super) use unix::{bind, serve_on};

/// Send a bounded request to the local coordinator.
///
/// # Errors
///
/// The resident owner is unavailable or the response is malformed.
pub fn call(socket: &Path, request: &Request) -> Result<Response> {
    #[cfg(unix)]
    {
        unix::call(socket, request)
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, request);
        anyhow::bail!("policy coordinator is supported only on Linux and macOS")
    }
}

/// Commit one workload ledger change through the coordinator at `socket`.
///
/// # Errors
///
/// The coordinator is unavailable or refuses the change. When the request was
/// sent but no usable reply came back, or the coordinator reports the commit
/// unresolved, the outcome is unknown: read the ledger back rather than
/// assuming the change did not land.
pub fn commit_workload(socket: &Path, change: &WorkloadChange) -> Result<WorkloadCommit> {
    let request = Request::CommitWorkload {
        change: change.clone(),
    };
    match call(socket, &request) {
        Ok(Response::Workload { commit }) => Ok(commit),
        Ok(Response::Refused { message }) if refused_by_older_coordinator(&message) => {
            anyhow::bail!(
                "the running policy coordinator is older than this binary and must be stopped before workload changes can be committed"
            )
        }
        Ok(Response::Refused { message }) => {
            anyhow::bail!("policy coordinator refused: {message}")
        }
        Ok(Response::Unresolved { message }) => anyhow::bail!(
            "the outcome of the workload ledger commit is unknown and must be read back: {message}"
        ),
        Ok(
            Response::Ready
            | Response::Status { .. }
            | Response::Policy { .. }
            | Response::Destination { .. }
            | Response::Unenrolled { .. },
        ) => {
            anyhow::bail!("unexpected policy coordinator response to a workload commit")
        }
        Err(error) if error.downcast_ref::<ReplyLost>().is_some() => anyhow::bail!(
            "the outcome of the workload ledger commit is unknown and must be read back, not assumed uncommitted: {error:#}"
        ),
        Err(error) => Err(error.context("policy coordinator unavailable for a workload commit")),
    }
}

/// An older coordinator cannot decode `commit_workload`, so it answers with
/// its frame-decoding failure naming that request.
fn refused_by_older_coordinator(message: &str) -> bool {
    names_unknown_request(message, "commit_workload")
}

fn names_unknown_request(message: &str, op: &str) -> bool {
    message.contains(FRAME_DECODE_CONTEXT) && message.contains(op)
}

/// What a destination request came to. `Refused` means nothing was written;
/// `Unknown` means the owner may or may not have acted, and the same signed
/// request can be sent again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationOutcome {
    Committed(DestinationCommit),
    Refused(String),
    /// The owner holds no such destination; enrolling it again may make the
    /// same request succeed.
    NotEnrolled(String),
    Unknown {
        message: String,
        /// The owner reported an interrupted commit, so ask it to recover
        /// before sending again.
        needs_recovery: bool,
    },
}

fn unknown(message: String, needs_recovery: bool) -> DestinationOutcome {
    DestinationOutcome::Unknown {
        message,
        needs_recovery,
    }
}

fn destination_outcome(socket: &Path, request: &Request, op: &str) -> DestinationOutcome {
    match call(socket, request) {
        Ok(Response::Destination { commit }) => DestinationOutcome::Committed(commit),
        Ok(Response::Refused { message }) if names_unknown_request(&message, op) => unknown(
            "the running policy coordinator is older than this binary".into(),
            false,
        ),
        Ok(Response::Refused { message })
            if message == CONNECTION_LIMIT_MESSAGE || message == WAITING_DESTINATIONS_MESSAGE =>
        {
            unknown(message, false)
        }
        Ok(Response::Refused { message }) => DestinationOutcome::Refused(message),
        Ok(Response::Unenrolled { message }) => DestinationOutcome::NotEnrolled(message),
        Ok(Response::Unresolved { message }) => unknown(message, true),
        Ok(
            Response::Ready
            | Response::Status { .. }
            | Response::Policy { .. }
            | Response::Workload { .. },
        ) => unknown("unexpected policy coordinator response".into(), false),
        Err(error) => unknown(format!("{error:#}"), false),
    }
}

/// Enroll a mailbox destination through the coordinator at `socket`.
pub fn enroll_destination(socket: &Path, enrollment: &DestinationEnrollment) -> DestinationOutcome {
    let request = Request::EnrollDestination {
        enrollment: enrollment.clone(),
    };
    destination_outcome(socket, &request, "enroll_destination")
}

/// Commit one signed prepared head through the coordinator at `socket`.
pub fn commit_destination(socket: &Path, prepared: &SignedPreparedHead) -> DestinationOutcome {
    let request = Request::CommitDestination {
        prepared: prepared.clone(),
    };
    destination_outcome(socket, &request, "commit_destination")
}

/// Connect to the resident owner of `home`, spawning its separate
/// `mvm-hostd` process under a serialized spawn lock if no process is
/// listening.
///
/// # Errors
///
/// The private state or helper is unavailable, or its readiness check fails.
pub fn ensure(home: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        unix::ensure(home)
    }
    #[cfg(not(unix))]
    {
        let _ = home;
        anyhow::bail!("local policy coordinator is supported only on Linux and macOS")
    }
}

#[cfg(test)]
mod older_coordinator_tests {
    use super::*;

    #[test]
    fn only_a_frame_decoding_refusal_naming_the_request_reads_as_an_older_coordinator() {
        let old = format!(
            "{FRAME_DECODE_CONTEXT}: unknown variant `commit_workload`, expected one of `ping`"
        );
        assert!(refused_by_older_coordinator(&old));
        assert!(!refused_by_older_coordinator("workload ledger is full"));
        assert!(!refused_by_older_coordinator(&format!(
            "{FRAME_DECODE_CONTEXT}: unknown variant `other`"
        )));
    }
}
