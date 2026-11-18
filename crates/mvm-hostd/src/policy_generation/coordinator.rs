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

use super::managed::CoordinatorStatus;
#[cfg(unix)]
use super::managed::Lifetime;
#[cfg(unix)]
use super::store::PublicationUnresolved;
use super::{GenerationStore, ProjectPolicyCandidate, prepare_initial};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(any(test, target_os = "linux"))]
const MAX_STATUS_BYTES: usize = 4 * 1024;
/// Handler threads alive at once; a connection past this is refused. An
/// activation can hold its thread for as long as a launch holds the shared
/// barrier, so the count needs a ceiling, and it stays well under the default
/// soft file-descriptor limit of 1024.
const MAX_CONNECTIONS: usize = 256;

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
    /// Resolve an interrupted publication if no activation is running now.
    Recover,
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
    Refused {
        message: String,
    },
    /// An activation's outcome is unknown; reads stay refused until the
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

    use super::*;

    static ACTIVATIONS: Mutex<()> = Mutex::new(());
    #[cfg(any(test, target_os = "linux"))]
    const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

    fn read_frame<T: serde::de::DeserializeOwned>(
        stream: &mut UnixStream,
        max: usize,
    ) -> Result<T> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(length <= max, "policy coordinator frame exceeds its limit");
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes)?;
        serde_json::from_slice(&bytes).context("decoding policy coordinator frame")
    }

    fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T, max: usize) -> Result<()> {
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
    }

    /// Ask the process on this connection who it is, within a short deadline
    /// and a small reply. The caller decides whether to believe it.
    #[cfg(any(test, target_os = "linux"))]
    pub(in crate::policy_generation) fn exchange_status(
        stream: &mut UnixStream,
    ) -> Result<CoordinatorStatus> {
        stream.set_read_timeout(Some(STATUS_TIMEOUT))?;
        stream.set_write_timeout(Some(STATUS_TIMEOUT))?;
        write_frame(stream, &Request::Status, MAX_REQUEST_BYTES)?;
        match read_frame(stream, MAX_STATUS_BYTES)? {
            Response::Status { status } => Ok(status),
            Response::Refused { message } => {
                anyhow::bail!("policy coordinator refused a status request: {message}")
            }
            Response::Ready | Response::Policy { .. } | Response::Unresolved { .. } => {
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
                if let Ok(_one_activation) = ACTIVATIONS.try_lock() {
                    store.recover()?;
                }
                return Ok(Response::Ready);
            }
            Request::Activate { project } => {
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
        if error.downcast_ref::<PublicationUnresolved>().is_some() {
            Response::Unresolved { message }
        } else {
            Response::Refused { message }
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
        let (listener, store, _owner) = {
            let _spawn_lock = mvm_core::util::atomic_io::FileLock::acquire(&dir.join("spawn"))?;
            bind(home)?
        };
        serve_on(
            &listener,
            &store,
            &CoordinatorStatus::of_this_process(home, lifetime),
        )
    }

    pub(super) fn serve(home: &Path, lifetime: Lifetime) -> Result<()> {
        let (listener, store, _owner) = bind(home)?;
        serve_on(
            &listener,
            &store,
            &CoordinatorStatus::of_this_process(home, lifetime),
        )
    }

    pub(in crate::policy_generation) fn bind(
        home: &Path,
    ) -> Result<(
        UnixListener,
        Arc<GenerationStore>,
        mvm_core::util::atomic_io::FileLock,
    )> {
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
        let dir = socket
            .parent()
            .context("policy coordinator socket has no parent")?;
        mvm_core::private_fs::create_owned_private_dir(dir)?;
        // Held for the listener's lifetime: recovery is only safe for the one
        // process that owns the store, and the socket probe below can race.
        let owner = mvm_core::util::atomic_io::FileLock::try_acquire(&dir.join("owner"))?
            .context("policy coordinator is already running")?;
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
        Ok((listener, store, owner))
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
                    message: "policy coordinator is at its connection limit".into(),
                };
                let _ = write_frame(&mut stream, &busy, MAX_RESPONSE_BYTES);
                continue;
            }
            let store = Arc::clone(store);
            let status = status.clone();
            let slot = Slot(Arc::clone(&in_flight));
            // An activation can wait on a caller's shared launch guard.
            // Accepting pings and reads on independent connections is
            // necessary: making the waiting activation block the listener
            // would deadlock a launcher that holds that guard and connects.
            let spawned = std::thread::Builder::new().spawn(move || {
                let _slot = slot;
                let reply = match read_frame(&mut stream, MAX_REQUEST_BYTES)
                    .and_then(|request| handle(request, &store, &status))
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
            let home = tempfile::tempdir().unwrap();
            let store = GenerationStore::open(home.path().to_path_buf()).unwrap();
            for request in [
                Request::Activate {
                    project: PathBuf::from("."),
                },
                Request::Read {
                    project: PathBuf::from("."),
                },
            ] {
                let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
                let error = handle(request, &store, &status).unwrap_err();
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
            let (listener, store, owner) = bind(&home).unwrap();
            let served = status.clone();
            std::thread::spawn(move || {
                let _owner = owner;
                serve_on(&listener, &store, &served)
            });

            let socket = socket_path(&home);
            let mut stream = UnixStream::connect(&socket).unwrap();
            assert_eq!(exchange_status(&mut stream).unwrap(), status);
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
            store
                .write_obligation(&"a".repeat(64), &"b".repeat(64))
                .unwrap();
            let status = CoordinatorStatus::of_this_process(home.path(), Lifetime::Detached);
            let reply = handle(Request::Recover, &store, &status).unwrap();
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
            let error = handle(Request::Read { project }, &store, &status).unwrap_err();
            assert!(matches!(
                error_response(&error),
                Response::Unresolved { .. }
            ));
            held.send(()).unwrap();
            holder.join().unwrap();
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
        fn a_status_reply_is_bounded_and_must_be_a_status() {
            for reply in [
                Response::Ready,
                Response::Refused {
                    message: "unknown variant `status`".into(),
                },
            ] {
                let (mut client, mut server) = UnixStream::pair().unwrap();
                let answering = std::thread::spawn(move || {
                    let request = read_frame::<Request>(&mut server, MAX_REQUEST_BYTES).unwrap();
                    assert!(matches!(request, Request::Status));
                    write_frame(&mut server, &reply, MAX_RESPONSE_BYTES).unwrap();
                });
                assert!(exchange_status(&mut client).is_err());
                answering.join().unwrap();
            }
            let (mut client, mut server) = UnixStream::pair().unwrap();
            server
                .write_all(&u32::try_from(MAX_STATUS_BYTES + 1).unwrap().to_be_bytes())
                .unwrap();
            let error = exchange_status(&mut client).unwrap_err();
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
