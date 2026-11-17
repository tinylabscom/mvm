//! Resident local policy-generation owner over an owner-only Unix socket.
//!
//! Initial activation serializes with the shared launch/restore barrier,
//! proves whole-host quiescence, and publishes generation 1 durably. No
//! workload effects, signers, or guest traffic are served on this socket.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{GenerationStore, ProjectPolicyCandidate, prepare_initial};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A local request to the resident lifecycle owner.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Versioned, side-effect-free readiness check.
    Ping,
    /// Commit generation one for a project while the entire host is idle.
    Activate { project: PathBuf },
    /// Return a validated committed generation, if one exists.
    Read { project: PathBuf },
}

/// Response from the owner. An absent `Read` result is an ordinary,
/// non-activated project; a corrupt or missing *activated* record is an error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ready,
    Policy {
        candidate: Option<Box<ProjectPolicyCandidate>>,
    },
    Refused {
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
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    static ACTIVATIONS: Mutex<()> = Mutex::new(());

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

    fn handle(request: Request, store: &GenerationStore) -> Result<Response> {
        if let Request::Activate { project } | Request::Read { project } = &request {
            ensure!(
                project.is_absolute(),
                "policy project identity must be absolute"
            );
        }
        let source = mvm_policy::PolicyStore::from_config();
        let candidate = match request {
            Request::Ping => return Ok(Response::Ready),
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

    pub(super) fn serve(home: &Path) -> Result<()> {
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
        for stream in listener.incoming() {
            let mut stream = stream.context("accepting policy coordinator request")?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            let store = Arc::clone(&store);
            // An activation can wait on a caller's shared launch guard.
            // Accepting pings and reads on independent connections is
            // necessary: making the waiting activation block the listener
            // would deadlock a launcher that holds that guard and connects.
            std::thread::spawn(move || {
                let reply = match read_frame(&mut stream, MAX_REQUEST_BYTES)
                    .and_then(|request| handle(request, &store))
                {
                    Ok(response) => response,
                    Err(error) => Response::Refused {
                        message: format!("{error:#}"),
                    },
                };
                if let Err(error) = write_frame(&mut stream, &reply, MAX_RESPONSE_BYTES) {
                    tracing::warn!(%error, "policy coordinator could not return a response");
                }
            });
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
                let error = handle(request, &store).unwrap_err();
                assert!(error.to_string().contains("must be absolute"), "{error}");
            }
            assert!(!store.has_active_generation().unwrap());
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

/// Serve the resident host-only coordinator, using the MVM home the launcher
/// passed on stdin. The CLI/SDK starts this automatically, never an operator.
///
/// # Errors
///
/// The config, owner-only socket, committed state, or listener is unusable.
pub fn serve() -> Result<()> {
    #[cfg(unix)]
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            home: PathBuf,
        }
        let bytes = crate::read_launch_config("mvm-policy-coordinator")?;
        let config: Config = serde_json::from_slice(&bytes)?;
        unix::serve(&config.home)
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("policy coordinator is supported only on Linux and macOS")
    }
}

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
