use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::RuntimeArtifacts;

mod deadline;

const SOCKET: &str = "runtime-artifacts.sock";
const MAX_REPLY: u64 = 256 * 1024;

/// Where a VM's observer socket lives. Through the per-VM socket namespace, not
/// the state directory itself: a deep configured home overflows the Unix
/// socket path limit, and every other socket of the VM already makes this move.
fn socket_path(state_dir: &Path) -> std::path::PathBuf {
    mvm_core::config::vm_socket_dir_at(state_dir).join(SOCKET)
}

/// A typed refusal is distinct from missing/unreachable supervisor IPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationError {
    NotPaused,
    Unsupported,
}

impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPaused => "runtime artifact observation requires all vCPUs paused",
            Self::Unsupported => "runtime artifact observation unavailable for this boot",
        })
    }
}
impl std::error::Error for ObservationError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    challenge: [u8; 32],
    result: std::result::Result<Evidence, ObservationError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Origin {
    LoadedBoot,
    InheritedSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    origin: Origin,
    artifacts: RuntimeArtifacts,
}

/// A single-purpose local query, authenticated against the supervisor's kernel
/// peer identity, never against a pid or configuration supplied in its reply.
/// Identity may be inherited from an authenticated snapshot. Neither origin
/// measures current guest RAM or protects against a hostile same-UID host.
pub fn query(state_dir: &Path, expected_pid: u32) -> Result<RuntimeArtifacts> {
    let end = Instant::now() + Duration::from_secs(2);
    let stream = mvm_agentd::vsock::connect_unix_before(&socket_path(state_dir), end)
        .context("connect supervisor runtime artifact observer")?;
    let (pid, uid) = peer_identity(&stream)?;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    ensure!(
        pid == expected_pid && uid == unsafe { libc::geteuid() },
        "wrong supervisor peer"
    );
    stream.set_nonblocking(true)?;
    let challenge: [u8; 32] = rand::random();
    deadline::write_all(&stream, &challenge, end)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut prefix = [0; 4];
    deadline::read_exact(&stream, &mut prefix, end)?;
    let len = u32::from_be_bytes(prefix);
    ensure!(
        u64::from(len) <= MAX_REPLY,
        "oversized runtime artifact reply"
    );
    let mut bytes = vec![0; len as usize];
    deadline::read_exact(&stream, &mut bytes, end)?;
    deadline::eof(&stream, end)?;
    let reply: Reply = serde_json::from_slice(&bytes)?;
    ensure!(reply.challenge == challenge, "wrong runtime artifact query");
    reply
        .result
        .map(|evidence| evidence.artifacts)
        .map_err(Into::into)
}

/// Serviced on the primary vCPU thread, not a network server or a worker that
/// could observe a stale pause marker. One connection per run-loop turn bounds
/// work; short I/O deadlines also bound a same-user client that sends nothing.
#[derive(Debug)]
pub struct Observer {
    listener: UnixListener,
    artifacts: Option<RuntimeArtifacts>,
    origin: Origin,
    path: std::path::PathBuf,
    inode: u64,
}

impl Observer {
    pub fn bind(state_dir: &Path, artifacts: Option<RuntimeArtifacts>) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(state_dir)?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0,
            "unsafe supervisor state directory"
        );
        // Do not unlink a pre-existing endpoint: a second supervisor must not
        // silently steal an existing instance's query channel.
        let path = socket_path(state_dir);
        mvm_core::config::secure_fallback_socket_dir_at(state_dir)?;
        if let Some(parent) = path.parent() {
            mvm_core::private_fs::ensure_private_dir(parent)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let inode = std::fs::symlink_metadata(&path)?.ino();
        Ok(Self {
            listener,
            artifacts,
            origin: Origin::LoadedBoot,
            path,
            inode,
        })
    }

    /// Called only with the final bootargs used to construct the guest DTB.
    pub fn set_kernel_cmdline(&mut self, cmdline: String) {
        if let Some(artifacts) = &mut self.artifacts {
            artifacts.kernel_cmdline = cmdline;
        }
    }

    /// Called with the kernel bytes already placed in guest RAM before execution.
    pub fn set_loaded_kernel(&mut self, artifact: super::RuntimeArtifact) {
        if let Some(artifacts) = &mut self.artifacts {
            artifacts.kernel = Some(artifact);
        }
    }

    /// Retained within the authenticated snapshot frame, never in mutable
    /// supervisor metadata.
    pub fn snapshot_payload(&self) -> Result<Vec<u8>> {
        let Some(artifacts) = self.artifacts.clone() else {
            // Preserve historical frame behavior. Checkpoint admission queries
            // refuse this lineage; the low-level snapshot need not kill a VM.
            return Ok(Vec::new());
        };
        let bytes = serde_json::to_vec(&Evidence {
            origin: self.origin,
            artifacts,
        })?;
        ensure!(
            bytes.len() as u64 <= MAX_REPLY,
            "oversized runtime artifact evidence"
        );
        Ok(bytes)
    }

    /// The caller supplies only the artifact section of the verified,
    /// descriptor-owned frame whose RAM was mapped for this restore.
    pub fn inherit_verified_snapshot(&mut self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            self.artifacts = None;
            return Ok(());
        }
        ensure!(
            payload.len() as u64 <= MAX_REPLY,
            "oversized inherited evidence"
        );
        let inherited: Evidence = serde_json::from_slice(payload)
            .context("snapshot lacks runtime artifact evidence; recapture from a verified boot")?;
        let current = self
            .artifacts
            .as_mut()
            .ok_or(ObservationError::Unsupported)?;
        ensure!(
            inherited.artifacts.initramfs == current.initramfs,
            "restored initramfs lineage differs from selected runtime"
        );
        // Disks are freshly opened. Their measurements remain, and the
        // consumer verifies selected runtime read-only attachments.
        // Cmdline belongs to saved RAM, not this new loader's config.
        current.initramfs = inherited.artifacts.initramfs;
        current.kernel = inherited.artifacts.kernel;
        current.kernel_cmdline = inherited.artifacts.kernel_cmdline;
        self.origin = Origin::InheritedSnapshot;
        Ok(())
    }

    pub fn service<G>(&self, all_paused: impl Fn() -> Option<G>) {
        if let Ok((stream, _)) = self.listener.accept() {
            // A malformed or disconnected client must not kill the VM.
            let _ = self.answer(stream, all_paused);
        }
    }

    fn answer<G>(&self, stream: UnixStream, all_paused: impl Fn() -> Option<G>) -> Result<()> {
        let end = Instant::now() + Duration::from_millis(50);
        let (_, uid) = peer_identity(&stream)?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            uid == unsafe { libc::geteuid() },
            "wrong observer client uid"
        );
        stream.set_nonblocking(true)?;
        let mut challenge = [0; 32];
        deadline::read_exact(&stream, &mut challenge, end)?;
        deadline::eof(&stream, end)?;
        // A backend-provided guard holds every CPU out of guest execution
        // through evidence capture/serialization, but never through socket I/O.
        let pause_guard = all_paused();
        let result = if pause_guard.is_none() {
            Err(ObservationError::NotPaused)
        } else {
            self.artifacts
                .clone()
                .map(|artifacts| Evidence {
                    origin: self.origin,
                    artifacts,
                })
                .ok_or(ObservationError::Unsupported)
        };
        let bytes = serde_json::to_vec(&Reply { challenge, result })?;
        drop(pause_guard);
        ensure!(
            bytes.len() as u64 <= MAX_REPLY,
            "oversized observer evidence"
        );
        deadline::write_all(&stream, &(bytes.len() as u32).to_be_bytes(), end)?;
        deadline::write_all(&stream, &bytes, end)?;
        Ok(())
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.inode) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn peer_identity(stream: &UnixStream) -> Result<(u32, u32)> {
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: live socket fd and correctly sized writable scalar outputs.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        ensure!(
            rc == 0,
            "read observer peer uid: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: LOCAL_PEERPID writes a pid_t into the provided sized buffer.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        ensure!(
            rc == 0 && len as usize == std::mem::size_of_val(&pid),
            "read observer peer pid: {}",
            std::io::Error::last_os_error()
        );
        Ok((u32::try_from(pid)?, uid))
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        // SAFETY: live socket fd and correctly sized writable ucred output.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        ensure!(
            rc == 0 && len as usize == std::mem::size_of_val(&cred),
            "read observer credentials: {}",
            std::io::Error::last_os_error()
        );
        Ok((u32::try_from(cred.pid)?, cred.uid))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = stream;
        anyhow::bail!("supervisor peer authentication unsupported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_artifacts::RuntimeArtifact;
    use std::io::{Read, Write};

    fn evidence() -> RuntimeArtifacts {
        RuntimeArtifacts {
            kernel: None,
            initramfs: Some(RuntimeArtifact::loaded("/loaded/initrd".into(), b"abc").unwrap()),
            disks: vec![],
            kernel_cmdline: "actual bootargs".into(),
            firecracker_drives: None,
        }
    }

    fn exchange(observer: &Observer, paused: bool) -> Reply {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&[7; 32]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        observer.answer(server, || paused.then_some(())).unwrap();
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).unwrap();
        serde_json::from_reader(client.take(u64::from(u32::from_be_bytes(prefix)))).unwrap()
    }

    #[test]
    fn a_state_directory_too_deep_for_a_socket_path_still_binds() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a".repeat(60)).join("b".repeat(60));
        mvm_core::private_fs::ensure_private_dir(&deep).unwrap();
        assert!(deep.join(SOCKET).as_os_str().len() > 104);
        let observer = Observer::bind(&deep, None).unwrap();
        let socket = socket_path(&deep);
        assert!(socket.exists());
        drop(observer);
        let _ = std::fs::remove_dir(socket.parent().unwrap());
    }

    #[test]
    fn paused_reply_roundtrips_and_ignores_mutable_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        observer.set_kernel_cmdline("final override".into());
        std::fs::write(dir.path().join("supervisor.json"), b"not configuration").unwrap();
        let reply = exchange(&observer, true);
        assert_eq!(reply.challenge, [7; 32]);
        let mut expected = evidence();
        expected.kernel_cmdline = "final override".into();
        let observed = reply.result.unwrap();
        assert_eq!(observed.origin, Origin::LoadedBoot);
        assert_eq!(observed.artifacts, expected);
    }

    #[test]
    fn not_paused_and_unavailable_are_typed_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let observer = Observer::bind(dir.path(), None).unwrap();
        assert_eq!(
            exchange(&observer, false).result,
            Err(ObservationError::NotPaused)
        );
        assert_eq!(
            exchange(&observer, true).result,
            Err(ObservationError::Unsupported)
        );
    }

    #[test]
    fn query_authenticates_peer_pid() {
        let dir = tempfile::tempdir().unwrap();
        let _observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        assert!(
            query(dir.path(), std::process::id().wrapping_add(1))
                .unwrap_err()
                .to_string()
                .contains("wrong supervisor peer")
        );
    }

    #[test]
    fn client_roundtrip_and_wrong_query_refusal() {
        for wrong_challenge in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
            observer.listener.set_nonblocking(false).unwrap();
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let (mut stream, _) = observer.listener.accept().unwrap();
                    if !wrong_challenge {
                        observer.answer(stream, || Some(())).unwrap();
                    } else {
                        let mut challenge = [0; 32];
                        stream.read_exact(&mut challenge).unwrap();
                        challenge[0] ^= 1;
                        let bytes = serde_json::to_vec(&Reply {
                            challenge,
                            result: Ok(Evidence {
                                origin: Origin::LoadedBoot,
                                artifacts: evidence(),
                            }),
                        })
                        .unwrap();
                        stream
                            .write_all(&(bytes.len() as u32).to_be_bytes())
                            .unwrap();
                        stream.write_all(&bytes).unwrap();
                    }
                });
                let result = query(dir.path(), std::process::id());
                if wrong_challenge {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("wrong runtime artifact query")
                    );
                } else {
                    assert_eq!(result.unwrap(), evidence());
                }
            });
        }
    }

    #[test]
    fn lifecycle_does_not_steal_existing_socket_and_cleans_own_endpoint() {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        assert!(Observer::bind(dir.path(), None).is_err());
        assert_eq!(
            std::fs::metadata(dir.path().join(SOCKET)).unwrap().mode() & 0o777,
            0o600
        );
        drop(observer);
        assert!(!dir.path().join(SOCKET).exists());
        assert!(query(dir.path(), std::process::id()).is_err());
        let _next = Observer::bind(dir.path(), None).unwrap();
    }

    #[test]
    fn malformed_request_does_not_receive_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        for request in [vec![1; 3], vec![1; 33]] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(&request).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(observer.answer(server, || Some(())).is_err());
        }
    }

    #[test]
    fn writable_directory_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Observer::bind(dir.path(), None).is_err());
    }

    #[test]
    fn recursive_snapshot_preserves_original_boot_and_refreshes_disks() {
        let dir = tempfile::tempdir().unwrap();
        let mut observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        let loaded_kernel = RuntimeArtifact::loaded("/loaded/kernel".into(), b"original").unwrap();
        observer.set_loaded_kernel(loaded_kernel.clone());
        let payload = observer.snapshot_payload().unwrap();
        observer.set_loaded_kernel(
            RuntimeArtifact::loaded("/new/kernel".into(), b"not loaded").unwrap(),
        );
        observer.set_kernel_cmdline("not loaded on restore".into());
        let fresh_disk = RuntimeArtifact::loaded("/new/disk".into(), b"fresh").unwrap();
        observer.artifacts.as_mut().unwrap().disks = vec![fresh_disk.clone()];
        observer.inherit_verified_snapshot(&payload).unwrap();
        let first = exchange(&observer, true).result.unwrap();
        assert_eq!(first.origin, Origin::InheritedSnapshot);
        assert_eq!(first.artifacts.kernel_cmdline, "actual bootargs");
        assert_eq!(first.artifacts.kernel, Some(loaded_kernel));
        assert_eq!(first.artifacts.disks, vec![fresh_disk]);
        let next = observer.snapshot_payload().unwrap();
        observer.inherit_verified_snapshot(&next).unwrap();
        assert_eq!(exchange(&observer, true).result.unwrap(), first);
        let historical = serde_json::to_vec(&Evidence {
            origin: Origin::LoadedBoot,
            artifacts: evidence(),
        })
        .unwrap();
        observer.inherit_verified_snapshot(&historical).unwrap();
        assert!(
            exchange(&observer, true)
                .result
                .unwrap()
                .artifacts
                .kernel
                .is_none(),
            "historical frame must not gain a fresh kernel measurement on restore"
        );
    }

    #[test]
    fn wrong_lineage_and_missing_frame_evidence_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        let mut different = evidence();
        different.initramfs.as_mut().unwrap().sha256 = "wrong-generation".into();
        let payload = serde_json::to_vec(&Evidence {
            origin: Origin::LoadedBoot,
            artifacts: different,
        })
        .unwrap();
        assert!(observer.inherit_verified_snapshot(&payload).is_err());
        assert!(observer.inherit_verified_snapshot(b"{}").is_err());
        assert_eq!(observer.origin, Origin::LoadedBoot);
        observer.inherit_verified_snapshot(b"").unwrap();
        assert!(observer.snapshot_payload().unwrap().is_empty());
        assert_eq!(
            exchange(&observer, true).result,
            Err(ObservationError::Unsupported)
        );
    }

    #[test]
    fn silent_and_slow_drip_clients_share_one_deadline() {
        for drip in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let started = Instant::now();
            std::thread::scope(|scope| {
                if drip {
                    scope.spawn(move || {
                        for _ in 0..32 {
                            if client.write_all(&[1]).is_err() {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    });
                }
                assert!(observer.answer(server, || Some(())).is_err());
            });
            assert!(started.elapsed() < Duration::from_millis(500));
        }
    }

    #[test]
    fn full_backlog_and_silent_server_cannot_extend_query_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        // SAFETY: reconfigure the live listener's backlog; no pointer arguments.
        assert_eq!(unsafe { libc::listen(observer.listener.as_raw_fd(), 1) }, 0);
        let _queued = UnixStream::connect(dir.path().join(SOCKET)).unwrap();
        let started = Instant::now();
        assert!(query(dir.path(), std::process::id()).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn resume_during_request_is_refused_and_guard_drops_before_send() {
        let dir = tempfile::tempdir().unwrap();
        let observer = Observer::bind(dir.path(), Some(evidence())).unwrap();
        let paused = std::sync::Mutex::new(true);
        let (mut client, server) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| {
                observer.answer(server, || {
                    let guard = paused.lock().unwrap();
                    (*guard).then_some(guard)
                })
            });
            // The request is incomplete until after resume; a pause check
            // performed before reading it would incorrectly authorize this.
            client.write_all(&[1; 16]).unwrap();
            *paused.lock().unwrap() = false;
            client.write_all(&[1; 16]).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            serving.join().unwrap().unwrap();
            let mut prefix = [0; 4];
            client.read_exact(&mut prefix).unwrap();
            let reply: Reply = serde_json::from_reader(client).unwrap();
            assert_eq!(reply.result, Err(ObservationError::NotPaused));
            assert!(paused.try_lock().is_ok());
        });
    }
}
