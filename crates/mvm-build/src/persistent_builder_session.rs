//! The persistent builder's session record transaction: one lock held across
//! read, write, touch and stop, so no two processes act on a stale record.

use super::*;

/// Serializes record transactions, not store deletion. The lock inode lives
/// outside the deletable builder cache and must never be unlinked. Acquire this
/// before any store lock; methods on this guard never acquire it recursively.
pub struct SessionRecordGuard {
    _lock: std::fs::File,
    path: PathBuf,
}

impl SessionRecordGuard {
    pub fn acquire() -> std::io::Result<Self> {
        let path = session_record_path()
            .ok_or_else(|| std::io::Error::other("persistent builder home is unavailable"))?;
        Self::acquire_at(path)
    }

    fn acquire_at(path: PathBuf) -> std::io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("record has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            loop {
                // SAFETY: flock operates on this owned file descriptor only.
                if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        #[cfg(not(unix))]
        return Err(std::io::Error::other(
            "persistent builders require Unix record locking",
        ));
        #[cfg(unix)]
        Ok(Self { _lock: lock, path })
    }

    pub fn read(&self) -> std::io::Result<SessionRecord> {
        serde_json::from_slice(&std::fs::read(&self.path)?).map_err(std::io::Error::other)
    }

    /// Publish complete JSON with mode 0600, atomically replacing the old record.
    pub fn write(&self, record: &SessionRecord) -> std::io::Result<()> {
        use std::io::Write;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| std::io::Error::other("record has no parent"))?;
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staged
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        staged.write_all(&serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?)?;
        staged.as_file().sync_all()?;
        staged.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }

    pub fn remove(&self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    pub fn stop(&self, record: &SessionRecord) {
        self.stop_with_supervisor(
            record,
            PersistentBuilderSupervisor::new(&record.dispatch_socket_path),
        );
    }

    fn stop_with_supervisor(
        &self,
        record: &SessionRecord,
        supervisor: PersistentBuilderSupervisor,
    ) {
        // A stale observer must never stop or unlink a replacement session.
        let Ok(current) = self.read() else { return };
        if current.session_id != record.session_id
            || current.supervisor_pid != record.supervisor_pid
            || current.dispatch_socket_path != record.dispatch_socket_path
        {
            return;
        }
        if let Err(error) = supervisor.shutdown() {
            tracing::warn!(%error, "persistent builder graceful shutdown failed");
        }
        if let Err(error) = terminate_supervisor(record.supervisor_pid) {
            tracing::warn!(%error, "persistent builder force-stop failed; record retained");
            return;
        }
        // Signal delivery is not proof of exit. Keep the record when uncertain
        // so a later start cannot publish over a VM that still owns the store.
        let _ = self.clear_stopped(record);
    }

    /// Clear only a matching record whose supervisor is confirmed absent.
    pub fn clear_stopped(&self, record: &SessionRecord) -> std::io::Result<bool> {
        let current = self.read()?;
        if current.session_id != record.session_id
            || current.supervisor_pid != record.supervisor_pid
            || current.dispatch_socket_path != record.dispatch_socket_path
            || supervisor_alive(record.supervisor_pid)
        {
            return Ok(false);
        }
        self.remove()?;
        Ok(true)
    }

    pub fn touch(&self, now_unix_secs: u64) -> std::io::Result<bool> {
        let mut record = match self.read() {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !supervisor_alive(record.supervisor_pid) {
            return Ok(false);
        }
        record.last_activity_unix_secs = Some(now_unix_secs);
        self.write(&record)?;
        Ok(true)
    }
}

#[cfg(all(test, unix))]
mod session_record_tests {
    use super::*;

    fn record(pid: u32) -> SessionRecord {
        SessionRecord {
            session_id: "record-test".into(),
            dispatch_socket_path: "/missing-dispatch.sock".into(),
            job_dir: "/missing-jobs".into(),
            disk_transport: None,
            workspace_root: "/work".into(),
            supervisor_pid: pid,
            last_activity_unix_secs: Some(1),
            boot_payload_digest: None,
        }
    }

    #[test]
    fn shutdown_requires_bye() {
        use std::os::unix::net::UnixListener;
        for response in [
            HostVmResponse::Bye {},
            HostVmResponse::WorkloadStatusReport {
                workload_id: WorkloadId::new(),
                status: "running".into(),
            },
        ] {
            let expected_success = matches!(&response, HostVmResponse::Bye {});
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("dispatch.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let peer = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = mvm_agentd::vsock::read_frame::<HostVmRequest>(&mut stream).unwrap();
                assert!(matches!(request, HostVmRequest::Shutdown {}));
                mvm_agentd::vsock::write_frame(&mut stream, &response).unwrap();
            });
            let result = PersistentBuilderSupervisor::new(socket)
                .with_frame_read_timeout(Duration::from_secs(1))
                .shutdown();
            peer.join().unwrap();
            assert_eq!(result.is_ok(), expected_success);
        }
    }

    #[test]
    fn silent_shutdown_releases_record_lock_within_budget() {
        use std::os::unix::net::UnixListener;
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dispatch.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let path = dir.path().join("session.json");
        let guard = SessionRecordGuard::acquire_at(path.clone()).unwrap();
        let mut session = record(std::process::id());
        session.dispatch_socket_path = socket.clone();
        guard.write(&session).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            // Independent watchdog prevents the regression from hanging tests.
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });
        let (done_tx, done_rx) = mpsc::channel();
        let stopping_session = session.clone();
        let stop = std::thread::spawn(move || {
            guard.stop_with_supervisor(
                &stopping_session,
                PersistentBuilderSupervisor::new(socket)
                    .with_frame_read_timeout(Duration::from_millis(50)),
            );
            drop(guard);
            done_tx.send(()).unwrap();
        });
        let (locked_tx, locked_rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let guard = SessionRecordGuard::acquire_at(path).unwrap();
            locked_tx.send(guard.read().unwrap().session_id).unwrap();
        });
        let bounded = done_rx.recv_timeout(Duration::from_secs(1));
        let released = locked_rx.recv_timeout(Duration::from_secs(1));
        let _ = release_tx.send(());
        peer.join().unwrap();
        stop.join().unwrap();
        contender.join().unwrap();
        bounded.unwrap();
        assert_eq!(released.unwrap(), session.session_id);
    }

    #[test]
    fn response_read_timeout_is_enforced_without_caller_socket_options() {
        use std::io::Write;
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        // A partial length header must obey the same deadline as a silent peer.
        peer.write_all(&[0]).unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            drop(peer);
        });
        let started = std::time::Instant::now();
        let result = read_next_response(&mut reader, Duration::from_millis(20));
        let elapsed = started.elapsed();
        let _ = release_tx.send(());
        peer.join().unwrap();
        assert!(result.is_err());
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn zero_deadline_does_not_disable_socket_timeouts() {
        let (mut stream, _peer) = UnixStream::pair().unwrap();
        assert!(read_next_response(&mut stream, Duration::ZERO).is_err());
    }

    #[test]
    fn guarded_signal_requires_exact_path_not_basename() {
        use mvm_vmm::host::process_liveness::process_executable;
        use std::os::unix::process::ExitStatusExt;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let executable = process_executable(pid).unwrap();
        let impostor = Path::new("/untrusted").join(executable.file_name().unwrap());
        let refused = signal_verified_supervisor(pid, &[impostor]);
        let running = child.try_wait().unwrap().is_none();
        let sent = signal_verified_supervisor(pid, &[executable]);
        if sent.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        assert!(refused.is_err());
        assert!(running);
        assert!(sent.is_ok());
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(signal_verified_supervisor(pid, &[]).is_ok());
    }

    #[test]
    fn stop_refuses_unrelated_live_process_and_retains_record() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SessionRecordGuard::acquire_at(dir.path().join("session.json")).unwrap();
        let session = record(std::process::id());
        guard.write(&session).unwrap();
        guard.stop(&session);
        assert_eq!(guard.read().unwrap().session_id, session.session_id);
        assert!(terminate_supervisor(std::process::id()).is_err());
        assert!(terminate_supervisor(0).is_err());
        assert!(terminate_supervisor(u32::MAX).is_err());
    }

    #[test]
    fn atomic_record_is_private_and_lock_survives_record_removal() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/persistent-builder.json");
        let guard = SessionRecordGuard::acquire_at(path.clone()).unwrap();
        guard.write(&record(std::process::id())).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let contender = std::fs::File::open(path.with_extension("lock")).unwrap();
        // SAFETY: flock only operates on the test-owned file descriptor.
        assert_ne!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        guard.remove().unwrap();
        assert!(path.with_extension("lock").exists());
        // Removing the record cannot create a second lock domain.
        assert_ne!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(guard);
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }

    #[test]
    fn uncertain_stop_and_old_observer_preserve_record() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SessionRecordGuard::acquire_at(dir.path().join("session.json")).unwrap();
        let live = record(std::process::id());
        guard.write(&live).unwrap();
        assert!(!guard.clear_stopped(&live).unwrap());
        let mut old = live.clone();
        old.session_id = "old".into();
        old.supervisor_pid = 2_000_000_000;
        assert!(!guard.clear_stopped(&old).unwrap());
        assert_eq!(guard.read().unwrap().session_id, live.session_id);
    }

    #[test]
    fn touch_and_stop_use_same_record_transaction_without_relocking() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SessionRecordGuard::acquire_at(dir.path().join("session.json")).unwrap();
        let mut session = record(std::process::id());
        guard.write(&session).unwrap();
        assert!(guard.touch(99).unwrap());
        assert_eq!(guard.read().unwrap().last_activity_unix_secs, Some(99));
        session.supervisor_pid = 2_000_000_000;
        guard.write(&session).unwrap();
        assert!(guard.clear_stopped(&session).unwrap());
        assert!(!guard.touch(100).unwrap());
    }
}
