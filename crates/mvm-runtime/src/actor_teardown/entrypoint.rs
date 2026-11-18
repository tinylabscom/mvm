use super::*;
use mvm_agentd::vsock::{AuthenticatedSession, EntrypointEvent, GuestRequest};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchState {
    Ready,
    Dispatched,
    Uncertain,
}

/// The single authenticated entrypoint response stream, separate from native stop custody.
///
/// Move this to a reader thread if the app is long-running; the original
/// `ActorOwner` remains available to stop/reap on cancellation or transport error.
/// A guest terminal is an application outcome, never native teardown evidence.
#[must_use = "observe the entrypoint outcome or explicitly stop the original actor"]
pub struct ActorEntrypoint {
    stream: UnixStream,
    session: AuthenticatedSession,
    request: GuestRequest,
    deadline: Instant,
}

/// Cancellation of the exact retained response socket, not authority to stop the VM.
#[derive(Debug)]
pub struct ActorEntrypointCancel {
    stream: UnixStream,
}

impl ActorEntrypointCancel {
    /// Interrupt the pending response read so its reader thread can be joined.
    ///
    /// Cancellation is not an application terminal or teardown proof. The caller
    /// must still stop/reap the original `ActorOwner`; no guest request is retried.
    pub fn cancel(&self) -> std::io::Result<()> {
        match self.stream.shutdown(std::net::Shutdown::Both) {
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            result => result,
        }
    }
}

impl std::fmt::Debug for ActorEntrypoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorEntrypoint")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ActorEntrypoint {
    /// Retain a cancellation handle before moving this reader to another thread.
    /// It duplicates this exact connected socket, never resolves the VM by name.
    pub fn cancellation_handle(&self) -> std::io::Result<ActorEntrypointCancel> {
        Ok(ActorEntrypointCancel {
            stream: self.stream.try_clone()?,
        })
    }

    /// Consume authenticated frames through the actual terminal, with a total deadline.
    ///
    /// # Errors
    /// EOF, malformed frames, authentication failure and timeout remain uncertain.
    /// No request is retried; the caller still owns the original actor teardown.
    /// The callback must be bounded: cancellation interrupts socket I/O, not caller code.
    pub fn wait(mut self, on_event: impl FnMut(&EntrypointEvent)) -> Result<EntrypointEvent> {
        self.stream.set_read_timeout(None)?;
        mvm_agentd::vsock::run_with_stream_deadline(&mut self.stream, self.deadline, |stream| {
            mvm_agentd::vsock::read_entrypoint_on_authenticated_session(
                stream,
                &mut self.session,
                &self.request,
                on_event,
            )
        })
    }
}

impl ActorOwner {
    /// Dispatch exactly the signed image entrypoint after admitted boot/activation.
    ///
    /// Sends `RunEntrypoint` with no argv, environment overrides, payload or open
    /// input stream. Successful return means the authenticated request was sent,
    /// not that boot itself ran the app or that application readiness was observed.
    /// The caller supplies the absolute admitted deadline, preserving time spent
    /// in admission/commit ACK; it must not be rebased as a fresh duration.
    /// Bridge/handshake time consumes that deadline. Only terminal reading gets
    /// completion grace. The caller retains this owner while reading independently.
    ///
    /// # Errors
    /// Refuses repeat dispatch, invalid duration or uncertain ownership. Any
    /// attempted bridge/handshake/send is non-retryable, since a failed write can
    /// already have started the app. Original native stop custody always remains.
    pub fn dispatch_entrypoint(&mut self, authority_deadline: Instant) -> Result<ActorEntrypoint> {
        ensure!(
            self.entrypoint == DispatchState::Ready
                && self.native_exit.is_none()
                && !self.terminal
                && self.startup_failure.is_none()
                && self.quarantined.is_empty()
                && self.journal.unverified_helpers.is_empty(),
            "actor entrypoint requires original undispatched running custody"
        );
        let remaining = authority_deadline
            .checked_duration_since(Instant::now())
            .context("actor authority expired before entrypoint dispatch")?;
        let mut request = fixed_entrypoint(remaining)?;
        let send_deadline = authority_deadline;
        let deadline = send_deadline
            .checked_add(Duration::from_secs(5))
            .context("actor terminal-read deadline overflow")?;
        self.entrypoint = DispatchState::Uncertain;
        let mut retained = None;
        let dispatched = (|| {
            self.original().open_agent_bridge(&mut retained)?;
            let stream = retained.as_mut().context("original actor bridge missing")?;
            let session = authenticate_and_send(stream, &mut request, send_deadline, |stream| {
                self.original().validate_agent_bridge(stream)
            })?;
            Ok(session)
        })();
        match dispatched {
            Ok(session) => {
                self.entrypoint = DispatchState::Dispatched;
                Ok(ActorEntrypoint {
                    stream: retained.expect("authenticated original stream exists"),
                    session,
                    request,
                    deadline,
                })
            }
            Err(error) => {
                self.failed_entrypoint_stream = retained;
                Err(error)
            }
        }
    }
}

fn fixed_entrypoint(timeout: Duration) -> Result<GuestRequest> {
    ensure!(
        timeout.as_secs() > 0,
        "actor entrypoint timeout must be at least one second"
    );
    Ok(GuestRequest::RunEntrypoint {
        stdin: Vec::new(),
        timeout_secs: timeout.as_secs(),
        env: Vec::new(),
        stream_input: false,
    })
}

fn authenticate_and_send(
    stream: &mut UnixStream,
    request: &mut GuestRequest,
    run_deadline: Instant,
    validate: impl FnOnce(&UnixStream) -> Result<()>,
) -> Result<AuthenticatedSession> {
    let deadline = Instant::now()
        .checked_add(mvm_agentd::vsock::COLD_GUEST_AGENT_READY_BUDGET)
        .context("actor guest handshake deadline overflow")?
        .min(run_deadline);
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    let (mut session, _guest_key) =
        mvm_agentd::vsock::run_with_stream_deadline(stream, deadline, |stream| {
            mvm_agentd::vsock::open_peer_authenticated_session(stream)
        })?;
    validate(stream)?;
    mvm_agentd::vsock::run_with_stream_deadline(stream, deadline, |stream| {
        let remaining = run_deadline
            .checked_duration_since(Instant::now())
            .context("actor authority expired before entrypoint send")?;
        let remaining_secs = remaining.as_secs();
        ensure!(
            remaining_secs > 0,
            "actor authority has no whole execution second remaining"
        );
        let GuestRequest::RunEntrypoint { timeout_secs, .. } = request else {
            anyhow::bail!("actor dispatch requires the exact image entrypoint");
        };
        *timeout_secs = (*timeout_secs).min(remaining_secs);
        session.write(stream, request)
    })?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_agentd::vsock::{AuthenticatedSession, GuestResponse};
    use mvm_core::util::test_env::TestEnv;

    fn authenticated_guest(
        mut peer: UnixStream,
        terminal: Option<EntrypointEvent>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let anchor = SigningKey::from_bytes(&[7; 32]).verifying_key();
            let mut session =
                AuthenticatedSession::guest(&mut peer, SigningKey::from_bytes(&[9; 32]), &anchor)
                    .unwrap();
            let request: GuestRequest = session.read(&mut peer).unwrap();
            let GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs,
                env,
                stream_input,
            } = request
            else {
                panic!("actor dispatch must never substitute Exec or another verb");
            };
            assert!(stdin.is_empty() && env.is_empty() && !stream_input);
            assert!((1..=5).contains(&timeout_secs));
            if let Some(event) = terminal {
                session
                    .write(&mut peer, &GuestResponse::EntrypointEvent(event))
                    .unwrap();
            }
        })
    }

    fn exercise_dispatch(terminal: Option<EntrypointEvent>) -> Result<EntrypointEvent> {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        mvm_core::atomic_io::write_private(&keys.join("host-signer.ed25519"), &[7; 32]).unwrap();
        let (mut stream, peer) = UnixStream::pair().unwrap();
        let guest = authenticated_guest(peer, terminal);
        let mut request = fixed_entrypoint(Duration::from_secs(5)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let session =
            authenticate_and_send(&mut stream, &mut request, deadline, |_| Ok(())).unwrap();
        let outcome = ActorEntrypoint {
            stream,
            session,
            request,
            deadline,
        }
        .wait(|_| {});
        guest.join().unwrap();
        outcome
    }

    #[test]
    fn dispatch_sends_the_exact_entrypoint_and_reads_actual_nonzero_terminal() {
        assert_eq!(
            exercise_dispatch(Some(EntrypointEvent::Exit { code: 17 })).unwrap(),
            EntrypointEvent::Exit { code: 17 },
        );
    }

    #[test]
    fn response_loss_never_becomes_success_or_a_second_dispatch() {
        assert!(exercise_dispatch(None).is_err());
    }

    #[test]
    fn no_unbounded_or_subsecond_entrypoint_request_is_created() {
        assert!(fixed_entrypoint(Duration::ZERO).is_err());
        assert!(fixed_entrypoint(Duration::from_millis(999)).is_err());
    }

    #[test]
    fn slow_handshake_cannot_dispatch_during_terminal_read_grace() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        mvm_core::atomic_io::write_private(&keys.join("host-signer.ed25519"), &[7; 32]).unwrap();
        let (mut stream, mut peer) = UnixStream::pair().unwrap();
        let (release_peer, delayed_peer) = std::sync::mpsc::sync_channel(1);
        let guest = std::thread::spawn(move || {
            delayed_peer.recv_timeout(Duration::from_secs(5)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let anchor = SigningKey::from_bytes(&[7; 32]).verifying_key();
            assert!(
                AuthenticatedSession::guest(&mut peer, SigningKey::from_bytes(&[9; 32]), &anchor,)
                    .is_err(),
                "expired handshake cannot reach request decoding"
            );
        });
        let authority_expiry = Instant::now() + Duration::from_millis(100);
        let terminal_read_deadline = authority_expiry + Duration::from_secs(5);
        let mut request = fixed_entrypoint(Duration::from_secs(5)).unwrap();
        assert!(
            authenticate_and_send(&mut stream, &mut request, authority_expiry, |_| Ok(())).is_err()
        );
        assert!(
            Instant::now() < terminal_read_deadline,
            "send must not borrow terminal-read grace"
        );
        release_peer.send(()).unwrap();
        guest.join().unwrap();
    }

    #[test]
    fn exact_socket_cancellation_joins_silent_reader_before_run_deadline() {
        use std::io::Read;
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        mvm_core::atomic_io::write_private(&keys.join("host-signer.ed25519"), &[7; 32]).unwrap();
        let (mut stream, mut peer) = UnixStream::pair().unwrap();
        let (received, request_received) = std::sync::mpsc::sync_channel(1);
        let guest = std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let anchor = SigningKey::from_bytes(&[7; 32]).verifying_key();
            let mut session =
                AuthenticatedSession::guest(&mut peer, SigningKey::from_bytes(&[9; 32]), &anchor)
                    .unwrap();
            let request: GuestRequest = session.read(&mut peer).unwrap();
            assert!(matches!(
                request,
                GuestRequest::RunEntrypoint {
                    timeout_secs: 1..=60,
                    ..
                }
            ));
            received.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).unwrap(),
                0,
                "cancel closes this exact stream"
            );
        });
        let mut request = fixed_entrypoint(Duration::from_secs(60)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let session =
            authenticate_and_send(&mut stream, &mut request, deadline, |_| Ok(())).unwrap();
        let running = ActorEntrypoint {
            stream,
            session,
            request,
            deadline,
        };
        let cancel = running.cancellation_handle().unwrap();
        request_received
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let (done, completion) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || done.send(running.wait(|_| {})).unwrap());
        cancel.cancel().unwrap();
        cancel.cancel().unwrap();
        assert!(
            completion
                .recv_timeout(Duration::from_secs(2))
                .expect("cancel must interrupt the 60-second read")
                .is_err()
        );
        reader.join().unwrap();
        guest.join().unwrap();
    }
}
