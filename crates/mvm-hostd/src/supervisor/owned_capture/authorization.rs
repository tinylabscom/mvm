//! Receiver authentication under the actual protected owner's permit.
//! No listener, client connector or payload writer is activated here.

use anyhow::{Context, Result, ensure};
use mvm_core::crypto::owned_capture::{
    CaptureBinding, CaptureChallenge, CapturePossession, CaptureProof,
};
use mvm_core::protocol::hvf_control::HvfInstance;
use mvm_vmm::host::hvf_control_transport as io;
use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{OriginalParent, StopAuthority};

const AUTH_BUDGET: Duration = Duration::from_secs(2);

#[cfg(test)]
type TestHook = (
    std::sync::mpsc::SyncSender<()>,
    std::sync::mpsc::Receiver<()>,
);

pub(crate) struct OwnedCapturePermit {
    shared: Arc<Shared>,
}

struct Shared {
    binding: CaptureBinding,
    instance: HvfInstance,
    native: StopAuthority,
    state: Mutex<State>,
    #[cfg(test)]
    before_spend: Mutex<Option<TestHook>>,
    #[cfg(test)]
    before_ready: Mutex<Option<TestHook>>,
}

struct State {
    parent: OriginalParent,
    phase: Phase,
    live: Option<[u8; 32]>,
}

enum Phase {
    Bound,
    Authorizing([u8; 32]),
    Spent {
        nonce: [u8; 32],
        ready: bool,
        progress: Progress,
    },
    Retired,
}

struct Progress {
    next_sequence: u64,
    accepted: Count,
    dropped: Count,
}

#[derive(Default)]
struct Count {
    fragments: u64,
    bytes: u64,
}

/// One authenticated/spent connection, not an append API or recording receipt.
/// No socket, raw descriptor, clone or serialization accessor is exposed.
#[must_use = "retain connection custody until retirement and close"]
pub struct AuthenticatedCapture {
    connection: Attempt,
}

struct Attempt {
    shared: Arc<Shared>,
    stream: Option<UnixStream>,
    observer: ProcessExitObserver,
    challenge: CaptureChallenge,
    deadline: Instant,
}

impl OwnedCapturePermit {
    pub(super) fn new(
        binding: CaptureBinding,
        instance: HvfInstance,
        parent: OriginalParent,
        native: StopAuthority,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                binding,
                instance,
                native,
                state: Mutex::new(State {
                    parent,
                    phase: Phase::Bound,
                    live: None,
                }),
                #[cfg(test)]
                before_spend: Mutex::new(None),
                #[cfg(test)]
                before_ready: Mutex::new(None),
            }),
        }
    }

    pub(super) fn vm(&self) -> &str {
        &self.shared.instance.vm_id
    }

    pub(crate) fn current_binding(&mut self) -> Result<&CaptureBinding> {
        self.shared.with_current(|_| Ok(()))?;
        Ok(&self.shared.binding)
    }

    /// False means a connection still owns its descriptor, not confirmed close.
    pub(crate) fn retire(&self) -> bool {
        self.shared.retire()
    }

    pub(crate) fn authenticate(&self, stream: UnixStream) -> Result<AuthenticatedCapture> {
        self.shared.authenticate(stream)
    }
}

impl Drop for OwnedCapturePermit {
    fn drop(&mut self) {
        self.retire();
    }
}

impl Shared {
    /// Lock order is native gate, then permit state. No transport or signature
    /// verification runs inside either critical section.
    fn with_current<T>(&self, action: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let checked = self
            .native
            .try_capture_instance(&self.instance.vm_id, |instance| {
                ensure!(
                    instance == &self.instance,
                    "capture native generation changed"
                );
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("capture gate poisoned"))?;
                state.parent.recheck()?;
                ensure!(
                    !matches!(state.phase, Phase::Retired),
                    "capture permit retired"
                );
                Ok(action(&mut state))
            });
        match checked {
            Ok(result) => result,
            Err(error) => {
                self.retire();
                Err(error)
            }
        }
    }

    fn retire(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.phase = Phase::Retired;
        state.live.is_none()
    }

    fn authenticate(self: &Arc<Self>, stream: UnixStream) -> Result<AuthenticatedCapture> {
        let deadline = Instant::now()
            .checked_add(AUTH_BUDGET)
            .context("capture deadline overflow")?;
        require_peer(&stream, self.binding.producer_pid())?;
        // This checks current flags only; creation/acceptance and fork custody
        // still require independent qualification before activating a listener.
        // SAFETY: only reads flags from the borrowed live socket.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        ensure!(
            flags >= 0 && flags & libc::FD_CLOEXEC != 0,
            "capture socket must be close-on-exec"
        );
        let observer = ProcessExitObserver::arm(i32::try_from(self.binding.producer_pid())?)?;
        let challenge = CaptureChallenge::fresh(self.binding.clone(), unix_now()?)?;
        let nonce = *challenge.nonce();
        self.with_current(|state| {
            ensure!(
                matches!(state.phase, Phase::Bound) && state.live.is_none(),
                "capture permit busy or spent"
            );
            ensure!(Instant::now() < deadline, "capture authentication deadline");
            challenge.validate(unix_now()?)?;
            require_peer(&stream, self.binding.producer_pid())?;
            ensure!(
                observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
                "capture peer exited"
            );
            state.phase = Phase::Authorizing(nonce);
            state.live = Some(nonce);
            Ok(())
        })?;
        let mut attempt = Attempt {
            shared: Arc::clone(self),
            stream: Some(stream),
            observer,
            challenge,
            deadline,
        };
        attempt.exchange()?;
        Ok(AuthenticatedCapture {
            connection: attempt,
        })
    }
}

impl Attempt {
    fn check_peer(&self) -> Result<()> {
        require_peer(
            self.stream.as_ref().context("capture stream closed")?,
            self.shared.binding.producer_pid(),
        )?;
        ensure!(
            self.observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "capture peer exited"
        );
        Ok(())
    }

    fn exchange(&mut self) -> Result<()> {
        let challenge = self.challenge.encode()?;
        io::write_all(
            self.stream.as_mut().context("capture stream closed")?,
            &challenge,
            self.deadline,
        )?;
        let bytes = read_control(
            self.stream.as_mut().context("capture stream closed")?,
            self.deadline,
        )?;
        let now = unix_now()?;
        let verified = CaptureProof::decode(&bytes, &self.challenge, now)
            .and_then(|proof| proof.verify(&self.challenge, now));
        let possession = match verified {
            Ok(possession) => possession,
            Err(error) => {
                self.reject_proof();
                return Err(error.into());
            }
        };
        #[cfg(test)]
        test_pause(&self.shared.before_spend);
        self.spend(possession)?;
        #[cfg(test)]
        test_pause(&self.shared.before_ready);
        self.with_ready(|_| {})?;
        let frame = ready_frame(self.challenge.nonce());
        io::write_all(
            self.stream.as_mut().context("capture stream closed")?,
            &frame,
            self.deadline,
        )?;
        self.with_ready(|ready| *ready = true)
    }

    fn with_ready(&self, action: impl FnOnce(&mut bool)) -> Result<()> {
        self.shared.with_current(|state| {
            ensure!(
                Instant::now() < self.deadline,
                "capture authentication deadline"
            );
            self.check_peer()?;
            match &mut state.phase {
                Phase::Spent {
                    nonce,
                    ready,
                    progress,
                } if nonce == self.challenge.nonce()
                    && !*ready
                    && progress.next_sequence == 1
                    && progress.accepted.fragments == 0
                    && progress.accepted.bytes == 0
                    && progress.dropped.fragments == 0
                    && progress.dropped.bytes == 0 =>
                {
                    action(ready);
                    Ok(())
                }
                Phase::Bound | Phase::Authorizing(_) | Phase::Spent { .. } | Phase::Retired => {
                    anyhow::bail!("capture Ready no longer current")
                }
            }
        })
    }

    fn spend(&self, possession: CapturePossession) -> Result<()> {
        self.shared.with_current(|state| {
            ensure!(Instant::now() < self.deadline, "capture authentication deadline");
            self.challenge.validate(unix_now()?)?;
            self.check_peer()?;
            ensure!(possession.challenge() == &self.challenge, "capture possession differs");
            ensure!(matches!(state.phase, Phase::Authorizing(nonce) if &nonce == self.challenge.nonce()), "capture reservation no longer current");
            state.phase = Phase::Spent {
                nonce: *self.challenge.nonce(),
                ready: false,
                progress: Progress { next_sequence: 1, accepted: Count::default(), dropped: Count::default() },
            };
            Ok(())
        })
    }

    fn reject_proof(&self) {
        let _ = self.shared.with_current(|state| {
            if matches!(state.phase, Phase::Authorizing(nonce) if &nonce == self.challenge.nonce())
            {
                state.phase = if Instant::now() < self.deadline
                    && self.challenge.validate(unix_now()?).is_ok()
                    && self.check_peer().is_ok()
                {
                    Phase::Bound
                } else {
                    Phase::Retired
                };
            }
            Ok(())
        });
    }
}

impl AuthenticatedCapture {
    /// Current authorization only, never evidence of stored or readable bytes.
    pub fn validate(&self) -> Result<()> {
        let result = self.connection.shared.with_current(|state| {
            self.connection.check_peer()?;
            ensure!(
                matches!(state.phase, Phase::Spent { nonce, ready: true, .. }
                if &nonce == self.connection.challenge.nonce()),
                "capture connection is not current"
            );
            Ok(())
        });
        if result.is_err() {
            self.connection.shared.retire();
        }
        result
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        let nonce = *self.challenge.nonce();
        {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(state.phase, Phase::Authorizing(id) | Phase::Spent { nonce: id, .. } if id == nonce)
            {
                state.phase = Phase::Retired;
            }
        }
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.live == Some(nonce) {
            state.live = None;
        }
    }
}

fn require_peer(stream: &UnixStream, expected: u32) -> Result<()> {
    let pid = mvm_vmm::host::uds_peer::connected_peer_pid(stream)?;
    ensure!(
        u32::try_from(pid)? == expected,
        "capture connector is not original launcher"
    );
    Ok(())
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn control_body_length(length: u32) -> Result<usize> {
    let length = usize::try_from(length)?;
    ensure!(
        length > 0 && length <= mvm_core::crypto::owned_capture::MAX_FRAME_BYTES - 4,
        "invalid capture control length"
    );
    Ok(length)
}

fn read_control(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    io::read_exact(stream, &mut header, deadline)?;
    let length = control_body_length(u32::from_be_bytes(header))?;
    let mut bytes = vec![0; length.checked_add(4).context("capture frame overflow")?];
    bytes[..4].copy_from_slice(&header);
    io::read_exact(stream, &mut bytes[4..], deadline)?;
    Ok(bytes)
}

fn ready_frame(nonce: &[u8; 32]) -> [u8; 37] {
    let mut bytes = [0; 37];
    bytes[..4].copy_from_slice(&33_u32.to_be_bytes());
    bytes[4] = 3;
    bytes[5..].copy_from_slice(nonce);
    bytes
}

#[cfg(test)]
fn test_pause(hook: &Mutex<Option<TestHook>>) {
    if let Some((entered, release)) = hook.lock().expect("test hook").take() {
        entered.send(()).expect("test hook notice");
        release
            .recv_timeout(AUTH_BUDGET)
            .expect("test hook release");
    }
}

#[cfg(test)]
mod tests;
