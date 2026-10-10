//! One bounded, supervisor-owned stop endpoint and ownership linearization gate.
//!
//! Connected sockets never leave this process. One worker serves connections
//! sequentially, each under a whole-exchange deadline. A client cannot create
//! another worker, and shutdown never waits for a client to acknowledge death.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_core::protocol::broker_control::{self, ControlRequest, ControlResponse, SignedControl};
use mvm_core::protocol::hvf_control::{HvfInstance, HvfInstanceControl, verify_stop};
use mvm_vmm::host::hvf_control_transport as wire;
use rand::Rng;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    Stopping,
    Transferring,
    Finalizing,
    Failed,
    Finalized,
}

struct State {
    instance: HvfInstance,
    phase: Phase,
    // At most the initial listener and one resident child's listener. Keeping
    // the old listener open avoids descriptor reuse while the worker polls it.
    listeners: Vec<UnixListener>,
    key: SigningKey,
    #[cfg(test)]
    before_commit: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}

struct Shared {
    state: Mutex<State>,
    closed: AtomicBool,
    stop: &'static AtomicBool,
    wake: UnixStream,
    #[cfg(test)]
    close_attempt: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
}

/// The capture controller borrows this gate; it cannot publish finalization.
#[derive(Clone)]
pub struct StopAuthority(Arc<Shared>);

/// The supervisor retains this owner until guest/capture teardown completes.
pub struct StopControl {
    authority: StopAuthority,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Publication cannot be rolled back after its signed bytes become visible.
#[derive(Debug)]
#[must_use]
pub enum FinalizationPublication {
    Durable,
    /// Capture/status/outcome were already durable before this attestation.
    /// Its visible signature still proves quiescence with independent exit
    /// evidence, but its own directory durability is not confirmed.
    PublishedDurabilityUnconfirmed(anyhow::Error),
}

impl StopControl {
    /// Call after admission/registration verification, before guest execution.
    /// Operational roles use the same existing host-root bootstrap, not an
    /// unsigned stop exception or a new independent issuer.
    pub fn start(vm: &str, stop: &'static AtomicBool) -> Result<Self> {
        let _ = wire::state_dir(vm)?;
        let bootstrap = crate::audit::host_keypair::load_or_init()?;
        drop(bootstrap);
        let (key, _) = wire::existing_operator()?;
        let (instance, listener) = provision(vm)?;
        let (wake_read, wake) = UnixStream::pair()?;
        wake_read.set_nonblocking(true)?;
        wake.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                instance,
                phase: Phase::Active,
                listeners: vec![listener],
                key,
                #[cfg(test)]
                before_commit: None,
            }),
            closed: AtomicBool::new(false),
            stop,
            wake,
            #[cfg(test)]
            close_attempt: Mutex::new(None),
        });
        let service = shared.clone();
        let worker = std::thread::Builder::new()
            .name("mvm-hvf-stop".into())
            .spawn(move || {
                if serve(&service, wake_read).is_err() {
                    service.stop.store(true, Ordering::Release);
                }
            })?;
        Ok(Self {
            authority: StopAuthority(shared),
            worker: Some(worker),
        })
    }

    pub fn authority(&self) -> StopAuthority {
        self.authority.clone()
    }

    pub fn current_state_dir(&self) -> Result<std::path::PathBuf> {
        let vm = self
            .authority
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?
            .instance
            .vm_id
            .clone();
        wire::state_dir(&vm)
    }

    pub fn publish_terminal_status(
        &self,
        status: mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus,
    ) -> Result<()> {
        self.publish_terminal_status_with(status, mvm_core::atomic_io::sync_dir)
    }

    fn publish_terminal_status_with(
        &self,
        status: mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus,
        sync_directory: impl FnOnce(&std::path::Path) -> Result<()>,
    ) -> Result<()> {
        let result = (|| {
            let directory = self.current_state_dir()?;
            status.publish(&directory)?;
            sync_directory(&directory)
        })();
        if result.is_err()
            || !matches!(
                status,
                mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus::Stopped
            )
        {
            let mut state = self
                .authority
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
            state.phase = Phase::Failed;
            self.authority.0.stop.store(true, Ordering::Release);
        }
        result
    }

    /// The owner calls only after guest quiescence and durable capture, status
    /// and outcome publication. Err means no attestation was published by this
    /// attempt; an error syncing its directory *after* publication is distinct.
    pub fn publish_finalized(&self) -> Result<FinalizationPublication> {
        self.publish_finalized_with(mvm_core::atomic_io::sync_dir)
    }

    fn publish_finalized_with(
        &self,
        sync_directory: impl FnOnce(&std::path::Path) -> Result<()>,
    ) -> Result<FinalizationPublication> {
        let (instance, message) = {
            let mut state = self
                .authority
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
            ensure!(
                matches!(state.phase, Phase::Active | Phase::Stopping),
                "HVF finalization is failed or already published"
            );
            state.phase = Phase::Finalizing;
            let message = sign(
                &state,
                HvfInstanceControl::Finalized {
                    instance: state.instance.clone(),
                },
            )?;
            (state.instance.clone(), message)
        };
        // Persistence is an owner operation, not part of the bounded control
        // exchange. Never hold the service gate over filesystem I/O.
        let result = (|| {
            let path = wire::state_dir(&instance.vm_id)?.join(wire::FINALIZED_FILE);
            let parent = path.parent().context("finalization directory missing")?;
            mvm_core::atomic_io::atomic_write_new(&path, &serde_json::to_vec(&message)?)?;
            Ok(match sync_directory(parent) {
                Ok(()) => FinalizationPublication::Durable,
                Err(error) => FinalizationPublication::PublishedDurabilityUnconfirmed(error),
            })
        })();
        let mut state = self
            .authority
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
        if state.instance != instance || state.phase != Phase::Finalizing {
            state.phase = Phase::Failed;
            self.authority.0.stop.store(true, Ordering::Release);
            anyhow::bail!("HVF finalization generation changed");
        }
        state.phase = if result.is_ok() {
            Phase::Finalized
        } else {
            Phase::Failed
        };
        result
    }
}

impl Drop for StopControl {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(notice) = self
            .authority
            .0
            .close_attempt
            .lock()
            .expect("test close notice")
            .as_ref()
        {
            let _ = notice.try_send(());
        }
        {
            // Cancellation and ownership commit linearize under the same gate.
            // Recovering a poisoned gate still cancels; it cannot authorize work.
            let mut state = self
                .authority
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.authority.0.closed.store(true, Ordering::Release);
            self.authority.0.stop.store(true, Ordering::Release);
            if state.phase != Phase::Finalized {
                state.phase = Phase::Failed;
            }
        }
        wake(&self.authority.0);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // Neither Drop nor service-thread exit removes any runtime evidence.
    }
}

impl StopAuthority {
    /// Reserve transfer under the short control gate, perform owner work outside
    /// it, then commit exactly the reserved generation. Stops are refused while
    /// the owner prepares; no client or destructor waits on the callback or disk.
    pub fn transfer<T>(
        &self,
        child_vm: &str,
        transfer_capture: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let generation = {
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
            ensure!(
                state.phase == Phase::Active
                    && !self.0.stop.load(Ordering::Acquire)
                    && !self.0.closed.load(Ordering::Acquire),
                "HVF stop already committed"
            );
            ensure!(
                state.listeners.len() == 1,
                "HVF ownership already transferred"
            );
            state.phase = Phase::Transferring;
            state.instance.clone()
        };
        let result = (|| {
            let (instance, listener) = provision(child_vm)?;
            let result = transfer_capture()?;
            Ok((instance, listener, result))
        })();
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
        let result = match result {
            Ok((instance, listener, result))
                if state.instance == generation
                    && state.phase == Phase::Transferring
                    && !self.0.closed.load(Ordering::Acquire)
                    && !self.0.stop.load(Ordering::Acquire) =>
            {
                #[cfg(test)]
                if let Some((entered, release)) = state.before_commit.take() {
                    entered.send(()).expect("test commit notice");
                    release.recv().expect("test commit release");
                }
                state.instance = instance;
                state.listeners.push(listener);
                state.phase = Phase::Active;
                Ok(result)
            }
            Ok(_) => Err(anyhow::anyhow!("HVF transfer reservation canceled")),
            Err(error) => Err(error),
        };
        if result.is_err() {
            state.phase = Phase::Failed;
            self.0.stop.store(true, Ordering::Release);
        }
        drop(state);
        wake(&self.0);
        result
    }
}

fn provision(vm: &str) -> Result<(HvfInstance, UnixListener)> {
    let dir = wire::state_dir(vm)?;
    let listener = wire::bind(vm)?;
    let mut nonce = [0; 32];
    rand::rng().fill_bytes(&mut nonce);
    let instance = HvfInstance {
        vm_id: vm.into(),
        boot_nonce: nonce,
    };
    mvm_core::atomic_io::atomic_write_new(
        &dir.join(wire::INSTANCE_FILE),
        &serde_json::to_vec(&instance)?,
    )?;
    mvm_core::private_fs::sync_managed_directory_chain(
        &mvm_core::config::mvm_home_strict()?,
        &dir,
    )?;
    Ok((instance, listener))
}

fn wake(shared: &Shared) {
    let mut wake = &shared.wake;
    let _ = wake.write(&[1]);
}

fn sign(state: &State, operation: HvfInstanceControl) -> Result<SignedControl> {
    let seed = zeroize::Zeroizing::new(state.key.to_bytes());
    Ok(broker_control::sign(
        ControlRequest::HvfInstanceV1(operation),
        &seed,
    )?)
}

fn serve(shared: &Shared, mut wake_read: UnixStream) -> Result<()> {
    while !shared.closed.load(Ordering::Acquire) {
        let mut fds = {
            let state = shared
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
            let mut fds = vec![libc::pollfd {
                fd: wake_read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            fds.extend(state.listeners.iter().map(|listener| libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }));
            fds
        };
        // SAFETY: listeners stay owned in Shared until this worker is joined;
        // wake_read is owned here. The vector remains valid throughout poll.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if fds[0].revents != 0 {
            let _ = wake_read.read(&mut [0; 64]);
        }
        for (index, fd) in fds.iter().skip(1).enumerate() {
            if fd.revents & libc::POLLIN == 0 || shared.closed.load(Ordering::Acquire) {
                continue;
            }
            let accepted = {
                let state = shared
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
                state.listeners[index].accept()
            };
            match accepted {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    // Malformed/expired/refused connections do not end service.
                    // There is no replay table: every connection has one fresh
                    // challenge and consumes at most one stop request.
                    let deadline = Instant::now() + wire::CONNECTION_BUDGET;
                    if exchange(shared, &mut stream, deadline).is_err() {
                        let _ = wire::write_frame(
                            &mut stream,
                            &ControlResponse::Err {
                                message: "control_unavailable".into(),
                            },
                            deadline,
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn exchange(shared: &Shared, stream: &mut UnixStream, deadline: Instant) -> Result<()> {
    let mut client_nonce = [0; 32];
    wire::read_exact(stream, &mut client_nonce, deadline)?;
    let mut connection_nonce = [0; 32];
    rand::rng().fill_bytes(&mut connection_nonce);
    let challenge = {
        let state = shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
        ensure!(
            matches!(
                state.phase,
                Phase::Active | Phase::Stopping | Phase::Finalized
            ),
            "HVF owner transition pending or failed"
        );
        sign(
            &state,
            HvfInstanceControl::Challenge {
                instance: state.instance.clone(),
                client_nonce,
                connection_nonce,
            },
        )?
    };
    wire::write_frame(stream, &challenge, deadline)?;
    let request = wire::read_frame(stream, deadline)?;
    {
        let mut state = shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
        ensure!(Instant::now() < deadline, "HVF stop connection expired");
        verify_stop(
            &request,
            &state.key.verifying_key(),
            &state.instance,
            &connection_nonce,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )?;
        ensure!(
            matches!(
                state.phase,
                Phase::Active | Phase::Stopping | Phase::Finalized
            ),
            "HVF owner transition pending or failed"
        );
        if state.phase == Phase::Active {
            state.phase = Phase::Stopping;
            shared.stop.store(true, Ordering::Release);
        }
    }
    // Dispatch only, never a process-death or finalization claim.
    wire::write_all(stream, &[1], deadline)?;
    Ok(())
}

#[cfg(test)]
#[path = "hvf_stop_tests.rs"]
mod tests;
