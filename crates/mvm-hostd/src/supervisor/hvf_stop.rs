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
use mvm_core::protocol::broker_control::{self, ControlRequest, SignedControl};
use mvm_core::protocol::hvf_control::{HvfInstance, HvfInstanceControl, verify_stop};
use mvm_vmm::host::hvf_control_transport as wire;
use rand::Rng;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    Stopping,
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
}

struct Shared {
    state: Mutex<State>,
    closed: AtomicBool,
    stop: &'static AtomicBool,
    wake: UnixStream,
}

/// The capture controller borrows this gate; it cannot publish finalization.
#[derive(Clone)]
pub struct StopAuthority(Arc<Shared>);

/// The supervisor retains this owner until guest/capture teardown completes.
pub struct StopControl {
    authority: StopAuthority,
    worker: Option<std::thread::JoinHandle<()>>,
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
            }),
            closed: AtomicBool::new(false),
            stop,
            wake,
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

    /// The owner calls this only after guest quiescence and capture sealing.
    /// Failure leaves all evidence in place and cannot authorize client cleanup.
    pub fn publish_finalized(&self) -> Result<()> {
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
        let message = sign(
            &state,
            HvfInstanceControl::Finalized {
                instance: state.instance.clone(),
            },
        )?;
        let path = wire::state_dir(&state.instance.vm_id)?.join(wire::FINALIZED_FILE);
        mvm_core::atomic_io::atomic_write_new(&path, &serde_json::to_vec(&message)?)?;
        mvm_core::atomic_io::sync_dir(path.parent().context("finalization directory missing")?)?;
        state.phase = Phase::Finalized;
        Ok(())
    }
}

impl Drop for StopControl {
    fn drop(&mut self) {
        self.authority.0.closed.store(true, Ordering::Release);
        wake(&self.authority.0);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // Neither Drop nor service-thread exit removes any runtime evidence.
    }
}

impl StopAuthority {
    /// Handoff preparation/finalization and generation rotation are atomic
    /// against stop acceptance. On failure, stop rather than admitting a child
    /// with ambiguous authority. Only one resident handoff is supported.
    pub fn transfer<T>(
        &self,
        child_vm: &str,
        transfer_capture: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
        ensure!(
            state.phase == Phase::Active && !self.0.stop.load(Ordering::Acquire),
            "HVF stop already committed"
        );
        ensure!(
            state.listeners.len() == 1,
            "HVF ownership already transferred"
        );
        let result = (|| {
            let (instance, listener) = provision(child_vm)?;
            let result = transfer_capture()?;
            state.instance = instance;
            state.listeners.push(listener);
            Ok(result)
        })();
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
    mvm_core::atomic_io::sync_dir(&dir)?;
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
                    let _ = exchange(shared, &mut stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn exchange(shared: &Shared, stream: &mut UnixStream) -> Result<()> {
    let deadline = Instant::now() + wire::CONNECTION_BUDGET;
    let mut client_nonce = [0; 32];
    wire::read_exact(stream, &mut client_nonce, deadline)?;
    let mut connection_nonce = [0; 32];
    rand::rng().fill_bytes(&mut connection_nonce);
    let challenge = {
        let state = shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("stop gate poisoned"))?;
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
            state.phase != Phase::Failed,
            "HVF ownership transfer failed"
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
