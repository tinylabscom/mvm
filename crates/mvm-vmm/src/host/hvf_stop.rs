//! Authenticated stop bound to the connected supervisor's kernel lifetime.
//!
//! No operation here reads a PID file, sends a numeric signal, removes state,
//! or substitutes an acknowledgment/EOF for a process-exit event.

use std::os::unix::net::UnixStream;
use std::process::Child;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::protocol::broker_control::{self, ControlRequest, SignedControl};
use mvm_core::protocol::hvf_control::{
    HvfInstance, HvfInstanceControl, verify_challenge, verify_finalized,
};
use rand::Rng;

use super::hvf_control_transport as wire;
use super::process_exit::{ProcessExitObserver, ProcessExitWait};

/// A fresh challenge has bound this connection to the armed observer.
pub struct ConnectedInstance {
    stream: UnixStream,
    observer: ProcessExitObserver,
    instance: HvfInstance,
    connection_nonce: [u8; 32],
    signing: SigningKey,
    root: VerifyingKey,
}

/// Produced only after both lifetime exit and authenticated finalization.
pub struct ConfirmedExit {
    instance: HvfInstance,
    pub dispatch: Duration,
    pub exit_wait: Duration,
}

impl ConfirmedExit {
    /// A handle to an older generation never authorizes cleanup of a new one.
    pub fn verify_current(&self) -> Result<()> {
        ensure!(
            wire::read_instance(&self.instance.vm_id)? == self.instance,
            "HVF ownership changed before cleanup"
        );
        Ok(())
    }
}

impl ConnectedInstance {
    pub fn connect(vm: &str) -> Result<Self> {
        let instance = wire::read_instance(vm)?;
        Self::connect_bound(instance, None)
    }

    pub fn connect_instance(instance: HvfInstance) -> Result<Self> {
        Self::connect_bound(instance, None)
    }

    /// An owned launch may use its Child's ID, never a PID loaded from disk.
    pub fn connect_owned(vm: &str, child_pid: u32) -> Result<Self> {
        Self::connect_bound(wire::read_instance(vm)?, Some(child_pid))
    }

    fn connect_bound(instance: HvfInstance, owned_pid: Option<u32>) -> Result<Self> {
        let vm = &instance.vm_id;
        ensure!(
            wire::read_instance(vm)? == instance,
            "HVF ownership generation changed"
        );
        let (signing, root) = wire::existing_operator()?;
        let deadline = Instant::now() + wire::CONNECTION_BUDGET;
        let mut stream = wire::connect(vm, deadline)?;
        let pid = super::uds_peer::connected_peer_pid(&stream)?;
        if let Some(expected) = owned_pid {
            ensure!(
                u32::try_from(pid)? == expected,
                "HVF control peer is not the owned child"
            );
        }
        let observer = ProcessExitObserver::arm(pid)?;
        ensure!(
            observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "HVF connected peer lifetime could not be armed while live"
        );
        // Generate only after arming: a response buffered before the observer
        // existed cannot answer this fresh challenge. The server never transfers
        // a connected socket, so its response closes the PID-to-observer race.
        let mut client_nonce = [0; 32];
        rand::rng().fill_bytes(&mut client_nonce);
        wire::write_all(&mut stream, &client_nonce, deadline)?;
        let challenge: SignedControl = wire::read_frame(&mut stream, deadline)?;
        let connection_nonce = verify_challenge(&challenge, &root, &instance, &client_nonce)?;
        Ok(Self {
            stream,
            observer,
            instance,
            connection_nonce,
            signing,
            root,
        })
    }

    pub fn stop(mut self) -> Result<ConfirmedExit> {
        let dispatch_start = Instant::now();
        let deadline = dispatch_start + wire::CONNECTION_BUDGET;
        let operation = HvfInstanceControl::StopHvfInstance {
            instance: self.instance.clone(),
            connection_nonce: self.connection_nonce,
            issued_at_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        let seed = zeroize::Zeroizing::new(self.signing.to_bytes());
        let request = broker_control::sign(ControlRequest::HvfInstanceV1(operation), &seed)?;
        wire::write_frame(&mut self.stream, &request, deadline)?;
        let mut acknowledgment = [0];
        wire::read_exact(&mut self.stream, &mut acknowledgment, deadline)?;
        ensure!(acknowledgment == [1], "HVF stop was not acknowledged");
        let dispatch = dispatch_start.elapsed();
        let wait_start = Instant::now();
        ensure!(
            self.observer
                .wait_event(wait_start + wire::SHUTDOWN_BUDGET)?
                == ProcessExitWait::Exited,
            "HVF supervisor exit remains unconfirmed"
        );
        let exit_wait = wait_start.elapsed();
        terminal_proof(self.instance, &self.root, dispatch, exit_wait)
    }

    /// Waiting for natural exit needs the same already-established lifetime
    /// binding, but sends no shutdown request. Socket EOF is deliberately unused.
    pub fn wait(self, deadline: Instant) -> Result<ConfirmedExit> {
        let started = Instant::now();
        ensure!(
            self.observer.wait_event(deadline)? == ProcessExitWait::Exited,
            "HVF supervisor natural exit remains unconfirmed"
        );
        terminal_proof(self.instance, &self.root, Duration::ZERO, started.elapsed())
    }
}

/// A launch retains real child ownership and the authenticated lifetime binding,
/// so a normal one-shot exit remains provable after its endpoint closes.
pub struct OwnedInstance {
    child: Mutex<Child>,
    observer: ProcessExitObserver,
    instance: HvfInstance,
    root: VerifyingKey,
}

impl OwnedInstance {
    /// Consume the Child only after its peer and instance are authenticated.
    /// On refusal the caller retains its exact owned handle for error cleanup.
    pub fn adopt(child: &mut Option<Child>, vm: &str) -> Result<Self> {
        let pid = child
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("owned child missing"))?
            .id();
        let peer = ConnectedInstance::connect_owned(vm, pid)?;
        Ok(Self {
            child: Mutex::new(
                child
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("owned child missing"))?,
            ),
            observer: peer.observer,
            instance: peer.instance,
            root: peer.root,
        })
    }

    pub fn instance(&self) -> &HvfInstance {
        &self.instance
    }

    pub fn try_exited(&self) -> Result<bool> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
        if child.try_wait()?.is_none() {
            return Ok(false);
        }
        terminal_proof(
            self.instance.clone(),
            &self.root,
            Duration::ZERO,
            Duration::ZERO,
        )?;
        Ok(true)
    }

    pub fn wait(&self, deadline: Instant) -> Result<ConfirmedExit> {
        let started = Instant::now();
        if self.try_exited()? {
            return terminal_proof(
                self.instance.clone(),
                &self.root,
                Duration::ZERO,
                Duration::ZERO,
            );
        }
        ensure!(
            self.observer.wait_event(deadline)? == ProcessExitWait::Exited,
            "owned HVF supervisor exit deadline"
        );
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
        child.wait()?;
        terminal_proof(
            self.instance.clone(),
            &self.root,
            Duration::ZERO,
            started.elapsed(),
        )
    }

    pub fn stop(&self) -> Result<ConfirmedExit> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
        if child.try_wait()?.is_some() {
            return terminal_proof(
                self.instance.clone(),
                &self.root,
                Duration::ZERO,
                Duration::ZERO,
            );
        }
        let peer = ConnectedInstance::connect_bound(self.instance.clone(), Some(child.id()))?;
        let proof = peer.stop()?;
        // wait_event deliberately did not reap this owned child's status.
        child.wait()?;
        Ok(proof)
    }
}

fn terminal_proof(
    instance: HvfInstance,
    root: &VerifyingKey,
    dispatch: Duration,
    exit_wait: Duration,
) -> Result<ConfirmedExit> {
    let terminal: SignedControl =
        wire::read_record(&wire::state_dir(&instance.vm_id)?.join(wire::FINALIZED_FILE))?;
    verify_finalized(&terminal, root, &instance)?;
    let proof = ConfirmedExit {
        instance,
        dispatch,
        exit_wait,
    };
    proof.verify_current()?;
    Ok(proof)
}
