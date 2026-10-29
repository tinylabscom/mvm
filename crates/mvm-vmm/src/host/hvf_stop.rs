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
use super::process_exit::{
    ProcessExitObserver, ProcessExitWait, collect_after_exit_event, require_owned_child_custody,
};

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
    pub fn instance(&self) -> &HvfInstance {
        &self.instance
    }
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
    pub fn instance(&self) -> &HvfInstance {
        &self.instance
    }
    pub fn connect(vm: &str) -> Result<Self> {
        let instance = wire::read_instance(vm)?;
        Self::connect_bound(instance, None)
    }

    pub fn connect_instance(instance: HvfInstance) -> Result<Self> {
        Self::connect_bound(instance, None)
    }

    /// An owned launch may use its Child's ID, never a PID loaded from disk.
    pub fn connect_owned(vm: &str, child_pid: u32) -> Result<Self> {
        require_owned_child_custody()?;
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
/// No other thread may reap that Child or change SIGCHLD disposition while owned.
pub struct OwnedInstance {
    child: Mutex<Child>,
    observer: ProcessExitObserver,
    passive_wait: Mutex<()>,
    instance: HvfInstance,
    root: VerifyingKey,
}

impl OwnedInstance {
    /// Consume the Child only after its peer and instance are authenticated.
    /// On refusal the caller retains its exact owned handle for error cleanup.
    pub fn adopt(child: &mut Option<Child>, vm: &str) -> Result<Self> {
        require_owned_child_custody()?;
        let process = child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("owned child missing"))?;
        ensure!(
            process.try_wait()?.is_none(),
            "cannot adopt an already-exited owned child"
        );
        let pid = process.id();
        let peer = ConnectedInstance::connect_owned(vm, pid)?;
        Ok(Self {
            child: Mutex::new(
                child
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("owned child missing"))?,
            ),
            observer: peer.observer,
            passive_wait: Mutex::new(()),
            instance: peer.instance,
            root: peer.root,
        })
    }

    pub fn instance(&self) -> &HvfInstance {
        &self.instance
    }

    /// Open the guest bridge only while the original child and signed native
    /// generation still agree. The returned socket is the one checked here;
    /// callers must retain it rather than resolving the VM name again. Once
    /// connected, even a validation failure leaves that exact stream in custody.
    pub fn open_agent_bridge(
        &self,
        path: &std::path::Path,
        retained: &mut Option<UnixStream>,
    ) -> Result<()> {
        ensure!(retained.is_none(), "native bridge must not be replaced");
        require_owned_child_custody()?;
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
        ensure!(
            child.try_wait()?.is_none(),
            "owned HVF child already exited"
        );
        ensure!(
            self.observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "owned HVF lifetime ended before bridge open"
        );
        let before = ConnectedInstance::connect_bound(self.instance.clone(), Some(child.id()))?;
        // This was an observation, not a pending stop request. Release its
        // serial control slot before taking the fresh post-connection probe.
        // The original child and lifetime observer remain held by this owner.
        drop(before);
        *retained = Some(mvm_agentd::vsock::connect_unix_before(
            path,
            Instant::now()
                .checked_add(wire::CONNECTION_BUDGET)
                .ok_or_else(|| anyhow::anyhow!("native bridge connection deadline overflow"))?,
        )?);
        let stream = retained
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native bridge missing"))?;
        require_bridge_peer(stream, child.id())?;
        // The bridge runs in the same supervisor, never in a delegated socket
        // server. A fresh native answer brackets the actual bridge connection.
        let after = ConnectedInstance::connect_bound(self.instance.clone(), Some(child.id()))?;
        ensure!(
            child.try_wait()?.is_none(),
            "owned HVF child exited during bridge open"
        );
        ensure!(
            self.observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "owned HVF lifetime ended during bridge open"
        );
        drop(after);
        Ok(())
    }

    /// Revalidate the retained bridge without opening or substituting a stream.
    pub fn validate_agent_bridge(&self, stream: &UnixStream) -> Result<()> {
        require_owned_child_custody()?;
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
        ensure!(
            child.try_wait()?.is_none(),
            "owned HVF child already exited"
        );
        require_bridge_peer(stream, child.id())?;
        let peer = ConnectedInstance::connect_bound(self.instance.clone(), Some(child.id()))?;
        ensure!(
            child.try_wait()?.is_none(),
            "owned HVF child exited during bridge validation"
        );
        ensure!(
            self.observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "owned HVF bridge lifetime ended"
        );
        drop(peer);
        Ok(())
    }

    pub fn try_exited(&self) -> Result<bool> {
        require_owned_child_custody()?;
        let exited = {
            let mut child = self
                .child
                .lock()
                .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
            child.try_wait()?.is_some()
        };
        if !exited {
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
        ensure!(started < deadline, "owned HVF supervisor exit deadline");
        // A kqueue event can be consumed once. Concurrent passive waits refuse
        // promptly rather than silently sharing/stealing that event. Explicit
        // stop uses its own fresh connected-peer observer and does not take this.
        let _wait = self
            .passive_wait
            .try_lock()
            .map_err(|_| anyhow::anyhow!("another owned HVF exit wait is active"))?;
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
        require_owned_child_custody()?;
        {
            let mut child = self
                .child
                .lock()
                .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
            ensure!(
                collect_after_exit_event(deadline, || child.try_wait())?.is_some(),
                "owned child exit status is not ready"
            );
        }
        terminal_proof(
            self.instance.clone(),
            &self.root,
            Duration::ZERO,
            started.elapsed(),
        )
    }

    pub fn stop(&self) -> Result<ConfirmedExit> {
        require_owned_child_custody()?;
        let (pid, exited) = {
            let mut child = self
                .child
                .lock()
                .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
            (child.id(), child.try_wait()?.is_some())
        };
        if exited {
            return terminal_proof(
                self.instance.clone(),
                &self.root,
                Duration::ZERO,
                Duration::ZERO,
            );
        }
        let peer = ConnectedInstance::connect_bound(self.instance.clone(), Some(pid))?;
        let proof = peer.stop()?;
        // wait_event deliberately did not reap this owned child's status.
        require_owned_child_custody()?;
        {
            let mut child = self
                .child
                .lock()
                .map_err(|_| anyhow::anyhow!("owned child poisoned"))?;
            ensure!(
                collect_after_exit_event(Instant::now() + wire::CONNECTION_BUDGET, || {
                    child.try_wait()
                })?
                .is_some(),
                "owned child exit status is not ready"
            );
        }
        Ok(proof)
    }
}

fn require_bridge_peer(stream: &UnixStream, child_id: u32) -> Result<()> {
    ensure!(
        u32::try_from(super::uds_peer::connected_peer_pid(stream)?)? == child_id,
        "HVF agent bridge peer is not the retained native child"
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_peer_comparison_rejects_substitution() {
        // This witnesses only kernel comparison, never native VM ownership.
        let (stream, _peer) = UnixStream::pair().unwrap();
        let peer =
            u32::try_from(super::super::uds_peer::connected_peer_pid(&stream).unwrap()).unwrap();
        assert!(require_bridge_peer(&stream, peer).is_ok());
        assert!(require_bridge_peer(&stream, peer.checked_add(1).unwrap()).is_err());
    }

    #[test]
    fn missing_child_cannot_be_adopted() {
        let mut child = None;
        assert!(OwnedInstance::adopt(&mut child, "not-an-existing-instance").is_err());
        assert!(child.is_none());
    }

    #[test]
    fn reaped_child_is_refused_before_any_instance_lookup_and_retains_status() {
        let mut process = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .spawn()
            .unwrap();
        assert_eq!(process.wait().unwrap().code(), Some(23));
        let mut process = Some(process);
        assert!(OwnedInstance::adopt(&mut process, "not-an-existing-instance").is_err());
        assert_eq!(
            process
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .unwrap()
                .code(),
            Some(23)
        );
    }
}
