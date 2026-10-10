//! Authenticated stop bound to the connected supervisor's kernel lifetime.
//!
//! No operation here reads a PID file, sends a numeric signal, removes state,
//! or substitutes an acknowledgment/EOF for a process-exit event.

use std::os::unix::net::UnixStream;
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
        let (signing, root) = wire::existing_operator()?;
        let deadline = Instant::now() + wire::CONNECTION_BUDGET;
        let mut stream = wire::connect(vm, deadline)?;
        let pid = super::uds_peer::connected_peer_pid(&stream)?;
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
        let terminal: SignedControl =
            wire::read_record(&wire::state_dir(&self.instance.vm_id)?.join(wire::FINALIZED_FILE))?;
        verify_finalized(&terminal, &self.root, &self.instance)?;
        let proof = ConfirmedExit {
            instance: self.instance,
            dispatch,
            exit_wait,
        };
        proof.verify_current()?;
        Ok(proof)
    }
}
