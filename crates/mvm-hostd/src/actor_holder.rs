//! VM-scoped actor channel custody, separate from lifecycle admission and launch.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_core::net::actor_session::{
    ActorDeadlineStream, ActorSession, ActorSessionBinding, read_actor_response,
    write_actor_request,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The sole inherited private controller connection in the holder process.
pub const CONTROLLER_FD: i32 = 3;
const BOOT_LIMIT: usize = 8192;
const BOOT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-boot actor transport material. Never persist, log, clone, or send to a broker.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorHolderConfig {
    pub binding: ActorSessionBinding,
    pub host_seed: [u8; 32],
    pub listen_socket: PathBuf,
}

impl Drop for ActorHolderConfig {
    fn drop(&mut self) {
        self.host_seed.zeroize();
    }
}

impl ActorHolderConfig {
    fn validate(&self) -> Result<()> {
        self.binding.session_id()?;
        ensure!(
            self.listen_socket.is_absolute(),
            "actor holder requires an absolute socket path"
        );
        ensure!(
            SigningKey::from_bytes(&self.host_seed)
                .verifying_key()
                .to_bytes()
                == self.binding.host_public_key,
            "actor holder key does not match boot binding"
        );
        Ok(())
    }
}

/// Spawn an owned holder and wait for its listener readiness under a deadline.
///
/// The caller must retain, stop and reap the returned child with the parent VM.
/// `controller` is a private socketpair endpoint, never a pathname connection.
/// The caller verifies the executable before supplying its path.
pub fn spawn(binary: &Path, config: ActorHolderConfig, controller: UnixStream) -> Result<Child> {
    config.validate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(&config)?);
    ensure!(
        bytes.len() <= BOOT_LIMIT,
        "actor holder config exceeds bound"
    );
    let (bootstrap, child_bootstrap) = UnixStream::pair()?;
    let mut bootstrap = ActorDeadlineStream::new(bootstrap, Instant::now() + BOOT_TIMEOUT)?;
    let mut command = mvm_core::env_hygiene::helper_command(binary);
    command
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(child_bootstrap)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let fd = controller.as_raw_fd();
    // SAFETY: only async-signal-safe descriptor operations run after fork.
    // The owned socket remains open until spawn returns; fd 3 is reserved here.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, CONTROLLER_FD) < 0 || libc::fcntl(CONTROLLER_FD, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    mvm_agentd::fd_hygiene::configure_close_fds(&mut command, 4, None);
    let mut child = command.spawn().context("spawn actor holder")?;
    drop(controller);
    let ready = (|| {
        bootstrap.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        bootstrap.write_all(&bytes)?;
        let mut ready = [0; 1];
        bootstrap.read_exact(&mut ready)?;
        ensure!(ready == [1], "actor holder did not become ready");
        ensure!(
            child.try_wait()?.is_none(),
            "actor holder exited during startup"
        );
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = ready {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

/// Run the dedicated role using inherited bootstrap and controller sockets.
pub fn run(bootstrap: UnixStream, controller: UnixStream) -> Result<()> {
    let mut bootstrap = ActorDeadlineStream::new(bootstrap, Instant::now() + BOOT_TIMEOUT)?;
    let mut length = [0; 4];
    bootstrap.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    ensure!(length <= BOOT_LIMIT, "actor holder config exceeds bound");
    let mut bytes = Zeroizing::new(vec![0; length]);
    bootstrap.read_exact(&mut bytes)?;
    let config: ActorHolderConfig = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid actor holder config"))?;
    bytes.zeroize();
    config.validate()?;
    // Do not unlink an existing listener: a stale/conflicting owner is a refusal.
    let listener = UnixListener::bind(&config.listen_socket)?;
    std::fs::set_permissions(
        &config.listen_socket,
        std::fs::Permissions::from_mode(0o600),
    )?;
    bootstrap.write_all(&[1])?;
    drop(bootstrap);
    for incoming in listener.incoming() {
        let stream = incoming?;
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut stream = ActorDeadlineStream::new(stream, deadline)?;
        let mut session = match ActorSession::host(
            &mut stream,
            &config.binding,
            SigningKey::from_bytes(&config.host_seed),
        ) {
            Ok(session) => session,
            Err(_) => continue,
        };
        let request = match session.receive_request(&mut stream) {
            Ok(request) => request,
            Err(_) => continue,
        };
        // Any IPC failure terminates this holder; continuing could pair a late
        // lifecycle response with a different request.
        let mut authority = ActorDeadlineStream::new(controller.try_clone()?, deadline)?;
        write_actor_request(&mut authority, &request)?;
        let response = read_actor_response(&mut authority)?;
        let _ = session.send_response(&mut stream, &response);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::workload_actor::{ActorRequest, ActorResponse};
    use mvm_core::net::actor_session::{read_actor_request, write_actor_response};

    #[test]
    fn holder_forwards_only_authenticated_canonical_requests_over_private_ipc() {
        let directory = tempfile::tempdir().unwrap();
        let binding = ActorSessionBinding {
            protocol_version: 1,
            purpose: "host.actor.v1".into(),
            tenant: "tenant".into(),
            workflow: "workflow".into(),
            boot_id: "boot".into(),
            plan_digest: [3; 32],
            epoch: 1,
            controller_generation: 1,
            key_generation: 1,
            guest_public_key: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            host_public_key: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
        };
        let config = ActorHolderConfig {
            binding: binding.clone(),
            host_seed: [2; 32],
            listen_socket: directory.path().join("actor.sock"),
        };
        let (mut bootstrap, holder_bootstrap) = UnixStream::pair().unwrap();
        bootstrap.set_read_timeout(Some(BOOT_TIMEOUT)).unwrap();
        let (mut authority, holder_authority) = UnixStream::pair().unwrap();
        authority.set_read_timeout(Some(BOOT_TIMEOUT)).unwrap();
        let holder = std::thread::spawn(move || run(holder_bootstrap, holder_authority));
        let bytes = serde_json::to_vec(&config).unwrap();
        bootstrap
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        bootstrap.write_all(&bytes).unwrap();
        let mut ready = [0; 1];
        bootstrap.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [1]);
        let request = ActorRequest::decode(
            br#"{"version":1,"operation":{"operation":"launch","grant_id":"g","template_id":"t","idempotency_key":"i"}}"#
        ).unwrap();
        let response = ActorResponse::decode(
            br#"{"version":1,"outcome":{"status":"refused","code":"capacity"}}"#,
        )
        .unwrap();
        let connect = || {
            let mut stream = ActorDeadlineStream::new(
                UnixStream::connect(&config.listen_socket).unwrap(),
                Instant::now() + BOOT_TIMEOUT,
            )
            .unwrap();
            let session =
                ActorSession::guest(&mut stream, &binding, SigningKey::from_bytes(&[1; 32]))
                    .unwrap();
            (stream, session)
        };
        let (mut guest, mut session) = connect();
        session.send_request(&mut guest, &request).unwrap();
        assert_eq!(read_actor_request(&mut authority).unwrap(), request);
        write_actor_response(&mut authority, &response).unwrap();
        assert_eq!(session.receive_response(&mut guest).unwrap(), response);
        drop(guest);
        // Lost private authority IPC terminates the holder rather than re-pairing
        // a late response with another guest invocation.
        drop(authority);
        let (mut guest, mut session) = connect();
        session.send_request(&mut guest, &request).unwrap();
        assert!(session.receive_response(&mut guest).is_err());
        assert!(holder.join().unwrap().is_err());
    }
}
