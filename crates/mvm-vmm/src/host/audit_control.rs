//! One-launch audit shutdown registration and endpoint-only failure notification.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use mvm_core::protocol::hvf_control::HvfInstance;
use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::process_identity::ProcessIdentity;

const REGISTER_FD: &str = "MVM_AUDIT_REGISTER_FD";
const BINDING: &str = "MVM_AUDIT_CONTROL_BINDING";
const NOTIFY_FD: &str = "MVM_AUDIT_NOTIFY_FD";
const MAX_MESSAGE_BYTES: u32 = 16 * 1024;
const ACK: u8 = 1;
const FAILURE: u8 = 2;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Admitted workload identity plus a fresh, launcher-generated control generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditBinding {
    pub tenant_id: String,
    pub instance_id: String,
    pub workload_id: String,
    pub plan_id: String,
    pub epoch: u64,
    pub generation: [u8; 32],
}

/// Exact backend authority; never sent to the serving endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ShutdownTarget {
    Hvf(HvfInstance),
    Firecracker {
        process: ProcessIdentity,
        api_socket: PathBuf,
    },
}

impl ShutdownTarget {
    fn instance_id(&self) -> &str {
        match self {
            Self::Hvf(instance) => &instance.vm_id,
            Self::Firecracker { process, .. } => &process.vm_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationMessage {
    binding: AuditBinding,
    target: ShutdownTarget,
}

struct Registration {
    binding: AuditBinding,
    registered: bool,
    target: Option<ShutdownTarget>,
}

impl Registration {
    fn new(binding: AuditBinding) -> Self {
        Self {
            binding,
            registered: false,
            target: None,
        }
    }

    fn register(&mut self, binding: AuditBinding, target: ShutdownTarget) -> io::Result<()> {
        if self.registered || self.binding != binding || target.instance_id() != binding.instance_id
        {
            return Err(invalid("audit shutdown registration mismatch or replay"));
        }
        self.target = Some(target);
        self.registered = true;
        Ok(())
    }

    fn take_target(&mut self) -> io::Result<ShutdownTarget> {
        self.target
            .take()
            .ok_or_else(|| invalid("audit shutdown target absent or consumed"))
    }
}

/// Launcher-held registration capability. Dropping it before registration refuses readiness.
#[derive(Debug)]
pub struct LaunchControl {
    binding: AuditBinding,
    launcher: UnixStream,
    keeper: UnixStream,
}

impl LaunchControl {
    /// Create an anonymous owner-only registration channel for this launch.
    pub fn new(mut binding: AuditBinding) -> io::Result<Self> {
        if binding.tenant_id.is_empty()
            || binding.instance_id.is_empty()
            || binding.workload_id.is_empty()
            || binding.plan_id.is_empty()
            || binding.epoch == 0
        {
            return Err(invalid("audit shutdown binding is incomplete"));
        }
        rand::rng().fill_bytes(&mut binding.generation);
        let (launcher, keeper) = UnixStream::pair()?;
        launcher.set_read_timeout(Some(REGISTRATION_TIMEOUT))?;
        launcher.set_write_timeout(Some(REGISTRATION_TIMEOUT))?;
        Ok(Self {
            binding,
            launcher,
            keeper,
        })
    }

    /// The identity the endpoint must compare before accepting readiness.
    pub fn binding(&self) -> &AuditBinding {
        &self.binding
    }

    /// Give the keeper only its receive end; retain this handle through spawning.
    pub fn configure(&self, command: &mut Command) -> io::Result<()> {
        command.env(BINDING, serde_json::to_string(&self.binding)?);
        inherit(command, REGISTER_FD, &self.keeper);
        Ok(())
    }

    /// Transfer exact boot authority and wait until the keeper has validated it.
    pub fn register(mut self, target: ShutdownTarget) -> io::Result<()> {
        drop(self.keeper);
        write_message(
            &mut self.launcher,
            &RegistrationMessage {
                binding: self.binding,
                target,
            },
        )?;
        let mut ack = [0];
        self.launcher.read_exact(&mut ack)?;
        if ack != [ACK] {
            return Err(invalid("audit shutdown registration was not acknowledged"));
        }
        Ok(())
    }
}

/// Keeper-owned channels. The serving endpoint never inherits registration authority.
#[derive(Debug)]
pub struct KeeperControl {
    binding: AuditBinding,
    registration: UnixStream,
    notifications: UnixStream,
    endpoint: UnixStream,
}

impl KeeperControl {
    /// Read only the non-secret control environment, never endpoint stdin.
    pub fn from_env() -> io::Result<Option<Self>> {
        let Some(registration) = inherited(REGISTER_FD)? else {
            return Ok(None);
        };
        let binding: AuditBinding = serde_json::from_str(
            &std::env::var(BINDING).map_err(|_| invalid("missing audit shutdown binding"))?,
        )?;
        registration.set_read_timeout(Some(REGISTRATION_TIMEOUT))?;
        registration.set_write_timeout(Some(REGISTRATION_TIMEOUT))?;
        let (notifications, endpoint) = UnixStream::pair()?;
        Ok(Some(Self {
            binding,
            registration,
            notifications,
            endpoint,
        }))
    }

    /// Wire a notification-only channel into the endpoint child.
    pub fn configure_endpoint(&self, command: &mut Command) {
        command.env_remove(REGISTER_FD).env_remove(BINDING);
        inherit(command, NOTIFY_FD, &self.endpoint);
    }

    /// Validate the backend before acknowledging registration, then consume one failure.
    ///
    /// A broken notification channel is a failure too: production must not keep
    /// executing after losing its audit owner. `prepare` must bind a live exact
    /// target; `stop` must use that prepared authority, not resolve a VM name.
    pub fn serve<T>(
        mut self,
        prepare: impl FnOnce(ShutdownTarget) -> anyhow::Result<T>,
        stop: impl FnOnce(T) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        drop(self.endpoint);
        let message: RegistrationMessage = read_message(&mut self.registration)?;
        let mut registration = Registration::new(self.binding.clone());
        registration.register(message.binding, message.target)?;
        let target = prepare(registration.take_target()?)?;
        // If the launcher or endpoint died during transfer, the keeper already
        // owns the exact target and must stop it rather than abandoning authority.
        let activated = self
            .registration
            .write_all(&[ACK])
            .and_then(|()| write_message(&mut self.notifications, &self.binding));
        if activated.is_ok() {
            let mut notification = [0];
            let _ = self.notifications.read_exact(&mut notification);
        }
        stop(target)
    }
}

/// Endpoint-side readiness and failure notification, with no workload stop authority.
#[derive(Debug)]
pub struct EndpointControl {
    stream: UnixStream,
}

impl Drop for EndpointControl {
    fn drop(&mut self) {
        // Adoption duplicates the inherited descriptor. Shutdown also closes
        // that original socket's channel, so abandoning the sink cannot leave
        // a keeper waiting on a descriptor the endpoint no longer uses.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl EndpointControl {
    /// Absent for builder sessions; production workload endpoints must require it.
    pub fn from_env() -> io::Result<Option<Self>> {
        Ok(inherited(NOTIFY_FD)?.map(|stream| Self { stream }))
    }

    /// Gate serving until the keeper confirms this exact admitted launch.
    ///
    /// Send the ordinary endpoint startup handshake first, so the launcher can
    /// boot the workload and obtain its exact backend identity.
    pub fn wait_ready(&mut self, expected: &AuditBinding) -> io::Result<()> {
        self.stream.set_read_timeout(Some(REGISTRATION_TIMEOUT))?;
        let actual: AuditBinding = read_message(&mut self.stream)?;
        if actual != *expected {
            return Err(invalid("audit shutdown readiness binding mismatch"));
        }
        self.stream.set_read_timeout(None)
    }

    /// Notify the lifecycle owner; it consumes its registered target only once.
    pub fn notify_failure(&self) -> io::Result<()> {
        (&self.stream).write_all(&[FAILURE])
    }
}

fn inherit(command: &mut Command, variable: &str, stream: &UnixStream) {
    command.env(variable, stream.as_raw_fd().to_string());
    super::restore_image::inherit_descriptors(command, vec![stream.as_raw_fd()]);
}

fn inherited(variable: &str) -> io::Result<Option<UnixStream>> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(None);
    };
    let fd: libc::c_int = value
        .to_str()
        .and_then(|value| value.parse().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or_else(|| invalid("invalid audit control descriptor"))?;
    // SAFETY: fcntl validates an integer descriptor without dereferencing memory.
    // Duplicate instead of adopting: repeated calls cannot double-own an fd.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful F_DUPFD_CLOEXEC created this owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    // SAFETY: mark the inherited descriptor close-on-exec before spawning children.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = UnixStream::from(duplicate);
    stream.peer_addr()?;
    Ok(Some(stream))
}

fn write_message(stream: &mut UnixStream, message: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(message)?;
    let size =
        u32::try_from(bytes.len()).map_err(|_| invalid("audit control message too large"))?;
    if size > MAX_MESSAGE_BYTES {
        return Err(invalid("audit control message too large"));
    }
    stream.write_all(&size.to_be_bytes())?;
    stream.write_all(&bytes)
}

fn read_message<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size);
    if size > MAX_MESSAGE_BYTES {
        return Err(invalid("audit control message too large"));
    }
    let mut bytes = vec![0; size as usize];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
