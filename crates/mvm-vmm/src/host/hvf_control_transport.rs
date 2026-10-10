//! Bounded transport and canonical paths for private HVF lifetime control.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::protocol::hvf_control::HvfInstance;
use serde::{Serialize, de::DeserializeOwned};

pub const MAX_FRAME_BYTES: usize = 4096;
pub const CONNECTION_BUDGET: Duration = Duration::from_secs(2);
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(15);
pub const INSTANCE_FILE: &str = "hvf-instance.json";
pub const FINALIZED_FILE: &str = "hvf-finalized.json";
pub const SOCKET_FILE: &str = "hvf-stop.sock";

/// Security-sensitive paths never silently fall back to a temporary home.
pub fn state_dir(vm: &str) -> Result<PathBuf> {
    mvm_core::naming::validate_vm_name(vm)?;
    let _ = mvm_core::config::mvm_home_strict()?;
    Ok(mvm_core::config::vm_state_dir(vm))
}

pub fn root_paths() -> Result<(PathBuf, PathBuf)> {
    let keys = mvm_core::config::mvm_keys_dir_at(mvm_core::config::mvm_home_strict()?);
    Ok((
        keys.join(super::broker_services_spawn::HOST_SIGNER_KEY),
        keys.join(super::broker_services_spawn::HOST_SIGNER_PUB),
    ))
}

/// Opens existing operator authority only; teardown must never repair custody.
pub fn existing_operator() -> Result<(SigningKey, VerifyingKey)> {
    let (secret, public) = root_paths()?;
    mvm_core::crypto::ed25519_keypair::load_existing(&secret, &public)
        .context("existing HVF operator root unavailable")
}

pub fn read_record<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = std::fs::File::open(path).context("open HVF control evidence")?;
    let mut bytes = Vec::new();
    file.take((MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "HVF control evidence exceeds bound"
    );
    serde_json::from_slice(&bytes).context("parse HVF control evidence")
}

pub fn read_instance(vm: &str) -> Result<HvfInstance> {
    let instance: HvfInstance = read_record(&state_dir(vm)?.join(INSTANCE_FILE))?;
    ensure!(
        instance.vm_id == vm,
        "HVF control evidence names another VM"
    );
    Ok(instance)
}

pub fn connect(vm: &str, deadline: Instant) -> Result<UnixStream> {
    let address = socket2::SockAddr::unix(state_dir(vm)?.join(SOCKET_FILE))?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&address, remaining(deadline)?)?;
    Ok(socket.into())
}

/// Refuses an existing endpoint; never unlinks another generation's evidence.
pub fn bind(vm: &str) -> Result<UnixListener> {
    let dir = state_dir(vm)?;
    mvm_core::config::create_private_dir(&dir)?;
    let path = dir.join(SOCKET_FILE);
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.bind(&socket2::SockAddr::unix(&path)?)?;
    mvm_core::private_fs::set_mode(&path, 0o600)?;
    socket.listen(8)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let time = deadline.saturating_duration_since(Instant::now());
    if time.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "HVF control deadline",
        ));
    }
    Ok(time)
}

pub fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream, deadline: Instant) -> Result<T> {
    let mut size = [0; 4];
    read_exact(stream, &mut size, deadline)?;
    let size = usize::try_from(u32::from_be_bytes(size))?;
    ensure!(
        size > 0 && size <= MAX_FRAME_BYTES,
        "invalid HVF control frame size"
    );
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes).context("invalid HVF control frame")
}

pub fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "HVF control frame exceeds bound"
    );
    let size = u32::try_from(bytes.len())?.to_be_bytes();
    write_all(stream, &size, deadline)?;
    write_all(stream, &bytes, deadline)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_frame_roundtrip_and_oversize_refusal() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + CONNECTION_BUDGET;
        write_frame(&mut sender, &"roundtrip", deadline).unwrap();
        assert_eq!(
            read_frame::<String>(&mut receiver, deadline).unwrap(),
            "roundtrip"
        );
        sender.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(read_frame::<String>(&mut receiver, deadline).is_err());
    }

    #[test]
    fn eof_truncation_and_expired_deadline_are_not_success() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(read_frame::<String>(&mut receiver, Instant::now() + CONNECTION_BUDGET).is_err());
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&8_u32.to_be_bytes()).unwrap();
        sender.write_all(b"\"bad").unwrap();
        drop(sender);
        assert!(read_frame::<String>(&mut receiver, Instant::now() + CONNECTION_BUDGET).is_err());
        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        assert!(write_frame(&mut sender, &"late", Instant::now()).is_err());
    }
}
