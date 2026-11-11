//! Mailbox listener glue: bind the reserved mailbox vsock port and forward the
//! workload's outbox message to each host connection.
//!
//! Opt-in and launch-asserted, like telemetry: the listener binds only when
//! the kernel cmdline carries `mvm.mailbox=1`, which the host sets only for a
//! signed plan that carries a mailbox grant. Otherwise no thread starts and no
//! port is held. Vsock-only; the container tier has none.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::sync::{OnceLock, atomic::Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use mvm_agentd::flowmux_drive::{MAILBOX_ACK_SIGNING_KEY_FILE, RUN_MVM_DIR};
use mvm_agentd::mailbox_outbox::{MAILBOX_CMDLINE_TOKEN, OUTBOX_PATH, wait_and_forward_outbox};
use mvm_agentd::telemetry_capture::session::TimedStream;
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader::MailboxReaderBootBinding;
use zeroize::Zeroizing;

use crate::globals::SHUTDOWN_REQUESTED;
use crate::telemetry::cmdline_asserts;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

const MAILBOX_IO_TIMEOUT: Duration = Duration::from_secs(12);
static ACK_SEED: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
static READER_BOOT: OnceLock<MailboxReaderBootBinding> = OnceLock::new();

/// Retain the root-only ACK key before PID 1 drops to the workload UID.
/// A missing or malformed key disables Receive; the existing Send path
/// remains available, and warm children never inherit reader authority.
pub(crate) fn capture_ack_key_before_privilege_drop() {
    let dir = Path::new(RUN_MVM_DIR);
    let binding = match MailboxReaderBootBinding::load(dir) {
        Ok(binding) => binding,
        Err(error) => {
            if dir
                .join(mvm_core::mailbox::reader::MAILBOX_READER_BOOT_FILE)
                .exists()
            {
                eprintln!("mvm-guest-agent: mailbox reader boot unavailable: {error}");
            }
            return;
        }
    };
    match load_ack_seed(&dir.join(MAILBOX_ACK_SIGNING_KEY_FILE), 0) {
        Ok(seed)
            if SigningKey::from_bytes(&seed).verifying_key().to_bytes()
                == binding.ack_public_key =>
        {
            if ACK_SEED.set(seed).is_err() || READER_BOOT.set(binding).is_err() {
                eprintln!("mvm-guest-agent: mailbox ACK identity already initialized");
            }
        }
        Ok(_) | Err(_) => eprintln!("mvm-guest-agent: mailbox ACK key does not match this boot"),
    }
}

fn load_ack_seed(path: &Path, owner_uid: u32) -> io::Result<Zeroizing<[u8; 32]>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() != 32
        || meta.nlink() != 1
        || meta.uid() != owner_uid
        || meta.permissions().mode() & 0o777 != 0o400
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mailbox ACK key is not root-only",
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    file.read_exact(seed.as_mut())?;
    Ok(seed)
}

struct MailboxDeadline<'a, S> {
    stream: &'a mut S,
    until: Instant,
}

impl<'a, S> MailboxDeadline<'a, S> {
    fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            until: Instant::now() + MAILBOX_IO_TIMEOUT,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mailbox I/O deadline",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl<S: AsRawFd> Read for MailboxDeadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let millis = self.remaining()?.as_millis().max(1);
            let millis = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
            let fd = self.stream.as_raw_fd();
            let mut ready = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd is borrowed from the live socket.
            let polled = unsafe { libc::poll(&raw mut ready, 1, millis) };
            if polled == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mailbox read timeout",
                ));
            }
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: `fd` is live and `buf` is writable for its exact length.
            let received =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if received >= 0 {
                return Ok(received as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
    }
}

impl<S: TimedStream> Write for MailboxDeadline<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let remaining = self.remaining()?;
            match self.stream.write_now(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.stream.wait_writable(remaining)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

/// Spawn the mailbox listener on a boot that asserts one. Called after PID-1
/// activation; a bind failure is logged and abandoned, never boot-fatal.
pub(crate) fn init_mailbox() {
    let asserted = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| cmdline_asserts(&cmdline, MAILBOX_CMDLINE_TOKEN))
        .unwrap_or(false);
    if !asserted || unix_transport_selected() {
        return;
    }
    let _ = mvm_agentd::detached::spawn_named("mailbox-listener", || {
        match bind_vsock_listener(MAILBOX_PORT) {
            Ok(fd) => accept_loop(fd),
            Err(e) => eprintln!(
                "mvm-guest-agent: mailbox listener bind failed (port {MAILBOX_PORT}): {e}"
            ),
        }
    });
}

/// One host connection at a time, each answered from the outbox.
fn accept_loop(listener_fd: RawFd) {
    let mut refused = 0u32;
    while !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        let Some(cfd) = accept_vsock(listener_fd, "mailbox") else {
            continue;
        };
        // SAFETY: `cfd` is the just-accepted connection fd, owned here and
        // closed on drop.
        let mut stream = unsafe { std::fs::File::from_raw_fd(cfd) };
        if let Err(error) = stream.set_timeouts(MAILBOX_IO_TIMEOUT, MAILBOX_IO_TIMEOUT) {
            eprintln!("mvm-guest-agent: mailbox connection has no bounded I/O: {error}");
            continue;
        }
        match wait_and_forward_outbox(
            &mut MailboxDeadline::new(&mut stream),
            Path::new(OUTBOX_PATH),
        ) {
            Ok(()) | Err(Refusal::Unavailable) => {}
            Err(refusal) => {
                if refused < 3 || refused.is_multiple_of(100) {
                    eprintln!("mvm-guest-agent: mailbox frame not delivered: {refusal}");
                }
                refused = refused.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_token_asserts_a_mailbox() {
        assert!(cmdline_asserts(
            "console=ttyS0 mvm.mailbox=1",
            MAILBOX_CMDLINE_TOKEN
        ));
        assert!(!cmdline_asserts("mvm.mailbox=0", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("xmvm.mailbox=1", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("console=ttyS0", MAILBOX_CMDLINE_TOKEN));
    }

    #[test]
    fn a_mailbox_deadline_refuses_more_io_after_it_expires() {
        let (mut stream, _peer) = std::os::unix::net::UnixStream::pair().expect("socket");
        let mut expired = MailboxDeadline {
            stream: &mut stream,
            until: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            expired.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            expired.write(b"pending").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn a_silent_host_cannot_keep_the_guest_reader_blocked() {
        let (mut stream, _silent_peer) = std::os::unix::net::UnixStream::pair().expect("socket");
        let mut bounded = MailboxDeadline {
            stream: &mut stream,
            until: Instant::now() + Duration::from_millis(25),
        };
        assert_eq!(
            bounded.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn ack_seed_loader_requires_exact_private_regular_file() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        let uid = dir.path().metadata().unwrap().uid();
        let path = dir.path().join(MAILBOX_ACK_SIGNING_KEY_FILE);
        std::fs::write(&path, [8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(*load_ack_seed(&path, uid).unwrap(), [8; 32]);
        assert!(load_ack_seed(&path, uid.wrapping_add(1)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
        std::fs::write(&path, [8; 31]).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &path).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
    }
}
