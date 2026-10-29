//! Kernel identity of a connected local socket, not a PID read from disk.
//!
//! A PID returned here is not yet a lifetime handle. Arm an event observer and
//! obtain a fresh authenticated answer on this same connection before relying
//! on the observer. EOF, an already-exited PID, and a missing peer are unknown,
//! not successful shutdown. The server must not pass its socket to another
//! process; such delegation would invalidate the lifetime binding.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// Obtain the peer PID directly from this connected socket.
pub fn connected_peer_pid(socket: &UnixStream) -> io::Result<libc::pid_t> {
    #[cfg(target_os = "macos")]
    {
        // Darwin sys/un.h defines SOL_LOCAL=0 and LOCAL_PEERPID=0x002;
        // this option returns pid_t, unlike LOCAL_PEERCRED's xucred.
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: the socket descriptor is borrowed for the call; the writable
        // pid and length buffers have exactly the sizes passed to getsockopt.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(length).ok() != Some(std::mem::size_of_val(&pid)) {
            return Err(io::Error::other("kernel peer PID has an unexpected size"));
        }
        validate_pid(pid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the socket descriptor is borrowed for the call. The kernel
        // initializes credentials on success; its returned length is checked
        // before the credentials are read.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
            return Err(io::Error::other(
                "kernel peer credentials have an unexpected size",
            ));
        }
        // SAFETY: successful getsockopt returned the full ucred above.
        validate_pid(unsafe { credentials.assume_init() }.pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "connected peer process identity is unsupported",
        ))
    }
}

fn validate_pid(pid: libc::pid_t) -> io::Result<libc::pid_t> {
    if pid <= 1 {
        return Err(io::Error::other(
            "kernel did not supply an eligible peer PID",
        ));
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_reserved_peer_identity_is_refused() {
        for pid in [-1, 0, 1] {
            assert!(validate_pid(pid).is_err());
        }
        assert_eq!(validate_pid(2).unwrap(), 2);
    }
}
