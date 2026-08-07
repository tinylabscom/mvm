//! Who is asking, taken from the kernel rather than from the message.
//!
//! A caller that names itself is not identified; it is quoted. The only
//! identity a Unix socket can prove is the one the kernel attaches to the
//! connection, so that is the only one this module produces — and
//! [`CallerIdentity`] deliberately has no `Serialize`, so it cannot travel
//! in a request and be mistaken for one.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// The peer of a connected Unix socket, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl CallerIdentity {
    /// Construct one directly. Only tests and a host process that already
    /// holds a kernel-supplied credential should reach for this — every
    /// other path goes through [`peer_identity`].
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    /// Whether this caller is the one that registered something.
    pub fn owns(&self, owner_uid: u32) -> bool {
        self.uid == owner_uid
    }
}

/// The identity of the process on the other end of `stream`.
pub fn peer_identity(stream: &UnixStream) -> io::Result<CallerIdentity> {
    peer_identity_of(stream.as_raw_fd())
}

#[cfg(target_os = "linux")]
fn peer_identity_of(fd: RawFd) -> io::Result<CallerIdentity> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a live socket owned by the caller, `cred` is a
    // correctly-sized live struct we own, and `len` names its size.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(CallerIdentity {
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(not(target_os = "linux"))]
fn peer_identity_of(fd: RawFd) -> io::Result<CallerIdentity> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a live socket owned by the caller; both out-params
    // are live locals of the exact types the call writes.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(CallerIdentity { uid, gid })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential comes from the connection. Both ends of a pair are
    /// this process, so this is the one identity the test can predict — and
    /// it proves the syscall path works on this platform rather than
    /// silently returning a zeroed struct.
    #[test]
    fn a_connected_peer_is_identified_by_the_kernel() {
        let (a, _b) = UnixStream::pair().expect("socket pair");
        let caller = peer_identity(&a).expect("the kernel identifies the peer");
        // SAFETY: `getuid`/`getgid` cannot fail and take no arguments.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(caller, CallerIdentity::new(uid, gid));
    }

    #[test]
    fn ownership_is_a_uid_comparison_and_nothing_else() {
        let caller = CallerIdentity::new(501, 20);
        assert!(caller.owns(501));
        assert!(!caller.owns(502));
        assert!(
            !caller.owns(0),
            "root is not an implicit owner: a node with a superuser exception \
             has no ownership boundary at all"
        );
    }
}
