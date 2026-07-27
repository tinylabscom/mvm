//! AF_VSOCK socket primitives shared by the guest's synchronous vsock sites.
//!
//! One leaf backing three callers — the forward-proxy client dial, the
//! one-shot workload-exit reporter, and the builder agent's listener — so the
//! `sockaddr_vm` layout and the socket/connect/bind/listen/accept syscalls
//! live in exactly one place instead of three hand-rolled copies. Depends only
//! on `nix` and `std`: no framing, serde, or async runtime, so the minimal
//! one-shot bins that call it keep a lean closure.
//!
//! `nix::sys::socket::socket` hands back an [`OwnedFd`], so each caller wraps
//! the result in whatever stream type it already exposes (`UnixStream`,
//! `TcpStream`, `File`) with a safe `From<OwnedFd>` conversion — the manual
//! `close`-on-error and the raw-`libc` `unsafe` blocks disappear.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use nix::sys::socket as sock;

/// Bind CID that accepts connections from any peer (`VMADDR_CID_ANY`).
/// Servers listen on this rather than a specific CID.
pub const ANY_CID: u32 = libc::VMADDR_CID_ANY;

/// Create a blocking AF_VSOCK stream socket as an owned fd.
fn vsock_stream_socket() -> io::Result<OwnedFd> {
    // `socket()` infers the protocol slot from `None`; vsock has a single
    // stream protocol so an explicit protocol is neither needed nor accepted.
    let protocol: Option<sock::SockProtocol> = None;
    sock::socket(
        sock::AddressFamily::Vsock,
        sock::SockType::Stream,
        sock::SockFlag::empty(),
        protocol,
    )
    .map_err(io::Error::from)
}

/// Open a connected AF_VSOCK stream to `(cid, port)`.
///
/// The returned [`OwnedFd`] closes on drop, so a failure mid-dial (whether at
/// `socket()` or `connect()`) needs no manual cleanup.
pub fn dial(cid: u32, port: u32) -> io::Result<OwnedFd> {
    let fd = vsock_stream_socket()?;
    sock::connect(fd.as_raw_fd(), &sock::VsockAddr::new(cid, port)).map_err(io::Error::from)?;
    Ok(fd)
}

/// Bind an AF_VSOCK stream socket to `(cid, port)` and start listening.
///
/// `backlog` is the accept-queue depth. Returns the listening socket as an
/// [`OwnedFd`].
pub fn bind_listen(cid: u32, port: u32, backlog: i32) -> io::Result<OwnedFd> {
    let fd = vsock_stream_socket()?;
    sock::bind(fd.as_raw_fd(), &sock::VsockAddr::new(cid, port)).map_err(io::Error::from)?;
    let backlog = sock::Backlog::new(backlog).map_err(io::Error::from)?;
    sock::listen(&fd, backlog).map_err(io::Error::from)?;
    Ok(fd)
}

/// Accept one connection from a listening AF_VSOCK socket.
pub fn accept(listener: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = sock::accept(listener.as_raw_fd()).map_err(io::Error::from)?;
    // SAFETY: `accept(2)` returns a fresh descriptor this process exclusively
    // owns; adopting it into an `OwnedFd` gives it RAII close-on-drop. nix's
    // `accept` returns a bare `RawFd`, so this is the one place the fresh fd
    // must be taken ownership of explicitly.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockaddrLike, VsockAddr};

    #[test]
    fn vsock_addr_maps_family_cid_port() {
        let addr = VsockAddr::new(2, 5251);
        assert_eq!(addr.family(), Some(AddressFamily::Vsock));
        assert_eq!(addr.cid(), 2);
        assert_eq!(addr.port(), 5251);
    }

    #[test]
    fn any_cid_is_the_wildcard_bind_value() {
        assert_eq!(ANY_CID, 0xFFFF_FFFF);
    }

    #[test]
    fn dial_to_dead_port_surfaces_os_error() {
        // Nothing binds this (cid, port): the runner either lacks AF_VSOCK
        // (socket() fails) or refuses/resets the connect — both must surface
        // as an OS-level io::Error rather than panic, and the transient
        // classifier in `connection.rs` keys on exactly that io::Error.
        let err = dial(2, 9).expect_err("dial to an unbound vsock port must fail");
        assert!(
            err.raw_os_error().is_some(),
            "expected an OS error, got {err:?}"
        );
    }
}
