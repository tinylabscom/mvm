//! Listener transport selection: AF_VSOCK on microVM backends, AF_UNIX on
//! the shared-kernel container tier.
//!
//! A container has no vsock: the host reaches the guest agent through a
//! Unix socket that lives on a host-owned directory bind-mounted into the
//! container. Everything above the accept — the frame I/O, the
//! authenticated session, the `NotActivated` gate, the verb dispatch — is
//! transport-agnostic and unchanged; only the socket family and the peer
//! authorization differ:
//!
//! - **AF_VSOCK**: the kernel reports a peer CID per accepted connection,
//!   and [`peer_cid_is_authorized`] rejects anything that is not the host.
//! - **AF_UNIX**: there is no peer identity to check. The boundary is the
//!   socket file's location on a host-owned directory (created 0700 by the
//!   host backend) — plus the authenticated session every connection still
//!   performs. That is a deliberately weaker boundary than the CID gate,
//!   which is exactly why the container tier is dev-only and prod-refused.

use std::os::fd::RawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::socket::{
    AF_VSOCK, SOCK_STREAM, SockAddrVm, VMADDR_CID_ANY, accept, bind, close, listen,
    peer_cid_is_authorized, socket,
};
use std::mem::size_of;

/// Environment variable selecting the listener transport. The only
/// non-default value is `unix`; anything else (or unset) keeps the vsock
/// listener the microVM backends use.
pub(crate) const TRANSPORT_ENV: &str = "MVM_AGENT_TRANSPORT";
/// Environment variable naming the AF_UNIX socket path in unix mode.
pub(crate) const UNIX_SOCK_ENV: &str = "MVM_AGENT_UNIX_SOCK";
/// Default AF_UNIX socket path: the shared run dir the host backend
/// bind-mounts into the container.
pub(crate) const DEFAULT_UNIX_SOCK: &str = "/run/mvm/agent.sock";

/// Whether the agent should listen on AF_UNIX instead of AF_VSOCK.
pub(crate) fn unix_transport_selected() -> bool {
    std::env::var(TRANSPORT_ENV).ok().as_deref() == Some("unix")
}

/// The AF_UNIX socket path to bind in unix mode.
pub(crate) fn unix_socket_path() -> PathBuf {
    std::env::var(UNIX_SOCK_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_UNIX_SOCK))
}

/// The control-plane listener, bound at startup.
pub(crate) enum AgentListener {
    /// AF_VSOCK listener fd (microVM backends; the peer-CID gate applies).
    Vsock(RawFd),
    /// AF_UNIX listener (shared-kernel container tier).
    Unix(UnixListener),
}

/// Bind the control-plane listener for the selected transport. `vsock_port`
/// is the agent's configured port; it is ignored in unix mode.
pub(crate) fn bind_listener(vsock_port: u32) -> std::io::Result<AgentListener> {
    if unix_transport_selected() {
        return bind_unix_listener(&unix_socket_path()).map(AgentListener::Unix);
    }
    // SAFETY: libc call, arguments are constant values.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: vsock_port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    // SAFETY: pointers are valid for the specified size; on failure the fd
    // is closed before returning.
    let bind_rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if bind_rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` is the vsock socket created above, not yet wrapped in
        // an owning type; close takes no pointers.
        unsafe {
            close(fd);
        }
        return Err(err);
    }
    // SAFETY: fd is valid; on failure it is closed before returning.
    if unsafe { listen(fd, 16) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            close(fd);
        }
        return Err(err);
    }
    Ok(AgentListener::Vsock(fd))
}

/// Bind an AF_UNIX listener at `path`, creating the parent directory if
/// needed and replacing any stale socket file. Split from
/// [`bind_listener`] so the unix-mode bind is unit-testable without the
/// env override.
pub(crate) fn bind_unix_listener(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A stale socket from a previous container run would fail the bind with
    // EADDRINUSE. Best-effort removal.
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path)
}

/// Accept one control connection, enforcing the transport's peer
/// authorization. `None` means "no usable connection this round" — an
/// interrupted accept or an unauthorized peer that was rejected and
/// closed; the caller re-checks its shutdown flags and retries.
pub(crate) fn accept_control(listener: &AgentListener) -> Option<RawFd> {
    match listener {
        AgentListener::Vsock(fd) => accept_control_vsock(*fd),
        AgentListener::Unix(listener) => accept_control_unix(listener),
    }
}

/// AF_VSOCK accept + the host-only peer-CID gate (unchanged semantics from
/// the original inline loop).
fn accept_control_vsock(fd: RawFd) -> Option<RawFd> {
    // Accept into a `sockaddr_vm` so the peer CID is captured: the control
    // port is host-only, and a guest-local workload on a loopback-capable
    // kernel could otherwise dial it and inject any GuestRequest.
    let mut peer = SockAddrVm {
        svm_family: 0,
        svm_reserved1: 0,
        svm_port: 0,
        svm_cid: 0,
        svm_zero: [0; 4],
    };
    let mut peer_len = size_of::<SockAddrVm>() as u32;
    // SAFETY: `peer` is a fully-owned, correctly-sized `sockaddr_vm`; the
    // kernel writes at most `peer_len` bytes and updates it to the actual
    // length.
    let cfd = unsafe {
        accept(
            fd,
            &mut peer as *mut SockAddrVm as *mut core::ffi::c_void,
            &mut peer_len,
        )
    };
    if cfd < 0 {
        // Most common reason: EINTR from a signal. The caller re-checks its
        // shutdown flag immediately.
        return None;
    }
    // Fail closed: reject unless the kernel filled a full AF_VSOCK address
    // whose peer CID is the host. A truncated/unfamiliar address leaves the
    // peer unknown, so it is treated as unauthorized.
    let peer_known =
        peer_len >= size_of::<SockAddrVm>() as u32 && peer.svm_family == AF_VSOCK as u16;
    if !peer_known || !peer_cid_is_authorized(peer.svm_cid) {
        eprintln!(
            "mvm-guest-agent: rejecting control connection from non-host peer (cid={}, family={})",
            peer.svm_cid, peer.svm_family
        );
        // SAFETY: `cfd` is the just-accepted connection fd, not yet wrapped
        // in an owning type; close takes no pointers.
        unsafe {
            close(cfd);
        }
        return None;
    }
    Some(cfd)
}

/// AF_UNIX accept. There is no peer CID to authorize — see the module docs
/// for the boundary that replaces it.
fn accept_control_unix(listener: &UnixListener) -> Option<RawFd> {
    use std::os::fd::IntoRawFd;
    match listener.accept() {
        Ok((stream, _addr)) => Some(stream.into_raw_fd()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    #[test]
    fn unix_listener_round_trips_a_byte_stream() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nested").join("agent.sock");
        // bind_unix_listener creates the missing parent dir.
        let listener = bind_unix_listener(&sock).expect("bind unix listener");
        assert!(sock.exists());

        let client = std::thread::spawn(move || {
            let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
            c.write_all(b"x").unwrap();
            let mut got = [0u8; 1];
            c.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"x");
        });

        let cfd = accept_control(&AgentListener::Unix(listener)).expect("accept");
        // SAFETY: `cfd` is the just-accepted connection fd, owned here.
        let mut conn = unsafe { std::fs::File::from_raw_fd(cfd) };
        let mut b = [0u8; 1];
        conn.read_exact(&mut b).unwrap();
        conn.write_all(&b).unwrap();
        client.join().unwrap();
    }

    #[test]
    fn bind_unix_listener_replaces_a_stale_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        std::fs::write(&sock, b"stale").unwrap();
        let listener = bind_unix_listener(&sock);
        assert!(listener.is_ok(), "stale file must be replaced");
    }
}
