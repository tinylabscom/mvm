//! Vsock → TCP and vsock → Unix-socket forwarders, started on demand via
//! `StartPortForward` / `StartUnixSocketForward` requests from the host.

use std::mem::size_of;
use std::net::Shutdown;
use std::os::fd::{FromRawFd, RawFd};

use crate::socket::{
    AF_VSOCK, SOCK_STREAM, SockAddrVm, VMADDR_CID_ANY, accept, bind, close, listen, socket,
};

/// Loopback host the port forwarder dials when proxying vsock → TCP.
///
/// Pinning this to `127.0.0.1` is load-bearing: the agent must never
/// accept TCP traffic from outside the guest. The forwarder only
/// originates outbound TCP, but a future "double-ended" forwarder must reuse
/// this constant rather than reach for `0.0.0.0` or a configurable host.
pub(crate) const PORT_FORWARD_TCP_HOST: &str = "127.0.0.1";

/// Bind a vsock listener and forward each connection to a local TCP port.
pub(crate) fn run_port_forwarder(vsock_port: u32, tcp_port: u16) {
    // SAFETY: libc call with constant arguments.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("port-fwd: failed to create vsock socket for port {tcp_port}");
        return;
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: vsock_port,
        svm_cid: VMADDR_CID_ANY,
        svm_flags: 0,
        svm_zero: [0; 3],
    };

    // SAFETY: valid pointer and size.
    let rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if rc != 0 {
        eprintln!("port-fwd: failed to bind vsock port {vsock_port} for tcp/{tcp_port}");
        // SAFETY: `fd` is the vsock socket created above, not yet wrapped in an
        // owning type; close takes no pointers.
        unsafe {
            close(fd);
        }
        return;
    }

    // SAFETY: fd is valid.
    if unsafe { listen(fd, 8) } != 0 {
        eprintln!("port-fwd: failed to listen on vsock port {vsock_port}");
        unsafe {
            close(fd);
        }
        return;
    }

    eprintln!("port-fwd: vsock:{vsock_port} → tcp://localhost:{tcp_port}");

    loop {
        // SAFETY: null addr pointers are fine when we don't need peer info.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }

        std::thread::spawn(move || {
            use std::os::unix::net::UnixStream;
            // SAFETY: cfd is a valid fd from accept(). UnixStream is a
            // thin wrapper around an fd — works fine for vsock sockets.
            let vsock_stream = unsafe { UnixStream::from_raw_fd(cfd as RawFd) };
            let Ok(tcp_stream) = std::net::TcpStream::connect((PORT_FORWARD_TCP_HOST, tcp_port))
            else {
                eprintln!("port-fwd: connect to localhost:{tcp_port} failed");
                return;
            };
            let Ok(mut tcp_read) = tcp_stream.try_clone() else {
                return;
            };
            let Ok(mut vsock_write) = vsock_stream.try_clone() else {
                return;
            };
            let mut vsock_read = vsock_stream;
            let mut tcp_write = tcp_stream;

            let h1 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut vsock_read, &mut tcp_write);
                let _ = tcp_write.shutdown(Shutdown::Write);
            });
            let h2 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut tcp_read, &mut vsock_write);
                let _ = vsock_write.shutdown(Shutdown::Write);
            });
            let _ = h1.join();
            let _ = h2.join();
        });
    }
}

fn validate_unix_forward_guest_path(path: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("guest socket path must be absolute");
    }
    if !path.starts_with("/run/mvm/") {
        anyhow::bail!("guest socket path must be under /run/mvm");
    }
    Ok(())
}

pub(crate) fn start_unix_socket_forwarder(
    guest_path: &str,
    host_vsock_port: u32,
    socket_mode: u32,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    validate_unix_forward_guest_path(guest_path)?;
    let path = std::path::PathBuf::from(guest_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(&path)?;
        }
        Ok(_) => {
            anyhow::bail!("refusing to replace non-socket path {}", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode & 0o777))?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let Ok(upstream) = mvm_agentd::vsock::connect_host_vsock(
                    host_vsock_port,
                    mvm_agentd::vsock::DEFAULT_TIMEOUT_SECS,
                ) else {
                    eprintln!("unix-fwd: connect_host_vsock({host_vsock_port}) failed");
                    return;
                };
                let Ok(mut guest_read) = stream.try_clone() else {
                    return;
                };
                let Ok(mut host_write) = upstream.try_clone() else {
                    return;
                };
                let mut guest_write = stream;
                let mut host_read = upstream;
                let h1 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut guest_read, &mut host_write);
                });
                let h2 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut host_read, &mut guest_write);
                });
                let _ = h1.join();
                let _ = h2.join();
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the port forwarder's TCP connect target must remain
    /// loopback. Anything else would let traffic exit the guest's network
    /// namespace, defeating the "no host network from guest" claim. If you
    /// ever need to make this configurable, update the threat model first.
    #[test]
    fn test_port_forward_target_is_loopback() {
        assert_eq!(PORT_FORWARD_TCP_HOST, "127.0.0.1");
        let parsed: std::net::IpAddr = PORT_FORWARD_TCP_HOST.parse().unwrap();
        assert!(parsed.is_loopback(), "port-forward target must be loopback");
    }

    #[test]
    fn unix_forward_guest_path_is_confined_to_run_mvm() {
        validate_unix_forward_guest_path("/run/mvm/forward.sock").expect("valid path");
        let relative = validate_unix_forward_guest_path("run/mvm/forward.sock")
            .expect_err("relative path rejected");
        assert!(relative.to_string().contains("absolute"));
        let outside =
            validate_unix_forward_guest_path("/tmp/forward.sock").expect_err("outside rejected");
        assert!(outside.to_string().contains("under /run/mvm"));
    }
}
