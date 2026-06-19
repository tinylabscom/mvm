//! mvm-builderd — the resident builder-VM control daemon.
//!
//! Runs inside the builder VM as a long-lived service. It binds the
//! AF_VSOCK control port, accepts host connections from `mvmctl`'s
//! builder client, and serves the typed `mvm_build::builderd_protocol`
//! over each one — handshake, then allowlisted build/eval operations.
//! There is no shell surface.
//!
//! The daemon logic lives in the cross-platform `builderd` /
//! `builderd_protocol` library modules; this binary is just the
//! Linux-only AF_VSOCK listener that feeds accepted connections into
//! `builderd::serve_connection_with_executor`. The modules are
//! `#[path]`-included (not reached via `use mvm_build::…`) so the binary
//! cross-compiles to static `aarch64-unknown-linux-musl` for the builder
//! rootfs without dragging in the full `mvm-build` lib (which pulls
//! `reqwest`/`tokio`) — the same structure every builder bin uses.
//!
//! On a non-Linux host the binary still compiles (workspace ergonomics)
//! but is a no-op that exits non-zero; the production binary is
//! cross-compiled from the builder-VM flake.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../builderd_protocol.rs"]
mod builderd_protocol;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../builderd.rs"]
mod builderd;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "mvm-builderd is Linux-only (the resident builder-VM control \
             daemon). On a developer host this binary is a no-op; the \
             production binary is cross-compiled to \
             aarch64-unknown-linux-musl from nix/images/builder-vm/."
        );
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::builderd;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::process::ExitCode;

    // AF_VSOCK constants and FFI are inlined rather than pulled through a
    // dep, mirroring `mvm-host-vm-init` and `mvm-builder-agent` (the
    // builder bins keep their dep tree tiny for the musl cross-compile).
    const AF_VSOCK: i32 = 40;
    const SOCK_STREAM: i32 = 1;
    const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

    #[repr(C)]
    struct SockAddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    unsafe extern "C" {
        fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
        fn listen(sockfd: i32, backlog: i32) -> i32;
        fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
        fn close(fd: i32) -> i32;
    }

    /// Open + bind + listen an AF_VSOCK socket on `port`. Returns the
    /// listening fd or `None` on any setup failure (with a stderr
    /// breadcrumb).
    fn open_vsock_listener(port: u32) -> Option<i32> {
        // SAFETY: a plain socket(2) with constant arguments.
        let listen_fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
        if listen_fd < 0 {
            eprintln!("mvm-builderd: socket(AF_VSOCK) failed");
            return None;
        }
        let addr = SockAddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        // SAFETY: `addr` is a valid, fully-initialised sockaddr_vm and
        // `listen_fd` is the socket just created above.
        let rc = unsafe {
            bind(
                listen_fd,
                &addr as *const SockAddrVm as *const core::ffi::c_void,
                std::mem::size_of::<SockAddrVm>() as u32,
            )
        };
        if rc < 0 {
            eprintln!("mvm-builderd: bind() failed on AF_VSOCK port {port}");
            // SAFETY: closing the fd we own on the error path.
            unsafe { close(listen_fd) };
            return None;
        }
        // SAFETY: `listen_fd` is a bound socket.
        if unsafe { listen(listen_fd, 16) } < 0 {
            eprintln!("mvm-builderd: listen() failed");
            // SAFETY: closing the fd we own on the error path.
            unsafe { close(listen_fd) };
            return None;
        }
        Some(listen_fd)
    }

    /// Accept one connection, returning its fd or `None` on failure.
    fn accept_one(listen_fd: i32) -> Option<i32> {
        // SAFETY: `listen_fd` is a listening socket; null addr/len are
        // permitted and mean "don't return the peer address".
        let conn_fd = unsafe { accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn_fd < 0 { None } else { Some(conn_fd) }
    }

    pub fn run() -> ExitCode {
        let port = mvm_guest::builder_agent::BUILDERD_CONTROL_PORT;
        let Some(listen_fd) = open_vsock_listener(port) else {
            return ExitCode::FAILURE;
        };
        eprintln!("mvm-builderd: listening on AF_VSOCK port {port}");

        // Accept loop. Each connection is served on its own thread so a
        // slow operation on one does not block accepting another;
        // concurrency-via-connections matches the client's model. The
        // executor runs real Nix work inside this builder VM.
        loop {
            let Some(conn_fd) = accept_one(listen_fd) else {
                // A transient accept() failure shouldn't kill the daemon;
                // log and keep serving.
                eprintln!("mvm-builderd: accept() failed; continuing");
                continue;
            };
            std::thread::spawn(move || {
                // SAFETY: `conn_fd` is a freshly accepted socket fd we own;
                // ownership transfers to the UnixStream, which closes it on
                // drop. A vsock stream fd supports the read/write the
                // framing uses.
                let mut stream = unsafe { UnixStream::from_raw_fd(conn_fd) };
                if let Err(e) = builderd::serve_connection_with_executor(
                    &mut stream,
                    &builderd::CommandExecutor,
                ) {
                    eprintln!("mvm-builderd: connection error: {e}");
                }
            });
        }
    }
}
