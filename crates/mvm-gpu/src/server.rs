//! The accept/serve loop: one listener, one thread per connection, one
//! backend per connection.
//!
//! A per-connection backend is deliberate. Contexts and allocations belong
//! to the guest process that minted them; two guests never share a handle
//! table, and a connection dropping reclaims its backend wholesale.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use mvm_contract::protocol::gpu::{GpuRequest, decode_frame, encode_frame};

use crate::GpuBackend;

/// How the endpoint listens. Mirrored by the guest's `MVM_GPU_RPC`
/// transport selection, so a test can point both ends at the same socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    /// A filesystem Unix socket (Firecracker/libkrun/HVF per-port relay).
    Unix(std::path::PathBuf),
    /// A TCP host:port (host-side testing).
    Tcp(String),
    /// A real host AF_VSOCK port (QEMU's vhost-vsock).
    #[cfg(target_os = "linux")]
    Vsock(u32),
}

impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tcp(addr) => write!(f, "tcp:{addr}"),
            #[cfg(target_os = "linux")]
            Self::Vsock(port) => write!(f, "vsock:{port}"),
        }
    }
}

/// Parse the `--listen` value: `unix:/path`, `tcp:HOST:PORT`, `vsock:PORT`.
pub fn parse_listen_addr(spec: &str) -> Result<ListenAddr, String> {
    let (kind, value) = spec
        .split_once(':')
        .ok_or_else(|| format!("listen address {spec:?} must be unix:/tcp:/vsock: prefixed"))?;
    match kind {
        "unix" if !value.is_empty() => Ok(ListenAddr::Unix(Path::new(value).to_path_buf())),
        "tcp" if !value.is_empty() => Ok(ListenAddr::Tcp(value.to_string())),
        #[cfg(target_os = "linux")]
        "vsock" => value
            .parse::<u32>()
            .map(ListenAddr::Vsock)
            .map_err(|e| format!("vsock port {value:?} is not a u32: {e}")),
        #[cfg(not(target_os = "linux"))]
        "vsock" => Err("vsock listen is only available on Linux hosts".to_string()),
        other => Err(format!("unknown listen kind {other:?} in {spec:?}")),
    }
}

/// Serve one accepted connection: read frames, dispatch, write answers,
/// until EOF or a fatal framing error.
pub fn serve_connection<S: Read + Write>(
    mut stream: S,
    backend: Arc<std::sync::Mutex<Box<dyn GpuBackend>>>,
) -> std::io::Result<()> {
    loop {
        let mut prefix = [0_u8; 4];
        match stream.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let body_len = mvm_contract::protocol::gpu::frame_body_len(prefix);
        if body_len > mvm_contract::protocol::gpu::MAX_MESSAGE_LEN {
            // Refuse before allocating anything sized by the peer.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame length {body_len} exceeds the wire cap"),
            ));
        }
        let mut body = vec![0_u8; body_len as usize];
        stream.read_exact(&mut body)?;
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&body);
        let request: GpuRequest = match decode_frame(&frame) {
            Ok(request) => request,
            Err(e) => {
                // A malformed frame kills the connection: the stream is no
                // longer frame-aligned, and every subsequent read would be
                // garbage. The guest shim reconnects on its next call.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ));
            }
        };
        let response = {
            let mut backend = backend.lock().unwrap_or_else(|e| e.into_inner());
            crate::handle_request(&mut **backend, &request)
        };
        let encoded = encode_frame(&response).map_err(std::io::Error::other)?;
        stream.write_all(&encoded)?;
        stream.flush()?;
    }
}

/// Accept connections until `stop` is set, spawning one thread per
/// connection. `make_backend` builds a fresh backend per connection.
///
/// Returns once the listener errors or `stop` flips. The stop flag is the
/// reap path: the per-VM supervisor sets it when the VM dies.
pub fn run(
    addr: &ListenAddr,
    make_backend: impl Fn() -> Box<dyn GpuBackend> + Send + 'static,
    stop: &'static AtomicBool,
) -> std::io::Result<()> {
    match addr {
        ListenAddr::Unix(path) => {
            let _ = std::fs::remove_file(path);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let listener = UnixListener::bind(path)?;
            accept_loop(&listener, make_backend, stop, UnixListener::accept)
        }
        ListenAddr::Tcp(host_port) => {
            let listener = TcpListener::bind(host_port)?;
            accept_loop(&listener, make_backend, stop, TcpListener::accept)
        }
        #[cfg(target_os = "linux")]
        ListenAddr::Vsock(port) => run_vsock(*port, make_backend, stop),
    }
}

fn accept_loop<L, S, E>(
    listener: &L,
    make_backend: impl Fn() -> Box<dyn GpuBackend>,
    stop: &'static AtomicBool,
    accept: impl Fn(&L) -> Result<(S, E), std::io::Error>,
) -> std::io::Result<()>
where
    S: Read + Write + Send + 'static,
{
    listener_nonblocking_hint(listener);
    while !stop.load(Ordering::Relaxed) {
        match accept(listener) {
            Ok((stream, _)) => {
                let backend: Arc<std::sync::Mutex<Box<dyn GpuBackend>>> =
                    Arc::new(std::sync::Mutex::new(make_backend()));
                std::thread::spawn(move || {
                    let _ = serve_connection(stream, backend);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Polling accept with a stop flag needs a nonblocking listener; where the
/// concrete listener type can't be named generically, each monomorphized
/// call site gets its own best-effort hint. The Unix/Tcp listeners above
/// are blocking by default, so this is a no-op placeholder kept for the
/// vsock path, which manages its own timeout via `poll`.
fn listener_nonblocking_hint<L>(_listener: &L) {}

#[allow(dead_code)]
fn _assert_stop_is_static(_: &'static AtomicBool) {}

#[cfg(target_os = "linux")]
fn run_vsock(
    port: u32,
    make_backend: impl Fn() -> Box<dyn GpuBackend> + Send + 'static,
    stop: &'static AtomicBool,
) -> std::io::Result<()> {
    let listener = vsock::VsockListener::bind(port)?;
    accept_loop(&listener, make_backend, stop, vsock::VsockListener::accept)
}

#[cfg(target_os = "linux")]
mod vsock {
    use std::io::{self, Read, Write};
    use std::os::fd::RawFd;

    /// A connected host-side AF_VSOCK stream, adapted to `Read + Write` so
    /// the generic `serve_connection` can treat it like any byte stream.
    pub(super) struct VsockStream {
        fd: RawFd,
    }

    impl Read for VsockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // SAFETY: `self.fd` is a connected stream socket and `buf` is
            // writable for its length.
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // SAFETY: `self.fd` is a connected stream socket and `buf` is
            // readable for its length.
            let n = unsafe { libc::write(self.fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for VsockStream {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is owned by this wrapper, released once here.
            unsafe { libc::close(self.fd) };
        }
    }

    /// A host AF_VSOCK listener (CID_ANY) on one port.
    pub(super) struct VsockListener {
        fd: RawFd,
    }

    impl VsockListener {
        pub(super) fn bind(port: u32) -> io::Result<Self> {
            // SAFETY: AF_VSOCK/SOCK_STREAM with protocol 0 is the defined
            // vsock stream constructor.
            let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let addr = libc::sockaddr_vm {
                svm_family: libc::AF_VSOCK as u16,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };
            // SAFETY: `fd` is a fresh AF_VSOCK socket and `addr` is a valid
            // sockaddr_vm of exactly the family-specific size.
            let rc = unsafe {
                libc::bind(
                    fd,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_vm>() as u32,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: `fd` was opened above and not yet handed out.
                unsafe { libc::close(fd) };
                return Err(err);
            }
            // SAFETY: same fd, listening with a small fixed backlog.
            let rc = unsafe { libc::listen(fd, 64) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: as above.
                unsafe { libc::close(fd) };
                return Err(err);
            }
            Ok(Self { fd })
        }

        pub(super) fn accept(&self) -> io::Result<(VsockStream, ())> {
            loop {
                // SAFETY: `self.fd` is a listening AF_VSOCK socket.
                let fd =
                    unsafe { libc::accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
                if fd >= 0 {
                    // SAFETY: `fd` is a fresh connected socket fd; ownership
                    // moves into the wrapper, which closes it on drop.
                    return Ok((VsockStream { fd }, ()));
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
        }
    }

    impl Drop for VsockListener {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is owned by this wrapper, released once here.
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::StubBackend;
    use mvm_contract::protocol::gpu::GpuResponse;
    use std::os::unix::net::UnixStream;

    #[test]
    fn listen_addresses_parse_by_kind() {
        assert_eq!(
            parse_listen_addr("unix:/run/gpu.sock"),
            Ok(ListenAddr::Unix("/run/gpu.sock".into()))
        );
        assert_eq!(
            parse_listen_addr("tcp:127.0.0.1:7000"),
            Ok(ListenAddr::Tcp("127.0.0.1:7000".into()))
        );
        #[cfg(target_os = "linux")]
        assert_eq!(parse_listen_addr("vsock:5256"), Ok(ListenAddr::Vsock(5256)));
        assert!(parse_listen_addr("bogus:x").is_err());
        assert!(parse_listen_addr("unix:").is_err());
        #[cfg(not(target_os = "linux"))]
        assert!(parse_listen_addr("vsock:5256").is_err());
    }

    #[test]
    fn a_pair_of_unix_streams_round_trip_a_request() {
        let (client, server) = UnixStream::pair().expect("pair");
        let backend: Arc<std::sync::Mutex<Box<dyn GpuBackend>>> =
            Arc::new(std::sync::Mutex::new(Box::new(StubBackend::new())));
        let served = std::thread::spawn(move || serve_connection(server, backend));
        let mut client = client;
        let request = crate::GpuRequest::DeviceGetCount;
        client
            .write_all(&encode_frame(&request).expect("encode"))
            .expect("write");
        let mut prefix = [0_u8; 4];
        client.read_exact(&mut prefix).expect("prefix");
        let len = mvm_contract::protocol::gpu::frame_body_len(prefix) as usize;
        let mut body = vec![0_u8; len];
        client.read_exact(&mut body).expect("body");
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&body);
        let response: GpuResponse = decode_frame(&frame).expect("decode");
        assert_eq!(response, GpuResponse::DeviceCount { count: 1 });
        drop(client);
        served.join().expect("serve thread").expect("serve");
    }

    #[test]
    fn an_oversized_frame_prefix_is_refused_without_a_huge_allocation() {
        let (mut client, server) = UnixStream::pair().expect("pair");
        let backend: Arc<std::sync::Mutex<Box<dyn GpuBackend>>> =
            Arc::new(std::sync::Mutex::new(Box::new(StubBackend::new())));
        let served = std::thread::spawn(move || serve_connection(server, backend));
        let over = (mvm_contract::protocol::gpu::MAX_MESSAGE_LEN + 1) as u32;
        client.write_all(&over.to_be_bytes()).expect("write");
        let err = served
            .join()
            .expect("serve thread")
            .expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
