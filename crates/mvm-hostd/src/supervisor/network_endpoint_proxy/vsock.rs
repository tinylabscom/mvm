use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const AF_VSOCK: libc::c_int = 40;
/// Bind to any guest CID so any guest on this host can reach the endpoint.
const VMADDR_CID_ANY: u32 = u32::MAX;

// Kernel uapi `struct sockaddr_vm`.
#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
    /// builds; carried so the mirror matches the header field-for-field.
    svm_flags: u8,
    svm_zero: [u8; 3],
}

// Layout contract with linux/vm_sockets.h, derived on Linux 6.8 with cc
// sizeof/offsetof/_Alignof rather than read off the Rust definition.
// Bytes 12..16: the header gained `svm_flags` at offset 12 in Linux 6.0,
// shrinking `svm_zero` to three bytes. The total is 16 either way, which
// is why the pre-6.0 shape went unnoticed here.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<SockaddrVm>() == 16);
    assert!(align_of::<SockaddrVm>() == 4);
    assert!(offset_of!(SockaddrVm, svm_family) == 0);
    assert!(offset_of!(SockaddrVm, svm_reserved1) == 2);
    assert!(offset_of!(SockaddrVm, svm_port) == 4);
    assert!(offset_of!(SockaddrVm, svm_cid) == 8);
    assert!(offset_of!(SockaddrVm, svm_flags) == 12);
    assert!(offset_of!(SockaddrVm, svm_zero) == 13);
};

/// A bound, listening host AF_VSOCK socket on a vsock port.
pub struct VsockListener {
    fd: OwnedFd,
}

impl VsockListener {
    /// Bind + listen on AF_VSOCK `(VMADDR_CID_ANY, port)`.
    pub fn bind(port: u32) -> io::Result<Self> {
        // SAFETY: standard socket/bind/listen on AF_VSOCK; `addr` is fully
        // initialized and sized exactly. The fd is adopted by `OwnedFd`
        // immediately, closing on drop / on the error paths.
        unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owned = OwnedFd::from_raw_fd(fd);
            let addr = SockaddrVm {
                svm_family: AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: VMADDR_CID_ANY,
                svm_flags: 0,
                svm_zero: [0; 3],
            };
            if libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::listen(fd, 128) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd: owned })
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Blocking `accept(2)` on a listening AF_VSOCK fd, returning the
/// connection fd. Run via `spawn_blocking` from the async serve loop.
pub fn accept(listen_fd: RawFd) -> io::Result<RawFd> {
    // SAFETY: accept(2) on a listening AF_VSOCK fd; peer addr not needed.
    let cfd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if cfd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cfd)
}

/// Read one length-prefixed JSON frame (4-byte BE length + body) with
/// blocking I/O. The vsock connection is handled synchronously (tokio's
/// async reactor doesn't interplay reliably with an AF_VSOCK fd).
pub fn read_frame_sync<T: serde::de::DeserializeOwned, R: io::Read>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > super::MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write one length-prefixed JSON frame with blocking I/O.
pub fn write_frame_sync<T: serde::Serialize, W: io::Write>(w: &mut W, value: &T) -> io::Result<()> {
    let body =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}
