//! Shared client core for the guest GPU shim libraries.
//!
//! Each shim (`libcuda.so.1`, `libcudart.so`, `libnvidia-ml.so.1`) is a
//! drop-in replacement that forwards every call to the host GPU endpoint
//! over vsock. This crate holds what all three share:
//!
//! - [`dial`]: transport selection. The default is AF_VSOCK to the host
//!   (CID 2) on [`wire::GPU_RPC_PORT`]; `MVM_GPU_RPC=tcp:HOST:PORT` or
//!   `MVM_GPU_RPC=unix:/path` override it, which is what makes the shims
//!   testable on a machine with no VM and no GPU.
//! - [`call`]: one process-wide framed RPC connection, lazily established
//!   and re-established after failures.
//! - [`guard`]: panic containment at the FFI edge, so a bug in the shim is
//!   an error code in the workload, never a guest crash.
//! - [`ptx_entry_param_sizes`]: the launch-parameter metadata reader. The
//!   CUDA launch APIs hand the shim a `void**` with no count, so the shim
//!   recovers each entry's parameter sizes from the PTX image it already
//!   loaded.

use std::io::{Read, Write};
use std::sync::{Mutex, OnceLock};

pub use mvm_contract::protocol::gpu as wire;
use mvm_contract::protocol::gpu::{GpuError, GpuRequest, GpuResponse, decode_frame, encode_frame};

/// Environment variable overriding the transport the shims dial.
pub const TRANSPORT_ENV: &str = "MVM_GPU_RPC";

/// Host CID the guest reaches the endpoint on, per the vsock convention.
#[cfg(target_os = "linux")]
const HOST_CID: u32 = 2;

fn io_error(what: &str, e: std::io::Error) -> GpuError {
    GpuError::new(
        wire::CUDA_ERROR_UNKNOWN,
        format!("mvm GPU shim: {what}: {e}"),
    )
}

/// A framed RPC connection to the host endpoint.
enum Transport {
    #[cfg(target_os = "linux")]
    Vsock(std::os::unix::net::UnixStream),
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl Transport {
    fn connect(spec: Option<&str>) -> Result<Self, GpuError> {
        match spec {
            None | Some("") | Some("vsock") => Self::connect_vsock(),
            Some(rest) => {
                let (kind, value) = rest.split_once(':').ok_or_else(|| {
                    GpuError::new(
                        wire::CUDA_ERROR_INVALID_VALUE,
                        format!("{TRANSPORT_ENV} must be vsock, tcp:HOST:PORT or unix:/path, got {rest:?}"),
                    )
                })?;
                match kind {
                    "tcp" => std::net::TcpStream::connect(value)
                        .map(Transport::Tcp)
                        .map_err(|e| io_error("connect tcp", e)),
                    "unix" => std::os::unix::net::UnixStream::connect(value)
                        .map(Transport::Unix)
                        .map_err(|e| io_error("connect unix", e)),
                    #[cfg(target_os = "linux")]
                    "vsock" => Self::connect_vsock(),
                    #[cfg(not(target_os = "linux"))]
                    "vsock" => Err(GpuError::new(
                        wire::CUDA_ERROR_NOT_SUPPORTED,
                        "vsock transport is only available on Linux guests",
                    )),
                    other => Err(GpuError::new(
                        wire::CUDA_ERROR_INVALID_VALUE,
                        format!("unknown {TRANSPORT_ENV} kind {other:?}"),
                    )),
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn connect_vsock() -> Result<Self, GpuError> {
        use std::os::fd::{FromRawFd as _, RawFd};

        // SAFETY: AF_VSOCK/SOCK_STREAM with protocol 0 is the defined vsock
        // stream constructor.
        let fd: RawFd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io_error("vsock socket", std::io::Error::last_os_error()));
        }
        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: wire::GPU_RPC_PORT,
            svm_cid: HOST_CID,
            svm_zero: [0; 4],
        };
        // SAFETY: `fd` is a fresh AF_VSOCK socket; `addr` is a valid
        // sockaddr_vm of exactly the family-specific size.
        let rc = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as u32,
            )
        };
        if rc < 0 {
            let err = io_error("vsock connect", std::io::Error::last_os_error());
            // SAFETY: `fd` was opened above and not yet wrapped.
            unsafe { libc::close(fd) };
            return Err(err);
        }
        // SAFETY: `fd` is a connected stream socket; ownership moves into
        // the wrapper, which closes it on drop.
        Ok(Transport::Vsock(unsafe {
            std::os::unix::net::UnixStream::from_raw_fd(fd)
        }))
    }

    #[cfg(not(target_os = "linux"))]
    fn connect_vsock() -> Result<Self, GpuError> {
        Err(GpuError::new(
            wire::CUDA_ERROR_NOT_SUPPORTED,
            "vsock transport is only available on Linux guests",
        ))
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => s.flush(),
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

/// The process-wide connection state: one lazily-dialed transport. A
/// poisoned or dead transport is dropped and re-dialed on the next call.
fn transport() -> &'static Mutex<Option<Transport>> {
    static TRANSPORT: OnceLock<Mutex<Option<Transport>>> = OnceLock::new();
    TRANSPORT.get_or_init(|| Mutex::new(None))
}

/// The transport override, read at dial time. Not cached: a dial happens
/// once per process lifetime in a real guest (the env is fixed there), and
/// re-reading lets a test — or a forked guest whose endpoint moved — point
/// the next connection somewhere new.
fn transport_spec() -> Option<String> {
    std::env::var(TRANSPORT_ENV).ok().filter(|s| !s.is_empty())
}

/// Issue one RPC. Reconnects once after a transport failure, so a restarted
/// endpoint (or a forked guest opening its first connection) recovers
/// without the workload noticing anything but latency.
pub fn call(request: &GpuRequest) -> GpuResponse {
    match try_call(request) {
        Ok(response) => response,
        Err(e) => GpuResponse::Err(e),
    }
}

fn try_call(request: &GpuRequest) -> Result<GpuResponse, GpuError> {
    let mut guard = transport().lock().unwrap_or_else(|e| e.into_inner());

    let attempt = |guard: &mut Option<Transport>| -> Result<GpuResponse, GpuError> {
        let conn = guard
            .as_mut()
            .ok_or_else(|| GpuError::new(wire::CUDA_ERROR_NOT_INITIALIZED, "not connected"))?;
        rpc(conn, request)
    };

    match attempt(&mut guard) {
        Ok(response) => Ok(response),
        Err(first) => {
            // One re-dial, then report: the endpoint may simply not have
            // been up when the shim first connected.
            *guard = None;
            let fresh = Transport::connect(transport_spec().as_deref())?;
            *guard = Some(fresh);
            let conn = guard.as_mut().expect("just connected");
            rpc(conn, request).map_err(|second| {
                GpuError::new(
                    second.code,
                    format!("{}; after one reconnect: {}", second.message, first.message),
                )
            })
        }
    }
}

fn rpc(conn: &mut Transport, request: &GpuRequest) -> Result<GpuResponse, GpuError> {
    let frame = encode_frame(request)
        .map_err(|e| GpuError::new(wire::CUDA_ERROR_UNKNOWN, e.to_string()))?;
    conn.write_all(&frame).map_err(|e| io_error("write", e))?;
    conn.flush().map_err(|e| io_error("flush", e))?;
    let mut prefix = [0_u8; 4];
    conn.read_exact(&mut prefix)
        .map_err(|e| io_error("read prefix", e))?;
    let body_len = wire::frame_body_len(prefix);
    if body_len > wire::MAX_MESSAGE_LEN {
        return Err(GpuError::new(
            wire::CUDA_ERROR_UNKNOWN,
            format!("endpoint frame of {body_len} bytes exceeds the wire cap"),
        ));
    }
    let mut body = vec![0_u8; body_len as usize];
    conn.read_exact(&mut body)
        .map_err(|e| io_error("read body", e))?;
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&body);
    decode_frame(&frame).map_err(|e| GpuError::new(wire::CUDA_ERROR_UNKNOWN, e.to_string()))
}

/// Run `f` with panic containment, mapping any panic to `panic_code`.
///
/// Every exported shim entry point passes through this: the shim lives in
/// an untrusted workload's address space, and a shim bug must surface as a
/// CUDA error, never as a guest crash. The `AssertUnwindSafe` is the point
/// of the wrapper — the closure carries raw workload pointers that are
/// `!UnwindSafe` by construction, and this function exists precisely to
/// keep whatever happens inside them from unwinding across the FFI edge.
pub fn guard<F, R>(f: F, panic_code: R) -> R
where
    F: FnOnce() -> R,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => panic_code,
    }
}

/// Copy `text` into a C out-buffer of `buf_len` bytes, NUL-terminated.
/// Returns false (without touching the buffer) when it does not fit —
/// callers turn that into their API's insufficient-size error.
///
/// # Safety
/// `buf` must be valid for `buf_len` writable bytes — the caller only
/// passes out-buffers the workload itself named to the API call.
#[must_use]
pub unsafe fn write_cstr(buf: *mut libc::c_char, buf_len: usize, text: &str) -> bool {
    if buf.is_null() || text.len() + 1 > buf_len {
        return false;
    }
    // SAFETY: `buf` is valid for `buf_len >= text.len() + 1` bytes (checked
    // above); the copy is bounded and NUL-terminated within that.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), buf.cast::<u8>(), text.len());
        *buf.add(text.len()) = 0;
    }
    true
}

/// Render a driver error code as text, for the shim's error-string tables.
#[must_use]
pub fn cuda_error_text(code: i32) -> &'static str {
    match code {
        wire::SUCCESS => "no error",
        wire::CUDA_ERROR_INVALID_VALUE => "invalid argument",
        wire::CUDA_ERROR_OUT_OF_MEMORY => "out of memory",
        wire::CUDA_ERROR_NOT_INITIALIZED => "CUDA driver not initialized",
        wire::CUDA_ERROR_NO_DEVICE => "no CUDA-capable device is available",
        wire::CUDA_ERROR_INVALID_DEVICE => "invalid device ordinal",
        wire::CUDA_ERROR_INVALID_CONTEXT => "invalid context",
        wire::CUDA_ERROR_INVALID_HANDLE => "invalid handle",
        wire::CUDA_ERROR_NOT_FOUND => "named symbol not found",
        wire::CUDA_ERROR_NOT_SUPPORTED => "operation not supported",
        _ => "unknown error",
    }
}

/// Recover a PTX entry point's parameter sizes from the image text.
///
/// The CUDA launch APIs hand the shim a `void** kernelParams` with no
/// count, so the only place the count and sizes live is the module image
/// itself. For PTX, an entry body lists its parameters as `.param`
/// directives; nvcc emits one per scalar, and vector parameters as one
/// `.param .vN` directive. Returns `None` when the image is not PTX or the
/// entry is absent — callers then refuse the launch rather than guess.
#[must_use]
pub fn ptx_entry_param_sizes(image: &[u8], entry: &str) -> Option<Vec<usize>> {
    let text = core::str::from_utf8(image).ok()?;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        // `.entry NAME(` — parameters follow until the matching `)`. The
        // directive may carry a visibility qualifier (`.visible .entry`),
        // so it is located rather than prefix-matched.
        let Some(idx) = trimmed.find(".entry") else {
            continue;
        };
        let rest = trimmed[idx + ".entry".len()..].trim_start();
        let name = rest.split(['(', ' ', '\t']).next().unwrap_or("");
        if name != entry {
            continue;
        }
        let mut sizes = Vec::new();
        // The parameter list ends at the first line whose trimmed form is
        // exactly `)` (nvcc layout), or a `)` at the end of the header line.
        let header_has_close = rest.contains(')');
        for param_line in lines.by_ref() {
            let p = param_line.trim();
            if p.starts_with(')') {
                return Some(sizes);
            }
            if let Some(directive) = p.strip_prefix(".param") {
                sizes.push(ptx_param_size(directive.trim_start()));
            } else if header_has_close && p.is_empty() {
                // `.entry foo()` with no params: the header line already closed.
                return Some(sizes);
            }
        }
        return Some(sizes);
    }
    None
}

/// Size in bytes of one `.param` directive's type (best-effort for common
/// nvcc output; unknown types conservatively size as a pointer).
fn ptx_param_size(directive: &str) -> usize {
    let mut size = 4_usize;
    let mut vector = 1_usize;
    for token in directive.split_whitespace() {
        match token {
            ".u64" | ".s64" | ".f64" | ".b64" | ".pred" if size < 8 => size = 8,
            ".u32" | ".s32" | ".f32" | ".b32" => size = size.max(4),
            ".v2" => vector = vector.max(2),
            ".v4" => vector = vector.max(4),
            _ => {}
        }
    }
    size * vector
}

#[cfg(test)]
mod tests {
    use super::*;

    const PTX: &str = r#"
.version 8.3
.target sm_75
.address_size 64

.visible .entry vector_add(
    .param .u64 param_0,
    .param .u64 param_1,
    .param .u64 param_2,
    .param .u32 param_3
)
{
    ret;
}
"#;

    #[test]
    fn ptx_param_sizes_are_recovered_for_an_entry() {
        assert_eq!(
            ptx_entry_param_sizes(PTX.as_bytes(), "vector_add"),
            Some(vec![8, 8, 8, 4])
        );
    }

    #[test]
    fn a_missing_entry_is_none_not_a_guess() {
        assert_eq!(ptx_entry_param_sizes(PTX.as_bytes(), "nope"), None);
        assert_eq!(ptx_entry_param_sizes(b"\x7fELF....", "vector_add"), None);
    }

    #[test]
    fn cstr_writes_are_bounded_and_nul_terminated() {
        let mut buf: [libc::c_char; 8] = [0; 8];
        assert!(unsafe { write_cstr(buf.as_mut_ptr(), buf.len(), "hello") });
        let as_u8: Vec<u8> = buf.iter().map(|&b| b as u8).collect();
        assert_eq!(&as_u8[..6], b"hello\0");
        assert!(!unsafe { write_cstr(buf.as_mut_ptr(), buf.len(), "this is too long") });
    }

    #[test]
    fn the_error_table_names_the_codes_workloads_see() {
        assert_eq!(cuda_error_text(wire::SUCCESS), "no error");
        assert_eq!(
            cuda_error_text(wire::CUDA_ERROR_NO_DEVICE),
            "no CUDA-capable device is available"
        );
        assert_eq!(cuda_error_text(-1), "unknown error");
    }
}
