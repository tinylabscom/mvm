//! JSON client for a separately installed, trusted libmvm_hostlib.
#![doc = include_str!("../README.md")]

use libloading::Library;
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 7;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("host library was not found")]
    NotFound,
    #[error("explicit host library path is not a file")]
    ExplicitPath,
    #[error("host library loading or symbol resolution failed")]
    Load,
    #[error("host library ABI {version:#x} is incompatible with 1.7")]
    Abi { version: u32 },
    #[error("host library returned an invalid buffer")]
    Buffer,
    #[error("invalid JSON (native status {status})")]
    Json { status: i32 },
    #[error("native host library failure (status {status})")]
    Native { status: i32, details: NativeError },
}

/// Native error fields, without any client-side error or retry policy.
/// Body fields are deliberately excluded from Debug and Display.
pub struct NativeError {
    pub code: Option<String>,
    pub retryable: Option<bool>,
    pub body: Value,
}
impl std::fmt::Debug for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeError { body: [redacted] }")
    }
}

/// An explicit snapshot of discovery inputs; no HOME-based guessing.
#[derive(Clone, Default)]
pub struct DiscoveryOptions {
    pub hostlib_path: Option<PathBuf>,
    pub path: Option<OsString>,
}
impl DiscoveryOptions {
    pub fn from_env() -> Self {
        Self {
            hostlib_path: std::env::var_os("MVM_HOSTLIB_PATH").map(PathBuf::from),
            path: std::env::var_os("PATH"),
        }
    }
    pub fn resolve(&self) -> Result<PathBuf, Error> {
        if let Some(path) = &self.hostlib_path {
            return if path.is_file() {
                path.canonicalize().map_err(|_| Error::ExplicitPath)
            } else {
                Err(Error::ExplicitPath)
            };
        }
        for dir in self
            .path
            .as_ref()
            .into_iter()
            .flat_map(std::env::split_paths)
        {
            let exe = dir.join(if cfg!(windows) {
                "mvmctl.exe"
            } else {
                "mvmctl"
            });
            if !is_executable(&exe) {
                continue;
            }
            for candidate in [Some(exe.clone()), exe.canonicalize().ok()]
                .into_iter()
                .flatten()
            {
                if let Some(parent) = candidate.parent() {
                    let library = parent.join(library_name());
                    if library.is_file() {
                        return library.canonicalize().map_err(|_| Error::NotFound);
                    }
                }
            }
            // Match PATH executable selection: a later mvmctl is not the installed one.
            break;
        }
        Err(Error::NotFound)
    }
}
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
fn library_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libmvm_hostlib.dylib"
    } else if cfg!(windows) {
        "mvm_hostlib.dll"
    } else {
        "libmvm_hostlib.so"
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Buffer {
    data: *mut u8,
    len: usize,
}

// Mirrors the released 64-bit C ABI: uint8_t* followed by size_t.
// Clang's sizeof/_Alignof/offsetof contract is 16/8/0/8.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Buffer>() == 16);
    assert!(align_of::<Buffer>() == 8);
    assert!(offset_of!(Buffer, data) == 0);
    assert!(offset_of!(Buffer, len) == 8);
};
#[cfg(not(target_pointer_width = "64"))]
compile_error!("runmvm-client requires the released 64-bit hostlib ABI");

type Call = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut Buffer) -> i32;
type Free = unsafe extern "C" fn(Buffer);
struct Returned<'a> {
    buffer: Buffer,
    host: &'a Hostlib,
}
impl Drop for Returned<'_> {
    fn drop(&mut self) {
        // SAFETY: the load contract guarantees every returned buffer is freeable once.
        unsafe { (self.host.free)(self.buffer) }
    }
}

/// Owns the native library for the full lifetime of its functions and buffers.
pub struct Hostlib {
    _library: Library,
    call: Call,
    free: Free,
    version: u32,
}
impl Hostlib {
    /// Load an explicitly chosen native library and negotiate ABI 1.7.
    ///
    /// # Safety
    /// The library and its dependencies must be trusted native code conforming
    /// to the libmvm_hostlib ABI, including pointer validity, allocation/free
    /// ownership, thread safety and no unwinding across FFI. Loading executes
    /// native initialization with the host account's privileges. Buffer checks
    /// do not protect against a malicious native library.
    /// Paths are canonicalized before loading to avoid native loader name
    /// searches, but this does not prevent filesystem replacement races.
    pub unsafe fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().canonicalize().map_err(|_| Error::Load)?;
        // SAFETY: caller guarantees trusted native initialization.
        let library = unsafe { Library::new(&path) }.map_err(|_| Error::Load)?;
        // SAFETY: caller guarantees the named symbols have these exact signatures.
        let (version, compatible, call, free) = unsafe {
            let version = *library
                .get::<unsafe extern "C" fn() -> u32>(b"mvm_hostlib_abi_version\0")
                .map_err(|_| Error::Load)?;
            let compatible = *library
                .get::<unsafe extern "C" fn(u16, u16) -> i32>(b"mvm_hostlib_abi_is_compatible\0")
                .map_err(|_| Error::Load)?;
            let call = *library
                .get::<Call>(b"mvm_hostlib_call\0")
                .map_err(|_| Error::Load)?;
            let free = *library
                .get::<Free>(b"mvm_hostlib_free\0")
                .map_err(|_| Error::Load)?;
            (version(), compatible(ABI_MAJOR, ABI_MINOR), call, free)
        };
        if compatible != 1 {
            return Err(Error::Abi { version });
        }
        Ok(Self {
            _library: library,
            call,
            free,
            version,
        })
    }
    /// Discover without executing mvmctl, then load.
    ///
    /// # Safety
    /// The selected path (including PATH entries, symlinks and environment
    /// override) must satisfy all trust and ABI requirements of [`Self::load`].
    pub unsafe fn discover(options: DiscoveryOptions) -> Result<Self, Error> {
        let path = options.resolve()?;
        // SAFETY: caller guarantees the discovered library satisfies load's contract.
        unsafe { Self::load(path) }
    }
    pub fn abi_version(&self) -> u32 {
        self.version
    }
    /// Call with exactly the supplied byte lengths; None is a null/zero request.
    pub fn call_json_bytes(&self, method: &str, request: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let mut buffer = Buffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
        let (ptr, len) = request.map_or((std::ptr::null(), 0), |r| (r.as_ptr(), r.len()));
        // SAFETY: slices are live and out is writable; library meets load's contract.
        let status = unsafe { (self.call)(method.as_ptr(), method.len(), ptr, len, &mut buffer) };
        let returned = Returned { buffer, host: self };
        if (buffer.data.is_null() && buffer.len != 0) || buffer.len > isize::MAX as usize {
            return Err(Error::Buffer);
        }
        let bytes = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: trusted ABI guarantees readable allocation; size checked above.
            unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
        };
        drop(returned);
        check_reply(status, &bytes)?;
        Ok(bytes)
    }
    pub fn call_value(&self, method: &str, request: Option<&Value>) -> Result<Value, Error> {
        let encoded = request
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| Error::Json { status: 0 })?;
        let bytes = self.call_json_bytes(method, encoded.as_deref())?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Json { status: 0 })
    }
}
fn check_reply(status: i32, bytes: &[u8]) -> Result<(), Error> {
    let body: Value = serde_json::from_slice(bytes).map_err(|_| Error::Json { status })?;
    if status == 0 {
        return Ok(());
    }
    Err(Error::Native {
        status,
        details: NativeError {
            code: body.get("code").and_then(Value::as_str).map(str::to_owned),
            retryable: body.get("retryable").and_then(Value::as_bool),
            body,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_older_binding_retains_unknown_recovery_status_as_opaque_failure() {
        assert_eq!((ABI_MAJOR, ABI_MINOR), (1, 7));
        let Err(Error::Native { status, details }) = check_reply(
            12,
            br#"{"code":"RECOVERY_REQUIRED","message":"recover","retryable":false,"details":{"machine_id":"private-machine","plan_id":"private-plan","reason":"private-reason"}}"#,
        ) else {
            panic!("nonzero status must remain an error")
        };
        assert_eq!(status, 12);
        assert_eq!(details.code.as_deref(), Some("RECOVERY_REQUIRED"));
        assert_eq!(details.retryable, Some(false));
        assert_eq!(details.body["details"]["machine_id"], "private-machine");
        assert!(!format!("{details:?}").contains("private-"));
    }

    #[test]
    fn status_and_json_are_not_client_policy() {
        assert!(check_reply(0, b"null").is_ok());
        assert!(matches!(
            check_reply(913, b"oops"),
            Err(Error::Json { status: 913 })
        ));
        let Err(Error::Native { status, details }) = check_reply(
            913,
            br#"{"code":"NEW","retryable":true,"message":"private"}"#,
        ) else {
            panic!()
        };
        assert_eq!(status, 913);
        assert_eq!(details.code.as_deref(), Some("NEW"));
        assert_eq!(details.retryable, Some(true));
        assert!(!format!("{details:?}").contains("private"));
    }
    #[test]
    fn missing_explicit_path_is_terminal() {
        let options = DiscoveryOptions {
            hostlib_path: Some(PathBuf::from("/nonexistent/runmvm-client-library")),
            path: Some(OsString::from("/usr/bin")),
        };
        assert!(matches!(options.resolve(), Err(Error::ExplicitPath)));
        assert!(matches!(
            DiscoveryOptions::default().resolve(),
            Err(Error::NotFound)
        ));
    }
}
