//! Guest-side witness probe for the GPU-over-vsock plane (BDD lane).
//!
//! Two modes, selected by argv[1]:
//!
//! - `calls <shim-dir>`: dlopens `<shim-dir>/libcuda.so.1` and
//!   `<shim-dir>/libnvidia-ml.so.1` and issues one CUDA driver call chain
//!   and one NVML call chain through them, printing `CUDA_DRIVER_OK ...`
//!   and `NVML_OK ...` with the answers the host endpoint returned. Exit 0
//!   only if every call succeeded — i.e. the calls were remoted to the
//!   host endpoint and answered.
//! - `dial`: opens `AF_VSOCK` and connects to the host endpoint port. The
//!   GPU channel exists only on launches that armed it, so a boot without
//!   the GPU plane must refuse here; the probe prints `CONNECT_REFUSED`
//!   and exits 3 (other failures exit 4).
//!
//! Built for the guest's own libc (aarch64-linux-gnu for the glibc BDD
//! guest) with `cargo zigbuild --example gpu_guest_probe`.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use libc::{c_char, c_int, c_uint, c_void};

type CuResult = c_int;
type NvmlResult = c_int;

const EXIT_OK: i32 = 0;
const EXIT_CALL_FAILED: i32 = 2;
const EXIT_CONNECT_ERROR: i32 = 4;
const EXIT_USAGE: i32 = 64;

// The wire contract pins the port; the guest dials the host at CID 2.
#[cfg(target_os = "linux")]
const EXIT_CONNECT_REFUSED: i32 = 3;
#[cfg(target_os = "linux")]
const GPU_RPC_PORT: u32 = 5256;
#[cfg(target_os = "linux")]
const VMADDR_CID_HOST: u32 = 2;

#[cfg(target_os = "linux")]
const AF_VSOCK: c_int = libc::AF_VSOCK;

#[cfg(target_os = "linux")]
use libc::{sockaddr, sockaddr_vm, socklen_t};

#[cfg(target_os = "linux")]
fn dial_host_endpoint() -> i32 {
    // SAFETY: socket() with valid constants returns a fd or -1; the result
    // is bounds-checked before any use.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("CONNECT_ERROR errno={} (socket)", errno());
        return EXIT_CONNECT_ERROR;
    }
    // SAFETY: `addr` is a fully initialized sockaddr_vm matching the
    // linux/vm_sockets.h layout (libc's repr(C) mirror); connect reads it
    // for exactly sizeof(sockaddr_vm) bytes per the AF_VSOCK contract.
    let addr = sockaddr_vm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: GPU_RPC_PORT,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const sockaddr_vm as *const sockaddr,
            std::mem::size_of::<sockaddr_vm>() as socklen_t,
        )
    };
    // SAFETY: fd is an owned socket handle in both branches.
    unsafe { libc::close(fd) };
    if rc == 0 {
        println!("CONNECT_OK");
        EXIT_OK
    } else {
        let err = errno();
        // The invariant is "no GPU channel, fail closed", not the exact
        // errno: libkrun and Firecracker refuse with ECONNREFUSED, while
        // HVF's vsock device resets an undeclared guest dial.
        if err == libc::ECONNREFUSED || err == libc::ECONNRESET {
            println!("CONNECT_REFUSED errno={err}");
            EXIT_CONNECT_REFUSED
        } else {
            println!("CONNECT_ERROR errno={err}");
            EXIT_CONNECT_ERROR
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn dial_host_endpoint() -> i32 {
    println!("CONNECT_ERROR errno=0 (AF_VSOCK needs Linux)");
    EXIT_CONNECT_ERROR
}

#[cfg(target_os = "linux")]
fn errno() -> c_int {
    // SAFETY: reading the thread-local errno is always sound.
    unsafe { *libc::__errno_location() }
}

fn dlopen(path: &Path) -> Result<*mut c_void, String> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: c_path is NUL-terminated; RTLD_NOW reports unresolved symbols
    // at load time, which is the failure we want to surface.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        // SAFETY: dlerror returns a static string or null.
        let err = unsafe { libc::dlerror() };
        let msg = if err.is_null() {
            "unknown dlopen failure".to_string()
        } else {
            // SAFETY: err names a NUL-terminated static string.
            unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        };
        Err(format!("{}: {msg}", path.display()))
    } else {
        Ok(handle)
    }
}

/// # Safety
/// `handle` must be a handle returned by `dlopen` and `name` a symbol it
/// exports, per the dlopen/dlsym contract.
unsafe fn dlsym(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    let c_name = CString::new(name).map_err(|e| e.to_string())?;
    // Clear any stale error, then read it back when dlsym returns null.
    // SAFETY: standalone calls per the dlsym contract.
    unsafe { libc::dlerror() };
    let sym = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
    if sym.is_null() {
        let err = unsafe { libc::dlerror() };
        if err.is_null() {
            return Err(format!("{name}: symbol not found"));
        }
        // SAFETY: err names a NUL-terminated static string.
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy();
        Err(format!("{name}: {msg}"))
    } else {
        Ok(sym)
    }
}

/// Resolve one symbol to the function pointer type it will be called
/// through; print and fail the probe on a missing symbol.
macro_rules! resolve {
    ($handle:expr, $name:literal, $sig:ty) => {
        match unsafe { dlsym($handle, $name) } {
            Ok(sym) => unsafe { std::mem::transmute::<*mut c_void, $sig>(sym) },
            Err(e) => {
                println!("DLSYM_FAILED {e}");
                return EXIT_CALL_FAILED;
            }
        }
    };
}

fn calls(shim_dir: &Path) -> i32 {
    let libcuda = match dlopen(&shim_dir.join("libcuda.so.1")) {
        Ok(handle) => handle,
        Err(e) => {
            println!("CUDA_DRIVER_FAILED dlopen {e}");
            return EXIT_CALL_FAILED;
        }
    };
    // The probe drives the ABI through raw pointers so it exercises exactly
    // what a dynamically linked workload would.
    let cu_init: unsafe extern "C" fn(c_uint) -> CuResult =
        resolve!(libcuda, "cuInit", unsafe extern "C" fn(c_uint) -> CuResult);
    let cu_driver_get_version: unsafe extern "C" fn(*mut c_int) -> CuResult = resolve!(
        libcuda,
        "cuDriverGetVersion",
        unsafe extern "C" fn(*mut c_int) -> CuResult
    );
    let cu_device_get: unsafe extern "C" fn(*mut c_int, c_int) -> CuResult = resolve!(
        libcuda,
        "cuDeviceGet",
        unsafe extern "C" fn(*mut c_int, c_int) -> CuResult
    );
    let cu_device_get_name: unsafe extern "C" fn(*mut c_char, c_int, c_int) -> CuResult = resolve!(
        libcuda,
        "cuDeviceGetName",
        unsafe extern "C" fn(*mut c_char, c_int, c_int) -> CuResult
    );

    // SAFETY: each call follows the CUDA Driver API contract — the probe
    // passes the pointer shapes the ABI names.
    let rc = unsafe { cu_init(0) };
    if rc != 0 {
        println!("CUDA_DRIVER_FAILED cuInit rc={rc}");
        return EXIT_CALL_FAILED;
    }
    let mut version = 0;
    let rc = unsafe { cu_driver_get_version(&mut version) };
    if rc != 0 {
        println!("CUDA_DRIVER_FAILED cuDriverGetVersion rc={rc}");
        return EXIT_CALL_FAILED;
    }
    let mut device = 0;
    let rc = unsafe { cu_device_get(&mut device, 0) };
    if rc != 0 {
        println!("CUDA_DRIVER_FAILED cuDeviceGet rc={rc}");
        return EXIT_CALL_FAILED;
    }
    let mut name = [0 as c_char; 128];
    let rc = unsafe { cu_device_get_name(name.as_mut_ptr(), name.len() as c_int, device) };
    if rc != 0 {
        println!("CUDA_DRIVER_FAILED cuDeviceGetName rc={rc}");
        return EXIT_CALL_FAILED;
    }
    // SAFETY: cuDeviceGetName wrote a NUL-terminated string into `name`.
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy();
    println!("CUDA_DRIVER_OK name={name} driver_version={version}");

    let libnvml = match dlopen(&shim_dir.join("libnvidia-ml.so.1")) {
        Ok(handle) => handle,
        Err(e) => {
            println!("NVML_FAILED dlopen {e}");
            return EXIT_CALL_FAILED;
        }
    };
    let nvml_init_v2: unsafe extern "C" fn() -> NvmlResult =
        resolve!(libnvml, "nvmlInit_v2", unsafe extern "C" fn() -> NvmlResult);
    let nvml_device_get_handle_by_index_v2: unsafe extern "C" fn(
        c_uint,
        *mut *mut c_void,
    ) -> NvmlResult = resolve!(
        libnvml,
        "nvmlDeviceGetHandleByIndex_v2",
        unsafe extern "C" fn(c_uint, *mut *mut c_void) -> NvmlResult
    );
    let nvml_device_get_name: unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> NvmlResult = resolve!(
        libnvml,
        "nvmlDeviceGetName",
        unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> NvmlResult
    );

    // SAFETY: NVML v2 init takes no arguments; the handle and name buffers
    // match the NVML ABI the shim exports.
    let rc = unsafe { nvml_init_v2() };
    if rc != 0 {
        println!("NVML_FAILED nvmlInit_v2 rc={rc}");
        return EXIT_CALL_FAILED;
    }
    let mut device: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { nvml_device_get_handle_by_index_v2(0, &mut device) };
    if rc != 0 {
        println!("NVML_FAILED nvmlDeviceGetHandleByIndex_v2 rc={rc}");
        return EXIT_CALL_FAILED;
    }
    let mut name = [0 as c_char; 128];
    let rc = unsafe { nvml_device_get_name(device, name.as_mut_ptr(), name.len() as c_uint) };
    if rc != 0 {
        println!("NVML_FAILED nvmlDeviceGetName rc={rc}");
        return EXIT_CALL_FAILED;
    }
    // SAFETY: nvmlDeviceGetName wrote a NUL-terminated string into `name`.
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy();
    println!("NVML_OK name={name}");

    EXIT_OK
}

fn main() {
    let mut args = std::env::args_os();
    let _bin = args.next();
    let mode = args.next().unwrap_or_default();
    let code = match mode.to_str() {
        Some("calls") => {
            let Some(dir) = args.next() else {
                eprintln!("usage: gpu_guest_probe calls <shim-dir>");
                std::process::exit(EXIT_USAGE);
            };
            calls(&PathBuf::from(dir))
        }
        Some("dial") => dial_host_endpoint(),
        _ => {
            eprintln!("usage: gpu_guest_probe <calls <shim-dir> | dial>");
            EXIT_USAGE
        }
    };
    std::process::exit(code);
}
