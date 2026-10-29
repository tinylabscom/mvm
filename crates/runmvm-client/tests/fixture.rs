// Dependency-free offline cdylib fixture, compiled only by native.rs.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static NEGOTIATED: AtomicBool = AtomicBool::new(false);
static FREES: AtomicUsize = AtomicUsize::new(0);
#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: usize,
}
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Buffer>() == 16);
    assert!(align_of::<Buffer>() == 8);
    assert!(offset_of!(Buffer, data) == 0);
    assert!(offset_of!(Buffer, len) == 8);
};
#[unsafe(no_mangle)]
pub extern "C" fn mvm_hostlib_abi_version() -> u32 {
    if cfg!(bad_abi) {
        2 << 16
    } else {
        (1 << 16) | 7
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn mvm_hostlib_abi_is_compatible(major: u16, minor: u16) -> i32 {
    let ok = !cfg!(bad_abi) && major == 1 && minor <= 7;
    NEGOTIATED.store(ok, Ordering::SeqCst);
    i32::from(ok)
}
#[unsafe(no_mangle)]
pub extern "C" fn fixture_frees() -> usize {
    FREES.load(Ordering::SeqCst)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_call(
    method: *const u8,
    ml: usize,
    request: *const u8,
    rl: usize,
    out: *mut Buffer,
) -> i32 {
    assert!(NEGOTIATED.load(Ordering::SeqCst));
    let method = unsafe { std::slice::from_raw_parts(method, ml) };
    let (status, body) = match method {
        b"error" => (
            913,
            br#"{"code":"FUTURE","retryable":true,"message":"private"}"#.to_vec(),
        ),
        b"parse" => (0, b"invalid".to_vec()),
        b"null" => {
            unsafe {
                *out = Buffer {
                    data: std::ptr::null_mut(),
                    len: 1,
                }
            };
            return 0;
        }
        b"oversize" => {
            unsafe {
                *out = Buffer {
                    data: std::ptr::null_mut(),
                    len: usize::MAX,
                }
            };
            return 0;
        }
        b"none" => {
            assert!(request.is_null());
            assert_eq!(rl, 0);
            (0, b"null".to_vec())
        }
        _ => {
            assert!(!request.is_null());
            (
                0,
                unsafe { std::slice::from_raw_parts(request, rl) }.to_vec(),
            )
        }
    };
    let mut body = body.into_boxed_slice();
    unsafe {
        *out = Buffer {
            data: body.as_mut_ptr(),
            len: body.len(),
        }
    };
    std::mem::forget(body);
    status
}
#[cfg(not(missing_free))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_free(buf: Buffer) {
    FREES.fetch_add(1, Ordering::SeqCst);
    if !buf.data.is_null() {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                buf.data, buf.len,
            )))
        };
    }
}
