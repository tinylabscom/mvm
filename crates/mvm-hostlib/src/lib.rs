//! The host library: the machine surface the language SDKs call in-process.
//!
//! The SDKs used to build an argv and run `mvmctl` once per call. That made a
//! second entrypoint to every verb, cost a process per call, and could not
//! stream. This library replaces it: the SDK loads `libmvm_hostlib` and calls
//! the same [`MvmClient`](mvm_core::client::MvmClient) the CLI drives.
//!
//! It sits at the top of the dependency graph, beside `mvm-cli`, and nothing
//! depends on it, so linking the local client cannot form a cycle.
//!
//! ## C ABI
//!
//! ```c
//! typedef struct { uint8_t *data; size_t len; } MvmHostlibBuf;
//!
//! // (major << 16) | minor of the ABI this library implements.
//! uint32_t mvm_hostlib_abi_version(void);
//!
//! // 1 when a binding built for (major, minor) can use this library, else 0.
//! // A binding must call this, and get 1, before its first call.
//! int32_t mvm_hostlib_abi_is_compatible(uint16_t major, uint16_t minor);
//!
//! // 0 on success, with `out` holding the method's reply JSON. Otherwise one
//! // of the MVM_HOSTLIB_* statuses, with `out` holding
//! // {"code": "...", "message": "...", "retryable": bool}.
//! int32_t mvm_hostlib_call(const uint8_t *method, size_t method_len,
//!                          const uint8_t *request, size_t request_len,
//!                          MvmHostlibBuf *out);
//!
//! // Release a buffer from mvm_hostlib_call. Safe on a zeroed buffer.
//! void mvm_hostlib_free(MvmHostlibBuf buf);
//! ```
//!
//! Methods are dotted names, listed in [`dispatch::METHODS`]. Each call builds
//! a single-threaded runtime and drops it before returning, so nothing the
//! library started is left running between calls.
//!
//! The version check is enforced, not advisory: a call made before a
//! successful `mvm_hostlib_abi_is_compatible` is refused. A binding and library
//! that disagree about the layout of the buffer they exchange would otherwise
//! read and free memory neither of them described.

// This crate exists to hold `extern "C"` functions, so it is the one place the
// workspace's unsafe_code lint is lifted. Each unsafe block states what it
// relies on.
#![allow(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

pub mod dispatch;
mod embedder;
pub mod status;

use status::{MVM_HOSTLIB_ABI_NOT_NEGOTIATED, MVM_HOSTLIB_EMBEDDER, MVM_HOSTLIB_INTERNAL, Outcome};

/// The ABI major version. A binding built for another major cannot use this
/// library.
pub const MVM_HOSTLIB_ABI_MAJOR: u16 = 1;
/// The ABI minor version. A minor bump only adds methods, so a binding built
/// for an older minor keeps working.
pub const MVM_HOSTLIB_ABI_MINOR: u16 = 0;

/// Set once a binding has confirmed it was built for this ABI.
static NEGOTIATED: AtomicBool = AtomicBool::new(false);

/// An owned byte buffer handed across the ABI. Produced by
/// [`mvm_hostlib_call`], released by [`mvm_hostlib_free`].
#[repr(C)]
pub struct MvmHostlibBuf {
    /// `len` bytes of UTF-8 JSON, or null when `len == 0`.
    pub data: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

// Every binding declares this struct again and reads its fields by offset. A
// reordered, resized or added field is an out-of-bounds read in the host
// language with no diagnostic here, so any change is a major ABI bump that
// lands with the bindings. Pointer-width gated rather than written as
// `2 * size_of::<usize>()`, which would hold for two pointer-sized fields in
// either order and so assert nothing.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<MvmHostlibBuf>() == 16);
    assert!(align_of::<MvmHostlibBuf>() == 8);
    assert!(offset_of!(MvmHostlibBuf, data) == 0);
    assert!(offset_of!(MvmHostlibBuf, len) == 8);
};

impl MvmHostlibBuf {
    /// The empty buffer, which is always safe to free.
    const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

/// Whether a binding built for `major.minor` can use a library implementing
/// `ours_major.ours_minor`: the majors agree and the library is at least as
/// new within it.
fn compatible(major: u16, minor: u16, ours_major: u16, ours_minor: u16) -> bool {
    major == ours_major && minor <= ours_minor
}

/// The ABI this library implements, as `(major << 16) | minor`.
#[unsafe(no_mangle)]
pub extern "C" fn mvm_hostlib_abi_version() -> u32 {
    (u32::from(MVM_HOSTLIB_ABI_MAJOR) << 16) | u32::from(MVM_HOSTLIB_ABI_MINOR)
}

/// Returns 1 when a binding built for `major.minor` can use this library, and
/// 0 otherwise. A 1 enables [`mvm_hostlib_call`] for the rest of the process.
#[unsafe(no_mangle)]
pub extern "C" fn mvm_hostlib_abi_is_compatible(major: u16, minor: u16) -> i32 {
    if compatible(major, minor, MVM_HOSTLIB_ABI_MAJOR, MVM_HOSTLIB_ABI_MINOR) {
        NEGOTIATED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

/// Answer one method, writing the reply or the error body into `out`.
///
/// Never unwinds across the boundary: a panic is reported as
/// `MVM_HOSTLIB_INTERNAL`.
///
/// # Safety
/// `method` and `request` must point to `method_len` and `request_len`
/// readable bytes, or be null when the length is 0. `out` must be a valid,
/// writable `*mut MvmHostlibBuf`; on return the caller owns `*out` and must
/// release it with [`mvm_hostlib_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_call(
    method: *const u8,
    method_len: usize,
    request: *const u8,
    request_len: usize,
    out: *mut MvmHostlibBuf,
) -> i32 {
    if out.is_null() {
        return status::MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: `out` is non-null and the caller guarantees it is writable.
    // Writing the empty buffer first makes `*out` freeable on every path.
    unsafe { *out = MvmHostlibBuf::empty() };
    // SAFETY: the caller guarantees each pointer covers its length.
    let (method, request) = unsafe { (borrow(method, method_len), borrow(request, request_len)) };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        handle(
            NEGOTIATED.load(Ordering::SeqCst),
            method,
            request,
            local_client,
        )
    }))
    .unwrap_or_else(|_| {
        Outcome::failure(
            MVM_HOSTLIB_INTERNAL,
            "INTERNAL",
            "the library panicked",
            false,
        )
    });
    // SAFETY: `out` is non-null and writable, as above.
    unsafe { *out = into_c_buf(outcome.body) };
    outcome.status
}

/// Release a buffer produced by [`mvm_hostlib_call`]. A zeroed buffer is a
/// no-op.
///
/// # Safety
/// `buf` must be a buffer returned by [`mvm_hostlib_call`] that has not been
/// freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_free(buf: MvmHostlibBuf) {
    if buf.data.is_null() {
        return;
    }
    let slice = ptr::slice_from_raw_parts_mut(buf.data, buf.len);
    // SAFETY: a non-null buffer came from `into_c_buf`, which leaked exactly
    // this boxed slice, and the caller guarantees it is freed once.
    drop(unsafe { Box::from_raw(slice) });
}

/// The client every production call is answered by: the local backend, in a
/// process that has been told it is a library embedder.
fn local_client() -> Result<Box<dyn mvm_core::client::MvmClient>, Outcome> {
    embedder::ensure_declared()
        .map_err(|e| Outcome::failure(MVM_HOSTLIB_EMBEDDER, "EMBEDDER", &e.to_string(), false))?;
    Ok(Box::new(mvm_client::LocalBackend::new()))
}

/// Everything [`mvm_hostlib_call`] does once its pointers are slices. The
/// client is built by `client` only after the call is known to be valid, so a
/// refused call touches no backend.
fn handle(
    negotiated: bool,
    method: &[u8],
    request: &[u8],
    client: impl FnOnce() -> Result<Box<dyn mvm_core::client::MvmClient>, Outcome>,
) -> Outcome {
    if !negotiated {
        return Outcome::failure(
            MVM_HOSTLIB_ABI_NOT_NEGOTIATED,
            "ABI_NOT_NEGOTIATED",
            "call mvm_hostlib_abi_is_compatible with the binding's ABI version first",
            false,
        );
    }
    let Ok(method) = std::str::from_utf8(method) else {
        return Outcome::invalid_input("method is not valid UTF-8");
    };
    if !dispatch::is_known(method) {
        return Outcome::invalid_input(&format!("unknown method `{method}`"));
    }
    let client = match client() {
        Ok(client) => client,
        Err(outcome) => return outcome,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return Outcome::failure(
                MVM_HOSTLIB_INTERNAL,
                "INTERNAL",
                &format!("the runtime would not start: {e}"),
                false,
            );
        }
    };
    runtime.block_on(dispatch::dispatch(client.as_ref(), method, request))
}

/// Move `bytes` into a buffer the caller owns until [`mvm_hostlib_free`].
fn into_c_buf(bytes: Vec<u8>) -> MvmHostlibBuf {
    if bytes.is_empty() {
        return MvmHostlibBuf::empty();
    }
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len();
    MvmHostlibBuf {
        data: Box::into_raw(boxed).cast::<u8>(),
        len,
    }
}

/// Borrow `len` bytes at `ptr`, reading a null pointer or zero length as empty.
///
/// # Safety
/// When `len > 0` and `ptr` is non-null, `ptr` must point to `len` readable
/// bytes that outlive the borrow.
unsafe fn borrow<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: guaranteed by the caller, per this function's contract.
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::client::mock::MockBackend;
    use status::{MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_OK};

    fn mock() -> Result<Box<dyn mvm_core::client::MvmClient>, Outcome> {
        Ok(Box::new(MockBackend::default()))
    }

    fn untouched() -> Result<Box<dyn mvm_core::client::MvmClient>, Outcome> {
        panic!("a refused call must not build a client")
    }

    #[test]
    fn the_version_packs_major_over_minor() {
        assert_eq!(
            mvm_hostlib_abi_version(),
            (u32::from(MVM_HOSTLIB_ABI_MAJOR) << 16) | u32::from(MVM_HOSTLIB_ABI_MINOR)
        );
    }

    /// Same major, and a minor no newer than ours.
    #[test]
    fn compatibility_needs_the_same_major_and_no_newer_minor() {
        assert!(compatible(1, 0, 1, 0));
        assert!(compatible(1, 0, 1, 3), "an older minor binding still works");
        assert!(
            !compatible(1, 4, 1, 3),
            "a newer minor may call a missing method"
        );
        assert!(!compatible(2, 0, 1, 3), "a different major");
        assert!(!compatible(0, 9, 1, 3), "a different major");
    }

    #[test]
    fn a_call_before_negotiation_is_refused_without_building_a_client() {
        let outcome = handle(false, b"machine.list", b"", untouched);
        assert_eq!(outcome.status, MVM_HOSTLIB_ABI_NOT_NEGOTIATED);
    }

    #[test]
    fn an_unknown_method_is_refused_without_building_a_client() {
        let outcome = handle(true, b"machine.shell", b"", untouched);
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn a_method_that_is_not_utf8_is_refused() {
        let outcome = handle(true, &[0xff, 0xfe], b"", untouched);
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn a_negotiated_call_is_answered() {
        let outcome = handle(true, b"machine.list", b"", mock);
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(outcome.body, b"[]");
    }

    /// A client that cannot be built reports its own failure.
    #[test]
    fn a_client_failure_is_reported() {
        let outcome = handle(true, b"machine.list", b"", || {
            Err(Outcome::failure(
                MVM_HOSTLIB_EMBEDDER,
                "EMBEDDER",
                "no",
                false,
            ))
        });
        assert_eq!(outcome.status, MVM_HOSTLIB_EMBEDDER);
    }

    /// Through the real entry points: a refusal still leaves a freeable buffer
    /// carrying the error body.
    #[test]
    fn the_entry_point_writes_a_freeable_error_body() {
        let method = b"machine.shell";
        let mut out = MvmHostlibBuf {
            data: ptr::dangling_mut::<u8>(),
            len: 99,
        };
        // SAFETY: the pointers cover their lengths and `out` is writable.
        let status =
            unsafe { mvm_hostlib_call(method.as_ptr(), method.len(), ptr::null(), 0, &mut out) };
        assert!(
            status == MVM_HOSTLIB_ABI_NOT_NEGOTIATED || status == MVM_HOSTLIB_INVALID_INPUT,
            "{status}"
        );
        assert!(!out.data.is_null());
        // SAFETY: `out` came from `mvm_hostlib_call` and is freed once.
        let body = unsafe { slice::from_raw_parts(out.data, out.len) }.to_vec();
        unsafe { mvm_hostlib_free(out) };
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["code"].is_string());
    }

    #[test]
    fn a_null_out_pointer_is_refused() {
        // SAFETY: a null `out` is the case under test and is never written.
        let status = unsafe { mvm_hostlib_call(ptr::null(), 0, ptr::null(), 0, ptr::null_mut()) };
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn freeing_a_zeroed_buffer_is_a_no_op() {
        // SAFETY: the empty buffer is always safe to free.
        unsafe { mvm_hostlib_free(MvmHostlibBuf::empty()) };
    }
}
