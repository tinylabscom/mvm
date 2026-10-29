//! Caller-owned serial invocation lifetime. No process-global owner table.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, TryLockError};

use mvm_client::entrypoint::CapturedOutput;
use mvm_client::entrypoint::call::OwnedTransientResult;
use mvm_core::client::MvmError;

use crate::status::{
    MVM_HOSTLIB_ABI_NOT_NEGOTIATED, MVM_HOSTLIB_INTERNAL, MVM_HOSTLIB_INVALID_INPUT, Outcome,
};
use crate::{MvmHostlibBuf, borrow, into_c_buf};

/// Opaque C allocation. Never serialize its address or treat it as admission.
/// The C caller must keep the library loaded for this allocation's lifetime.
/// Only pointers cross the ABI; the incomplete C type has no exposed layout.
pub type MvmHostlibContext = std::ffi::c_void;

struct ContextOwner {
    state: Mutex<ContextState>,
}

#[derive(PartialEq)]
enum Phase {
    Empty,
    Occupied,
    Closed,
}

enum SessionLifetime {
    Empty,
    Starting,
    Active(mvm_core::session::SessionId),
    UnknownStart,
    Finished,
}

impl SessionLifetime {
    fn unresolved(&self) -> bool {
        matches!(self, Self::Starting | Self::Active(_) | Self::UnknownStart)
    }
}

#[derive(serde::Deserialize)]
struct SessionBinding {
    session_id: String,
}

impl SessionBinding {
    fn parse(bytes: &[u8]) -> anyhow::Result<mvm_core::session::SessionId> {
        // A derived struct rejects duplicate fields rather than collapsing
        // competing identities through an intermediate JSON Value.
        let binding: Self = serde_json::from_slice(bytes)?;
        mvm_core::session::SessionId::parse(&binding.session_id)
    }
}

struct ContextState {
    phase: Phase,
    operation: Option<OwnedTransientResult<CapturedOutput>>,
    last: Option<Outcome>,
    session: SessionLifetime,
    session_response: Option<Outcome>,
    session_error: Option<anyhow::Error>,
    panic_payload: Option<Box<dyn Any + Send>>,
}

impl ContextState {
    fn new() -> Self {
        Self {
            phase: Phase::Empty,
            operation: None,
            last: None,
            session: SessionLifetime::Empty,
            session_response: None,
            session_error: None,
            panic_payload: None,
        }
    }

    fn call(&mut self, method: &[u8], request: &[u8]) -> Outcome {
        if method == crate::entrypoint::SESSION_START.as_bytes() {
            return self.call_start_using(request, crate::entrypoint::start_owned);
        }
        self.call_using(method, request, |method, request| {
            crate::handle(true, method, request, &crate::Local)
        })
    }

    fn call_start_using(
        &mut self,
        request: &[u8],
        start: impl FnOnce(&[u8]) -> crate::entrypoint::OwnedStartAttempt,
    ) -> Outcome {
        let mut known_error = None;
        let outcome = self.call_using(
            crate::entrypoint::SESSION_START.as_bytes(),
            request,
            |_, request| match start(request) {
                crate::entrypoint::OwnedStartAttempt::KnownNotDispatched { outcome, error } => {
                    known_error = Some(error);
                    outcome
                }
                crate::entrypoint::OwnedStartAttempt::MayHaveDispatched(outcome) => outcome,
            },
        );
        if let Some(error) = known_error {
            self.session = SessionLifetime::Finished;
            self.session_error = Some(error);
        }
        outcome
    }

    fn call_using(
        &mut self,
        method: &[u8],
        request: &[u8],
        dispatch: impl FnOnce(&[u8], &[u8]) -> Outcome,
    ) -> Outcome {
        if self.phase == Phase::Closed || self.operation.is_some() {
            return conflict("context is closed or its one invocation is already retained");
        }
        if matches!(
            self.session,
            SessionLifetime::Starting | SessionLifetime::UnknownStart
        ) {
            return conflict("original session start is unconfirmed; retain this context");
        }
        let Ok(method_name) = std::str::from_utf8(method) else {
            return Outcome::invalid_input("method is not valid UTF-8");
        };
        if method_name == crate::entrypoint::SESSION_START {
            if !matches!(self.session, SessionLifetime::Empty) {
                return conflict("this context already attempted its one session start");
            }
            // Arm BEFORE dispatch, including FFI, callbacks, encoding and
            // unwinding. A failed return cannot assert that nothing launched.
            self.session = SessionLifetime::Starting;
        } else if matches!(
            method_name,
            crate::entrypoint::SESSION_STOP | crate::entrypoint::SESSION_CALL
        ) {
            let SessionLifetime::Active(original) = &self.session else {
                return conflict("context has no validated original session binding");
            };
            let Ok(requested) = SessionBinding::parse(request) else {
                return Outcome::invalid_input("session request has no unique valid binding");
            };
            if &requested != original {
                return conflict("session request differs from this context's original binding");
            }
        }
        self.phase = Phase::Occupied;
        let outcome = if method_name == crate::entrypoint::ENTRYPOINT_CALL {
            if !matches!(self.session, SessionLifetime::Empty) {
                return conflict("context already attempted its session lifetime");
            }
            // Store output and the full error aggregate BEFORE embedder
            // setup, request parsing, resolution, callbacks or boot.
            self.operation = Some(OwnedTransientResult::prepare(CapturedOutput::default()));
            let operation = self.operation.as_mut().expect("stored invocation");
            match crate::declared() {
                Ok(()) => crate::entrypoint::run_owned(request, operation),
                Err(outcome) => {
                    operation.fail_preparation(
                        ContextPreparationError {
                            _status: outcome.status,
                            _body: outcome.body.clone(),
                        }
                        .into(),
                    );
                    outcome
                }
            }
        } else {
            // Compatibility methods keep their existing schemas and policy.
            // LocalEntrypoint refuses native unowned/session/prompt paths
            // before effects; metadata does not reconstruct a native owner.
            dispatch(method, request)
        };
        if method_name == crate::entrypoint::SESSION_START {
            // Keep the exact response even if validating or rendering its
            // public projection fails. Unknown raw replies remain private.
            self.session_response = Some(copy_outcome(&outcome));
            if outcome.status != crate::status::MVM_HOSTLIB_OK {
                self.session = SessionLifetime::UnknownStart;
                self.session_error = Some(
                    ContextPreparationError {
                        _status: outcome.status,
                        _body: outcome.body.clone(),
                    }
                    .into(),
                );
            } else {
                match SessionBinding::parse(&outcome.body) {
                    Ok(id) => self.session = SessionLifetime::Active(id),
                    Err(error) => {
                        self.session_error = Some(error);
                        self.session = SessionLifetime::UnknownStart;
                        let refused = conflict(
                            "session start returned no unique valid binding; original response retained",
                        );
                        self.last = Some(copy_outcome(&refused));
                        return refused;
                    }
                }
            }
        }
        if outcome.status == crate::status::MVM_HOSTLIB_OK
            && method_name == crate::entrypoint::SESSION_STOP
        {
            self.session = SessionLifetime::Finished;
        }
        self.last = Some(copy_outcome(&outcome));
        outcome
    }

    fn inspect(&self, part: u32) -> Outcome {
        match part {
            0 => {
                if matches!(
                    self.session,
                    SessionLifetime::Starting | SessionLifetime::UnknownStart
                ) {
                    return conflict(
                        "session start is unconfirmed; original response remains private",
                    );
                }
                if let Some(operation) = &self.operation {
                    if operation.projection().is_ok() {
                        return crate::entrypoint::owned_projection(operation);
                    }
                    // Only an error response may be copied without output
                    // completion. Never return a cached successful body.
                    if let Some(last) = &self.last
                        && last.status != crate::status::MVM_HOSTLIB_OK
                    {
                        return copy_outcome(last);
                    }
                    return crate::entrypoint::owned_projection(operation);
                }
                self.last
                    .as_ref()
                    .map(copy_outcome)
                    .unwrap_or_else(|| conflict("context has no result"))
            }
            1..=4 => {
                let error = self.operation.as_ref().and_then(|operation| match part {
                    1 => operation.call_error(),
                    2 => operation.flush_error(),
                    3 => operation.stop_error(),
                    4 => operation.cleanup_error(),
                    _ => unreachable!("selector range checked"),
                });
                if error.is_some()
                    || (part == 1 && self.session_error.is_some())
                    || (part == 4 && self.panic_payload.is_some())
                {
                    return Outcome::from(MvmError::Backend {
                        reason: "original owned error remains retained in this context".into(),
                    });
                }
                if part == 1
                    && let Some(last) = &self.last
                    && last.status != crate::status::MVM_HOSTLIB_OK
                {
                    return copy_outcome(last);
                }
                // Error absence is NOT successful result/terminal evidence.
                empty()
            }
            _ => Outcome::invalid_input("context inspect selector must be in 0..=4"),
        }
    }

    fn retry_stop(&mut self) -> Outcome {
        if self.session.unresolved() {
            return conflict("ordinary session must use its existing explicit stop operation");
        }
        if let Some(operation) = self.operation.as_mut()
            && operation.retry_stop().is_err()
        {
            return crate::entrypoint::owned_projection(operation);
        }
        empty()
    }

    fn close(&mut self) -> Outcome {
        if self.session.unresolved() {
            return conflict("session stop is unconfirmed; retain this context");
        }
        if let Some(operation) = self.operation.as_mut()
            && operation.close().is_err()
        {
            return crate::entrypoint::owned_projection(operation);
        }
        self.phase = Phase::Closed;
        empty()
    }
}

#[derive(Debug)]
struct ContextPreparationError {
    _status: i32,
    _body: Vec<u8>,
}
impl std::fmt::Display for ContextPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned context preparation failed")
    }
}
impl std::error::Error for ContextPreparationError {}

fn empty() -> Outcome {
    Outcome {
        status: crate::status::MVM_HOSTLIB_OK,
        body: Vec::new(),
    }
}
fn conflict(reason: &str) -> Outcome {
    Outcome::from(MvmError::Conflict {
        reason: reason.into(),
    })
}
fn copy_outcome(outcome: &Outcome) -> Outcome {
    Outcome {
        status: outcome.status,
        body: outcome.body.clone(),
    }
}

// SAFETY: each public caller documents pointer validity and exclusive free.
unsafe fn access(
    context: *mut MvmHostlibContext,
    out: *mut MvmHostlibBuf,
    action: impl FnOnce(&mut ContextState) -> Outcome,
) -> i32 {
    if out.is_null() {
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: out is writable by the caller's contract.
    unsafe { *out = MvmHostlibBuf::empty() };
    if context.is_null() {
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: context is a live allocation and cannot be freed concurrently.
    let context = unsafe { &*context.cast::<ContextOwner>() };
    let mut state = match context.state.try_lock() {
        Ok(state) => state,
        Err(TryLockError::Poisoned(error)) => error.into_inner(),
        Err(TryLockError::WouldBlock) => {
            let outcome = conflict("context is busy or reentered");
            // SAFETY: out is writable and receives a fresh owned buffer.
            unsafe { *out = into_c_buf(outcome.body) };
            return outcome.status;
        }
    };
    // Catch with the guard OUTSIDE the closure. A callback panic cannot
    // drop the stored operation, its output, errors, admission or native owner.
    let outcome = match catch_unwind(AssertUnwindSafe(|| action(&mut state))) {
        Ok(outcome) => outcome,
        Err(payload) => {
            state.panic_payload = Some(payload);
            if matches!(state.session, SessionLifetime::Starting) {
                state.session = SessionLifetime::UnknownStart;
            }
            state.phase = Phase::Occupied;
            Outcome::failure(
                MVM_HOSTLIB_INTERNAL,
                mvm_core::error_codes::INTERNAL,
                "owned context operation panicked; original state remains retained",
                false,
            )
        }
    };
    // SAFETY: out is writable; only copied/rendered bytes cross this boundary.
    unsafe { *out = into_c_buf(outcome.body) };
    outcome.status
}

/// Allocate an empty context using independent per-context ABI negotiation.
///
/// # Safety
/// `slot` must point to an empty writable context slot, and `out` to writable
/// buffer storage. Keep the library loaded until checked_free succeeds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_create(
    major: u16,
    minor: u16,
    slot: *mut *mut MvmHostlibContext,
    out: *mut MvmHostlibBuf,
) -> i32 {
    if out.is_null() {
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: caller supplies writable buffer storage.
    unsafe {
        *out = MvmHostlibBuf::empty();
    }
    if slot.is_null() {
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: caller supplies an empty writable context slot.
    unsafe {
        *slot = std::ptr::null_mut();
    }
    if major != crate::MVM_HOSTLIB_ABI_MAJOR || !(9..=crate::MVM_HOSTLIB_ABI_MINOR).contains(&minor)
    {
        return MVM_HOSTLIB_ABI_NOT_NEGOTIATED;
    }
    let context = Box::new(ContextOwner {
        state: Mutex::new(ContextState::new()),
    });
    // SAFETY: caller owns the allocation until checked_free consumes it.
    unsafe { *slot = Box::into_raw(context).cast::<MvmHostlibContext>() };
    crate::status::MVM_HOSTLIB_OK
}

/// Call through this exact serial context.
///
/// # Safety
/// Context must be live; input pointers cover their lengths; out is writable.
/// No thread may free the context while any call can access it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_call(
    context: *mut MvmHostlibContext,
    method: *const u8,
    method_len: usize,
    request: *const u8,
    request_len: usize,
    out: *mut MvmHostlibBuf,
) -> i32 {
    if (method.is_null() && method_len != 0) || (request.is_null() && request_len != 0) {
        if !out.is_null() {
            // SAFETY: the caller guarantees writable output storage.
            unsafe { *out = MvmHostlibBuf::empty() };
        }
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: lengths/pointers obey the public contract.
    let (method, request) = unsafe { (borrow(method, method_len), borrow(request, request_len)) };
    // SAFETY: caller retains this context and writable output.
    unsafe { access(context, out, |state| state.call(method, request)) }
}

/// Inspect copied data: 0=result, 1=primary, 2=flush, 3=stop, 4=cleanup.
/// Empty error output means absent, never successful completion.
///
/// # Safety
/// Context is live and not concurrently freed; out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_inspect(
    context: *mut MvmHostlibContext,
    part: u32,
    out: *mut MvmHostlibBuf,
) -> i32 {
    // SAFETY: same allocation/output contract as context_call.
    unsafe { access(context, out, |state| state.inspect(part)) }
}

/// Retry only the held original owner's stop/remaining cleanup, not work.
///
/// # Safety
/// Context is live and not concurrently freed; out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_retry_stop(
    context: *mut MvmHostlibContext,
    out: *mut MvmHostlibBuf,
) -> i32 {
    // SAFETY: caller preserves the allocation and output.
    unsafe { access(context, out, ContextState::retry_stop) }
}

/// Explicit cleanup. Failure retains every original object and the pointer.
///
/// # Safety
/// Context is live and not concurrently freed; out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_close(
    context: *mut MvmHostlibContext,
    out: *mut MvmHostlibBuf,
) -> i32 {
    // SAFETY: caller preserves the allocation and output.
    unsafe { access(context, out, ContextState::close) }
}

/// Nonblocking destruction, only Empty/Closed. Never stops implicitly.
///
/// # Safety
/// Slot points to this allocation or null. Caller must exclude ALL concurrent
/// access, including threads that could begin a call after this check.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hostlib_context_checked_free(
    slot: *mut *mut MvmHostlibContext,
) -> i32 {
    if slot.is_null() {
        return MVM_HOSTLIB_INVALID_INPUT;
    }
    // SAFETY: caller owns this writable pointer slot.
    let pointer = unsafe { *slot };
    if pointer.is_null() {
        return crate::status::MVM_HOSTLIB_OK;
    }
    {
        // SAFETY: pointer is live and exclusively protected from free/access.
        let context = unsafe { &*pointer.cast::<ContextOwner>() };
        let state = match context.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => return crate::status::MVM_HOSTLIB_CONFLICT,
        };
        if !matches!(state.phase, Phase::Empty | Phase::Closed) {
            return crate::status::MVM_HOSTLIB_CONFLICT;
        }
    }
    // SAFETY: checked state is quiescent; exclusive caller contract prevents a
    // new access racing guard release. This consumes exactly this Box once.
    unsafe {
        drop(Box::from_raw(pointer.cast::<ContextOwner>()));
        *slot = std::ptr::null_mut();
    }
    crate::status::MVM_HOSTLIB_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn create() -> *mut MvmHostlibContext {
        let mut pointer = std::ptr::null_mut();
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: fresh writable slots, no concurrent access.
        assert_eq!(
            unsafe { mvm_hostlib_context_create(1, 9, &mut pointer, &mut out) },
            0
        );
        assert!(!pointer.is_null());
        // SAFETY: buffer came from this ABI, freed once.
        unsafe { crate::mvm_hostlib_free(out) };
        pointer
    }

    fn discard(out: MvmHostlibBuf) {
        // SAFETY: tests pass each ABI buffer here exactly once.
        unsafe { crate::mvm_hostlib_free(out) };
    }

    #[test]
    fn context_negotiates_independently_and_checked_free_never_stops() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(
            crate::handle(false, b"unknown.method", b"{}", &crate::Local).status,
            9
        );
        // SAFETY: live context and valid fixed input/output storage.
        assert_eq!(
            unsafe {
                mvm_hostlib_context_call(
                    pointer,
                    b"unknown.method".as_ptr(),
                    14,
                    b"{}".as_ptr(),
                    2,
                    &mut out,
                )
            },
            8
        );
        discard(out);
        let original = pointer;
        // SAFETY: exclusive caller; no call is active.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
        assert_eq!(pointer, original);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: live context, fresh output. Invalid selector has no effects.
        assert_eq!(
            unsafe { mvm_hostlib_context_inspect(pointer, 99, &mut out) },
            8
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: same live context and fresh output.
        assert_eq!(
            unsafe { mvm_hostlib_context_inspect(pointer, 2, &mut out) },
            0
        );
        assert_eq!(out.len, 0);
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: explicit close; no VM/child was created by unknown method.
        assert_eq!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        // SAFETY: exclusively owned Closed allocation.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        assert!(pointer.is_null());
    }

    #[derive(Debug)]
    struct RetainedError(Arc<AtomicUsize>);
    impl std::fmt::Display for RetainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("local fixture error")
        }
    }
    impl std::error::Error for RetainedError {}
    impl Drop for RetainedError {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn actual_context_retains_prepared_output_and_error_across_callback_panic() {
        let mut pointer = create();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: valid allocation/output; injected callback has no native effects.
        let status = unsafe {
            access(pointer, &mut out, |state| {
                let mut output = CapturedOutput::default();
                output
                    .stdout
                    .extend_from_slice(b"fixture-output-not-released");
                state.operation = Some(OwnedTransientResult::prepare(output));
                state
                    .operation
                    .as_mut()
                    .unwrap()
                    .fail_preparation(RetainedError(Arc::clone(&drops)).into());
                panic!("local callback failure");
            })
        };
        assert_eq!(status, MVM_HOSTLIB_INTERNAL);
        discard(out);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: live retained context and fresh buffer.
        assert_eq!(
            unsafe { mvm_hostlib_context_inspect(pointer, 0, &mut out) },
            3
        );
        // SAFETY: ABI owns these readable bytes until discard.
        let body = unsafe { std::slice::from_raw_parts(out.data, out.len) };
        assert!(!String::from_utf8_lossy(body).contains("fixture-output-not-released"));
        discard(out);
        // SAFETY: exclusive nonblocking free must refuse Occupied state.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: real child-free cleanup, not a fabricated native proof.
        assert_eq!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // SAFETY: Closed exclusively owned allocation.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn encoding_failure_keeps_the_actual_context_operation_until_explicit_close() {
        struct RefusesEncoding;
        impl serde::Serialize for RefusesEncoding {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("local encoding fixture"))
            }
        }
        let mut pointer = create();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: exclusively held valid allocation and writable buffer.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.phase = Phase::Occupied;
                    state.operation =
                        Some(OwnedTransientResult::prepare(CapturedOutput::default()));
                    state
                        .operation
                        .as_mut()
                        .unwrap()
                        .fail_preparation(RetainedError(Arc::clone(&drops)).into());
                    Outcome::ok(&RefusesEncoding)
                })
            },
            MVM_HOSTLIB_INTERNAL
        );
        discard(out);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // SAFETY: exclusive caller; Occupied still refuses free.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: only original child-free operation is closed.
        assert_eq!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        // SAFETY: Closed and no concurrent accesses.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reentrant_context_access_refuses_without_deadlock_or_effects() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: stable allocation, nested operation does not free it.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |_| {
                    let mut nested = MvmHostlibBuf::empty();
                    assert_eq!(mvm_hostlib_context_inspect(pointer, 0, &mut nested), 5);
                    discard(nested);
                    empty()
                })
            },
            0
        );
        discard(out);
        // SAFETY: no operation started; Empty state remains unchanged.
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
    }

    #[test]
    fn one_context_refuses_second_start_and_foreign_stop_before_dispatch() {
        let mut pointer = create();
        let first = b"abcdefghijklmnopqrstuvwx";
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: original live allocation; adapter emits only ordinary
        // metadata, creates no VM/Child and supplies no native proof.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_using(b"session.start", b"{}", |_, _| {
                        Outcome::ok(
                            &serde_json::json!({"session_id": std::str::from_utf8(first).unwrap()}),
                        )
                    })
                })
            },
            0
        );
        discard(out);
        for (method, request) in [
            (b"session.start".as_slice(), b"{}".as_slice()),
            (b"session.stop".as_slice(), br#"{"session_id":"zyxwvutsrqponmlkjihgfedc"}"#.as_slice()),
            (b"session.stop".as_slice(), br#"{"session_id":"abcdefghijklmnopqrstuvwx","session_id":"abcdefghijklmnopqrstuvwx"}"#.as_slice()),
        ] {
            let mut out = MvmHostlibBuf::empty();
            // SAFETY: unchanged original allocation. Refusal must precede
            // the dispatch seam, not merely ignore its successful response.
            assert_ne!(unsafe {
                access(pointer, &mut out, |state| state.call_using(method, request, |_, _| {
                    panic!("foreign or repeated operation reached dispatch")
                }))
            }, 0);
            discard(out);
        }
        let original = pointer;
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: no concurrent access; active original binding forbids close/free.
        assert_ne!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
        assert_eq!(pointer, original);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: only the held exact id reaches this no-child operation adapter.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_using(
                        b"session.stop",
                        br#"{"session_id":"abcdefghijklmnopqrstuvwx"}"#,
                        |_, _| empty(),
                    )
                })
            },
            0
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_ne!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_using(b"session.start", b"{}", |_, _| {
                        panic!("finished context restarted")
                    })
                })
            },
            0
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
    }

    #[test]
    fn actual_local_start_validation_retains_response_but_can_close_and_free() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: real C consumer with owned output; invalid JSON cannot boot.
        let status = unsafe {
            mvm_hostlib_context_call(
                pointer,
                b"session.start".as_ptr(),
                13,
                b"{".as_ptr(),
                1,
                &mut out,
            )
        };
        assert_ne!(status, 0);
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: same allocation, exclusive access.
        assert_eq!(
            unsafe { mvm_hostlib_context_inspect(pointer, 0, &mut out) },
            status
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    assert!(matches!(state.session, SessionLifetime::Finished));
                    assert!(state.session_error.is_some());
                    assert_eq!(state.session_response.as_ref().unwrap().status, status);
                    empty()
                })
            },
            0
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        assert!(pointer.is_null());
    }

    #[test]
    fn owned_start_unwind_keeps_unknown_custody_and_original_payload() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: no-child callback panic passes through the real ABI catcher.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_start_using(b"{}", |_| panic!("original start unwind"))
                })
            },
            MVM_HOSTLIB_INTERNAL
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_ne!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    assert!(matches!(state.session, SessionLifetime::UnknownStart));
                    assert_eq!(
                        state.panic_payload.as_ref().unwrap().downcast_ref::<&str>(),
                        Some(&"original start unwind")
                    );
                    empty()
                })
            },
            0
        );
        discard(out);
        assert_ne!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        // Deliberately retain the ambiguous fixture, never manufacture exit.
    }

    #[test]
    fn same_rejection_after_possible_dispatch_cannot_release_unknown_start() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        // This adapter supplies no quiescence proof: a wire rejection alone
        // must remain ambiguous even when it has the native-refusal status.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_start_using(b"{}", |_| {
                        crate::entrypoint::OwnedStartAttempt::MayHaveDispatched(Outcome::from(
                            MvmError::Rejected {
                                reason: "fixture rejection".into(),
                            },
                        ))
                    })
                })
            },
            crate::status::MVM_HOSTLIB_REJECTED
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_ne!(unsafe { mvm_hostlib_context_close(pointer, &mut out) }, 0);
        discard(out);
        let original = pointer;
        assert_ne!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 0);
        assert_eq!(pointer, original);
        // Deliberately retain the ambiguous no-child fixture, not a native proof.
    }

    #[test]
    fn malformed_start_keeps_original_response_and_error_and_refuses_false_cleanup() {
        for raw in [
            br#"{"private_marker":"not-public"}"#.as_slice(),
            br#"{"session_id":7,"private_marker":"not-public"}"#.as_slice(),
            br#"{"session_id":"NOT-BASE32","private_marker":"not-public"}"#.as_slice(),
            br#"{"session_id":"abcdefghijklmnopqrstuvwx","session_id":"abcdefghijklmnopqrstuvwx","private_marker":"not-public"}"#.as_slice(),
        ] {
            let mut pointer = create();
            let mut out = MvmHostlibBuf::empty();
            // SAFETY: no-child response adapter drives the production state machine.
            assert_ne!(unsafe {
                access(pointer, &mut out, |state| state.call_using(
                    b"session.start", b"{}", |_, _| Outcome { status: 0, body: raw.to_vec() },
                ))
            }, 0);
            discard(out);
            let mut out = MvmHostlibBuf::empty();
            assert_ne!(unsafe { mvm_hostlib_context_inspect(pointer, 0, &mut out) }, 0);
            // SAFETY: fresh ABI buffer is readable until its paired free.
            let body = unsafe { std::slice::from_raw_parts(out.data, out.len) };
            assert!(!String::from_utf8_lossy(body).contains("not-public"));
            discard(out);
            let mut out = MvmHostlibBuf::empty();
            assert_eq!(unsafe {
                access(pointer, &mut out, |state| {
                    assert!(matches!(state.session, SessionLifetime::UnknownStart));
                    assert_eq!(state.session_response.as_ref().unwrap().body, raw);
                    assert!(state.session_error.is_some());
                    empty()
                })
            }, 0);
            discard(out);
            for operation in [mvm_hostlib_context_retry_stop, mvm_hostlib_context_close] {
                let mut out = MvmHostlibBuf::empty();
                assert_ne!(unsafe { operation(pointer, &mut out) }, 0);
                discard(out);
            }
            let original = pointer;
            assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
            assert_eq!(pointer, original);
            // Deliberately retain this no-child test allocation until process
            // exit. This is refusal-policy evidence, not native uncertainty proof.
        }
    }

    #[test]
    fn start_panic_retains_pending_context_and_blocks_further_dispatch() {
        let mut pointer = create();
        let mut out = MvmHostlibBuf::empty();
        // SAFETY: callback cannot create a Child; access catches its real payload.
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_using(b"session.start", b"{}", |_, _| {
                        panic!("original start callback")
                    })
                })
            },
            MVM_HOSTLIB_INTERNAL
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_ne!(
            unsafe {
                access(pointer, &mut out, |state| {
                    state.call_using(b"session.start", b"{}", |_, _| {
                        panic!("must not replace original panic")
                    })
                })
            },
            0
        );
        discard(out);
        let mut out = MvmHostlibBuf::empty();
        assert_eq!(
            unsafe {
                access(pointer, &mut out, |state| {
                    assert!(matches!(state.session, SessionLifetime::UnknownStart));
                    assert_eq!(
                        state.panic_payload.as_ref().unwrap().downcast_ref::<&str>(),
                        Some(&"original start callback"),
                    );
                    empty()
                })
            },
            0
        );
        discard(out);
        assert_eq!(unsafe { mvm_hostlib_context_checked_free(&mut pointer) }, 5);
        // No public fake proof or forced terminal state is used to free it.
    }
}
