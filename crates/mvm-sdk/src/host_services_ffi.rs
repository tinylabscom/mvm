//! C-ABI veneer over the in-guest host-services broker clients.
//!
//! Every language SDK that runs *inside* a booted workload reaches the
//! host-services broker (`host.audit.v1` / `host.time.v1` / `host.cost.v1`)
//! through this single shared object. The contract is deliberately tiny and
//! language-agnostic: JSON in, JSON out, one paired free function, and an
//! `i32` status that maps the broker's typed error vocabulary onto a stable
//! set of codes. A new language SDK is then a shim-sized change — load the
//! `.so`, marshal a request, call [`mvm_hsvc_call`], parse the reply — with
//! zero new Rust binding code.
//!
//! The veneer holds no key and is not a security boundary: it runs in the
//! untrusted guest and rides the advisory broker transport
//! ([`mvm_agentd::broker_client`]). Every gate — the `ExecutionPlan.services`
//! binding, the category-forcing and size/rate caps on `host.audit.v1`, the
//! correlation-id assignment — lives host-side. This layer only translates
//! between the C ABI and the typed Rust transport.
//!
//! ## C ABI
//!
//! ```c
//! typedef struct { uint8_t *data; size_t len; } MvmHsvcBuf;
//!
//! // 0 == ok; any other value is one of MVM_HSVC_* and `out` then carries an
//! // error JSON object {"code": "...", "message": "..."} rather than the
//! // service reply.
//! int32_t mvm_hsvc_call(const uint8_t *method, size_t method_len,
//!                       const uint8_t *request, size_t request_len,
//!                       uint64_t timeout_secs, MvmHsvcBuf *out);
//!
//! // Free a buffer produced by mvm_hsvc_call. Safe on a zeroed buffer.
//! void mvm_hsvc_free(MvmHsvcBuf buf);
//! ```
//!
//! `method` is `"<service>.<verb>"`, e.g. `host.audit.emit`,
//! `host.audit.emit_batch`, `host.time.now`, `host.cost.workload`,
//! `host.cost.tenant`. `request` is the verb's typed request JSON (an empty
//! body is accepted for the no-payload verbs). The reply written to `out` is
//! the verb's typed response JSON on success.

use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;

use mvm_agentd::vsock::{BROKER_PORT, connect_host_vsock};
use mvm_agentd::{host_audit, host_cost, host_kv, host_time};
use mvm_core::protocol::host_audit::{EmitBatchRequest, EmitRequest};
use mvm_core::protocol::host_kv::{KvDeleteRequest, KvGetRequest, KvListRequest, KvPutRequest};

/// Call succeeded; `out` carries the typed response JSON.
pub const MVM_HSVC_OK: i32 = 0;
/// The host rejected the record shape or size (audit cap).
pub const MVM_HSVC_BAD_REQUEST: i32 = 1;
/// The per-workload audit emit rate limit is exhausted.
pub const MVM_HSVC_RATE_LIMITED: i32 = 2;
/// The host could not answer (handler down, broker not ready).
pub const MVM_HSVC_UNAVAILABLE: i32 = 3;
/// The workload's `ExecutionPlan.services` did not bind the service.
pub const MVM_HSVC_NOT_BOUND: i32 = 4;
/// The verb is not implemented in this build (e.g. `host.cost.tenant`).
pub const MVM_HSVC_NOT_IMPLEMENTED: i32 = 5;
/// Any other typed broker error code (see the error JSON `message`).
pub const MVM_HSVC_SERVICE: i32 = 6;
/// Connect, framing, or (de)serialization failure on the vsock path.
pub const MVM_HSVC_TRANSPORT: i32 = 7;
/// The FFI input was malformed: unknown method, non-UTF-8 method, or a
/// request body that does not parse as the verb's request type.
pub const MVM_HSVC_INVALID_INPUT: i32 = 8;

/// An owned byte buffer handed across the C ABI. Produced by
/// [`mvm_hsvc_call`], released by [`mvm_hsvc_free`].
#[repr(C)]
pub struct MvmHsvcBuf {
    /// Pointer to `len` bytes of UTF-8 JSON, or null when `len == 0`.
    pub data: *mut u8,
    /// Length of the buffer in bytes.
    pub len: usize,
}

// Layout contract for the dlopen'd C ABI. Every language SDK declares this
// struct again in its own FFI binding and reads the two fields by offset;
// a reordered, resized, or added field is an out-of-bounds read inside
// that runtime, with no diagnostic on this side of the boundary. Any
// change here is a breaking ABI change and must land together with the
// matching change in every binding under `sdks/`.
//
// Pointer-width-gated rather than written as `2 * size_of::<usize>()`,
// which would hold for any two pointer-sized fields in any order and so
// would assert nothing.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<MvmHsvcBuf>() == 16);
    assert!(align_of::<MvmHsvcBuf>() == 8);
    assert!(offset_of!(MvmHsvcBuf, data) == 0);
    assert!(offset_of!(MvmHsvcBuf, len) == 8);
};

impl MvmHsvcBuf {
    /// The empty buffer. A freshly-zeroed `out` is always safe to free.
    const fn empty() -> Self {
        MvmHsvcBuf {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

/// The status + body of a single dispatched call. `body` is the typed response
/// JSON when `status == MVM_HSVC_OK`, otherwise an error JSON object.
struct Outcome {
    status: i32,
    body: Vec<u8>,
}

/// Exchange one host-services call over an already-open broker stream and
/// marshal the typed reply (or typed error) back to JSON bytes.
///
/// This is the in-process seam the C entry point delegates to once it has a
/// connected stream; isolating it keeps the JSON↔typed marshalling testable
/// over a `UnixStream::pair()` mock broker, with no vsock dial.
fn dispatch_on(stream: &mut UnixStream, method: &str, request: &[u8]) -> Outcome {
    match method {
        "host.audit.emit" => match parse::<EmitRequest>(request) {
            Ok(req) => match host_audit::emit_on(stream, &req) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_audit(e),
            },
            Err(o) => o,
        },
        "host.audit.emit_batch" => match parse::<EmitBatchRequest>(request) {
            Ok(batch) => match host_audit::emit_batch_on(stream, &batch) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_audit(e),
            },
            Err(o) => o,
        },
        "host.kv.get" => match parse::<KvGetRequest>(request) {
            Ok(req) => match host_kv::get_on(stream, &req.key) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_kv(e),
            },
            Err(o) => o,
        },
        "host.kv.put" => match parse::<KvPutRequest>(request) {
            Ok(req) => match host_kv::put_on(stream, &req.key, &req.value) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_kv(e),
            },
            Err(o) => o,
        },
        "host.kv.delete" => match parse::<KvDeleteRequest>(request) {
            Ok(req) => match host_kv::delete_on(stream, &req.key) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_kv(e),
            },
            Err(o) => o,
        },
        "host.kv.list" => match parse::<KvListRequest>(request) {
            Ok(req) => match host_kv::list_on(stream, &req.prefix) {
                Ok(resp) => ok_json(&resp),
                Err(e) => from_kv(e),
            },
            Err(o) => o,
        },
        "host.time.now" => match host_time::now_on(stream) {
            Ok(resp) => ok_json(&resp),
            Err(e) => from_time(e),
        },
        "host.cost.workload" => match host_cost::workload_on(stream) {
            Ok(report) => ok_json(&report),
            Err(e) => from_cost(e),
        },
        "host.cost.tenant" => match host_cost::tenant_on(stream) {
            Ok(report) => ok_json(&report),
            Err(e) => from_cost(e),
        },
        other => Outcome {
            status: MVM_HSVC_INVALID_INPUT,
            body: error_json("invalid_input", &format!("unknown method `{other}`")),
        },
    }
}

/// Parse the request body into the verb's typed request, or fail closed with a
/// local `invalid_input` outcome that never reaches the broker.
fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request).map_err(|e| Outcome {
        status: MVM_HSVC_INVALID_INPUT,
        body: error_json("invalid_input", &format!("request body did not parse: {e}")),
    })
}

/// Marshal a typed success response back to JSON. A serialization failure is a
/// host-side bug, not a service error — surface it as transport.
fn ok_json<T: serde::Serialize>(value: &T) -> Outcome {
    match serde_json::to_vec(value) {
        Ok(body) => Outcome {
            status: MVM_HSVC_OK,
            body,
        },
        Err(e) => Outcome {
            status: MVM_HSVC_TRANSPORT,
            body: error_json("transport", &format!("response encoding failed: {e}")),
        },
    }
}

/// Map a `host.audit.v1` error onto a status + error JSON.
fn from_audit(err: host_audit::AuditError) -> Outcome {
    use host_audit::AuditError::*;
    let (status, code, message) = match err {
        BadRequest(m) => (MVM_HSVC_BAD_REQUEST, "bad_request", m),
        RateLimited => (
            MVM_HSVC_RATE_LIMITED,
            "rate_limited",
            "audit emit rate limit exceeded".to_string(),
        ),
        Unavailable(m) => (MVM_HSVC_UNAVAILABLE, "unavailable", m),
        Service { code, message } => (
            MVM_HSVC_SERVICE,
            "service_error",
            format!("[{code:?}] {message}"),
        ),
        Transport(e) => (MVM_HSVC_TRANSPORT, "transport", e.to_string()),
    };
    Outcome {
        status,
        body: error_json(code, &message),
    }
}

/// Map a `host.time.v1` error onto a status + error JSON.
fn from_kv(err: host_kv::KvError) -> Outcome {
    use host_kv::KvError::*;
    let (status, code, message) = match err {
        NotBound => (
            MVM_HSVC_NOT_BOUND,
            "not_bound",
            "host.kv.v1 not bound to this workload".to_string(),
        ),
        // A refused key is the caller's bug, not the host being down. Keeping
        // them distinct is what lets a caller tell "fix the request" from
        // "retry later".
        BadRequest(m) => (MVM_HSVC_SERVICE, "bad_request", m),
        Unavailable(m) => (MVM_HSVC_UNAVAILABLE, "unavailable", m),
        Service { code, message } => (
            MVM_HSVC_SERVICE,
            "service_error",
            format!("[{code:?}] {message}"),
        ),
        Transport(e) => (MVM_HSVC_TRANSPORT, "transport", e.to_string()),
    };
    Outcome {
        status,
        body: error_json(code, &message),
    }
}

fn from_time(err: host_time::TimeError) -> Outcome {
    use host_time::TimeError::*;
    let (status, code, message) = match err {
        NotBound => (
            MVM_HSVC_NOT_BOUND,
            "not_bound",
            "host.time.v1 not bound to this workload".to_string(),
        ),
        Unavailable(m) => (MVM_HSVC_UNAVAILABLE, "unavailable", m),
        Service { code, message } => (
            MVM_HSVC_SERVICE,
            "service_error",
            format!("[{code:?}] {message}"),
        ),
        Transport(e) => (MVM_HSVC_TRANSPORT, "transport", e.to_string()),
    };
    Outcome {
        status,
        body: error_json(code, &message),
    }
}

/// Map a `host.cost.v1` error onto a status + error JSON.
fn from_cost(err: host_cost::CostError) -> Outcome {
    use host_cost::CostError::*;
    let (status, code, message) = match err {
        NotBound => (
            MVM_HSVC_NOT_BOUND,
            "not_bound",
            "host.cost.v1 not bound to this workload".to_string(),
        ),
        NotImplemented => (
            MVM_HSVC_NOT_IMPLEMENTED,
            "not_implemented",
            "host.cost.v1 verb not implemented in this build".to_string(),
        ),
        Unavailable(m) => (MVM_HSVC_UNAVAILABLE, "unavailable", m),
        Service { code, message } => (
            MVM_HSVC_SERVICE,
            "service_error",
            format!("[{code:?}] {message}"),
        ),
        Transport(e) => (MVM_HSVC_TRANSPORT, "transport", e.to_string()),
    };
    Outcome {
        status,
        body: error_json(code, &message),
    }
}

/// Build an error JSON body: `{"code": "<symbol>", "message": "<detail>"}`.
fn error_json(code: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "code": code, "message": message }))
        .unwrap_or_else(|_| br#"{"code":"transport","message":"error encoding failed"}"#.to_vec())
}

/// Move `bytes` into a heap buffer the C side owns. Released by
/// [`mvm_hsvc_free`].
fn into_c_buf(bytes: Vec<u8>) -> MvmHsvcBuf {
    if bytes.is_empty() {
        return MvmHsvcBuf::empty();
    }
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len();
    let data = Box::into_raw(boxed).cast::<u8>();
    MvmHsvcBuf { data, len }
}

/// Write `outcome.body` into `out` as an owned C buffer and return the status.
///
/// # Safety
/// `out` must be a valid, writable `*mut MvmHsvcBuf`.
unsafe fn write_outcome(out: *mut MvmHsvcBuf, outcome: Outcome) -> i32 {
    unsafe { *out = into_c_buf(outcome.body) };
    outcome.status
}

/// Dispatch a call over `stream` and write the reply into `out`. The in-process
/// seam shared by [`mvm_hsvc_call`] and the unit tests.
///
/// # Safety
/// `out` must be a valid, writable `*mut MvmHsvcBuf`.
unsafe fn call_with_stream(
    stream: &mut UnixStream,
    method: &str,
    request: &[u8],
    out: *mut MvmHsvcBuf,
) -> i32 {
    unsafe { write_outcome(out, dispatch_on(stream, method, request)) }
}

/// Dial the host-services broker, dispatch one call, and write the reply.
///
/// Returns [`MVM_HSVC_OK`] on success; otherwise one of the `MVM_HSVC_*`
/// codes, with `out` carrying an error JSON object. Never panics across the
/// boundary: any unwinding is caught and reported as a transport error.
///
/// # Safety
/// `method` / `request` must point to `method_len` / `request_len` readable
/// bytes (or be null when the length is 0). `out` must be a valid, writable
/// `*mut MvmHsvcBuf`; on return the caller owns `*out` and must release it
/// with [`mvm_hsvc_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hsvc_call(
    method: *const u8,
    method_len: usize,
    request: *const u8,
    request_len: usize,
    timeout_secs: u64,
    out: *mut MvmHsvcBuf,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            // No buffer to report through — the status is all the caller gets.
            return MVM_HSVC_INVALID_INPUT;
        }
        // Make `*out` freeable no matter which path we return on.
        unsafe { *out = MvmHsvcBuf::empty() };

        let method_bytes = unsafe { borrow(method, method_len) };
        let method = match std::str::from_utf8(method_bytes) {
            Ok(m) => m,
            Err(_) => {
                return unsafe {
                    write_outcome(
                        out,
                        Outcome {
                            status: MVM_HSVC_INVALID_INPUT,
                            body: error_json("invalid_input", "method is not valid UTF-8"),
                        },
                    )
                };
            }
        };
        let request = unsafe { borrow(request, request_len) };

        let mut stream = match connect_host_vsock(BROKER_PORT, timeout_secs) {
            Ok(s) => s,
            Err(e) => {
                return unsafe {
                    write_outcome(
                        out,
                        Outcome {
                            status: MVM_HSVC_TRANSPORT,
                            body: error_json("transport", &e.to_string()),
                        },
                    )
                };
            }
        };
        unsafe { call_with_stream(&mut stream, method, request, out) }
    }));
    result.unwrap_or(MVM_HSVC_TRANSPORT)
}

/// Release a buffer produced by [`mvm_hsvc_call`]. A zeroed buffer
/// (`data == null`) is a no-op, so calling this on an `out` that never
/// received a reply is safe.
///
/// # Safety
/// `buf` must be a buffer returned by [`mvm_hsvc_call`] and must not have been
/// freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mvm_hsvc_free(buf: MvmHsvcBuf) {
    if buf.data.is_null() {
        return;
    }
    let slice = ptr::slice_from_raw_parts_mut(buf.data, buf.len);
    drop(unsafe { Box::from_raw(slice) });
}

/// Borrow `len` bytes at `ptr`, treating a null pointer as the empty slice.
///
/// # Safety
/// When `len > 0`, `ptr` must point to `len` readable bytes.
unsafe fn borrow<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use mvm_agentd::vsock::{read_frame, write_frame};
    use mvm_core::protocol::broker::{ServiceCall, ServiceErrorCode, ServiceResponse};

    use super::*;

    fn sample_emit() -> EmitRequest {
        EmitRequest {
            ts: "2026-06-16T00:00:00Z".into(),
            fields: serde_json::json!({"action": "login", "user": "alice"}),
        }
    }

    /// Spawn a one-shot mock broker on the server half of a socket pair: read
    /// the `ServiceCall`, capture it, write the response `respond` returns.
    fn serve_once(
        server: UnixStream,
        captured: Arc<Mutex<Option<ServiceCall>>>,
        respond: impl FnOnce(&ServiceCall) -> ServiceResponse + Send + 'static,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut server = server;
            let call: ServiceCall = read_frame(&mut server).unwrap();
            *captured.lock().unwrap() = Some(call.clone());
            write_frame(&mut server, &respond(&call)).unwrap();
        })
    }

    #[test]
    fn dispatch_marshals_emit_request_and_response_json() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"chain_head": "head-001"}),
        });

        let request = serde_json::to_vec(&sample_emit()).unwrap();
        let outcome = dispatch_on(&mut client, "host.audit.emit", &request);
        handle.join().unwrap();

        assert_eq!(outcome.status, MVM_HSVC_OK);
        // EmitResponse marshalled back to JSON.
        let resp: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(resp["chain_head"], "head-001");

        // The request JSON deserialized into the typed EmitRequest, with no
        // category field a workload could ever set.
        let call = captured.lock().unwrap().take().unwrap();
        assert_eq!(call.service.as_str(), "host.audit.v1");
        assert_eq!(call.verb, "emit");
        assert!(call.payload.get("category").is_none());
        let record: EmitRequest = serde_json::from_value(call.payload).unwrap();
        assert_eq!(record, sample_emit());
    }

    #[test]
    fn dispatch_marshals_emit_batch() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({
                "chain_head": "head-b2",
                "statuses": [{"kind": "ok", "chain_head": "head-b1"},
                             {"kind": "ok", "chain_head": "head-b2"}],
            }),
        });

        let batch = EmitBatchRequest {
            entries: vec![sample_emit(), sample_emit()],
        };
        let request = serde_json::to_vec(&batch).unwrap();
        let outcome = dispatch_on(&mut client, "host.audit.emit_batch", &request);
        handle.join().unwrap();

        assert_eq!(outcome.status, MVM_HSVC_OK);
        let resp: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(resp["chain_head"], "head-b2");

        let call = captured.lock().unwrap().take().unwrap();
        assert_eq!(call.verb, "emit_batch");
        let parsed: EmitBatchRequest = serde_json::from_value(call.payload).unwrap();
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn dispatch_marshals_time_now_with_empty_request() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"wall_ms": 1_717_000_000_000_u64}),
        });

        // The no-payload verbs accept an empty request body.
        let outcome = dispatch_on(&mut client, "host.time.now", &[]);
        handle.join().unwrap();

        assert_eq!(outcome.status, MVM_HSVC_OK);
        let resp: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(resp["wall_ms"], 1_717_000_000_000_u64);

        let call = captured.lock().unwrap().take().unwrap();
        assert_eq!(call.service.as_str(), "host.time.v1");
        assert_eq!(call.verb, "now");
        assert_eq!(call.payload, serde_json::json!({}));
    }

    #[test]
    fn dispatch_surfaces_audit_bad_request_as_error_json_not_panic() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::BadRequest,
            message: "record 5121 bytes exceeds cap 4096".into(),
        });

        let request = serde_json::to_vec(&sample_emit()).unwrap();
        let outcome = dispatch_on(&mut client, "host.audit.emit", &request);
        handle.join().unwrap();

        assert_eq!(outcome.status, MVM_HSVC_BAD_REQUEST);
        let err: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(err["code"], "bad_request");
        assert!(err["message"].as_str().unwrap().contains("exceeds cap"));
    }

    #[test]
    fn dispatch_surfaces_audit_rate_limit() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::RateLimitExceeded,
            message: "per-workload audit emit rate limit exceeded".into(),
        });

        let request = serde_json::to_vec(&sample_emit()).unwrap();
        let outcome = dispatch_on(&mut client, "host.audit.emit", &request);
        handle.join().unwrap();
        assert_eq!(outcome.status, MVM_HSVC_RATE_LIMITED);
    }

    #[test]
    fn dispatch_surfaces_time_not_bound() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service `host.time.v1` not bound to workload".into(),
        });

        let outcome = dispatch_on(&mut client, "host.time.now", &[]);
        handle.join().unwrap();
        assert_eq!(outcome.status, MVM_HSVC_NOT_BOUND);
        let err: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(err["code"], "not_bound");
    }

    #[test]
    fn dispatch_surfaces_cost_not_implemented() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Err {
            correlation_id: call.correlation_id.clone(),
            code: ServiceErrorCode::NotImplemented,
            message: "tenant verb not implemented".into(),
        });

        let outcome = dispatch_on(&mut client, "host.cost.tenant", &[]);
        handle.join().unwrap();
        assert_eq!(outcome.status, MVM_HSVC_NOT_IMPLEMENTED);
    }

    #[test]
    fn dispatch_routes_cost_workload_verb() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured.clone(), |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"spent_micros_usd": 4_200_000_u64}),
        });

        let outcome = dispatch_on(&mut client, "host.cost.workload", &[]);
        handle.join().unwrap();
        assert_eq!(
            outcome.status,
            MVM_HSVC_OK,
            "body: {:?}",
            String::from_utf8_lossy(&outcome.body)
        );
        let resp: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(resp["spent_micros_usd"], 4_200_000_u64);

        let call = captured.lock().unwrap().take().unwrap();
        assert_eq!(call.service.as_str(), "host.cost.v1");
        assert_eq!(call.verb, "workload");
    }

    #[test]
    fn dispatch_rejects_unknown_method_as_invalid_input() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        let outcome = dispatch_on(&mut client, "host.bogus.v9", &[]);
        assert_eq!(outcome.status, MVM_HSVC_INVALID_INPUT);
        let err: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(err["code"], "invalid_input");
    }

    #[test]
    fn dispatch_rejects_malformed_request_body_before_dialing() {
        // A method that needs a typed body, but the body is not that type. We
        // must reject locally without ever writing to the broker — the mock
        // server here never reads, so a premature write would not hang the
        // test but would prove the parse came after the call.
        let (mut client, _server) = UnixStream::pair().unwrap();
        let outcome = dispatch_on(&mut client, "host.audit.emit", b"not json");
        assert_eq!(outcome.status, MVM_HSVC_INVALID_INPUT);
        let err: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(err["code"], "invalid_input");
    }

    #[test]
    fn c_buffer_round_trips_and_frees_over_mock_broker() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let handle = serve_once(server, captured, |call| ServiceResponse::Ok {
            correlation_id: call.correlation_id.clone(),
            payload: serde_json::json!({"chain_head": "head-free"}),
        });

        let request = serde_json::to_vec(&sample_emit()).unwrap();
        let mut out = MvmHsvcBuf::empty();
        // Drive the C-ABI marshalling path: dispatch over the mock broker, fill
        // `out` with an owned C buffer, read it back as a C caller would, then
        // release it.
        let status =
            unsafe { call_with_stream(&mut client, "host.audit.emit", &request, &mut out) };
        handle.join().unwrap();

        assert_eq!(status, MVM_HSVC_OK);
        assert!(!out.data.is_null());
        assert!(out.len > 0);
        let body = unsafe { slice::from_raw_parts(out.data, out.len) };
        let resp: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(resp["chain_head"], "head-free");

        // Free-after-use: a no-double-free, no-leak round trip. Miri/ASan in CI
        // would catch a mismatch between into_c_buf and mvm_hsvc_free here.
        unsafe { mvm_hsvc_free(out) };
    }

    #[test]
    fn free_is_a_no_op_on_zeroed_buffer() {
        unsafe { mvm_hsvc_free(MvmHsvcBuf::empty()) };
    }

    /// Every `host.kv.*` method reaches the store rather than falling through
    /// to the unknown-method arm.
    ///
    /// `dispatch_on` is a hardcoded match, not a generic passthrough, so an
    /// arm that is missing produces a *method* failure. On a host with no
    /// vsock every call fails at the dial before dispatch is reached, which is
    /// why this drives the mock broker directly instead of the FFI entry
    /// point — the transport error there would hide a missing arm.
    #[test]
    fn every_kv_method_routes_to_the_store() {
        for (method, request, reply) in [
            (
                "host.kv.get",
                serde_json::json!({"key": "k"}),
                serde_json::json!({"value": [1, 2, 3]}),
            ),
            (
                "host.kv.put",
                serde_json::json!({"key": "k", "value": [1]}),
                serde_json::json!({"replaced": false}),
            ),
            (
                "host.kv.delete",
                serde_json::json!({"key": "k"}),
                serde_json::json!({"removed": true}),
            ),
            (
                "host.kv.list",
                serde_json::json!({"prefix": "k"}),
                serde_json::json!({"keys": ["k"]}),
            ),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let captured = Arc::new(Mutex::new(None));
            let reply_for_thread = reply.clone();
            let handle = serve_once(server, captured.clone(), move |call| ServiceResponse::Ok {
                correlation_id: call.correlation_id.clone(),
                payload: reply_for_thread,
            });

            let body = serde_json::to_vec(&request).unwrap();
            let outcome = dispatch_on(&mut client, method, &body);
            handle.join().unwrap();

            assert_eq!(
                outcome.status,
                MVM_HSVC_OK,
                "{method} did not route: {}",
                String::from_utf8_lossy(&outcome.body)
            );
            let call = captured.lock().unwrap().take().unwrap();
            assert_eq!(call.service.as_str(), "host.kv.v1", "{method}");
            // The guest never names its own namespace on the wire.
            assert!(call.payload.get("workload_id").is_none(), "{method}");
        }
    }

    /// A method with no arm fails as a *method* problem, which is what makes
    /// the assertion above meaningful rather than vacuous.
    #[test]
    fn an_unknown_method_is_not_routed() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        let outcome = dispatch_on(&mut client, "host.kv.truncate", b"{}");
        assert_ne!(outcome.status, MVM_HSVC_OK);
    }
}
