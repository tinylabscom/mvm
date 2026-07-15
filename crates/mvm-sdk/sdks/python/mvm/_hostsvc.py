"""In-guest host-services transport — a thin ``ctypes`` shim over the one
``libmvm_host_services.so`` C ABI.

A workload running *inside* the microVM calls ``mvm.audit`` / ``mvm.host``,
which build the verb's typed request dict and hand it to [`call`]. This module
is the only hand-written transport piece: it loads the shared object, marshals
the request as JSON across the C ABI (``mvm_hsvc_call`` — JSON in, JSON out, an
``i32`` status, paired ``mvm_hsvc_free``), and maps the status onto a typed
exception. Every other language SDK is the same shim over the same ``.so``, so
the wire + framing live once, in Rust.

This holds no key and is not a security boundary: it runs in the untrusted
guest over the advisory broker transport. The host derives identity from the
connection and enforces the ``ExecutionPlan.services`` binding, the
category-forcing and size/rate caps, and the correlation-id assignment.
"""

import ctypes
import json
import os
from typing import Any, Callable, Optional, Tuple

# Where mkGuest bakes the shared object inside the runtime overlay. Overridable
# (host unit tests, alternate layouts) via the env var.
LIB_PATH_ENV = "MVM_HOST_SERVICES_LIB"
DEFAULT_LIB_PATH = "/mvm/runtime/lib/libmvm_host_services.so"

# Must match the MVM_HSVC_* status codes in the Rust cdylib.
_OK = 0
_BAD_REQUEST = 1
_RATE_LIMITED = 2
_UNAVAILABLE = 3
_NOT_BOUND = 4
_NOT_IMPLEMENTED = 5
_SERVICE = 6
_TRANSPORT = 7
_INVALID_INPUT = 8

_DEFAULT_TIMEOUT_SECS = 5.0


class HostServiceError(Exception):
    """Base of every typed host-services failure."""


class BadRequestError(HostServiceError):
    """The host rejected the record shape or size (e.g. the 4 KiB audit cap)."""


class RateLimitedError(HostServiceError):
    """The per-workload audit emit rate limit is exhausted."""


class UnavailableError(HostServiceError):
    """The host could not answer (handler down, broker not ready)."""


class NotBoundError(HostServiceError):
    """The workload's ``ExecutionPlan.services`` did not bind the service."""


class VerbNotImplementedError(HostServiceError):
    """The verb is not implemented in this build (e.g. ``host.cost.tenant``)."""


class ServiceError(HostServiceError):
    """Any other typed broker error code."""


class TransportError(HostServiceError):
    """Connect, framing, or (de)serialization failure on the vsock path."""


class InvalidInputError(HostServiceError):
    """The request was malformed: unknown method or a body the verb rejects."""


_STATUS_EXCEPTIONS = {
    _BAD_REQUEST: BadRequestError,
    _RATE_LIMITED: RateLimitedError,
    _UNAVAILABLE: UnavailableError,
    _NOT_BOUND: NotBoundError,
    _NOT_IMPLEMENTED: VerbNotImplementedError,
    _SERVICE: ServiceError,
    _TRANSPORT: TransportError,
    _INVALID_INPUT: InvalidInputError,
}


class _MvmHsvcBuf(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


_lib: Optional[ctypes.CDLL] = None


def _load() -> ctypes.CDLL:
    """Load and memoize the shared object, declaring the C ABI signatures."""
    global _lib
    if _lib is None:
        path = os.environ.get(LIB_PATH_ENV, DEFAULT_LIB_PATH)
        lib = ctypes.CDLL(path)
        lib.mvm_hsvc_call.argtypes = [
            ctypes.c_char_p,  # method ptr
            ctypes.c_size_t,  # method len
            ctypes.c_char_p,  # request ptr
            ctypes.c_size_t,  # request len
            ctypes.c_uint64,  # timeout_secs
            ctypes.POINTER(_MvmHsvcBuf),  # out
        ]
        lib.mvm_hsvc_call.restype = ctypes.c_int32
        lib.mvm_hsvc_free.argtypes = [_MvmHsvcBuf]
        lib.mvm_hsvc_free.restype = None
        _lib = lib
    return _lib


def _invoke(method: str, request_json: bytes, timeout_secs: float) -> Tuple[int, bytes]:
    """Call the C ABI once and return ``(status, response_bytes)``.

    The single test seam: monkeypatch this to drive the marshalling layer
    without a real ``.so`` or broker.
    """
    lib = _load()
    method_bytes = method.encode("utf-8")
    out = _MvmHsvcBuf()
    status = lib.mvm_hsvc_call(
        method_bytes,
        len(method_bytes),
        request_json,
        len(request_json),
        ctypes.c_uint64(int(timeout_secs)),
        ctypes.byref(out),
    )
    try:
        body = bytes(ctypes.string_at(out.data, out.len)) if out.len else b""
    finally:
        lib.mvm_hsvc_free(out)
    return status, body


def call(
    method: str,
    request: Any,
    *,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
    invoke: Optional[Callable[[str, bytes, float], Tuple[int, bytes]]] = None,
) -> Any:
    """Marshal ``request`` to JSON, call ``method``, and return the parsed reply.

    Raises a typed [`HostServiceError`] subclass when the host refuses.
    ``invoke`` overrides the C-call seam (used by tests).
    """
    fn = invoke if invoke is not None else _invoke
    request_json = json.dumps(request, separators=(",", ":")).encode("utf-8")
    status, body = fn(method, request_json, timeout_secs)
    parsed = json.loads(body) if body else {}
    if status == _OK:
        return parsed
    message = parsed.get("message", "") if isinstance(parsed, dict) else ""
    exc = _STATUS_EXCEPTIONS.get(status, ServiceError)
    raise exc(message or f"host service call `{method}` failed (status {status})")
