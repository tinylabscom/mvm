"""Host-side transport: the host library, loaded in-process.

The SDK drives machines by calling ``libmvm_hostlib``, the same machine and
guest surface ``mvmctl`` uses, through its C ABI: JSON in, JSON out, an
``i32`` status, a paired free. No process is spawned — not ``mvmctl``, and
not a helper standing in for it.

Where the library comes from, in order:

1. ``MVM_HOSTLIB_PATH``, the library file itself. When it is set and names
   nothing, that is an error, not a reason to keep looking: an override that
   silently fell through would load a library the caller did not choose.
2. Packaged with the SDK, at ``mvm/_native/<library>``, so an installed
   package that carries its own library needs nothing else on the host.
3. Beside ``mvmctl`` on ``PATH``, and beside the file that path resolves to.
   The release ships them side by side; the binary is located, never run.
4. Otherwise [`MvmTransportError`], naming all three.

Before the first call the binding tells the library which ABI it was built
for, and the library refuses every call until that succeeds, so a binding
and library that disagree about the buffer layout cannot exchange one.
"""

import ctypes
import json
import os
import re
import shutil
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, List, Literal, Optional, Tuple

from mvm._env.vars import MVM_HOSTLIB_PATH_ENV
from mvm._errors.types import (
    CODE_ERRORS,
    STATUS_OK as _OK,
    HostLibraryAbiError,
    HostLibraryError,
    HostLibraryInternalError,
    MvmTransportError,
)
from mvm._hostabi.methods import ABI_MAJOR, ABI_MINOR, SESSION_CALL, SESSION_START, SESSION_STOP

#: Environment variable naming the library file. The name is owned by the
#: Rust registry, so the CLI that sets it and the SDKs that read it agree.
LIB_PATH_ENV = MVM_HOSTLIB_PATH_ENV

@dataclass(frozen=True, kw_only=True)
class RecoveryRequiredDetails:
    """Validated recovery metadata, not a recovery operation or authority."""

    machine_id: str
    plan_id: str
    reason: str


def _protocol_error(status: int) -> HostLibraryError:
    error = HostLibraryInternalError("malformed host library error response")
    error.code = "INTERNAL"
    error.retryable = False
    error.status = status
    return error

#: Where a package that bundles the library keeps it, beside this module.
PACKAGED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_native")


def library_file_name(platform: str = sys.platform) -> str:
    """The library's file name on ``platform``."""
    return "libmvm_hostlib.dylib" if platform == "darwin" else "libmvm_hostlib.so"


def candidate_paths(
    environ: Optional[dict] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    platform: str = sys.platform,
    packaged_dir: str = PACKAGED_DIR,
) -> List[str]:
    """Where to look for the library, in order. Pure, for testing: it names
    paths and reads no files."""
    env = os.environ if environ is None else environ
    explicit = env.get(LIB_PATH_ENV)
    if explicit:
        return [explicit]
    name = library_file_name(platform)
    paths = [os.path.join(packaged_dir, name)]
    found = which("mvmctl")
    if not found:
        return paths
    beside = os.path.join(os.path.dirname(found), name)
    if beside not in paths:
        paths.append(beside)
    # A package manager usually links `mvmctl` into its bin directory; the
    # library sits beside the real file.
    real = os.path.realpath(found)
    beside_real = os.path.join(os.path.dirname(real), name)
    if beside_real not in paths:
        paths.append(beside_real)
    return paths


def resolve_library_path(
    environ: Optional[dict] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    exists: Callable[[str], bool] = os.path.isfile,
    platform: str = sys.platform,
    packaged_dir: str = PACKAGED_DIR,
) -> str:
    """The first candidate that exists, or [`MvmTransportError`]."""
    env = os.environ if environ is None else environ
    candidates = candidate_paths(env, which, platform, packaged_dir)
    if env.get(LIB_PATH_ENV):
        path = candidates[0]
        if not exists(path):
            raise MvmTransportError(f"{LIB_PATH_ENV} names {path}, which does not exist")
        return path
    for path in candidates:
        if exists(path):
            return path
    raise MvmTransportError(
        f"the host library {library_file_name(platform)} was not found: set "
        f"{LIB_PATH_ENV} to its path, install an SDK package that bundles it "
        f"under {packaged_dir}, or put the directory holding it and mvmctl on PATH"
    )


class _Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


_lock = threading.Lock()
_lib: Optional[ctypes.CDLL] = None
_ApprovalCallbackC = ctypes.CFUNCTYPE(
    ctypes.c_int32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
)
# Registered C callbacks can be invoked after the registration call returns.
# Keep the active trampoline alive until the native setter confirms that it
# has been replaced or cleared.
_approval_callback_lock = threading.Lock()
_approval_callback_ref: Optional[Any] = None

ApprovalDecision = Literal["deny", "once", "session"]
ApprovalCallback = Callable[[dict[str, Any]], ApprovalDecision]


_legacy_negotiated_library: ctypes.CDLL | None = None


def _negotiate_legacy(lib: ctypes.CDLL) -> None:
    global _legacy_negotiated_library
    if _legacy_negotiated_library is lib:
        return
    if lib.mvm_hostlib_abi_is_compatible(ABI_MAJOR, ABI_MINOR) != 1:
        version = lib.mvm_hostlib_abi_version()
        raise HostLibraryAbiError(
            f"the host library implements ABI {version >> 16}.{version & 0xFFFF}, and "
            f"this SDK needs {ABI_MAJOR}.{ABI_MINOR}; install matching versions"
        )
    _legacy_negotiated_library = lib


def _load(*, negotiate: bool = True) -> ctypes.CDLL:
    """Load the library once, declare its signatures, and negotiate the ABI."""
    global _lib
    with _lock:
        if _lib is not None:
            if negotiate:
                _negotiate_legacy(_lib)
            return _lib
        lib = ctypes.CDLL(resolve_library_path())
        lib.mvm_hostlib_abi_version.argtypes = []
        lib.mvm_hostlib_abi_version.restype = ctypes.c_uint32
        lib.mvm_hostlib_abi_is_compatible.argtypes = [ctypes.c_uint16, ctypes.c_uint16]
        lib.mvm_hostlib_abi_is_compatible.restype = ctypes.c_int32
        lib.mvm_hostlib_call.argtypes = [
            ctypes.c_char_p,  # method
            ctypes.c_size_t,
            ctypes.c_char_p,  # request
            ctypes.c_size_t,
            ctypes.POINTER(_Buf),  # out
        ]
        lib.mvm_hostlib_call.restype = ctypes.c_int32
        lib.mvm_hostlib_free.argtypes = [_Buf]
        lib.mvm_hostlib_free.restype = None
        # The callback pointer is nullable so applications can clear it. Using
        # c_void_p here lets ctypes represent both a CFUNCTYPE trampoline and
        # C NULL without weakening the public Python callback type.
        lib.mvm_hostlib_set_approval_callback.argtypes = [ctypes.c_void_p]
        lib.mvm_hostlib_set_approval_callback.restype = ctypes.c_int32
        if negotiate:
            _negotiate_legacy(lib)
        _lib = lib
        return lib


def _invoke(method: str, request_json: bytes) -> Tuple[int, bytes]:
    """Call the C ABI once and return ``(status, body)``.

    The one test seam: monkeypatch this to drive the marshalling without the
    library.
    """
    lib = _load()
    method_bytes = method.encode("utf-8")
    out = _Buf()
    status = lib.mvm_hostlib_call(
        method_bytes, len(method_bytes), request_json, len(request_json), ctypes.byref(out)
    )
    try:
        body = bytes(ctypes.string_at(out.data, out.len)) if out.len else b""
    finally:
        lib.mvm_hostlib_free(out)
    return status, body


_DIRECT_INVOKE = _invoke


class OwnedContextFailure(MvmTransportError):
    """Both failures and the original context, without rendering their data."""

    def __init__(self, primary: BaseException | None, cleanup: BaseException, context: "NativeContext"):
        super().__init__("cleanup is unresolved; original errors and context remain retained")
        self.primary_error = primary
        self.cleanup_error = cleanup
        self.recovery = context


def _session_id_from_reply(reply: Any) -> str:
    session_id = reply.get("session_id") if isinstance(reply, dict) else None
    if not isinstance(session_id, str) or re.fullmatch(r"[a-z2-7]{16,64}", session_id) is None:
        raise MvmTransportError("session.start returned no usable session id; original reply retained")
    return session_id


def _session_id_from_wire(body: bytes) -> str:
    # Keep object pairs until the original top-level binding is checked;
    # json.loads' ordinary dict conversion silently collapses duplicate ids.
    marker = object()
    root = json.loads(body, object_pairs_hook=lambda pairs: (marker, pairs))
    if not isinstance(root, tuple) or root[0] is not marker:
        raise MvmTransportError("session start has no unique object binding")
    bindings = [value for name, value in root[1] if name == "session_id"]
    if len(bindings) != 1:
        raise MvmTransportError("session start has no unique object binding")
    return _session_id_from_reply({"session_id": bindings[0]})


class NativeContext:
    """One caller-owned C lifetime. No automatic destructor stop or free."""

    def __init__(self) -> None:
        self._pointer = ctypes.c_void_p()
        self._library: ctypes.CDLL | None = None
        self._closed = False
        self._freed = False
        self._context_lock = threading.RLock()
        self._session_phase = "empty"
        self._session_id: str | None = None
        self._session_reply: Any = None
        self._session_reply_bytes: bytes | None = None
        self._session_error: BaseException | None = None

    def _allocate(self) -> ctypes.CDLL:
        if self._freed:
            raise MvmTransportError("context was already freed")
        if self._library is None:
            library = _load(negotiate=False)
            signatures = {
                "create": [ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(_Buf)],
                "call": [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(_Buf)],
                "inspect": [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_Buf)],
                "retry_stop": [ctypes.c_void_p, ctypes.POINTER(_Buf)],
                "close": [ctypes.c_void_p, ctypes.POINTER(_Buf)],
                "checked_free": [ctypes.POINTER(ctypes.c_void_p)],
            }
            for name, arguments in signatures.items():
                function = getattr(library, f"mvm_hostlib_context_{name}")
                function.argtypes = arguments
                function.restype = ctypes.c_int32
            self._library = library  # strong reference after all signatures bind
        if not self._pointer:
            out = _Buf()
            status = self._library.mvm_hostlib_context_create(
                ABI_MAJOR, ABI_MINOR, ctypes.byref(self._pointer), ctypes.byref(out)
            )
            self._library.mvm_hostlib_free(out)
            if status != _OK or not self._pointer:
                raise HostLibraryAbiError("the library refused independent context ABI negotiation")
        return self._library

    def _buffer_call(self, function: Any, *arguments: Any) -> Tuple[int, bytes]:
        out = _Buf()
        status = function(*arguments, ctypes.byref(out))
        assert self._library is not None
        try:
            body = bytes(ctypes.string_at(out.data, out.len)) if out.len else b""
        finally:
            self._library.mvm_hostlib_free(out)
        return status, body

    def _invoke(self, method: str, request: bytes) -> Tuple[int, bytes]:
        if self._closed:
            raise MvmTransportError("context is closed")
        if not self._context_lock.acquire(blocking=False):
            raise MvmTransportError("context is busy")
        try:
            lib = self._allocate()
            encoded = method.encode("utf-8")
            return self._buffer_call(
                lib.mvm_hostlib_context_call, self._pointer,
                encoded, len(encoded), request, len(request),
            )
        finally:
            self._context_lock.release()

    def call(self, method: str, request: Any = None) -> Any:
        if self._closed or self._freed:
            raise MvmTransportError("context is closed")
        if not self._context_lock.acquire(blocking=False):
            error = MvmTransportError("context is busy")
            error.recovery = self
            raise error
        starting = method == SESSION_START
        try:
            if self._session_phase == "unknown":
                raise MvmTransportError("original session start remains unconfirmed")
            if starting:
                if self._session_phase not in ("empty", "reserved"):
                    raise MvmTransportError("context already attempted its one session start")
                # Armed before JSON encoding, FFI and reply decoding.
                self._session_phase = "starting"
            elif method in (SESSION_STOP, SESSION_CALL):
                if (
                    self._session_phase != "active"
                    or not isinstance(request, dict)
                    or request.get("session_id") != self._session_id
                ):
                    raise MvmTransportError("session request has no original context binding")
            # The explicit recorder seam never supplies native authority.
            invoke = _invoke if _invoke is not _DIRECT_INVOKE else self._invoke
            def retained_invoke(name: str, encoded: bytes) -> Tuple[int, bytes]:
                status, body = invoke(name, encoded)
                if starting:
                    self._session_reply_bytes = body
                    if status == _OK:
                        _session_id_from_wire(body)
                return status, body

            reply = call(method, request, invoke=retained_invoke)
            if starting:
                self._session_reply = reply
                self._session_id = _session_id_from_reply(reply)
                self._session_phase = "active"
            elif method == SESSION_STOP:
                self._session_phase = "finished"
            return reply
        except BaseException as error:
            if starting and self._session_phase == "starting":
                self._session_phase = "unknown"
                self._session_error = error
            setattr(error, "recovery", self)
            raise
        finally:
            self._context_lock.release()

    def _reserve_session_start(self) -> None:
        if self._session_phase != "empty":
            raise MvmTransportError("context already reserved its one session start")
        self._session_phase = "reserved"

    def _require_session_quiescent(self) -> None:
        if self._session_phase in ("reserved", "starting", "active", "unknown"):
            error = MvmTransportError("original session start or stop remains unconfirmed")
            error.recovery = self
            raise error

    def _control(self, operation: str, part: int | None = None) -> Any:
        if self._freed:
            raise MvmTransportError("context was already freed")
        if not self._pointer:
            return None  # no C resource was ever created
        if not self._context_lock.acquire(blocking=False):
            raise MvmTransportError("context is busy")
        try:
            assert self._library is not None
            function = getattr(self._library, f"mvm_hostlib_context_{operation}")
            arguments = (self._pointer,) if part is None else (self._pointer, part)
            return call(f"context.{operation}", invoke=lambda _m, _r: self._buffer_call(function, *arguments))
        except BaseException as error:
            setattr(error, "recovery", self)
            raise
        finally:
            self._context_lock.release()

    def inspect(self, part: int = 0) -> Any:
        if not 0 <= part <= 4:
            raise ValueError("context inspection selector must be in 0..=4")
        if part == 0 and self._session_phase in ("reserved", "starting", "unknown"):
            error = MvmTransportError("original session start response remains private")
            error.recovery = self
            raise error
        return self._control("inspect", part)

    def retry_stop(self) -> None:
        self._require_session_quiescent()
        self._control("retry_stop")

    def close(self) -> None:
        if self._session_phase == "unknown" and self._pointer:
            # Only the actual C allocation can establish that preparation
            # never dispatched. A recorder/no-allocation reply cannot.
            self._control("close")
            self._session_phase = "finished"
            self._closed = True
            return
        self._require_session_quiescent()
        self._control("close")
        self._closed = True

    def free(self) -> None:
        if self._freed:
            return
        self._require_session_quiescent()
        if not self._context_lock.acquire(blocking=False):
            raise MvmTransportError("context is busy")
        try:
            if self._pointer:
                assert self._library is not None
                status = self._library.mvm_hostlib_context_checked_free(ctypes.byref(self._pointer))
                if status != _OK:
                    error = MvmTransportError("context still owns resources; close and retain it")
                    error.recovery = self
                    raise error
            self._freed = True
        finally:
            self._context_lock.release()


def _approval_result(callback: ApprovalCallback, prompt_json: bytes) -> int:
    """Map one callback answer to the host ABI's bounded decision enum.

    Malformed JSON, callback exceptions, and unknown answers all deny.
    """
    try:
        prompt = json.loads(prompt_json)
        if not isinstance(prompt, dict):
            return 0
        decision = callback(prompt)
    except BaseException:
        return 0
    return {"deny": 0, "once": 1, "session": 2}.get(decision, 0)


def set_approval_callback(callback: Optional[ApprovalCallback]) -> None:
    """Set the callback that answers runtime ``ask`` decisions.

    The callback receives the supervisor's JSON prompt and returns ``"deny"``,
    ``"once"`` or ``"session"``. Register it before launching or starting a
    machine. It is process-wide and affects machines launched or started
    through this SDK. Clearing it with ``None`` makes all existing SDK brokers
    deny; no answer is persisted to a profile.
    """
    global _approval_callback_ref
    with _approval_callback_lock:
        lib = _load()
        registered = None
        if callback is None:
            status = lib.mvm_hostlib_set_approval_callback(None)
        else:
            if not callable(callback):
                raise TypeError("approval callback must be callable or None")

            def invoke(prompt: Any, length: int) -> int:
                try:
                    encoded = bytes(ctypes.string_at(prompt, length)) if length else b""
                    return _approval_result(callback, encoded)
                except BaseException:
                    return 0

            registered = _ApprovalCallbackC(invoke)
            status = lib.mvm_hostlib_set_approval_callback(
                ctypes.cast(registered, ctypes.c_void_p)
            )
        if status != _OK:
            raise HostLibraryError(
                f"host library refused the approval callback (status {status})"
            )
        _approval_callback_ref = registered


def call(
    method: str,
    request: Any = None,
    *,
    invoke: Optional[Callable[[str, bytes], Tuple[int, bytes]]] = None,
) -> Any:
    """Call ``method`` with ``request`` and return the parsed reply.

    Raises the [`HostLibraryError`] subclass the error body's ``code`` names,
    with its ``retryable`` flag set, and the base class for a code this SDK
    does not know.
    """
    fn = invoke if invoke is not None else _invoke
    request_json = b"" if request is None else json.dumps(request, separators=(",", ":")).encode()
    status, body = fn(method, request_json)
    if status == _OK:
        return json.loads(body) if body else None
    invalid_json = False
    try:
        parsed = json.loads(body) if body else None
    except (ValueError, TypeError):
        parsed = None
        invalid_json = True
    # Raise outside the parser's except block so no raw JSON exception/doc is
    # retained as the context of a safe protocol error.
    if invalid_json:
        raise _protocol_error(status)
    fields = parsed if isinstance(parsed, dict) else {}
    code = fields.get("code")
    recovery_details = None
    if status == 12 or code == "RECOVERY_REQUIRED":
        details = fields.get("details")
        if (
            status != 12
            or code != "RECOVERY_REQUIRED"
            or fields.get("retryable") is not False
            or not isinstance(fields.get("message"), str)
            or not isinstance(details, dict)
            or set(details) != {"machine_id", "plan_id", "reason"}
            or not all(isinstance(details[key], str) for key in details)
        ):
            raise _protocol_error(status)
        recovery_details = RecoveryRequiredDetails(**details)
    message = fields.get("message") or f"host library call `{method}` failed (status {status})"
    exc = CODE_ERRORS.get(code if isinstance(code, str) else None, HostLibraryError)(message)
    exc.code = code
    exc.retryable = bool(fields.get("retryable", False))
    exc.status = status
    if recovery_details is not None:
        exc.details = recovery_details
    raise exc
