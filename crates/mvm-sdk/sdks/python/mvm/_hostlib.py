"""Host-side transport: the host library, loaded in-process.

The SDK drives machines by calling ``libmvm_hostlib``, the same machine and
guest surface ``mvmctl`` uses, through its C ABI: JSON in, JSON out, an
``i32`` status, a paired free. No process is spawned — not ``mvmctl``, and
not a helper standing in for it.

Where the library comes from, in order:

1. ``MVM_HOSTLIB_PATH``, the library file itself.
2. Beside ``mvmctl`` on ``PATH``. The release ships them side by side; the
   binary is located, never run.
3. Otherwise [`MvmTransportError`], naming both.

Before the first call the binding tells the library which ABI it was built
for, and the library refuses every call until that succeeds, so a binding
and library that disagree about the buffer layout cannot exchange one.
"""

import ctypes
import json
import os
import shutil
import sys
import threading
from typing import Any, Callable, List, Optional, Tuple

from mvm._errors.types import (
    CODE_ERRORS,
    STATUS_OK as _OK,
    HostLibraryAbiError,
    HostLibraryError,
    MvmTransportError,
)
from mvm._hostabi.methods import ABI_MAJOR, ABI_MINOR

#: Environment variable naming the library file.
LIB_PATH_ENV = "MVM_HOSTLIB_PATH"

#: The ABI this binding was written against, generated from the host
#: registry (`mvm._hostabi.methods`). A library with another major, or an
#: older minor, refuses it.


def library_file_name(platform: str = sys.platform) -> str:
    """The library's file name on ``platform``."""
    return "libmvm_hostlib.dylib" if platform == "darwin" else "libmvm_hostlib.so"


def candidate_paths(
    environ: Optional[dict] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    platform: str = sys.platform,
) -> List[str]:
    """Where to look for the library, in order. Pure, for testing: it names
    paths and reads no files."""
    env = os.environ if environ is None else environ
    explicit = env.get(LIB_PATH_ENV)
    if explicit:
        return [explicit]
    name = library_file_name(platform)
    found = which("mvmctl")
    if not found:
        return []
    paths = [os.path.join(os.path.dirname(found), name)]
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
) -> str:
    """The first candidate that exists, or [`MvmTransportError`]."""
    env = os.environ if environ is None else environ
    candidates = candidate_paths(env, which, platform)
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
        f"{LIB_PATH_ENV} to its path, or put the directory holding it and mvmctl "
        "on PATH"
    )


class _Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


_lock = threading.Lock()
_lib: Optional[ctypes.CDLL] = None


def _load() -> ctypes.CDLL:
    """Load the library once, declare its signatures, and negotiate the ABI."""
    global _lib
    with _lock:
        if _lib is not None:
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
        if lib.mvm_hostlib_abi_is_compatible(ABI_MAJOR, ABI_MINOR) != 1:
            version = lib.mvm_hostlib_abi_version()
            raise HostLibraryAbiError(
                f"the host library implements ABI {version >> 16}.{version & 0xFFFF}, and "
                f"this SDK needs {ABI_MAJOR}.{ABI_MINOR}; install matching versions"
            )
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
    parsed = json.loads(body) if body else None
    if status == _OK:
        return parsed
    fields = parsed if isinstance(parsed, dict) else {}
    message = fields.get("message") or f"host library call `{method}` failed (status {status})"
    exc = CODE_ERRORS.get(fields.get("code"), HostLibraryError)(message)
    exc.code = fields.get("code")
    exc.retryable = bool(fields.get("retryable", False))
    exc.status = status
    raise exc
