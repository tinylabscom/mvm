"""In-guest witness for `host.kv.v1`: write a key, read it back, list it, drop it.

Runs *inside* a booted workload. It deliberately does not import `mvm` — the
package is not in an arbitrary guest image — and instead speaks the same C ABI
the SDK does, so the witness covers the real path a workload takes: guest code
-> the sidecar cdylib -> vsock -> the broker -> the host store, and back.

Prints `KV-OK` on success. Any failure raises, so the run exits nonzero and the
scenario fails with the reason rather than a bare assertion.
"""

import ctypes
import json
import os
import sys

LIB = os.environ.get("MVM_HOST_SERVICES_LIB", "/mvm/sdk/lib/libmvm_host_services.so")


class Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


def call(lib, method: str, request: dict, timeout_secs: int = 5) -> dict:
    m = method.encode()
    r = json.dumps(request).encode()
    out = Buf()
    status = lib.mvm_hsvc_call(m, len(m), r, len(r), timeout_secs, ctypes.byref(out))
    body = b""
    if out.data and out.len:
        body = bytes(bytearray(ctypes.cast(
            out.data, ctypes.POINTER(ctypes.c_uint8 * out.len)).contents))
    lib.mvm_hsvc_free(out)
    if status != 0:
        raise RuntimeError(f"{method} failed status={status} body={body!r}")
    return json.loads(body) if body else {}


def main() -> int:
    lib = ctypes.CDLL(LIB)
    lib.mvm_hsvc_call.restype = ctypes.c_int
    lib.mvm_hsvc_call.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_uint64, ctypes.POINTER(Buf),
    ]
    lib.mvm_hsvc_free.argtypes = [Buf]

    key, value = "bdd-witness", [1, 2, 3]

    # Absent before the write: proves the read is answering about this key
    # rather than returning something left over.
    first = call(lib, "host.kv.get", {"key": key})
    assert first.get("value") is None, f"expected absent, got {first}"

    put = call(lib, "host.kv.put", {"key": key, "value": value})
    assert put["replaced"] is False, f"first write must not replace: {put}"

    got = call(lib, "host.kv.get", {"key": key})
    assert got.get("value") == value, f"round trip lost the value: {got}"

    listed = call(lib, "host.kv.list", {"prefix": "bdd-"})
    assert key in listed["keys"], f"key missing from listing: {listed}"

    removed = call(lib, "host.kv.delete", {"key": key})
    assert removed["removed"] is True, f"delete reported nothing removed: {removed}"

    after = call(lib, "host.kv.get", {"key": key})
    assert after.get("value") is None, f"key survived delete: {after}"

    print("KV-OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
