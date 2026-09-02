"""``mvm.kv`` — the per-workload key-value store (the ``host.kv.v1`` service),
callable from inside a booted workload.

The store lives on the host and is reached over the host-services broker, so a
workload gets durable storage with **no network path and no credential**.

The namespace is not a parameter. The host derives it from the connection, so
one workload cannot address another's keys by asking — there is no argument
here that could name someone else's namespace.

Keys are validated by the host rather than sanitized: a key that would need
rewriting to be safe is refused as [`mvm._hostsvc.BadRequestError`], because a
caller that read back a different key than it wrote has no way to notice.
Values are bounded for the same reason the broker is a control channel and not
a bulk transport — reach for a volume if you have real data.
"""

from typing import List, Optional

from mvm import _hostsvc

HOST_KV_SERVICE = "host.kv.v1"

_DEFAULT_TIMEOUT_SECS = 5.0


def get(key: str, *, timeout_secs: float = _DEFAULT_TIMEOUT_SECS) -> Optional[bytes]:
    """Read ``key``. Returns ``None`` when it is absent.

    Absence is an ordinary outcome, not an error: making it raise would push
    callers into treating a missing key and a broken store alike.
    """
    resp = _hostsvc.call("host.kv.get", {"key": key}, timeout_secs=timeout_secs)
    value = resp.get("value")
    return bytes(value) if value is not None else None


def put(key: str, value: bytes, *, timeout_secs: float = _DEFAULT_TIMEOUT_SECS) -> bool:
    """Write ``key``. Returns whether it replaced an existing value."""
    resp = _hostsvc.call(
        "host.kv.put",
        {"key": key, "value": list(value)},
        timeout_secs=timeout_secs,
    )
    return bool(resp["replaced"])


def delete(key: str, *, timeout_secs: float = _DEFAULT_TIMEOUT_SECS) -> bool:
    """Remove ``key``. Returns whether anything was there to remove."""
    resp = _hostsvc.call("host.kv.delete", {"key": key}, timeout_secs=timeout_secs)
    return bool(resp["removed"])


def list_keys(
    prefix: str = "", *, timeout_secs: float = _DEFAULT_TIMEOUT_SECS
) -> List[str]:
    """List this workload's keys under ``prefix``, sorted.

    Named ``list_keys`` rather than ``list`` so it does not shadow the builtin
    for anyone doing ``from mvm.kv import *``.
    """
    resp = _hostsvc.call("host.kv.list", {"prefix": prefix}, timeout_secs=timeout_secs)
    return list(resp["keys"])
