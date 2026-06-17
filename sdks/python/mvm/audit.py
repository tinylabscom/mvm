"""``mvm.audit`` — workload-emitted audit entries (the ``host.audit.v1``
service), callable from inside a booted workload.

``emit`` / ``emit_batch`` append to the chain-signed per-VM workload audit log
over the host-services broker. The request carries no ``category``: the host
handler forces ``workload_audit`` and stamps the host-authoritative IDs, so a
workload can never write a host-category entry (claim 8). The 4 KiB per-record
cap and the rate limit are likewise host-enforced and surface here as typed
[`mvm._hostsvc.BadRequestError`] / [`mvm._hostsvc.RateLimitedError`].
"""

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from mvm import _hostsvc

HOST_AUDIT_SERVICE = "host.audit.v1"

_DEFAULT_TIMEOUT_SECS = 5.0


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(
    fields: Any,
    ts: Optional[str] = None,
    *,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
) -> str:
    """Append one audit entry. ``fields`` is opaque workload JSON; ``ts`` is an
    RFC 3339 timestamp (defaults to now). Returns the new chain head."""
    record = {"ts": ts or _now_rfc3339(), "fields": fields}
    resp = _hostsvc.call("host.audit.emit", record, timeout_secs=timeout_secs)
    return resp["chain_head"]


def emit_batch(
    entries: Iterable[Any],
    *,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
) -> str:
    """Append a batch of audit entries in one call. Each item is opaque
    workload JSON (the record ``fields``), stamped with the current time.
    Returns the final chain head."""
    now = _now_rfc3339()
    batch = {"entries": [{"ts": now, "fields": fields} for fields in entries]}
    resp = _hostsvc.call("host.audit.emit_batch", batch, timeout_secs=timeout_secs)
    return resp["chain_head"]
