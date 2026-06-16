"""``mvm.audit`` — workload-emitted audit entries (the ``host.audit.v1`` service).

A workload running inside the microVM appends to its chain-signed audit log:

    import mvm
    mvm.audit.emit({"action": "login", "user": "alice"})

The host forces ``category: workload_audit``, stamps the authoritative ids,
rate/size-caps, and chain-signs the entry — a workload can never write a
host-category entry (the request carries no category). The 4 KiB per-record cap
and 20/s rate limit are host-enforced; this surfaces the host's refusal as a
typed error.
"""

from __future__ import annotations

import datetime
from typing import Any, List, Optional

from mvm._broker import transport
from mvm._broker.services import EmitBatchResponse, EmitResponse

HOST_AUDIT_SERVICE = "host.audit.v1"


class AuditError(transport.BrokerError):
    """A ``host.audit.v1`` call failed."""


class AuditBadRequest(AuditError):
    """The host rejected the record shape/size (e.g. over the 4 KiB cap)."""


class AuditRateLimited(AuditError):
    """The per-workload audit emit rate limit (20/s) is exhausted."""


class AuditUnavailable(AuditError):
    """The host could not reach the audit signer (broker/signer down)."""


def _now_rfc3339() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _map_service_error(e: transport.BrokerServiceError) -> AuditError:
    return {
        "bad_request": AuditBadRequest,
        "rate_limit_exceeded": AuditRateLimited,
        "unavailable": AuditUnavailable,
        "not_ready": AuditUnavailable,
    }.get(e.code, AuditError)(str(e))


def emit(
    fields: Any,
    ts: Optional[str] = None,
    *,
    timeout_secs: float = 5.0,
    connect: Optional[transport.Connect] = None,
) -> EmitResponse:
    """Append one audit entry. ``fields`` is opaque workload JSON; ``ts`` is an
    RFC 3339 timestamp (defaults to now). Returns the new chain head."""
    record = {"ts": ts or _now_rfc3339(), "fields": fields}
    try:
        payload = transport.call(
            HOST_AUDIT_SERVICE, "emit", record, timeout_secs=timeout_secs, connect=connect
        )
    except transport.BrokerServiceError as e:
        raise _map_service_error(e) from e
    return EmitResponse(**payload)


def emit_batch(
    entries: List[Any],
    *,
    timeout_secs: float = 5.0,
    connect: Optional[transport.Connect] = None,
) -> EmitBatchResponse:
    """Append a batch of entries. Each item is either a ``{"ts", "fields"}``
    record dict or bare ``fields`` (timestamped now). Returns the final chain
    head plus a per-entry status array."""
    records = [
        e if isinstance(e, dict) and "fields" in e else {"ts": _now_rfc3339(), "fields": e}
        for e in entries
    ]
    try:
        payload = transport.call(
            HOST_AUDIT_SERVICE,
            "emit_batch",
            {"entries": records},
            timeout_secs=timeout_secs,
            connect=connect,
        )
    except transport.BrokerServiceError as e:
        raise _map_service_error(e) from e
    return EmitBatchResponse(**payload)
