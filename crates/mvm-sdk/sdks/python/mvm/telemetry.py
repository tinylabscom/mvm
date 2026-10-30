"""One-page host-local telemetry reads; no polling, health inference or file access.

Known envelope fields follow mvm-core's protocol/telemetry/served.rs. The ABI
deliberately leaves replies opaque: additive fields and nested record payloads
are preserved, not fully validated as Rust records. Cursor objects remain closed.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict, cast

from mvm import _hostlib
from mvm._hostabi.methods import TELEMETRY_RECORDS, TELEMETRY_STATUS


class TelemetryError(RuntimeError):
    """The host returned an unusable telemetry envelope, not a typed host refusal."""


class TelemetryCursor(TypedDict):
    offset: int


class Connecting(TypedDict):
    kind: Literal["connecting"]


class Collecting(TypedDict):
    kind: Literal["collecting"]
    generation: int


class Degraded(TypedDict):
    kind: Literal["degraded"]
    code: str


class Stopped(TypedDict):
    kind: Literal["stopped"]


CollectorState = Connecting | Collecting | Degraded | Stopped


class HostLosses(TypedDict):
    queue_full: int
    cap_reached: int
    write_failed: int
    secret_withheld: int


class NotProvisioned(TypedDict):
    collection: Literal["not_provisioned"]


class _StatusOptional(TypedDict, total=False):
    losses: HostLosses
    snapshot_age_ms: int


class Provisioned(_StatusOptional):
    collection: Literal["provisioned"]
    vm_name: str
    state: CollectorState
    shed: int
    records_bytes: int


TelemetryStatus = NotProvisioned | Provisioned


class _ReceivedOptional(TypedDict, total=False):
    received_at_ms: int


class ReceivedRecord(_ReceivedOptional):
    record: dict[str, Any]


class TelemetryPage(TypedDict):
    records: list[ReceivedRecord]
    next_cursor: TelemetryCursor
    undecodable: int
    exhausted: bool


def _uint(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**64


def _cursor(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {"offset"} and _uint(value["offset"])


def _identity(id: str) -> None:
    if not isinstance(id, str) or not id:
        raise ValueError("id must be a non-empty str")


def status(id: str) -> TelemetryStatus:
    """Read the selected machine's collector status without interpreting health."""
    _identity(id)
    reply = _hostlib.call(TELEMETRY_STATUS, {"id": id})
    valid = isinstance(reply, dict)
    if valid and reply.get("collection") == "not_provisioned":
        return cast(TelemetryStatus, reply)
    if valid and reply.get("collection") == "provisioned":
        state = reply.get("state")
        valid = (
            isinstance(reply.get("vm_name"), str)
            and _uint(reply.get("shed")) and _uint(reply.get("records_bytes"))
            and isinstance(state, dict)
        )
        if valid:
            kind = state.get("kind")
            valid = (
                kind in ("connecting", "stopped")
                or kind == "collecting" and _uint(state.get("generation"))
                or kind == "degraded" and isinstance(state.get("code"), str)
            )
        if "snapshot_age_ms" in reply:
            valid = valid and _uint(reply["snapshot_age_ms"])
        if "losses" in reply:
            losses = reply["losses"]
            valid = valid and isinstance(losses, dict) and all(
                _uint(losses.get(field))
                for field in ("queue_full", "cap_reached", "write_failed", "secret_withheld")
            )
        if valid:
            return cast(TelemetryStatus, reply)
    raise TelemetryError("telemetry.status returned an invalid status envelope")


def records(
    id: str, *, cursor: TelemetryCursor | None = None, limit: int | None = None
) -> TelemetryPage:
    """Read one page. Reuse its cursor only for the same machine/record file.

    The host defaults to 256 records and clamps a supplied limit to 1..1024,
    including zero. Exhaustion is a snapshot, not an end-of-session promise.
    """
    _identity(id)
    request: dict[str, Any] = {"id": id}
    if cursor is not None:
        if not _cursor(cursor):
            raise ValueError("cursor must contain only a u64 offset")
        request["cursor"] = dict(cursor)
    if limit is not None:
        if not _uint(limit):
            raise ValueError("limit must be a non-negative u64 integer")
        request["limit"] = limit
    reply = _hostlib.call(TELEMETRY_RECORDS, request)
    valid = (
        isinstance(reply, dict) and isinstance(reply.get("records"), list)
        and _cursor(reply.get("next_cursor")) and _uint(reply.get("undecodable"))
        and type(reply.get("exhausted")) is bool
    )
    if valid:
        valid = all(
            isinstance(item, dict) and isinstance(item.get("record"), dict)
            and ("received_at_ms" not in item or _uint(item["received_at_ms"]))
            for item in reply["records"]
        )
    if not valid:
        raise TelemetryError("telemetry.records returned an invalid page envelope")
    return cast(TelemetryPage, reply)
