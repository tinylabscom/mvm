"""Host-local volume operations, distinct from authoring volume declarations.

Lifecycle reads can recover interrupted work. Keys, leases and encryption policy
remain in the client; no raw key material is accepted or returned here.
"""
from __future__ import annotations

from typing import Any, Literal

from mvm import _hostlib
from mvm._hostabi.methods import (
    VOLUME_ATTACHMENTS, VOLUME_CREATE, VOLUME_DETACH, VOLUME_INSPECT, VOLUME_LIST,
    VOLUME_LOCK, VOLUME_MOUNT, VOLUME_RESTORE, VOLUME_SNAPSHOT, VOLUME_UNLOCK,
)


def list() -> list[dict[str, Any]]:
    return _hostlib.call(VOLUME_LIST, {})


def inspect(name: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_INSPECT, {"name": name})


def create(name: str, capacity_mib: int, *, root: str | None = None) -> dict[str, Any]:
    return _hostlib.call(VOLUME_CREATE, {"name": name, "capacity_mib": capacity_mib, "root": root})


def unlock(name: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_UNLOCK, {"name": name})


def lock(name: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_LOCK, {"name": name})


def mount(
    vm: str, volume: str, guest_path: str, *, host: str | None = None,
    access: Literal["read-only", "read-write"] = "read-only",
) -> dict[str, Any]:
    return _hostlib.call(VOLUME_MOUNT, {
        "vm": vm, "volume": volume, "guest_path": guest_path, "host": host, "access": access,
    })


def detach(vm: str, guest_path: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_DETACH, {"vm": vm, "guest_path": guest_path})


def attachments(vm: str) -> list[dict[str, Any]]:
    return _hostlib.call(VOLUME_ATTACHMENTS, {"vm": vm})


def snapshot(name: str, snapshot: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_SNAPSHOT, {"name": name, "snapshot": snapshot})


def restore(name: str, snapshot: str) -> dict[str, Any]:
    return _hostlib.call(VOLUME_RESTORE, {"name": name, "snapshot": snapshot})
