"""Local checkpoint catalog and complete client-owned mutations.

Image-revert launch handoffs and revert/rewind/advance are unavailable here.
"""
from __future__ import annotations
import builtins
from typing import Any, Literal

from mvm import _hostlib
from mvm._hostabi.methods import (
    CHECKPOINTS_LIST, CHECKPOINTS_INFO, CHECKPOINTS_DIFF, CHECKPOINTS_VERIFY,
    CHECKPOINTS_TIMELINE, CHECKPOINTS_REMOVE, CHECKPOINTS_CAPTURE,
    CHECKPOINTS_RESTORE, CHECKPOINTS_FORK,
)


def list() -> builtins.list[dict[str, Any]]:
    return _hostlib.call(CHECKPOINTS_LIST, {})


def info(id: str) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_INFO, {"id": id})


def diff(a: str, b: str) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_DIFF, {"a": a, "b": b})


def verify(id: str) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_VERIFY, {"id": id})


def timeline(target: str, *, kind: str | None = None) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_TIMELINE, {"target": target, "kind": kind})


def remove(id: str, *, intent: Literal["execute"]) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_REMOVE, {"intent": intent, "request": {"id": id}})


def capture(
    name: str, *, intent: Literal["execute"], checkpoint_class: Literal["fs_quick", "vm_full"],
    tag: str | None = None,
) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_CAPTURE, {"intent": intent, "request": {
        "name": name, "class": checkpoint_class, "tag": tag,
    }})


def restore(id: str, *, intent: Literal["execute"], tenant: str) -> dict[str, Any]:
    return _hostlib.call(CHECKPOINTS_RESTORE, {"intent": intent, "request": {
        "id": id, "tenant": tenant,
    }})


def fork(
    id: str, *, intent: Literal["execute"], tenant: str, boot: bool,
    new_id: str | None = None, hypervisor: str = "", cpus: int | None = None,
    memory: str | None = None,
) -> dict[str, Any]:
    """A vm_full fork boots even with boot=False. Secret rebinding is not exposed."""
    return _hostlib.call(CHECKPOINTS_FORK, {"intent": intent, "request": {
        "id": id, "new_id": new_id, "boot": boot, "hypervisor": hypervisor,
        "cpus": cpus, "memory": memory, "tenant": tenant,
    }})
