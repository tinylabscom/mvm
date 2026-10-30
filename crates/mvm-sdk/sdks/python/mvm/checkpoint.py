"""Host-local checkpoint operations through the client-owned host service."""

from __future__ import annotations

import builtins
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import CHECKPOINT_LIST, CHECKPOINT_REMOVE


def list() -> builtins.list[dict[str, Any]]:
    """Return complete metadata in ID order, preserving omitted legacy fields.

    This is catalog data, not authenticated lineage or permission to restore.
    A missing catalog is empty; unsafe or malformed metadata raises a host error.
    """
    return _hostlib.call(CHECKPOINT_LIST, {})


def remove(id: str) -> None:
    """Remove a host-local checkpoint after metadata, pin and descendant checks.

    A missing directory is already removed. Incomplete metadata or failed guard
    reads refuse deletion. These preflight checks do not serialize concurrent
    pin, lineage or path changes, and grant no guest or remote deletion authority.
    """
    _hostlib.call(CHECKPOINT_REMOVE, {"id": id})
