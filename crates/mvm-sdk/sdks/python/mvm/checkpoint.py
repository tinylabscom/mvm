"""Read-only checkpoint catalog access through the client-owned host service."""

from __future__ import annotations

import builtins
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import CHECKPOINT_LIST


def list() -> builtins.list[dict[str, Any]]:
    """Return complete metadata in ID order, preserving omitted legacy fields.

    This is catalog data, not authenticated lineage or permission to restore.
    A missing catalog is empty; unsafe or malformed metadata raises a host error.
    """
    return _hostlib.call(CHECKPOINT_LIST, {})
