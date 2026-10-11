"""Host-local thin-pool inspection and explicit garbage collection."""

from __future__ import annotations

from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import STORAGE_GC, STORAGE_INFO


def info(*, mock: bool = False) -> dict[str, Any]:
    """Inspect the host pool; an unavailable pool is represented in the report."""
    return _hostlib.call(STORAGE_INFO, {"mock": mock})


def gc(
    *, apply: bool = False, mock: bool = False, keep_prefix: list[str] | None = None
) -> dict[str, Any]:
    """Preview collection by default; keep_prefix retains matching volume names."""
    return _hostlib.call(
        STORAGE_GC,
        {"apply": apply, "mock": mock, "keep_prefix": [] if keep_prefix is None else keep_prefix},
    )
