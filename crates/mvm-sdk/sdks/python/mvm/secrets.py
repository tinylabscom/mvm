"""Host-local secret metadata, never stored secret values."""

from __future__ import annotations

from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import SECRET_GET


def get(name: str, *, tenant: str = "local") -> dict[str, Any] | None:
    """Return metadata for a local secret, or None when absent.

    Storage faults raise a host-library error rather than looking like absence.
    No value is decrypted or returned.
    """
    return _hostlib.call(SECRET_GET, {"tenant": tenant, "name": name})
