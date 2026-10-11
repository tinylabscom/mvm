"""Host-signed exports of registered artifacts. Private keys never cross the ABI."""

from __future__ import annotations

from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import BUNDLE_EXPORT


def export(
    template: str,
    out: str,
    *,
    label: str | None = None,
    cmdline: str | None = None,
    posture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Export a signed bundle. cmdline is a host file path.

    posture uses wire fields profile, allow_egress, allow_volumes, and
    allow_unauthenticated; the client validates all supplied fields.
    """
    return _hostlib.call(
        BUNDLE_EXPORT,
        {"template": template, "out": out, "label": label, "cmdline": cmdline, "posture": posture},
    )
