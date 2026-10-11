"""Configured-host verified audit session queries; never raw unchecked lines."""
from __future__ import annotations
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import AUDIT_SESSIONS_LIST, AUDIT_SESSIONS_SHOW, AUDIT_SESSIONS_VERIFY


def list(
    *, tenant: str = "local", since: str | None = None, until: str | None = None,
) -> dict[str, Any]:
    return _hostlib.call(AUDIT_SESSIONS_LIST, {
        "tenant": tenant, "range": {"since": since, "until": until},
    })


def show(
    selector: str, *, tenant: str = "local", kind: str | None = None,
    since: str | None = None, until: str | None = None,
) -> dict[str, Any]:
    return _hostlib.call(AUDIT_SESSIONS_SHOW, {
        "tenant": tenant, "selector": selector,
        "filter": {"kind": kind, "range": {"since": since, "until": until}},
    })


def verify(selector: str, *, tenant: str = "local") -> dict[str, Any]:
    return _hostlib.call(AUDIT_SESSIONS_VERIFY, {"tenant": tenant, "selector": selector})
