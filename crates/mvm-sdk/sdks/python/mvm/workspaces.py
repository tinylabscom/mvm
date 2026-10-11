"""Stateless reviewed host workspace changes.

Review can recover interrupted work. Mandatory protected paths cannot be disabled.
Apply requires the returned fingerprint and explicit approval; no plan is accepted.
"""
from __future__ import annotations
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import WORKSPACE_APPLY, WORKSPACE_REDO, WORKSPACE_REVIEW, WORKSPACE_UNDO


def _workspace(
    vm: str, volume: str | None, exclude: list[str] | None, protected_paths: list[str] | None,
) -> dict[str, Any]:
    return {"vm": vm, "volume": volume, "exclude": [] if exclude is None else exclude,
            "protected_paths": [] if protected_paths is None else protected_paths}


def review(
    vm: str, *, volume: str | None = None, exclude: list[str] | None = None,
    protected_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Return review status, safe changes, fingerprint when ready, and recoveries."""
    return _hostlib.call(WORKSPACE_REVIEW, _workspace(vm, volume, exclude, protected_paths))


def apply(
    vm: str, expected_fingerprint: str, *, approved: bool = False,
    volume: str | None = None, exclude: list[str] | None = None,
    protected_paths: list[str] | None = None,
) -> dict[str, Any]:
    return _hostlib.call(WORKSPACE_APPLY, {
        "workspace": _workspace(vm, volume, exclude, protected_paths),
        "expected_fingerprint": expected_fingerprint, "approved": approved,
    })


def undo(vm: str, *, approved: bool = False, volume: str | None = None) -> dict[str, Any]:
    return _hostlib.call(WORKSPACE_UNDO, {
        "workspace": _workspace(vm, volume, None, None), "approved": approved,
    })


def redo(vm: str, *, approved: bool = False, volume: str | None = None) -> dict[str, Any]:
    return _hostlib.call(WORKSPACE_REDO, {
        "workspace": _workspace(vm, volume, None, None), "approved": approved,
    })
