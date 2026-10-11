"""Durable local sessions; unrelated to the short-lived session authoring API.

Mutations require intent="execute". No mutation in this namespace has a preview.
"""
from __future__ import annotations
import builtins
from typing import Any, Literal

from mvm import _hostlib
from mvm._hostabi.methods import (
    AGENT_SESSIONS_LIST, AGENT_SESSIONS_SHOW, AGENT_SESSIONS_OPEN,
    AGENT_SESSIONS_PARK, AGENT_SESSIONS_RENEW, AGENT_SESSIONS_RESUME,
)


def list() -> builtins.list[dict[str, Any]]:
    return _hostlib.call(AGENT_SESSIONS_LIST, {})


def show(session_id: str) -> dict[str, Any]:
    return _hostlib.call(AGENT_SESSIONS_SHOW, {"session_id": session_id})


def open(
    session_id: str, *, intent: Literal["execute"], members: builtins.list[str] | None = None,
    resume_point: str | None = None,
) -> dict[str, Any]:
    return _hostlib.call(AGENT_SESSIONS_OPEN, {"intent": intent, "request": {
        "session_id": session_id, "members": [] if members is None else members,
        "resume_point": resume_point,
    }})


def park(
    session_id: str, *, intent: Literal["execute"], reason: str, journal_cursor: int,
    approval_head: str | None = None, retain_for: str | None = None,
    expected_generation: int | None = None,
) -> dict[str, Any]:
    return _hostlib.call(AGENT_SESSIONS_PARK, {"intent": intent, "request": {
        "session_id": session_id, "reason": reason, "journal_cursor": journal_cursor,
        "approval_head": approval_head, "retain_for": retain_for,
        "expected_generation": expected_generation,
    }})


def renew(
    session_id: str, *, intent: Literal["execute"], extend_for: str,
    expected_deadline: int | None = None, expected_generation: int | None = None,
) -> dict[str, Any]:
    return _hostlib.call(AGENT_SESSIONS_RENEW, {"intent": intent, "request": {
        "session_id": session_id, "extend_for": extend_for,
        "expected_deadline": expected_deadline, "expected_generation": expected_generation,
    }})


def resume(
    session_id: str, *, intent: Literal["execute"], backend: str, image: str,
    image_sha256: str, cpus: int, mem_mib: int, boot: bool,
    kernel_sha256: str | None = None, approval_head: str | None = None,
    kernel: str | None = None, expected_generation: int | None = None,
) -> dict[str, Any]:
    """Re-admit using host signer custody. boot=False still mutates session state."""
    return _hostlib.call(AGENT_SESSIONS_RESUME, {"intent": intent, "request": {
        "session_id": session_id, "backend": backend, "image": image,
        "image_sha256": image_sha256, "kernel_sha256": kernel_sha256,
        "cpus": cpus, "mem_mib": mem_mib, "approval_head": approval_head, "boot": boot,
        "kernel": kernel, "expected_generation": expected_generation,
    }})
