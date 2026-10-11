"""Verified prompt replay. Preview is the default; no plaintext inputs are returned."""
from __future__ import annotations
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import REPLAY_RUN_SESSION


def run_session(
    session_id: str, *, tenant: str, timeout_secs: int, dry_run: bool = True,
    from_checkpoint: str | None = None, as_name: str | None = None,
) -> dict[str, Any]:
    """Set dry_run=False to fork, boot and replay. Guest output is not streamed."""
    return _hostlib.call(REPLAY_RUN_SESSION, {
        "selection": {"session_id": session_id, "from": from_checkpoint, "as_name": as_name},
        "dry_run": dry_run, "timeout_secs": timeout_secs, "tenant": tenant,
    })
