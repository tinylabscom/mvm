"""Shared CLI resolution helpers for the Python SDK."""

from __future__ import annotations

import os
import shutil

# Owned by the Rust registry (crates/mvm-sdk/src/env.rs), generated into
# `_env/vars.py`. Re-exported here so existing importers of
# `mvm._cli.MVM_CLI_BIN_ENV` keep working.
from mvm._env.vars import MVM_CLI_BIN_ENV

MVM_LEGACY_CLI_BIN_ENV = "MVM_MVM_BIN"
SDK_CLI_CANDIDATES = ("mvmctl",)


def cli_resolution_hint() -> str:
    """Return the actionable CLI-install hint shared across SDK surfaces."""
    return (
        f"set {MVM_CLI_BIN_ENV}=/path/to/mvmctl, or install "
        "`mvmctl` on PATH."
    )


def resolve_cli_bin(*, purpose: str, include_legacy_env: bool = False) -> str:
    """Resolve the CLI used by the SDK.

    Resolution order is:
    1. ``MVM_CLI_BIN``
    2. ``MVM_MVM_BIN`` when ``include_legacy_env`` is enabled
    3. ``mvmctl`` on ``PATH``
    """
    explicit = os.environ.get(MVM_CLI_BIN_ENV)
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        raise RuntimeError(
            f"{MVM_CLI_BIN_ENV} points at {explicit!r} but it is not an executable file; "
            f"{cli_resolution_hint()}"
        )

    if include_legacy_env:
        legacy = os.environ.get(MVM_LEGACY_CLI_BIN_ENV)
        if legacy:
            if os.path.isfile(legacy) and os.access(legacy, os.X_OK):
                return legacy
            raise RuntimeError(
                f"{MVM_LEGACY_CLI_BIN_ENV} points at {legacy!r} but it is not an executable file; "
                f"{cli_resolution_hint()}"
            )

    for candidate in SDK_CLI_CANDIDATES:
        found = shutil.which(candidate)
        if found is not None:
            return found

    raise RuntimeError(f"{purpose} requires the mvm CLI; {cli_resolution_hint()}")
