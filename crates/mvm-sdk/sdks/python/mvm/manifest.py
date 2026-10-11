"""Built-manifest inspection through the host library.

Discovery, verification, and validation are owned by the client facade.
Persisted manifests and snapshots are returned without interpretation.
"""

from __future__ import annotations

import builtins
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import (
    MANIFEST_EXPORT_OCI, MANIFEST_INFO, MANIFEST_LIST, MANIFEST_PRUNE,
    MANIFEST_REMOVE, MANIFEST_VERIFY,
)


def list(
    *, orphans: bool = False, tags: builtins.list[str] | None = None
) -> builtins.list[dict[str, Any]]:
    """List built manifests, optionally restricted to orphans and matching tags."""
    return _hostlib.call(
        MANIFEST_LIST, {"orphans": orphans, "tags": [] if tags is None else tags}
    )


def info(path: str | None = None) -> dict[str, Any]:
    """Inspect a manifest, using the client facade's default when path is omitted."""
    return _hostlib.call(MANIFEST_INFO, {"path": path})


def remove(
    path: str | None = None, *, force: bool = False, manifest_file: bool = False
) -> dict[str, Any]:
    """Remove a local slot without prompting; source deletion requires manifest_file."""
    return _hostlib.call(
        MANIFEST_REMOVE, {"path": path, "force": force, "manifest_file": manifest_file}
    )


def prune(*, orphans: bool = False, dry_run: bool = True) -> dict[str, Any]:
    """Preview orphan removal; select orphans explicitly, and dry_run=False to apply."""
    return _hostlib.call(MANIFEST_PRUNE, {"orphans": orphans, "dry_run": dry_run})


def export_oci(template: str, out: str) -> dict[str, Any]:
    """Copy the registered template's existing OCI archive to a host path."""
    return _hostlib.call(MANIFEST_EXPORT_OCI, {"template": template, "out": out})


def verify(
    path: str | None = None,
    *,
    revision: str | None = None,
    check_signature: bool = False,
) -> dict[str, Any]:
    """Verify a built manifest using the client facade's verification policy."""
    return _hostlib.call(
        MANIFEST_VERIFY,
        {"path": path, "revision": revision, "check_signature": check_signature},
    )
