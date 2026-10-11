"""Host-local published artifact inspection, validation and configuration."""
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import (
    ARTIFACT_CONFIGURE_FIRECRACKER, ARTIFACT_INSPECT, ARTIFACT_VALIDATE,
)


def inspect(id: str) -> dict[str, Any]:
    return _hostlib.call(ARTIFACT_INSPECT, {"id": id})


def validate(id: str) -> dict[str, Any]:
    return _hostlib.call(ARTIFACT_VALIDATE, {"id": id})


def configure_firecracker(id: str) -> dict[str, Any]:
    """Explicitly write the artifact's Firecracker configuration."""
    return _hostlib.call(ARTIFACT_CONFIGURE_FIRECRACKER, {"id": id})
