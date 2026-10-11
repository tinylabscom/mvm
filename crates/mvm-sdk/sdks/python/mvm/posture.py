"""Security posture for the configured host, without root or trust-key overrides."""
from typing import Any

from mvm import _hostlib
from mvm._hostabi.methods import POSTURE_INSPECT


def inspect() -> dict[str, Any]:
    return _hostlib.call(POSTURE_INSPECT, {})
