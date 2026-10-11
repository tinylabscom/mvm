"""Host-local maintenance through the client-backed host library."""

from mvm import _hostlib
from mvm._hostabi.methods import MAINTENANCE_RECONCILE


def reconcile(*, apply: bool = False) -> dict[str, list[str]]:
    """Preview registry drift, or repair it with explicit ``apply=True``.

    Non-fatal repair errors are returned in the report's ``errors`` list.
    This operates on the host registry, not a guest or a remote gateway.
    """
    return _hostlib.call(MAINTENANCE_RECONCILE, {"apply": apply})
