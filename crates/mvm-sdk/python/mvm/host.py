"""``mvm.host`` — host-services clock + cost (``host.time.v1`` /
``host.cost.v1``), callable from inside a booted workload.

Both ride the same broker transport as ``mvm.audit`` and carry an empty body —
the scope is the verb, so a workload cannot ask for another scope's clock or
spend. Host refusals surface as typed [`mvm._hostsvc.HostServiceError`]
subclasses (e.g. [`mvm._hostsvc.NotBoundError`] when the service is unbound).
"""

from mvm import _hostsvc

HOST_TIME_SERVICE = "host.time.v1"
HOST_COST_SERVICE = "host.cost.v1"

_DEFAULT_TIMEOUT_SECS = 5.0


def time(*, timeout_secs: float = _DEFAULT_TIMEOUT_SECS) -> int:
    """Host wall-clock in milliseconds since the Unix epoch."""
    resp = _hostsvc.call("host.time.now", {}, timeout_secs=timeout_secs)
    return resp["wall_ms"]


def cost(scope: str = "workload", *, timeout_secs: float = _DEFAULT_TIMEOUT_SECS) -> int:
    """Accumulated spend for ``scope`` (``"workload"`` or ``"tenant"``), in
    micro-USD (1e-6 USD)."""
    if scope not in ("workload", "tenant"):
        raise ValueError(f"cost scope must be 'workload' or 'tenant', got {scope!r}")
    resp = _hostsvc.call(f"host.cost.{scope}", {}, timeout_secs=timeout_secs)
    return resp["spent_micros_usd"]
