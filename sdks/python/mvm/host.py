"""``mvm.host`` — host-services clock + cost (``host.time.v1`` / ``host.cost.v1``).

A workload running inside the microVM reads the host wall-clock and its
accumulated spend:

    import mvm
    now_ms = mvm.host.time()
    spent = mvm.host.cost()              # this workload, micro-USD
    tenant_spent = mvm.host.cost("tenant")

Both ride the same broker transport as :mod:`mvm.audit`. Scope is the verb, so a
workload can only read its own / its tenant's spend.
"""

from __future__ import annotations

from typing import Optional

from mvm._broker import transport
from mvm._broker.services import CostReport, TimeNowResponse

HOST_TIME_SERVICE = "host.time.v1"
HOST_COST_SERVICE = "host.cost.v1"


class HostServiceError(transport.BrokerError):
    """A ``host.time.v1`` / ``host.cost.v1`` call failed."""


def time(
    *,
    timeout_secs: float = 5.0,
    connect: Optional[transport.Connect] = None,
) -> int:
    """Host wall-clock in milliseconds since the Unix epoch."""
    try:
        payload = transport.call(
            HOST_TIME_SERVICE, "now", {}, timeout_secs=timeout_secs, connect=connect
        )
    except transport.BrokerServiceError as e:
        raise HostServiceError(str(e)) from e
    return TimeNowResponse(**payload).wall_ms


def cost(
    scope: str = "workload",
    *,
    timeout_secs: float = 5.0,
    connect: Optional[transport.Connect] = None,
) -> int:
    """Accumulated spend for ``scope`` (``"workload"`` or ``"tenant"``), in
    micro-USD (1e-6 USD)."""
    if scope not in ("workload", "tenant"):
        raise ValueError(f"cost scope must be 'workload' or 'tenant', got {scope!r}")
    try:
        payload = transport.call(
            HOST_COST_SERVICE, scope, {}, timeout_secs=timeout_secs, connect=connect
        )
    except transport.BrokerServiceError as e:
        raise HostServiceError(str(e)) from e
    return CostReport(**payload).spent_micros_usd
