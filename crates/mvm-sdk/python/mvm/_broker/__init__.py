"""Host-services broker wire types, generated from `schema/broker-services-v0.json`.

Do not edit `services.py` by hand. To refresh after a Rust broker-type
change, run `cargo xtask gen-stubs` from the workspace root.

These are the `ServiceCall`/`ServiceResponse` envelope + the typed
`host.audit.v1` / `host.time.v1` / `host.cost.v1` payloads an in-guest
workload exchanges with the per-VM broker over vsock `BROKER_PORT`. The
thin transport veneer (`mvm.audit.emit` / `mvm.host.time` / `mvm.host.cost`)
rides on top of these.
"""

from mvm._broker.services import (
    BrokerServices,
    CostReport,
    EmitBatchRequest,
    EmitBatchResponse,
    EmitRequest,
    EmitResponse,
    ServiceCall,
    ServiceErrorCode,
    ServiceResponse,
    TimeNowResponse,
)

__all__ = [
    "BrokerServices",
    "CostReport",
    "EmitBatchRequest",
    "EmitBatchResponse",
    "EmitRequest",
    "EmitResponse",
    "ServiceCall",
    "ServiceErrorCode",
    "ServiceResponse",
    "TimeNowResponse",
]
