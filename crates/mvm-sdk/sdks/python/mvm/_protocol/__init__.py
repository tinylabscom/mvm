"""Host↔guest RPC protocol types, generated from `schema/protocol-v0.json`.

Do not edit `protocol.py` by hand. To refresh after a Rust protocol
change, run `cargo xtask gen-stubs` from the workspace root.

`Protocol` is the schema root (both wire directions under one document);
`GuestRequest` is the verb the host sends the agent, `GuestResponse`
what the agent returns.
"""

from mvm._protocol.protocol import GuestRequest, GuestResponse, Protocol

__all__ = ["GuestRequest", "GuestResponse", "Protocol"]
