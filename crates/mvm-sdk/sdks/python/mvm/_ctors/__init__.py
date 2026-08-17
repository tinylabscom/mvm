"""SDK constructors, generated from `schema/sdk-ctors-v0.json`.

Do not edit `generated.py` by hand. The parameters, defaults and runtime
constraints are owned by the Rust registry at
`crates/mvm-sdk/src/ctor_registry.rs`; to refresh after a change there,
run `cargo xtask gen-stubs` from the workspace root.
"""

from mvm._ctors.generated import (
    dns_none,
    dns_resolver,
    dns_system,
    egress,
    host_port,
    no_deps,
    node_deps,
    python_deps,
    warm_process,
)

__all__ = [
    "dns_none",
    "dns_resolver",
    "dns_system",
    "egress",
    "host_port",
    "no_deps",
    "node_deps",
    "python_deps",
    "warm_process",
]
