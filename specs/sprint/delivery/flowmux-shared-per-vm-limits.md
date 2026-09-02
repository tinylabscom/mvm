# FlowMux limits belong to the VM, not a session

An admitted workload's signed `NetworkLimits` now travel with the endpoint
spawn request and configuration into the FlowMux endpoint. The endpoint
validates those limits before binding and creates one VM-scoped resource owner
for its lifetime. It no longer constructs a fresh default budget for every
authenticated session.

The shared owner accounts for aggregate TCP and HTTP streams, UDP associations,
DNS queries, mediated ICMP, declared-ingress listeners, and connection-rate
tokens. RAII permits return capacity when a flow is refused, cancelled, reaches
EOF, or its session ends. A separate 16-session ceiling is acquired before the
handshake, so unauthenticated or stalled clients cannot multiply per-session
workers without bound.

The propagation path covers cold and warm runtime launches, the wasm backend,
and endpoint construction. A present admitted plan is parsed and validated;
only launches with no admitted plan use the documented defaults. Deserialized
zero ceilings are rejected rather than silently repaired.

Witnesses include serde and validation tests, admitted-plan-to-registry mapping,
cross-session exhaustion, reconnect and teardown permit release, shared rate
limiting, ingress reservation, session-cap enforcement, and a real endpoint
subprocess proving two authenticated sessions share one UDP ceiling. A second
subprocess test proves malformed decoded limits fail before socket setup. The
workspace nextest suite (12,496 tests), workspace check, host all-target Clippy,
Linux gated compilation, BDD-feature check and Clippy, and the endpoint
subprocess suite pass.
