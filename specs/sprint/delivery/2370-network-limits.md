# Transport-neutral signed network limits

Plan 316 Phase 1 now carries endpoint resource ceilings in a signed,
transport-neutral `NetworkLimits` plan type. Defaults preserve the previous
4,096 TCP/HTTP flows, 256 UDP associations, 1,024 DNS bindings, and 16 ingress
listeners. Default values are omitted from serialized plans, preserving the
bytes and signatures of plans authored before the additive field existed.

`ExecutionPlan::effective_network_limits()` is the single compatibility seam:
new plans consume the neutral field, while frozen pre-migration L3 plans project
their legacy flow and DNS values into the same type. The legacy gateway now
uses that accessor rather than reading its transport-specific flow ceiling
directly. Builder, serde, signed-byte compatibility, legacy projection, and
gateway-lowering tests cover the positive and fail-closed paths.
