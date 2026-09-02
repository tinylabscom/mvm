# Declared ingress uses the authenticated FlowMux endpoint

Signed workload IR and execution plans now carry transport-neutral ingress
mappings: a non-zero mapping ID, TCP or UDP transport, exact host bind, guest
loopback target, transformation class, and an optional same-plan TLS material
reference. Rust, Python, TypeScript, generated schema, synthesis, and endpoint
spawn configuration use the same shape.

The endpoint binds only those admitted listeners before readiness. TCP ingress
allocates host-owned even stream IDs and waits for `InboundReady` before
relaying; the guest connects only to the mapping's declared loopback target.
UDP ingress keeps a bounded observed-peer table per mapping, and replies can
address only peers that previously sent a datagram to that listener. Exact and
explicit wildcard binds, duplicate and unavailable binds, undeclared mappings,
listener and peer exhaustion, guest refusal, and socket release all have
fail-closed witnesses.

Opaque TCP crosses the same FlowMux lifecycle without inspection. HTTP and TLS
connections instead pass through a bounded host-side streaming transformer:
request replacement/redaction completes before each chunk reaches the guest,
response reinjection/redaction completes before each chunk reaches the external
peer, ambiguous or oversized framing is refused, and audit events carry only
mapping IDs, verdicts, stable reason classes, and counters. TLS certificate and
key material is resolved from its signed keystore reference inside the
endpoint and is never serialized into the guest mapping or FlowMux frames.
The unused second ingress broker/handler model is deleted.

Verification includes focused endpoint, FlowMux host/guest, protocol-state,
schema/SDK parity, streaming-transform, TLS-material, audit, teardown, and
mutation-witness tests; strict `mvm-hostd` all-target Clippy; host and x86_64
Linux all-target workspace checks; and the complete BDD suite: 56 features,
212 scenarios (211 passed, one capability-gated skip), and 867 steps.
