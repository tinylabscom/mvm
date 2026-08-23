# One endpoint and one socket owner are permanent invariants

The FlowMux migration ratchets have been replaced by
`xtask check-single-network-path`, a permanent architecture gate. It pins every
networked workload runner to the shared endpoint spawner and `NetworkFlow`
channel, requires exactly one production endpoint spawn implementation, and
rejects reintroduced raw-packet, L3, guest-NIC, gateway, or stale public-mode
symbols.

The same gate inventories production TCP/UDP connects and listener binds.
Workload traffic may be originated only by the per-VM endpoint and its exact
support modules; unrelated host infrastructure has a narrow, purpose-labelled
file exemption. A new socket owner therefore fails CI instead of creating an
unreviewed policy bypass.

Endpoint construction now creates one projection from the admitted signed
plan and shares its policy gate, resource budget, VM identity, VM resource,
limits, audit recorder, and declared-ingress transports across every session.
Tests prove pointer identity for TCP, UDP, DNS, typed connector, and ingress
consumers, including the connector service's gate and recorder.

Synthetic gate fixtures cover second endpoints, runner and channel drift,
retired symbols, guest NICs, stale compatibility spellings, unauthorized
connects and binds, and the exact permitted cases. Host all-target/all-feature
Clippy, the complete workspace test and doctest suite, Linux all-target and
BDD-feature gated compilation, and all 56 BDD features pass (194 scenarios:
193 passed and one capability-gated skip). Formatting, dependency, advisory,
license, source, ban, duplicate-major, closure-budget, conformance, claim,
workflow-path, process-citation, sprint-append, one-guest-protocol, and
permanent networking checks pass.

The workspace regression for the host-binary manifest gate executes Cargo's
already-built `xtask` integration-test binary. This keeps the behavioral check
while preventing a redundant nested workspace compilation from overlapping
doctests and causing nondeterministic compiler exits.
