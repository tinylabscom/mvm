# Typed telemetry contract and encrypted worker transport

Issue #3421, preparatory W2a of `2026-09-17-host-mediated-telemetry`.
Epic #3419 and the runtime acceptance workstreams remain open.

## Implemented boundary

`mvm_core::protocol::telemetry` defines eight closed record families: span
open/update/close, event, log, stdio, coverage and guest loss. Existing trace/span
IDs are reused through a validated correlation wrapper. Producer epoch and
sequence are explicit; guest-authored host/VM/tenant/boot identity is absent and
unknown fields are rejected. Loss stages are guest-owned, so a guest cannot
impersonate host retention/export accounting.

The record wire API bounds encoded JSON to 32 KiB and depth to eight before
deserialization. Text, attributes, links and stdio have independent caps.
Attributes are typed primitives, not recursive JSON. Worker-side encode buffers
have a byte ceiling; parser errors and Debug output do not quote text/stdio.
This is an allocation-conscious wire API, not a heapless producer interface.

`mvm_core::net::telemetry` reuses the existing signed AES-GCM session and binary
sealed-frame I/O. The receiver pins an externally registered guest key; the
sender pins the host anchor and telemetry session namespace. Each host connection
gets a fresh random session ID. The receive frame ceiling is checked before body
allocation. Any read/validation failure ends the connection. A write failure
after sealing ends it with an explicitly unknown delivery tail; a locally
oversized record spends no transport sequence number. Sending reads no ACK.

`GuestService::Telemetry` reserves port 5254 independently of other fixed service
ports. No backend endpoint, listener or guest source is activated by this change.

## Local validation complete; queued delivery pending

Test-first contract tests failed to compile before the new module existed.
All eight final contract tests, nine encrypted-stream tests and four service
channel tests passed, including the golden wire corpus, terminal failure behavior
and unauthenticated handshake
diagnostic redaction. The host workspace suite completed with 13,943 passed,
zero failed and 31 ignored tests across 226 test/doc-test results; its three
host-forbidden probes were explicitly excluded as described below. The final
Linux all-target cross-check and standalone fuzz harness compile check passed.
The address-sanitized parser smoke test on
nightly-2026-08-25 passed 235,886 inputs in 31 seconds, seeded by the eight
committed golden record fixtures. CI's fuzz job copies those same fixtures to a
temporary corpus. The short smoke test is not exhaustive malformed-input or
runtime security certification. Final workspace all-target clippy and
BDD-feature all-target clippy passed with warnings denied; all 69 repository
gates passed. Required PR checks and actual merge-queue delivery remain pending.

The first PR invariant run passed those 69 gates, then the separate
`check-declared-backing` gate rejected a negated phrase in the preview plan.
The limitation was reworded without promoting the plan's backing status;
`check-declared-backing` and `check-doc-links` then passed locally. After rebasing
onto current main, all eight contract tests, nine transport tests and workspace
all-target clippy also passed again.

Host validation uses isolated MVM_HOME/CARGO_HOME/CARGO_TARGET_DIR and Rust
1.97.1. Full host tests exclude `run_build_surfaces_environment_gaps` (two
builder-boot probes) and `mk_guest_eval_assertions_all_pass_when_nix_available`
(Nix); those commands cannot run on macOS under the repository execution rules.
Linux cross-compilation is not execution of Linux-specific tests.

`cargo audit` and `cargo deny check` passed with the existing unmaintained
`proc-macro-error2` advisory (RUSTSEC-2026-0173). `cargo machete` reported the six
existing findings: `anyhow`/`tracing` in mvm-capture, `tar` in mvm-client,
`etherparse` in mvm-hostd, `tempfile` in mvm-runtime-fuzz-backend and `am-fs-core`
in third_party/am-fs-ext4. This change adds no library dependency.

## Still required

W1's remaining source inventory, startup witnesses and performance budgets;
non-waiting producer queues/adapters; source and host redaction; VM-generation
registration; backend endpoint provisioning; VM-lifetime host collection;
bounded retention/fanout/export; detached retrieval and real-VM stall/loss
acceptance. Peer-key checking is not runtime VM/boot/generation certification.
Structural bounds are not a policy that makes arbitrary workload text safe.

The next integration cannot simply reuse the networking enable switch:
`workload_runner/claim.rs::spawn_endpoint` returns no identity drive when no
egress, ingress or secrets are admitted. Telemetry identity and collection must
be provisioned for those VMs too, without admitting network access. Also,
`mvm-vmm/src/host/flowmux_identity.rs::persist_inheritable` deliberately lets warm
children inherit the parent's guest key. That key alone cannot distinguish the
child's VM/boot/generation. The collector must bind its owned backend endpoint
and fresh session to authoritative generation state, and guest restore must
discard old telemetry sessions/queues and create a new producer epoch. Add
no-egress, cross-endpoint and restored-child witnesses at that seam.

This change must not close #3421 or #3419 or advertise default-on tracing.
