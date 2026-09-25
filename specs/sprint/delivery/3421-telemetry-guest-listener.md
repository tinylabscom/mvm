# Guest telemetry listener and authenticated serve half

Issue #3421, W2b (guest listener half) of `2026-09-17-host-mediated-telemetry`.
Epic #3419 and the runtime acceptance workstreams remain open.

## Implemented boundary

`mvm_agentd::telemetry_service::serve_telemetry_connection` is the guest
cryptographic role over any `Read + Write` stream: it accepts the host's
authenticated telemetry session under the guest signing key and pinned host
anchor, mints a fresh random producer epoch per session, and announces
Coverage-Started as the session's first record. A wrong guest key or a wrong
host anchor ends the handshake; a dead peer ends the session without hanging
the agent. Five focused tests cover the `TelemetryReceiver`↔serve wire
round-trip, epoch freshness across sessions, wrong-guest-key refusal,
wrong-host-anchor refusal and dead-peer handling.

The `mvm-guest-agent` binary binds a vsock listener on the reserved telemetry
port (`mvm_core::protocol::telemetry::TELEMETRY_PORT`, 5254), reusing the
transport module's vsock bind and host-only peer-CID gate. The accept loop
runs on a thread spawned only in the post-activation zone — PID-1 activation
forbids earlier threads — and serves one session at a time. Keys are loaded
lazily per connection (`flowmux_sync::load_guest_signing_key("/run/mvm")` plus
the host-signer verifying key), so a connection arriving before keys are
provisioned is dropped cleanly and the listener keeps serving. The listener is
vsock-only: the unix/container tier gets no telemetry listener in this slice,
recorded in code where the tiers diverge.

With #3597's boot-generation registration merged, a full-chain witness
(`crates/mvm-runtime/tests/telemetry_full_chain.rs`) composes the sequence a
host collector must run — register the boot, resolve the expected peer,
assert it is current, then authenticate — against `serve_telemetry_connection`
itself over a live stream: the registered peer's session yields the coverage
record, a superseded (warm-claim-shaped) re-registration refuses at the gate
before any dial, and a guest serving a key other than the registered one
fails the session with no record crossing.

## Not claimed

The full-chain witness runs over a Unix stream pair; a real-vsock
over-the-wire witness on a booted guest remains open with the live lanes. No
real telemetry capture is wired (W3): the listener serves a session, and
nothing in the guest yet produces spans, events, logs or stdio into it. The
VM-lifetime host collector (W4) remains unimplemented; no host process dials
this listener outside tests. Serving an authenticated session is not runtime
VM/boot/generation certification, and a bound port is not capture coverage.

This change must not close #3421 or #3419 or advertise default-on tracing.

## Validation

Twelve focused tests across the three seams: five on the serve half
(`telemetry_service` — receiver↔serve round-trip, epoch freshness, wrong
guest key, wrong host anchor, dead peer), four on the bin glue
(`mvm-guest-agent` `telemetry` module — full session with provisioned keys,
pre-provisioning connection dropped with clean EOF, missing anchor dropped
before any byte, malformed key refused without panic), and three on the
full chain (`crates/mvm-runtime/tests/telemetry_full_chain.rs` — coverage
record through the resolved registration, superseded-boot gate refusal
before any dial, imposter-key session failure with no record crossing).
One pre-existing serve-half test deadlocked under the workspace runner
(the refusing guest's socket was held open across the host-thread join)
and was fixed in this change.

Full battery on the branch: `cargo fmt --all -- --check`, workspace
clippy with warnings denied, `cargo nextest run --workspace` (14,917
passed), workspace doctests, all 74 repository gates
(`cargo run -p xtask -- check-all`), and `just check-gated`.
