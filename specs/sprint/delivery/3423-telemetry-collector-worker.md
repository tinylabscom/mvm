# Host telemetry collector worker

Issue #3423, first W4 slice of `2026-09-17-host-mediated-telemetry`.
Epic #3419 and the runtime acceptance workstreams remain open.

## Implemented boundary

`mvm_hostd::telemetry_collector` is the per-VM collector worker: one thread
that owns a VM's telemetry session for as long as it is asked to. Every
connection attempt composes the required dialer sequence —
`resolve_expected_telemetry_peer` → `assert_peer_is_current` → connect →
`TelemetryReceiver::connect_with_signer` — the composition that existed on
main only as unassembled parts after #3472 (receive-side authentication with
the delegated resident signer) and #3597 (boot-generation registration)
merged.

Received records are delivered into a bounded, non-waiting `RecordSink`:
`try_ingest` never blocks, and a full sink is a counted host-side shed, never
backpressure on the receive loop. The worker surfaces a `CoverageStatus`
snapshot (Connecting / Collecting with the boot generation / Degraded with a
static code / Stopped) for the future supervisor slot; degraded codes are
static labels, never payload bytes. Recovery runs under capped exponential
backoff (100 ms base, 5 s ceiling) that re-resolves the registration on each
attempt, so a warm-claim or restore re-registration is picked up through the
gate rather than authenticated under a stale expectation. Stop is prompt: the
stop flag interrupts a backoff sleep within its 25 ms poll bound.

The stream connector and handshake signer are injected, so the worker
composes over any byte stream and any signing authority. Production wiring is
the per-backend telemetry socket and `sign_telemetry_handshake` through the
resident signer, whose blocking bridge the existing `telemetry_signer.rs`
integration tests already exercise.

## Not claimed

Deliberately absent, as follow-on W4 slices: the supervisor slot and
VM-lifetime ownership, spawn wiring across the boot paths, and the real
per-backend socket wiring. No boot path starts a collector, and outside tests
nothing dials the guest listener. A worker that authenticates and receives
over a socket pair is not VM-lifetime collection, capture coverage (W3) or
runtime certification.

This change must not close #3423 or #3419 or advertise default-on tracing.

## Validation

Five focused tests over socket pairs, with `TelemetrySender` as the guest
double: ordered record delivery through an authenticated session; a
warm-claim-shaped re-registration picked up with a newer generation through
per-attempt re-resolution; a full sink shedding with counted loss evidence
while the receive loop keeps draining; prompt stop during backoff; and an
unregistered-key authentication failure with no record crossing.

`cargo nextest run -p mvm-hostd` passed 2,010 tests; all-target clippy with
warnings denied and `cargo fmt --all -- --check` passed. PR #3658 merged
through the queue at 2026-09-27T00:53:05Z as
`e2cbf029a2c97e01c8300abac4bb85d52a06ac2d`.
