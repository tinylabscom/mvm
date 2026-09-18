# Every-VM host-mediated tracing

Backing: preview
Validation: check-telemetry-inventory covers Rust binary inventory only; runtime acceptance remains open.

**Tracking:** #3419 (epic); #3420 (W1), #3421 (W2), #3422 (W3), #3423 (W4),
#3424 (W5), #3425 (W6), #3426 (W7).

**Status: W1 AND PREPARATORY W3 CAPTURE WORK IN PROGRESS.** Baseline inspected:
`2555ef935abb6aff8354f7c9001f4bcd42c52572`. Component tests from the preceding
baseline `a424c1a8728b1d98654d471ae9f5a67a35d3aed4` are not an end-to-end witness.

## Product requirement

Every microVM has tracing, collected by the MVM host over authenticated encrypted
typed guest messaging. No guest exports directly to an external collector.
Collection must remain available without a CLI attachment, invocation RPC,
mailbox grant, or configured OTLP endpoint. Host export is optional; collection
is a core product feature, not an opt-in side effect of OTLP configuration.

Every declared source and record kind must be handled: spans and their lifecycle,
events inside and outside spans, supported SDK logs, guest-agent/helper diagnostics,
stdout/stderr, and boot/restore/exit coverage. Arbitrary uninstrumented application
internals cannot be inferred; unsupported instrumentation must be reported honestly.

Fire-and-forget means bounded producer work and non-waiting admission to a bounded
local queue. A producer never waits for transport, host ACK, disk, follower,
exporter, worker join, or a contended queue lock. Finite memory and indefinite
outages make guaranteed lossless delivery incompatible with this requirement:
shed excess records and report explicit losses. Complete source coverage is not
the same as retaining every event under overload.

Audit remains a separate durable contract. Lossy telemetry cannot authorize an
operation or substitute for an audit-outbox commit or signed evidence.

## Existing plans and concrete gaps

[Secure message fabric](2026-08-18-secure-message-fabric.md) M0/M1/M2/M7/M8 and
[ADR-046](../adrs/046-secure-message-fabric.md) already require typed encrypted
Telemetry and explicit bounded-retention gaps. Those implementation items remain
open. This plan delivers that telemetry slice without waiting for mailbox/store
implementation. [Host OTLP export](2026-09-14-otlp-trace-export.md) is shipped but
does not implement guest telemetry.

| Existing code | Why it does not prove the requirement |
|---|---|
| `mvm-agentd/src/vsock/framing.rs`, `AuthenticatedSession` | Provides reusable encrypted framing, not an always-on telemetry service. |
| `mvm-net/src/channel.rs`, `GuestService` | No dedicated telemetry service. |
| `mvm-agentd/src/entrypoint_stream.rs`, shared `stream_handoff::Handoff` | Bounded live handoff and owned completion tail; still invocation-scoped, not an independent telemetry producer. |
| `mvm-agentd/src/stream_pump.rs`, `Pump::run` | Bounded reader queues/tails with stage-specific losses; synchronous sinks and pipe EOF/reaping are not a VM-lifetime telemetry supervisor. |
| `mvm-cli/src/commands/vm/invoke.rs`, `write_entrypoint_event` | Invocation-scoped; only fd3 header is captured, payload is omitted; synchronous terminal writes/flushes may stall the consumer. |
| `mvm-hostd/src/stream/entrypoint_source.rs` | Process-local collector lookup and mutex-taking ingest cannot establish VM-lifetime, non-waiting collection. |
| `mvm-client/src/stream_tracing.rs` | Optional event bridge is not complete distributed span reconstruction. |
| `mvm-observability/src/otlp/layer.rs` | Drops outside-span events; span event vectors are not bounded by export queue capacity. |
| `mvm-observability/src/logging.rs` | Synchronous fmt output can block independently of the export queue. |
| `mvm-agentd/src/bin/mvm-guest-agent.rs` and helper subscribers | No demonstrated complete shared subscriber/capture path across all binaries. |

Paths in this table are relative to `crates/`. The inspected code is the evidence;
plan checkboxes and a green OTLP test do not establish complete tracing.

## Architecture

```text
guest spans / events / supported logs / diagnostics / stdio adapters
  -> source-side policy and bounded typed capture
  -> bounded non-waiting guest queue
  -> telemetry worker using authenticated encrypted guest messaging
  -> VM-lifetime host collector with session-derived identity
  -> bounded validation and redaction
  -> host retention + independent subscribers + optional host OTLP export
```

The runtime registers and supervises a collector for the VM before workload
start. CLI readers subscribe to that collector; they do not own it. Collector
failure marks coverage degraded and starts bounded recovery without stopping
the workload. Guest capture does not require a mailbox grant. Telemetry availability
must be wired separately from the fabric plan's optional message role.

Add a closed Telemetry role through `GuestService` and the existing backend
endpoint abstraction. Use the current authenticated session/framing helpers,
not a second crypto implementation. If the secure-fabric transport replacement
lands first, use it behind the same semantic service. Do not describe the
current custom Session as TLS. No unauthenticated or plaintext fallback.

Use a separate bounded telemetry connection and worker so congestion cannot
occupy machine-control, workload-exit, network-flow, or audit delivery queues.
Enforce per-VM and aggregate host byte/event/connection/worker limits. A transport
worker may wait on readiness under a deadline; instrumented callers may not.
Use owned readiness/exit events for live resources and cancellable timers for
retry backoff. Do not introduce a repository-wide async runtime.

## Closed typed record contract

Use one versioned shared contract with span-open, span-update, span-close,
standalone-or-span-associated event, supported log, stdout/stderr chunk,
producer-coverage and loss-summary variants. Preserve typed attribute values,
trace/span/parent IDs and links rather than flattening spans into message strings.
No extensible opcode bag or guest-authored host-system event.

Each record carries a source kind, producer epoch/id/sequence, monotonic guest
timestamp and optional validated trace context. The host adds VM/boot/generation
identity from the authenticated session, host receive time and stream position.
Guest-provided tenant/host identity is never authoritative. Caller trace context
is correlation, not permission. Guest clocks are not trusted wall clocks, and
per-producer order plus host receive order does not imply global causal order.

Validate wire version and all count/byte/depth limits before unbounded allocation:
frames, strings, fields, links, batches, producer tables and active spans. Unknown
versions/variants, malformed IDs and unauthorized sources are safely rejected
without payload dumps. Missing lifecycle records produce incomplete spans; bound
their state by count/bytes and TTL instead of fabricating successful closes.

Restore starts a fresh authenticated session and producer epoch bound to the new
VM generation. Do not restore/replay telemetry queues, transport sequence state
or donor identity. Reconnect is best-effort: a partial transport tail is uncertain,
not acknowledged delivery. No application ACK is awaited by the emitting thread.

## Nonblocking, boundedness and loss

Every stage must have count and byte limits, including pipe-reader handoff,
fd3 headers and records, capture buffers, span state, host ingress, disk queues,
subscriber queues and exporter batches. Stdio readers must keep draining when
telemetry is saturated; a full telemetry queue must not become child pipe
backpressure. This does not promise that arbitrary application writes or OS
scheduling are mathematically wait-free.

Capture uses bounded primitive field handling and a non-waiting queue offer.
Do not invoke arbitrary unbounded `Debug` formatting, blocking format writers,
allocation-retry loops, spin-until-success queues or recursively instrumented loss
reporting. Generic user formatter execution cannot carry a strict latency promise;
supported adapters must enforce and document bounded handling.

Worker cancellation and reaping belong to the supervisor. Instrumented callbacks,
VM control/exit and producer teardown must not join/flush a worker or wait for
tail delivery. A bounded best-effort tail remains optional and off the critical path.

Keep coalesced loss counters outside the full data queue, with reserved summary
capacity/bandwidth. Distinguish source filtering/sampling, truncation, guest
shedding, wire rejection, host shedding, retention pruning, follower lag and export
failure. Sequence gaps and summaries identify what is known; a process crash can
destroy counters, so the host must mark the tail unknown instead of promising an
exact count. Treat host transcript integrity as evidence of receipt, not guest
truth or complete delivery.

## All-source coverage and secure defaults

Maintain an executable producer/channel inventory with initialization site, source
kind, policy and test witness for every supported guest binary, helper, worker,
SDK adapter and host lifecycle source. A coverage test must fail when a new
producer is added without a declared capture path. Expected source startup
witnesses are checked by the host; missing witnesses produce visible degradation.

Cover Rust tracing/log, supported Python/JavaScript SDK instrumentation, cold and
warm workers, detached workloads, cancellation, boot, restore and exit. Filtering
and sampling are explicit inspectable policy; no missing default subscriber or
disabled OTLP export may silently disable local collection.

Source-side allowlisting/redaction runs before wire; host policy sanitizes before
all retention, fanout and export. Use synthetic secret sentinels in tests and
never log environment values, credentials, request bodies or parser-error payloads
by default. Authenticate identity/generation, reject replay and tamper, and enforce
tenant isolation, restrictive storage permissions and bounded retention.

Early boot needs an authenticated encrypted producer with bounded preconnection
storage. Until that producer is live, expose an explicit unavailable interval.
ADR-046 forbids raw guest-console fallback; host-authored VMM diagnostics are a
separate source. Do not certify full early-boot coverage while the interval remains
unobservable. Wasm has no vsock/microVM: an equivalent bounded host adapter reports
that distinction honestly. The backend matrix includes Firecracker, libkrun, HVF,
apple-container, QEMU, builder-tier guests and the separate wasm adapter.

## Delivery workstreams

Core telemetry-service implementation checkboxes remain open. Each workstream has a product issue and
focused PRs; update this plan, SPRINT and REFACTOR-STATUS in the same change as
tested progress. A documentation PR must not close the implementation epic.

### W1 — Producer inventory and acceptance harness

- [ ] Enumerate binaries, source/capture initialization, runtime owner, backend
      channel and expected witness. Add the static gate for unregistered producers.
  - [x] W1a — Rust binary inventory and CI drift gate: explicit and implicit
        workspace targets, including disabled features, with source/feature drift,
        required signal families, owner roles, capture gaps and non-runtime
        exclusions. Seventeen focused tests and the live inventory gate pass;
        workspace and xtask all-target clippy are warning-free. See the
        [validation record](../sprint/delivery/3420-telemetry-binary-inventory.md)
        for broader checks and host-test limitations.
  - [ ] W1b — Extend discovery to library producers, SDK/dispatch scripts and
        guest init/early-boot sources; map actual initialization, image/launcher
        membership and backend service endpoints. Add startup witness checking.

The current [binary inventory](../telemetry/README.md) classifies 45 targets:
28 runtime gaps and 17 non-runtime tools/fixtures. Passing its static gate is not
runtime coverage, a startup witness, or evidence of nonblocking delivery.

- [ ] Add tests proving current outside-span, detached-lifetime and capture gaps.
      Tests for not-yet-enabled features stay in an explicit conformance harness,
      not silently ignored tests presented as product support.
- [ ] Define reproducible hardware/fixture inputs and commit baseline measurements
      for emit p50/p95/p99/max, allocations, memory, control/exit latency and flood
      fairness. Set regression budgets from repeated baseline runs before enabling
      the feature, recording the commands and variance.

### W2 — Typed records and authenticated telemetry service

- [ ] Add the validated closed shared contract and semantic service, using existing
      ID/framing/backend helpers. Roundtrip every variant and pin wire encoding.
- [ ] Prove wrong boot/VM/generation, replay, tamper, unknown versions, oversize,
      malformed lengths/IDs and unauthenticated peers fail without payload leakage.
- [ ] Prove independent service routing and absence of raw/direct-guest-export
      fallback through mock I/O and real backend witnesses.

### W3 — Guest capture with bounded non-waiting emission

- [ ] Wire subscribers and adapters for all inventoried sources, including
      outside-span events and log bridges; preserve span parent/link relationships.
- [ ] Bound every upstream/downstream queue and active-span/field allocation;
      remove blocking completion sends and recursive diagnostics on capture paths.
  - [x] W3a — Bound existing entrypoint pipe-reader handoffs and transfer completion
        tails without queue sends. Reuse retention rings, separate pipe-reader and
        consumer-handoff gap scopes, and mark reader failures as unknown tails.
        Validated by 81 stream unit tests, authenticated encrypted mock streams
        and a hermetic workload-completion BDD witness. See
        [validation record](../sprint/delivery/3422-bounded-capture-handoff.md).
- [ ] Add independent loss accounting, bounded summaries and cancellation/reaping;
      prove a stopped peer/full queue does not stall workload or pipe draining.

### W4 — Host collector owned for the VM lifetime

- [ ] Supervise per-VM collection independently of CLI/grants, bind identity and
      generation, and reuse stream validation/redaction/retention/fanout helpers.
- [ ] Bound host resource usage and make saturation non-waiting for ingress and
      unrelated control operations. Isolate slow terminal/follower/disk writes.
- [ ] Verify detached, cold, warm, restore and restart behavior; disk-full and
      collector-loss recovery; cross-tenant/forged-identity refusal and fairness.

### W5 — Complete host views and optional export

- [ ] Preserve spans, updates, events, logs and source coverage in host views;
      display incomplete spans and each loss/degradation class.
- [ ] Bound host OTLP open-span/event/attribute state and export bytes as well as
      record counts. Export outside-span logs/events through their proper signal,
      not fabricated successful spans.
- [ ] Verify disabled/slow/broken OTLP and full stdout/stderr sinks do not block
      guest producers or VM lifecycle; keep credentials/export policy host-side.

### W6 — Real-backend and security certification

- [ ] Exercise the backend/source matrix with actual runtime witnesses, not mocks
      alone. Prove early boot or retain an explicit uncertified coverage gap.
- [ ] Use deterministic stopped readers, filled queues and cancellation barriers
      to verify latency/memory budgets; do not use sleeps as synchronization.
- [ ] Verify synthetic-secret absence at wire/host/log/export boundaries, tamper,
      replay, malformed/flood input, restore identity, missing witnesses and gaps.
- [ ] Add user-visible BDD for detached trace retrieval, standalone events, span
      correlation, loss visibility, slow-host operation and multi-VM isolation.

### W7 — Default-on rollout, documentation and queued delivery

- [ ] Enable collection by default only when its registered coverage and acceptance
      gates pass. An OTLP endpoint must remain optional. Document unsupported sources
      and remaining unavailable intervals without claiming complete capture.
- [ ] Update guest-agent/networking/observability references and CLI/help for any
      new inspection surface; remove superseded capture routes after parity tests.
- [ ] Observe every implementation PR through required checks, actual merge-queue
      entry and merge; immediately synchronize main. Record immutable commits and
      evidence on product issues before closing them.

Dependencies: W1 -> W2; W2 -> W3 and W4; W3+W4 -> W5; W1-W5 -> W6 -> W7.
Telemetry is not blocked on mailbox storage or functional-stream reliability.
W3a is an independent repair to existing invocation capture, not activation of the
new telemetry feature ahead of W1/W2. It does not establish every-source coverage,
strict wait-free queue internals, emission latency budgets, detached collection,
or real-backend certification. Completion tails and gap summaries can remain
pending until the next offer or EOF; live periodic loss reporting remains open.

## Required verification before product completion

Tests first, then host `cargo test --workspace`, workspace check, fmt and
zero-warning clippy; Linux all-target clippy and Linux-only/vsock/Firecracker tests
in the project builder VM. Shared types require `just check-gated`, including BDD
feature-gated targets. Run applicable supply-chain and repository gates. Follow
AGENTS.md's environment exceptions exactly; this plan grants no broader HVF/Lima
permission. Use per-worktree MVM_HOME, CARGO_HOME and CARGO_TARGET_DIR.

The completion claim needs end-to-end evidence for every declared producer and
supported backend plus saturated queues, unavailable disk/exporter, full terminal
pipes, canceled workers, lost lifecycle records and secret filtering. Baseline
component tests are useful but insufficient: they establish neither the new
service nor complete coverage. Documentation and green checks alone are not a
substitute for real-VM evidence.
