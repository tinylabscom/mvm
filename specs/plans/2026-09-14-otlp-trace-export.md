# OTLP trace export for host-side processes

Tracking issue: #3242. Parent item: `specs/plans/2026-08-18-secure-message-fabric.md`
("Add optional asynchronous authenticated OTLP export"). ADR-046 governs the
posture: OTLP is an analysis projection and never the proof of record.

## Problem

`mvm-observability` installs a formatter and the span-timing layer and nothing
else. Spans reach an operator only as stderr text or as `MVM_SPAN_TIMINGS`
aggregates. There is no way to see a boot, a build, or an admission as a trace
in a standard collector, and the audit mirror's `mvm::audit` events stop at
stderr.

## Decision: encode OTLP/HTTP JSON ourselves, over `mvm-http`

Measured against `mvmctl`'s shipped no-dev closure on 2026-09-14 (resolved
lockfiles, names not already in `cargo tree -p mvmctl -e normal`):

| Option | Crates added |
| --- | --- |
| `opentelemetry-otlp` default (gRPC/tonic) + SDK + `tracing-opentelemetry` | 54 |
| `opentelemetry-otlp` HTTP/protobuf + reqwest | 54 |
| SDK + `tracing-opentelemetry`, no exporter | 29 |
| Own OTLP/HTTP JSON encoder, sent with `mvm-http` | 0 |

The 54 include `hyper`, `hyper-util`, `tower`, `tower-http`, `reqwest`,
`http-body`, `prost` and the `futures-*` set, which is the stack
`check-closure-budget` records removing (262 -> 242). The SDK-only option still
brings `futures-*`, `wasm-bindgen` and a second random-number stack, and would
still need an exporter.

OTLP/HTTP with JSON encoding is a stable part of the OTLP specification and the
trace payload is small: resource, scope, and a list of spans with ids, times,
attributes, events and status. Every OTLP collector accepts it on
`/v1/traces`. The costs we accept: no gRPC, no protobuf encoding, no metrics or
logs signal in this change, and an encoder we maintain.

## Design

- **Layer.** `OtlpLayer` implements `tracing_subscriber::Layer`. On span
  creation it records a start time, a span id, the trace id (inherited from the
  parent span, random for a root) and the span's fields as attributes in the
  registry extensions. Events inside a span become span events. On close it
  builds a finished span record and offers it to the export queue. Events
  outside any span are not exported; the logs signal is out of scope.
- **Never block the instrumented thread.** The queue is a bounded
  `std::sync::mpsc::sync_channel` used with `try_send`. Overflow drops the span
  and increments a counter; nothing on the instrumented side waits on the
  network.
- **Export thread.** A dedicated std thread drains the queue into batches
  (size- or interval-bounded), encodes them, and POSTs with `mvm-http`'s
  blocking client under a timeout. A failed POST drops that batch; there is no
  retry loop. The first failure is reported once on stderr, not per batch.
- **Flush on exit.** Initialization returns a guard; dropping it closes the
  queue and waits a bounded time for the export thread to send what is queued.
  The export itself is held process-wide, so a path that calls
  `mvm_observability::exit` instead of returning flushes it the same way.
- **Configuration** uses the standard variables, so existing collector setups
  apply unchanged: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (used as-is) or
  `OTEL_EXPORTER_OTLP_ENDPOINT` (`/v1/traces` appended),
  `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT`,
  `OTEL_SERVICE_NAME`. `MVM_OTLP_FILTER` sets the layer's own filter, attached
  per-layer like the span-timing filter so spans are constructed even when the
  log filter is quieter. With no endpoint set the layer is not installed.
- **Transport security.** `https://` is always allowed. `http://` is allowed
  only to a loopback host, so headers carrying collector credentials and span
  contents never cross a network in the clear. Header values are redacted in
  `Debug` and never logged.
- **Guest boundary.** The sealed guest agent does not depend on
  `mvm-observability`, so nothing is exported from inside a microVM. This change
  does not alter that.

## Work

- [x] Configuration: env parsing into a validated config, endpoint rules,
      header parsing, redacted `Debug`; unit tests for each rule.
- [x] Encoder: finished span records to OTLP/HTTP JSON; tests pin the wire shape
      (hex ids, string nanos, parent linkage, events, attributes, status).
- [x] Layer: span ids, trace inheritance, attributes, events, close; tests with
      a capturing sink.
- [x] Export thread: batching, bounded queue with drop counter, timeout, flush
      guard; tests for overflow and for a listener that never answers.
- [x] Integration test: a local HTTP listener receives a well-formed export.
- [x] Wire into `mvmctl`'s subscriber assembly and hold the guard for the
      process lifetime.
- [x] Flush on early exit: hold the export guard process-wide, route every
      `mvm-cli` exit through `mvm_observability::exit` (Ctrl-C through
      `exit_after_interrupt`, bounded to 1 s), deny `clippy::exit` in
      `mvm-cli`, and witness it with a re-exec test whose child exits through
      the helper.
- [x] Documentation: how to point `mvmctl` at a collector.
- [x] `check-closure-budget` passes on both targets with no budget change.

## Follow-ups

- [ ] Converge the `mvm-hostd` binaries that install their own `fmt()`
      subscriber (`mvm-network-endpoint`, `mvm-broker`, `mvm-host-agent`, the
      signers) onto `mvm-observability` so they export too. Their stderr is
      captured by the supervisor, so the format change needs care.
- [ ] Per-VM supervisors: propagate trace context from `mvmctl` so a boot is
      one trace across processes.
- [ ] mvmd: reuse the same layer for the long-running daemon.
- [ ] Logs and metrics signals, if a consumer needs them.
