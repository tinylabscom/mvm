# 3242 — OTLP trace export for `mvmctl`, with no new dependencies

Plan: `specs/plans/2026-09-14-otlp-trace-export.md`.

## Shipped

`mvm-observability` gains an `otlp` module, and `mvmctl` installs it when an
OTLP endpoint is configured.

- **Configuration** (`otlp/config.rs`). `OtlpConfig::from_env` /
  `from_lookup` read `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (verbatim) or
  `OTEL_EXPORTER_OTLP_ENDPOINT` (`/v1/traces` appended),
  `OTEL_EXPORTER_OTLP_HEADERS` (percent-decoded, validated as HTTP headers),
  `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_SERVICE_NAME` and `MVM_OTLP_FILTER`. No
  endpoint means no layer. `https://` is accepted anywhere; `http://` only to a
  loopback host, decided by `mvm_http::is_loopback_host` — the gateway client's
  existing rule, moved into `mvm-http` so both callers share one predicate.
  `Debug` prints header names, never values. A refused configuration prints one
  stderr line and leaves export off.
- **Encoder** (`otlp/encode.rs`). OTLP/HTTP JSON per the protobuf JSON mapping:
  hex ids, decimal-string nanos and `intValue`, integer `kind` and status code.
  Resource carries `service.name`, `service.version` and `process.pid`.
- **Layer** (`otlp/layer.rs`). Span ids and trace inheritance through the
  registry's parent resolution, typed attributes (plus `code.namespace`,
  `code.filepath`, `code.lineno`), `Span::record` merges, events inside a span
  become span events, and an `error` field or ERROR event sets status ERROR.
  Close offers the record with `try_send`; it never blocks.
- **Export** (`otlp/export.rs`). Bounded queue (2048) with a drop counter; a
  named thread batches up to 512 spans or 1 s, POSTs with `mvm-http`'s blocking
  client under the configured timeout, drops a failed batch without retry and
  reports only the first failure. `ExportGuard` flushes on drop, waiting at most
  the export timeout, and reports the dropped-span count if nonzero.
- **Wiring.** `init` / `init_with_filter` now return `ObservabilityGuard`;
  `mvmctl`'s `run_command` holds it for the command's lifetime.
- **Early exits flush too.** The `ExportGuard` is held process-wide in an
  `ExportSlot` rather than in the `ObservabilityGuard`, so a path that ends
  without unwinding can still reach it. `mvm_observability::exit(code)` flushes
  it, bounded by the export timeout, and then exits;
  `exit_after_interrupt(code)` caps the wait at `INTERRUPT_FLUSH_BOUND` (1 s)
  for Ctrl-C. Whichever of the guard's drop and an exit helper runs first
  flushes, and the other finds the slot empty. All 28 `std::process::exit`
  calls in `mvm-cli` now go through `exit`, the Ctrl-C handler through
  `exit_after_interrupt`, and the `seccomp-audit` fork child through
  `libc::_exit` so it never touches the parent's export thread.
  `#![deny(clippy::exit)]` on `mvm-cli` stops a new direct exit from landing.
  Witness: `tests/otlp_exit.rs` re-runs its own test binary as a child that
  emits a span and calls `exit(7)`; the parent asserts exit code 7 and that a
  local collector received the span, and a second case asserts that with no
  collector configured the helper exits at once.
- **Docs.** "Exporting traces to a collector" in
  `public/src/content/docs/contributing/development.md`.

## Dependency decision, measured

Names added to `mvmctl`'s shipped no-dev closure, per the plan's table: the
OpenTelemetry SDK with `tracing-opentelemetry` and either OTLP exporter adds 54
crates, including the hyper/tower/reqwest/prost stack this workspace removed;
the SDK alone adds 29. Encoding in-tree adds 0. `mvm-observability` now depends
on `mvm-http`, `percent-encoding` (new workspace-table entry, already in the
closure through `url`), `rand`, `serde` and `serde_json` — all already present.

| Target | `check-closure-budget` before | after | `cargo tree` names before | after |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | 239 | 239 | 232 | 232 |
| `aarch64-apple-darwin` | 230 | 230 | 224 | 224 |

No budget changed.

## Not covered

- **Exits outside `mvm-cli`.** A dependency that calls `std::process::exit`
  itself (the host-helper contract probe answers before logging starts, so
  nothing is queued there) is not covered by the lint. An exit after Ctrl-C
  keeps only what can be sent within one second.
- **Other host processes.** The `mvm-hostd` binaries (`mvm-network-endpoint`,
  `mvm-broker`, the signers) install their own subscribers, and the per-VM
  supervisors neither export nor receive trace context from `mvmctl`, so a boot
  is not yet one trace across processes.
- **mvmd** does not use the layer yet.
- **Logs and metrics signals.** Events outside a span are not exported.
- **Guests.** Nothing is exported from inside a microVM; the guest agent does
  not link `mvm-observability`.
- **`host.name`** is not reported: no hostname source exists in the closure
  without `unsafe` libc calls or a new crate.
- No gRPC or protobuf encoding.
