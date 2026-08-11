# Plan 318 — Span-timing profiling for `#[instrument]`

**Status:** COMPLETE (Phases 1-3)
**Date opened:** 2026-08-10
**Branch:** `perf/318-span-timing`

## Problem

The workspace carries ~60 `#[instrument]` attributes across 17 files. None of
them produce timing data, for two independent reasons:

1. **No layer consumes span close events.** `rg 'FmtSpan|with_span_events'`
   returned no hits anywhere in the tree. `tracing` does not time spans on its
   own — a span's duration exists only if some layer records `on_close`.
2. **The log filter suppressed span construction.** Both subscriber setups
   (`mvm-core/src/observability/logging.rs`, `mvm-cli/src/logging.rs`) attached
   `EnvFilter` to the *registry*, making it a global filter. The CLI's default
   at verbosity 0 is `error`, while `#[instrument]` declares INFO spans, so the
   spans were never constructed at all.

The consequence is that the attributes read as instrumentation but are inert.
Adding more of them changes nothing until a consumer exists.

This is the same measurement gap the sprint's current top item works around:
Plan 311's launch-path findings (~557 ms re-hash, ~67 ms `ps` subprocess,
~28 ms verity marker scan) came from ad-hoc measurement, not from a profile the
tool can produce on demand.

## Approach

Build the consumer first, then instrument.

### Phase 1 — the timing layer (COMPLETE)

- [x] `LogHistogram` — fixed-memory (2 KiB) log-scale histogram, 4 sub-buckets
      per octave, ~12% typical bucket error. Bounded so a long-running daemon
      cannot grow unbounded sample vectors.
      (`crates/mvm-core/src/observability/span_timing/histogram.rs`)
- [x] `SpanTimings` registry keyed by `(target, name)`, accumulating calls,
      inclusive time, child time, wall clock, min/max and the histogram.
      (`.../span_timing/registry.rs`)
- [x] `SpanTimingLayer` — records `on_new_span`/`on_enter`/`on_exit`/`on_close`
      and attributes each span's time upward to its parent's `child_busy_ns`,
      so the report can show **self time** (time in this function excluding
      nested instrumented calls) alongside inclusive total.
      (`.../span_timing/layer.rs`)
- [x] Text and JSON report rendering, sorted by self time descending.
      (`.../span_timing/mod.rs`)
- [x] **Layer stack fix**: the log filter now attaches to the fmt layer as a
      per-layer filter rather than to the registry, so the timing layer's own
      (wider) filter governs whether a span is constructed. This is the change
      that makes any of the existing attributes measurable.
- [x] `mvm-cli/src/logging.rs` reduced to the verbosity mapping and delegated
      to `mvm-core`, removing a duplicated subscriber assembly.
- [x] Report emitted at CLI exit via `mvm_cli::commands::run`.

### Phase 2 — instrumenting hot paths (COMPLETE)

Coarse-grained entry points only. Per-file/per-entry functions are deliberately
left uninstrumented: the registry takes a mutex per span close, so instrumenting
an inner loop would distort the measurement it is meant to produce.

- [x] `mvm-fs` (previously had no `tracing` dependency at all — the OCI and ext4
      crate, the heaviest I/O path):
      `unpack_layer_with_prior_paths`, `verify_and_unpack_layer_file`,
      `materialize_to_ext4`, `estimate_image_size`, `seal_with_verity`,
      `hash_source`.
- [x] `mvm-backends` launch paths: `fc.boot`, `hvf.boot`, `libkrun.boot`,
      `qemu.boot`, `hvf.restore`.

#### Relationship to `launch_trace`

`mvm_core::launch_trace` already times the launch path, but covers exactly one
function — `workload_runner/runner.rs`, with six ordered marks (`endpoint_spawn`
→ `broker_register`). It records an ordered phase *sequence* for a single
launch into a per-VM sidecar, consumed by the launch regression lane.

Span timing is the complementary axis: an aggregate *profile* across every call
of every instrumented function. The boundary held here is that `launch_trace`
owns in-launch phase ordering and span timing owns everything upstream of it —
which is where the Plan 311 findings live and where `mvm-cli` had no
instrumentation at all. The two are deliberately not bridged.

#### Tier 1 — launch critical path (COMPLETE)

- [x] `mvm-core` `crypto::image_verify`: `sha256_file` (as
      `sha256_file.uncached`) and `sha256_file_cached_with_source` (as
      `sha256_file.cached`). The cached wrapper calls the uncached hasher on a
      sidecar miss, so self time separates sidecar-hit cost from real hashing
      and a regression to uncached hashing shows up as a row rather than an
      inference. This is the ~557 ms re-hash Plan 311 names; the byte counter
      (`record_artifact_bytes_hashed`) already existed, the time did not.
- [x] `mvm-cli` `up::admission::resolve_image_sha256` — the caller that selects
      the uncached path when a precomputed digest is supplied.
- [x] `mvm-cli` `up::runtime_source`: `attach_runtime_overlay`,
      `attach_universal_initramfs_if_cached`.
- [x] `mvm-cli` `up::kernel::resolve_pinned_kernel_with`.
- [x] `mvm-cli` `image::pull_core`: `pull_image_ref`, `fetch_or_unpack_layer`.
- [x] `mvm-cli` `ProcSnapshot::capture` — the `ps` process-table scan, Plan
      311's ~67 ms.

#### Tier 2 — daemons and build pipeline (COMPLETE)

- [x] `mvm-hostd`: `plan_admission::admit_for_run`, `admit_and_start`,
      `supervisor::audit_file::verify_audit_chain_entries`.
- [x] `mvm-build`: `pipeline::orchestrator::pool_build_with_opts`,
      `pipeline::vsock_builder::build_via_vsock`,
      `pipeline::build_cache::workload_build_fingerprint`.
- [x] `mvm-client`: `launch_transient`.

#### Deliberately not instrumented

- Inner loops (per-file hashing, per-packet datapath, per-tar-entry unpack) —
  the per-close lock would distort what it measures.
- `mvm-hostd`'s `stream::serve::serve_follower` and peers — a per-connection
  blocking loop whose span duration is connection lifetime, not cost.
- `mvm-agentd` — it runs in the guest, so its spans land on the guest's stderr
  rather than the host profile. Instrumenting it needs a collection path first.
- Pure predicates (`argv_is_shell`, `program_basename`) and `mvm-contract`
  (`no_std`, no `tracing` by design).

### Phase 3 (COMPLETE)

- [x] **Prometheus export.** `span_timing::prometheus_exposition` renders a
      `SpanReport` as labelled series — `mvm_span_calls_total`,
      `mvm_span_self_seconds_total`, `mvm_span_total_seconds_total`,
      `mvm_span_max_seconds`, each carrying `target` and `span` labels. The
      existing `Metrics` counters are fixed-name singletons, so labels are what
      a per-call-site metric needs. Durations are exported in seconds per
      Prometheus convention. Label values are escaped: an unescaped quote in a
      span name would produce a malformed exposition that breaks the whole
      scrape rather than one series. Appended to the served body in
      `mvm-cli/src/metrics_server.rs`, and empty unless the process is
      profiling, so the scrape shape is unchanged for everyone else.

      Not wired into `mvmctl ops metrics`. It was, briefly, until a live run
      showed it structurally empty: a profile accumulates in the process that
      ran the instrumented code, and that command renders its output before
      doing any. The scrape endpoint is different — there the serving process is
      the one doing the work, so each scrape reflects what has happened so far.

- [x] **Bench-harness diffing.** `mvm-cli/src/bench/span_profile.rs`. The launch
      harness spawns `mvmctl` as a child, so `profile_env` supplies the env that
      makes the child write a JSON profile and `read_profile` reads it back;
      this composes with the runner's existing env list without changing it.
      `compare_span_reports` is pure and returns a per-call-site
      `RegressionVerdict` (reusing `regression.rs`'s enum), plus the spans that
      appeared or disappeared between runs.

      The gate compares **per-call** self time, not total. Two runs may execute
      a different number of iterations, and a total-time gate would read that as
      a regression. Call counts are reported alongside via
      `SpanDelta::call_count_changed`, because "this function got slower" and
      "this function got called twice as often" are different defects that need
      telling apart — the second is exactly the shape of the Plan 311 re-hash. A
      zero or call-less baseline returns `Incomparable` rather than a pass,
      since a ratio against zero would be a false green.

- [x] **The per-close mutex stays.** Measured rather than argued, in
      `crates/mvm-core/tests/span_timing_overhead.rs` (debug build, Apple
      silicon; release is faster and the ratios are what matter):

      | scenario                        | ns/span |
      | ------------------------------- | ------- |
      | profiling disabled (filtered)   | 12      |
      | enabled, 1 thread               | 4,278   |
      | enabled, 8 threads (aggregate)  | 2,084   |

      Aggregate throughput *improves* roughly 2x under 8 threads rather than
      collapsing, so the lock is not the bottleneck at entry-point granularity —
      most of the per-span cost sits outside the critical section. Sharded or
      thread-local accumulation would be speculative complexity, so it is not
      built. The disabled path costs 12 ns/span, which is what every
      non-profiling run pays.

      The tests assert a deliberately loose ceiling. They exist to catch a
      pathological regression — a deadlock, or per-record work that grows with
      what the registry already holds — not to pin a number on a shared CI box.
      Revisit if instrumentation moves into an inner loop; that is the condition
      that would change the answer.

### Still deferred

- [ ] Wire `compare_span_reports` into a CI lane. The comparison and capture are
      in place and tested; choosing a baseline artifact and a tolerance is a
      launch-lane decision that belongs with Plan 311's large-image work, not
      here.
- [ ] Guest-side profiling for `mvm-agentd`, which needs a path to get a profile
      out of the guest before instrumenting it is worth anything.

## Usage

```sh
MVM_SPAN_TIMINGS=1 mvmctl <command>            # table to stderr
MVM_SPAN_TIMINGS=json mvmctl <command>         # JSON to stderr
MVM_SPAN_TIMINGS=json MVM_SPAN_TIMINGS_OUT=/tmp/p.json mvmctl <command>
MVM_SPAN_TIMINGS=1 MVM_SPAN_TIMINGS_FILTER=mvm_fs=trace mvmctl <command>
```

Profiling is off unless `MVM_SPAN_TIMINGS` is set; when off the layer is never
installed and the cost is that of a disabled span.

## Interpreting the report

`self` is time in the function excluding nested instrumented calls, and is the
column that identifies what to optimize. `total` includes nested calls, so a
high-total/low-self row is an orchestrator whose cost lives in a callee. `wall`
exceeds `total` when a span was open but not entered — on async code that gap
is time awaiting something else.

Percentiles are histogram estimates carrying ~12% bucket error. They are a
profiling signal, not an SLO measurement.

## Witnesses

- `crates/mvm-core/tests/span_timing.rs` — 10 end-to-end tests, including
  `instrumented_function_is_timed_despite_a_quiet_log_filter` (the CLI's default
  posture) and `a_registry_wide_filter_suppresses_span_construction_and_yields_no_timings`
  (locks in the diagnosis above, and fails if the layer stack regresses to a
  registry-wide filter).
- `nested_spans_attribute_self_time_to_the_function_doing_the_work` and
  `self_times_sum_to_roughly_the_wall_clock_of_the_root` cover self-time
  attribution.
- Unit tests in each `span_timing` module cover histogram bucketing and
  quantiles, registry aggregation and ordering, and report rendering.
