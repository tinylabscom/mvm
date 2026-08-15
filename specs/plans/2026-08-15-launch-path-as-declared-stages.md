# Launch path as declared stages

Backing: preview
Validation: none

**Status:** OPEN — no workstream started
**Opened:** 2026-08-15

## Why this plan exists

`resolve_launch` (`crates/mvm-cli/src/exec.rs`) is a strictly sequential
function with five hand-rolled `Instant::now()` / `tracing::debug!("admit
window: …")` pairs bolted onto it. Its own comment concedes the problem:
`admit_ms` is "a window, not a call", whose remainder "needs naming before any
of it can be acted on".

Two things follow from that shape. Several of the steps are independent
filesystem probes and cache lookups, serialized only because they each mutate
`start_config` in turn. And the largest span in the function is unattributed,
so there is nothing to aim at.

### What this does *not* move — read before scoping

The 200ms figure is real but it is **not on this code**:

- `PREPARED_COLD_P50_BUDGET_MS = 200.0` (`crates/mvm-cli/src/bench/cold_launch.rs`),
  with p95 250ms and p99 300ms.
- `require_budget` applies those to `report.stats.dispatch_window_ms` **only**.
- `RunPhaseTimings::dispatch_window_ms()` is `backend_start_ms + vsock_wait_ms`.

`resolve_launch` produces `resolve_ms`, `drives_ms` and `admit_ms`. Those are
sampled and reported, and no budget is applied to any of them. So this
workstream is entirely outside the budgeted window: it cannot regress the 200ms
number and it cannot improve it either. It reduces end-to-end wall clock
(`total_ms`), which is what a user experiences as start-up time, and that is the
only ground it should be justified on.

Note also that the `Boot latency ceiling` job in `.github/workflows/ci.yml` is
`if: github.event_name == 'workflow_dispatch'`, so the 200ms budget does not
gate a PR. It runs on manual dispatch.

**WS0 exists because of this.** Attribute the cost before restructuring for it:
a restructuring justified by a number it cannot move is the wrong change, even
if the restructuring is independently worth having for testability.

## Design

No new framework crate and no async runtime on `mvm-cli`'s hot path. The
independent work is filesystem probing, so `std::thread::scope` is sufficient
and adds no dependency.

Extract each step into a named free function taking a shared immutable context
and returning its own product — small enough to unit test, which the current
inline body is not.

| Stage | Mode | Steps |
|---|---|---|
| 1 | sequential | `resolve_image_artifacts` |
| 2 | **parallel** | `resolve_boot_strategy` probe · runtime-overlay lookup · universal-initramfs lookup |
| 3 | sequential | `build_start_config` + `admit_fn` |
| 4 | sequential | apply stage-2 products, `emit_runtime_source_status` |

The win is stage 2. `attach_runtime_overlay_if_cached` and
`attach_universal_initramfs_if_cached` run after admission today purely because
they mutate `start_config`. Split each into a pure `lookup_*` returning what it
found and a trivial `attach_*` that applies it; the lookups then move ahead of
admission and run alongside the boot-strategy probe.

### Ordering constraint — security-relevant

Those two `attach_*` calls currently run **after** admission. Moving their
*application* earlier would change what the signed plan covers.

- [ ] Only the **lookups** move into the parallel stage. Application stays
      exactly where it is relative to admission — stage 4, after stage 3.
- [ ] Admission stays sequential and single-threaded; it is never a parallel
      stage task.
- [ ] Stage 2 tasks take `&Ctx` and return owned products. `start_config` is
      touched only in stages 3 and 4, on one thread.

Behaviour-preserving: same resolved `VmStartConfig`, same admitted plan
contents, same ordering of anything the plan signs.

### Instrumentation

Do not build a metrics framework. `crates/mvm-cli/src/commands/vm/phase_timing.rs`
already has `SubPhase`, `LaunchSubMarks::start`/`finish`, `dispatch_window_ms()`
and `within_warm_start_slo()`. Add one `SubPhase` variant per stage and have the
stage runner bracket each, replacing the five ad-hoc timing pairs.

## Workstreams

- [ ] **WS0** — attribute the cost first. Record `resolve_ms` / `drives_ms` /
      `admit_ms` / `dispatch_window_ms` / `total_ms` for a prepared-cold launch
      on one host and image. If `resolve_launch` is a small share of `total_ms`,
      stop: the remaining workstreams are then a testability change, not a
      latency one, and should be scoped and justified as such.
- [ ] **WS1** — split `attach_runtime_overlay_if_cached` and
      `attach_universal_initramfs_if_cached` into `lookup_*` + `attach_*`, with
      a unit test each over a temp cache root (hit, miss, malformed).
- [ ] **WS2** — extract the `resolve_launch` steps into named functions and run
      them as the staged table above.
- [ ] **WS3** — add the `SubPhase` variants and bracket each stage. Add
      `every_launch_stage_is_timed`, so a future stage cannot be added untimed.
- [ ] **WS4** — golden-compare the resolved `VmStartConfig` against `main` for
      the same inputs. Record `total_ms` before/after, and `dispatch_window_ms`
      as a no-change control: this workstream must leave the budgeted window
      untouched.

## Files

- `crates/mvm-cli/src/exec.rs` — `resolve_launch` decomposition
- `crates/mvm-cli/src/commands/vm/up/` — the `lookup_*` / `attach_*` split
- `crates/mvm-cli/src/commands/vm/phase_timing.rs` — new `SubPhase` variants

## Origin

Split out of the artifact-derived runtime identity work
(`specs/sprint/delivery/artifact-derived-runtime-identity.md`), which shares no
files with this and landed first so its cache-staleness class would not muddy
these timing measurements.
