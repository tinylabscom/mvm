# Launch path as declared stages

Backing: preview
Validation: none

**Status:** OPEN — WS0 done; WS1-WS3 rescoped as testability work
**Opened:** 2026-08-15
**WS0 measured:** 2026-08-15

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

- [x] **WS0** — attribute the cost first. **Done 2026-08-15. Result: this is
      not a latency change.** See "WS0 result" below.
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

## WS0 result — measured 2026-08-15

`resolve_launch` driven through the existing no-boot harness
(`resolve_launch_yields_a_bootable_config_without_starting_a_vm`'s fixture:
prebuilt image, `mock` backend, deny-all policy), 30 rounds after 3 warm-up
rounds, macOS 26.5.2 / arm64:

```
p50 = 6.694 ms   p95 = 7.615 ms   max = 7.638 ms
```

Against the budgeted window (`dispatch_window_ms` p50 budget 200ms) the whole
of `resolve_launch` is ~3%, and it is not inside that window in the first place.

### Why this settles it, despite the measurement's limits

The probe understates the real path in two ways, and neither changes the
conclusion:

- It resolves a **prebuilt** image, so it never enters the OCI path or calls
  `oci_runtime_tag` (separately measured at 2.6ms steady-state).
- It passes `admit = None`, so **admission is not exercised at all**. The
  in-code comment on `resolve_launch` suggests admission is roughly half the
  `admit_ms` window, so the real figure is larger — possibly much larger.

That second gap would matter if admission were parallelisable. It is not:
admission is stage 3, and the security constraint above requires it to stay
sequential and single-threaded, with the `attach_*` application after it. The
only work this plan makes concurrent is stage 2 — the boot-strategy probe and
the two cache lookups — all of which sit inside the ~6.7ms envelope measured
here.

So the parallelism ceiling for the whole restructuring is a few milliseconds,
whatever admission costs. **Perfect execution of WS1–WS3 cannot produce a
user-visible latency improvement.**

### What follows

- WS1–WS3 remain worth doing, on **testability and observability** grounds:
  `resolve_launch` is a single branchy function that cannot be unit-tested
  piecewise, and its largest span is unattributed. Both are real defects
  against the repo's own "compose small, testable units" rule. They are not a
  latency fix and must not be justified as one.
- If launch latency is the actual goal, the budgeted window is
  `backend_start_ms + vsock_wait_ms`. That is where the 200ms lives and where
  attribution should go next. Nothing in this plan touches it.

## Files

- `crates/mvm-cli/src/exec.rs` — `resolve_launch` decomposition
- `crates/mvm-cli/src/commands/vm/up/` — the `lookup_*` / `attach_*` split
- `crates/mvm-cli/src/commands/vm/phase_timing.rs` — new `SubPhase` variants

## Origin

Split out of the artifact-derived runtime identity work
(`specs/sprint/delivery/artifact-derived-runtime-identity.md`), which shares no
files with this and landed first so its cache-staleness class would not muddy
these timing measurements.
