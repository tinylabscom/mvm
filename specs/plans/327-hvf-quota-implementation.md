# Plan 327 Phases 1–3 — Implementation

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a `CpuGrant::Share` a real bound on the HVF tier by scheduling
our own vCPU against a quota in our own run loop, and report the tier from the
scheduler's *measured* achievement rather than its configured target.

**Design spec:** [`327-hvf-vcpu-quota.md`](327-hvf-vcpu-quota.md).
**Measurements the design is built on:**
[`327-hvf-quota-spike-findings.md`](327-hvf-quota-spike-findings.md). Read both
before Task 1. The spike's numbers are constraints, not suggestions.

**Architecture:** three layers, each testable without the one above it.

1. A **pure policy** (`mvm-vmm::quota::policy`) that owns `(quota, period)` and
   answers "how long may the vCPU run, and how long must it be held" from a
   consumed-CPU reading. No threads, no clocks, no FFI — every envelope rule
   and the debt carry-over are unit-testable on any host.
2. A **thread CPU clock** (`mvm-vmm::quota::clock`) behind a trait, with a Mach
   `thread_info` implementation on macOS and a fake for tests.
3. A **controller thread** (`mvm-vmm::quota::controller`) that owns the
   `VcpuHandle`, sleeps to the policy's predicted exhaustion instant, reads the
   clock once per period, calls `force_exit` itself, and holds the vCPU through
   a throttle seam in the run loop that is deliberately *not* the pause seam
   (see hazard 1). It accumulates what it actually achieved and writes that measurement to the VM's state dir, which is what
   Phase 2 reads back.

The read-back mirrors `mvm_core::cpu_scope` exactly: something is recorded at
spawn time, and the tier is derived by reading it back off the system rather
than from the value that was written. The one difference is that macOS has no
kernel file to consult, so the recorded artifact is the scheduler's own
measurement — which is why an overshooting run must read back as `Declared`.

**Tech Stack:** Rust, `serde`, `libc` (which already exposes Apple's
`thread_info`, `mach_thread_self`, `THREAD_BASIC_INFO` — no new dependency),
`cargo nextest`.

## Global Constraints

- **Worktree:** `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-327-p1`,
  branch `feat/327-phase1-hvf-quota`. All work happens there, never in the main
  checkout and never in another session's worktree.
- **HVF only.** libkrun is a third-party in-process VMM whose vCPUs we do not
  drive; macOS 13-25 stays declared-only and the ADR must keep saying so. No
  task in this plan may make libkrun claim a CPU bound.
- **Every witness proven red before green.** Write the test, run it, paste the
  failure into the report, then implement. A test that was never red is not a
  witness.
- **`mvm-contract` is `#![no_std]` + alloc and must keep building for
  `wasm32-unknown-unknown`.** Use `alloc::string::String`; no `std::`.
- **No floating point in any signed or serialized payload.** CPU is `u32`
  millicores; periods are `u32` milliseconds. Compute ratios in integer
  microseconds internally.
- **`#[serde(deny_unknown_fields)]` on every new serialized type.**
- **No `#[allow(clippy::...)]`, ever.** A function that trips
  `too_many_arguments` gets a params struct with a builder.
- **No plan/PR/ADR references in code comments** — `xtask
  check-no-spec-refs-in-comments` fails the build. Comments explain *why*, not
  which plan asked for it.
- **All `~/.mvm` paths go through `mvm_core::config`.** Never build a path from
  `$HOME` inline.
- **Scratch files go in `/tmp`**, never in the repo tree.
- **Gate before every push** (all of these, from the worktree):
  - `cargo +nightly fmt --all -- --check`
  - `cargo nextest run --workspace`
  - `cargo test --workspace --doc`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - test-support lane: `cargo nextest run -p mvm-vmm --features test-support
    --lib`, and the same for `mvm-backends`, `mvm-runtime`, `mvm-client`,
    `mvm-cli`
  - client-facade lane: `cargo nextest run -p mvm-core --features client-remote`
  - `just check-linux` (the quota module must still compile for Linux even
    though its clock is macOS-only)

## The measured constraints this plan must build inside

Taken from the spike; each one has a task that witnesses it.

| Constraint | Number behind it |
| --- | --- |
| Predictive, not polling | polling cost 8.57 % of the enforced budget at 1 ms and still missed by +16 %; predictive hit -0.01 % at 0.46 % |
| Debt carried across periods | without it every period ran 8–33 % high |
| Period floor 5 ms | below it the run loop's 1 ms pause-hold quantum caps precision regardless of controller design |
| Period exceeds the slowest device op | `force_exit` only latches, so a 1 ms device op at a 500 µs period produced -11.5 % instantaneous error |
| Run slice and hold both ≥ 2 ms | 10 % and 90 % quotas at a 10 ms period missed by -42.8 % and -4.8 % |
| Ceiling 1.0 core | the HVF backend creates exactly one vCPU and the FDT emits a single `cpu@0` |
| The controller holds the `VcpuHandle` | driving the production `paused` flag alone achieved 0.82 cores against a 0.50 target, because the watchdog only cancels every 5 ms |
| Worst-case stall is `period × (1 - quota)` | 7.5 ms at the recommended 10 ms period; 31.5 ms at 50 ms |

## Structural hazards found while planning (read before Task 1)

1. **A quota hold must not reuse the pause seam.** `run.rs:207-221` calls
   `RunDevice::prepare_snapshot()` on every device the first time
   `should_pause()` goes true, and the vsock device's override stops its
   host-I/O owner and clears host bindings. `kernel_boot.rs:1080-1094`'s
   `should_pause` closure also writes the `pause_state` marker, and its
   `on_pause` hook (`kernel_boot.rs:1095+`) is the snapshot publisher. Driving
   any of that once per 10 ms period would tear down guest I/O continuously.
   The run loop therefore needs a **throttle hold** distinct from the pause
   hold: same 1 ms poll-and-sleep quantum, same device polling (so host→guest
   I/O keeps flowing while the vCPU is parked), and none of the snapshot
   machinery.
2. **The vCPU thread is the thread that called `boot_kernel_until`** — in
   production, the main thread of the per-VM `mvm-hvf-supervisor` process
   (`crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs:297`). No vCPU thread is
   spawned. So the controller must capture that thread's Mach port *before*
   spawning itself, and the controller is the spawned thread.
3. **`run_with_pause_hook` already takes 7 arguments.** An eighth trips
   `clippy::too_many_arguments`, which this repo bans outright. The throttle
   seam arrives as a params struct, not another positional argument.
4. **`libc` already exposes Apple's Mach thread accounting** —
   `libc::thread_info`, `libc::mach_thread_self`, `libc::thread_basic_info`,
   `libc::THREAD_BASIC_INFO`, `libc::THREAD_BASIC_INFO_COUNT` are all present
   in the pinned `libc` on `target_os = "macos"`, and `mvm-vmm` already depends
   on `libc`. **Do not add `mach2` or any other crate.**
5. **The grant reaches the supervisor through `HvfSupervisorConfig`**
   (`crates/mvm-vmm/src/host/hvf_supervisor.rs:94`), which is the one config
   contract the driver writes and the supervisor bin reads. The HVF driver
   already reads `spec.cpu_grant` at
   `crates/mvm-backends/src/driver/hvf.rs:272-276` to wrap the spawn in a
   systemd scope (a no-op on macOS); that call stays, and the new field is set
   from the same `spec.cpu_grant`.

## File Structure

**New:**

| File | Responsibility |
| --- | --- |
| `crates/mvm-vmm/src/quota/mod.rs` | Module root; re-exports `QuotaConfig`, `QuotaPolicy`, `VcpuQuota`, `QuotaAchievement` |
| `crates/mvm-vmm/src/quota/policy.rs` | Pure `QuotaConfig` validation + `QuotaPolicy` allowance/debt arithmetic |
| `crates/mvm-vmm/src/quota/clock.rs` | `ThreadCpuClock` trait, Mach implementation, test fake |
| `crates/mvm-vmm/src/quota/controller.rs` | The controller thread: predict, read once, `force_exit`, hold, measure |
| `crates/mvm-contract/src/protocol/vcpu_quota.rs` | `VcpuQuotaRecord` — the measured-achievement DTO |
| `crates/mvm-core/src/vcpu_quota.rs` | Record write/read under a VM state dir + `tier_for_vm` + degradation reason |
| `crates/mvm-vmm/tests/vcpu_quota_live.rs` | `#[ignore]`d live measurement on real Apple Silicon |

**Modified:**

| File | Change |
| --- | --- |
| `crates/mvm-vmm/src/vmm/run.rs` | `RunHooks` params struct + `run_with_hooks` + the throttle hold; `run`/`run_with_pause_hook` become wrappers |
| `crates/mvm-vmm/src/lib.rs` | `pub mod quota;` |
| `crates/mvm-contract/src/protocol/resource_controls.rs` | `CpuControl::HvfVcpuQuota`, `EnforcedTier::HvfVcpuQuota`, the `Hvf | AppleContainer` arm of `for_backend` |
| `crates/mvm-contract/src/protocol/mod.rs` | `pub mod vcpu_quota;` |
| `crates/mvm-core/src/lib.rs` | `pub mod vcpu_quota;` |
| `crates/mvm-vmm/src/host/hvf_supervisor.rs` | `cpu_millicores` + `quota_record` fields on `HvfSupervisorConfig` |
| `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs` | Start/stop the controller around the run; thread the throttle predicate in |
| `crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs` | Pass the config's quota through to `KernelBootUntilParams` |
| `crates/mvm-backends/src/driver/hvf.rs` | Set the new config fields from `spec.cpu_grant` |
| `crates/mvm-backends/src/legacy/hvf.rs` | `impl VmBackend::apply_grants` reading the measured record back |
| `crates/mvm-hostd/src/plan_admission.rs` | The HVF arm of the enforceability gate |
| `specs/adrs/001-microvm-security-posture.md` | Claim 18 limit 1 + the claims-table row |
| `CLAUDE.md` | The claim-18 paragraph |

## Task Dependency Order

```
Task 1 (policy) ─┐
Task 2 (clock)  ─┼─→ Task 4 (controller) ─→ Task 6 (wiring) ─→ Task 7 (live witness + docs)
Task 3 (run loop)┘                      ↗
Task 5 (record + tier) ────────────────┘
```

Tasks 1, 2, 3 and 5 are independent of each other. Task 4 needs 1 and 2.
Task 6 needs 3, 4 and 5. Task 7 needs 6.

---

### Task 1: The quota policy — pure arithmetic, no threads

**Files:**
- Create: `crates/mvm-vmm/src/quota/mod.rs`, `crates/mvm-vmm/src/quota/policy.rs`
- Modify: `crates/mvm-vmm/src/lib.rs` (add `pub mod quota;`)

**Interfaces produced:**

```rust
pub struct QuotaConfig { millicores: u32, period: Duration }

impl QuotaConfig {
    pub const MIN_PERIOD: Duration      = Duration::from_millis(5);
    pub const DEFAULT_PERIOD: Duration  = Duration::from_millis(10);
    pub const MAX_PERIOD: Duration      = Duration::from_millis(100);
    pub const MIN_SLICE: Duration       = Duration::from_millis(2);
    pub const MAX_MILLICORES: u32       = 1000;

    /// The shortest period at or above `DEFAULT_PERIOD` at which this share's
    /// run slice and hold both clear `MIN_SLICE`. Errs when no period up to
    /// `MAX_PERIOD` can express the share.
    pub fn for_share(millicores: u32) -> anyhow::Result<Self>;
    /// An explicitly chosen period, validated against every rule.
    pub fn new(millicores: u32, period: Duration) -> anyhow::Result<Self>;
    pub fn millicores(&self) -> u32;
    pub fn period(&self) -> Duration;
    /// CPU time the vCPU may consume per period.
    pub fn slice(&self) -> Duration;
    /// The guest-visible worst-case freeze, `period × (1 - quota)`.
    pub fn worst_case_stall(&self) -> Duration;
}

pub struct QuotaPolicy { config: QuotaConfig, debt: Duration }

pub struct PeriodVerdict { pub hold: bool, pub allowance: Duration }

impl QuotaPolicy {
    pub fn new(config: QuotaConfig) -> Self;
    pub fn config(&self) -> &QuotaConfig;
    pub fn debt(&self) -> Duration;
    /// CPU the vCPU may burn this period: this period's slice less the debt
    /// carried in, floored at zero.
    pub fn allowance(&self) -> Duration;
    /// Fold one period's measurement in. `consumed_total` is vCPU CPU time
    /// since the controller started; `periods_elapsed` counts periods that
    /// have *completed*, including this one. Updates the carried debt and
    /// answers whether the vCPU must be held for the rest of this period.
    pub fn settle(&mut self, consumed_total: Duration, periods_elapsed: u32) -> PeriodVerdict;
}
```

**Rules, each with the measurement behind it:**

- `MIN_PERIOD` 5 ms: below it the run loop's 1 ms hold quantum caps precision
  regardless of controller design (spike §Q3).
- `MIN_SLICE` 2 ms on **both** the run slice and the hold: 10 % and 90 % quotas
  at a 10 ms period missed by -42.8 % and -4.8 % because one side collapsed to
  the 1 ms quantum (spike §Q1 quota sweep).
- `MAX_MILLICORES` 1000: the HVF backend creates exactly one vCPU
  (`kernel_boot.rs:730`), so 1.0 core is the ceiling.
- `for_share` picks `period_ms = max(10, ceil(2000/m), ceil(2000/(1000-m)))`
  and errs above `MAX_PERIOD`. That makes shares in **[20, 980] millicores**
  expressible and everything outside it an honest refusal rather than a bound
  that silently misses.
- **Debt is capped at one period's worth of CPU time.** The period must exceed
  the slowest uninterruptible host-side device operation (spike §Hazard), so a
  single overrun cannot exceed one period; capping there absorbs exactly one
  overrun and makes it impossible for debt to compound into an unbounded
  freeze. Uncapped debt would turn a long device stall into a multi-period
  guest hang.

- [ ] **Step 1: Write the failing tests** in `policy.rs`'s `#[cfg(test)] mod
      tests`, run them, and paste the failure output into the report. These
      names are the witnesses; use them verbatim:

  | Test | Asserts |
  | --- | --- |
  | `a_default_share_lands_on_the_recommended_ten_millisecond_period` | `for_share(500).period() == 10ms`; the spike's recommended default |
  | `a_lopsided_share_lengthens_the_period_rather_than_missing_its_target` | `for_share(100).period() == 20ms` and `for_share(900).period() == 20ms`; both slice and hold clear 2 ms |
  | `a_share_no_period_can_express_is_refused_with_the_expressible_range` | `for_share(19)` and `for_share(981)` are `Err`, and the message names 20 and 980 |
  | `a_share_over_the_single_vcpu_ceiling_is_refused` | `for_share(1500)` is `Err` naming the 1.0-core ceiling |
  | `a_period_below_the_floor_is_refused` | `new(500, 4ms)` is `Err`; `new(500, 5ms)` is `Ok` |
  | `a_period_over_the_ceiling_is_refused` | `new(500, 101ms)` is `Err` |
  | `an_explicit_period_that_collapses_a_slice_is_refused` | `new(100, 10ms)` is `Err` (slice 1 ms), `new(900, 10ms)` is `Err` (hold 1 ms) |
  | `the_slice_is_the_period_scaled_by_the_share` | `new(500, 10ms).slice() == 5ms`; `new(250, 20ms).slice() == 5ms` |
  | `the_worst_case_stall_is_the_period_less_the_slice` | `new(500, 10ms).worst_case_stall() == 5ms`; matches the spike's `period × (1 - quota)` |
  | `an_unspent_period_carries_no_credit_forward` | consume less than the slice; next `allowance()` is the full slice, never more — cgroup `cpu.max` grants no credit either |
  | `an_overspent_period_carries_its_overshoot_as_debt` | consume `slice + 2ms` in period 1; `allowance()` is `slice - 2ms` |
  | `debt_repays_across_periods_until_the_average_converges` | after an overshoot, several exactly-on-budget periods; debt returns to zero and stays there |
  | `debt_never_exceeds_one_period_so_a_stall_cannot_compound` | consume `slice + 10 × period` in one period; `debt() == period`, and `allowance()` is zero rather than negative |
  | `a_period_that_did_not_exhaust_its_allowance_needs_no_hold` | `settle` with `consumed_total` below the allowance returns `hold: false` |
  | `a_period_that_spent_its_allowance_must_hold` | `settle` at exactly the allowance returns `hold: true` |

- [ ] **Step 2: Implement** `QuotaConfig` and `QuotaPolicy` so the tests pass.
      All arithmetic in integer microseconds — no `f32`/`f64` anywhere.
      `settle` computes entitlement as `slice × periods_elapsed` and debt as
      `consumed_total.saturating_sub(entitlement).min(period)`; deriving debt
      from a cumulative total rather than per-period bookkeeping is what makes
      the carry-over exact.
- [ ] **Step 3:** `cargo nextest run -p mvm-vmm --lib quota::` green, `cargo
      clippy -p mvm-vmm --all-targets -- -D warnings` clean, `cargo +nightly
      fmt --all`.

---

### Task 2: The thread CPU clock

**Status:** COMPLETE — implemented, tested, clippy/fmt clean, Linux cross-build passes.

**Files:**
- Create: `crates/mvm-vmm/src/quota/clock.rs`

**Interfaces produced:**

```rust
/// A source of one thread's consumed CPU time (user + system).
pub trait ThreadCpuClock: Send + 'static {
    /// Total CPU consumed by the thread this clock was opened on.
    fn consumed(&self) -> Duration;
}

/// A handle to another thread's CPU accounting, captured on that thread.
pub struct ThreadCpuHandle(/* platform-specific */);

impl ThreadCpuHandle {
    /// Capture the calling thread. Must be called *on* the thread to be
    /// measured; the returned handle is `Send` so a controller thread can
    /// read it.
    pub fn for_current_thread() -> anyhow::Result<Self>;
}

impl ThreadCpuClock for ThreadCpuHandle { .. }
```

**Constraints:**

- macOS implementation only, via `libc::thread_info` with
  `libc::THREAD_BASIC_INFO` / `libc::THREAD_BASIC_INFO_COUNT` on the port from
  `libc::mach_thread_self()`, summing `user_time` + `system_time`. **No new
  crate.** The whole `unsafe` surface is one `thread_info` call and one
  `mach_port_deallocate`; keep it to a single small `unsafe` block with a
  `// SAFETY:` comment.
- `mach_thread_self()` returns a send right that leaks unless deallocated.
  `ThreadCpuHandle` must own the port and deallocate it in `Drop`.
- The module must **compile on Linux** (`just check-linux` is in the gate). Use
  `#[cfg(target_os = "macos")]` for the Mach body and a non-macOS arm whose
  `for_current_thread()` returns `Err` naming the platform. Do not stub it with
  a zero clock — a clock that always reads zero would make a controller
  silently never throttle.
- A test fake lives behind `#[cfg(any(test, feature = "test-support"))]`:
  `FixedClock` / `ScriptedClock` that returns a caller-supplied sequence of
  `Duration`s and counts how many times it was read. The read count is what
  Task 4's "predictive, not polling" witness asserts against, so it must be
  observable.

- [x] **Step 1: Write the failing tests**, run them, paste the failure:

  | Test | Asserts |
  | --- | --- |
  | `a_captured_thread_reports_monotonically_increasing_cpu_time` | macOS-only (`#[cfg(target_os = "macos")]`): capture, burn a measurable amount of CPU in a busy loop, read twice; the second read is strictly greater and the delta is within an order of magnitude of the wall time burned |
  | `a_thread_that_slept_is_charged_almost_nothing` | macOS-only: sleep 50 ms; the CPU delta is under 5 ms — proves the clock measures CPU, not wall |
  | `a_scripted_clock_counts_its_reads` | the fake reports its readings in order and exposes the read count |
  | `capturing_a_thread_off_macos_fails_loudly_rather_than_reading_zero` | non-macOS: `for_current_thread()` is `Err` |

- [x] **Step 2: Implement.**
- [x] **Step 3:** `cargo nextest run -p mvm-vmm --lib quota::clock`, clippy,
      fmt, and `just check-linux` to prove the Linux arm compiles.

---

### Task 3: A throttle hold in the run loop, distinct from the pause hold

**Status:** COMPLETE — `RunHooks`, `run_with_hooks`, throttle hold, and wrapper
entry points implemented; 7 new tests pass; `mvm-runtime` callers unaffected.

**Files:**
- Modify: `crates/mvm-vmm/src/vmm/run.rs`

**Why a new seam rather than reusing `should_pause`:** hazard 1 above. A
throttle that reused the pause seam would call `RunDevice::prepare_snapshot()`
— which stops the vsock device's host-I/O owner — once per period.

**Interfaces produced:**

```rust
/// The hooks the run loop consults. A struct rather than more positional
/// arguments: the loop already takes seven, and an eighth would trip the
/// argument-count lint this repo bans exceptions to.
pub struct RunHooks<X, Q, P, H, T> {
    pub on_exception: X,
    pub should_stop: Q,
    pub should_pause: P,
    pub on_pause: H,
    /// True while the vCPU must be held out of guest execution to stay inside
    /// its CPU quota. Polled like `should_pause`, but parks the vCPU without
    /// touching any snapshot machinery.
    pub should_throttle: T,
}

pub fn run_with_hooks<C, S, X, Q, P, H, T>(
    vcpu: &C, set_irq: S, devices: &mut [&mut dyn RunDevice],
    hooks: RunHooks<X, Q, P, H, T>,
) -> Result<RunOutcome, C::Error>;
```

`run` and `run_with_pause_hook` keep their present signatures and become thin
wrappers that fill the missing hooks with `|_, _| Ok(())` and `|| false`, so
the two `kvm/vm.rs` call sites (`vm.rs:140`, `vm.rs:239`) and the
`kernel_boot.rs:1044` call site need no change in this task.

**The hold, placed in the `VcpuExit::Canceled` arm after the pause block:**

```rust
// A throttle is not a pause: the vCPU is parked to stay inside its CPU
// quota, and the guest's device state must survive it untouched. Devices are
// still polled every millisecond so host→guest I/O keeps flowing while the
// vCPU is out of guest execution; nothing else from the pause path runs.
while (hooks.should_throttle)() && !(hooks.should_stop)() && !(hooks.should_pause)() {
    for d in devices.iter_mut() {
        if let Some(irq) = d.poll() { set_irq(irq, true)?; }
    }
    std::thread::sleep(Duration::from_millis(1));
}
```

- [x] **Step 1: Write the failing tests** in `run.rs`'s existing test module,
      alongside `canceled_with_pause_holds_until_resume_then_continues`
      (`run.rs:572`), which is the pattern to copy. Run them, paste the failure:

  | Test | Asserts |
  | --- | --- |
  | `a_throttle_hold_parks_the_vcpu_until_it_clears` | with `should_throttle` true for ~40 ms then false, the loop blocks for at least that long and then continues; mirrors the pause test |
  | `a_throttle_hold_never_prepares_a_snapshot` | a `RunDevice` counting `prepare_snapshot()` calls records **zero** across a throttle hold, and non-zero across a pause hold — the difference is the point of the seam |
  | `a_throttle_hold_never_calls_the_pause_hook` | the `on_pause` hook's call count stays zero across a throttle hold |
  | `a_throttle_hold_keeps_polling_devices` | a device's `poll()` count rises during the hold, so host→guest I/O is not stalled by a throttle |
  | `a_stop_breaks_a_throttle_hold` | setting stop during a throttle returns `RunOutcome::Canceled` rather than spinning |
  | `a_pause_during_a_throttle_takes_precedence` | with both set, the loop is in the pause hold (snapshot machinery runs) and leaves the throttle hold |
  | `the_existing_entry_points_throttle_never` | `run` and `run_with_pause_hook` behave exactly as before — a regression net for the two `kvm/vm.rs` callers |

- [x] **Step 2: Implement** `RunHooks`, `run_with_hooks`, the throttle hold,
      and rewrite `run`/`run_with_pause_hook` as wrappers.
- [x] **Step 3:** `cargo nextest run -p mvm-vmm --lib vmm::run`, plus `cargo
      nextest run -p mvm-runtime --lib` (the KVM callers), clippy, fmt.

---

### Task 4: The controller — predict, read once, hold, measure

**Files:**
- Create: `crates/mvm-vmm/src/quota/controller.rs`

**Interfaces produced:**

```rust
/// What the scheduler actually delivered. The only honest source for the
/// enforced tier on this tier, since macOS exposes no quota file to read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaAchievement {
    pub target_millicores: u32,
    pub achieved_millicores: u32,
    pub period: Duration,
    pub measured_wall: Duration,
    pub measured_cpu: Duration,
    pub periods: u32,
}

pub struct VcpuQuota { /* hold flag, stop flag, join handle */ }

impl VcpuQuota {
    /// Start scheduling `handle` against `policy`, charging `clock`.
    pub fn start<H: VcpuHandle, C: ThreadCpuClock>(
        handle: H, clock: C, policy: QuotaPolicy,
    ) -> Self;
    /// A predicate for `RunHooks::should_throttle`.
    pub fn throttle_flag(&self) -> Arc<AtomicBool>;
    /// Stop the controller and take its measurement.
    pub fn stop(self) -> QuotaAchievement;
}
```

**The loop, per period:**

1. Clear the hold flag.
2. `allowance = policy.allowance()`; sleep exactly that long. This is the
   prediction: on a uniprocessor tier the vCPU can burn at most 1.0 core, so
   `allowance` of wall time is the earliest instant the allowance can be spent.
3. Read the clock **once** — `consumed_total`.
4. `verdict = policy.settle(consumed_total, periods_elapsed)`.
5. If `verdict.hold`: set the hold flag, then `H::force_exit(&[handle])`
   **in that order** — the flag must be visible before the vCPU leaves guest
   execution, or the run loop reaches the throttle check before it is set and
   re-enters the guest for another period. Sleep to the period boundary.
6. If not: sleep to the period boundary without holding (the guest idled and
   never spent its allowance).
7. On stop: clear the hold flag, `force_exit` once so a parked vCPU is not left
   in the hold, and return the accumulated achievement.

**Constraints:**

- **Exactly one clock read per period.** Polling cost 8.57 % of the enforced
  budget at a 1 ms period and still missed by +16 %; the predictive controller
  hit -0.01 % at 0.46 %. This is a witnessed property, not an aspiration.
- `achieved_millicores = measured_cpu.as_micros() × 1000 / measured_wall.as_micros()`,
  integer arithmetic, saturating.
- Clearing the hold flag must never require a `force_exit` — the run loop's
  throttle hold polls the flag every millisecond and leaves on its own.

- [ ] **Step 1: Write the failing tests**, driving the controller with a mock
      `VcpuHandle` that records its `force_exit` calls and the scripted clock
      from Task 2. Run them, paste the failure:

  | Test | Asserts |
  | --- | --- |
  | `the_controller_reads_the_clock_once_per_period` | over N periods the scripted clock's read count is exactly N — the predictive property, and the one that separates this from the polling design the spike rejected |
  | `a_vcpu_that_spent_its_slice_is_forced_out_and_held` | the mock handle records a `force_exit` and the throttle flag is set |
  | `an_idle_vcpu_is_never_forced_out` | a clock that barely advances produces zero `force_exit` calls and the flag stays clear |
  | `the_hold_flag_is_set_before_the_vcpu_is_forced_out` | the mock handle asserts the flag is already true when `force_exit` runs; the reverse order lets the guest run an extra period |
  | `an_overshooting_period_shrinks_the_next_allowance` | the debt carry is visible in the controller's own sleep schedule, not just in the policy |
  | `stopping_releases_a_parked_vcpu` | after `stop()` the throttle flag is clear and a final `force_exit` was issued |
  | `the_achievement_is_computed_from_measurement_not_from_the_target` | a clock scripted to overshoot yields `achieved_millicores > target_millicores`; the controller reports what happened, not what was asked |
  | `an_achievement_over_a_zero_wall_window_is_not_a_division_by_zero` | `stop()` immediately after `start()` returns a defined value |

- [ ] **Step 2: Implement.** Keep the thread body small enough to read: one
      `run_period` function that the loop calls, so the per-period logic is
      unit-testable on its own.
- [ ] **Step 3:** `cargo nextest run -p mvm-vmm --lib quota::`, clippy, fmt,
      `just check-linux`.

---

### Task 5: The record and the tier — what was achieved, not what was asked

**Files:**
- Create: `crates/mvm-contract/src/protocol/vcpu_quota.rs`,
  `crates/mvm-core/src/vcpu_quota.rs`
- Modify: `crates/mvm-contract/src/protocol/mod.rs`,
  `crates/mvm-contract/src/protocol/resource_controls.rs`,
  `crates/mvm-core/src/lib.rs`

**Interfaces produced:**

```rust
// mvm-contract — no_std + alloc, must keep building for wasm32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcpuQuotaRecord {
    pub target_millicores: u32,
    pub achieved_millicores: u32,
    pub period_ms: u32,
    pub measured_wall_ms: u64,
    pub measured_cpu_ms: u64,
    pub periods: u32,
}

impl VcpuQuotaRecord {
    /// Periods a run must complete before its measurement is long enough to
    /// attest to.
    pub const MIN_ATTESTABLE_PERIODS: u32 = 20;
    /// How far above target a run may land and still count as bounded.
    pub const TOLERANCE_PERCENT: u32 = 15;
    /// Whether this measurement witnesses a bound that actually held.
    pub fn bounded(&self) -> bool;
}
```

```rust
// mvm-core — std, mirrors cpu_scope's shape.
pub fn write_record(state_dir: &Path, record: &VcpuQuotaRecord) -> std::io::Result<()>;
pub fn read_record(state_dir: &Path) -> Option<VcpuQuotaRecord>;
/// The tier this VM's *measurement* witnesses. Never derived from config.
pub fn tier_for_vm(state_dir: &Path) -> EnforcedTier;
```

**The honesty rules, which are the point of this task:**

- No record ⇒ `EnforcedTier::Declared`. Same understating direction as
  `a_vm_with_no_recorded_scope_reads_back_as_declared_not_as_an_error`.
- A record with fewer than `MIN_ATTESTABLE_PERIODS` ⇒ `Declared`. The spike's
  short real-guest runs sat +9 % and +14 % off target over 1–2 s precisely
  because a handful of debt corrections is not a measurement.
- A record whose achievement exceeds target by more than `TOLERANCE_PERCENT`
  ⇒ `Declared`. **The mechanism ran and did not bound.** This is the whole
  reason the tier is computed from the measurement: on Linux a missing
  `cpu.max` is what reads back as unenforced, and this is its analogue.
- Otherwise ⇒ `EnforcedTier::HvfVcpuQuota`, label `"hvf:vcpu-quota"`.

**`resource_controls.rs` changes:**

- `CpuControl::HvfVcpuQuota`, included in `serves_share()`.
- `EnforcedTier::HvfVcpuQuota` with `label() == "hvf:vcpu-quota"`.
- The `BackendKind::Hvf | BackendKind::AppleContainer` arm answers
  `CpuControl::HvfVcpuQuota` when `cfg!(target_os = "macos")` and
  `CpuControl::None` otherwise — the same host-dependent shape the `Libkrun`
  arm already uses, and for the same reason. **`BackendKind::Libkrun` is not
  touched.**
- The existing `the_hvf_tier_cannot_bound_cpu` test
  (`resource_controls.rs:202-310`) asserts today's `None` and must be replaced
  by a macOS/non-macOS pair mirroring
  `the_libkrun_tier_bounds_cpu_via_cgroup_on_linux` /
  `the_libkrun_tier_cannot_bound_cpu_off_linux`. Renaming a witness means
  updating the ADR-001 claims table in Task 7 — note it in the report.

- [ ] **Step 1: Write the failing tests**, run them, paste the failure:

  | Test | Asserts |
  | --- | --- |
  | `a_vm_with_no_quota_record_reads_back_as_declared` | absent record ⇒ `Declared`, no error |
  | `an_unparseable_quota_record_reads_back_as_declared` | garbage in the file ⇒ `Declared`, never a panic |
  | `a_run_too_short_to_measure_reads_back_as_declared` | 19 periods ⇒ `Declared`; 20 ⇒ enforced |
  | `a_run_that_overshot_its_target_reads_back_as_declared` | achieved 700 against target 500 ⇒ `Declared` — the mechanism ran and did not bound |
  | `a_run_inside_tolerance_reads_back_as_enforced` | achieved 505 against target 500 ⇒ `HvfVcpuQuota` |
  | `a_run_under_its_target_is_still_a_bound` | achieved 300 against target 500 ⇒ `HvfVcpuQuota`; undershooting is a bound holding, not failing |
  | `a_quota_record_round_trips_through_json` | serde round trip |
  | `an_unknown_field_in_a_quota_record_is_refused` | `deny_unknown_fields` |
  | `the_hvf_tier_bounds_cpu_with_its_own_scheduler_on_macos` | `#[cfg(target_os = "macos")]`: `for_backend(Hvf).cpu == HvfVcpuQuota` and `serves_share()` |
  | `the_hvf_tier_cannot_bound_cpu_off_macos` | `#[cfg(not(target_os = "macos"))]`: `CpuControl::None` |
  | `the_libkrun_tier_still_cannot_bound_cpu_off_linux` | unchanged — libkrun is permanently out of scope |
  | `every_enforced_tier_has_a_distinct_label` | the new label is unique |

- [ ] **Step 2: Implement.** Keep `mvm-contract` `no_std`; the file I/O lives
      in `mvm-core`.
- [ ] **Step 3:** `cargo nextest run -p mvm-contract -p mvm-core`, plus a
      `wasm32-unknown-unknown` build of `mvm-contract`, clippy, fmt.

---

### Task 6: Wire it — grant to supervisor to controller to record

**Files (modify):** `crates/mvm-vmm/src/host/hvf_supervisor.rs`,
`crates/mvm-runtime/src/backends/hvf/kernel_boot.rs`,
`crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs`,
`crates/mvm-backends/src/driver/hvf.rs`,
`crates/mvm-backends/src/legacy/hvf.rs`,
`crates/mvm-hostd/src/plan_admission.rs`

**The chain:**

1. `HvfSupervisorConfig` gains `#[serde(default)] pub cpu_millicores:
   Option<u32>` and `#[serde(default)] pub quota_record: Option<PathBuf>`.
2. `crates/mvm-backends/src/driver/hvf.rs` sets both from `spec.cpu_grant`
   (`CpuGrant::Share` only — `Fuel` is wasmtime's unit and passes through
   untouched, exactly as `bind_cpu_grant` already treats it at `hvf.rs:272`).
   The record path resolves through `mvm_core::config`, never from `$HOME`.
3. `mvm-hvf-supervisor` threads them into `KernelBootUntilParams`.
4. `kernel_boot.rs`: after `let handle = vcpu.exit_token();`
   (`kernel_boot.rs:784`), capture the vCPU thread's clock with
   `ThreadCpuHandle::for_current_thread()` **before** spawning anything, start
   the `VcpuQuota`, pass its flag as `RunHooks::should_throttle`, and after
   `watchdog.join()` (`kernel_boot.rs:1132`) stop the controller and write the
   record.
5. `impl VmBackend for HvfBackend` (`crates/mvm-backends/src/legacy/hvf.rs:400`)
   gains `apply_grants`, returning `EnforcedGrants { cpu:
   mvm_core::vcpu_quota::tier_for_vm(state_dir), wall_clock: Declared }`.
6. `plan_admission.rs`'s enforceability gate: on the HVF tier a
   `CpuGrant::Share` that `QuotaConfig::for_share` refuses is treated exactly
   like a missing mechanism — refused under `--prod`, warned under dev. Reuse
   `mvm_core::cpu_scope::cpu_degradation_reason`'s shape; do not fork a second
   warning path.

**Constraints:**

- **Failing to start the controller must not fail the boot.** Same rule as
  `bind_cpu_grant`: the admission gate already decided whether an unenforceable
  grant was allowed, and the read-back is what keeps the outcome honest. Log
  and continue.
- No grant ⇒ no controller thread, no record file, no behaviour change. The
  unbounded path must be byte-identical to today.

- [ ] **Step 1: Write the failing tests**, run them, paste the failure:

  | Test | Asserts |
  | --- | --- |
  | `a_share_grant_reaches_the_supervisor_config` | the driver sets `cpu_millicores` and `quota_record` from `spec.cpu_grant` |
  | `a_fuel_grant_leaves_the_supervisor_config_alone` | `CpuGrant::Fuel` sets neither |
  | `no_grant_leaves_the_supervisor_config_alone` | `None` sets neither |
  | `a_supervisor_config_with_a_quota_round_trips` | serde round trip with the new fields, and an old config without them still parses (`serde(default)`) |
  | `an_hvf_vm_with_no_quota_record_reports_declared` | `apply_grants` on a state dir with no record ⇒ `Declared` |
  | `an_hvf_vm_with_a_bounded_record_reports_the_measured_tier` | a written record ⇒ `HvfVcpuQuota` |
  | `prod_admits_an_expressible_cpu_share_on_the_hvf_tier` | `#[cfg(target_os = "macos")]`: the gate no longer refuses; the inverse of today's `prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu` for this tier |
  | `prod_refuses_a_share_no_period_can_express_on_the_hvf_tier` | 19 millicores is refused under `--prod` with a message naming the expressible range |
  | `the_libkrun_tier_is_untouched_by_the_hvf_quota` | a libkrun spec still produces no quota config and still reports `Declared` off Linux |

- [ ] **Step 2: Implement** the chain.
- [ ] **Step 3:** full workspace suite, both feature lanes, clippy, fmt,
      `just check-linux`.

---

### Task 7: The live witness, the claim, and the docs

**Files:**
- Create: `crates/mvm-vmm/tests/vcpu_quota_live.rs`
- Modify: `specs/adrs/001-microvm-security-posture.md`, `CLAUDE.md`,
  `specs/plans/327-hvf-vcpu-quota.md`, `specs/REFACTOR-STATUS.md`,
  `specs/sprint/delivery/327-hvf-vcpu-quota.md` (new)

**The live witness** mirrors `crates/mvm-core/tests/cpu_scope_live.rs`: a
single `#[ignore = "needs a macOS host with Hypervisor.framework"]` test named
`a_granted_cpu_share_binds_a_real_vcpu_to_its_quota`, run explicitly with
`cargo test -p mvm-vmm --test vcpu_quota_live -- --ignored --nocapture`. Like
its Linux sibling it must **measure**, not read back what it wrote: drive a
real controller against a thread burning CPU in a loop, and assert the achieved
fraction lands within the spike's envelope of the target. It must fail loudly
rather than skip silently when run somewhere the mechanism is absent.

**Claim 18 limit 1** (`001-microvm-security-posture.md:244-256`) currently reads
"CPU is enforced on Linux and declared-only on macOS. (OPEN, permanent on
macOS.)" It becomes a statement about *which VMM is being driven*, not which
OS, and must say all of:

- Enforced on the HVF tier by our own run-loop scheduler; enforced on Linux by
  cgroup v2 `cpu.max`; **declared-only on libkrun**, permanently, because it is
  a third-party in-process VMM whose vCPUs we do not drive — so macOS 13-25,
  where libkrun is the default, stays declared-only.
- The HVF ceiling is **1.0 core** (uniprocessor) and the expressible share
  range is **[20, 980] millicores**.
- The guest **sees the bound as stolen time**, worst case `period × (1 -
  quota)` — 7.5 ms at the default 10 ms period. A cgroup hides this; this
  cannot.
- The tier is reported from the scheduler's **measured achievement**, and a run
  that overshot, or that was too short to measure, reads back as `Declared`.
- Update the witness names in the claim-18 row of the claims table to the ones
  this plan actually created — `xtask check-claim-catalog` parses that table
  and fails on a name that does not exist. Re-run it.

`CLAUDE.md`'s claim-18 paragraph gets the same correction, in its own voice.
Tick the Phase 1 and Phase 2 boxes in `327-hvf-vcpu-quota.md`, bump
`REFACTOR-STATUS.md` with its "Last updated" date, and write the delivery note
as its own file under `specs/sprint/delivery/` — never append to `SPRINT.md`.

- [ ] **Step 1:** Write the live witness; run it on this host with `--ignored`
      and paste the achieved-vs-target numbers into the report.
- [ ] **Step 2:** Update the ADR, the claims table, `CLAUDE.md`, the plan
      checkboxes, `REFACTOR-STATUS.md`, and the delivery note.
- [ ] **Step 3:** `cargo run -p xtask -- check-claim-catalog` and the rest of
      the xtask gates, then the full gate list.
