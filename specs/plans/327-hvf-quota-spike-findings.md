# Plan 327 Phase 0 — HVF vCPU quota spike: findings

**Verdict: Phase 1 proceeds**

Measured on this host, 2026-08-12.

## Environment

| | |
|---|---|
| OS | macOS 26.5.2 (build 25F84) |
| Arch | arm64, Apple M4 Max |
| CPUs | 16 logical (12 P + 4 E) |
| `kern.hv_support` | 1 |
| Toolchain | rustup 1.96.0-aarch64-apple-darwin (Homebrew rustc shadow pinned around) |
| Tree | worktree `mvm-327-quota`, branch `plan/327-hvf-vcpu-quota`, off `origin/main` |

## What was measured, and through what

Two tiers. Both drive **real Hypervisor.framework** through the **real in-repo
seam**; the difference is the guest.

- **Tier A — real hypervisor, real run loop, synthetic guest.** A throwaway
  harness creates a real `HvfVm`, a real `HvfVcpu`, and drives
  `mvm_vmm::vmm::run::run_with_pause_hook` — the production run loop — with a
  real `HvfHandle::force_exit` from the controller thread. The guest program is
  hand-assembled arm64 running at EL1 out of mapped guest RAM: a tight loop
  incrementing a counter the host reads out of the same mapping (so guest
  forward progress is directly observable at fine granularity). It is **not** a
  booted Linux kernel. This tier owns the precision numbers because it gives the
  controller a directly held `force_exit` token and a guest whose instantaneous
  progress the host can sample.
- **Tier B — real Linux guest, real device model, production pause path.** The
  builder-VM kernel and 758 MiB ext4 rootfs already cached at
  `~/.mvm/cache/builder-vm/aarch64/` booted through the production
  `boot_kernel_until` with virtio-blk + PL011 + virtio-rng. The controller drives
  the production `paused: &'static AtomicBool`, which the production watchdog
  turns into `force_exit`. This tier owns the real-guest confirmation and the
  hazard provocation.

Accounting in both tiers is per-thread Mach `thread_info(THREAD_BASIC_INFO)`,
user + system, summed as the plan proposes.

Both binaries were ad-hoc codesigned with `com.apple.security.hypervisor`. No
production code was modified; the harness lives in `/tmp` and is not committed.

## Structural facts found while wiring the spike

These constrain the design and are not opinions.

1. **The HVF backend is uniprocessor.** `kernel_boot` creates exactly one vCPU
   and the FDT emits a single `cpu@0`. "Spin every vCPU" is "spin the one vCPU".
   A quota on this tier can therefore bound at most **1.0 core**, and
   `max_cpu_millicores > 1000` is not expressible on HVF today.
2. **The run loop's pause hold sleeps 1 ms per iteration**
   (`crates/mvm-vmm/src/vmm/run.rs`, the `while should_pause() && !should_stop()`
   loop). That is the resume-latency quantum, and it is what makes very short
   periods and extreme quota ratios inaccurate (§Q1).
3. **The production HVF watchdog force-exits at 5 ms**
   (`crates/mvm-runtime/src/backends/hvf/kernel_boot.rs`, `step =
   Duration::from_millis(5)`). A controller that only sets `paused` and lets the
   watchdog do the cancel therefore cannot enforce a period below ~10 ms. A real
   quota controller must hold the `VcpuHandle` and call `force_exit` itself.
   Measured directly in §Q1, tier B.
4. **`force_exit` cannot interrupt host-side device work.** It only latches a
   cancel that takes effect at the next `hv_vcpu_run`. This is why the named
   hazard turns out to be structurally absent rather than merely unobserved
   (§Hazard).

## Q1 — does holding vCPUs out of `step()` bound a spinning guest?

**Yes.** Headline, tier A, predictive controller, 10 ms period, 50 % quota, 60 s:

```
wall 60.0044 s   vCPU CPU 30.0000 s   achieved 0.5000 cores   target 0.5000   err -0.01 %
```

For comparison the Linux cgroup spike reached 1.4937 against 1.5 (-0.42 %).

A first-draft controller that forgave a period's overshoot sat 8–33 % **above**
target at every period length. Carrying the overshoot forward as debt into the
next period's budget — which is what `cpu.max` does — is what makes it converge,
and it is a required part of the design, not an optimisation.

### Period sweep, 50 % quota, 10 s each, debt carry on

| period | controller | achieved cores | err | stall p50 | stall p99 | stall max |
|---|---|---|---|---|---|---|
| 1 ms | poll | 0.5808 | **+16.15 %** | 663 µs | 986 µs | 4476 µs |
| 5 ms | poll | 0.4878 | -2.45 % | 2321 µs | 4901 µs | 5020 µs |
| 10 ms | poll | 0.5000 | +0.01 % | 4844 µs | 9632 µs | 9958 µs |
| 20 ms | poll | 0.5002 | +0.05 % | 9069 µs | 13920 µs | 15846 µs |
| 50 ms | poll | 0.5006 | +0.13 % | 24783 µs | 32673 µs | 36289 µs |
| 1 ms | predict | 0.3888 | **-22.23 %** | 6 µs | 802 µs | 1031 µs |
| 5 ms | predict | 0.4997 | -0.07 % | 1890 µs | 3315 µs | 4124 µs |
| 10 ms | predict | 0.5000 | 0.00 % | 4343 µs | 6888 µs | 7531 µs |
| 20 ms | predict | 0.4995 | -0.10 % | 9336 µs | 13481 µs | 14230 µs |
| 50 ms | predict | 0.4998 | -0.05 % | 24203 µs | 31455 µs | 31472 µs |

"poll" reads `thread_info` every `period/16`; "predict" sleeps to the predicted
exhaustion instant and reads `thread_info` once per period for the debt
correction.

**1 ms periods do not work** in either controller, for the reason in structural
fact 2: the hold quantum is 1 ms, so a 500 µs hold cannot be expressed.

### Quota sweep, 10 ms period, predictive, 15 s each

| quota | achieved | target | err |
|---|---|---|---|
| 10 % | 0.0572 | 0.1000 | **-42.79 %** |
| 25 % | 0.2497 | 0.2500 | -0.13 % |
| 50 % | 0.5000 | 0.5000 | +0.01 % |
| 75 % | 0.7498 | 0.7500 | -0.02 % |
| 90 % | 0.8565 | 0.9000 | **-4.83 %** |

The two failures are the same 1 ms quantum seen from both ends: at 10 % the run
slice is 1 ms, at 90 % the hold is 1 ms. Lengthening the period fixes both,
confirming the diagnosis:

| period | quota | achieved | target | err |
|---|---|---|---|---|
| 50 ms | 10 % | 0.0988 | 0.1000 | -1.22 % |
| 50 ms | 90 % | 0.9000 | 0.9000 | 0.00 % |

**Enforceable envelope:** accurate to ≈0.1 % whenever both the run slice and the
hold exceed ~2 ms. At a 10 ms period that is quota ∈ [20 %, 80 %]; a controller
wanting a wider ratio must lengthen the period.

### Tier B — real Linux guest

Builder rootfs boots, mounts ext4 off virtio-blk, runs `/init` →
`mvm-host-vm-init`, finds no job, powers off. Whole guest life measured.

| quota (20 ms period) | boot wall | achieved cores | guest clock to poweroff | console bytes |
|---|---|---|---|---|
| unthrottled | 0.7939 s | 0.9732 | 0.657084 s | 12747 |
| 50 % | 1.2177 s | 0.5450 | 1.091662 s | 12747 |
| 25 % | 2.3679 s | 0.2856 | 2.227390 s | 12749 |

The console output is byte-identical: the guest does the same work, more slowly.
Accuracy is looser than tier A (+9 %, +14 %) because the measured window is only
1–2 s — a handful of debt-correction periods — and includes non-CPU-bound VM
setup and teardown. Tier A is the precision number; this is the confirmation
that a real guest with a real device model behaves the same way.

Driving the **production `paused` flag alone** at a 500 µs period achieved only
0.82 cores against a 0.50 target across 20 runs — the 5 ms watchdog cadence
(structural fact 3), not a failure of the mechanism. Phase 1 must call
`force_exit` from the quota controller directly.

## Q2 — what does it cost in jitter?

The guest counter is sampled every 5 ms; the per-window increment rate is the
guest's visible forward progress. Unthrottled baseline over 15 s:

```
mean 12.72 M/s   p1 11.35 M   p10 11.67 M   p50 11.91 M   p90 14.82 M   p99 15.81 M
```

The ±10 % spread with no controller running at all is P-core/E-core migration.
That is the noise floor; anything inside it is not attributable to the quota.

Rates below normalised against the 12.72 M/s baseline. 50 % quota, predictive.

| period | p1 | p10 | p50 | p90 | p99 | stall p50 | stall max |
|---|---|---|---|---|---|---|---|
| 5 ms | 0.29 | 0.37 | 0.49 | 0.61 | 0.69 | 1.9 ms | 4.1 ms |
| 10 ms | 0.23 | 0.36 | 0.52 | 0.70 | 0.83 | 4.3 ms | 7.5 ms |
| 20 ms | 0.00 | 0.15 | 0.51 | 0.89 | 1.07 | 9.3 ms | 14.2 ms |
| 50 ms | 0.00 | 0.00 | 0.49 | 1.03 | 1.12 | 24.2 ms | 31.5 ms |

**This is the trade, and it is sharp.** At a 5 ms period the guest paces
smoothly: the 1st-to-99th percentile band is 0.29–0.69 of baseline, never fully
stopped, and the longest single freeze is 4.1 ms. At a 50 ms period the same
mean is delivered by alternating full speed and frozen: over 10 % of 5 ms
windows show *zero* guest progress, p90 is at full unthrottled rate, and the
longest freeze is 31.5 ms. A latency-sensitive workload sees a 31 ms stall
roughly 20 times a second at the long period and nothing above 4 ms at the short
one.

Stall length tracks `period × (1 - quota)` closely, so the freeze a workload can
see is predictable from the configuration and should be surfaced as such.
**Recommended default: 10 ms period** — 7.5 ms worst-case stall, 0.01 % accuracy,
0.4 % controller cost. 5 ms buys a 2× smaller stall for 2× the controller cost.

The guest sees this as stolen time. Nothing hides it, exactly as the plan's risk
section says.

## Q3 — is the accounting cheap enough?

Controller thread's own CPU, measured with `thread_info` on itself, 50 % quota.

| period | controller | `thread_info` calls | ctrl cores | **ctrl as % of the enforced budget** |
|---|---|---|---|---|
| 1 ms | poll | 121 369 / 10 s | 0.0498 | **8.57 %** |
| 5 ms | poll | 26 390 | 0.0138 | 2.82 % |
| 10 ms | poll | 13 517 | 0.0078 | 1.55 % |
| 20 ms | poll | 6 902 | 0.0045 | 0.90 % |
| 50 ms | poll | 2 838 | 0.0021 | 0.41 % |
| 1 ms | predict | 10 006 | 0.0109 | 2.81 % |
| 5 ms | predict | 2 001 | 0.0038 | 0.76 % |
| 10 ms | predict | 1 001 | 0.0020 | 0.41 % |
| 20 ms | predict | 501 | 0.0012 | 0.23 % |
| 50 ms | predict | 201 | 0.0005 | 0.10 % |

**Yes, if the controller is predictive.** Reading `thread_info` once per period
and sleeping to the predicted exhaustion instant costs 0.41 % of the budget it
enforces at a 10 ms period, and does not lose accuracy relative to polling
(0.00 % vs +0.01 % error) because the debt carry corrects the prediction after
the fact.

**Where it stops being worth it:** polling at a 1 ms period spends 8.57 % of the
enforced budget on enforcement, while simultaneously missing the target by
+16 %, so it is strictly dominated. Predictive at 1 ms is cheap (2.81 %) but
misses by -22 % for the quantum reason. **Below a 5 ms period the mechanism is
not worth building at any controller design**, because the run loop's 1 ms hold
quantum caps the achievable precision regardless of how the controller is
written. Between 5 ms and 50 ms it costs 0.10–0.76 % and is accurate to 0.1 %.

The 60 s headline run at the recommended settings spent 0.13755 CPU-seconds in
the controller against 30.0000 CPU-seconds delivered to the guest: **0.46 %**.

## The hazard, provoked deliberately

The plan names it: forcing a vCPU out of `step()` while a device operation is
mid-flight. It was attacked from both tiers.

**Tier A — synthetic device, maximum collision rate.** A `RunDevice` whose
`write()` busy-waits for a configured span, with a guest program that stores to
the device window on every loop iteration, and a controller force-exiting every
500 µs:

| device work per access | duration | device dispatches | force exits | run loop stuck | join | outcome |
|---|---|---|---|---|---|---|
| 0 µs | 20 s | 5 886 127 | ~40 000 | none > 25 ms | 0 ms | `Ok(Canceled)`, 0 unexpected exceptions |
| 1000 µs | 20 s | 8 995 | ~40 000 | none | 0 ms | `Ok(Canceled)`, 0 unexpected exceptions |

In the 1 ms case every force-exit lands while a device operation is in flight by
construction — the device is busy more than half the time. Nothing deadlocked,
hung, or produced an unmodelled exit.

**Tier B — real device model, 20 consecutive real Linux boots** under
pause/resume hammering at a 500 µs period (≈1 640 toggles per 0.8 s boot,
≈33 000 toggles total), through the ext4 mount and module load where virtio-blk
traffic is heaviest:

```
OK=20  FAIL=0
```

Every boot completed, reached `mvm-host-vm-init`, and returned from the run
loop. `other_exceptions` stayed at 2 in every run — identical to the
unhammered control, so the hammering introduced no new exception class. Console
output was byte-identical in 19 of 20 runs and differed by 4 bytes in one (a
kernel timestamp digit width — the guest ran slower, so a printk crossed
`[ 1.0…]`), not corruption.

**Why it does not deadlock, structurally.** `hv_vcpus_exit` cannot interrupt
host-side device work: the run loop is inside `dispatch()` on the vCPU thread,
not inside `hv_vcpu_run`, so the cancel is merely latched and takes effect at the
next entry. Device operations are therefore never torn in half. The consequence
is a *bounding* limit rather than a safety one: the guest's charge overruns the
deadline by up to the length of the longest uninterruptible host-side device
operation. Measured, with a 1 ms synthetic device op and a 500 µs period, that
showed up as -11.54 % error on the instantaneous target while remaining bounded
in the long run because the debt carry absorbs it. Phase 1 should state this as
the granularity floor: **the period must exceed the slowest device operation.**

No defect in `force_exit` or the run loop was found. The 1 ms pause-hold sleep
and the 5 ms watchdog cadence are design parameters that Phase 1 must work with
or change, not bugs.

## What Phase 1 inherits from this

- Predictive controller, one `thread_info` read per period, debt carried forward.
- Default 10 ms period; refuse or round periods below 5 ms.
- Refuse quota ratios whose run slice or hold would fall below ~2 ms at the
  chosen period.
- Hold the `VcpuHandle` and call `force_exit` directly; do not rely on the
  watchdog's 5 ms cadence.
- Ceiling of 1.0 core on this tier until the HVF backend becomes multi-vCPU.
- Phase 2's `EnforcedTier` should report the *measured* achieved fraction: the
  controller already computes it, and it is the only honest read-back available
  since there is no kernel file to consult.
- Surface the worst-case stall (`period × (1 - quota)`) alongside the grant. It
  is the guest-visible cost and it is predictable.
