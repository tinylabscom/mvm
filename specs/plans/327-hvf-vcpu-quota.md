# Plan 327 — A CPU quota for the HVF tier, enforced in our own run loop

**Status: OPEN — Phase 0 COMPLETE; Phase 1 COMPLETE; Phase 2 COMPLETE; Phase 3 open**

Phase 0 results: [`327-hvf-quota-spike-findings.md`](327-hvf-quota-spike-findings.md).
Measured 0.5000 cores against a 0.5000 target (-0.01 %) over 60 s at a 10 ms
period, through the real HVF vCPU and the real run loop, with the controller
costing 0.46 % of the budget it enforces. The mechanism bounds; the constraints
Phase 1 must build inside are in that document.

## Why

Claim 18 records that CPU is enforced on Linux and declared-only on macOS.
The mechanism on Linux is a cgroup v2 `cpu.max` on a systemd transient scope;
macOS has no host-level quota primitive at all, so a `CpuGrant::Share` there
is refused under `--prod` and warned about under dev.

That limit is currently phrased as a property of macOS. It is really a
property of *which VMM we are driving*. On the HVF tier the VMM is ours: the
run loop calls `HypervisorVcpu::step()` and `VcpuHandle::force_exit` already
exists to pull vCPUs out of it from another thread — "Batched: HVF does it in
one call (`hv_vcpus_exit`)". A quota is therefore implementable above the
hypervisor rather than below it: measure each vCPU thread's consumed CPU time,
and when a period's budget is spent, force the vCPUs out and hold them until
the period rolls over. That is what `cpu.max` does — quota over period — with
the accounting in userspace.

**libkrun is explicitly out of scope, permanently.** It is a third-party
in-process VMM; we do not drive its vCPUs and cannot hold them. On macOS 13-25,
where libkrun is the default, CPU stays declared-only. This plan bounds the
macOS 26+ Apple Silicon tier and says so.

A side benefit worth stating but not designing for: the seam is shared with
KVM, so the same scheduler would give Linux a cgroup-free fallback on hosts
where delegation is unavailable — which the Plan 308 spike found is not rare.

## What this is not

Not a replacement for cgroups where cgroups exist. Linux keeps `cpu.max`: it
throttles below the guest, invisibly, and this cannot.

## Phase 0 — the spike. Blocks Phases 1+.

Three questions, answered by measurement on real Apple Silicon before any
design is committed. A negative answer to (1) ends the plan.

1. **Does holding vCPUs out of `step()` actually bound a spinning guest?**
   Boot an HVF guest, spin every vCPU, hold them for a measured fraction of
   each period, and compare achieved host CPU against the target. Report
   measured-vs-target the way the Linux spike did (it reached 1.4937 cores
   against 1.5).
2. **What does it cost in jitter?** A vCPU held out of `step()` is a stall the
   guest can see, where cgroup throttling is invisible below it. Measure the
   distribution, not just the mean — a bound that meets its average by
   alternating full-speed and frozen is a different product than one that
   paces smoothly.
3. **Is the accounting cheap enough?** Per-thread Mach `thread_info` polling
   costs CPU itself. Measure the controller's own consumption; a scheduler that
   spends a meaningful slice of the budget it is enforcing is not viable.

**Deliverable:** `specs/plans/327-hvf-quota-spike-findings.md` with the raw
numbers, the period/quota values tried, and a one-line verdict — **"Phase 1
proceeds"** or **"the approach does not bound / costs too much, and here is
what it would take instead"**.

Write the spike as a throwaway harness, not shipped code. It exists to answer
the three questions, and its value is the numbers.

## Phase 1 — the scheduler

- [x] A quota controller owning `(quota, period)` per VM, driving the existing
      `force_exit` seam and the `run_with_pause_hook` seam already in the run
      loop. No new hypervisor plumbing.
- [x] **Predictive, with debt carry-over — not polling.** The spike measured
      polling at 1.55% of the budget at a 10 ms period and 8.57% at 1 ms *while
      still missing by +16%*; the predictive controller hit -0.01% at 0.46%
      cost. Without carrying debt across periods every period ran 8-33% high.
- [x] **Period floor of 5 ms**, and the period must exceed the slowest device
      operation — a 1 ms device op at a 500 us period produced -11.5%
      instantaneous error. Below 5 ms no controller design pays for itself.
- [x] **Three existing-code constraints**, each surfaced by the spike:
      the HVF backend is uniprocessor, so the ceiling is 1.0 core until that
      changes; the run-loop pause hold sleeps 1 ms, which kills 1 ms periods and
      the 10%/90% quotas at 10 ms; and the production watchdog cancels only
      every 5 ms, so the controller must hold the `VcpuHandle` itself rather
      than relying on the watchdog.
- [x] Per-vCPU-thread accounting via Mach `thread_info`, summed per VM.
- [x] `ResourceControls::for_backend(Hvf)` gains a real `CpuControl`, replacing
      today's honest `None`.

## Phase 2 — report what was achieved, not what was asked

- [x] A new `EnforcedTier` variant for this mechanism, reported from the
      scheduler's own state. This is the one place the Linux design does not
      transfer: there is no kernel file to read back, so the tier's honesty
      rests on the scheduler reporting its *measured* achievement, not its
      configured target. Design that in from the start.
- [x] The tier reaches the audit chain and `machine inspect` through the paths
      Plan 308 already built.

## Phase 3 — claim 18

- [ ] Update limit 1. It currently reads "not built on macOS rather than
      impossible there"; if Phase 1 lands it becomes enforced on the HVF tier
      and declared-only on libkrun, with the reason being the VMM rather than
      the OS.
- [ ] Witnesses for the achieved bound, including a live measurement — the
      Plan 308 CPU claim rests on one and this should too.

## Risks

- **The guest sees stolen time.** Nothing hides it the way a cgroup does.
- **The hot path is the hot path.** This adds work to the run loop, which is
  the most latency-sensitive code in the system.
- **A held vCPU must not deadlock the device model.** Forcing exit while a
  device operation is mid-flight is the obvious hazard; the spike should
  provoke it deliberately rather than hope.