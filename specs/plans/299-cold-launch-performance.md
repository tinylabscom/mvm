# Plan 299 — Prepared cold-launch performance

**Status:** Phase 0 complete — substrate implemented and gated, both native
baselines measured. Phase 6 is promoted ahead of Phase 3 by the measurements;
Phase 3 is retargeted at the Firecracker boot path.

This plan is one owner of the [fast machine substrate](../notes/2026-08-10-fast-machine-substrate.md),
which composes cold launch with Plans 298, 265, 270, and 292. It owns the
prepared cold path and its evidence; it does not define a second artifact or
snapshot graph.

## Goal

Make a genuinely cold VMM launch fast enough that warm-VM performance is not the
only credible low-latency path.

The primary requirement is:

> On a supported, uncontended host, a release `mvmctl machine run` using
> already-cached, digest-verified artifacts must reach an authenticated guest
> agent and dispatch `/bin/true` in **≤300 ms at p99**. The p50 target is
> **≤200 ms**.

The requirement measures the prepared cold path: a new VMM and a new guest
identity, with no warm standby claim and no snapshot restore. It does not pretend
that registry download, OCI unpack, kernel compilation, or first-time host
directory image creation can complete in 300 ms. Those costs receive separate
budgets and evidence.

## Current evidence and diagnosis

The initial phase-timing sample was not primarily a VMM cold-boot measurement:

| Phase | Observed |
|---|---:|
| Image resolution | 0 ms |
| Drive preparation | 429,809 ms |
| Admission | 152 ms |
| Backend start | 1,214 ms |
| Guest agent wait | 7 ms |
| Command | 4,063 ms |
| Teardown | 2,529 ms |
| Total | 437,775 ms |

The 430-second drive phase came from rebuilding the `--mount` ext4 image. The
1.2-second backend phase is the first useful cold-start signal. This plan first
separates those costs, then removes repeatable work from the launch critical
path.

## Boundaries and composition

This plan composes with existing work:

- Plan 255 owns warm-pool claims, checkpoint lineage, fresh child identity, and
  post-restore authority.
- Plan 265 owns warm restore sequencing, the warm-start SLO, page-cache priming,
  density, and backend comparison.
- Plan 292 owns tiered artifact storage and remote cold recovery.
- Plan 270 owns the universal initramfs and vsock-activated boot contract.
- The current `--mount` surface remains the supported host-directory interface;
  the obsolete internal `AddDir` naming and any compatibility-only flag path are
  removed while this launch path is changed.

The prepared template identity includes the kernel, universal initramfs, rootfs
lower artifacts, verity metadata, runtime overlay, backend/VMM version, guest
protocol, CPU/memory shape, block-device/share topology, network-policy shape,
warmup profile, and readiness probe. Host paths, host-directory contents,
tenant authority, live channels, and mutable writable state are excluded.

The launch measurement vocabulary is canonical: kernel entry, agent ready,
authenticated activation, environment ready, first useful RPC, and reaped.
`/bin/true` remains a launch probe; the first useful authenticated RPC is a
separate end-to-end signal.

No task here may weaken admission, signed-plan verification, dm-verity,
host-directory isolation, vsock authentication, or the no-NIC workload
boundary.

## Non-goals

- Do not promise a 300 ms first-use registry pull or image build.
- Do not make a dirty guest reusable as a workload parent.
- Do not add a second snapshot, artifact, or cache graph.
- Do not put remote object storage on the launch critical path.
- Do not introduce a new hypervisor-specific public CLI surface.
- Do not use a privileged host-directory mount as a shortcut around the current
  read-only image and policy checks.
- Do not reintroduce removed platform frameworks or a second Apple VMM stack.

## Performance contract

Every benchmark reports these dimensions independently:

1. **Prepared cold:** cached kernel, initramfs, runtime overlay, rootfs, and no
   mount image; new VMM and new guest identity.
2. **Prepared cold with mount hit:** the same launch with an unchanged cached
   read-only host-directory image.
3. **Mount miss:** directory fingerprint plus first ext4 image materialization.
4. **Artifact miss:** image acquisition, unpack, verification, and preparation.
5. **Warm claim:** existing warm-start measurement, retained as a regression
   comparison rather than folded into the cold SLO.

Required release-build gates on each supported backend:

| Lane | p50 | p95 | p99 |
|---|---:|---:|---:|
| Prepared cold to authenticated agent | ≤200 ms | ≤250 ms | ≤300 ms |
| Prepared cold with mount-cache hit | ≤200 ms | ≤250 ms | ≤300 ms |
| Warm claim to authenticated agent | no regression against Plan 265 | no regression | no regression |

**Every published percentile names the image and rootfs size it was measured
on.** The gates above are size-independent targets, but a launch path can carry
per-launch work that is a function of artifact size, and a number measured on a
small image then reads as a property of the code rather than of the pair. The
recorded baselines below use `alpine` (9.9 MB cached rootfs); Plan 311 adds a
large-image lane on `python:3.12` (1.1 GB) after finding ~557 ms of per-launch
rootfs re-hashing that `alpine` could not reveal and this contract's lane gate
had no flag for.

Mount misses and artifact misses are reported with p50/p95/p99 and cache hit
rate, but are not silently included in the prepared-cold SLO.

## Phase 0 — Freeze a trustworthy baseline

- [x] Add a release-only benchmark entry point that invokes the built
      `mvmctl` binary directly; `cargo run` compilation time must never enter a
      launch sample.
      (`crates/mvm-cli/src/bench/cold_launch_runner.rs` —
      `ColdLaunchBench::builder(...).build()?.run()` spawns the binary path and
      refuses `cargo`/`rustc`/`just` outright. The release check is made
      against the sample the binary writes, which reports its own
      `cfg!(debug_assertions)` profile, so it cannot be spoofed by a path.)
- [x] Extend phase timing below the current `drives` bucket with distinct
      marks for mount fingerprint, mount-cache lookup, mount-image materialize,
      artifact verification, backend process/VMM creation, guest kernel entry,
      agent authentication, first command dispatch, and cleanup handoff.
      (`SubPhase` + `LaunchSubMarks` in
      `crates/mvm-cli/src/commands/vm/phase_timing.rs`, collapsing to
      `LaunchSubTimings`. Six have producers on the transient run path today;
      the three mount spans do not, because the current `--mount` surface
      attaches a live virtio-fs share and materializes nothing. Phase 1's
      content-addressed mount cache is what records them, and the lane gate
      already refuses a prepared-cold sample that reports one.)
- [x] Record backend, host architecture, kernel digest, initramfs digest,
      overlay digest, rootfs digest, VMM version, CPU count, memory setting,
      filesystem, selected root filesystem strategy, cache state, and run
      number with every sample.
      (The launch writes artifact **paths**, not digests — hashing inside the
      measured window would charge the launch for the measurement. The runner
      resolves digests, filesystem, and cache state afterwards into
      `LaunchContext`/`CacheState`. `vmm_version` is resolved only for the
      in-house VMM, which ships inside `mvmctl`; a third-party VMM records
      `None` rather than a fabricated number. The launch sample records the
      tier-gated `virtiofs_root` or `block_ext4` strategy so filesystem
      comparisons never mix security or capability tiers. The runner rejects
      a missing strategy and refuses to aggregate a report whose warmup or
      measured samples change strategy.)
- [x] Add a benchmark report format containing raw samples and p50/p95/p99;
      do not store only summary numbers.
      (`ColdLaunchReport` carries `raw: Vec<ColdLaunchSample>` alongside
      `LaneStats`. A span no launch recorded reports `samples: 0` with `None`
      percentiles, so "never measured" is distinguishable from "measured as
      fast" and the report still round-trips through JSON.)
- [x] Measure at least 20 iterations per lane after two warm-up iterations on
      native Apple Silicon/HVF and the Linux Firecracker host. Measure libkrun
      where the supported Linux or macOS environment can run it.
      (Apple Silicon/HVF and Linux Firecracker/KVM both measured below. libkrun
      is not measured: neither available host selects it by default, and it is
      an explicit opt-in on both.)
- [x] Add a benchmark assertion that rejects a sample labeled `prepared_cold`
      when it performed an image pull, image build, mount-image materialize, or
      warm claim.
      (`validate_lane` in `crates/mvm-cli/src/bench/cold_launch.rs`, called on
      every warm-up and measured launch. It reads `LaunchWork` flags rather
      than spans — an uninstrumented phase records no span, and refusing on a
      missing span would pass exactly the contamination the gate exists to
      catch. A warm claim is refused on the launch mode as well as the flag, so
      one signal going missing cannot let it through.)
- [x] Add an opt-in lifecycle-density benchmark that performs 1,000 start/stop
      operations, defaults to HVF, reports independent start and stop
      distributions plus wall-clock throughput, and accepts bounded batches
      across the real microVM backend selectors.
      (`tests/microvm_lifecycle_bench.rs`; the test remains disabled unless
      `MVM_LIFECYCLE_BENCH=1` is set and requires explicit prepared kernel and
      rootfs paths.)
- [x] Add stop-phase timing to the lifecycle benchmark so backend teardown can
      be separated from runner attach, endpoint reaping, console cleanup, and
      backend-specific process teardown. A 1,000-cycle HVF run measured
      `pid_disappearance` at 67.62 ms p50 / 74.97 ms p95 / 77.01 ms p99;
      endpoint reaping and state cleanup were below 0.1 ms at p99, and no
      force-kill escalation occurred.

**Exit gate:** the report can distinguish the 430-second mount-image cost from
the actual approximately 1.2-second backend-start cost, and the baseline is
reproducible from a release binary.

**Exit-gate status:** met. The substrate is in place and gated, and both
native baselines are measured and recorded below from release binaries.

### Measured baseline — Apple Silicon / HVF

Release `mvmctl`, `machine run --image alpine -- /bin/true`, prepared artifact
cache, 20 measured iterations after 2 warm-ups per lane. Every sample cleared
the lane gate. Raw samples in `$MVM_HOME/state/bench/cold-launch-*.json`.

Image: `alpine`, 9.9 MB cached rootfs. See Plan 311 for the same launch on a
1.1 GB rootfs and for what that difference exposed.

| span (p50 / p99) | prepared cold | warm claim |
|---|---:|---:|
| **dispatch window** | **114.1 / 122.6 ms** | **18.9 / 20.0 ms** |
| `vmm_create` | 58.8 / 63.4 ms | — (no VMM created) |
| `guest_kernel_entry` | 54.1 / 59.3 ms | — |
| `agent_auth` | 1.4 / 1.7 ms | 0.9 / 1.2 ms |
| artifact verify, first dispatch | ≤0.1 ms | ≤0.1 ms |
| foreground teardown | 139.1 / 148.0 ms | 1086.0 / 1135.6 ms |
| **total** | **343.6 / 352.0 ms** | **1216.1 / 1271.9 ms** |

Backend phases recorded inside `start_workload`, prepared-cold lane:

| backend phase | p50 | p99 |
|---|---:|---:|
| `endpoint_spawn` | 0.0 ms | 0.0 ms |
| `spec_assembly` | 0.0 ms | 0.0 ms |
| `driver_boot` | 53.7 ms | 55.5 ms |
| `console_stream_start` | 2.3 ms | 3.4 ms |
| `activate_workload` | 0.0 ms | 0.0 ms |
| `broker_register` | 1.0 ms | 6.4 ms |

What this establishes:

1. **Both lanes already meet their dispatch targets.** Prepared cold reaches an
   authenticated agent in 114 ms p50 / 122.6 ms p99 against a ≤200 / ≤300 ms
   budget, and a warm claim in 18.9 / 20.0 ms against the 300 ms
   `WARM_START_MAX_MS` ceiling. The dispatch-window SLO is not where the
   remaining work is.
2. **Foreground teardown is now the dominant cost in both lanes** — 139 ms of
   the 344 ms cold wall clock, and 1086 ms of the 1216 ms warm wall clock,
   where it is 89% of the launch. The warm cost is pool replenish running
   inline on the way out. Phase 6 is therefore the highest-value remaining
   phase, ahead of Phase 3.
3. **A cold launch splits evenly between VMM and guest.** `driver_boot` is
   53.7 ms and the wait from `start` returning to an answering agent is
   54.1 ms. Neither dominates, and together they are only a third of the cold
   wall clock.

### Post-Plan-311 re-measurement — Apple Silicon / HVF

Release `mvmctl` at `c866611af`, `ColdLaunchBench`, 20 runs + 2 warm-ups per
lane, every sample through the lane gate. Both images reported independently
per the contract's image-naming rule.

| lane | dispatch p50 | p95 | p99 | total p50 |
|---|---:|---:|---:|---:|
| `alpine` (9.9 MB rootfs) | 79.6 ms | 84.9 ms | 93.6 ms | 320.1 ms |
| `python:3.12` (1.1 GB rootfs) | 77.3 ms | 79.7 ms | 90.1 ms | 316.1 ms |

Plan 311 removed the per-launch work that made these two differ; they now agree
inside run-to-run noise at every percentile. The prepared-cold contract is met
on this backend with a 3.3x margin at p99, on a 1.1 GB image.

What this changes for the remaining phases on HVF:

- **Phase 3 has little left here.** `vmm_create` is 11.6 ms and the backend's
  own `driver_boot` is 7.8 ms p50. `guest_kernel_entry` at 58.6 ms is now three
  quarters of the dispatch window, so the remaining cold-start cost on this
  backend is the guest booting, not the VMM being created.
- **Phase 6 is still the largest single span in the run.** `stop_transient` is
  128.1 ms p50 — larger than the whole dispatch window that precedes it, and it
  runs after the command has already produced its answer.

### Measured baseline — Linux Firecracker / KVM

Same lane, same 20 runs + 2 warm-ups, release build, on the established KVM
host (x86_64, 8 cores). Every sample cleared the lane gate.

| span (p50 / p99) | Firecracker / x86_64 | HVF / aarch64 |
|---|---:|---:|
| **dispatch window** | **674.0 / 888.6 ms** | 112.6 / 116.6 ms |
| **`driver_boot`** | **623.6 / 643.8 ms** | 53.8 / 55.5 ms |
| `activate_workload` | 20.4 / 42.6 ms | 0.0 / 0.0 ms |
| `broker_register` | 28.1 / 219.3 ms | 1.1 / 1.5 ms |
| `agent_auth` | 1.4 / 3.9 ms | 1.6 / 3.8 ms |
| foreground teardown | 416.9 / 1842.1 ms | 143.7 / 152.4 ms |
| **total** | **1387.5 / 3383.2 ms** | 347.1 / 354.8 ms |

**The fast boot is backend-specific, not structural.** Firecracker spends
623.6 ms where HVF spends 53.8 ms for the same operation on the same code
path — 11.6x — and misses the 300 ms p99 budget by 3x while HVF clears it.
Since both run the identical runner, spec assembly and activation sequence,
this is the VMM boot itself, and HVF is the existence proof that the
surrounding code is not what costs the time.

Two honest limits on the comparison. The hosts differ in architecture
(x86_64 vs aarch64) and in hardware, so this is not a controlled VMM
benchmark; an 11.6x gap is far larger than that difference plausibly
explains, but the exact split is not established. And the Firecracker host's
tail is wide — a 1842 ms teardown p99 against a 417 ms p50 — which suggests
contention or a variance source that has not been chased.

This retargets Phase 3: it is a Firecracker-path phase, with a concrete
target (HVF's 54 ms on the same code) rather than an invented budget.

### A fail-slow, fail-silent registration path

The first baseline recorded here was invalid, and the way it was wrong is
worth keeping. It was measured against a build containing only the `mvmctl`
binary, so `mvm-host-agent` was absent. That produced a prepared-cold figure of
780 ms p50 — 6.8x the real number — with 711 ms attributed to broker
registration.

The mechanism is a real defect, independent of the build mistake:

- `resolve_subprocess_bin` cannot find the daemon binary, so
  `register_host_agent_services_if_admitted` fails.
- `RealBrokerRegistrar::register` treats that as best-effort: it logs a warning
  and continues, so **the workload runs with `host.audit.v1` unavailable and
  nothing in the launch result says so**.
- The armed rollback guard then attempts a deregister against a control socket
  that does not exist. `is_transient_control_error` counts `NotFound` as
  transient, so the retry ladder sleeps `100 + 200 + 400 = 700 ms` waiting for
  a socket that can never appear.

So an unavailable daemon costs 700 ms per launch and silently degrades a
security-relevant capability. Both halves are worth fixing: a missing binary
should fail fast rather than back off, and a launch that lost `host.audit.v1`
should say so rather than report as clean.

That second half is also a gap in this plan's own measurement contract. The
lane gate refuses a launch that did *too much* work (a pull, a build, a warm
claim) but cannot see a launch that silently did *too little*. A degraded
launch is not a valid sample of a healthy one.

**Both halves are fixed.**

*Fail fast.* `should_retry_control` now requires the control socket to exist on
disk before a transient error is retried. The ladder exists so the register
path can wait out a daemon that has bound but is not yet serving; it cannot
wait a socket that is not there into existence. Measured against the same
absent-daemon scenario, `broker_register` fell from 711 ms to 0.5 ms.

*Fail loud.* `ServicesGuard::is_registered` reports whether host services
actually registered, `LaunchTraceRecorder::degrade_unless` records the loss
into the trace sidecar, and the launch sample carries a `degraded` list.
`validate_lane` refuses a sample with a non-empty list **for every lane, before
the per-lane rules**, so a degraded launch cannot be reported as a measurement
of a healthy one. Verified live: hiding the daemon binary produces
`degraded: ["host_services"]`.

A third gap surfaced while verifying this. A run that spent 59.9 s
cross-compiling the guest agent reported `image_build: false`, because the work
recorder was only wired to the flake-build site — so the prepared-cold gate
would have accepted a one-minute sample. The acquisition recorder now lives in
`mvm_core::launch_trace`, where the crates that actually pull and build can
reach it, and `build_guest_binaries` records itself.

Kernel size is not a candidate lever here. The workload kernel is an 8.2 MiB
arm64 `Image` (6.12.100, 936 options, zero modules, already ratcheted by
`check-kernel-config-budget`), loaded by direct copy — single-digit
milliseconds against a 778 ms span. Two external reference runtimes were
examined for prior art: one vendors a 29 MiB prebuilt kernel (3.5x larger than
ours) and reports its headline figure for snapshot restore rather than a cold
boot; the other uses its VMM's stock bundled kernel with a two-option
filesystem tweak. Neither builds a smaller kernel than the one already shipped
here.

### Phase 6 evidence — what foreground teardown actually is

Teardown decomposed on the warm lane (HVF, 20 runs + 2 warm-ups), where it is
largest:

| teardown span | p50 | p99 | share of teardown |
|---|---:|---:|---:|
| `stop_transient` | 152.5 ms | 168.5 ms | 13% |
| **`pool_replenish`** | **1025.9 ms** | **1573.1 ms** | **87%** |
| `state_remove` | 0.5 ms | 14.7 ms | <1% |
| cleanup total | 1181.8 ms | 1719.4 ms | |

The launch's own dispatch window was 27.1 ms. So a warm `machine run` does
27 ms of useful work and returns to the user after 1366 ms, and three quarters
of that wait is provisioning the standby for the *next* launch.

That reframes Phase 6. Only `stop_transient` and `state_remove` are cleanup of
this VM, and together they are 153 ms; the plan's ownership rules (confirm
process exit, protect the state dir and PID until it does) apply to them.
`pool_replenish` is not cleanup at all — it is next-launch provisioning that
happens to be executed on this launch's critical path, and it holds no
resource this launch owns.

Moving it is a deliberate decision to revisit rather than an oversight. The
code comment on the call says the removed backend's image-bound rewarm was
kept explicit "so teardown does not spawn background work that can contend
with foreground launches" — so inline execution was chosen to avoid
contention, and detaching it trades a 1 s foreground stall for exactly that
contention risk. The measurement says the trade is now heavily one-sided, but
it is a trade, and the alternatives (detach, defer to the next launch's start,
make replenish cheaper, or make it opt-in) have not been compared here.

### Phase 6 first change — replenish leaves the foreground

`teardown_transient_vm` no longer refills the pool. Filling it is explicit
(`mvmctl pool warm`), which is the conclusion the same reasoning had already
reached for the image-bound rewarm; the difference is that the work is not done
inline either now.

Measured on the default residency (`always_warm`), 20 runs + 2 warm-ups:

| default `machine run` | before | after |
|---|---:|---:|
| **total p50** | 1366.1 ms | **353.8 ms** |
| foreground teardown | 1181.8 ms | 143.8 ms |
| dispatch window | 27.1 ms (warm claim) | 117.2 ms (cold boot) |

A launch is **3.9x faster end to end**, trading 90 ms of dispatch for 1012 ms
of wall clock. Teardown is now `stop_transient` 142.9 ms plus `state_remove`
0.7 ms — both genuinely this VM's cleanup, both under the ownership rules, and
`pool_replenish` no longer appears in the sample at all.

The behavioural consequence, stated plainly: nothing auto-fills the pool, so a
default sequential run now cold-boots rather than claiming. That is the right
default because a claim saved 90 ms of dispatch and cost 1026 ms to prepare —
the pool only pays off when its refill overlaps idle time or launches are
concurrent, and neither holds for back-to-back `machine run`. Residency still
governs whether a claim is *attempted*, so a pool filled by `pool warm` is
still claimed; it is the automatic refill that is gone.

The remaining 142.9 ms `stop_transient` is real cleanup and stays synchronous:
it is what confirms process exit before the state directory is removed.

**Follow-up:** the resident per-tenant `mvm-host-agent` daemon is the right
long-term owner of pool maintenance — it already outlives the CLI and is the
host-side lifecycle seam this phase names. That would restore automatic warm
claims without putting the refill on any launch's critical path.

### Phase 5 first change — the readiness cadence was reporting itself

`wait_for_agent` polled on a flat 50 ms tick. Readiness can only be observed on
a probe, so that tick is a floor under every reported wait — and the HVF
baseline showed `guest_kernel_entry` at 53.8 ms p50 / 59.3 ms p99, clustered
just above the tick on a backend whose entire VM creation takes 53.8 ms. The
number was a readout of the cadence, not of the guest.

Replaced with backoff from 1 ms doubling to a 25 ms ceiling (the shape the
control-retry path already uses). Same lane, 20 runs + 2 warm-ups:

| HVF (p50 / p99) | before | after |
|---|---:|---:|
| `guest_kernel_entry` | 53.8 / 59.3 ms | **18.0 / 19.3 ms** |
| **dispatch window** | 117.2 / 125.3 ms | **81.4 / 83.5 ms** |

So 36 ms of what the baseline attributed to guest boot was quantization, and
the guest is actually serving ~18 ms after `start` returns. Prepared cold now
clears the ≤200 ms p50 / ≤300 ms p99 budget with a 2.5x margin on this backend.

This does not help Firecracker, whose `start` already returns after the guest
is up (`guest_kernel_entry` 0.0 ms there) — its 623.6 ms is inside `driver_boot`
and is Phase 3's subject.

Full event-driven readiness — one authenticated notification rather than any
polling — remains this phase's actual task; this removes the quantization the
polling was adding in the meantime.

### The same cadence bug, three more times

Three further fixed 50 ms polls were quantizing the same way: the supervisor
PID-file wait inside the HVF driver's boot, the guest-agent wait on the
standby path, and `wait_for_pid_exit` on teardown. All four sites now share
one backoff (`mvm_core::poll_backoff`) rather than four copies of a constant.

| HVF (p50) | flat tick | readiness fixed | all four fixed |
|---|---:|---:|---:|
| `driver_boot` | 53.8 ms | 53.8 ms | **4.6 ms** |
| `guest_kernel_entry` | 53.8 ms | 18.0 ms | 65.1 ms |
| **VMM + guest boot** | 107.6 ms | 71.8 ms | **69.7 ms** |
| dispatch window | 117.2 ms | 81.4 ms | **79.2 ms** |
| total | — | 352.1 ms | **310.1 ms** |

Read this honestly. The readiness fix was a real 36 ms. This one is worth
about 2 ms of wall clock; what it actually buys is a true number — VM creation
on this backend costs **4.6 ms**, not the 53.8 ms the tick reported, and the
~65 ms is genuinely the guest booting to a serving agent. The work did not
move off the launch, it moved to the span that was always doing it.

It also widened the tail (dispatch p99 83.5 ms -> 156.7 ms). The flat tick had
been rounding every launch up to the same value and so *hiding* variance; the
distribution was never that tight. A tighter-looking p99 that comes from
quantization is not a better launch.

Two consequences for the rest of the plan. Phase 3's target on HVF is now
known to be guest boot rather than VMM setup — 65 ms of the 70 ms. And the
Firecracker `driver_boot` of 623.6 ms should be re-measured against these
fixes before being decomposed, since it contains a poll of its own.

### Phase 3 re-measurement — Linux Firecracker / KVM, post-Phase-5

Phase 5 said the Firecracker `driver_boot` of 623.6 ms should be re-measured
against the poll fixes before being decomposed, since it contains a poll of its
own. Re-measured on `main` at `c866611af`, release, prepared cache, x86_64 KVM
host:

```
phases:  drives=46.0  admit=294.4  backend_start=689.8  vsock_wait=2.1
         command=57.3  teardown=423.8  total=1513.4   dispatch_window=691.9
backend: driver_boot=630.5  console_stream_start=3.6  activate_workload=16.6
         broker_register=38.7
work:    artifact_bytes_hashed=0  process_table_scans=0
```

`driver_boot` **did not move**: 623.6 ms before, 630.5 ms after. The poll it was
suspected of containing is not one of the four Phase 5 replaced. So Phase 3 is a
real cost and can be decomposed — that was the open question and it is now
closed.

Note `guest_kernel_entry=0.0`: the Firecracker driver confirms boot before
returning, so `driver_boot` spans VMM start *and* guest boot, which HVF reports
as two spans. The like-for-like comparison is HVF's 11.6 + 58.6 = ~70 ms against
630 ms, an excess of ~560 ms.

Decomposed (**issue #2292**): the driver boots through a shell script that polls
for the API socket on a fixed `sleep 0.1` — the same quantization Phase 5
removed from four Rust sites, missed here because it lives in a shell heredoc —
and then issues each API call as its own `curl` subprocess behind `sudo bash`.
Measured on the same box: 7 ms per `sudo bash -c true`, 6 ms per `curl` spawn,
about nine calls per boot. So ~100 ms of tick plus ~120 ms of spawn, roughly 35%
of `driver_boot`, removable without touching the VMM.

**A second cost this exposed (issue #2293).** `admit` is 294 ms here against
~38 ms on HVF, and it is neither compute nor hashing. One launch appends **8**
chain entries, each its own `write_all` + `sync_data` per Plan 303 WS2, and
`fsync` on this host's md2 array costs 41.7 ms p50 — so ~334 ms of durability
per launch. The entry list also shows `plan.admitted` twice, once from the OCI
provenance path and once from the boot admission. On Linux, admission alone
exceeds the ≤200 ms p50 contract before any VMM work happens; on macOS it is
invisible. Phase 4's "keep admission entirely local" is necessary but not
sufficient — local is not the same as cheap when every entry is a barrier.

## Phase 1 — Content-addressed `--mount` image cache

- [ ] Add a reusable `mvm-fs` directory fingerprint helper covering relative
      path, file bytes, symlink target, mode, ownership where supported, and
      the materializer format version. Reject unsupported inode kinds exactly
      as the current pure ext4 writer does.
- [ ] Add a private, `MVM_HOME`-rooted mount-image cache with one directory
      named by the computed fingerprint beneath
      `$MVM_HOME/cache/mount-images/`. Each entry contains `manifest.json` and
      `image.ext4`. The manifest records the fingerprint, image digest, label,
      format version, byte size, source policy, and creation time.
- [ ] Publish cache entries through a temporary directory, fsync the image and
      manifest, and atomically rename the directory. A process that observes a
      partial entry must treat it as a miss and never attach it.
- [ ] Serialize competing builders for one fingerprint with an existing
      filesystem-lock pattern. Concurrent requests must converge on one image,
      not rebuild it or attach a partially written file.
- [ ] Verify the manifest and image digest on cache read. A mismatch quarantines
      the entry and rebuilds it; it never falls back to an unverified image.
- [ ] Make read-only mount-cache hits attach the immutable cached image
      directly. Writable mounts receive a per-run CoW clone and never mutate
      the shared cache entry.
- [ ] Add bounded cache pruning by byte budget and age, preserving entries in
      use. Cache permissions must remain user-private and follow `MVM_HOME`.
- [ ] Rename the internal mount data types and helpers away from the obsolete
      `AddDir` terminology while preserving only the documented `--mount`
      parser and behavior.
- [ ] Add unit tests for deterministic fingerprints, changed content, changed
      metadata, symlink handling, unsupported inodes, corrupt manifests,
      interrupted publication, concurrent builders, read-only hits, writable
      CoW clones, and pruning.
- [ ] Add a BDD scenario proving that two identical `--mount` launches build
      one image and that the second launch reports a cache hit without changing
      the source directory.

**Exit gate:** an unchanged mount contributes no ext4 materialization work to a
prepared-cold launch; the mount-cache-hit p99 gate is met on both native host
families.

## Phase 2 — Artifact preparation outside the launch path

- [ ] Define a prepared-artifact manifest for the kernel, universal initramfs,
      runtime overlay, rootfs, verity sidecars, and their compatibility
      fingerprints. Reuse existing content-addressed verification rather than
      adding another manifest format.
- [ ] Make launch resolve perform only local manifest reads and digest checks
      when the caller selects a cached, digest-pinned image.
- [ ] Ensure OCI pull, layer unpack, ext4 creation, verity generation, kernel
      compilation, and universal-initramfs construction are explicit acquire or
      prepare operations, never hidden fallback work in `machine run`.
- [ ] Add an explicit preparation command or existing cache-population path for
      all artifacts required by the prepared-cold benchmark.
- [ ] Ensure runtime overlay and initramfs source fingerprints invalidate stale
      entries before launch, while a valid entry is attached without rebuilding.
- [ ] Add negative tests proving that missing or stale artifacts fail with an
      actionable preparation error rather than silently doing expensive work in
      the SLO-measured path.

**Exit gate:** a prepared-cold run performs no network access, Nix evaluation,
OCI unpack, verity generation, kernel build, or initramfs build.

## Phase 3 — Reduce backend cold-start latency

Implement the same typed `VmBackend` contract on each backend; keep the
optimization backend-local and the benchmark backend-neutral.

- [ ] Replace per-launch shell/API subprocess setup on the Firecracker path with
      the existing native API seam. Pre-open or memory-map immutable boot
      artifacts and reuse the control socket setup without reusing guest state.
- [ ] For the in-house HVF path, profile VM creation, memory map, vCPU start,
      virtio device setup, and first guest instruction separately. Remove only
      measured setup work; preserve the paused-parent handoff and no-NIC guard
      owned by Plans 255 and 265.
- [ ] For libkrun, profile host process creation, kernel load, device setup,
      and agent readiness independently. Reuse immutable host-side preparation,
      not a prior guest identity.
- [ ] Keep a resident host control/supervisor process where it removes process
      startup from the critical path. It must receive a fully admitted,
      per-launch configuration and create a fresh VM identity; it may not reuse
      a dirty workload.
- [ ] Share read-only kernel mappings between launches where the backend
      supports it, and measure page-cache effects separately from VMM creation.
- [ ] Use the smallest supported default memory commitment and demand-fault
      guest RAM. Prove that the change affects resident cost without changing
      guest-visible memory capacity or isolation.
- [ ] Run the kernel and boot-substrate budget from
      [issue #2280](https://github.com/tinylabscom/mvm/issues/2280): compare
      raw/compressed kernel and initramfs size, boot probes, kernel entry,
      authenticated readiness, resident pages, and restore fault cost. A size
      reduction is accepted only with readiness, security, and compatibility
      witnesses.
- [x] Extend `cargo xtask perf footprint` to include the initramfs artifact and
      an optional resolved kernel config. The JSON report now records the
      initramfs bytes and built-in-symbol count, and reuses the per-architecture
      kernel-config budget gate. This is the artifact-ledger slice of #2280;
      live boot timing and guest resident-memory evidence remain open; the
      libkrun probe now captures host supervisor/VMM resident footprints.
- [x] Carry artifact byte counts and optional resolved kernel-config symbol
      counts into each `ColdLaunchReport` sample. The runner resolves these
      after the child launch exits, so the report joins substrate evidence to
      launch timing without charging metadata I/O to the measured window.
- [x] Add a bounded live resident-footprint capture for the libkrun probe.
      `mvm_cli::bench::probes::run_density` boots admitted guests through
      authenticated readiness, samples each host supervisor/VMM process with
      the platform footprint reader, and drops every held guest on success or
      failure. This reports host process residency; guest demand-fault and
      restore-fault evidence remain separate gates.
- [x] Add the guest-agent RSS witness to the same live libkrun density report.
      After the readiness boundary, each held guest is queried through the
      existing `ResourceUsage` RPC and the result is carried beside host
      supervisor/VMM RSS, with aggregate statistics for samples that answered.
      This measures the guest-agent process, not the whole guest working set;
      whole-VM and first-use restore-fault evidence remain open.
- [x] Add an allocation-level demand-fault witness to the HVF guest-RAM seam.
      `GuestRam` exposes a `mincore` resident-byte query, the raw kernel boot
      result records it after vCPU and host-I/O shutdown, and a focused test
      proves untouched anonymous pages become resident only after writes.
      The raw result also records monotonic private restore-mapping duration
      when a restore file is supplied. These are allocation and mapping
      witnesses, not substitutes for end-to-end guest working-set or first-use
      restore-fault measurements.
- [x] Add a baseline filesystem-path report at the existing pure-Rust
      materializer seam. `mvm_fs::rootfs::measure_ext4_pure` records the source
      content digest, node composition, file bytes, emitted image size/digest,
      materializer format version, and separate source-hash/walk/build timing
      phases. `cargo xtask perf filesystem --root <DIR> --json` exposes the
      report for repeated fixture comparisons.
- [ ] Evaluate the current rootfs and host-directory image path against the
      guest-local immutable filesystem hypothesis in
      [issue #2281](https://github.com/tinylabscom/mvm/issues/2281). Keep the
      current path as the baseline, use the new report for candidate
      comparisons, and preserve dm-verity, xattrs/whiteouts, read-only
      enforcement, and clean writable CoW state.
- [ ] Add backend-specific unit tests for immutable artifact reuse, fresh VM
      identity, failed setup cleanup, and no cross-launch mutable state.

**Exit gate:** backend start plus authenticated agent readiness is below 200 ms
p50 and below 300 ms p99 for prepared cold on the primary native backend—HVF on
Apple Silicon and Firecracker on the established Linux KVM host—with no
regression in warm claims or security witnesses.

## Phase 4 — Parallelize independent host work

- [ ] Build a dependency graph for image resolution, backend selection, mount
      fingerprint/cache lookup, static policy validation, and artifact manifest
      reads.
- [ ] Run independent local work concurrently, but keep rootfs-dependent plan
      signing and final admission after the verified rootfs is known.
- [ ] Keep admission entirely local for prepared-cold launches: no registry,
      remote object store, builder VM, or blocking shell command.
- [ ] Bound concurrency and preserve cancellation. A failed admission or cache
      verification must cancel the launch and clean temporary state.
- [ ] Add phase timing proving overlap rather than merely moving work between
      labels; the sum of wall-clock phases may be less than the sum of internal
      work durations.

**Exit gate:** admission remains fail-closed and its p99 is ≤50 ms in the
prepared-cold lane; overlapping work reduces total launch latency without
creating duplicate cache builders or orphan VMs.

## Phase 5 — Event-driven guest readiness

- [ ] Replace repeated readiness polling on the prepared-cold path with one
      authenticated readiness notification from the guest agent or existing
      control channel.
- [ ] Keep the current host-key pin, boot identity, generation token, and
      protocol-version checks on the notification. A socket becoming readable
      is not readiness.
- [ ] Make the first command dispatch use the same authenticated connection
      where possible, avoiding a second connect/handshake.
- [ ] Add tests for notification-before-wait, notification timeout, wrong host
      key, wrong boot identity, replayed notification, guest crash, and delayed
      agent startup.

**Exit gate:** the prepared-cold readiness wait is ≤20 ms p99 on the primary
backend and no unauthenticated or replayed notification can release dispatch.

## Phase 6 — Move cleanup off the foreground critical path safely

- [ ] Split command completion from cleanup completion in the timing model.
- [ ] Hand transient cleanup to the existing host-side lifecycle/reaper seam
      after the guest exit code and audit receipt are durable.
- [ ] Keep the VM state directory, PID ownership, cache locks, and network
      handles protected until cleanup confirms process exit. Never return early
      by abandoning a live VM.
- [ ] Preserve synchronous cleanup for interactive, error, or explicitly
      requested strict-teardown modes.
- [ ] Add crash/restart tests proving that a detached cleanup cannot delete a
      newer VM's state, remove a live process marker, or leak an egress session.

**Exit gate:** foreground teardown contributes ≤50 ms p99 to prepared-cold
launch completion while orphan-reap and process-ownership witnesses remain
green.

## Phase 7 — Live validation and regression gates

- [ ] Add a native Apple Silicon/HVF live benchmark job with cached artifacts,
      no mount, mount-cache hit, and mount miss lanes.
- [ ] Add a Linux Firecracker live benchmark on the established KVM host and a
      libkrun lane where supported.
- [ ] Store signed benchmark evidence with host, backend, artifact, and cache
      metadata; do not make CI infer hardware performance from a hosted runner
      without the required VMM capability.
- [ ] Add a BDD scenario for the prepared-cold contract and retain hermetic
      unit tests for all cache, admission, identity, and failure behavior.
- [ ] Add a CI regression check that fails when a prepared-cold run performs
      network/build/mount materialization work or exceeds the p99 budget on a
      designated live host.
- [ ] Update `specs/SPRINT.md`, Plan 265, Plan 292, and
      `specs/REFACTOR-STATUS.md` with measured results only after the live gates
      pass.

## Definition of done

- [ ] The benchmark distinguishes prepared cold, mount-cache hit, mount miss,
      artifact miss, and warm claim.
- [ ] Prepared cold reaches an authenticated guest agent in ≤200 ms p50,
      ≤250 ms p95, and ≤300 ms p99 on the primary native backend.
- [ ] Mount-cache hit meets ≤200 ms p50, ≤250 ms p95, and ≤300 ms p99.
- [ ] No launch path hides image acquisition, build, or first-time mount image
      creation inside the prepared-cold measurement.
- [ ] Warm-claim performance does not regress against Plan 265.
- [ ] The full workspace, Linux/backend, BDD, formatting, policy, and clippy
      gates pass.
- [ ] Security tests cover cache corruption, symlink/path handling, replay,
      wrong identity, wrong key, stale artifacts, interrupted publication,
      process ownership, and cleanup races.
- [ ] The final sprint and refactor rollup entries cite concrete evidence files,
      host/backend details, and commit references.
- [ ] The template identity and lifecycle vocabulary match
      `specs/notes/2026-08-10-fast-machine-substrate.md`; no parallel cache or
      snapshot graph exists.

## Explicit follow-ups if the gate remains red

If prepared cold remains above 300 ms after Phases 1–5, do not weaken the SLO or
fold warm claims into it. Capture a backend-specific breakdown and choose the
next optimization from measured time:

- VMM process/control startup → resident supervisor or in-process backend
  setup.
- Kernel/initramfs load → shared read-only mappings, smaller artifacts, and
  page-cache preparation.
- Guest userspace → minimal stage-0 path and one authenticated readiness event.
- Admission → local verification cache and bounded parallel preparation.
- Cleanup → lifecycle handoff with ownership-safe reaping.

If the first-use artifact lane is slow, improve acquisition and preparation
separately; it is not evidence that the prepared cold-boot SLO is impossible.
