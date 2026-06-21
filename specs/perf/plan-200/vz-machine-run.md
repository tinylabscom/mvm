# Plan 200 — `machine run` phase timing on macOS Vz

Manual capture, recorded so latency discussion is grounded in measurement
rather than assertion. These are exploratory numbers from one developer host,
**not** a CI-gated baseline (contrast `specs/perf/plan-118/*.json`).

## Method

- Host: macOS 26 Apple Silicon, `vz` backend (Apple Virtualization.framework).
- Binary: **debug** `mvmctl` (`cargo build`, not `--release`) — treat every
  number as an upper bound; a release build will be faster.
- Isolated `MVM_DATA_DIR`, warm shared builder/store cache.
- `MVM_PHASE_TIMING=1` emits one `[mvm] phase-timing:` line per transient run
  (`crates/mvm-cli/src/commands/vm/phase_timing.rs`); fields are wall-clock ms
  for each `exec::run_inner` seam. `dispatch_window` = admitted→agent-reachable.
- Command: `mvmctl machine run --image alpine -- true` (transient OCI path).

## Results

### Cold first run

```
resolve=0.0 drives=48.1 admit=173.8 backend_start=13659.0 vsock_wait=0.8 command=52.7 teardown=0.4 total=13934.7 dispatch_window=13659.7
```

The cold `backend_start` (~13.7 s) folds in three one-time costs that are not
part of steady state: a source-checkout rebuild of `mvm-vz-supervisor` (helper
freshness check), the first `alpine` OCI pull, and ext4 rootfs materialization
in the builder VM. It is recorded for completeness, not as a steady-state
figure.

### Warm (alpine cached, builder up), N=3

| run | total | backend_start | drives | admit | vsock_wait | command | teardown |
|-----|------:|--------------:|-------:|------:|-----------:|--------:|---------:|
| 1   | 2458.9 | 2253.9 | 75.1 | 19.8 | 13.8 | 94.2 | 2.1 |
| 2   | 2488.1 | 2261.4 | 89.0 | 32.4 | 28.6 | 75.6 | 1.1 |
| 3   | 2475.3 | 2298.0 | 86.7 | 24.3 |  3.9 | 61.2 | 1.1 |

(ms)

Warm steady state is **~2.46–2.49 s total**, of which `backend_start`
(~2.25–2.30 s) — Vz machine creation + boot of the alpine OCI rootfs — is the
dominant term and the obvious lever. `teardown` is ~1–2 ms (the eager-kill
`stop_transient` from the B2 work, vs the pre-fix ~6 s). `vsock_wait`
(boot→agent reachable) is single/low-double-digit ms once booted.

### `--net` DNS smoke — FAILS on Vz

`mvmctl machine run --net --image alpine -- nslookup example.com` exits 1
before boot:

```
Error: boot vz guest
    resolve observers: allowlist <keys>/policies/local/exec-<id>.toml:
    policy bundle for local:exec-<id> not found at the expected path
Error: starting transient microVM
    supervisor exited before writing PID file (status: exit status: 1).
```

The `--net` / `--allow-host` transient path does not synthesize/locate the
egress policy bundle the resolve-observers step expects, so the Vz guest never
boots. This is an open egress-enforcement gap on the transient `machine run`
path (related to the in-flight `fix/plan-200-up-egress-enforcement` work), not
a measurement artifact. The no-network path above is unaffected.

## Linux KVM / Firecracker lane (live-captured)

Captured on a Linux KVM host (x86_64, Firecracker v1.14.1, `/dev/kvm`),
debug `mvmctl` off `origin/main`, isolated `MVM_CACHE_DIR`/`MVM_DATA_DIR`,
`MVM_BUILDER_BACKEND=qemu` (the builder VM runs under QEMU on this host;
the *workload* boots on Firecracker). `machine run --image
docker.io/library/alpine:3.20 -- /bin/true`, cold isolated cache, exit 0:

```
phase-timing: resolve=0.0ms drives=3.1ms admit=490.7ms
              backend_start=1259.7ms vsock_wait=975.3ms command=56.7ms
              teardown=1243.0ms total=4028.5ms dispatch_window=2235.0ms
```

The OCI materialization + builder Stage-0 bootstrap happen *before* this
window (resolve/drives ≈ 0), so these are the workload-run spans, directly
comparable to the Vz numbers above. Firecracker `backend_start` ~1.26 s is
notably faster than Vz's ~2.25 s create+boot; the hot-path cost is split
between `backend_start` and the ~0.98 s guest boot (`vsock_wait`).
`dispatch_window` = 2235 ms → this binary predates the `dispatch_bar`
token, but the value clears the 200 ms warm bar only when `backend_start`
collapses on a standby claim; cold, it is correctly over.

## Open / not covered here

- Release-build numbers (these are debug upper bounds).
- The `--net`/`--allow-host` smoke, blocked on the egress-policy-bundle gap above.
- A committed cached-hot-start benchmark *harness* — the live loop that
  claims a warm standby and measures the hot-path dispatch window across
  N iterations. (Still open; needs a warm standby, so it overlaps the
  warm-pool work.)

The `<200 ms` dispatch bar itself is now a first-class, surfaced
construct (`RunPhaseTimings::DISPATCH_BAR_MS` / `within_dispatch_bar()`):
`MVM_PHASE_TIMING=1` runs now end their line with `dispatch_bar=ok|over`,
comparing `dispatch_window` (`backend_start + vsock_wait`) against the
200 ms warm-start ceiling, so a regression is visible in the line rather
than eyeballed. On the cold Vz numbers above (`backend_start` ~2.25 s)
the verdict is correctly `over` — the bar is a *warm/cached* hot-start
target (where `backend_start` collapses toward zero on a standby claim),
not a claim that cold runs clear it.

No latency claim should be made beyond what is measured here.
