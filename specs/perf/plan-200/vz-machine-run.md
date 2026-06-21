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

## Open / not covered here

- Release-build numbers (these are debug upper bounds).
- The `--net`/`--allow-host` smoke, blocked on the egress-policy-bundle gap above.
- The Linux KVM / builder-VM lane (`machine run` on Firecracker) — needs a KVM host.
- A committed cached-hot-start benchmark harness + a `<200 ms` dispatch bar
  assertion (the dominant `backend_start` is the work item before any such claim).

No latency claim should be made beyond what is measured here.
