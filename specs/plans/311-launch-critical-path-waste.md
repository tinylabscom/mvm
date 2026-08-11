# Plan 311 — Launch critical-path waste on real-sized images

**Status:** Phases A0-E complete and measured on Apple Silicon / HVF at
p50/p95/p99. Phase F complete except the warm-lane comparison, which cannot run
until a standby pool can be filled. The Firecracker/KVM repeat is done and
surfaced two costs this plan does not own — see #2292 and #2293.

## Goal

Remove per-launch host work that a prepared cold launch does not need, and that
Plan 299's benchmark cannot currently see because it scales with image size and
Plan 299 measures one small image.

The target is Plan 299's existing contract, unchanged:

> a release `mvmctl machine run` using already-cached, digest-verified artifacts
> must reach an authenticated guest agent and dispatch in **≤300 ms at p99**,
> p50 **≤200 ms**

with one addition this plan owns: **the contract must hold on a large image, not
only on `alpine`.**

## Why this is not simply Plan 299

Plan 299 owns the prepared cold path and has already measured it. Its Phase 0
baseline, and the Phase 5 fixes recorded against it, put HVF prepared cold at
79.2 ms dispatch p50 and 310.1 ms total on a release binary. Read on its own
terms, the dispatch SLO is met with margin.

That measurement runs `machine run --image alpine -- /bin/true`. The cached
`alpine` rootfs is 9.9 MB. The cached `python:3.12` rootfs is 1.1 GB — 116x
larger. Three costs on the launch path are a function of artifact size or host
state rather than of the VMM, and all three are invisible at 9.9 MB:

| Work | on `alpine` | on `python:3.12` |
|---|---:|---:|
| Full-rootfs SHA-256 for OCI provenance | a few ms | **~557 ms** |
| `ps` process-table snapshot | ~67 ms | ~67 ms |
| dm-verity marker scan over `vmlinux` | ~28 ms (debug) | ~28 ms (debug) |

Plan 299's lane gate refuses a `prepared_cold` sample that pulled, built,
materialized a mount image, or claimed a warm standby. A per-launch re-hash of an
already-cached rootfs is none of those, so the gate has no flag for it and the
sample reports itself clean. This plan closes that specific hole; Plan 299 keeps
ownership of the mount cache (Phase 1), artifact preparation (Phase 2), the
Firecracker boot path (Phase 3), readiness (Phase 5), and teardown (Phase 6).

Composition, as with Plan 299's own boundaries:

- Plan 299 owns the prepared-cold contract, the benchmark substrate, and phases
  1–7. This plan adds work items beneath its contract; it does not renumber or
  supersede them.
- Plan 255 / Plan 265 own warm claims and warm restore. Nothing here changes
  either, and the warm lane is a regression comparison only.
- No task here may weaken admission, signed-plan verification, the claim-8 image
  digest binding, the claim-14 OCI provenance record, dm-verity, or the
  vsock-only workload boundary.

## Evidence

Host: Apple Silicon, macOS, HVF backend. `machine run --image python:3.12`,
fully warm artifact cache, no pull, no build. **Debug binary** except where
noted — see "What is not yet measured".

`MVM_PHASE_TIMING=1`, three consecutive runs, steady state:

```
resolve=0.0ms drives=13.2ms admit=40.7ms backend_start=26.4ms vsock_wait=50.8ms
command=54.9ms teardown=166.8ms total=352.7ms launch_mode=cold dispatch_window=77.1ms
```

`sample`-based main-thread profile over the process lifetime (1026 samples ≈ 1.0 s):

```
1022  run_secure_with_source
 675    run_run_args
 568      build_exec_request
 557        emit_oci_run_admission
 484          image_verify::sha256_file          <- SHA-256 compute
  73          image_verify::sha256_file -> read  <- I/O
  76      resolve_or_pull_run_image
  72        sweep_orphaned_vm_helpers_on_startup
  67          std::process::Command::output      <- `ps -axww`
  28      assert_workload_kernel_supports_verity
  28        byte_contains                        <- windows().any() over 8.2 MB
 332    run_inner                                <- the span phase-timing measures
 149      teardown_transient_vm
  95      run_in_guest
```

Wall-clock decomposition of the same command:

| Segment | ms | On the VM-start path? |
|---|---:|---|
| `cargo run` wrapper | ~1570 | no — invocation artifact |
| process startup (debug binary) | 110 | no |
| **full-rootfs SHA-256** | **557** | no |
| **`ps` process-table snapshot** | **67** | no |
| **dm-verity marker scan** | **28** | no |
| drives | 13 | setup |
| admit (plan signing + audit chain) | 46 | setup |
| backend start (VMM create) | 32 | yes |
| vsock wait (boot → agent ready) | 42 | yes |
| command (`python -c`) | 55 | no |
| teardown | 179 | no — after dispatch |

The microVM itself is 74 ms of that. 652 ms is host-side work that no launch
depends on.

Two facts that decide how each item is fixed:

- **The SHA-256 does not shrink in release.** 1.1 GB in 557 ms is ~2.0 GB/s and
  the profile bottoms out in `sha2::sha256::aarch64_sha2::compress` — hardware
  SHA-256. Optimization level is not the lever; not doing the work is.
- **The verity scan does shrink in release.** Benchmarked standalone on the same
  8,216,584-byte `vmlinux`: 44.2 ms unoptimized vs 2.32 ms at `-O` for the
  `"Linux version"` probe. Most of its measured cost is the debug build.

The value the SHA-256 recomputes is already on disk. Next to the rootfs:

```
c20b3c26ac72e7ae147045438354173c159c4dd42ab9cb09e9e335d694b5fe07 1205739520 1786327964101437241
```

which is exactly the `image_sha256=c20b3c26...` the admission then records.

## Measured result — release, both images, same host and cache state

Apple Silicon / HVF, release `mvmctl` on both sides, identical prepared cache,
`</dev/null` stdin, wall clock via `/usr/bin/time -p`. Baseline is the branch
point (`5cd52bc69`); fixed is this branch with Phases B, C and D applied.

| wall clock | baseline | fixed | removed |
|---|---:|---:|---:|
| `python:3.12` (1.1 GB rootfs) | 1.15–1.57 s | **0.43 s** | ~840 ms |
| `alpine` (9.9 MB rootfs) | 0.52 s | **0.43 s** | ~90 ms |

The two images converge. Before, they differed by ~780 ms on identical code —
which was the whole finding. After, `python:3.12` costs what `alpine` costs,
because nothing on the launch path is a function of image size any more.

The alpine delta is Phases C and D, which are image-size-independent; the
python delta is those plus Phase B.

Phase timing on the fixed binary, `python:3.12`, three consecutive runs:

```
drives=13.6ms admit=37.9ms backend_start=17.6ms vsock_wait=61.8ms
command=52.9ms teardown=133.2ms total=317.0ms dispatch_window=79.4ms
```

Dispatch window is **78.8–79.4 ms** against the ≤200 ms p50 / ≤300 ms p99
contract, now on a 1.1 GB image rather than a 9.9 MB one. That is the claim
Plan 299 could not previously make.

The launch sample reports the new counter as zero, which is the proof rather
than the timing:

```json
{ "image_pull": false, "image_build": false, "mount_materialize": false,
  "warm_claim": false, "artifact_bytes_hashed": 0, "process_table_scans": 0 }
```

Both counters are zero on a prepared launch, and both are refused by the
prepared lanes when nonzero — so this is a gate, not a note. The six runs
behind the table above vary by 0.01 s across both images, which is the
convergence stated as a measurement rather than a claim.

### Percentiles through the benchmark harness

Wall clock above is the before/after. These are the contract numbers: release
binary, `ColdLaunchBench` via the Plan 299 entry point, 20 measured runs after
2 warm-ups per lane, every sample through the lane gate (the harness refuses a
short report, so 20 samples means 20 launches cleared it).

| lane | dispatch p50 | p95 | p99 | total p50 |
|---|---:|---:|---:|---:|
| `alpine` (9.9 MB rootfs) | 79.6 ms | 84.9 ms | 93.6 ms | 320.1 ms |
| `python:3.12` (1.1 GB rootfs) | **77.3 ms** | **79.7 ms** | **90.1 ms** | 316.1 ms |
| budget | ≤200 ms | ≤250 ms | ≤300 ms | — |

The 116x image-size difference is now inside the run-to-run noise at every
percentile, and `python:3.12` clears the p99 budget with a 3.3x margin. Before
this change the same pair differed by ~780 ms.

Sub-phases on the large image, p50 / p99:

| span | p50 | p99 |
|---|---:|---:|
| `vmm_create` | 11.6 ms | 14.4 ms |
| `guest_kernel_entry` | 58.6 ms | 67.9 ms |
| `agent_auth` | 3.4 ms | 6.0 ms |
| `artifact_verify`, `first_dispatch` | ≤0.1 ms | ≤0.1 ms |
| `stop_transient` | 128.1 ms | 139.8 ms |
| backend `driver_boot` | 7.8 ms | 8.9 ms |

Two things this says. Guest boot to a serving agent is ~59 ms and is now three
quarters of the dispatch window — VM creation is 11.6 ms and the backend's own
`driver_boot` is 7.8 ms, so there is little left to win on the HVF VMM side.
And `stop_transient` at 128 ms is larger than the entire dispatch window it
follows.

### What is left, and who owns it

Of the ~420 ms wall clock that remains, the largest single span is
`teardown=133 ms` (`stop_transient` 132.6 ms), which runs *after* the command
has already produced its answer. That is Plan 299 Phase 6 and is deliberately
not touched here. `guest_kernel_entry` at ~60 ms is the guest booting to a
serving agent and is Plan 299 Phase 3/5.

## What is still not measured

- **Firecracker/KVM is now measured** (Plan 299 Phase 3 re-measurement section).
  The Plan 311 fixes hold there — a prepared Firecracker launch reports
  `artifact_bytes_hashed: 0` and `process_table_scans: 0` — but that backend
  misses the contract for reasons this plan does not own: `driver_boot` 630.5 ms
  (#2292) and 294 ms of audit-chain fsync in `admit` (#2293). The prepared-cold
  contract is met on HVF and **not** on Firecracker.
- The debug-build figures in the Evidence section above are retained because
  they are what located each cost. They are not comparable to the release
  results and are not a contract measurement.

## Non-goals

- Do not change what is admitted, signed, or audited. The claim-8 image digest
  and the claim-14 provenance record keep the same values; only how the digest
  is obtained changes.
- Do not weaken the dm-verity kernel refusal. A kernel with no device-mapper
  symbols must still be refused.
- Do not stop reaping orphaned VM helpers. Move the work, do not delete it.
- Do not add a second artifact cache, digest graph, or benchmark harness.
- Do not fold large-image numbers into Plan 299's existing `alpine` percentiles.
- Do not touch the Firecracker boot path (Plan 299 Phase 3) or foreground
  teardown (Plan 299 Phase 6) here.

## Phase A0 — Establish a release baseline on a large image

- [x] Build a release `mvmctl` and record a prepared-cold lane on `python:3.12`
      through the Plan 299 benchmark entry point, 20 iterations after 2 warm-ups,
      every sample through the existing lane gate.
- [x] Record the paired `alpine` lane from the same binary on the same host, so
      the image-size delta is a measured quantity rather than an inference.
- [x] Publish both as a table naming the image, its rootfs size, and the build
      profile. Replace the debug numbers in this plan's Evidence section with
      the release ones and mark which findings survived.
- [x] Confirm from the release profile that the SHA-256 remains the dominant
      term. If it does not, re-order the phases below before writing any code.

## Phase B — Stop re-hashing a cached rootfs on every launch

Issue #2273.

- [x] Change `emit_oci_run_admission`
      (`crates/mvm-cli/src/commands/vm/exec.rs:934`) from
      `image_verify::sha256_file` to `image_verify::sha256_file_cached`, matching
      `commands/vm/up/admission.rs`, `commands/pool.rs`, `mvm-hostd/src/run.rs`,
      and `commands/build/image_lineage.rs`.
- [x] Add a test asserting the digest recorded on the admission is byte-identical
      to the uncached hash of the same rootfs.
- [x] Add a test asserting a rewritten rootfs invalidates the sidecar and yields
      the new digest, so a stale digest can never be admitted.
- [x] Add a test asserting an unreadable or absent sidecar falls back to hashing
      rather than failing the launch.
- [x] Audited the remaining `sha256_file` call sites reachable from a launch.
      **Nothing else was converted, deliberately.** The two kernel-digest sites
      (`mvm-hostd/src/run.rs` and `plan_admission.rs`) are uncached on purpose
      and carry the reason in-tree: a path+mtime-keyed cache can hand back a
      stale hash, "which for an integrity pin would defeat the point of having
      one". Note the asymmetry that makes this change consistent rather than
      contradictory: `run.rs` already hashes the *rootfs* through
      `sha256_file_cached` on the very next line, so the rootfs digest was
      always the cached one and the OCI path was the outlier. The remaining
      callers are `verify_artifact` (verification is the work), the checkpoint
      and volume paths (not on this launch), and the benchmark harness (outside
      the measured window). The empirical check is the counter: a prepared cold
      launch now reports `artifact_bytes_hashed: 0`, so no site on this path
      hashes anything.
- [x] Record phase timing before and after on the Phase A0 large-image lane.

## Phase C — Take the process-table sweep off the launch path

Issue #2274.

- [x] Establish which of the three options is correct and say why in the PR:
      defer the sweep until after command dispatch (matching the
      `reap_orphan_state_dirs` precedent already in `crates/mvm-cli/src/exec.rs`),
      restrict it to the cache-miss pull path, or replace the `ps` subprocess with
      a direct process enumeration. The first and third compose.
- [x] Implement it at `crates/mvm-cli/src/commands/image/pull_core.rs:75` without
      changing what gets reaped.
- [x] Keep orphan reaping working: the existing `reap_orphaned_vm_helpers_*`
      suite is unchanged and still passes, because the sweep's behaviour is
      untouched — only *when* it runs moved. No new end-to-end test was written;
      planting a real orphan and running a real launch needs a live backend and
      belongs in the BDD lane, not a unit test.
- [x] Add a gate proving no process-table walk executes before guest command
      dispatch on a prepared cold launch: `ProcSnapshot::capture` reports itself,
      the count reaches the launch sample as `process_table_scans`, and the
      prepared lanes refuse a nonzero one — the same shape as the bytes-hashed
      witness rather than a second mechanism.
- [x] Record phase timing before and after.

## Phase D — Make the kernel verity probe sublinear

Issue #2275.

- [x] Replace `byte_contains`
      (`crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs:141`) with a
      skip-capable substring search. Confirm whether `memchr` is already in the
      workspace graph before adding a dependency; if it is not, weigh the
      dependency against the measured release cost (~5 ms) and say which way the
      call went.
- [x] Keep the existing refusal semantics exactly: marker-free kernel refused,
      good kernel accepted, opaque/compressed kernel not wrongly rejected. The
      tests in `builder_vm_bootstrap_tests.rs` must pass unchanged.
- [x] Considered a path+size+mtime verdict sidecar mirroring
      `sha256_file_cached` and **rejected** it: with `memmem` the whole check is
      ~5 ms in release, and caching a safety check to save that is a bad trade.
      The check exists to convert an unactionable guest panic into a host error,
      and a cache is one more thing that can be stale when it matters.
- [x] Note in the PR that the marker loop short-circuits on the first hit, so the
      refusal case — the one the check exists for — pays the full scan; confirm
      the new implementation does not regress that case.

## Phase E — Make the benchmark see this class of regression

Issue #2276.

- [x] Ran the prepared-cold lane on a large-rootfs image, reported
      independently. The benchmark entry point already takes its argv from
      `MVM_COLD_LAUNCH_ARGS`, so the large-image lane needed a second
      invocation rather than new code. Both lanes are recorded above at
      p50/p95/p99 through the lane gate.
- [x] Add a bytes-hashed counter to the launch sample, populated at the sites that
      hash an artifact during a launch.
- [x] Extend the Plan 299 lane gate to refuse a `prepared_cold` sample that hashed
      a full rootfs. Follow the gate's existing design rule: refuse on a work flag,
      not on a missing span, so an uninstrumented path cannot pass by recording
      nothing.
- [x] Add a test proving the gate goes red on a sample carrying a full-rootfs hash
      and green without one.
- [x] Amend the Plan 299 performance-contract table to name the image and rootfs
      size behind each published percentile.

## Phase F — Validation

- [x] Re-run the Phase A0 lanes on the final tree; publish `alpine` and
      large-image prepared cold side by side against the ≤200 ms p50 / ≤300 ms
      p99 contract. Done at p50/p95/p99 on both images.
- [x] Repeat on Firecracker/KVM. The fixes hold (both counters zero); that
      backend's remaining gap is #2292 and #2293, recorded in Plan 299 Phase 3.
- [~] Confirm the warm lane has not regressed against Plan 265. **Not run at
      the time:** the standby pool was empty on this host (`pool status`
      reported 0 idle) and `pool warm` could spawn nothing, so there was no warm
      claim to measure. Nothing in this change touches the claim path. That
      blocker is gone — Plan 299 Phase 2's launch resolution lets
      `pool warm --image` fill the pool (**#2333**) — so the check is owed
      against a filled pool.
- [x] Confirmed the claim-8 image digest and claim-14 provenance entries are
      unchanged in value across the change. Baseline and fixed runs both record
      `image_sha256=c20b3c26ac72e7ae147045438354173c159c4dd42ab9cb09e9e335d694b5fe07`
      — one distinct digest across the last 14 plan entries, spanning both
      binaries — `plan.oci_provenance` is still emitted, and
      `mvmctl trust audit verify` exits 0.
- [x] Run the security-claim BDD suite and `xtask` gate set; a launch-path
      optimization must not move a claim witness.
- [x] Update `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md` in the same change
      as each phase lands.

## Risks

- **A cached digest is a trust decision.** The sidecar is keyed on size + mtime.
  That is sound against ordinary rewrites and is already relied on by every other
  admission path, but it is weaker than re-reading the bytes. The claim-8 binding
  is what depends on it. If review concludes the OCI provenance record needs a
  stronger guarantee than the sibling paths accept, the alternative is to hash
  once at materialization and treat the sidecar as authoritative from then on —
  not to keep hashing on every launch, which costs 557 ms and still trusts the
  same file.
- **Deferring the orphan sweep changes when reaping happens.** A run that is
  SIGKILLed after dispatch and before the deferred sweep leaves an orphan for the
  next run to collect. That is the behaviour `reap_orphan_state_dirs` already
  accepts; it should be stated, not discovered.
- **A verdict sidecar for the kernel probe caches a safety check.** Weigh it
  against ~5 ms of release cost. Cheap is not the same as free, and the check
  exists to prevent an unactionable guest panic.
- **Optimizing against one host.** Every number here is from one Apple Silicon
  machine on HVF. Firecracker's profile differs materially (Plan 299 Phase 0
  records `driver_boot` at 623.6 ms there against 53.8 ms on HVF). Phase A0's
  paired measurement should be repeated on the KVM host before any percentile is
  published as a cross-backend claim.
