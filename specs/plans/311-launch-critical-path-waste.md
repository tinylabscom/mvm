# Plan 311 — Launch critical-path waste on real-sized images

**Status:** Proposed — evidence gathered, no code changed.

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

## What is not yet measured

Stated plainly, because the plan's first task is to close it:

- Every number above is from a **debug** binary. Plan 299's are from release.
  The two are not comparable, and the release cost of a `python:3.12` prepared
  cold launch is **unknown**.
- The `alpine`-vs-`python:3.12` gap is inferred from the profile plus the 116x
  size ratio, not from a paired release measurement of both images.
- Process-startup cost in release is estimated, not measured.

No percentile in this plan may be published until Phase A0 replaces these with
release measurements.

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

- [ ] Build a release `mvmctl` and record a prepared-cold lane on `python:3.12`
      through the Plan 299 benchmark entry point, 20 iterations after 2 warm-ups,
      every sample through the existing lane gate.
- [ ] Record the paired `alpine` lane from the same binary on the same host, so
      the image-size delta is a measured quantity rather than an inference.
- [ ] Publish both as a table naming the image, its rootfs size, and the build
      profile. Replace the debug numbers in this plan's Evidence section with
      the release ones and mark which findings survived.
- [ ] Confirm from the release profile that the SHA-256 remains the dominant
      term. If it does not, re-order the phases below before writing any code.

## Phase B — Stop re-hashing a cached rootfs on every launch

Issue #2273.

- [ ] Change `emit_oci_run_admission`
      (`crates/mvm-cli/src/commands/vm/exec.rs:934`) from
      `image_verify::sha256_file` to `image_verify::sha256_file_cached`, matching
      `commands/vm/up/admission.rs`, `commands/pool.rs`, `mvm-hostd/src/run.rs`,
      and `commands/build/image_lineage.rs`.
- [ ] Add a test asserting the digest recorded on the admission is byte-identical
      to the uncached hash of the same rootfs.
- [ ] Add a test asserting a rewritten rootfs invalidates the sidecar and yields
      the new digest, so a stale digest can never be admitted.
- [ ] Add a test asserting an unreadable or absent sidecar falls back to hashing
      rather than failing the launch.
- [ ] Audit the remaining `sha256_file` call sites reachable from a launch and
      convert any that hash a cached, immutable artifact. Leave one-shot and
      verification-time call sites alone; list what was deliberately not changed.
- [ ] Record phase timing before and after on the Phase A0 large-image lane.

## Phase C — Take the process-table sweep off the launch path

Issue #2274.

- [ ] Establish which of the three options is correct and say why in the PR:
      defer the sweep until after command dispatch (matching the
      `reap_orphan_state_dirs` precedent already in `crates/mvm-cli/src/exec.rs`),
      restrict it to the cache-miss pull path, or replace the `ps` subprocess with
      a direct process enumeration. The first and third compose.
- [ ] Implement it at `crates/mvm-cli/src/commands/image/pull_core.rs:75` without
      changing what gets reaped.
- [ ] Add a test proving an orphaned helper planted before a run is gone after it.
- [ ] Add a test or gate proving no process-table walk executes before guest
      command dispatch on a prepared cold launch.
- [ ] Record phase timing before and after.

## Phase D — Make the kernel verity probe sublinear

Issue #2275.

- [ ] Replace `byte_contains`
      (`crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs:141`) with a
      skip-capable substring search. Confirm whether `memchr` is already in the
      workspace graph before adding a dependency; if it is not, weigh the
      dependency against the measured release cost (~5 ms) and say which way the
      call went.
- [ ] Keep the existing refusal semantics exactly: marker-free kernel refused,
      good kernel accepted, opaque/compressed kernel not wrongly rejected. The
      tests in `builder_vm_bootstrap_tests.rs` must pass unchanged.
- [ ] Consider a path+size+mtime verdict sidecar mirroring `sha256_file_cached`,
      so a steady-state launch does not re-read the kernel at all. Decide with the
      release measurement in hand, not before.
- [ ] Note in the PR that the marker loop short-circuits on the first hit, so the
      refusal case — the one the check exists for — pays the full scan; confirm
      the new implementation does not regress that case.

## Phase E — Make the benchmark see this class of regression

Issue #2276.

- [ ] Add a prepared-cold lane on a large-rootfs image, reported independently
      and never averaged into the `alpine` lane.
- [ ] Add a bytes-hashed counter to the launch sample, populated at the sites that
      hash an artifact during a launch.
- [ ] Extend the Plan 299 lane gate to refuse a `prepared_cold` sample that hashed
      a full rootfs. Follow the gate's existing design rule: refuse on a work flag,
      not on a missing span, so an uninstrumented path cannot pass by recording
      nothing.
- [ ] Add a test proving the gate goes red on a sample carrying a full-rootfs hash
      and green without one.
- [ ] Amend the Plan 299 performance-contract table to name the image and rootfs
      size behind each published percentile.

## Phase F — Validation

- [ ] Re-run the Phase A0 lanes on the final tree; publish `alpine` and
      large-image prepared cold side by side against the ≤200 ms p50 / ≤300 ms p99
      contract.
- [ ] Confirm the warm lane has not regressed against Plan 265.
- [ ] Confirm the claim-8 image digest and claim-14 provenance entries are
      unchanged in value across the whole change, on both images.
- [ ] Run the security-claim BDD suite and `xtask` gate set; a launch-path
      optimization must not move a claim witness.
- [ ] Update `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md` in the same change
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
