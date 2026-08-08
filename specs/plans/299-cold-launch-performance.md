# Plan 299 — Prepared cold-launch performance

**Status:** Phase 0 in progress — the measurement substrate is implemented and
gated; the live baseline measurement remains.

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
      filesystem, cache state, and run number with every sample.
      (The launch writes artifact **paths**, not digests — hashing inside the
      measured window would charge the launch for the measurement. The runner
      resolves digests, filesystem, and cache state afterwards into
      `LaunchContext`/`CacheState`. `vmm_version` is resolved only for the
      in-house VMM, which ships inside `mvmctl`; a third-party VMM records
      `None` rather than a fabricated number.)
- [x] Add a benchmark report format containing raw samples and p50/p95/p99;
      do not store only summary numbers.
      (`ColdLaunchReport` carries `raw: Vec<ColdLaunchSample>` alongside
      `LaneStats`. A span no launch recorded reports `samples: 0` with `None`
      percentiles, so "never measured" is distinguishable from "measured as
      fast" and the report still round-trips through JSON.)
- [ ] Measure at least 20 iterations per lane after two warm-up iterations on
      native Apple Silicon/HVF and the Linux Firecracker host. Measure libkrun
      where the supported Linux or macOS environment can run it.
- [x] Add a benchmark assertion that rejects a sample labeled `prepared_cold`
      when it performed an image pull, image build, mount-image materialize, or
      warm claim.
      (`validate_lane` in `crates/mvm-cli/src/bench/cold_launch.rs`, called on
      every warm-up and measured launch. It reads `LaunchWork` flags rather
      than spans — an uninstrumented phase records no span, and refusing on a
      missing span would pass exactly the contamination the gate exists to
      catch. A warm claim is refused on the launch mode as well as the flag, so
      one signal going missing cannot let it through.)

**Exit gate:** the report can distinguish the 430-second mount-image cost from
the actual approximately 1.2-second backend-start cost, and the baseline is
reproducible from a release binary.

**Exit-gate status:** the substrate is in place and gated; the gate itself is
not met until the live baseline above is measured and recorded.

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
