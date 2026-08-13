# Plan 323 — Concurrent builds through one builder VM

**Status:** Phase 1 COMPLETE, Phases 2-4 OPEN
**Date opened:** 2026-08-11
**Branch:** Phase 1 on `worktree-builder-lock-wait`

## Problem

Two `mvmctl build` / `mvmctl machine build` / `mvmctl deps install` invocations
cannot run at the same time. The second dies immediately:

```
Error: builder VM

Caused by:
    extracting artifacts from builder sandbox: image ~/.mvm/cache/builder-vm/
    nix-store-aarch64.img.lock is already attached by another builder VM
    process; wait for the running `mvmctl build` / `mvmctl deps install` to
    finish and retry: lock acquisition failed because the operation would block
```

The lock itself is correct and load-bearing. Every builder backend attaches
`nix-store-<arch>.img` as a **read-write** virtio-blk device
(`libkrun_builder.rs`, `builder_runner/hvf_builder.rs`, `qemu_builder.rs`); the
guest mounts it as ext4 at `/nix-store`. Two guests mounting one ext4 image
read-write corrupts it. So the shared Nix store is a genuinely exclusive
resource and "just run two builder VMs against it" is not available.

What was wrong is the *response* to contention — a hard error that hands the
operator a manual retry — and the fact that the mechanism which does support
concurrency is off by default and unavailable on the macOS default backend.

## Approach

Two independent problems, addressed in order:

1. Contention should **queue**, not fail. (Phase 1 — landed.)
2. Concurrent builds should **share one builder VM** rather than serialize,
   because Nix inside a single guest already parallelizes derivations safely
   and shares one warm store. (Phases 2-4.)

Explicitly rejected: per-process store images cloned via `clonefile`/reflink
with a `nix copy` merge back under a short lock. It buys real VM-level
parallelism, but duplicates build effort across VMs, has no reflink on ext4
Linux hosts (silently degrading to a full multi-GiB copy), and adds a merge
step that can fail after a successful build. Multiplexing into one VM gets the
same user-visible outcome with none of that.

### Phase 1 — queue instead of failing (COMPLETE)

- [x] `LockWait` newtype in `builder_vm_runtime.rs`: `none()` (fail fast),
      `of(Duration)`, `from_env()` reading `MVM_BUILDER_LOCK_WAIT_SECS`
      (default 1h, `0` restores fail-fast).
- [x] `acquire_sidecar_lock_within` polls `try_lock` on a 500 ms interval up to
      the budget instead of failing on the first `WouldBlock`. Non-contention
      lock errors (permissions, a filesystem without locking) still surface
      immediately.
- [x] The holder stamps a `LockOwner` record (pid, argv, acquisition time) into
      the sidecar lock file, so a waiter names the real command instead of
      guessing a verb. A missing, corrupt, or dead-pid record degrades to
      "another mvm builder process".
- [x] `pid_alive` rejects any `u32` that isn't a single positive `pid_t` before
      calling `kill` — `kill(0, …)` and `kill(-1, …)` address process *groups*,
      so a corrupt record must never reach the syscall.
      `persistent_builder::supervisor_alive` now delegates to it.
- [x] Progress on stderr: one line when the wait starts (naming the holder), a
      "still waiting" line every 15 s, one line on acquisition.
- [x] The refusal that remains (budget exhausted) names the holder, the
      `MVM_BUILDER_LOCK_WAIT_SECS` override, and `mvmctl persistent-builder
      start`.
- [x] Both lock call sites — the Nix store image and `ensure_persistent_volume_
      image` — take the wait.
- [x] The two spurious-`WouldBlock` retry wrappers in the test suite
      (`acquire_named_or_retry`, `ensure_vol_rw_or_retry`) collapse into a
      bounded `LockWait`, since the production path now does the waiting.

- [x] `LockWait::from_env` is fail-fast under `cfg(test)`. Found the hard way:
      `run_build_surfaces_environment_gaps_on_clean_input` calls the production
      `run_build`, which locks the **host-wide** store image rather than a
      tempdir, so with a waiting default it queued behind another checkout's
      test process and "passed" in 2106 s.

Phase 1 removes the hard failure. It does **not** make two builds run at once —
the second one waits.

Follow-up this surfaced (not fixed here — it changes what the test asserts):
several `mvm-build` unit tests drive `run_build` against the real
`~/.mvm/cache/builder-vm` instead of an isolated root. `xtask
check-test-home-isolation` doesn't catch them because they never move
`MVM_HOME` and never call a seeding resolver — they just take a host-wide
cross-process lock. Worth either isolating them or extending the gate with a
"unit test reaches a host-wide lock" rule.

### Phase 2 — an HVF persistent builder (OPEN)

The persistent-builder session is the existing multiplexing mechanism: one
long-lived VM holds the store lock for its lifetime and serves jobs over vsock
(`LibkrunPersistentHostVm` → `PersistentVmHandle` → the in-guest dispatch loop
on `BUILDER_DISPATCH_PORT`). `dev_build_via_builder_vm_uncached`
(`pipeline/dev_build.rs`) already routes any build into a live session when
`~/.mvm/run/persistent-builder.json` exists.

It is libkrun-only. `mvmctl persistent-builder start` bails for both other
backends (`crates/mvm-cli/src/commands/build/persistent_builder.rs:199,203`).
Since macOS 26+ Apple Silicon auto-detects **hvf**, the mechanism is
unreachable on the default macOS configuration — which is why the reported
failure happened at all.

**The blocker is the job transport, not the dispatch loop.** The dispatch loop
is already VMM-agnostic: it is an AF_VSOCK listener the guest enters when it
finds `/job/dispatch.sock.marker`. What differs is how per-job inputs and
outputs reach it.

- libkrun/qemu attach `/work`, `/job`, `/out`, `/mvm-bins` as **live virtio-fs
  shares**, so each dispatch stages a new job into `/job` and reads artifacts
  back out while the VM keeps running.
- The HVF builder uses the **disk transport**: `BuilderRunner::build` tars
  `{job, work, mvm-bins}` into `input.img` *before boot* and reads `output.img`
  *after poweroff* (`crates/mvm-runtime/src/builder_runner/runner.rs`). That is
  inherently run-to-completion — a second dispatch has nowhere to put its
  inputs.

The guest already handles both, selected purely by cmdline:
`mvm-host-vm-init` reads `mvm.builder_transport=disk` and, when it is absent,
takes the virtio-fs path (`parse_disk_transport_cmdline`, the Track B fan-out).
**No guest change is required** — only a host-side spec that omits the token
and attaches the shares. The `hvf VMM has no virtio-fs` comments in the guest
init are stale as of the virtio-fs work in PR #2387.

- [x] **Depends on #2387** (HVF virtio-fs shared-memory discovery). Until it
      merges, an HVF virtio-fs share does not come up, so nothing below can be
      verified live. Host-side unit coverage does not depend on it.
- [x] A persistent-builder variant of `builder_spec`: drop
      `mvm.builder_transport=disk` / `mvm.builder_input` / `mvm.builder_output`
      from `BUILDER_CMDLINE`, drop the input/output disks, and populate
      `VmmSpec.shares` with `work`, `job`, `out`, `mvm-bins`. Keep the
      nix-store disk at `vdb` and the runtime overlay. `builder_spec` currently
      hardcodes `shares: Vec::new()` and the disk-transport cmdline
      (`crates/mvm-runtime/src/builder_runner/spec.rs:17`).
- [x] `HvfPersistentHostVm` alongside `HvfBuilderVm` in
      `crates/mvm-runtime/src/builder_runner/`: hold the `NixStoreImageLock`
      for the VM's lifetime, register the same vsock ports libkrun does
      (`BUILDER_DISPATCH_PORT`, `WORKLOAD_FORWARD_PORT`,
      `BUILDERD_CONTROL_PORT`, host-listen `EGRESS_PORT`), wait for the
      dispatch-ready marker, and return a handle whose kill/wait releases the
      lock.
- [x] Move the shared persistent-session helpers out of `libkrun_builder.rs`,
      where they sit behind `#[cfg(feature = "builder-vm")]`, into the
      backend-agnostic `builder_vm_runtime`: `stage_persistent_job_dir`, the
      dispatch markers, `wait_for_path`, and `PersistentVmHandle`. Copying them
      into a second backend is the failure mode this repo has hit before.
- [x] Wire it into `persistent_builder::start` so the hvf bail becomes a
      supported branch. The session record is backend-agnostic already;
      confirm `stop`/`status` work unchanged.
- [x] Confirm the Stage 0 reaper and `mvmctl cache prune` see the hvf
      persistent VM state dir (the `mvm-persistent-builder-hvf-*` prefix).
- [x] Tests: spec shape (no disk-transport token, four shares present),
      session start/stop round-trip, lock held for the VM's lifetime and
      released on kill. Live: a dispatched build returning artifacts, once
      #2387 lands.

### Phase 3 — adopt the persistent builder on contention (OPEN)

With Phase 2 in place, a waiting build has a better option than waiting.

- [x] On `WouldBlock` at the store lock, before queueing: re-read the session
      record. If a live session exists, dispatch into it instead of waiting.
      (Today the session is only consulted *before* the single-shot path
      decides to boot its own VM, so a build that already committed to
      single-shot queues rather than re-checking.)
- [x] Decide whether contention should *auto-start* a session rather than only
      adopt one. Recommended: yes, behind the same residency policy that
      already governs `persistent_routing_allowed` — a second concurrent build
      is exactly the signal that a shared builder is worth its RAM. Needs a
      guard against two contending processes both trying to start one (the
      store lock itself is the natural arbiter: whoever holds it starts the
      session).
- [x] `mvmctl doctor`: report whether a session is live and how many builds are
      routed through it.

### Phase 4 — documentation (OPEN)

- [x] `public/src/content/docs/guides/troubleshooting.md`: the contention
      message, the wait override, and the persistent-builder path.
- [x] `public/src/content/docs/reference/cli-commands.md`: document
      `MVM_BUILDER_LOCK_WAIT_SECS` alongside the other builder env knobs.

## Invariants this must not break

- One writer per `nix-store-<arch>.img`, always. Phases 2-4 change *who* holds
  the lock and for how long, never how many hold it.
- Stage 0 keeps its separate `nix-store-stage0-<arch>.img` so a builder-VM
  bootstrap never serializes against a user build.
- The single-shot builder stays the safety net: any persistent-dispatch failure
  falls back to it, as it does today.
