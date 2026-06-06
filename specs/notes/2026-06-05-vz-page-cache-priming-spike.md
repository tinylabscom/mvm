# Spike — Vz page-cache priming: does a warm cache speed first-read after restore?

**Date:** 2026-06-05
**Status:** Design (awaiting review) — throwaway measurement spike, nothing ships.
**Feeds:** [ADR-073](../adrs/073-warm-snapshot-prior-art-adoption-boundary.md) §1 +
the Plan 157 "page-cache priming at freeze" deferred follow-up.

## Goal — the one decision this feeds

Answer with a real number on *our* stack: after a Vz (`Virtualization.framework`)
snapshot restore, does a **warm guest page cache** produce a meaningfully faster
first read of the working set than a **cold** one?

- **Clear gain** → the Plan 157 page-cache-priming follow-up is justified; proceed
  to a sized/realistic measurement (B/C below).
- **No gain / lost in noise** → **delete** the follow-up. We don't build it.

The premise today is borrowed from a commercial sibling's docs (ADR-073's "pooled
OCI-microVM runtime", `with_warmup`, "~7× on rustc-class"). This converts that
assumption into evidence we own.

## Background (why this is the cheap first move)

Page-cache priming sits at the *top* of a dependency chain, not the bottom:

```
page-cache priming
  needs → Plan 157 Phase C (memory-snapshot freeze)
            needs → Plan 123 Phase C (FC fast-resume) + Plan 140 (restore correctness)
```

Building that whole stack on the strength of a competitor's number is backwards.
Vz already has working `snapshot save`/`restore` CLI (macOS 14+), so we can measure
the *page-cache* variable in isolation **today**, without building any of it.

## Experiment — the A/B (existing CLI only, scope A)

Vz `saveMachineStateTo` serializes the **entire guest RAM** (page cache included) and
`restoreMachineStateFrom` loads it back. So priming *is* captured in the snapshot; the
question is whether that warm cache beats a cold one **net of Vz's restore overhead**.

1. Boot a long-lived `dev-shell` workload on Vz (PID 1 idles; agent serves the vsock
   console — the Plan 120 init-EOF exit is already fixed).
2. **Primed run:** read the working set in-guest via `mvmctl console <vm> --command
   '<read>'`, then `mvmctl snapshot save <vm> --path primed.vzsnap`.
3. **Cold run:** fresh boot, *don't* touch the working set, `mvmctl snapshot save
   <vm> --path cold.vzsnap`.
4. **Measure:** `mvmctl snapshot restore` each, then time the first read of the
   working set via `console --command`. N trials each (≥5); compare distributions, not
   single runs — we want an obvious gap, not a precise figure.

### Working set — read existing immutable rootfs, no image surgery

Use a large `/nix/store` subtree the boot path never touches as the working set:

```sh
time sh -c 'find /nix/store/<subtree> -type f -exec cat {} + >/dev/null'
```

Rationale: it's block-backed (rootfs ext4 on virtio-blk, so a cold read genuinely
faults from the virtual disk), naturally cold (boot doesn't read it, so no root
`drop_caches` needed), and it's *also the most representative* thing — "warm the
binaries/libs the workload will read" is exactly what priming buys. A tmpfs file would
be useless here (tmpfs is always RAM-resident — no cold/primed distinction).

### Success threshold (judgment, stated up front)

A gain worth pursuing should be **obvious**: primed first-read consistently ≥~2× faster,
or saving on the order of hundreds of ms on the working set, across trials. A
difference under ~20% or inside trial-to-trial noise = no signal = kill the follow-up.

## Security constraints (carried into the eventual feature)

The spike is security-neutral (see below), but it nails down the scope the *feature*
must obey, so record it here:

- **Prime the immutable root volume (rootfs) only.** The rootfs is read-only,
  verity'd, secret-free by design. It is the *only* thing priming touches. A primed
  page cache becomes part of a snapshot that forked children (Plan 157 / 148) all
  restore from, so priming anything mutable or sensitive would share it across every
  fork — a claim-1 / claim-11 confidentiality leak.
- **Secrets are never in any volume — root or data.** They arrive as destination-bound,
  signed credentials over the host broker (`host.secrets.v1`, claims 12/13), never as
  raw bytes in the guest. So there is no secret-in-volume for a primed cache to leak.
- **Other (data / app-dep) volumes may be mounted, but are never primed into a shared
  base.** Mutable per-tenant data must not be baked into a snapshot N children share;
  each fork gets its own volume disposition (Plan 157 / 140 per-instance freshness).

Net constraint, one line: **priming = read-only immutable rootfs, never volumes,
never secrets.** The spike's working-set choice (`/nix/store` reads) already obeys it.

## Why the spike itself has no security impact

- Changes no production code; merges nothing; throwaway worktree torn down after.
- Runs entirely in the **dev tier** — a `dev-shell` image is required for the console
  `Exec` path. That is the explicitly non-hardened tier
  (`feedback_dev_vm_vs_prod_security_tiers`); it does **not** touch **claim 4**
  (`prod-agent-no-exec`, which asserts `do_exec` is absent from *prod* builds), and
  this path is never presented as evidence about prod.
- `snapshot save/restore` already emit `vm.snapshot_saved` / `vm.snapshot_restored`
  audit-chain entries — the actions aren't covert.
- No network — claim 10 / egress posture untouched.
- Honest caveat: it measures perf on a restore path that still has Plan 140's four
  correctness gaps (seccomp-off-on-restore, no entropy reseed, no clock resync, no
  wake admission). Fine for a latency number on a dev guest; it's why the result is
  "is the perf worth pursuing," not "restore is ready."

## Environment / isolation

- Run in a **git worktree** with `MVM_CACHE_DIR` / `MVM_DATA_DIR` pointed at scratch
  dirs, so the shared nix-store flock can't race parallel sessions
  (`project_dev_host_runs_builder_via_vz`).
- Build the codesigned `mvm-vz-supervisor` via `crates/mvm-vz-supervisor/tools/build.sh`
  (or set `MVM_VZ_SUPERVISOR_PATH`) — Vz refuses an unsigned/missing supervisor
  (`reference_mvm_vz_supervisor_separate_swiftpm_binary`).

## Deliverable

A results section appended to this note: the trial numbers, the verdict (proceed to
B/C, or kill the follow-up), and any surprises (esp. the host-page-cache confound
below). No code merged; snapshots/images discarded.

## Confound we note, not fight

The **host's** page cache for the rootfs disk image can make even a "cold" guest read
fast and mask the benefit. That's part of the truth about this backend, so the results
state it plainly rather than trying to defeat it (e.g. we won't purge host cache between
runs — a real deployment wouldn't either).

## Feasibility items to resolve in the plan (not blockers)

1. Which ready **dev-shell Vz-bootable workload image** to use, vs. building one (a
   single Vz builder run on this Mac). Prefer an existing example image if one boots on
   Vz with the agent.
2. Confirm `console --command` returns the timing output cleanly from a one-shot exec
   (vs. needing the raw `Exec` vsock RPC — that would be scope B, out of bounds for A).

## Out of scope

- Implementing page-cache priming, or any change to the freeze/restore path.
- Firecracker / cloud-hypervisor (different snapshot mechanism — measure later if Vz
  shows a signal worth generalizing).
- B (realistic workload, e.g. `python -c "import numpy"`) and C (synthetic + realistic)
  — gated on A showing a signal.
