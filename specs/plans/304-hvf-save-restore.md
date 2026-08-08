# Plan 304 — HVF save/restore for checkpoint and fork

**Status: COMPLETE**
Owner: runtime
Created: 2026-08-08

## What this buys, and what it does not

HVF already has fast warm launch. It comes from **resident handoff**: a standby
parent stays live and paused, and a claim hands its machine instance straight to
a child identity (`HvfDriver::fork_standby_child` → the supervisor's handoff
socket). That path measures 18.9 ms p50 dispatch on an M-series Mac and does not
go through a saved state at all.

So this work is **not** a warm-start latency change. What it buys:

- `mvmctl machine checkpoint create --class vm-full` on HVF — a durable,
  content-addressed, chain-anchored record of a running machine.
- `mvmctl machine checkpoint restore` — same-identity resume from one.
- `mvmctl machine checkpoint fork` — a fresh child identity resumed from one.
- The lineage those three feed: `timeline`, `revert`, `rewind`, `advance`, and
  the fork tree the sandbox-branching model is built on.

A checkpoint restore is slower than a resident handoff and always will be: it
reads guest RAM back off disk and starts a new VMM, where a handoff transfers a
process that is already running. Measured numbers are in "Benchmark evidence"
below. Nothing in this plan changes the launch path.

## Starting point

More of this existed than the `SnapshotCapability::Unsupported` flag suggested.
Verified by reading the code, then by running it:

- `mvm-runtime/src/backends/hvf/snapshot.rs` — the frame codec: encode, parse,
  restore, and the AArch64 vCPU state codec.
- `mvm-runtime/src/backends/hvf/kernel_boot.rs` — capture (a `snapshot_request`
  file makes the paused run loop serialize RAM + devices + vCPU into
  `snapshot.ram`/`snapshot.frame`) and restore (`restore_ram` maps the saved RAM
  privately, `restore_frame` restores the control plane and rebinds host
  channels).
- `mvm-backends/src/driver/hvf.rs` — `HvfVmFullControl` already implemented
  `VmFullControl`: pause via SIGUSR1 + acknowledged marker, `save_memory`,
  resume via SIGUSR2, `retain_paused_after_capture`, `device_anchors`,
  `extra_content`, `supervisor_config_path`.

What was missing was everything **around** the VMM primitives: nothing ever set
`restore_ram`/`restore_frame` (a dead config path), the CLI hardcoded
Firecracker's capture control, the liveness and quiescence probes did not know
`hvf.pid` or the HVF pause marker, and `checkpoint restore` was a hard `bail!`.

## Workstreams

### WS1 — Audit `HvfVmFullControl` against the full `VmFullControl` surface

- [x] Every method has a real implementation; none of the trait's defaults are
      left standing where HVF needs a behaviour (`supervisor_config_path` and
      `extra_content` were already overridden, and both are load-bearing here).
- [x] `save_memory` gained the one precondition the surface could not express:
      **refuse a VM with a writable disk**. A snapshot carries guest RAM plus the
      devices' control plane, never a device's backing bytes. That is sound for a
      read-only file-served disk (the restore rebinds the same unchanged image)
      and unsound for a RAM-backed ephemeral rootfs, whose writes vanish with the
      VMM. Failing closed at capture is the difference between "unsupported" and
      "mints a checkpoint that silently reverts data".
- [x] The capture rendezvous poll uses a bounded exponential backoff (200 µs →
      5 ms) rather than a flat 10 ms tick, so it does not quantize its own
      measurement.

### WS2 — The restore entry point

- [x] `mvm-backends/src/driver/hvf_restore.rs` — the mechanics. Reads the
      captured launch config and device anchors out of the materialized state
      dir and rewrites them into a child config that:
      - re-derives **every** per-VM host path from the child's own state dir
        (pid file, console log, workload exit, pause marker, snapshot
        rendezvous, agent socket);
      - remaps each device path through the recorded anchors to the child's own
        clone, and refuses a writable disk (independently of WS1's gate);
      - sets `restore_ram` / `restore_frame` so the supervisor maps the saved RAM
        privately and restores the frame instead of loading a kernel;
      - **drops every authority-bearing relay** — substitution endpoint, broker,
        dev console sockets, live-handoff control. A restored guest reaches the
        network only once a claim binds a relay, so a restore comes up deny-all
        by construction, before its vCPU runs.
- [x] `mvm-runtime/src/hvf_restore.rs` — the two adapters: `HvfForkRestorer`
      (fork into a fresh identity, reached through the
      `ForkRestore` callback the way `FcForkRestorer` is — an inherent method,
      no shared trait, since plan 298 collapsed that trait when it extracted the
      Firecracker driver) and
      `HvfVmFullRestore: VmFullRestore` (same-identity resume). The latter clones
      the checkpoint's content dir into the target's state dir first: a resumed
      guest writes through to its rootfs, and the sealed bytes are what every
      later fork verifies against.

### WS3 — Backend-neutral dispatch

- [x] `AnyBackend::vm_full_control` — the capture control of the backend that
      owns the VM, with an exhaustive match so a new variant must decide.
- [x] `mvm_runtime::checkpoint::vm_is_running` reads the one shared marker list
      (`mvm_vmm::host::process_liveness`), so `hvf.pid` counts and `EPERM` on a
      root-owned Firecracker still reads as alive. The CLI's private two-marker
      list is gone — it now delegates here.
      `vm_is_running_covers_every_catalog_pid_marker` drives that probe from the
      backend descriptors, so a backend that registers a marker the shared list
      does not carry goes red instead of silently reading as stopped.
- [x] `vm_is_quiesced` understands the HVF pause marker. The supervisor writes
      `pause.state` only after its vCPU has entered the pause hold, so its
      presence beside a live `hvf.pid` *is* the acknowledgement.
- [x] The supervisor-config predicate that gated fork dispatch (it would have
      misread every HVF checkpoint, because HVF also carries a supervisor
      config) is replaced by
      `mvm_core::checkpoint::vm_full_origin` — a typed classification derived
      from the machine-state blob the manifest names (`memory.bin.hvf-frame` →
      HVF, `vmstate.bin` → Firecracker, supervisor config alone → the removed
      backend, none → not a vm_full checkpoint). Dispatch is on the bytes a
      restore would actually load.
- [x] `fork_vm_full_fc` → `fork_vm_full`: the clone, the verity-binding check and
      the lineage record were already backend-neutral; only the restorer differs.
- [x] `ensure_save_restore_supported` checks the backend that owns *this* VM
      rather than the host default.

### WS4 — Capability flip

- [x] `HvfBackend::capabilities().snapshot_capability` → `SaveRestore`.
      `SaveRestore`, not `LiveMemory`: a capture copies the whole mapping.
- [x] Tests that pinned `Unsupported` updated (`mvm-backends` driver identity
      test, the `mvm-runtime` per-backend capability table).

### WS5 — Security invariants

- [x] **Lineage chain-anchoring.** `restore_checkpoint` now takes a
      `CheckpointChainAnchor` and runs `verify_checkpoint_against_chain` — the
      same fail-closed gate `fork_checkpoint` and `fork_vm_full` run. Bringing a
      machine back to life is at least as consequential as branching from it, so
      a record edited after it was audited must not be restorable either. This
      closed a real hole: restore previously verified content hashes only.
- [x] **Sealed-content verification.** `verify_content` still runs on both
      paths, and the HVF fork inherits `validate_fork_verity_binding` — an
      incomplete dm-verity sidecar set, a missing `device-anchors.json`, or a
      verity anchor without sidecars all refuse before the VMM starts.
- [x] **`capture_fs_quick` unchanged.** The fs_quick path is untouched; the only
      change it sees is that a paused HVF VM now reads as quiesced, which is what
      lets it be checkpointed at all.
- [x] **Fresh child identity.** An HVF fork admits its own claim-8 plan (own
      nonce, own VM name, `deny_all` networking), then delivers a fresh
      generation token over the backend-agnostic vsock dispatcher and refuses
      anything short of acknowledged + reseeded + clock-resynced. A child that
      cannot prove it rotated is stopped.
- [x] The Firecracker arm's experimental opt-in is **not** carried over, and the
      reason is recorded in code: that guard exists because a restored
      Firecracker child inherits the parent's guest IP/MAC out of saved memory
      and collides with it on the shared bridge. An HVF guest has no NIC to
      inherit an address on.

### WS6 — Tests, BDD, benchmarks

- [x] Unit coverage on every new seam, positive and negative.
- [x] `features/suites/s11_snapshot/hvf_save_restore.feature`.
- [x] Benchmark evidence (below).

## Known limits

Recorded here rather than papered over:

1. **A writable disk is not checkpointable on HVF.** The device model's snapshot
   section carries a device's control plane, not its backing bytes, and the
   section is capped at 1 MiB. The two workload tiers HVF actually runs are
   unaffected: a sealed/verity boot attaches only read-only file-served disks
   (guest-writable state lives in guest RAM, which *is* captured), and a
   virtiofs-root dev boot attaches no block device at all. The non-verity ext4
   dev tier, whose rootfs is RAM-backed ephemeral, is refused with a message
   naming the disk. Lifting this needs a new snapshot section for block-image
   contents, which is a device-model change, not a checkpoint change.
2. **A capture writes guest RAM twice** — once as `snapshot.ram` and once inside
   the frame's RAM section — so a checkpoint of an N-MiB VM costs ~2N MiB on
   disk before deduplication. Pre-existing: the standby-pool capture path has
   always paid this. Collapsing the frame's RAM section into a reference to the
   sibling file is a frame-format change.
3. **Same-identity restore is HVF-only.** Firecracker's saved state loads only
   into a fresh child (`machine warm-restore`), and `restore` says so.

## Benchmark evidence

See `specs/plans/304-hvf-save-restore-bench.md`.
