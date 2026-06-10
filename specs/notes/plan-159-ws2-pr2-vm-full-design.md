# Plan 159 WS-2 PR2 — `vm_full` memory checkpoint + restore + fork (design)

**Date:** 2026-06-10
**Status:** design approved; ready for implementation-plan authoring
**Builds on:** PR1 (`fs_quick` checkpoint+fork, merged #762) + the Vz SAVE
pause→save→resume fix (merged #740). Both on `main`.

## Goal

Complete the Vz "instant fork" DX: add the `vm_full` checkpoint class —
full machine *memory* state, not just the filesystem — plus same-identity
**restore** (suspend/resume) and **fork** (branch a new identity from a memory
checkpoint), all through the unified `checkpoint` surface. This is the headline
"resume / fork a running sandbox in seconds" capability.

## Decisions (from the brainstorm)

1. **Scope = full bundle (C):** fold + restore + fork + auto-boot in one PR.
   To de-risk the coupling, the **fork-from-memory feasibility spike is task 1**
   with a decision gate; the fold + restore do not depend on it and proceed
   regardless.
2. **Fork semantics = A with B fallback:** aim for a *live* fork (child gets a
   new identity and resumes from the parent's exact memory while the parent
   keeps running); if the spike shows Vz rejects cross-identity restore, fall
   back to *restore-as-new from a non-running parent* (one copy at a time) —
   not a silent degrade.
3. **Verb surface = full unification (A):** retire the standalone Vz
   `mvmctl snapshot save`/`snapshot restore`; everything routes through
   `checkpoint`. `snapshot ls/rm` (Firecracker instance snapshots, a different
   feature) stay.

## Where this reuses existing machinery

The Vz memory primitives already work — PR2 is consolidation + the fork arm,
not a rebuild:

- **Vz SAVE** — `vz_objc.rs::save` (pause→save→resume, #740) →
  `saveMachineStateToURL`; `VzBackend::snapshot_save(id, path)`.
- **Vz RESTORE** — `vz_objc.rs::restore_and_resume` →
  `restoreMachineStateFromURL`; `VzBackend::snapshot_restore(id, snapshot_path,
  machine_id_path) -> VmId` via `StartupMode::Restore`.
- **machine-id sidecar** — `write_machine_id_sidecar` (mode 0600); the
  `<snapshot>.machine-id` continuity token.
- **control protocol** — `vz_control::send_command` (`PAUSE`/`RESUME`/`SAVE`).
- **capability gate** — `snapshot_capability() -> SaveRestore` on macOS-26 Vz;
  no change.
- **checkpoint subsystem (PR1)** — `CheckpointStore`, `CheckpointMeta`,
  `fork_checkpoint` (currently refuses `VmFull` — the slot we fill), the audit
  emitters, the CLI group.

## Architecture

Extend the unified `checkpoint` model with the reserved `VmFull` class. A
`vm_full` checkpoint is a **consistent triple** captured in one pause window:
filesystem (CoW-cloned rootfs) + memory blob + machine-id. Restore resumes the
*same* identity; fork branches a *new* one (strategy per the spike). All
operations are `pub` library API in `mvm-backend`/`mvm-core`; the CLI is a thin
wrapper.

### Content model (the one change reaching back into PR1 code)

PR1 modeled checkpoint content as a single blob (`content_sha256: String` +
`only_file_in`, "exactly one file"). `vm_full` holds three artifacts, so this
generalizes to a small **manifest**:

```
ContentBlob { name: String, sha256: String }
CheckpointMeta.content: Vec<ContentBlob>   // replaces content_sha256
```

- `fs_quick` → one blob (`rootfs.ext4`).
- `vm_full` → three blobs (`rootfs.ext4`, `memory.bin`, `machine-id`).

One integrity-verify path covers both (verify each named blob against its
recorded hash), replacing `only_file_in`. This *extends* our own just-merged
PR1 code (not a fork of it). `content_sha256` is **replaced** by `content`
(not kept alongside) — so checkpoints written by PR1 are not read by PR2. That
is acceptable under no-backcompat: checkpoints are disposable local state with
no cross-version persistence guarantee, so there is no migration shim; a
pre-PR2 checkpoint is simply re-created. The single-blob helper (`only_file_in`)
is replaced by the manifest-verify, not duplicated.

### Operations (all `pub` in `mvm-backend::checkpoint`)

- **`capture_vm_full(store, params) -> CheckpointMeta`** — requires a
  **running** VM (the inverse of `fs_quick`'s quiesced contract). Orchestrates
  **one pause window** so memory and disk are from the same instant:
  `PAUSE` → `saveMachineStateToURL`(→ `content/memory.bin`) + CoW-clone the
  live rootfs (→ `content/rootfs.ext4`) + copy the machine-id (→
  `content/machine-id`) → `RESUME`. Today's `snapshot_save` resumes immediately
  after the save, so this needs the disk clone to happen *inside* the pause —
  a small extension that orchestrates `PAUSE`/`SAVE`/clone/`RESUME` via the
  existing control verbs rather than the all-in-one `save`. Hashes all three
  blobs into the manifest; writes meta (class `VmFull`).
- **`restore_checkpoint(store, id, target_vm) -> ()`** — same-identity resume:
  verify the manifest, materialize `content/rootfs.ext4` back to the VM's rootfs
  (the memory expects that disk state), flip the supervisor config to
  `StartupMode::Restore { memory.bin, machine-id }`, boot → resume. Reuses
  `VzBackend::snapshot_restore`, **extended to also restore the rootfs** (today
  it restores only memory + machine-id). Replaces `snapshot restore`.
- **`fork_checkpoint` (vm_full arm)** — replaces PR1's `VmFull` refusal. Copy
  `memory.bin` + CoW-clone `rootfs.ext4` into the child's state dir, then apply
  the **spike-determined identity strategy**:
  - **A (live):** mint a new machine-id + fresh MAC; restore the child from the
    copied memory while the parent stays running → two live copies.
  - **B (fallback):** restore-as-new from a non-running parent (one at a time),
    sidestepping the two-live-copies MAC/identity collision.
  Auto-boot is inherent (restore = resume), which also delivers the auto-boot
  deferred from PR1 for the `fs_quick` arm.

### The feasibility spike (task 1, decision gate)

Resolve the cross-identity-restore unknown before building the fork arm:
(a) save a running Vz VM's memory; (b) attempt `restoreMachineStateFromURL`
into a VM with a **new** machine-id; (c) if rejected, retry with the **same**
machine-id + a **new MAC** and check whether guest networking survives (the
guest kernel holds the old MAC in memory). Outcome picks **A vs B** and the
exact machine-id/MAC handling. The fold + `restore_checkpoint` do not depend on
the spike and proceed in parallel.

## Library API surface (explicit requirement)

The whole capability is a **library API**, not CLI-only:

- Types: `mvm_core::checkpoint::{CheckpointId, CheckpointClass, CheckpointMeta,
  ContentBlob, builder}`.
- Operations + store: `mvm_backend::checkpoint::{CheckpointStore,
  capture_fs_quick, capture_vm_full, restore_checkpoint, fork_checkpoint,
  CaptureVmFullParams, RestoreParams, ForkParams}` — all `pub`, params-struct
  in / `CheckpointMeta` (or `()`) out.
- Reachable by library consumers (notably **mvmd**, for warm pools / Plan 148
  fork-fanout) through the facade re-export `mvmctl::backend::checkpoint::*`.
- **Audit binding exposed:** the backend operations stay **audit-free / pure**
  (params in, `CheckpointMeta` out) — exactly PR1's separation. PR1 left the
  chain-signed binding (host signer + plan + `emit_checkpoint_*`) in the CLI;
  PR2 relocates it to a `pub` library helper that takes an `AuditEmitter` +
  the `CheckpointMeta`, so any consumer (CLI or mvmd) wires identical
  `checkpoint.created/restored/forked` audit by calling one function. The
  operations never emit on their own.
- The `mvmctl checkpoint …` commands contain **zero logic** beyond arg
  resolution + calling the library.

## CLI surface (unified)

- `mvmctl checkpoint create [--class fs_quick|vm_full] <vm> [--tag T] [--json]`
  — default `fs_quick` (quiesced VM); `vm_full` requires a **running** VM.
- `mvmctl checkpoint ls [--json]` · `rm <id>`
- `mvmctl checkpoint restore <id>` — **new**, same-identity resume (replaces
  `snapshot restore`).
- `mvmctl checkpoint fork <id> [--new-id]` — now works for both classes;
  **auto-boots** the child.
- Retire `snapshot save` / `snapshot restore`. New audit event
  `checkpoint.restored` alongside `created`/`forked`.

## Error handling (fail-closed)

- `vm_full` create on a stopped VM → refuse ("start the VM first").
- restore/fork verify every manifest blob's hash before use (same posture as
  PR1's integrity gate).
- cross-identity restore failure in the spike → documented fallback to B, not a
  silent degrade.
- macOS-26-Vz-gated (the `snapshots` capability already reports honestly per
  host).
- fork audit fatal on signing error (no unaudited fork), matching PR1.

## Testing

- **Host-side units:** the content manifest (serde, multi-blob verify), capture
  orchestration with mocked control verbs (pause-window ordering), restore/fork
  wiring, integrity refusals, audit emission + chain verify, the library API
  surface (call the ops without the CLI).
- **Live Vz round-trip = the spike + one integration validation:** save →
  restore → fork on this macOS-26 host (the Vz builder works here). The
  dev-VM-init-EOF flakiness means validating with a long-lived workload image,
  not the dev shell.

## Roadmap position

PR2 completes the memory + fork half of WS-2. **PR3** (the remaining WS-2
slice) is `checkpoint diff <a> <b>` + wiring `mvmctl pause/resume` to the Vz
path (today `pause.rs::snapshot_io_for` is Firecracker-only).

## Crate placement

- types + manifest → `mvm-core/src/checkpoint.rs`
- `capture_vm_full` / `restore_checkpoint` / vm_full fork + the consistent
  pause-window orchestration → `mvm-backend` (`checkpoint` module + `vz.rs`
  extensions: rootfs-aware restore, in-pause disk clone)
- exposed audit-binding helper → `mvm-cli` audit module made `pub` /
  relocated so the facade reaches it (or a thin `mvm-backend`-level seam)
- `StartupMode::Restore` gains a rootfs path → `mvm-build/src/vz.rs`
- CLI verbs (`create --class`, `restore`, retire `snapshot save/restore`) →
  `mvm-cli/src/commands/vm/checkpoint.rs` + `pause.rs`
