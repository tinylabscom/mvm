# Plan 159 WS-2 — `fs_quick` checkpoint + fork (PR1 design)

**Date:** 2026-06-10
**Status:** design approved; ready for implementation-plan authoring
**Scope:** Plan 159 WS-2, first PR (the `fs_quick` slice). PR2/PR3 sketched
under "Roadmap" but out of scope for this design.

## Goal

Give the Apple `Virtualization.framework` (Vz) / `apple_container` runtime a
first-class, audit-bound **checkpoint + fork** primitive: freeze a quiesced
microVM's filesystem state into an immutable checkpoint, then branch new
sandbox instances from it in seconds via APFS copy-on-write. This is the
filesystem half of the "instant fork" DX; the live-memory half lands in PR2.

## Where this sits (boundaries — do not duplicate)

Reuses, does **not** rebuild:

- **Vz supervisor** already exposes `PAUSE`/`RESUME`/`SAVE` control verbs and a
  `Restore` startup mode (`mvm-vm-host/src/vz_objc.rs`, `mvm-backend/src/vz.rs`).
- **APFS CoW** rootfs cloning via `clonefile(2)` is built —
  `base::cow::clone_rootfs_for_instance` (`mvm-backend/src/base/cow.rs:137`),
  O(1) template→instance, already used by `apple_container`.
- **Snapshot audit spine** — `vm.snapshot_saved` / `vm.snapshot_restored`
  events on the chain-signed log (`audit_chain.rs:304-356`).
- `mvmctl snapshot save/restore/ls/rm` already wired for Vz.

Owned **elsewhere** — WS-2 stays clear of:

- **Plan 140** (landed) — snapshot *correctness*: seccomp-on-restore, entropy
  reseed, clock resync, wake re-admission. WS-2 inherits these, doesn't touch.
- **Plan 148 Phase A** — the fork *fan-out* primitive (batched spawn, shared
  RO base, per-child identity). WS-2's `fork` is the DX surface, not the batch
  engine.
- **Plan 123 C1** (landed in `main`) — the `SnapshotCapability` enum/trait.
  Don't modify. C2/C3 (PostRestore sender, Vz save/restore substrate) are
  deferred/unowned (the `mvm-plan-123c-warmstart` worktree is stale — its C1
  commit is already merged; no open PR). PR2 will build on, not collide with,
  C3's territory.

## Decisions (from the brainstorm)

1. **Phasing** — PR1 = `fs_quick` (this doc); PR2 = `vm_full` memory
   save/restore + fork-from-memory (folds in the unmerged pause→save→resume
   ordering fix on `mvm-152-savefix`); PR3 = `checkpoint diff` + wire
   `mvmctl pause/resume` to the Vz path. `PR1 ∪ PR2 ∪ PR3` = full WS-2.
   Risk-ascending: pure host logic → live memory → polish.
2. **Data model** — one unified, first-class `checkpoint` object from PR1
   (model "A"); no separate wrapping surface, no later migration (project rule:
   no backcompat / no shim layers). PR1 only *populates* the `fs_quick` class;
   PR2 adds `vm_full` into the same model with no new surface.
3. **Consistency contract** — `fs_quick` requires the VM **quiesced** (stopped,
   or pause→`sync`→clone). The clone is a clean, deterministic rootfs image; no
   reliance on guest journal recovery. "Fork a *live, running* sandbox with its
   memory" is deliberately PR2's headline (`vm_full`), not PR1.

## Architecture

A host-side `checkpoint` subsystem. A **`Checkpoint`** is an immutable,
audit-bound record of frozen VM state under `~/.mvm/checkpoints/<id>/`
(holding `meta.json` + the CoW-cloned `content/`). PR1 implements the
`fs_quick` class only. **`fork`** clones a checkpoint's content into a new VM
instance with a fresh identity and records parent→child lineage. No new VMM
code; no live-boot dependency for any of the core logic.

### Components (small, independently testable units)

- **`mvm-core::checkpoint`** — pure types, no runtime deps (keeps
  `xtask check-core-runtime-free` green):
  - `CheckpointId` (newtype), `CheckpointClass { FsQuick, VmFull }`,
  - `CheckpointMeta { id, class, parent: Option<CheckpointId>, vm_name, tag:
    Option<String>, created_unix, content_sha256, supervisor_config_digest,
    audit_ref: Option<...> }` — serde + `deny_unknown_fields` + builder.
    `audit_ref` is backfilled (see "audit binding direction" below), so it is
    `Option` and not part of the hashed content.
- **`CheckpointStore`** (mvm-backend) — FS + serde over `~/.mvm/checkpoints/`
  via a new `mvm_core::config::checkpoints_dir()` helper (all `~/.mvm` paths go
  through `config`): `create / write_meta / read_meta / list / remove /
  by_tag / children_of`. Temp-dir unit-testable.
- **`capture_fs_quick`** (mvm-backend) — assert quiesced → `sync` →
  `clone_rootfs_for_instance(rootfs, content)` → SHA-256 → write meta.
  Reuses existing CoW.
- **`fork_checkpoint`** (mvm-backend) — verify `content_sha256` → CoW-clone
  content into a new instance state dir → mint a new `VmId` → write child
  lineage meta. PR1 **materializes** the child and prints the `mvmctl up` hint;
  **auto-boot-on-fork moves to the start of PR2** (pinning the start path showed
  booting a forked child pulls in the full `up` path + plan synthesis and isn't
  validatable on the local flaky Vz boot — which would defeat the host-side-
  testable rationale for doing `fs_quick` first). No machine-id sidecar here:
  `fs_quick` is a cold boot from a cloned rootfs with no saved machine state;
  the machine-id identity sidecar belongs to the `vm_full` path in PR2.
- **Audit** — new `LocalAuditKind::{CheckpointCreated, CheckpointForked}` +
  `AuditEmitter::emit_checkpoint_created/forked`; `tests/audit_total_coverage.rs`
  posture updated (same pattern as the `PoolWarm` kind added in Plan 118).
- **CLI** (`commands/vm/checkpoint.rs`) — `mvmctl checkpoint create <vm>
  [--tag T]`, `checkpoint ls`, `checkpoint rm <id>`, `checkpoint fork <id>
  [--new-id NAME] [--no-start]`; `--json` per the shared convention. Existing
  `snapshot save/restore` folds under the model as the (reserved) `vm_full`
  class. (Grouped under `checkpoint` for Plan 178 coherence; a top-level
  `mvmctl fork` alias is trivial to add later if wanted.)
- **Capability flip** — `apple_container` / `vz` `capabilities()` advertises
  `fs_quick` supported, `vm_full` reserved/gated.
- **GC** — `cache prune` sweeps untagged checkpoints past retention; `--tag`
  pins. Mirrors the standby-reaper sweep already in `ops/cache.rs`.

### Data flow

- **create**: quiesced VM → `sync` → `clonefile` rootfs → SHA-256 →
  `meta.json` → `checkpoint.created` (signed, chained).
- **fork**: read + verify parent meta → `clonefile` content → new instance dir
  + new id/machine-id → child lineage meta → `checkpoint.forked` → cold-boot
  child (default).

### Audit binding direction

The binding is **audit → checkpoint**: the chain-signed `checkpoint.created` /
`checkpoint.forked` entry carries the checkpoint `id`, `class`, `content_sha256`
and (for fork) the `parent` id. So `meta.json` is written first, the audit
entry is emitted referencing it, and the resulting entry's seq/hash is
backfilled into `meta.audit_ref` (a second, cheap meta write). The integrity
check at fork time relies on `content_sha256` (the audit chain proves the
checkpoint was admitted; the hash proves the content is intact) — `audit_ref`
is a convenience back-pointer, never load-bearing for verification.

### Error handling (fail-closed)

- `checkpoint create` on a non-quiesced VM → hard error (consistency contract).
- `checkpoint fork` of a `vm_full` checkpoint in PR1 → hard error
  ("vm_full lands in PR2") — no silent degrade (Plan 159: "reject when the
  backend can't honor it").
- `content_sha256` mismatch at fork → refuse (sealed-volume-style integrity).
- audit emit failure → operation fails (never an unaudited fork).

### Testing (all host-side, no live VM boot)

- `CheckpointMeta` serde roundtrip + `deny_unknown_fields` + builder defaults.
- `CheckpointStore` CRUD + tag-select + `children_of` over a temp dir.
- `capture_fs_quick`: refuses non-quiesced; clones; hashes; writes meta (temp
  rootfs file, no VM).
- `fork_checkpoint`: clones content, mints distinct id, records parent lineage,
  verifies hash, refuses `vm_full`, refuses tampered content.
- Audit: `checkpoint.created` / `checkpoint.forked` land in the chain;
  `verify_audit_chain` detects tamper; `audit_total_coverage` posture.
- GC: untagged pruned, tagged kept.
- `tests/cli.rs`: help text + arg parsing for `checkpoint` / `fork`.

## Roadmap (out of scope for PR1, recorded for continuity)

- **PR2 — `vm_full`**: memory checkpoint via `saveMachineStateToURL` /
  `restoreMachineStateFromURL`; fork-from-memory; fold in the unmerged
  pause→save→resume ordering fix; live-Vz round-trip validation. The
  live-boot validation risk is isolated to this PR.
- **PR3 — completes WS-2**: `checkpoint diff <a> <b>`; wire `mvmctl
  pause/resume` to the Vz path (today `pause.rs::snapshot_io_for` is
  Firecracker-only); cross-class polish.

## Crate placement

- types → `mvm-core/src/checkpoint.rs`
- store + capture + fork → `mvm-backend` (`checkpoint` module)
- audit kinds → `mvm-core/src/policy/audit.rs`; emitters →
  `mvm-cli/.../audit_chain.rs`
- CLI orchestration → `mvm-cli/src/commands/vm/checkpoint.rs`
- GC → `mvm-cli/src/commands/ops/cache.rs`
