# Plan 159 WS-2 PR3 — `checkpoint diff` + Vz `pause/resume` (design)

**Date:** 2026-06-11
**Status:** design approved; ready for implementation-plan authoring
**Finishes:** Plan 159 WS-2. Builds on the merged checkpoint subsystem —
fs_quick (#762), vm_full (#770), AuditEmitter hoist (#775).

## Goal

Close out WS-2 with the two remaining items: a `mvmctl checkpoint diff <a> <b>`
comparison and wiring `mvmctl pause/resume` to the Vz backend (today the CLI
pause/resume is Firecracker-snapshot-sealing only).

## Decision (from the brainstorm)

`mvmctl pause <vz-vm>` = **lightweight vCPU quiesce** (semantic A): dispatch to
`VzBackend::pause()`/`resume()` (the native PAUSE/RESUME control verbs; the VM
stays resident in memory, no disk write). Firecracker keeps its existing
sealed-snapshot pause **unchanged**. "Seal a Vz snapshot to disk" stays
`checkpoint create --class vm_full`. Clean split: **pause = quiesce,
checkpoint = seal.**

## Part A — `mvmctl checkpoint diff <a> <b>`

### What it compares (zero byte reads)
Reads both `CheckpointMeta` via `CheckpointStore::read_meta`. Compares:
- **Header**: `class`, `vm_name`, `tag`, `created_unix` (newer/older),
  `supervisor_config_digest` (same/changed).
- **Lineage**: whether `b` is a child of `a` (`b.parent == a.id`), the reverse,
  or unrelated.
- **Content manifest** (the heart): per-blob keyed by `ContentBlob.name` —
  **unchanged** (same sha256), **changed** (different sha256), **added** /
  **removed** (present in only one side). A blob sha256 mismatch is the
  realistic "this changed" signal; we deliberately do NOT byte-diff the
  multi-GB opaque ext4 / memory images. Cross-class diffs (fs_quick ↔ vm_full)
  naturally surface `memory.bin` / `machine-id` as added/removed.

### Shape (library-first)
- **`mvm-backend::checkpoint`** (pure, testable): `diff_checkpoints(a: &CheckpointMeta,
  b: &CheckpointMeta) -> CheckpointDiff`. `CheckpointDiff` is a structured value:
  header field deltas + a `Vec<BlobDelta { name, status: Unchanged|Changed|AddedInB|RemovedFromB, sha_a: Option<String>, sha_b: Option<String> }>` + a lineage relation enum. No I/O — the CLI reads the two metas and passes them in.
- **CLI** (`commands/vm/checkpoint.rs`): a `Diff { a, b, json }` subcommand that
  validates the two ids, reads both metas from the store, calls
  `diff_checkpoints`, and renders: a human summary + per-blob table by default,
  or `serde_json` of `CheckpointDiff` under `--json`.
- **No `--verify-content`** — YAGNI; `verify_content` is the separate on-disk
  integrity check and isn't part of a metadata diff.

## Part B — Vz `pause`/`resume` wiring

### Change 1: backend resolution
`AnyBackend::for_started_vm(name)` (in `mvm-backend/src/backend.rs`) probes
`fc.pid`/`qemu.pid`/`libkrun.pid` markers but NOT `vz.pid`. Add the `vz.pid`
arm so a running Vz VM resolves to `VzBackend` (the const is
`vz::PID_FILE_NAME = "vz.pid"`). This is the missing seam — without it Vz VMs
return `None` and fall through to a platform default.

### Change 2: CLI dispatch
`run_pause` / `run_resume` (in `commands/vm/pause.rs`) resolve the running VM's
backend via `for_started_vm`, then dispatch:
- **Firecracker / mock** → the existing `snapshot_io_for` →
  `pause_and_seal` / `verify_and_resume` path, **unchanged**. Preserves FC's
  sealed-snapshot semantics (HMAC envelope, epoch/vmstate/mem sidecar) and the
  mock `CannedIO` test path.
- **Vz** → `backend.pause(&VmId(name))` / `backend.resume(&VmId(name))` — the
  native PAUSE/RESUME control verbs (lightweight vCPU quiesce).

Both paths keep:
- `VmNameRegistry::set_paused(name, true|false)` + `touch_last_active` on resume.
- The `WorkloadSleep` / `WorkloadWake` audit emit.

The Vz resume path does **NOT** fire the FC post-restore signal
(`signal_post_restore`): the guest never left memory on a vCPU quiesce, so there
is nothing to remount/restart. That signal is specific to FC's sealed-snapshot
cold-ish restore.

### Capability gate
Dispatch consults `backend.capabilities().pause_resume`; a backend reporting
`false` yields a clear "backend X does not support pause/resume" error rather
than a confusing fall-through. Vz reports `pause_resume: true`.

## Error handling

- `checkpoint diff` with a missing id → clean "checkpoint `<id>` not found"
  (validate ids with the existing `validated_checkpoint_id`). The two ids may be
  any class/lineage; the diff is **directional** — it presents `b` relative to
  `a` (so swapping the args flips Added↔Removed), but neither needs to be the
  other's parent.
- `pause`/`resume` when `for_started_vm` returns `None` → "VM `<name>` is not
  running (no backend marker)".
- resolved backend with `pause_resume == false` → the capability error above.
- Vz pause on an already-paused VM → surface the supervisor's control-socket
  response (the PAUSE verb is effectively idempotent at the control layer).

## Testing

- **diff (pure, host-side):** `diff_checkpoints` over hand-built `CheckpointMeta`
  pairs — identical metas (no deltas), one changed blob, an added blob, a
  removed blob, cross-class (fs_quick vs vm_full), and a child-vs-parent lineage
  pair. Serde roundtrip of `CheckpointDiff`. CLI parse test for
  `checkpoint diff a b [--json]`.
- **pause/resume:** unit — `for_started_vm` resolves a `vz.pid` marker dir to
  `VzBackend` (write a temp `vz.pid`, assert the variant). Dispatch routing via
  the existing mock/`CannedIO` seam where reachable; CLI parse tests for
  `pause`/`resume`. The live Vz pause→resume round-trip is the one
  not-host-mockable piece (same constraint as PR1/PR2) — covered by the
  unit-level dispatch + a manual-validation note, not a blocker.

## Scope guard (YAGNI)

Two focused features, mostly host-side-testable. Out of scope: byte-level
content diff; `--verify-content` on diff; any change to Firecracker's
sealed-snapshot pause; a generic "drop FC sealing" refactor (semantic C, rejected).

## Crate placement

- `diff_checkpoints` + `CheckpointDiff`/`BlobDelta` → `mvm-backend/src/checkpoint/mod.rs`
- `vz.pid` arm → `mvm-backend/src/backend.rs` (`for_started_vm`)
- `checkpoint diff` subcommand + render → `mvm-cli/src/commands/vm/checkpoint.rs`
- `run_pause`/`run_resume` backend dispatch → `mvm-cli/src/commands/vm/pause.rs`

## Rollup

On merge, flip `specs/REFACTOR-STATUS.md` PLAN 159 WS-2 from `[~]` to `[x]`
(checkpoint diff + pause/resume wiring land; WS-2 complete), bump the date.
