# Reviewed workspace apply, undo, redo (PS-08, #3718)

## What landed

The agent never writes the host tree by itself: a workspace is a private
copy of a host directory, and `mvmctl machine apply` is the one reviewed
write-back path.

- `mvm-fs::workspace_apply` is the engine, usable without the CLI. A plan
  diffs the workspace's baseline image against the guest's live image and
  checks every changed path against the protected-path set (one match
  refuses the whole apply, naming every match) and the operator's
  exclusions (matching paths are dropped and recorded).
- Staging copies every pre-image (the host bytes about to be replaced) and
  post-image (the guest bytes) into a content-addressed blob store — a
  blob's name is the digest computed while writing it — then persists the
  manifest with a Merkle root over its ops and journals `begin`.
- Commit writes through a temp file + fsync + atomic rename per file; a
  delete renames the victim into the apply's trash first. A `done` marker
  separates the two crash windows: begun-without-done rolls the host tree
  back from the snapshot (journals `rollback`); done-without-commit
  completes the commit on the next open.
- `mvmctl machine undo` / `redo` are journal verbs: each reversal is
  itself a journaled apply (the original's pre-images become the undo's
  post-images), so undo, redo, and crash recovery share one machinery and
  one durability story. Redo only stands when the undone record was a
  forward apply and nothing newer has been applied.
- Exclusions are persisted in the manifest and are the only list a later
  undo or restore consults — the failure this answers is a restore
  rebuilding ignore defaults and deleting files the session never
  excluded.
- The host-signed audit chain records `workspace.applied` /
  `workspace.undone` / `workspace.redone` entries carrying the committed
  manifest Merkle root; the local operational log retains its stable
  `workspace_apply` / `workspace_undo` / `workspace_redo` kinds. The
  protected-path gate (shipped CI/build/test classes + `--protected-path`)
  refuses guest-authored changes to CI config, hooks, and signing material
  before anything reaches the host tree.
- `machine apply` prompts `Apply to working tree? [y/N]`; `--yes` applies
  non-interactively (required without a terminal), `--dry-run` reports
  without staging.

## Deliberate scope

Per-step checkpoints and `replay` from a checkpoint with recorded input
remain as an operator surface. The runtime now has the secure substrate for
that slice: bounded encrypted and content-addressed replay inputs, session- and
cursor-bound hash-linked checkpoint capture, an atomic session-record commit
point, chain-verified replay planning, ordered idempotent dispatch, and session
seal snapshot roots. Production step orchestration and the `mvmctl` replay verb
still need to connect those primitives to the agent's input transport.
Multi-volume machines apply one `--volume` at a time.

## Tests

10 `mvm-fs` engine tests against real ext4 images (lifecycle, undo/redo
semantics, both crash windows, protected refusal, exclusion persistence,
blob-integrity refusal); 4 BDD scenarios on the user-visible surface
(no-workspace remedy, unchanged workspace, terminal requirement, empty
history); signed-chain workspace-root and session snapshot-root tests; replay
input encryption, tamper, wrong-key, cursor-binding, step-commit, lineage, and
ordered-dispatch tests.
