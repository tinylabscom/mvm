---
title: Bring agent changes home
description: Review what an agent changed in its workspace, apply it back to the host directory through a journaled snapshot, undo or redo the apply, and replay recorded input from a checkpoint.
---

A workspace volume is a **private copy** of a host directory: the guest reads
and writes its own ext4 image, and nothing it does reaches your tree by
itself. That boundary is what makes an agent safe to point at real code — and
this guide is the one reviewed path back across it.

Everything here is journaled and reversible. An apply snapshots every host
byte it will replace before touching anything, the snapshot's Merkle root
lands in the audit chain, and undo/redo walk the same journal. The agent
never writes the host tree; you do, after reading the diff.

## Attach a workspace

```sh
mvmctl machine volume mount coding-agent --volume work --host ~/src/app --guest /work --rw
```

The first mount snapshots `~/src/app` into a cached image; the guest gets the
copy. Restarts refresh the copy from the source only while the source
changed and no apply has made the copy the authoritative side — see
[Persistent Workspaces](/guides/persistent-workspaces/) for the lifecycle.

## See what the agent changed

```sh
mvmctl machine diff coding-agent
mvmctl machine diff coding-agent --stat
```

`diff` compares the guest's live image with the snapshot it began as —
content, not just paths: unified output by default, `--side-by-side` for a
review layout, `--json` for tooling. Nothing is written; this is the read
half of the review.

## Apply, reviewed

```sh
mvmctl machine apply coding-agent --dry-run
mvmctl machine apply coding-agent
```

`--dry-run` lists exactly what would be written or deleted and stops.
Without it, the apply prints the change count and asks:

```text
Apply to working tree? [y/N]
```

Only a `y` proceeds. Piped or scripted runs pass `--yes` explicitly — an
apply is never a silent non-interactive write:

```sh
mvmctl machine apply coding-agent --yes
```

Before anything is written, every host file the apply would overwrite or
delete is copied into a content-addressed snapshot under the machine's state
dir, the manifest records a Merkle root over the plan, and the journal gains
a begin entry. Writes then land through temp files and atomic renames. A
crash mid-apply recovers on the next command: begun-without-finished rolls
back from the snapshot; finished-without-recorded completes the entry.

Two gates shape the plan:

- **Protected paths.** The shipped CI/build/test classes — `.github/workflows/**`,
  git hooks, signing material — refuse the whole apply if the guest changed
  any of them, naming every match. Add operator patterns with
  `--protected-path`; there is no silent off switch.
- **Exclusions.** Paths the apply must never touch, persisted with the
  snapshot so a later undo or restore never consults a rebuilt default:

```sh
mvmctl machine apply coding-agent --exclude '.git/**' --exclude 'target/**'
```

## Undo and redo

```sh
mvmctl machine undo coding-agent
mvmctl machine redo coding-agent
```

`undo` restores the pre-apply bytes from the snapshot — including files the
apply deleted. `redo` re-applies, but only while the undo is still the newest
entry: once anything else has been applied on top, redo says so instead of
clobbering it. Each undo and redo is itself a journaled apply, so it carries
the same crash guarantees and lands in the same audit history.

## Replay recorded input

Every `machine exec` records its argv in a per-machine journal — the input,
never the output. From a checkpoint, the whole session can be re-run against
byte-identical state:

```sh
mvmctl machine save coding-agent --tag before-refactor
mvmctl machine replay <checkpoint-id> --dry-run
mvmctl machine replay <checkpoint-id>
```

Replay fork-boots the checkpoint through the ordinary admission path — the
same machinery as [Rewind and replay a sandbox](/guides/lineage-recovery/) —
so the restored machine is a fresh sibling, not a mutation of the original.
It then re-executes each journaled entry recorded at or after the checkpoint
and takes a checkpoint after every step: each replayed step is a first-class
restore point you can diff or fork. Replay never touches the original
machine or any host directory.

## What this does not do

Applying changes home does not retract effects that already left the guest —
an API call, a pushed commit, a sent message. Compensate those separately,
the same way a sandbox [restore](/guides/lineage-recovery/) cannot un-send
what already went out.
