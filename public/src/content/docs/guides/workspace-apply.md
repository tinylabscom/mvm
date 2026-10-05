---
title: Bring agent changes home
description: Review what an agent changed in its workspace, apply it back to the host directory through a journaled snapshot, undo or redo the apply, and replay recorded input from a checkpoint.
---

A workspace volume is a **private copy** of a host directory: the guest reads
and writes its own ext4 image, and nothing it does reaches your tree by
itself. That boundary is what makes an agent safe to point at real code — and
this guide is the one reviewed path back across it.

`mvmctl machine --help` lists `apply`, `undo`, and `redo`. These commands
operate on named machines with workspace volumes, not transient `run --mount`
copies. A foreground run on such a machine offers the same apply when it ends
— see [Apply when a run ends](#apply-when-a-run-ends).

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

The question is asked on the controlling terminal (`/dev/tty`), not on
standard input. Only `y` or `yes` proceeds; an empty line, anything else, or
no answer within ten minutes applies nothing. Without a terminal, pass `--yes`
explicitly — an apply is never a silent non-interactive write:

```sh
mvmctl machine apply coding-agent --yes
```

Before anything is written, every host file the apply would overwrite or
delete is copied into a content-addressed snapshot under the machine's state
dir, the manifest records a Merkle root over the plan, and the journal gains
a begin entry. Before any host write, a separate root over the captured host
pre-images, including whether each path was absent, a file, or a symlink, is
recorded as a chain-signed `workspace.snapshot` entry, linked
to the later `workspace.applied` entry by apply ID and manifest root. Writes
then land through temp files and atomic renames. A
crash mid-apply recovers on the next command: begun-without-finished rolls
back from the snapshot; finished-without-recorded completes the entry.
The apply refuses a host symlink whose target cannot be represented as UTF-8,
because it could not restore that target safely after a crash.
If the signed `workspace.applied` entry cannot be appended during the command,
`mvmctl` restores the staged pre-images and cancels that commit. If restoration
also fails, the command reports that the working tree may have changed and
requires inspection before another apply. A durable marker also covers a
process crash after the host commit but before the signed append: the next
`machine apply`, `machine undo`, or `machine redo` command verifies the signed
audit chain, keeps a matching signed commit, or restores and cancels an
unsigned one. If the chain is unavailable, recovery restores host pre-images
and retains an uncertainty marker rather than treating an unverified entry
as proof.
If an append reports an error after writing a valid signed entry, verification
keeps the audited commit. If verification itself is unavailable, the command
restores host pre-images and refuses another apply until recovery can determine
the signed result. Recovery retries an interrupted restore before reading the
chain. If the original apply entry did land, it records a chain-signed
`workspace.audit_rollback` compensation before clearing the marker; otherwise
it clears the marker without claiming a mutation occurred.

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

## Apply when a run ends

Run the agent's entrypoint in the foreground on the machine that holds the
workspace:

```sh
mvmctl machine run --entrypoint --attach --name coding-agent
```

When the entrypoint exits, with any status, `mvmctl` offers each of the
machine's workspaces back through the same apply `machine apply` uses:

- **On a terminal**, it shows the diff and asks `Apply to working tree? [y/N]`.
  The question is asked on the controlling terminal (`/dev/tty`), never on the
  run's standard input, which belongs to the workload. Keys typed before the
  question appears, or during a short arming window after it does, are
  discarded, so type-ahead cannot answer it. Only `y` or `yes` applies; an empty
  line, anything else, or no answer within ten minutes applies nothing. File
  content in the diff is shown with terminal control sequences removed, since
  the guest wrote it.
- **With `--apply`**, it applies without asking:

  ```sh
  mvmctl machine run --entrypoint --attach --name coding-agent --apply
  ```

- **With no terminal and no `--apply`, or with `--json`**, nothing is applied.
  The run prints the exact command that applies the changes later,
  `mvmctl machine apply coding-agent`, with `--volume` added when the machine
  has more than one workspace. `--apply` cannot be combined with `--json`.

This is not a second way to write your tree. The prompt and `--apply` take the
same pre-apply snapshot, write the same journal, pass the same protected-path
gate, and record the same signed `workspace.snapshot` and `workspace.applied`
entries, with the same restore when the signed entry cannot be shown written.
A plan the gate refuses applies nothing; with `--apply` the run then fails.
Otherwise the run exits with the entrypoint's status, unless the apply itself
fails.

Only a run on an existing named machine has a workspace to offer. A fresh
boot, including a transient `run --mount`, discards its image when it exits.

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
