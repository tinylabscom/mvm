---
title: Workload output streaming
description: Follow a microVM's stdout and stderr while it runs and after it exits, verify what you read, and understand what a truncation or gap notice means.
---

A production microVM has no shell. Its stdout and stderr are the only thing
you can read from the outside, so `mvm` captures them for every workload,
streams them while the workload runs, and keeps a verifiable copy you can read
after it exits.

Use this guide when you need to watch a running machine, read back a machine
that already finished, or decide how much to trust what you are shown.

## Follow a running machine

```sh
mvmctl machine logs my-machine -f
```

Output appears as the workload produces it. Nothing is held back until exit,
and nothing is dropped because the workload was chatty — see
[Retention](#retention-what-you-get-is-a-window) below.

Workload stdout is written to your stdout and workload stderr to your stderr,
so a pipeline filters the channel it asked for:

```sh
mvmctl machine logs my-machine -f | grep ERROR      # searches stdout only
mvmctl machine logs my-machine -f 2>/dev/null       # drops the workload's stderr
```

A **persistent** machine — one you keep alive with `--ttl` or `--healthcheck` —
attaches to the output itself once it boots, so you usually do not have to
follow up with `logs` at all. Starting one with `-d` (`--detach`) or asking for
JSON prints and returns instead of attaching:

```sh
mvmctl machine run --healthcheck 'curl -fsS localhost/health' \
  --name svc --image ghcr.io/example/service:1.4
```

This is specific to the persistent lifecycle. A plain foreground (transient)
`machine run` streams its own output directly as the workload runs, not
through this attach step; and passing a command after `--` on a persistent
machine opens an interactive console instead of attaching to its log stream.

Interrupting an attached `machine run` on a **persistent** machine detaches
from the output; the machine keeps running. That is the opposite of what
Ctrl-C does to a foreground transient run, so the command says which one you
are in before it blocks. To reattach later:

```sh
mvmctl machine logs svc -f
```

## Read a machine that already exited

The same command, without `-f`:

```sh
mvmctl machine logs my-machine
```

`mvm` resolves three sources, in order, and tells you which one answered:

| Source              | When                                                   | What you get                                                                       |
| ------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Live broker         | The machine is running and this host is capturing it.  | Channel-separated, hash-chained, live.                                             |
| Recorded transcript | The machine has ended, or you asked for history first. | Channel-separated, hash-chained, encrypted at rest, verified on read.              |
| Console log         | Neither of the above.                                  | One merged byte stream. Not redacted. No channels, no chain, no record boundaries. |

A console-only read says so on stderr, because it cannot do four things the
other two can:

```
note: microVM "my-machine" has no output capture; showing its console log,
which is not redacted, merges stdout and stderr, is not hash-chained, and has
no record boundaries — so -n is approximated in bytes
```

## The `--stream` filter

```sh
mvmctl machine logs my-machine --stream stderr
```

Valid values are `all` (the default), `stdout`, `stderr`, and `trace`.

`trace` is the structured channel: a workload can write tracing-shaped records
(level, target, fields) on file descriptor 3, and they are rendered with a
`[mvmctl-trace]` prefix the workload's own output cannot forge. stdout and
stderr are stored byte-for-byte and never parsed.

Two things to know about narrowing:

**Console-sourced output is recorded as stdout whichever fd wrote it.** The
console is one merged byte stream, so it carries no channel labels. That covers
boot output and anything written after the guest agent is gone. A `--stream
stdout` read therefore shows more than the entrypoint's stdout, and a `--stream
stderr` read shows only what the entrypoint call separated. `mvmctl` prints a
note saying so whenever you narrow.

**A console-only machine refuses a narrowed read** rather than guessing:

```
microVM `my-machine` has no output capture; its console log at
/…/console.log is one unlabelled stream merging stdout and stderr, so
a channel selection cannot be honoured — drop it to read the whole console
```

Refusing is deliberate. Filtering a merged stream would put the wrong bytes on
stdout, and warning-and-ignoring would mean `--stream stderr | wc -c` silently
counted the whole console.

## Verification

Every captured record carries the hash of the record before it, and the
recorded transcript seals to a Merkle root when the workload exits. `mvmctl
machine logs` verifies what it reads:

- A verification failure **exits nonzero**, the same as `mvmctl trust audit
verify`. What you were shown cannot be trusted.
- A pruned window is **not** a failure. It is retention doing its job, and it
  is reported as a gap notice.

Verification runs before filtering. `--stream` removes records from the middle
of a window, which breaks the chain by construction, so the whole delivered
batch is verified first and narrowed afterwards.

### What the chain proves

The chain proves **what you were shown**, not what the workload wrote.

Redaction runs once, at capture, before the record is hashed. That is what
keeps redaction to a single seam — every consumer sees the same masked
bytes — but it means the original pre-redaction bytes are never stored and
cannot be reconstructed or proven afterwards. If you need to argue about
whether a mask fired correctly, the transcript cannot settle it.

## Retention: what you get is a window

A capture is a ring. When it fills, the oldest records are dropped to make
room for the newest, and the drop is recorded.

Nothing about a chatty workload can silence it, slow it down, or kill it. The
old behaviour — a 1 MiB cap that terminated the workload — is gone. The cases
where a program produces the most output are usually the cases you most need
to see, so the newest bytes win and the loss is announced:

```
warning: recorded output is incomplete: 412 oldest record(s) (1048576 bytes)
were dropped to make room — what follows is a window, not the whole run
```

You may also see:

- `N record(s) (M bytes) never reached the store` — the host's disk refused
  them or the writer fell behind. The live stream was unaffected; the recording
  has holes.
- `the capture was sealed after the process recording it exited, so anything it
dropped on the way out is uncounted` — the counts above are a floor, not an
  exact figure. See [limit 2](#2-a-detached-machines-later-output-is-not-recorded).
- `microVM "…" has recorded output, but none of it is on the stderr channel` —
  the capture is healthy and your filter matched nothing. Not a missing
  capture.

## Retention mode

Recording is on by default for every workload. The opt-out lives in the
signed execution plan, as `stream_retention`:

- `persist` (the default) — keep an encrypted transcript, sealed at exit.
- `ephemeral` — fan out live and keep no chained, verifiable transcript.
  `mvmctl machine logs -f` works exactly as before while the workload runs.

**Nothing selects `ephemeral` today.** Every production caller builds the plan
with the default, so every real run is `persist`. The mode is admitted and
signed, and the field is read on the boot path, but there is no operator-facing
way to set it. Read this section as the contract the mode is bound by, not as
a switch you can throw. (The [input channel](/guides/workload-input/) used to
be described here as the same shape; it is not any more — it has an operator
surface.)

Were it selected, `ephemeral` would still not mean no bytes land on disk. The
backend writes its own `console.log` regardless — outside this plane and
unaffected by the retention mode — and once the run ends, `mvmctl machine
logs` falls back to reading that file, printing the run's output. That
fallback is redacted as it is read, so it is not a rawer copy, but the masking
is applied per 64 KiB read: a value split across a read boundary is not
caught. What `ephemeral` drops is the audited, hash-chained copy, not the output's
readability afterward.

There is deliberately **no CLI flag** for this. A flag would make a missing
transcript ambiguous: nobody reading the evidence later could tell a run that
was admitted not to keep one from a run whose recording was lost or deleted.
Because the mode is admitted, it is written into the `plan.admitted` entry of
the chain-signed audit log, so you can always answer _was this run recorded?_
even when you cannot answer _what did it print?_

```sh
mvmctl trust audit verify        # the chain that carries the retention mode
```

The audit chain records that a follower attached, which machine, and from
which sequence number. It never records payload bytes.

## Three limits

These are properties of the shipped implementation, not planned work.

### 1. The console fallback is not redacted

The recorded transcript is redacted. The console log is not — it is written by
the hypervisor before anything in the capture path sees it. When a recording
exists but does not cover the whole run, `mvmctl machine logs` shows the
recording and then splices the console behind it, so both appear in one read.

So: **every consumer of the capture sees masked output; a read that falls back
to the console does not.** If your workload prints material you rely on the
redaction seam to mask, do not treat console-sourced output as masked.

### 2. A detached machine's later output is not recorded

The process that starts a machine is the one that captures its console.
`machine run -d` returns as soon as the machine is up, and the capture ends
with it. The machine keeps running, and what it prints after that point reaches
no recorder.

The transcript that exists is real and verifies — it just covers the beginning
of the run rather than the run. Whichever later invocation stops the machine
seals it, rebuilt from a journal, and marks it as a reconstruction that cannot
account for whatever the departed process dropped.

You still see the missing output: `mvmctl machine logs` splices the console log
behind the recording. That part is unchained and unverifiable.

Closing this needs a resident host process that owns the capture for the
machine's whole life. `mvm` does not have one today.

### 3. A spliced read repeats its recorded prefix

The recorded half is indexed by sequence number and the console half by byte
offset in a file. There is no shared coordinate, so the console cannot be
resumed exactly where the recording stopped.

The splice overlaps rather than risking a hole, so the part the recording
already showed appears a second time. Duplicated, never lost. The notice says
so:

```
note: microVM "…" was recorded by a process that exited before the run did;
what the recording covers is shown first, then the console log covering the
rest — which is not redacted, merges stdout and stderr, is not hash-chained,
and repeats the part the recording already showed
```

## When there is no source at all

`mvmctl machine logs` exits nonzero when it cannot find any source to read from.
This happens when:

1. The machine was removed with `machine rm` — both its spec and state directory are deleted
2. The machine was never booted — it only has a spec (created with `machine create`) but no state directory exists
3. The console capture file was manually deleted

In these cases, the error message will indicate which state directory it looked in, and suggest that the machine may have been removed or never booted. To verify if a machine still exists, run:

```sh
mvmctl machine ls
```

If the machine is not listed, it was removed. If it shows with status "stopped" but `machine logs` fails, the state directory may be missing (perhaps due to a manual cleanup or an earlier failure).

If the state directory still exists but all three output sources are missing,
the error names the retained state and each missing source separately. This can
indicate an interrupted boot or manual capture cleanup; run `mvmctl machine
inspect <name>` to inspect the persisted machine before deciding whether to
boot it again or remove it.

## Reading output from code

The same stream is available to library and SDK callers through
`mvm_client::stream`, which resolves the same three sources and performs the
same verification. Enable the `tracing-bridge` feature to republish records
into an existing `tracing` subscriber; payloads travel as base64 so the exact
bytes survive the trip.

## See also

- [Workload input](/guides/workload-input/) — the other direction. Output is a
  property of running a workload; input is a capability that has to be granted
  in the signed plan, and you ask for it with
  `machine run --entrypoint --stdin -`.
- [Audit and receipts](/guides/audit-and-receipts/) — the chain that carries
  the retention mode and the subscribe events.
- [Observability and results](/guides/observability-and-results/) — how
  streamed output fits alongside receipts, metrics, and boot reports.
- [CLI commands](/reference/cli-commands/) — the full `machine logs` flag set.
