---
title: Workload input
description: The host-to-guest stdin channel — how to stream into a workload with `machine run --entrypoint --stdin -`, the grant it needs in the signed plan, the single-writer lease, the secret scan, explicit EOF, and why a sealed production run refuses a shell entrypoint.
---

`mvm` can carry bytes from the host into a running workload's stdin. This page
is the contract that channel enforces, and how to reach it.

```sh
# Stream this terminal's stdin into the workload as you type or pipe it.
# Your EOF (Ctrl-D, or the end of the pipe) closes the workload's stdin.
generate-events | mvmctl machine run --entrypoint --manifest ./app --stdin -
```

`--stdin -` is what asks for the stream. Anything else keeps the behaviour this
command has always had: a piped stdin, or `--stdin <PATH>`, is read to the end
and sent as one complete payload with the call, and the workload's stdin closes
behind it. The request matters because streaming is what puts the input grant on
the signed plan — see below — and a grant nobody asked for is a grant nobody
reviewed.

Two shapes are deliberately not covered:

- `--attach` dispatches into a machine some earlier invocation admitted, so this
  process holds no admitted plan to write under. `--stdin -` there is refused
  with that explanation rather than a refusal from three layers down.
- `mvmctl session attach --stdin` is a one-shot payload for the same reason.

Output goes the other way and *does* work today — see
[Workload output streaming](/guides/workload-output-streaming/).

## What the channel is, and what it deliberately is not

It carries bytes to the stdin of an entrypoint that is already running. It
cannot select a program, change its argv or its environment, or spawn anything.
The entrypoint is fixed when the plan is admitted, and the channel writes into a
pipe, not into a launcher.

That boundary is the whole reason the channel is allowed to exist at all. See
[What this costs claim 15](#what-this-costs-claim-15).

## The grant is in the signed plan

Input is default-deny. A write is refused unless the workload's signed
`ExecutionPlan` lists `host.stream.v1` among its services:

| | |
| --- | --- |
| Without the grant | Every write is refused (`not-granted`) before a byte moves. |
| With the grant | A writer may claim the stream. |

The grant is signed with the rest of the plan, so it is fixed at admission. You
cannot add it to a machine that is already running, and a plan carrying it is a
plan somebody signed.

Both outcomes are recorded in the chain-signed audit log —
`stream.input_granted` and `stream.input_refused`, carrying the VM name, the
holder, and a reason word. Neither entry carries a payload byte.

Granting is **fail-closed on auditability**: if the grant cannot be written to
the chain, the lease is released and the open is refused (`unauditable`). The
channel declines to operate rather than operate unrecorded.

## One writer at a time

A per-VM lease arbitrates writers, so two consumers cannot interleave into one
byte stream:

- The default TTL is 30 seconds. Every write renews it; an idle writer can hold
  the stream open with an explicit refresh.
- A second writer arriving while the lease is live is refused (`lease-held`) and
  told who holds it.
- A writer that lets its lease lapse is refused (`lease-expired`) and stays
  refused. It never silently reacquires a stream a successor may have taken
  over.
- When a successor does take over, whatever the displaced writer had not
  delivered is zeroized and counted, not injected into the successor's stream.

Frames carry a sequence number. A frame whose sequence does not advance is
refused as out-of-order, and a frame redelivered because its answer was lost is
not written into the workload twice.

Back-pressure never reaches the guest as a stall. Up to 1 MiB of undelivered
input is queued per workload; past that a write is refused as `queue-full` and
can be offered again. A workload that has stopped reading its stdin produces a
`workload-gone` refusal rather than a hung host.

## The secret scan

Secrets known to the host are registered against the VM, and the gate scans the
byte stream — not each frame in isolation — before anything is delivered:

- A tail that is still a live *prefix* of a known secret is **withheld**, not
  shipped and then regretted. It is released at close, before the workload sees
  EOF, if the rest of the stream turns out not to complete the match.
- A completed match refuses the session outright, zeroizes the buffer, and
  audits the refusal with the secret's category — never its value.

Splitting a secret across frames therefore does not reassemble it inside the
workload, down to one byte per frame.

### What the scan is worth

Two things you must not read into it:

**The known-secret set is empty on every real VM.** The only way a secret is
registered has no caller outside tests. The scanner is correct and it currently
has nothing to match against.

**It is a backstop, not a defence.** Base64, hex, URL-escaping, any derivation
(a hash, a signature, a substring), an unregistered secret, and a split that
straddles the scan window all pass straight through. It catches a confused
host-side caller. It does not catch a determined one.

The real guarantee is upstream and structural: the host has no reason to send a
secret into a guest at all, because credentials are substituted on the
host-owned egress path rather than handed over. See
[Secrets and credentials](/guides/secrets-and-credentials/).

## Explicit EOF

A writer ends the stream explicitly. The close names the last sequence it covers
and carries any trailing bytes the scan was still holding back. The agent
delivers that tail and then closes the descriptor — the fd close *is* the EOF,
with no sentinel byte the workload could confuse with data.

A close naming a sequence earlier than what was already delivered is refused,
and the stream stays open rather than truncating on a stale message. Stopping
the workload ends its input stream too, so a writer never holds a lease on a VM
that is gone.

## `--prod` refuses the grant for a shell entrypoint

Under a sealed production posture, a plan that carries *both* the input grant
and a shell-shaped entrypoint is refused at admission, before any hashing,
signing, or boot work:

```
refusing the workload input grant: the resolved entrypoint ["/bin/sh"] is
shell-shaped, and under a sealed production posture streaming stdin to a shell
is interactive access wearing a different hat
```

An entrypoint counts as shell-shaped if its program basename is a known shell,
if it is a shell reached through `env` or a busybox applet, if `-c` appears
anywhere in its arguments, or if its shebang names a shell.

### The refusal is a heuristic. Treat it as one.

A wrapper script that `exec`s a shell defeats it. So does a program that spawns
one, and an interpreter installed under a name the list has never heard of.
There is no test over argv that separates *a program that reads stdin* from *a
program that will interpret stdin as commands*, because that is a property of
the program, not of its name.

Moving input to a side descriptor would not help either: a shell can read fd 4
and pipe it into itself. There is no fd assignment that makes a shell stop being
a shell.

So do not read the refusal as the control. **The control is the grant in the
signed plan.** A workload that was never granted input has no channel at all,
and that decision is structural — it is made against a signed document, before
any byte moves, by code that does not have to guess what the entrypoint will do
with what it reads. The shell refusal raises the cost of laundering interactive
access past claim 15 through a plan that otherwise looks ordinary. It does not
close the path, and it was never going to.

### Where the entrypoint comes from

The host cannot read inside a materialized rootfs — it is an ext4 blob, and
mounting a guest filesystem on the host is a privilege `mvm` does not take. The
argv is therefore recorded at build time in the `mvm-meta.json` sidecar written
beside the rootfs, by both the Nix (`mkGuest`) and OCI image paths, and read
back from there at admission.

An image whose sidecar records **no** argv — built before the build path
recorded one — is *unresolved*, and unresolved is refused, not admitted:

```
refusing the workload input grant: this launch cannot say what the workload
runs (the image sidecar in … records no entrypoint argv), so it cannot rule out
a shell
```

That is deliberate. An entrypoint nobody resolved is one nobody checked, and
admitting on it is exactly what turns the refusal above into a control that
reports present and never fires. Rebuild the image to get a sidecar that carries
its argv.

## What this costs claim 15

Claim 15 — no interactive access to a sealed production microVM — used to hold
by *absence*. A sealed production microVM had no host-to-guest byte path at all,
so "nobody can drive it" needed no policy to be true.

This channel builds one. What survives is narrower, and worth stating plainly:

- Unchanged: no shell, no `do_exec`, and no PTY on a sealed image.
- Unchanged in substance: input bytes cannot select a program, alter argv or the
  environment, or spawn anything, because the entrypoint is fixed at admission
  and the channel writes to a pipe.
- Weaker: refusing input without a grant is now a *policy* decision made by host
  code, rather than a consequence of there being nothing to refuse.

That trade is recorded in
[ADR-035](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/035-workload-stream-plane.md),
and the claim rows and their limits live in
[ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md).
The input channel is tracked there as claim 17 at status `Preview`. It stays a
preview even though the channel now ships: the grant, the lease, the EOF and the
shell refusal all have production callers, but the secret scan still has none,
and a claim is worth what its weakest enforced leg is worth.

## Limits, all of them true today

1. **One surface, one lifecycle.** `machine run --entrypoint --stdin -` is the
   only way in. It works because that one invocation admits the plan, boots the
   VM and dispatches the call, so the plan authorizing the writes is in the
   hands of the process making them. `--attach`, `session attach`, and any
   other process reaching a machine it did not boot cannot stream.
2. **The secret scan is inert.** No production code registers a secret, so the
   known-secret set is empty on every real VM. The scanner is correct and has
   nothing to match against, so the refusal it exists to produce has never
   fired outside tests.
3. **The scan is a backstop.** Encoding, derivation, and a window-straddling
   split defeat it. This one is permanent; it is a property of scanning, not a
   gap to close.
4. **The shell refusal is a heuristic over argv**, and the argv comes from the
   image's own build-time record. A wrapper that `exec`s a shell still defeats
   it; see [above](#the-refusal-is-a-heuristic-treat-it-as-one).

Limits 2 and 4 are what keep claim 17 at `Preview`: an enforcement path with no
production caller (the scan) and a heuristic control are not the same thing as a
proven guarantee. Limits 1 and 3 stay whatever happens to the other two.

## See also

- [Workload output streaming](/guides/workload-output-streaming/) — the other
  half of the plane, which is on by default for every workload.
- [Audit and receipts](/guides/audit-and-receipts/) — the chain the grant and
  every refusal are written into.
- [Secrets and credentials](/guides/secrets-and-credentials/) — host-side
  substitution, which is why the host has no reason to write a secret inward.
