---
title: Workload input
description: The host-to-guest stdin channel — the grant it needs in the signed plan, the single-writer lease, the secret scan, explicit EOF, and why a sealed production run refuses a shell entrypoint. No command reaches it yet.
---

`mvm` can carry bytes from the host into a running workload's stdin. This page
is the contract that channel enforces.

**Nothing on this page is reachable from the CLI today.** No `mvmctl` verb opens
an input stream, `mvmctl invoke` always asks for input off, and no client
refreshes the lease. The mechanism is built, tested, and dormant; the operator
surface is not written. Read this as what the surface will be bound by, not as
something you can run.

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

It also **cannot fire today**: every production admission passes an empty
entrypoint argv, so the gate never sees an entrypoint to classify. Whoever makes
the grant live has to resolve a real entrypoint in the same change, or the
refusal ships as a label rather than as a control.

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
The input channel is tracked there as claim 17 at status `Preview` — a preview
precisely because most of its enforcement has no production caller.

## Limits, all of them true today

1. **No operator surface.** No CLI verb opens an input stream, `mvmctl invoke`
   always asks for input off, and nothing refreshes the lease from a client. The
   granted half runs in tests only.
2. **The secret scan is inert.** No production code registers a secret, so the
   known-secret set is empty on every real VM.
3. **The shell refusal cannot fire.** Every production admission passes an empty
   entrypoint argv.
4. **The scan is a backstop.** Encoding, derivation, and a window-straddling
   split defeat it. This one is permanent; it is a property of scanning, not a
   gap to close.

Limits 1 to 3 are what keep claim 17 at `Preview`. Limit 4 stays whatever
happens to the other three.

## See also

- [Workload output streaming](/guides/workload-output-streaming/) — the other
  half of the plane, which is on by default for every workload.
- [Audit and receipts](/guides/audit-and-receipts/) — the chain the grant and
  every refusal are written into.
- [Secrets and credentials](/guides/secrets-and-credentials/) — host-side
  substitution, which is why the host has no reason to write a secret inward.
