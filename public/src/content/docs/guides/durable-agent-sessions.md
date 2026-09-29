---
title: Durable agent sessions
description: Park an agent's durable record, re-admit it later, and understand the current boot, retention, and audit limits.
---

A durable agent session tracks an agent across sandbox lifetimes. Its record can
be parked and later resumed under a new signed `ExecutionPlan`. It is not the
same as `mvmctl machine session`, which keeps a machine resident across calls,
and it is not console reattachment. Use `mvmctl agent-session` for this durable
record lifecycle.

## Record and inspect a session

```sh
mvmctl agent-session open <id> --resume-point <sha256:digest> --member <sandbox-id>
mvmctl agent-session ls
mvmctl agent-session show <id> --json
```

`open` writes a generation-1 record; it does not boot a new sandbox. A session
with no resume point is legal to record, but a later `resume` refuses it. Name
a member sandbox when you have one: without a member's admitted plan, a later
park cannot be bound into the signed audit chain and warns about that gap.
`show` is the place to read the current generation, residency, journal cursor,
approval head, and retention deadline before making a transition.

## Park and extend retention

```sh
mvmctl agent-session park <id> --reason approval-wait --expected-generation <n>
mvmctl agent-session show <id>
mvmctl agent-session renew <id> --for 48h --expected-generation <n> --expected-deadline <unix-seconds>
```

Parking records why the agent stopped and its journal cursor; a reason also
selects a storage tier and default retention. Use `--retain-for` to set an
explicit deadline of at most 30 days. `--approval-head` can bind the park to
the current approval ledger, so resume can refuse a changed head. A park
without that head resumes unfenced; inspect `show` before trusting its grants.

The deadline is a **retention promise, not an automatic cleanup timer**. An
expired record is not reclaimed by a scheduler and can still resume. `renew`
extends a parked session's deadline but never shortens it; it refuses an
already-expired record. For an exact retry of `renew`, supply both the
generation and the deadline observed before the first attempt. See the
[CLI reference](/reference/cli-commands/#durable-agent-sessions) for reason
defaults and the complete retry rules.

## Re-admit, then decide whether to boot

```sh
mvmctl agent-session resume <id> \
  --backend <backend> --image <reference> --image-sha256 <hex> \
  --cpus <n> --mem-mib <n> --expected-generation <n>
```

The record does not store the image, kernel, backend, or sandbox size. Supply
these explicitly so the new admission is bound to the workload you intend.
`resume` verifies the resume point and approval head, admits a fresh plan, and
**does not boot a sandbox by default**. Add `--boot` only for a cold-tier
session when you intend to start one; a parked or resident tier that still
holds state refuses a cold boot rather than discarding it. If the admitted
plan pins a kernel digest, `--boot` also needs `--kernel <path>` so the file
can be checked against that digest.

`--expected-generation` fences a park or non-boot resume against another
transition. Repeating an identical transition after losing the first response
returns a replay marker without writing a second record or audit entry.
`resume --boot` is different: a retry that already applied is refused, not
reported as a successful boot, because the record alone cannot prove whether
the first boot finished. Inspect the named machine directly.

## Audit and secret boundaries

Park, renew, and resume attempt to append chain entries. A store transition
can succeed while that append fails; the command warns rather than falsely
reporting that the transition did not happen. If evidence is required,
**verify the audit chain separately** with `mvmctl trust audit verify` and
inspect the session's plan ID. The durable record is not a substitute for a
verified chain or a sealed run receipt.

Keep credentials in the host-side [secret binding and substitution
path](/guides/secrets-and-credentials/), not in session metadata, command
arguments, or a restored guest image. A new plan re-evaluates network and
service grants; parking does not carry old authority into a later sandbox.
