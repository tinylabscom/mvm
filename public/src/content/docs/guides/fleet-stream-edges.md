---
title: Stream edges between workloads
description: How one workload's output feeds another's stdin, what redaction does to data in flight, and what happens when a consumer falls behind.
---

A **stream edge** connects one workload's output to another's stdin, so a fleet
can run a workflow. `mvm` provides the mechanism; `mvmd` declares the edges and
resolves them. A single-VM `mvmctl` run has no edges.

:::caution[Mechanism only, today]
The pieces below are on `main` and tested, but nothing in `mvm` declares an
edge — `mvmd` is the caller. Until it does, this page describes a surface you
can build against rather than a feature you can drive from the CLI.
:::

## A consumer names a binding, never a VM

An edge appears on the **consumer's** signed plan, and it names a *binding*:

```json
{
  "stream_edges": [
    { "binding": "upstream", "redaction": "redacted", "backpressure": "lossy" }
  ]
}
```

The host resolves `upstream` to a producer. The guest never learns which
workload that is, or that there was one at all.

That indirection is the whole point. The two workloads never share a
transport, never learn each other's identity, and neither gains a network
interface — bytes cross inside the host, between two independent vsock
channels, at the same place that was already the single authorization point.
An edge adds no new path out of a guest.

A consumer naming a binding it was not granted is refused before boot, and the
refusal reaches the chain-signed audit log. "Not granted" and "no such source"
are deliberately the same answer, so a workload cannot map the fleet by trying
names.

## Redaction in flight

`redaction` defaults to `redacted`: the consumer sees what every other consumer
sees, masked by the one seam all output crosses.

`raw` exists because always-masking corrupts a pipeline whose second stage
needs what the first computed — a masked value is not a value. It requires an
operator acknowledgement **in addition to** the plan signature:

```sh
MVM_ACK_RAW_STREAM_EDGE=1
```

A plan is signed on behalf of whoever launched the workload. Letting a plan
alone opt out would let a careless or compromised workload definition export
raw PII into another workload with no human involved, and between two workloads
those are different trust domains. Never set it in CI.

(Design notes describe this as "shaped after `MVM_ACK_UNRESTRICTED_NETWORK`".
That variable is aspirational: it is read nowhere in the workspace, so there is
no unrestricted-egress acknowledgement to be modelled on yet.)

:::note[`raw` is not servable yet]
Redaction runs *before* hashing, so a record that reaches a reader has already
crossed the seam and no unmasked copy survives. A `raw` edge is therefore
refused at connect time rather than handed masked bytes under a fidelity
label — being told you have the value while computing on `XXX` is worse than
being told no. Serving it needs a tap on the pre-seam side, which does not
exist.
:::

## One input slot, one writer

A workload has a single stdin, so it can be fed by **one** edge.

Two edges into one consumer is fan-in, and it is rejected when the topology is
validated. Two producers interleaving into one stdin produce corrupted records,
and stdin carries no framing to recover them — there is no way to tell whose
half-line you are holding.

A workflow that needs fan-in declares a **merge stage**: a workload that reads
several inputs and emits one stream. That is itself a workload the fleet can
express, so nothing is lost except the illusion that stdin could carry it.

Two consequences worth knowing before you hit them:

- An edge consumes the input slot, so a workload fed by an edge **cannot also
  take operator stdin**. That is an admission error you can read, not a runtime
  race for the lease.
- **Iteration is not expressible.** A workflow needing a loop re-invokes the
  graph from outside, which keeps termination and provenance intact.

## The topology is a DAG

Cycles are rejected before anything boots.

A cycle breaks EOF propagation: nothing downstream of itself ever sees its
producer close, so it never closes either. With lossy eviction it does not even
deadlock into something obvious — it degrades into a silently churning loop
that looks like work. And every edge hash-chains, so a cycle leaves no order in
which to ask what a workload saw.

Because fan-in is refused first, every consumer has at most one inbound edge —
which means a cycle can only ever be an isolated loop. Entering one from
outside gives the entry node two writers, and is reported as fan-in.

## When a consumer falls behind

**The producer never stalls.** A workload whose behaviour changes because
someone is reading it slowly is a workload you cannot reason about, so that is
not allowed to happen. The reader's queue is bounded and evicts on its own; the
mode decides how the edge *reacts* to that loss.

| Mode | On loss |
| --- | --- |
| `lossy` (default) | Marks the gap and carries on. The consumer's operator can see the stream has a hole. |
| `reliable` | Fails the edge, loudly. |

`reliable` does not mean "buffers more". A mode with that name must never
quietly drop a record, so when it cannot hold one it stops being an edge rather
than becoming a lossy one under a reassuring name. Recovery is to re-run the
workflow.

## A broken edge fails the workflow

An edge does not silently reconnect across a consumer restart.

Reconnection is not free. The gate builds a fresh secret scanner per session,
so a secret split across the restart boundary would be scanned by two scanners
with neither seeing the whole — the exact hole this project has refused to open
elsewhere. Surviving a restart also means buffering on the producer for an
unbounded interval, which breaks the bounded-memory guarantee that keeps the
producer unstalled in the first place.

Workflows already have a supervisor; re-running the graph is the right recovery
at the right layer. The edge records its last delivered sequence in the
chain-signed log, so a re-run is something you reason about rather than guess
at.

## What an edge does not give you

- **Not a channel.** Bytes flow one way, into stdin. There is no reply path.
- **Not ordered across sources.** One edge is one producer; ordering between
  two different producers is not something the transport can offer.
- **Not exactly-once.** `lossy` marks gaps and `reliable` fails; neither
  replays.
- **Not a claim.** See below.

## Security posture

An edge is a different authorization shape from a per-plan grant, and it is
**not** covered by a numbered security claim today.

What holds by construction, and is tested:

- A guest cannot address another guest. It names a binding; the host resolves
  it.
- Neither workload gains a network interface, and no workload path grows a tap
  or a gateway. Both vsock gates cover this.
- A raw edge is refused rather than served masked bytes.
- Duplicate bindings, fan-in and cycles are refused before boot.
- Defaults are the safe ones, and a plan written before edges existed cannot
  acquire a raw edge by omission.

What is **not** claimed:

- That the refusals fire in production. They have no caller in `mvm`; `mvmd`
  is expected to call them, and until it does they are declared dormant in
  `xtask/dormant-controls.toml` so CI notices if that changes.
- Anything about a consumer's handling of what it receives. An edge delivers
  bytes to stdin; what the workload does with them is the workload's business.

Claim 17 (the workload input plane) stays at `Preview`. An edge would be its
second production caller, and reassessing that is deferred until one exists —
promoting a claim on the strength of a caller that has not been written is the
drift this project's gates exist to prevent.

## See also

- [Workload output streaming](/guides/workload-output-streaming/)
- [Workload input](/guides/workload-input/)
