# ADR-047 — The agent memory plane

Backing: preview
Validation: none

**Status:** Proposed
**Date:** 2026-08-18
**Related:** ADR-001 (claims 8, 10, 11, 12, 13, 15; Preview claims 17, 18),
ADR-014, ADR-020 (host services broker), ADR-023 (secrets subsystem — egress
substitution), ADR-035 (workload stream plane), ADR-045 (sections 8, 18, 19),
ADR-046 (sections 7, 13, 14).
**Depends on:** the durable agent sessions design,
`specs/plans/2026-08-18-durable-agent-sessions.md`, which is unmerged at the
time of writing — it exists on `docs/durable-agent-sessions` and has no open
pull request. Every reference to it below is a forward reference to a design
that may still change, not to a landed document.
**Implemented by:** `specs/plans/2026-08-18-agent-tool-and-memory-planes.md`.

## Context

Two different things get called an agent's memory, and conflating them is how
the authority story leaks.

The first is **substrate**: machine state the host captures and restores. The
durable agent sessions design owns it — a hibernation record, a
content-addressed parent checkpoint, a journal cursor, a signed approval
ledger head — and it resumes a task across disposable sandboxes. Its D6 is
explicit that a restored image resumes the agent's reasoning state while its
communication and authority state is torn down and rebuilt.

The second is **content**: what an agent deliberately writes down and reads
back. Notes, findings, learned constraints, a record of what it already tried
and what failed. Long-horizon work is not workable without it, and nothing in
the current documents defines it.

The two have different properties. Substrate is host-captured, opaque, and
verified by digest. Content is guest-authored, semantic, read back into a
context window and acted upon, and crosses epoch boundaries by design —
precisely what D6 tears down for the memory image.

In the absence of a definition, an agent will use whatever writable surface it
can reach: a mounted volume, an artifact, a self-addressed mailbox message, a
file in its own rootfs overlay. Each puts unbounded, unattributed,
guest-authored bytes across an epoch boundary with no record of what crossed.

## Threat model

What memory uniquely enables, beyond what an ordinary workload already can:

1. **Cross-epoch authority laundering.** Epoch N writes; epoch N+1 reads. The
   agent in N+1 is admitted under a freshly synthesized plan whose grants may
   be narrower. If memory carries capability state, handles, or credentials,
   that narrowing is cosmetic.

2. **Stored injection.** A poisoned tool result written in epoch N is read
   back as context in epoch N+1, after its untrusted provenance has been
   forgotten. This is the most likely failure in practice and the cheapest one
   to get wrong: it converts a bounded, in-epoch injection (ADR-045 section
   19) into a durable one.

3. **Secret exfiltration by recall.** Egress substitution keeps raw
   credentials out of the guest (claim 13), but a guest observing a
   substituted response can write a derived value into memory and read it back
   after the destination binding has lapsed.

4. **Unbounded accumulation.** Memory is the one durable, agent-controlled,
   per-task growth surface, and an agent under injection has an obvious
   denial-of-service in it.

5. **Attribution loss.** A remembered finding that later changes an operator
   decision needs to be traceable to the admission that produced it.

## Decision

### 1. Memory is a broker service, not a writable mount

Memory is `host.memory.v1`, plan-bound like every other service under ADR-045
section 18. Writes and reads are typed RPCs. There is no writable filesystem
surface and no shared volume.

A mount is refused because a mount keeps no record of what was remembered.
Byte-level diffs against an opaque tree are not attribution, and every
property below needs the write to be an observable, typed event with a
host-side decision point.

### 2. Memory is keyed by task, not by sandbox

The store is keyed by session ID — the durable unit of the durable agent
sessions design — and never by `VmId`, boot ID, or checkpoint digest. A
sandbox is a bounded lease; the task is the thing that remembers.

### 3. Memory carries facts; it never carries authority

This is the load-bearing decision.

A resumed sandbox derives every grant from its freshly synthesized
`ExecutionPlan` and its signed constraint snapshot. Nothing in memory
contributes to that derivation. Mechanically:

- No memory record is an input to admission, binding, egress, or budget.
- The host never parses memory content for policy meaning.
- A record naming a capability is a string, not a request.

This is ADR-045 section 9's advisory-versus-signed split applied across time
instead of across the graph, and it matches what ADR-046 section 14 and
durable-sessions D6 already require of a restored image — extended to content
the guest authored on purpose.

### 4. Every record carries host-stamped provenance and a trust class

```text
record = {
    session_id,
    generation,
    admission_digest,      // which plan wrote it
    authored_at,           // host monotonic
    trust,                 // Observed | Derived
    content_digest,
    content,
}
```

`Observed` is content the agent took from a tool result or other external
input. `Derived` is the agent's own conclusion. Where a derivation reads
`Observed` input, the result is `Observed` — the class does not launder by
being restated.

Provenance is stamped by the host, not declared by the guest. A guest cannot
claim a record was authored by an earlier, more privileged epoch.

Recall returns the class alongside the content. An agent reading `Observed`
content is reading attacker-influenced data with the standing it had on
arrival. Forgetting provenance is exactly what upgrades a bounded injection
into a durable one, so the class travels with the bytes or the whole
distinction is decorative.

### 5. Writes are scanned, bounded, and audited

- A secret-fingerprint scan runs on the write path, reusing the input-gate
  mechanism of Preview claim 17 and inheriting its stated limits: a
  fingerprint match is a length-and-hash match, not an identity, and encoding,
  derivation, and splitting defeat it. It raises the cost of threat 3. It does
  not close it, and this ADR does not claim otherwise.
- Per-record and per-session ceilings are charged against the session budget
  of ADR-045 section 6, so memory competes for the same accounting as every
  other resource rather than growing beside it.
- Every write emits a chain-signed entry naming session, generation, admission
  digest, size, trust class, and content digest — never content bytes. This is
  the payload-freedom rule the stream plane already follows.

### 6. Memory is append-only; forgetting is host-side retention

A guest cannot delete or rewrite a record. Compaction — which agents genuinely
need, since unbounded history is unusable — is a host-run operation that emits
a *new* record naming the records it summarizes, with the originals retained
until retention expires.

A guest-driven rewrite would let an agent, or whatever is steering it, erase
the evidence of what it did. Retention rides the durable-sessions ladder
rather than growing a second one, and cryptographic erasure at session close
remains ADR-046 section 7, unchanged.

### 7. Recall is a bounded query, not a mount

A read is a query with a host-enforced result ceiling. Unbounded recall is a
denial of service against the agent's own context window as much as against
the host.

Recall is scoped to the session. Cross-session recall is a distinct
capability, off by default, because it is the mechanism by which one task's
memory becomes another's, and it needs its own grant and its own audit entry.

### 8. Memory does not resurrect a lapsed credential

A corollary of decisions 3 and 5, stated separately because it is the case
most likely to be built wrong.

The substitution endpoint mints destination-bound and time-bound credentials
(claim 13, ADR-023). Memory is not a place credentials may be kept, and a
record whose fingerprint matches a live secret is refused at write. A workload
needing a credential in epoch N+1 obtains it the way it did in epoch N: from
the endpoint, under the new plan. The guest never held the raw value in either
epoch, so there is nothing for it to have remembered.

## Alternatives rejected

### A writable volume or artifact the agent manages itself

Rejected. No attribution of what crossed the epoch boundary, no write-path
scan, no ceiling, and no way to distinguish a summary from a stored injection.
This is the default outcome if this ADR does not exist, which is the reason it
does.

### Fold memory into the checkpoint image

Rejected. It conflates substrate with content. A `Cold` resume — boot and
replay, per durable-sessions D5 — has no memory image at all, and D6
deliberately tears down restored state that memory is supposed to survive.

### Let the host read memory to make better decisions

Rejected. It makes guest-authored semantic content an input to authority,
which is decision 3 inverted. The value is real and the failure mode is
unbounded: a host that reads memory for policy meaning can be argued into a
decision by an agent that writes persuasively.

### A guest-side vector store with its own persistence

Rejected. That is the writable volume with extra steps and an embedding model
in front of it. Retrieval ranking is also a soft channel: what gets recalled
becomes steerable by whoever controls the corpus.

### Carry approvals in memory so a resumed agent knows what it may do

Rejected. An approval is a signed host-side record with its own ledger.
Duplicating it into memory creates a second answer to the same question, and
the second one is guest-held.

## Consequences

### Positive

- A long-horizon task keeps its findings without any epoch inheriting the
  previous epoch's authority.
- Stored injection stays visible: `Observed` content is still labelled
  `Observed` on the day it is recalled.
- Every remembered fact is attributable to the admission that produced it, so
  an operator decision informed by agent memory is reviewable after the fact.
- Memory competes in the existing budget rather than growing outside it.

### Negative

- Recall becomes a host round trip on the hot path of agent reasoning, where
  a local file read would have been immediate.
- Host-side compaction can only summarize structurally, because the host must
  understand nothing about content. Semantic compaction has to be a `Derived`
  write by the agent, costing a full write cycle.
- The fingerprint scan will both miss real secrets and refuse innocuous
  records; Preview claim 17's limits apply unchanged.
- Append-only plus retention means the store grows, and disk pressure is an
  operational cost that lands on the same host budget.
- An agent framework that expects a filesystem-backed memory needs an adapter.

### Neutral but important

- Nothing here makes remembered content true. Memory is bounded and
  attributable, not correct.
- Trust classes are coarse by design. Two classes that are always applied
  correctly are worth more than five that are applied by guess.
- Cross-session recall is where the useful and the dangerous both live; it is
  deferred rather than solved.

## Claim witnesses required before promotion

Promotion of any part of this ADR into ADR-001's numbered claims requires
witnesses that exist and are named in the ledger table:

- A memory write from a guest without a `host.memory.v1` binding is refused.
- A record written in epoch N contributes nothing to the grants admitted in
  epoch N+1.
- An `Observed` record recalled in a later epoch is still classified
  `Observed`.
- A record derived from `Observed` input is not classified `Derived`.
- A write whose content fingerprint-matches a live substituted secret is
  refused, and the refusal is audited.
- A chain-signed memory entry carries the binding and no content bytes.
- A guest cannot delete or rewrite a record; host compaction retains the
  originals.
- Recall is bounded by the host ceiling regardless of the query the guest
  sends.
- Cross-session recall without its capability is refused.
