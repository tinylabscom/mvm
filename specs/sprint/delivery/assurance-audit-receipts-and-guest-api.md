# Assurance sessions: audit/receipt emission and the workload-facing API

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md` (W4, W6/W7)

## What landed

The layer that shipped first had a hole worth naming: `MvmBinding` required an
audit and a receipt reference to build, and nothing produced one. The builder
enforced a citation that no code could satisfy outside a test. These two
workstreams close that, and give the guest something to call.

**Emission is fail-closed, and that is the whole point.** The existing emit
path treats receipts as a derived cache and logs-and-swallows their failures,
which is right when nothing cites them. It is wrong for evidence a later claim
rests on: a citation to a receipt that was never written reads as proof.
`emit_entry_for_evidence` therefore errors where the ordinary path warns, and
the caller says whether a receipt is `Required` or `Omitted` — a probe is
fine-grained and rides the audit chain alone, a trial completion is the unit a
campaign publishes and carries a receipt.

**A probe that cannot be recorded does not happen.** The handler decides,
records, then commits: the egress decision is a pure policy query with no side
effect, so a failed record refuses the probe outright and leaves
`attempted_effect` false. A session with no emitter attached probes nothing at
all. Both paths answer `AuditUnavailable`, which is deliberate — "recording is
off" and "recording failed" should not be distinguishable to a workload, and
neither may yield a boundary attempt with no record of it.

**Citations resolve.** An audit reference is `mvm:audit:<hex>` over the exact
bytes `seal` signs, and the envelope stores those same bytes in `canonical`, so
`resolve_audit_ref` finds the line back on disk. A test emits, then resolves,
then checks the reference does *not* resolve against a different chain. A
reference that resolves to nothing is the same failure mode the
`check-declared-backing` gate exists to prevent, one layer down.

**Records name the label, never the destination.** A probe entry carries the
declared synthetic label, the closed decision token, and identifiers. It does
not carry the host or port the label resolves to. The test for this asserts
over the decoded labels rather than the raw file — the file also holds a base64
copy of the same entry, and grepping that for a digit sequence would pass or
fail for reasons unrelated to what crossed.

**The guest API offers nothing to misuse.** `AssuranceCampaign` exposes
`probe_egress(label, idempotency_key)` and no method taking a command, path,
host, port, or socket. That is a property of the type, not a convention. Local
guards fire before any round-trip, so a mistake is an error rather than a
refusal after a round-trip; the host re-derives every gate regardless, because
this client runs in the untrusted guest and is advisory.

## A direction problem worth recording

`AiSessionInput` is serialize-only on purpose, so the host can never parse
admission facts out of provider bytes. The guest has the opposite need — it
only ever receives an envelope — so it reads a separate `DeliveredSession`.
Two types, two directions, and a test asserting they describe the same
document, because nothing else would catch them drifting apart.

## What is still not true

No certifying campaign can run. `open_session` is still called only by tests,
so the probe surface has no production caller yet (W7b); observer, cleanup and
attestation evidence have no producer (W5), so a live trial still evaluates
`INCONCLUSIVE` by design; and the framed-stdio provider the counterparty spawns
does not exist in either repository (W8).
