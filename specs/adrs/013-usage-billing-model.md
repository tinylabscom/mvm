# ADR-013: Resource metering is audit-grade, not a billing system

## Status

Accepted for the metering data model and audit-chain wiring. The
sampling producer — the code that actually reads instance resource
consumption and calls the aggregator — is not built yet.

## Context

mvm/mvmd is multi-tenant; a downstream operator needs to attribute
resource consumption per tenant for cost or capacity planning. Any data
used to answer "what did this tenant consume" must be tamper-evident: a
host operator must not be able to retroactively edit or delete a
resource-consumption record, matching the chain-signed audit posture the
rest of the security model uses.

Pricing, tiers, and invoicing are commercial policy, not runtime
architecture. Folding that policy into the runtime library would couple
a local-first runtime crate to one specific commercial model.

## Decision

`mvm-core::metering` defines the resource-usage data shapes and their
aggregation, not a sampling daemon or an exporter:

- `MeteringSample` — one instance, one tick: CPU nanoseconds, memory
  byte-seconds, and a cold/hot storage byte-seconds split aligned to the
  dm-thin pool layout.
- `MeteringBucket` — a per-minute aggregation of samples for one
  `(tenant_id, instance_id, tag-set)` triple, produced by
  `MeteringBucket::aggregate`.

Every bucket chains into the tamper-evident host audit log via
`LocalAuditKind::MeteringEpoch` — the same chain-signed mechanism every
other audited state transition uses. A host operator cannot retroactively
edit or delete a metering bucket without breaking the chain.

Buckets also serialize to JSONL (`MeteringBucket::to_jsonl`, one bucket
per line) for a per-tenant rollup file, and to a Prometheus exposition
format (`to_prometheus`) for ops dashboards — two read paths over the
same audited source of truth.

Pricing, tiers, invoicing, and any payment-processor integration are out
of scope for mvm's runtime. This module answers "how much did this
instance consume," never "what does that cost." A downstream billing
system, if one exists, prices these raw resource-time values; mvm-core
carries no tier table and no currency type.

## Consequences

One canonical, tamper-evident resource-usage record per tenant, instance,
and tag-set — a downstream pricing system can consume it without mvm's
runtime ever holding commercial logic.

The sampling producer does not exist yet: the shapes, the aggregation
function, and the audit-chain wiring are proven end-to-end by an
integration test, but nothing in the runtime calls
`MeteringBucket::aggregate` in production today. Standing this up is
follow-on work, not part of this decision.

This ADR does not define billing tiers, usage caps, or their enforcement
— those are commercial and quota decisions that, if built, belong to a
fleet-orchestration layer outside this crate, not to mvm-core's metering
shapes.
