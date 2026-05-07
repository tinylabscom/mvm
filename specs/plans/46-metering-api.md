# Plan 46 — Metering API (auditing-grade, no pricing)

Status: **Proposed.**

## Background

mvmd is multi-tenant; downstream operators want to attribute resource
consumption per-tenant for cost or capacity-planning purposes. Today
`mvm/crates/mvm-supervisor/src/instance_sampler.rs` records per-VM
metrics for diagnostics but does not emit a structured, tamper-evident
metering stream.

The motivating requirement (per cross-repo plan §W1.3) is **metering
for auditing**, not pricing. The API must be tamper-evident — feed
the signed audit chain so a host operator cannot retroactively delete
or modify resource consumption records.

## Goal

Add a `MeteringSample` type emitted from the supervisor on three axes
(CPU-second, memory-GB-second, storage-GB-second with cold/hot tier
split). Aggregate into per-minute buckets, sign each bucket and chain
into the audit log, expose via Prometheus and per-tenant JSONL rollup.

## Design

### MeteringSample

```rust
pub struct MeteringSample {
    pub instance_id: String,
    pub tenant_id: String,
    pub tags: BTreeMap<String, String>,
    pub ts: SystemTime,
    pub cpu_ns: u64,
    pub mem_byte_seconds: u64,
    pub storage_byte_seconds_cold: u64,
    pub storage_byte_seconds_hot: u64,
}
```

The cold/hot storage split mirrors sprites.dev's pricing dimensions
and aligns with the dm-thin pool layout from Plan 47 (CoW snapshots):
"hot" = NVMe-resident pages, "cold" = pool-backed but spilled.

### Aggregation

The supervisor's existing tick (≥1 Hz, jittered) emits one
`MeteringSample` per running instance. An aggregator rolls samples
into per-minute buckets keyed on `(tenant_id, instance_id, tag-set)`.
At each bucket boundary (clock minute), the aggregator:

1. Sums the four counter fields across samples in the bucket.
2. Signs the bucket via the existing audit chain.
3. Emits a new `LocalAuditKind::MeteringEpoch` audit record.
4. Writes the bucket to the per-tenant JSONL exporter.

### Exporters

- **Prometheus.** Per-instance gauges
  (`mvm_metering_cpu_ns`, `mvm_metering_mem_byte_seconds`, etc.) and
  per-tenant counters. Endpoint hangs off the existing
  supervisor-side metrics surface.
- **Per-tenant JSONL rollup.**
  `~/.mvm/metering/<tenant>/<YYYY-MM-DD>.jsonl`. Mode 0600,
  append-only (one bucket per line; line is canonical-JSON of the
  bucket plus its audit-chain signature).

### Audit-chain integration

Extend `LocalAuditKind` in `mvm/crates/mvm-core/src/policy/audit.rs`
with:

```rust
MeteringEpoch {
    tenant_id: String,
    instance_id: String,
    bucket_start: SystemTime,
    cpu_ns: u64,
    mem_byte_seconds: u64,
    storage_byte_seconds_cold: u64,
    storage_byte_seconds_hot: u64,
}
```

Per the audit-emit gate in `mvm/CLAUDE.md` and per the
`FileAuditSigner` integration shipped on main (commit `a001c69`),
this variant naturally chains.

## Critical files

- New: `mvm/crates/mvm-supervisor/src/metering.rs` — `MeteringSample`,
  aggregator, exporter trait.
- Modified: `mvm/crates/mvm-supervisor/src/instance_sampler.rs` — emit
  `MeteringSample` alongside existing metrics.
- Modified: `mvm/crates/mvm-core/src/policy/audit.rs` — new
  `LocalAuditKind::MeteringEpoch` variant.
- Modified: `mvm/crates/mvm-supervisor/src/main.rs` — wire up exporter.
- New: `mvm/crates/mvm-supervisor/tests/metering_audit.rs` — unit +
  integration tests.
- Documentation: extend `mvm/CLAUDE.md` § Security model with the
  metering claim once shipped.

## Verification

- Unit tests: aggregator math (sum across samples in a bucket, edge
  cases at bucket boundaries).
- Integration test: spawn a fake instance sampler emitting known
  values; assert the bucket signed into the audit chain matches; tamper
  the JSONL file and assert the chain detects the corruption.
- Prometheus exporter test: scrape the endpoint, assert gauge format
  and values.

## Effort

~half-sprint.

## Out of scope

- Pricing. This plan emits raw resource-time only. Downstream systems
  (mvmd? a separate billing service?) apply prices.
- Network egress metering. Deferred until L7 egress proxy lands
  (plan 34) and exposes per-tenant byte counters.
- Cross-host rollup. Each host emits its own buckets; mvmd-side
  aggregation is a separate plan.
