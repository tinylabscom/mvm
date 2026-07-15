---
title: "ADR-040: Usage-based billing model — sandbox-runtime metering dimensions and event schema"
status: Proposed
date: 2026-05-08
related: ADR-007 (overlay composition), plan 61-runtime-overlay-composition-and-billing, plan 45-filesystem-volumes
---

## Status

Proposed. Metering surface (event emission) sequenced in plan 61 Phase 5. Aggregation, billing, and Stripe integration land in mvmd separately.

## Context

mvm/mvmd is positioned in the same product class as other sandbox-runtime / code-execution platforms (per plan 60's product positioning section). To compete commercially we need a billing model with at least the dimensions the sandbox-runtime category prices on:

- **vCPU-time** (priced per vCPU-hour)
- **RAM-time** (priced per GB-RAM-hour)
- **Disk storage** (priced per GB-month)
- **Network egress** (priced per GB or included in tier)
- **Build minutes** (priced per minute or included in tier)
- **Concurrent sandboxes** (capped per tier)
- **Max session duration** (capped per tier)

Typical sandbox-runtime tier shape (used in the industry as a reference):
- **Hobby (free)**: bundled credits, ~20 concurrent sandboxes max, ~1 hr per-sandbox max, no custom domain.
- **Pro (~$150/mo)**: bundled credits, ~100 concurrent, ~24 hr per-sandbox, custom domain.
- **Enterprise**: custom — dedicated infra, SOC 2, longer session caps.

mvm needs to **emit the metering events the runtime can observe**; mvmd aggregates per-tenant rollups and produces invoices. This ADR fixes the runtime-side event schema so mvmd can be built against a stable contract.

Existing infrastructure to build on:
- `crates/mvm/src/vm/tenant/quota.rs::TenantUsage` and `crates/mvm-core/src/tenant.rs::TenantQuota` — fleet-level rollups, Postgres-backed in mvmd.
- `crates/mvm-core/src/instance.rs::InstanceState` — per-VM state.
- `crates/mvm/src/sleep/metrics.rs` — already emits sleep-related metrics; same shape can be reused.
- `crates/mvm-core/src/metering.rs` — three-axis decomposition (CPU, memory, storage) already documented; this ADR extends it with event emission.

Plan 45 (filesystem-volumes, sandbox-runtime parity) shipped feature parity around volumes. This ADR is its commercial counterpart.

## Decision

### Metering dimensions

The runtime emits events sufficient to compute, per VM, per tenant, per billing period:

| Dimension | Unit | Source |
|---|---|---|
| vCPU-time | vCPU-seconds | hypervisor stats sampled @ 10 s |
| RAM-time | byte-seconds (RSS) | hypervisor stats sampled @ 10 s |
| Disk storage | byte-seconds | provisioned disk sizes × wall-clock |
| Disk I/O | bytes read / written | hypervisor stats at stop + sampled |
| Network egress | bytes out (vsock + TAP) | TAP counter polling + vsock proxy bookkeeping |
| Build minutes | wall-clock seconds | `BuildStarted` / `BuildFinished` events from `mvm-build` |
| Concurrent sandboxes | count over time | derivable from `Started` / `Stopped` events |
| Session duration | wall-clock seconds | derivable from `Started` / `Stopped` |

### Event schema

Defined in `crates/mvm-core/src/usage.rs`. Every type carries `#[serde(deny_unknown_fields)]` (W4.1).

```rust
pub enum UsageEvent {
    Started { vm_id, tenant_id, image_digest, vcpus, mem_mib, ts_unix_ms },
    Stopped { vm_id, reason: StopReason, total_vcpu_s, total_rss_byte_s, ts_unix_ms },
    Paused  { vm_id, ts_unix_ms },
    Resumed { vm_id, ts_unix_ms },
    DiskAttached { vm_id, kind: DiskKind, bytes, ts_unix_ms },
    DiskDetached { vm_id, kind: DiskKind, ts_unix_ms },
    ResourceSample { vm_id, vcpu_s_delta, rss_bytes,
                     disk_bytes_read_delta, disk_bytes_written_delta,
                     net_bytes_in_delta, net_bytes_out_delta, ts_unix_ms },
    BuildStarted   { workspace_id, tenant_id, ts_unix_ms },
    BuildFinished  { workspace_id, elapsed_ms, ok: bool, ts_unix_ms },
    LimitHit { vm_id, kind: LimitKind, ts_unix_ms },
}

pub enum StopReason { UserStop, LimitDuration, LimitConcurrent, ProviderError, OomKilled }
pub enum DiskKind { Rootfs, Overlay, Volume, Scratch }
pub enum LimitKind { Duration, Concurrent, VcpuPerVm, RamPerVm }
```

Encoded as JSONL (one event per line). Stable wire format — version-tagged at the file level via a leading `Header` event.

### Storage and durability

- Path: `~/.mvm/usage/<vm-id>/events.jsonl` (per-VM).
- Append-only, fsync on flush boundary (every event in dev; batched in fleet mode by mvmd).
- mvmd's coordinator scrapes via the existing host-mediated channel (or in fleet mode, the agent ships them directly through the iroh QUIC link).
- Local retention: 30 days default; configurable via `~/.mvm/config.toml`.

### Caps and enforcement

Caps are advisory in standalone dev mode (`~/.mvm/caps.json` user-editable; not a billing-grade trust path) and authoritative in fleet mode (written by mvmd). The runtime enforces:

- **`max_session_duration_secs`** — VM force-stopped on expiry; emits `Stopped { reason: LimitDuration }` and `LimitHit { kind: Duration }`.
- **`max_concurrent_per_tenant`** — `start` returns `Error::QuotaExceeded` and emits `LimitHit { kind: Concurrent }`. No VM created.
- **`max_vcpu_per_vm`**, **`max_ram_mib_per_vm`** — `start_with_config` rejects oversize before contacting the provider.

### What lives in mvmd, not mvm

- Tier definitions (Hobby/Pro/Enterprise) and price tables.
- Stripe customer / subscription / invoice integration.
- Cross-host aggregation across multiple mvmctl runtimes per tenant.
- Billing-period boundaries (monthly close-out, prorated charges).
- Overage handling, credit balances, prepaid blocks.

### Bridge to existing types

`TenantUsage` (current in-memory tenant rollup) becomes a *consumer* of the JSONL stream rather than a separately-maintained counter. Implementation: a small reducer in `mvm::vm::tenant::quota` reads the per-VM JSONL files for the tenant and computes `TenantUsage` on demand. Backwards compatible — all existing call sites keep working.

## Consequences

**Positive:**
- Single canonical event source — no double-counting between TenantUsage and a separate billing pipeline.
- Stable schema (`mvm-core::usage`) gives mvmd a clean library contract; future telemetry consumers (UI, alerts) plug in without runtime changes.
- Caps enforcement at the runtime boundary closes the "user evades cap by talking to the provider directly" loophole.
- All security claims (W2–W5) preserved; metering is observation-only and adds no new privileged surface.

**Negative:**
- Sampling overhead: 10 s cadence chosen as a default. Profile work in plan 61 verifies it costs <0.5% CPU; if not, drop to 30 s.
- Standalone dev mode caps are advisory (user-editable). Documented; not a billing-grade trust path. Fleet mode (mvmd-written) is authoritative.
- JSONL on disk grows unbounded if not scraped. Default 30-day retention rotates old files; mvmd-fleet scrapes ship-and-delete.

**Neutral:**
- The existing `mvm::sleep::metrics` module remains; usage events sit alongside it. Overlap is small (sleep metrics record state transitions; usage records billing-relevant deltas).

## Alternatives considered

**Push events directly to a remote billing endpoint** — rejected for the runtime layer. Couples mvm to a specific billing backend, breaks airgap deployments, and conflates mvm's "pure local runtime" role with mvmd's orchestrator role. Local JSONL + mvmd scraping keeps the layering clean.

**Use Prometheus-style scraping (`/metrics` endpoint)** — rejected. Prometheus is great for ops dashboards but lossy for billing (counters reset on restart; scrape gaps lose events). Append-only JSONL is the right shape for billing.

**Compute usage retroactively from logs** — rejected. Brittle, log-format-coupled, slow at billing-cycle close. Native event emission is cheaper and more accurate.

**Skip caps in the runtime; let mvmd enforce them by killing VMs** — rejected. Adds latency between cap-hit and enforcement; requires mvmd to be reachable. Runtime-side enforcement is fail-safe.

## Threat model impact

- **Trust boundary for caps**: in fleet mode, `caps.json` is written by mvmd over the trusted agent channel; the runtime trusts it. In standalone mode, the user can edit `caps.json` themselves — they're billing themselves, so no trust violation. Documented explicitly.
- **Event tampering**: a compromised guest cannot forge usage events — events are emitted host-side from hypervisor stats, never from the guest. The guest agent has no `record_usage` RPC.
- **DoS via event flood**: the host emits at a fixed cadence; the guest cannot cause more events. Build events are emitted by the build pipeline, not by the guest.
- **Audit completeness**: every state transition that affects a billing dimension emits an event. Reviewing `events.jsonl` for any VM tells you what was billed and why.

## Compliance impact

- **SOC 2**: positive. Append-only event stream + cap enforcement at the runtime boundary = auditable, deterministic billing controls.
- **GDPR**: events carry `vm_id` and `tenant_id`; no user-content data. Image digests are hashes, not contents. Retention is configurable for tenant deletion requests.
- **PCI**: not applicable — mvm/runtime layer never sees payment data; that's mvmd + Stripe.
