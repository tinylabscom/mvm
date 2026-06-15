# Plan 125 E5.3b — broker-services subprocess lifecycle: scoping note

**Status:** scoped, not started. This is the gating dependency for the live
`mvm.audit.emit` round-trip (E5's headline acceptance). It is the deferred
"lifecycle pipeline" the broker modules repeatedly reference, and it is large
+ security-critical (claims 8/12/13) — distinct in character from the
guest-side SDK surface (E5.1/E5.2) and arguably closer to Plan 128's
process-moat territory than to Plan 125's "SDK DX".

## What is already built (verified on `main`)

- **Guest side (E5.1/E5.2):** `mvm-guest::broker_client` (framed `ServiceCall`
  ↔ `ServiceResponse` over `connect_host_vsock(BROKER_PORT)`) and
  `mvm-guest::host_audit` (`emit`/`emit_batch`, typed `AuditError`). Done.
- **`BROKER_PORT` (5300)** is reserved in both backends' `host_listen_ports`
  (E5.3a — libkrun + vz, fail-closed: nothing binds the UDS yet, so a stray
  guest dial gets `ECONNREFUSED`).
- **The subprocess binaries exist** and are unit-tested in isolation:
  - `mvm-broker` (`crates/mvm-hostd/src/bin/mvm-broker.rs`) registers
    `HostAuditV1Handler` (forces `category: workload_audit`, 4 KiB cap, 20/s
    token bucket, forwards to the audit-signer), plus `host.time.v1` /
    `host.cost.v1` / `broker.v1`. Its `serve_on_listener` accepts framed
    `ServiceCall`s and dispatches via the `Registry`.
  - `mvm-audit-signer` (`crates/mvm-hostd/src/bin/mvm-audit-signer.rs`) is the
    chain-signer: `AppendEntryRequest` → signed chain entry, fsync, returns
    `chain_head`.
- **Host-side UDS proxies + spawn primitives exist** but are wired only in
  tests: `BrokerProxy` / `AuditSignerProxy` (UDS clients),
  `supervisor::services::spawn` (`SubprocessSpawner`/`ProcessSpawner`/
  `RestartSupervisor`), `config_signer`, `binary_integrity` (cosign verify;
  TOCTOU-via-`fexecve` deferred), `SubprocessConfig` (`broker/config.rs`,
  carries `audit_signer_uds_path`).

## The gap (what makes the live path dead today)

Traced every call site: `BrokerProxy::new`, `AuditSignerProxy::new`, the
broker `serve_on_listener`, and the spawn module are **only reached from
`#[cfg(test)]`**. The per-VM supervisors (`mvm-vm-host` bins) spawn exactly one
subprocess today — `codesign`. So **nothing spawns `mvm-broker` or
`mvm-audit-signer` per VM, and nothing binds the per-VM broker UDS.**

The substitution path is the working precedent: a per-VM subprocess
(`spawn_substitution_endpoint`, called from `LibkrunBackend::start` via
`spawn_libkrun_egress_endpoint_if_needed`) binds
`vm_vsock_port_socket(vm_name, SUBSTITUTION_PORT)`; libkrun proxies the guest's
`connect_host_vsock(SUBSTITUTION_PORT)` straight to it. The broker needs the
analogous per-VM spawn binding `vm_vsock_port_socket(vm_name, BROKER_PORT)`.

## Components to build

1. **Per-VM audit-signer spawn + chain wiring.** Spawn `mvm-audit-signer` with
   its signed config (chain key + the per-tenant chain file —
   `~/.mvm/audit/<tenant>.jsonl`, the same chain `mvmctl trust audit verify`
   reads); it binds its UDS. Gated on an admitted plan (tenant present).
2. **Per-VM broker spawn + `BROKER_PORT` bind.** Spawn `mvm-broker` with a
   `SubprocessConfig` carrying `workload_id` / `tenant_id` and the
   `audit_signer_uds_path` from (1); have it `serve_on_listener` on
   `vm_vsock_port_socket(vm_name, BROKER_PORT)` so libkrun/vz forward the
   guest's dial straight to it. Mirror `spawn_libkrun_egress_endpoint_if_needed`
   in `LibkrunBackend::start` + the vz equivalent.
3. **`ServiceCallCtx` enrichment.** `broker/server.rs` builds a *stub* ctx
   today (`session_id: "w1a-stub-session"`, `profile: Dev`). For a correct
   live entry: `workload_id`/`tenant_id` from config (done), a real
   `session_id`, `profile` from the admitted plan, and the **correlation-id
   rewrite at ingress** (the supervisor reassigns the guest-supplied
   placeholder — the claim-12-adjacent integrity step).
4. **Process-moat hardening at spawn** (the claim surface): cosign
   verify-then-exec (`binary_integrity`; TOCTOU close is deferred), the signed
   config envelope (`config_signer`, currently unadopted — the broker still
   parses unsigned), seccomp + setpriv + resource caps + per-workload cgroup +
   `pdeathsig`. Decide MVP-now vs deferred-follow-up per item, and *log* what's
   deferred (no silent gaps).

## Open questions to resolve FIRST

1. **Spawn ownership** — backend `start()` path (mirrors the substitution
   endpoint, simplest) vs the per-VM supervisor bin. Recommend the backend
   `start()` path for parity with substitution.
2. **Bind-direct vs splice** — does `mvm-broker` bind
   `vm_vsock_port_socket(name, BROKER_PORT)` directly (mirror substitution, no
   extra hop) or does the supervisor accept + splice to the broker's own UDS?
   Direct-bind is simpler and matches the substitution precedent.
3. **Spawn gating** — `host.audit.v1` is available to every profile, but the
   chain needs a tenant + admitted plan. Gate the broker spawn on
   `plan_json + tenant_id` present (like the vz drainer/bridge), so an
   unadmitted dev VM simply has no broker (guest dial → `ECONNREFUSED`).
4. **Audit-signer key + chain provenance** — where the per-tenant chain key
   comes from and how the chain file path is derived per VM/tenant.
5. **Backend coverage** — libkrun + vz first (the workload backends with the
   host_listen_port reserved); firecracker/qemu later or never (match the
   substitution/gateway substrate coverage decision).

## Test matrix

- **Unit (no VM):** spawn-config construction (UDS paths, `audit_signer_uds_path`
  threading, gating on admitted plan); the `BrokerProxy`/`AuditSignerProxy`
  round-trips already exist; a spliced/bound listener test if (2) lands a
  supervisor splice.
- **Live-VM E2E (gated, dev-kvm box `root@88.99.197.234`, isolated with
  `MVM_CACHE_DIR`/`MVM_DATA_DIR`):** `mvm.audit.emit({...})` from inside a
  `Sandbox` lands a `workload_audit` entry visible in `mvmctl trust audit
  verify`, host-stamped + workload-originated; a workload can never write a
  host-category entry (the handler forces it); >4 KiB → `BadRequest`; 20/s
  rate-limit trips.

## Recommended slicing

- **E5.3b-1** — per-VM audit-signer spawn + chain wiring (unit-tested config).
- **E5.3b-2** — per-VM broker spawn + `BROKER_PORT` direct-bind + ctx
  enrichment (correlation rewrite, profile/session). Unblocks the round-trip.
- **E5.3b-3** — PyO3/napi veneer (`mvm.audit.emit`/`emit_batch`) — greenfield
  (no pyo3/napi in the repo yet; new deps under the ADR-002 trust model).
- **E5.3b-4** — live-VM E2E on the box.

Process-moat hardening (item 4) rides whichever slice introduces the spawn,
with deferred items tracked, not silently skipped. Binding-gated dispatch +
no-payload-in-errors remain Plan 128 (claims 12/13).
