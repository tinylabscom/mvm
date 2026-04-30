# mvm Sprint 8: Integration Lifecycle & Gateway Routing

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [SPRINT-6-minimum-runtime.md](sprints/SPRINT-6-minimum-runtime.md) (complete)
- [SPRINT-7-role-profiles.md](sprints/SPRINT-7-role-profiles.md) (complete)

Sprint 8 adds the infrastructure for OpenClaw integrations to operate inside mvm workers:
gateway inbound routing, integration state preservation across sleep/wake, artifact reporting
via vsock, and per-integration secret scoping.

OpenClaw workers connect to external services (WhatsApp, Telegram, Slack, iMessage, etc.)
which maintain session state that must survive sleep/wake cycles. Workers also produce
artifacts (messages, notes, images) that the host needs to observe for coordination.

---

## Phase 1: Gateway Routing Table Model
**Status: COMPLETE**

The gateway config drive needs a routing table so the coordinator can direct inbound
traffic (webhooks, bot callbacks) to specific worker instances.

- [x] `src/vm/pool/routing.rs` — **NEW** routing table types:
  - `RoutingTable { routes: Vec<Route> }`
  - `Route { match_rule: MatchRule, target: RouteTarget }`
  - `MatchRule { path_prefix: Option<String>, port: Option<u16>, source_cidr: Option<String> }`
  - `RouteTarget { pool_id: String, instance_selector: InstanceSelector }`
  - `InstanceSelector` enum: `Any`, `ByIp(String)`, `LeastConnections`
  - Serde roundtrip, validation (no overlapping rules), `from_json()`/`to_json()`
- [x] `src/vm/pool/mod.rs` — add `pub mod routing;`
- [x] `src/agent.rs` — add `routing_table: Option<RoutingTable>` to `DesiredPool` (`#[serde(default)]`)
- [x] Tests: routing table serde, validation rejects overlap, empty table allowed, instance selector variants (9 tests)

## Phase 2: Integration State Model
**Status: COMPLETE**

Structured data disk layout for integration session state. The guest agent checkpoints
integration state before sleep and restores it on wake.

- [x] `src/worker/integrations.rs` — **NEW** integration state types:
  - `IntegrationManifest { integrations: Vec<IntegrationEntry> }`
  - `IntegrationEntry { name, checkpoint_cmd, restore_cmd, critical }`
  - Guest-side paths: `/data/integrations/<name>/state/`, `/data/integrations/<name>/checkpoint`
  - `IntegrationStatus` enum: `Active`, `Paused`, `Error(String)`, `Pending`
  - `IntegrationStateReport` struct for vsock status reports
- [x] `src/worker/mod.rs` — add `pub mod integrations;`
- [x] Tests: manifest serde, path generation, status roundtrip, state report (7 tests)

## Phase 3: Vsock Protocol Extensions
**Status: COMPLETE**

Extend the guest agent protocol so workers can report integration state and produced
artifacts back to the host.

- [x] `src/worker/vsock.rs` — add new `GuestRequest` variants:
  - `IntegrationStatus` — query status of all integrations
  - `CheckpointIntegrations { integrations: Vec<String> }` — ask guest to checkpoint named integrations before sleep
- [x] `src/worker/vsock.rs` — add new `GuestResponse` variants:
  - `IntegrationStatusReport { integrations: Vec<IntegrationStateReport> }` — per-integration status
  - `CheckpointResult { success: bool, failed: Vec<String>, detail: Option<String> }`
- [x] High-level API: `query_integration_status()`, `checkpoint_integrations()` functions
- [x] Tests: new variant serde roundtrip, checkpoint result handling (2 new tests)

## Phase 4: Secret Scoping
**Status: COMPLETE**

Per-integration secret namespacing on the secrets drive. Each integration gets only the
secrets it needs, reducing blast radius if a guest is compromised.

- [x] `src/vm/pool/config.rs` — `SecretScope { integration, keys }` struct
- [x] `src/vm/pool/config.rs` — add `secret_scopes: Vec<SecretScope>` to `PoolSpec` (`#[serde(default)]`)
- [x] `src/agent.rs` — add `secret_scopes` to `DesiredPool` (`#[serde(default)]`)
- [x] Updated all DesiredPool/PoolSpec construction sites (agent.rs tests, shell_mock, pool/lifecycle)
- [x] Tests: secret scope serde roundtrip, backward compat (2 new tests)

## Phase 5: Gateway NixOS Routing Service
**Status: COMPLETE**

Update the gateway NixOS module to read the routing table from the config drive and
set up iptables DNAT rules.

- [x] `nix/roles/gateway.nix` — `mvm-gateway` service reads `/etc/mvm-config/routes.json` on boot
- [x] For each route: `iptables -t nat -A PREROUTING` + `OUTPUT` DNAT rules via jq parsing
- [x] `mvm-gateway-healthcheck` timer: periodic ping check every 60s that targets are reachable
- [x] IP forwarding enabled, socat + iptables + jq in system packages

## Phase 6: Worker NixOS Integration Lifecycle Service
**Status: COMPLETE**

Update the worker NixOS module with integration state management services.

- [x] `nix/roles/worker.nix` — `mvm-integration-manager` service:
  - Reads `/etc/mvm-config/config.json` for integration list
  - Ensures `/data/integrations/<name>/state/` dirs exist
- [x] `nix/roles/worker.nix` — updated `mvm-sleep-prep-vsock` to checkpoint integrations before ACK
- [x] `nix/roles/worker.nix` — added `mvm-integration-restore` service for wake restore commands
- [x] `nix/guests/baseline.nix` — already had `/data` mount at `/dev/vdb` (no changes needed)

## Phase 7: Documentation
**Status: COMPLETE**

- [x] `docs/integrations.md` — integration lifecycle, state preservation, secret scoping, gateway routing
- [x] `specs/SPRINT.md` — updated with final metrics

---

## Summary

| Metric | Value |
|--------|-------|
| Lib tests | 296 (+20) |
| Integration tests | 10 |
| Total tests | 306 |
| Clippy warnings | 0 |
| New files | `src/vm/pool/routing.rs`, `src/worker/integrations.rs` |

## Files Created/Modified

| File | Changes |
|------|---------|
| `src/vm/pool/routing.rs` | **NEW** — routing table types, validation, serde |
| `src/vm/pool/mod.rs` | Add `pub mod routing` |
| `src/worker/integrations.rs` | **NEW** — integration manifest, state types |
| `src/worker/mod.rs` | Add `pub mod integrations` |
| `src/worker/vsock.rs` | New protocol variants for integration state |
| `src/vm/instance/disk.rs` | Scoped secrets, gateway config disk |
| `src/vm/pool/config.rs` | `secret_scopes` on PoolSpec |
| `src/agent.rs` | `routing_table`, `secret_scopes` on DesiredPool |
| `nix/roles/gateway.nix` | Routing table DNAT service, healthcheck timer |
| `nix/roles/worker.nix` | Integration manager service, checkpoint on sleep |
| `nix/guests/baseline.nix` | Data drive mount |
| `docs/integrations.md` | **NEW** — integration lifecycle docs |
