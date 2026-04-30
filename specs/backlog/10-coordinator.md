# mvm Sprint 10: Coordinator — On-Demand Gateway + Request Routing

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [SPRINT-6-minimum-runtime.md](sprints/SPRINT-6-minimum-runtime.md) (complete)
- [SPRINT-7-role-profiles.md](sprints/SPRINT-7-role-profiles.md) (complete)
- [SPRINT-8-integration-lifecycle.md](sprints/SPRINT-8-integration-lifecycle.md) (complete)
- [SPRINT-9-openclaw-support.md](sprints/SPRINT-9-openclaw-support.md) (complete)

---

## Motivation

A gateway is just another microVM — it responds to requests from external clients.
Today, gateways must be running before any request arrives (reconcile ensures desired
counts). This wastes resources when tenants are idle.

Sprint 10 adds a coordinator that sits at the edge, accepts inbound connections, and
wakes gateway VMs on demand from warm snapshots. Firecracker snapshot restore is
~200ms, so the cold-start penalty is sub-second. After an idle timeout, the gateway
goes back to warm.

```
Client request
  → Coordinator (always running, lightweight)
    → Is gateway running? → yes → forward
    → no → wake from snapshot → buffer → forward when ready
    → idle timeout → sleep gateway back to warm
```

## What existed (pre-sprint)

- `coordinator/client.rs` — QUIC client that talks to agent nodes (push desired
  state, query status, wake instances, list instances)
- `coordinator/mod.rs` — module declaration
- `main.rs` — CLI subcommands: `mvm coordinator push|status|list-instances|wake`
- Agent QUIC API — `WakeInstance`, `NodeInfo`, `InstanceList`, `Reconcile` endpoints
- Sleep/wake lifecycle — snapshot + restore preserves network identity
- Sleep policy engine — idle detection, minimum runtime enforcement

## What was added (this sprint)

- `coordinator/config.rs` — TOML config with validation (nodes, routes, timeouts)
- `coordinator/routing.rs` — `RouteTable` with port-based tenant routing
- `coordinator/wake.rs` — `WakeManager` with coalesced on-demand wake via watch channels
- `coordinator/proxy.rs` — L4 TCP proxy via `copy_bidirectional`
- `coordinator/idle.rs` — per-tenant connection tracking + idle detection
- `coordinator/server.rs` — TCP accept loop + graceful shutdown + idle sweep
- `coordinator/health.rs` — background TCP health probes + post-wake readiness

---

## Phase 1: Coordinator Config + Server Skeleton
**Status: COMPLETE**

A long-running coordinator process that listens for inbound TCP connections on
configured ports and routes them to tenant gateways via the agent QUIC API.

- [x] `src/coordinator/config.rs` — `CoordinatorConfig`: listen address, agent node
  registry (list of `SocketAddr`), idle timeout, wake timeout, health check interval
- [x] `src/coordinator/config.rs` — `from_file()` TOML loader + `parse()` from string
- [x] `src/coordinator/server.rs` — `CoordinatorState` struct with tokio TCP listeners
- [x] `src/coordinator/server.rs` — accept loop: for each connection, look up route,
  hand off to wake manager + proxy
- [x] `src/main.rs` — `mvm coordinator serve --config coordinator.toml` command
- [x] Graceful shutdown on SIGTERM/SIGINT via `tokio::signal` + watch channel
- [x] Tests: config parsing (minimal, full, overrides, validation), server Send+Sync

## Phase 2: Tenant Routing Table
**Status: COMPLETE**

Map inbound connections to tenants. Port-based routing — each tenant gets a
dedicated listen port.

- [x] `src/coordinator/routing.rs` — `ResolvedRoute`: tenant_id, pool_id,
  node address, idle_timeout_secs
- [x] `src/coordinator/routing.rs` — `RouteTable`: from_config, lookup by listen addr,
  listen_addrs, len/is_empty
- [x] Port-based routing: each tenant gets a dedicated port (simple, no TLS inspection)
- [x] Config validation: reject empty routes, duplicate listen addresses, unknown nodes
- [x] Tests: route lookup, missing route, per-route idle timeout override, listen addrs

## Phase 3: On-Demand Wake
**Status: COMPLETE**

When a request arrives for a tenant whose gateway is not running, the coordinator
wakes it from a warm snapshot via the agent QUIC API and buffers the connection.

- [x] `src/coordinator/wake.rs` — `WakeManager` + `GatewayState` enum
  (Running, Waking, Idle)
- [x] On inbound connection:
  1. Check gateway state (fast path if Running)
  2. If Idle → transition to Waking, send `WakeInstance` to agent, poll until Running
  3. If already Waking → subscribe to `tokio::sync::watch` broadcast
- [x] Wake coalescing: concurrent requests share the same wake via watch channel
- [x] Configurable wake timeout (default 10s) — bail on timeout
- [x] `do_wake()`: query InstanceList → find Warm/Sleeping/Stopped → WakeInstance →
  poll at 200ms until Running → return guest_ip:service_port
- [x] Tests: default idle state, mark_running, mark_idle, fast path, timeout,
  wake notify success, wake notify failure (7 tests)

## Phase 4: Connection Proxying
**Status: COMPLETE**

Forward TCP connections between clients and gateway VMs. Layer 4 TCP proxy.

- [x] `src/coordinator/proxy.rs` — bidirectional TCP splice via
  `tokio::io::copy_bidirectional`
- [x] Connection logging: bytes sent/received per connection
- [x] `max_connections_per_tenant` in config (default 1000)
- [x] Tests: proxy bidirectional forwarding

## Phase 5: Idle Sleep
**Status: COMPLETE**

Per-tenant idle tracking for connection lifecycle management.

- [x] `src/coordinator/idle.rs` — `IdleTracker` with per-tenant activity tracking
- [x] `connection_opened()` / `connection_closed()` increment/decrement counters
- [x] `idle_tenants(timeout_secs)` — find tenants past idle timeout
- [x] `active_connections()` / `total_connections()` for metrics
- [x] Tests: open/close counting, idle detection, multi-tenant, reset

## Phase 6: Health Checking + Readiness
**Status: COMPLETE**

- [x] `src/coordinator/health.rs` — background health check loop
- [x] TCP probe: periodically connect to gateway service port, mark idle on failure
- [x] `wait_for_readiness()` — post-wake TCP probe with configurable timeout
- [x] Post-wake readiness: `do_wake()` polls instance status at 200ms intervals
  until Running, then returns guest IP for proxying
- [x] Gateway IP discovery: parsed from `InstanceList` response guest_ip field
- [x] Configurable health check interval in config (default 30s)
- [x] Stale state detection: if health probe fails, mark gateway idle for re-wake
- [x] Idle sweep loop: periodically check for idle tenants and mark gateways for sleep
- [x] Tests: health probe success/failure, readiness timeout, readiness success (4 tests)

## Phase 7: CLI + Documentation
**Status: COMPLETE**

- [x] `mvm coordinator serve --config coordinator.toml` — start the coordinator
- [x] `mvm coordinator routes --config coordinator.toml` — display routing table
- [x] `mvm coordinator push|status|list-instances|wake` — existing CLI commands
- [x] `docs/coordinator.md` — architecture, config format, deployment guide

---

## Non-goals (this sprint)

- **Multi-node scheduling**: coordinator talks to a fixed set of agent nodes from
  config. Dynamic node discovery and placement decisions are future work.
- **HTTP-aware routing**: this is L4 TCP proxying only. L7 routing (path-based,
  header inspection, request buffering) is future work.
- **TLS termination**: the coordinator forwards TLS passthrough. The gateway VM
  terminates TLS. SNI routing peeks at ClientHello but doesn't decrypt.
- **Coordinator HA**: single coordinator instance. Leader election and failover
  are future work.
- **Worker wake**: only gateway VMs are woken on demand in this sprint. Worker
  wake-on-request (gateway tells coordinator to wake a specific worker) uses the
  same primitives but is a separate feature.

## Architecture

```
                    ┌──────────────────────┐
                    │     Coordinator      │
                    │  (TCP proxy + wake)  │
                    │                      │
  Client ──TCP───► │  port 8443 ──────────┼──► Agent QUIC API
                    │       │              │       │
                    │   route table        │    WakeInstance
                    │   tenant → gateway   │    InstanceList
                    │       │              │       │
                    │   wake manager       │       ▼
                    │   idle timer         │   Gateway VM
                    │       │              │   (warm → running)
                    └───────┼──────────────┘       │
                            │                      │
                            └────TCP proxy─────────┘
```

## Config Format

```toml
[coordinator]
idle_timeout_secs = 300
wake_timeout_secs = 10
health_interval_secs = 30

[[nodes]]
address = "127.0.0.1:4433"
name = "node-1"

[[routes]]
tenant_id = "alice"
pool_id = "gateways"
listen = "0.0.0.0:8443"
node = "127.0.0.1:4433"
idle_timeout_secs = 600   # override per-route

[[routes]]
tenant_id = "bob"
pool_id = "gateways"
listen = "0.0.0.0:8444"
node = "127.0.0.1:4433"
```

---

## Summary

| Metric | Value |
|--------|-------|
| Lib tests | 349 (+35) |
| Integration tests | 10 |
| Total tests | 359 |
| Clippy warnings | 0 |
| New files | 7 (config, routing, server, wake, proxy, idle, health) |
| Sprint status | COMPLETE |
