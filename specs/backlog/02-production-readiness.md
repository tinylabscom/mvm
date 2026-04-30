# mvm Sprint 2: Production Readiness

Previous sprint: [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete, merged to main)

Sprint 1 delivered the full foundation: multi-tenant object model, lifecycle API, networking, security hardening, sleep/wake, reconcile loop, QUIC+mTLS daemon, and CI/CD. Sprint 2 focuses on making mvm production-ready.

---

## Phase 1: End-to-End Integration Testing
**Status: COMPLETE**

Shell-mockable integration tests that validate the full workflow without a real Lima VM.

- [x] Shell mock infrastructure (`src/infra/shell_mock.rs`) — thread-local `RefCell<HashMap>` intercept layer
- [x] Tenant create/list/info/destroy tests (`tests/integration_tenant.rs` via shell mock)
- [x] Pool create/build lifecycle tests
- [x] Instance create/start/ssh/stop/destroy lifecycle
- [x] Sleep/wake round-trip with snapshot verification
- [x] Agent serve + QUIC client test (send NodeInfo request, verify response)
- [x] Bridge verify produces clean BridgeReport

## Phase 2: Observability & Logging
**Status: COMPLETE**

Replaced ad-hoc `eprintln!` with structured `tracing`:

- [x] Add `tracing` + `tracing-subscriber` crates (with `json` + `env-filter` features)
- [x] Instrument all lifecycle operations with `#[instrument]` spans (instance, pool, tenant)
- [x] Structured JSON log output for agent daemon mode (`LogFormat::Json`)
- [x] Request-level tracing in QUIC handler (request type, latency, outcome)
- [x] Prometheus-style metrics endpoint (`src/observability/metrics.rs` — atomic counters, exposition format)
- [x] `RUST_LOG` env filter support via `tracing-subscriber`

## Phase 3: CLI Polish & UX
**Status: COMPLETE**

- [x] `mvm instance stats` — structured display with IP, TAP, MAC, PID, revision, timestamps
- [x] `mvm pool info` — show flake, profile, resources, desired counts, seccomp policy
- [x] `mvm tenant info` — show quota usage, network config, net_id, bridge, created_at
- [x] Colorized table output for list commands (`tabled` crate)
- [x] `--output table|json|yaml` global flag for all list/info commands
- [x] Display row structs (`src/infra/display.rs`) — TenantRow, TenantInfo, PoolRow, PoolInfo, InstanceRow, InstanceInfo
- [x] Output format rendering (`src/infra/output.rs`) — render_list/render_one helpers

## Phase 4: Error Handling & Resilience
**Status: COMPLETE**

- [x] Retry logic for transient failures (`src/infra/retry.rs` — exponential backoff, configurable attempts)
- [x] Stale PID detection (`src/vm/instance/health.rs` — `detect_stale_pids()`)
- [x] Orphan cleanup (`src/vm/instance/health.rs` — `detect_orphans()`)
- [x] Structured error types with `StalePidResult` and `OrphanResult`

## Phase 5: Coordinator Client
**Status: COMPLETE**

QUIC client side for multi-node fleet management:

- [x] `mvm coordinator` CLI subcommand group
- [x] `coordinator push --desired desired.json --node <addr>` — send desired state to agent
- [x] `coordinator status --node <addr>` — query node info + stats
- [x] `coordinator list-instances --node <addr> --tenant <id>` — query instances
- [x] `coordinator wake --node <addr> --tenant <t> --pool <p> --instance <i>` — urgent wake
- [x] Parallel push to multiple nodes (`send_multi()` via `tokio::task::JoinSet`)
- [x] mTLS client config using shared cert infrastructure

## Phase 6: Performance & Resource Optimization
**Status: COMPLETE**

- [x] Lazy Lima VM startup (`src/vm/lima_state.rs` — `OnceLock` checked on first use)
- [x] Parallel instance operations (`src/vm/instance/parallel.rs` — `parallel_start/stop/create` with configurable concurrency)
- [x] Disk space management (`src/vm/disk_manager.rs` — `disk_usage_report()`, `cleanup_old_revisions()`)

## Phase 7: Documentation & Examples
**Status: COMPLETE**

- [x] User guide: writing custom Nix flakes for mvm (`docs/user-guide.md`)
- [x] Example: web server fleet — nginx + app instances (`docs/examples/web-fleet.md`)
- [x] Example: CI runner pool — ephemeral build workers (`docs/examples/ci-runners.md`)
- [x] Troubleshooting guide (`docs/troubleshooting.md`)
- [x] API reference for desired state JSON schema (`docs/desired-state-schema.md`)
- [x] Architecture decision records — 4 ADRs (`docs/adr/001-004`)
