# mvm Sprint 6: Minimum Runtime Policy & Vsock Guest Agent

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening — hostd/agentd split, snapshot encryption, Ed25519 signing, memory hygiene, attestation (complete)

Sprint 6 implements minimum runtime enforcement, vsock guest communication, and the config drive model. Based on [specs/plans/9-minimum-runtime.md](plans/9-minimum-runtime.md).

---

## Phase 1: Vsock Guest Agent Module
**Status: COMPLETE**

Host-side vsock client for guest agent communication over Firecracker's vsock UDS proxy.

- [x] `src/worker/vsock.rs` — new module: connect, send_request, query_worker_status, request_sleep_prep, signal_wake, ping
- [x] `src/worker/mod.rs` — add `pub mod vsock`
- [x] GuestRequest/GuestResponse JSON roundtrip tests
- [x] 4-byte BE length-prefixed frame protocol (matches hostd pattern)

## Phase 2: Firecracker Vsock Device
**Status: COMPLETE**

Add vsock device to FC config for host↔guest communication.

- [x] `src/vm/instance/fc_config.rs` — VsockDevice struct, Optional vsock field on FcConfig
- [x] `src/vm/instance/fc_config.rs` — generate() updated with vsock_uds_path parameter
- [x] `src/vm/instance/lifecycle.rs` — pass vsock path on instance_start
- [x] `src/vm/pool/build.rs` — pass vsock: None for ephemeral build VMs
- [x] Tests: FcConfig with/without vsock serialization

## Phase 3: Config Drive
**Status: COMPLETE**

Read-only config drive delivers instance/pool metadata to the guest without SSH.

- [x] `src/vm/instance/disk.rs` — create_config_disk(), remove_config_disk()
- [x] `src/vm/instance/fc_config.rs` — config_disk_path parameter, drive_id "config" (ro)
- [x] `src/vm/instance/lifecycle.rs` — create config disk on start/wake, clean up on stop
- [x] Drive model: rootfs (ro) → config (ro) → data (rw) → secrets (ro)
- [x] rootfs changed to read-only (was read-write)

## Phase 4: RuntimePolicy Struct
**Status: COMPLETE** (already existed from Sprint 5)

- [x] `src/vm/pool/config.rs` — RuntimePolicy with min_running_seconds, min_warm_seconds, drain_timeout_seconds, graceful_shutdown_seconds
- [x] `src/vm/pool/config.rs` — PoolSpec has runtime_policy field
- [x] `src/agent.rs` — DesiredPool has runtime_policy field

## Phase 5: Instance State Timestamps
**Status: COMPLETE**

Per-instance timestamps for minimum runtime enforcement.

- [x] `src/vm/instance/state.rs` — entered_running_at, entered_warm_at, last_busy_at fields
- [x] `src/vm/instance/lifecycle.rs` — set entered_running_at on start/wake, entered_warm_at on warm, clear both on stop/sleep
- [x] `src/vm/instance/lifecycle.rs` — load_instance made pub(crate)
- [x] Backward compatibility via #[serde(default)]

## Phase 6: Sleep Policy Integration
**Status: COMPLETE**

Eligibility check prevents premature state transitions.

- [x] `src/sleep/policy.rs` — is_eligible_for_transition() checks min_running_seconds / min_warm_seconds
- [x] `src/sleep/policy.rs` — elapsed_secs() helper for ISO timestamp math
- [x] `src/sleep/policy.rs` — evaluate_instance() defers warm/sleep when within min runtime
- [x] `src/sleep/policy.rs` — pressure_candidates() deprioritizes (but includes) ineligible instances
- [x] 10+ new tests for eligibility edge cases

## Phase 7: Audit Trail & Metrics
**Status: COMPLETE**

Track deferrals and overrides in audit log and Prometheus metrics.

- [x] `src/security/audit.rs` — TransitionDeferred, MinRuntimeOverridden action variants
- [x] `src/observability/metrics.rs` — instances_deferred counter + Prometheus exposition
- [x] Tests: new audit action serialization

## Phase 8: Reconcile Integration
**Status: COMPLETE**

Agent reconcile loop respects min-runtime and reports deferrals.

- [x] `src/agent.rs` — ReconcileReport.instances_deferred field
- [x] `src/agent.rs` — Phase 6 logs TransitionDeferred audit entries, increments metrics
- [x] `src/agent.rs` — generate_desired() propagates role + runtime_policy
- [x] `src/agent.rs` — CLI reconcile() prints deferral count
- [x] Tests: DesiredPool structs updated with role + runtime_policy

## Phase 9: Vsock Drain (Replace SSH)
**Status: COMPLETE**

Replace SSH-based sleep-prep with vsock guest agent.

- [x] `src/vm/instance/lifecycle.rs` — instance_sleep() uses vsock::request_sleep_prep() instead of SSH
- [x] `src/vm/instance/lifecycle.rs` — instance_wake() signals guest via vsock::signal_wake()
- [x] `src/vm/instance/lifecycle.rs` — graceful_shutdown_seconds from policy replaces hardcoded sleep 1
- [x] `src/hostd/protocol.rs` — SleepInstance gains drain_timeout_secs field

## Phase 10: Documentation
**Status: COMPLETE**

- [x] `docs/minimum-runtime.md` — semantics, exceptions, drain protocol, drive model
- [x] `specs/SPRINT.md` — updated to Sprint 6

---

## Summary

| Metric | Value |
|--------|-------|
| Lib tests | 264 |
| Integration tests | 10 |
| Total tests | 274 |
| Clippy warnings | 0 |
| New files | `src/worker/vsock.rs`, `docs/minimum-runtime.md` |

## Files Modified

| File | Changes |
|------|---------|
| `src/worker/vsock.rs` | **NEW** — vsock guest agent client |
| `src/worker/mod.rs` | Add `pub mod vsock` |
| `src/vm/instance/fc_config.rs` | VsockDevice, config drive, 8 params, rootfs ro |
| `src/vm/instance/disk.rs` | create_config_disk(), remove_config_disk() |
| `src/vm/instance/state.rs` | 3 timestamp fields |
| `src/vm/instance/lifecycle.rs` | Timestamps, vsock drain, config drive, load_instance pub(crate) |
| `src/vm/pool/config.rs` | Role derive Default, RuntimePolicy (existing) |
| `src/vm/pool/lifecycle.rs` | role + runtime_policy in pool_create |
| `src/vm/pool/build.rs` | vsock: None |
| `src/sleep/policy.rs` | Eligibility checks, RuntimePolicy integration |
| `src/agent.rs` | runtime_policy on DesiredPool, deferrals in reconcile |
| `src/security/audit.rs` | TransitionDeferred, MinRuntimeOverridden |
| `src/observability/metrics.rs` | instances_deferred counter |
| `src/hostd/protocol.rs` | drain_timeout_secs on SleepInstance |
| `src/hostd/server.rs` | Handle new SleepInstance field |
| `src/infra/shell_mock.rs` | role + runtime_policy in pool_fixture |
