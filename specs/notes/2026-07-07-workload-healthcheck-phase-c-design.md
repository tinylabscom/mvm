# Workload healthcheck phase C — active probing + bounded restart

**Status:** design, pending implementation plan.
**Builds on:** phase A (`specs/notes/2026-07-07-workload-healthcheck-lifecycle-design.md`) — the `HealthCheck` IR type + `MachineSpec.health_check` are already persisted. Driver reuses the per-tenant host-services daemon ([Plan 202](../plans/202-host-services-daemon.md) / [ADR-084](../adrs/084-host-services-daemon-not-per-vm-spawn.md)). Extends [ADR-091](../adrs/091-unified-machine-run-lifecycle.md).

## Problem

Phase A records a healthcheck and uses its *presence* to keep a service alive. That alone is not production-ready: a healthcheck exists to catch the failure a crash-exit does not — a process that is alive but **wedged** (deadlocked, event loop stalled, dependency hung). Production behaviour is to detect that on an interval and recover automatically. Phase C makes the healthcheck *do* something: probe it, track health, and restart a failed service under a bounded policy.

One rule spans both lifecycle types: **liveness is judged by the signal appropriate to the lifecycle — exit code for a transient task, healthcheck for a persistent service — and the system recovers on failure of that signal.** Transient tasks are already production-correct via phase A (exit code is the verdict; nothing to add). Phase C is entirely about persistent services.

## Decisions

- **Driver: the resident per-tenant `mvm-host-agent` daemon.** It is the project's sanctioned "resident daemon over per-VM spawn" (ADR-084), is already resident with a periodic tick, tracks the live VM registration set, and — critically — **outlives individual VMs**, which is what makes restart possible (a per-VM process cannot cleanly restart itself).
- **Probe = agent exec.** The daemon runs the check in the guest via a host→guest exec client (exit 0 = healthy). Exec-form only (the guest is vsock-only).
- **Restart the whole VM**, bounded by exponential backoff + a max-attempts cap, then park `Unhealthy` rather than crash-loop.
- **Restart-on-crash for declared services, via the probe path.** A crashed service is restarted — but *not* by watching for its disappearance from the daemon's live set. A genuine crash does not deregister the VM (no `stop()` call), so its registration lingers and the next probe hits an unreachable agent → `Fail` → `Unhealthy` → restart, through the same bounded policy. A *clean* disappearance from the live set is treated as possibly-intentional and is **not** restarted, because a deliberate `machine stop` also removes the registration (making vanish-detection unable to distinguish the two — it would spuriously resurrect stopped machines). This still refines phase A's "exit always wins" for services only: a task with no healthcheck tears down on exit; a service's crash is caught by probing.
- **Scope: accessible/dev-tier persistent services** (`machine run`). Sealed prod images ship an agent without exec; their health needs a non-exec signal — an mvmd-deployment concern, out of scope here.

## Architecture

### Driver — host-agent daemon probe tick

The daemon (`crates/mvm-hostd`, `mvm-host-agent`) gains a health-probe pass on its existing periodic tick (the `run_idle_watcher` cadence is the structural precedent). Each pass:

1. Walk the daemon's live VM registrations.
2. For each, load its on-disk `MachineSpec` (phase A persists `health_check` there — **no registration-protocol change**). Skip machines with `health_check = None`.
3. For a machine due for a probe (per `interval_secs`, respecting `start_period_secs` grace), connect to its guest agent (`mvm::vsock_transport::for_vm` + `mvm_guest::vsock::send_exec_streaming`, `timeout_secs` per probe) and run the check. `ExecEvent::Exit { code: 0 }` = pass; non-zero / `TimedOut` / transport error = fail.
4. Fold the result into per-machine prober state (held in daemon memory): consecutive-failure count, current state, backoff clock, restart-attempt count.

**Two integration gaps to close (de-risk first):**
- **HVF wiring.** The daemon is confirmed selected in `libkrun.rs`/`vz.rs` `start()`; verify it is (or wire it) on `hvf_backend.rs` — the macOS-26 default. A phase C that does not run on the HVF backend is a non-starter; this is task 0.
- **Admission.** The daemon registers only *admitted* workloads. A `machine run --healthcheck` is admitted as tenant `local`; verify end-to-end that a healthchecked persistent machine actually registers with the daemon.

If the HVF gap cannot be closed cleanly, the fallback is a probe thread in the per-VM hypervisor supervisor — but that complicates restart (self-restart), so the daemon is the primary.

### Health state machine

Per machine: **Starting** (first `start_period_secs` after boot — failures do not count) → **Healthy** → **Unhealthy** (after `retries` consecutive failures). Recovery: a passing probe returns Unhealthy→Healthy (or the restart path resets to Starting).

Persisted through the **existing** readiness seam — `record_vm_readiness(vm_name, InstanceReadiness)` (`crates/mvm-cli/src/commands/vm/readiness.rs`), already used in production by the launch path (`up.rs` → `LaunchAccepted`) and the stop path (`down.rs` → `Stopping`). Phase C composes with that lifecycle by writing the health states through the same function (which updates `VmRegistration.readiness` + `last_readiness_change_at`); it does **not** reinvent registry writes. Mapping onto `InstanceReadiness` (`crates/mvm-core/src/domain/instance.rs`): `Starting → ServicesStarting`, `Healthy → ServicesReady`, `Unhealthy → Degraded`. **The daemon lives in `mvm-hostd` and cannot reach `record_vm_readiness` (it's in `mvm-cli`); either lift the tiny recorder to a lower crate (`mvm`, alongside `name_registry`) that both consume, or have the daemon write via `name_registry::set_readiness` directly — the plan picks one.** `machine ls` gains a health column and `machine inspect` a health field — net-new rendering (confirmed: no current renderer reads `readiness`); storage + enum already exist. When the daemon is disabled/absent, health reads `unknown` and the machine still runs — clean degradation.

### Restart — bounded

On the transition **→ Unhealthy** (which a crashed service reaches via probe-detected unreachability — see restart-on-crash above), the daemon restarts the whole VM by spawning `mvmctl machine restart <name>` (reuses `run_restart` = `stop_running_machine` + `start_machine`; a subprocess avoids an `mvm-hostd → mvm-cli` dependency and matches the daemon's existing subprocess model).

- **Backoff:** exponential from a base (1s → 2s → 4s …) capped (e.g. 5 min) between attempts.
- **Cap:** after `MAX_RESTART_ATTEMPTS` (e.g. 5) without reaching a sustained Healthy state, stop restarting and leave the machine parked `Unhealthy` (stopped) — no thrash.
- **Reset:** a sustained Healthy period (e.g. ≥ one full `interval` healthy) resets the backoff + attempt counter, so a service that recovers and later fails again gets a fresh budget.

### Observability

Each health transition and each restart emits an event to the machine's chain-signed audit log, so `mvmctl trust audit` shows the health/restart history.

## Build sequencing (stages for the plan)

Same end-state as the decisions above; ordered to be independently testable:

- **S0 — de-risk:** confirm/wire the host-agent daemon on the HVF backend and confirm a healthchecked `machine run` registers with it. (Spike/fix; unblocks S2.)
- **S1 — probe primitive + state + display:** a pure `probe_once(vm) -> ProbeResult` (exec via `send_exec_streaming`), the Starting/Healthy/Unhealthy state-machine reducer (pure, unit-tested), persistence to the registry, and `machine ls`/`inspect` rendering. Drive it initially by an on-invocation probe (`machine ls` probes) so it is testable without the daemon.
- **S2 — daemon interval loop:** move the driver into the daemon tick — read specs, probe due machines honoring interval/timeout/start_period, write readiness.
- **S3 — restart:** the bounded-restart policy (backoff + max-attempts + reset) and restart-on-exit, plus audit events.

## Error handling

- Transport/connect failure to the agent counts as a failed probe (a service whose agent is unreachable is not healthy), subject to the same `retries`.
- A probe must never wedge the tick: `timeout_secs` bounds each exec; a slow machine's probe cannot stall others (bounded per-probe, and the tick budgets its work).
- The daemon crashing/restarting must not lose safety: prober state is in-memory (rebuilt from the registry's persisted `readiness` + spec on restart); Plan 202's supervise-worker + registration journal already make the daemon resilient.

## Testing

- Pure state-machine reducer: start-period grace, N-consecutive-failure → Unhealthy, recovery → Healthy, backoff schedule, max-attempts cap, reset-after-healthy (table tests).
- `probe_once`: mock guest agent (exec exit 0 / non-zero / timeout / transport error) → correct `ProbeResult`.
- Registry: readiness + `last_readiness_change_at` round-trip and atomic update.
- `machine ls`/`inspect`: health column/field renders each state.
- Restart: the daemon spawns `mvmctl machine restart <name>` on →Unhealthy, respects backoff/cap, resets after healthy (mock the restart spawn).
- Integration (manual, macOS HVF): a healthchecked service that goes unhealthy is restarted; a wedged service (check fails, process alive) is caught; a task with no healthcheck is unaffected.

## Out of scope

- Sealed-prod (agent-without-exec) health signals — mvmd concern.
- HTTP/TCP probe kinds (vsock-only guest → exec only).
- Multi-tenant fleet health aggregation (mvmd).
- The phase A tuning-flag surface is unchanged; phase C only starts *enforcing* the already-stored `interval/timeout/retries/start_period`.
