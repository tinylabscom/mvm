# Workload healthcheck → lifecycle signal

**Status:** design, pending implementation plan.
**Extends:** [ADR-091](../adrs/091-unified-machine-run-lifecycle.md) unified
`machine run` transient/persistent/interactive model (impl [Plan 207](../plans/207-machine-run-unified-lifecycle.md)).

## Problem

A task-based microVM should shut down when it finishes: the entrypoint exits,
we receive its exit code, and — with no healthcheck configured — the VM is
transient and tears down. A long-running *service* is a different animal: it is
not "done" when nothing has exited, and tearing it down on some backstop is
wrong. Today the only way to say "keep this alive" is `-d`/`--name`/`--ttl`
(a host-side launch flag). There is no way for a workload to declare *itself* a
service.

This design adds a **healthcheck** as that declaration. Its presence promotes a
run to the persistent, managed lifecycle. This slice ships the **lifecycle
signal only**; the check is recorded but not yet executed.

## Decisions

- **Scope now: signal only.** The *presence* of a healthcheck is a lifecycle
  signal. No probe loop, no health state, no restart. The IR type is shaped
  richly (interval/timeout/retries) so active probing + restart is a purely
  additive follow-up ("phase C" below) with no schema change.
- **Exit code always wins.** If the entrypoint exits, the workload's work is
  done → tear down, healthcheck or not. A healthcheck never resurrects a
  finished task; it only says "this entrypoint is not supposed to exit — treat
  it as a service." Restart-on-exit is phase C.
- **Source: a CLI flag on `machine run`**, backed by an IR field. The IR field
  is the single representation; an SDK/decorator author can populate the same
  field later with no rework. OCI-image `HEALTHCHECK` mapping is out of scope.
- **Foreground by default.** `--healthcheck` without `-d` runs in the
  foreground (stream logs; Ctrl-C detaches/stops), matching
  `docker run --health-cmd`. `-d` detaches. `--healthcheck` governs
  *lifecycle/liveness*, not *backgrounding*.

## Lifecycle model

One term added to the persistence predicate. Today (post-ADR-091 evolution)
`persistent() = detach || up_json || ttl.is_some()` — note `--name` is an
*identity only*, not a persistence trigger. Add the healthcheck term:

```
persistent = --detach | --up-json | --ttl | --healthcheck
transient  = otherwise           (--name alone stays transient)
```

| entrypoint | flags | mode | what shuts it down |
|---|---|---|---|
| exits (task) | *none* (or `--name` alone) | transient | exit code → teardown *(today's behavior)* |
| exits (task) | `-d`/`--ttl`/`--up-json` | persistent | exit code → teardown (exit wins); stays registered |
| exits (task) | `--healthcheck` | persistent | exit code → teardown (exit wins) — healthcheck effectively a no-op here |
| never exits (server) | *none* | transient | Ctrl-C / timeout backstop; not registered |
| never exits (server) | `--healthcheck` | persistent, **foreground** | `stop` (or Ctrl-C); registered, (phase C) probed |
| never exits (server) | `-d [--healthcheck]` | persistent, detached | `stop` |

**No healthcheck changes nothing.** The `--healthcheck` term simply drops out of
the OR; persistence is decided exactly as today. The healthcheck is a purely
additive fourth way to opt into persistent.

A healthcheck on a run-to-completion entrypoint is harmless but pointless (the
exit tears it down first). A future lint may warn; not in scope.

## `HealthCheck` IR type

New `Option<HealthCheck>` on `App` in `mvm-sdk::ir` (`ir/workload.rs`),
Docker/k8s-shaped:

```rust
pub struct HealthCheck {
    /// Command exec'd in the guest via the agent; exit 0 = healthy. Exec form
    /// (not HTTP/TCP): the guest is vsock-only and the agent already speaks exec.
    pub command: Vec<String>,
    pub interval_secs: u32,       // default 30
    pub timeout_secs: u32,        // default 5
    pub retries: u32,             // default 3
    pub start_period_secs: u32,   // default 0
}
```

- Fields default via `#[serde(default = ...)]` (no schema-version ceremony —
  nothing in prod yet).
- **This slice reads only `.is_some()`** for the lifecycle decision. The timing
  fields are persisted (see plan carriage) but not acted on.

## CLI surface

```
machine run --image nginx --healthcheck 'curl -fsS localhost/health'
  [--health-interval 30] [--health-timeout 5] [--health-retries 3] [--health-start-period 0]
```

- `--healthcheck '<shell cmd>'` is the trigger; stored as
  `["/bin/sh", "-lc", "<cmd>"]` (exec argv the agent runs).
- The tuning flags are accepted and stored now (so phase C adds no flags),
  documented as "recorded, not yet enforced".

## Where it plugs in

- `MachineRunArgs` gains `healthcheck: Option<String>` + the four tuning fields.
- `MachineRunArgs::persistent()` (crates/mvm-cli/.../machine/mod.rs) gains
  `|| self.healthcheck.is_some()`.
- **New behavior — foreground persistent.** Today `resolve_mode()` maps
  persistent → detached/managed only; there is no "persistent but attached"
  mode. A healthchecked run without `-d` needs exactly that: it boots/registers
  through the persistent path (named, `machine ls`-visible, survives) yet
  streams in the foreground and does not tear down on a backstop. The plan
  decides the mechanism — a new `MachineRunMode` variant vs. a `foreground` bit
  threaded onto the persistent path — but this is the one genuinely new
  lifecycle behavior; `--healthcheck` with `-d` or `-it` composes with the
  existing detached/interactive axes unchanged.
- The healthcheck flows into the synthesized `ExecutionPlan` (claim 8) so it is
  signed + audited and available to the phase-C probe, then onto the `App` IR.
- Persistent registration reuses ADR-091's existing `MachineSpec` write + name
  registry — no new lifecycle code.

## Deferred — phase C (probe + restart)

Builds only on the stored `HealthCheck` fields, no schema change:

- A probe loop (host-driven, via the guest agent's exec) honoring
  `interval/timeout/retries/start_period`.
- Health state (`Starting`/`Healthy`/`Unhealthy`) surfaced in
  `machine ls`/`inspect` — maps onto the existing display-only
  `InstanceReadiness` (`mvm-core/domain/instance.rs`), which is explicitly
  non-gating today.
- Restart-on-unhealthy / restart-on-exit policy.

## Testing

- IR: serde roundtrip, field defaults.
- `persistent()` truth table incl. the healthcheck term.
- CLI parse in `tests/cli.rs`: `--healthcheck` + tuning flags; `--healthcheck`
  flips mode to persistent; foreground-vs-`-d`.
- Admission: the synthesized plan carries the healthcheck through
  sign/verify unchanged.
- Lifecycle: transient (no healthcheck) still tears down on exit; a
  healthchecked server registers as a persistent machine and survives entrypoint
  non-exit until `stop`.

## Out of scope

- Active probing, health state, restart (phase C).
- OCI-image `HEALTHCHECK` directive mapping.
- HTTP/TCP probe kinds (vsock-only guest → exec only).
- Idle auto-stop / TTL reaping (already a separate concern per ADR-091).
