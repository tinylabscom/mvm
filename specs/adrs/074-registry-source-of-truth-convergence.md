---
title: "ADR-074: VM name-registry is the source of truth; converge at CLI entry, not a resident daemon"
status: Proposed
date: 2026-06-07
related: Plan 170 (host-lifecycle convergence + density); ADR-045 (hermetic VM-lifecycle testing); ADR-044 (audit_emit! macro); Plan 140 (snapshot/restore productionization); Plan 99 (Stage 0 reaper / cache prune)
---

## Status

Proposed. Records the architectural posture behind Plan 170; WS-A code
lands in PR #688. Supersedes nothing — it formalizes a model the codebase already
half-implements (`VmNameRegistry` + `cache prune --reap-orphans` + the TTL
`reaper`) and makes the resolution rule explicit.

## Context

mvm's local runtime state lives in two places that can drift apart:

1. The **persistent registry** — `VmNameRegistry` at
   `{mvm_share_dir}/vm-names.json` (`crates/mvm/src/vm/name_registry.rs`):
   what mvm *believes* is running.
2. **On-disk runtime reality** — per-VM state dirs, `libkrun.pid`, vsock
   sockets, TAP devices (`mvm-core/src/config.rs` helpers): what is *actually*
   running.

Today the two are reconciled only **manually** (`mvmctl cache prune
--reap-orphans`) and **lazily** (drift is discovered when a command trips over
it, then fails). Every recurring stale-state bug in the project's history —
the libkrun.pid-vs-socket race, the Stage 0 stale-crate bail, the
degraded-builder-store `dev up` loop, the stale-`pause`-against-a-vanished-VM
error — is the same root cause: **no component owns making reality match the
registry, proactively.**

A sibling single-machine sandbox control plane resolves exactly this with a
"converge persistent-store → runtime on every boot" pass, because it is a
long-lived daemon. mvm's local path is **one-shot CLI invocations**, so a
"reconcile on boot" goroutine has no boot to hook. Two questions, then:

- **Which side wins on conflict?**
- **When does convergence run, given there's no resident process?**

## Decision

**The registry is the source of truth; runtime reality is converged to it.**
A record with a dead process means "tear the leftovers down and deregister,"
not "adopt the orphan." Orphan state with no record is reaped. A record
pointing at vanished state is dropped. Convergence is idempotent — running it
twice is a no-op.

**Convergence runs at CLI entry for state-touching commands, not in a resident
daemon.** Any command that reads or mutates VM lifecycle (`up`, `start`,
`run`, `console`, `down`, `status`, `dev *`, `pause`/`wake`) first runs a
**cheap** convergence pass (registry read + PID-liveness stat only — never
spawns a VM, never touches Nix). Read-only, VM-agnostic commands skip it. An
explicit `mvmctl reconcile` verb exposes the same pass observably, and
`MVM_SKIP_RECONCILE=1` is the documented escape hatch (never set in CI).

The **resident** reaper loop (`mvm_hostd::supervisor::reaper`) stays where it
is — spawned by mvmd's supervisor daemon and the MCP dispatcher — and consumes
the *same* convergence + sweep library. There is exactly one convergence
implementation; the difference between local and fleet is only *who ticks it*
(CLI entry vs. daemon timer), never *what it does*.

## Consequences

- **A whole bug class becomes a non-event.** Stale records self-heal at the
  next state-touching command instead of surfacing as a confusing failure
  three layers down.
- **Convergence must be cheap and pure-logic-first** (testable without a real
  backend, mirroring the existing `reaper::sweep` shape) — otherwise it taxes
  every CLI invocation. The PID-liveness-only budget is a hard constraint, not
  a guideline.
- **It must fail open, not closed.** A convergence error must warn and proceed
  with the requested command, never block it — a bookkeeping sweep that bricks
  `mvmctl down` would be worse than the drift it fixes.
- **Observability:** convergence actions and idle/pressure lifecycle
  transitions emit to the shared local audit log via `audit_emit!`
  (consistent with ADR-044 / the Stage 0 audit contract), so density and
  self-heal behavior are auditable and `audit verify` still chains.
- **Boundary preserved:** this is host-side lifecycle bookkeeping only. It
  never touches the guest trust boundary or any of claims 1–15.

## Alternatives considered

- **A resident local daemon that converges on a timer.** Rejected: mvm's local
  UX is a stateless CLI; a background daemon is a new failure surface, a new
  thing to install/supervise, and contradicts the one-shot model. mvmd already
  *is* the resident process for fleet use.
- **Runtime reality wins (adopt orphans into the registry).** Rejected: an
  orphan process whose record is gone has lost its admission context
  (`ExecutionPlan`, audit chain); adopting it would resurrect a workload
  outside the signed-admission path. Reaping is the only safe direction.
- **Keep reconciliation manual (`cache prune` only).** Rejected: that is the
  status quo whose lazy-discovery failure mode this ADR exists to end.
