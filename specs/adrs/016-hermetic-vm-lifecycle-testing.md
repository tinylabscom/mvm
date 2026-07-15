---
title: "ADR-016: Hermetic testing for the VM-lifecycle Emits rows"
status: Accepted
date: 2026-05-12
related: ADR-014 (audit_emit! macro); plan 60 Phase 4 (persistent observability); plan 37 §6 (no unaudited control-plane mutation); plans 65/66/67/68/69/70 (per-row hermetic test work)
---

## Status

Accepted. Architecture decided; per-row implementation deferred to
plans 65–70 (one plan per blocked verb cluster). Foundation in place
as of PR #108 (`feat/mock-backend`):

- `MockBackend` substrate in `crates/mvm-backend/src/mock.rs` —
  in-memory `Arc<Mutex<HashMap>>` recording, full `VmBackend` trait
  impl, 10 unit tests, selected via `--hypervisor mock`.
- `MVM_DIRECT_BOOT` LocalAudit emit-parity with the main `up` path
  (PR #108) — both paths now emit `VmStart` and respect `--detach`.
- `bring_up_mock_vm(&sandbox, name)` test fixture in
  `tests/audit_emissions_live.rs` brings up a registered mock VM
  for chained-step coverage.

End-to-end coverage of `mvmctl up` and `mvmctl set-ttl` against the
mock VM shipped in PR #108. Six verb clusters remain blocked on
per-cluster substrate work (plans 65–70).

## Context

ADR-014 established `audit_emit!` as the canonical emit surface and
required every state-changing CLI verb to have a live drive-and-assert
test pinning its `LocalAuditKind` emit. Pinning the easy rows shipped
in PRs #106 / #107 / #108 — 40 live tests at PR #108 close, covering
every Emits row that doesn't need a running Firecracker / Apple
Container / Docker / libkrun / Nix builder / GitHub network.

The remaining rows fall into six clusters by what they reach through:

| Cluster | Verbs | Reaches through | Why hermetic testing is hard |
|---|---|---|---|
| **Snapshot lifecycle** | `pause` / `resume` | `FirecrackerIO` socket + `pause_and_seal` / `verify_and_resume` | Talk directly to Firecracker UDS; bypass `AnyBackend.pause`/`resume` trait methods. Routing through the trait drops the snapshot semantics (vmstate + mem files) — substantive behavior change. |
| **Guest agent commands** | `fs write/mkdir/rm/chmod`, `proc start/signal/kill/stdin` | Vsock connection to the in-guest `mvm-guest-agent` daemon | Per-VM vsock socket + agent protocol RPC. No mock layer for the vsock or the agent protocol exists. |
| **VM-attached storage** | `volume mount` / `volume unmount` | `mvm_storage::virtio_fs::*` + per-VM Firecracker socket | Mount path validation runs against `MountPathPolicy`; the actual virtio-fs daemon attach is Firecracker-specific. |
| **Nix build pipeline** | `build` → `TemplateBuild` | `mvm-build::pipeline::build` → host Nix or `LibkrunBuilderVm` | The whole chain runs `nix build` against a flake — needs a Nix install or a running builder VM. |
| **GitHub-driven self-update** | `update` → `UpdateInstall` | `reqwest` HTTPS to `github.com/auser/mvm/releases/latest` (now tinylabscom/mvm) | Reaches the public internet on every invocation. `--check` mode also hits GitHub. |
| **System-path destruction** | `uninstall` positive | `sudo rm -rf /var/lib/mvm`, `sudo rm /usr/local/bin/mvmctl`, `microvm::stop()` | Sudo-gated absolute paths that on a developer's machine point at a real install. |

Every cluster is solvable; each has a distinct fixture/refactor shape.
The cost is not architectural-fundamental; it's per-cluster substrate
work. The decision here is *how* to sequence and structure that work
so the audit-emit hardening campaign closes incrementally without one
giant PR.

## Decision

### One plan per cluster, dependencies kept linear

Six standalone plans, each independently mergeable, sharing the
existing PR #106/#107/#108 substrate (`audit_emit!`, `MockBackend`,
`AuditSandbox` fixture). Each plan ships:

1. Whatever substrate the verb cluster needs (a trait extension, a
   mock layer, an env-var override).
2. The minimal production behavior change (if any) — typically gated
   so the new path activates only in test contexts.
3. Live drive-and-assert tests for every positive + negative row in
   the cluster.
4. An entry in `tests/audit_emissions_live.rs`'s module-doc coverage
   list.

```
ADR-014 → ADR-016 (this doc) → six independent plans
                              ├─ plan 65: pause/resume via AnyBackend + snapshot extension
                              ├─ plan 66: vsock guest-agent mock layer (fs + proc)
                              ├─ plan 67: volume mount/unmount with mock virtio-fs
                              ├─ plan 68: TemplateBuild via stub builder fixture
                              ├─ plan 69: UpdateInstall via httpmock
                              └─ plan 70: Uninstall via path-prefix override
```

Sequencing is not strict — plans 65–70 don't share files in any
meaningful way and can ship in parallel. Suggested priority order:

1. **Plan 65 (pause/resume)** — unblocks `WorkloadSleep` / `WorkloadWake`
   Emits, which are the most-cited rows when operators audit a
   sandbox's lifecycle.
2. **Plan 67 (volume)** — small surface, useful coverage, no agent
   protocol to mock.
3. **Plan 69 (update)** — well-known pattern (httpmock); short PR.
4. **Plan 70 (uninstall)** — small but careful — touches sudo paths
   in production.
5. **Plan 66 (vsock guest-agent mock)** — biggest substrate
   investment; pays off across `fs` + `proc` (8 rows) + future
   `exec`/`run-code`/`console` work.
6. **Plan 68 (build)** — has the most external dependencies (Nix);
   probably last.

### Constraints every plan honors

- **No production-only flags.** Any new flag (`--rootfs-path`,
  `--no-build`, etc.) must be valuable to operators, not just tests.
  Test-only escape hatches go through env vars (matching the
  `MVM_DIRECT_BOOT` pattern) or `#[cfg(test)]`-gated alt code paths.
- **No backwards-compat shims.** When refactoring (e.g. pause through
  `AnyBackend`), the old call site is removed — there is no `--legacy`
  flag. The migration is the migration.
- **xtask `check-audit-positional` stays green throughout.** Every
  new emit uses the `audit_emit!` macro.
- **Plan 37 §6 holds.** Every plan's tests assert one audit record per
  attempt, including the no-op / failure branches.

## Consequences

### Positive

- **Bounded PR scope.** Each plan is a 1–3 commit PR. Reviewers don't
  face a 30-commit mega-refactor.
- **Failure isolates.** A bug in the vsock mock (plan 66) doesn't
  block the snapshot refactor (plan 65) from landing.
- **Compounding leverage.** Plan 66's vsock mock unlocks future
  `exec`/`run-code`/`console` test work; plan 65's `AnyBackend.pause`
  routing unlocks the snapshot CLI ergonomics that ADR-012 wants
  (single-host preview of mvmd's sleep/wake).
- **Documentation trail.** Each plan is a discoverable, dated record of
  what was done and why. Audit-emit campaigns started by future
  contributors don't have to reverse-engineer the substrate.

### Negative

- **More plan files.** specs/plans/ already has 60+ entries; adding
  six more grows the directory. Mitigated because the plans are
  short (single-cluster scope) and the index in SPRINT.md groups them.
- **Sequencing decisions are deferred.** This ADR doesn't decide
  which plan ships first; the priority order above is *suggested*,
  not binding. A contributor who wants to ship plan 68 ahead of plan
  65 is free to.

### Bounded

- **Not a refactor of the supervisor/plan-64 chain.** The plans here
  cover the **LocalAudit stream only** — the per-tenant chain-signed
  audit emitter (`~/.mvm/audit/<tenant>.jsonl`) is plan-64's
  territory and already complete. The hard rows below all emit to
  the LocalAudit stream; their chain-signed counterparts (e.g.
  `plan.launched`) ride the existing supervisor middleware.
- **Not new behavior.** The plans surface existing emits behind new
  test fixtures. No verb gains a new emit kind; no operator-facing
  surface changes (modulo plan 65's pause-through-AnyBackend, which
  is the only intentional refactor).

## References

- **ADR-014** — `audit_emit!` macro convention
- **Plan 37 §6** — "no unaudited control-plane mutation"
- **Plan 60 Phase 4** — persistent observability
- **PR #106** — macro + lint + 37 emit-site migrations
- **PR #107** — cleanup host-fs refactor
- **PR #108** — MockBackend + up/down/set-ttl live coverage
- **Plans 65–70** — per-cluster hermetic-test work (this ADR scopes
  the architecture; the plans scope the implementation)
