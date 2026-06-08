# Plan 170 — Host-side lifecycle convergence + single-host density (reconcile / idle-reaper / wake)

> **Status (2026-06-07):** WS-A **implemented** (PR #688); WS-B/C/D
> Proposed. Grounded in a
> review of an external single-machine sandbox control plane — an
> MIT-licensed Go service that pairs a container runtime, a reverse proxy,
> and an embedded SQLite store to run agent workloads behind preview URLs.
> It is a weaker *isolation* tier than mvm (hardened container isolation,
> default-off auth, open egress — its own docs say as much), so none of its
> security model transfers. What does transfer is its **host-daemon
> lifecycle model**: three background tasks — a boot-time reconciler
> ("converge the runtime back to the persistent store on every boot"), an
> idle-timeout **and** host-memory-pressure reaper, and a wake-on-request
> handler. The external project is **inspiration, not a dependency**; named
> obliquely per repo policy (the private oblique-reference key lives in
> auto-memory).
>
> **Numbering:** renumbered 169 → 170. 169 was claimed by the
> agent-RPC backend-agnostic-transport plan that merged to `main` first,
> which would trip the `check-spec-numbers` Lint gate (it hard-fails on a
> duplicate integer prefix); 170 is the next free number. Companion:
> **ADR-074** (registry-as-source-of-truth; converge at CLI entry, not a
> resident daemon).

## Context

mvm already owns every *primitive* that lifecycle trio is built from — they are
just fragmented across crates and never converged into one model, and two of
the three only run inside mvmd's resident supervisor, never on the plain
local `mvmctl` path:

| Lifecycle task | mvm primitive that exists today | Gap |
|---|---|---|
| reconcile-on-boot | `VmNameRegistry` (`{mvm_share_dir}/vm-names.json`, `crates/mvm/src/vm/name_registry.rs`) + `cache prune --reap-orphans` (`crates/mvm-cli/src/commands/ops/cache.rs`) | Reconciliation is **manual** (`cache prune`) and **lazy** (drift surfaces at use-time, then fails). No automatic convergence pass. |
| idle/pressure reaper | `mvm_hostd::supervisor::reaper::Reaper` (`crates/mvm-hostd/src/supervisor/reaper.rs`) | TTL-only — keys off `VmRegistration.expires_at` wall-clock. **No idle-activity trigger, no host-memory-pressure eviction.** Spawned only by mvmd's supervisor daemon + the MCP dispatcher (`ops/mcp.rs::spawn_reaper`), never on a bare `mvmctl` invocation. |
| wake-on-request | `instance_wake()` (`crates/mvm/src/vm/instance/lifecycle.rs:555`) + `VmRegistration.auto_resume` ("connecting to a sleeping VM auto-resumes it") + `sleeping_count` quota (`vm/tenant/quota.rs`) | Wake exists; the **stop-on-idle *trigger* that creates a sleeping VM is missing** — sleep today is only explicit (`mvmctl pause`). No `last_active` timestamp to key idle off. |

The standing pain this addresses is documented across auto-memory: the
libkrun.pid-vs-socket race in the core_demo chain, the Stage 0 stale-crate
bail, and the degraded-builder-store loop where `dev up` spins with no
self-heal and only `rm -rf ~/.cache/mvm/builder-vm` recovers. Every one of
those is **stale host-side state discovered lazily at use-time**. That model's
answer — a single idempotent convergence pass that makes the persistent
registry the source of truth and rebuilds runtime reality to match — is the
direct structural fix, and the density lever (idle-stop + pressure-evict) is
the same reaper extended. The user already runs parallel `mvmctl` sessions on
one Mac (isolated via `MVM_CACHE_DIR`/`MVM_DATA_DIR`), so single-host density
is a live concern, not a fleet abstraction.

**mvm / mvmd boundary.** Fleet warm-pool orchestration and wake-time
*admission policy* stay in mvmd (Plan 140 already draws this line;
`../mvmd/specs/plans/53-warm-pool-ms-restore.md`). This plan delivers only the
**local single-host mechanism** that lives in this repo: the registry, the
reaper, the wake trigger, the convergence pass. mvmd consumes the same
`mvm_hostd::supervisor::reaper` library it already does.

**`mvmctl` is a CLI, not a resident daemon.** That control plane "converges on
every boot" because it *is* a long-lived process. mvm's local path is one-shot CLI
invocations. So "converge on boot" maps to **converge at CLI entry for any
state-touching command** (`up` / `start` / `run` / `console` / `down` /
`status` / `dev *`) plus an explicit `mvmctl reconcile` verb — not a new
resident process. ADR-074 records this adaptation.

## Workstreams

### WS-A — Reconcile-on-entry convergence (the core fix) — **DONE (PR #688)**

Make `VmNameRegistry` the source of truth and converge on-disk runtime reality
to it, cheaply, at the start of every state-touching command.

- [x] Add `mvm::vm::reconcile` — pure-logic-first `classify`/`sweep`
      (testable without a real backend, mirroring `reaper.rs`'s `sweep`): for
      each `VmRegistration`, classify as `Live` / `DeadProcessLeftState` /
      `RecordNoState`, plus `OrphanStateNoRecord` for unrecorded state dirs.
      Liveness = `kill(pid, 0)` on the recorded supervisor pid files
      (`libkrun.pid` / `vz.pid` / `pid`) — the cheap half of the live-vs-orphan
      discrimination from `env::apple_container::reap_orphaned_vm_helpers`,
      restated as a bare syscall because the lower `mvm` crate can't depend on
      `mvm-cli`. Intentionally-paused records are skipped.
- [x] Convergence actions, all idempotent: dead-process records → tear down
      leftover state + deregister; orphan state dirs with no record → reap;
      record pointing at vanished state → drop the stale record (the "stale
      `mvmctl pause` against a vanished VM" failure family). `converge()` fails
      open and emits a `RegistryReconcile` audit line per healed item.
      `FsRuntimeView`/`FsReconcileActions` are the real adapter; `converge_at`
      is the path-injectable load/save seam.
- [x] Wire a **cheap** `converge()` call into CLI entry for state-touching
      commands behind `MVM_SKIP_RECONCILE=1` (escape hatch, never set in CI).
      Cheap = registry read + PID liveness stat only; never spawns a VM, never
      touches Nix. Gated by `Commands::touches_vm_state()`
      (up/down/run/console/dev/pause/resume/snapshot/ls); read-only / VM-agnostic
      commands skip it; `reconcile` itself never double-runs.
- [x] Add `mvmctl reconcile [--dry-run] [--json]` as the explicit, observable
      entry point (sibling to `cache prune`). `--json` emits the
      `ConvergeReport` for scripting; `doctor` gained a one-line "registry
      drift: N reconciled / clean" summary.

### deferred follow-ups (WS-A)

- [ ] **Self-heal the degraded-builder-store loop.** `converge()` detects the
      dangling-GC'd `…-source/flake.nix does not exist` builder state and, with
      `--repair`, clears `~/.cache/mvm/builder-vm` rather than letting `dev up`
      spin. Closes the recovery side noted against that failure family. Deferred
      from PR #688 — the builder-store probe is heavier than the PID-liveness
      budget and wants its own slice.

### WS-B — Activity-driven idle reaper (stop-on-idle) — **mvm-side mechanism DONE (PR #696)**

Extend the TTL reaper from wall-clock-only to TTL **or** idle-timeout, and have
idle expiry *sleep* (drain/pause) rather than tear down — so the workspace
persists and WS-C's wake brings it back.

- [x] Add `last_active` to `VmRegistration` (stored as `Option<String>`
      RFC3339 for consistency with `registered_at`/`expires_at`; `#[serde(default)]`,
      backward-compatible — absent = treat as `registered_at`). `touch_last_active`
      is called on console attach and successful `wake` (coarse touch — the
      per-vsock-request sharpening stays in deferred follow-ups, where the plan
      already parks it).
- [x] Extend `reaper::sweep` with `IdleSlept`/`SleepFailed` outcomes alongside
      `Reaped`: when `now - last_active > idle_timeout` **and** `auto_resume`
      **and** `!paused`, invoke an injected `SleepFn`, then flip `paused = true`
      so the next tick skips it. TTL `expires_at` still hard-reaps and **wins over
      idle**. Opt-in + additive: `Reaper::new` stays TTL-only;
      `Reaper::with_idle_sleep(sleep, default_timeout)` enables it. The ±10 s tick
      jitter is untouched.
- [x] Idle timeout config: `MVM_IDLE_TIMEOUT` env (`global_idle_timeout_from_env`)
      + per-VM `idle_timeout_secs` tag override (`resolve_idle_timeout`; `0` opts a
      workload out), default off (opt-in) so a plain `mvmctl start` is unchanged.
- [ ] **Backend-aware `SleepFn` + the resident loop that calls
      `with_idle_sleep` are mvmd-side.** The reaper exposes the hook; the concrete
      sleep (drain+snapshot for `caps.snapshots` backends; clean stop with data
      disk + TAP retained for libkrun/apple-container — disk/TAP retention already
      exists at `lifecycle.rs:454/523`) and the timer that ticks it live in mvmd's
      supervisor. By ADR-074 the local `mvmctl` path has **no resident daemon**, so
      there is nothing on the bare-CLI path to tick an idle loop; idle-sleep fires
      under a long-lived consumer (mvmd's supervisor / the MCP dispatcher). Also
      mvmd: add `IdleSlept`/`SleepFailed` arms to any exhaustive `ReapOutcome`
      match. No new snapshot code; this is a *trigger*, not a new mechanism.

### WS-C — Host-memory-pressure reaper (single-host density)

Evict (sleep) the least-recently-active VMs when the host is under RAM
pressure, so "dozens share one box" works on the user's Mac without manual
babysitting.

- [ ] Add a pressure-driven sweep to the reaper: read host memory via `sysinfo`
      (already a dep — `balloon_runtime.rs` uses it), and when free RAM drops
      below `MVM_HOST_MEM_LOW_WATERMARK`, sleep VMs in `last_active`-ascending
      order until back above the high watermark. LRU eviction, never kill —
      sleep + persist, same path as WS-B.
- [ ] **Reconcile against the existing balloon lever before evicting.** mvm
      already reclaims guest memory via `BalloonController` / `run_balloon_loop`
      (`balloon_runtime.rs`). Order of escalation: balloon-reclaim first (cheap,
      transparent), sleep-evict only when ballooning is exhausted. Document the
      two-stage policy so they don't fight.
- [ ] This is the mvm-side mechanism only; mvmd's fleet scheduler may layer its
      own cross-host policy on top via the same `reaper` library. Note the seam,
      don't build the fleet side here.

### WS-D — Wake-on-request completion

Close the loop so a slept VM (WS-B/C) comes back on first contact.

- [ ] Audit every guest-contact entry point (`mvmctl console`, vsock agent
      dispatch, `forward`) to honor `auto_resume`: if the target is slept,
      `instance_wake()` it, refresh `last_active`, then proceed. `instance_wake`
      already does fresh secrets/config disks + clock/entropy concerns (Plan 140
      gaps) — depend on, don't duplicate.
- [ ] Emit the lifecycle transitions (`vm.slept_idle`, `vm.slept_pressure`,
      `vm.woke`) to the shared local audit log via `audit_emit!`, consistent
      with the Stage 0 audit-emit contract — so density behavior is observable
      and `audit verify` still chains.

## Verification

- [ ] `converge()` unit tests over a synthetic registry: each classification
      (`Live`/`DeadProcessLeftState`/`OrphanStateNoRecord`/`RecordNoState`) →
      correct idempotent action; running twice is a no-op (convergence is stable).
- [ ] Reaper unit tests extended: idle → `IdleSlept` (not `Reaped`); TTL still
      hard-reaps; pressure sweep evicts LRU-first and stops at the high watermark;
      `auto_resume=false` is never auto-slept.
- [ ] Integration (macOS/Vz + libkrun, on this host per auto-memory): start two
      workloads, force one idle past `MVM_IDLE_TIMEOUT`, assert it sleeps and the
      other survives; `mvmctl console` the slept one and assert wake; kill a VM's
      supervisor PID out-of-band and assert the next `mvmctl status` converges the
      stale record instead of erroring.
- [ ] `cargo fmt --all -- --check` (nightly per CI), `cargo nextest run
      --workspace -E 'not package(mvm-backend)'` locally (mvm-backend SIGKILL on
      macOS codesign — auto-memory), full suite on Linux CI, `cargo clippy
      --workspace -- -D warnings`, doctests.

## Non-goals

- No fleet/cross-host scheduling — mvmd (Plan 140 / mvmd Plan 53).
- No new snapshot/restore mechanism — WS-B/C are *triggers* over the existing
  pause/drain/wake machinery; the four FC restore-correctness gaps stay Plan 140.
- No resident local daemon. Convergence is a CLI-entry pass (ADR-074). The
  resident reaper loop remains mvmd's supervisor / the MCP dispatcher.
- No change to the isolation posture or any of claims 1–15. This is host-side
  lifecycle bookkeeping; it never touches the guest trust boundary.

## Deferred follow-ups

- [ ] `last_active` could be sharpened from coarse touch-points to real guest
      activity (vsock byte counters via the Plan 141 packet-observer) — deferred;
      coarse touch is enough for stop-on-idle v1.
- [ ] A `warming page` analog for HTTP-preview workloads (the external control
      plane serves one during cold wake) only matters once mvm grows preview-URL routing — that is
      mvmd product surface, tracked there, not here.
