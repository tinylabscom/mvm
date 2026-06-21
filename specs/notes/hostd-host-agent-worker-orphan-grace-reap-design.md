# mvm-host-agent worker — orphan grace-timer self-reap — Design + Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the one leak the child-side parent-death watchdog deliberately left open — the `mvm-host-agent` worker tree — without breaking the worker's by-design ability to outlive a wrapper restart.

**Depends on:** the parent-death watchdog + reaper (PR #1174, branch `fix/hostd-helper-parent-death-watchdog`). That PR added `mvm_hostd::parent_death::exit_when_orphaned()` to the five leaf moat bins and **excluded `mvm-host-agent` on purpose**. This note specifies the host-agent-specific replacement. **Must land after #1174 is merged.**

**Standing project rules that bind this work:** all `~/.mvm` / `~/.cache/mvm` paths go through `mvm_core::config`; reuse before reimplementing; many small testable functions + builder pattern; no `clippy::too_many_arguments` suppression; no spec/PR/plan citations in code comments; no `Co-Authored-By: Claude` trailer; `cargo fmt --all`; `cargo nextest run --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo test --workspace --doc` green before "done".

---

## Problem

The host-side moat bins reparent to launchd/init and leak when their supervisor
dies abnormally (a SIGKILL from `amfid` codesign on a test binary, or a
panic-abort — both skip every teardown path). #1174 fixes the **leaf** bins with
a `getppid`-based watchdog: the instant the parent dies, the child exits.

`mvm-host-agent` cannot use that mechanism. Its process model:

```
test / mvmctl  ──spawns──▶  host-agent (wrapper / supervisor mode)
                                  │ supervises + restarts
                                  ▼
                            host-agent (worker mode)  ──serves the broker socket──
                                  │ spawns
                                  ▼
                            signer-helper
```

The **worker is designed to outlive a wrapper restart**: a killed wrapper is
re-spawned by `ensure_host_agent_daemon`, and the existing worker keeps serving
the broker socket the whole time (the new wrapper reconnects via the pid file
rather than re-parenting the worker). This is asserted by
`wrapper_restart_restores_journaled_registration_and_chain` in
`crates/mvm-hostd/tests/host_agent_restart.rs`.

So from the worker's point of view a wrapper restart and a total-tree death look
**identical** through `getppid()` — both reparent it to pid 1. A `getppid`-based
self-reap (what #1174 installs in the leaf bins) would kill the worker
mid-restart. #1174 therefore leaves host-agent trees to the age-based reaper
(`just reap-helpers`) — correct but coarse (30-minute latency, manual/CI-cron
trigger). The host-agent + signer-helper trees were the **bulk** of the observed
orphans (≈97 + 51 of ≈170), so a tighter, automatic mechanism is worth it.

## Key insight

The signal the worker needs is not "do I still have a parent?" but **"does a
live wrapper still own me?"** A wrapper restart re-establishes wrapper liveness
within seconds; a total-tree death never does. So: when the worker is orphaned,
start a **grace timer**; if wrapper liveness returns before it expires, cancel
and continue serving; if the grace expires with no live wrapper, exit.

## Liveness signal — recommendation: wrapper-held advisory lock

Two candidate liveness signals:

1. **`daemon.pid` liveness (simpler).** The wrapper already writes its pid to
   `config::host_agent_dir(tenant).join("daemon.pid")` (see the fixture's
   `daemon_pid_path`). The worker re-reads it and probes with the existing
   `pid_alive()` helper (`kill(pid, 0)`) in `mvm-host-agent.rs`. Drawback: a
   stale dead pid sits in the file during the restart window, and pid recycling
   could make a dead wrapper look alive (low probability, but a real hole for a
   security-relevant daemon).

2. **Wrapper-held `flock` on a liveness file (recommended).** The wrapper takes
   `LOCK_EX` on `config::host_agent_dir(tenant).join("daemon.lock")` at startup
   and holds it for its whole life. The kernel **releases the lock on process
   death for any reason, including SIGKILL** — exactly the property we need, and
   immune to pid recycling. The worker, when orphaned, probes with
   `LOCK_EX | LOCK_NB` and immediately releases: failure (`EWOULDBLOCK`) ⇒ a live
   wrapper holds it ⇒ reset grace; success ⇒ no live wrapper ⇒ accrue grace. A
   restarted wrapper re-acquires the lock, so the worker sees liveness return.

**Recommendation: option 2 (flock).** It is the kernel-guaranteed,
pid-recycling-proof version of the same idea, and reuses an existing dir + an
existing dependency surface (`rustix`/`libc` `flock`, already in `mvm-hostd`).
Implement option 1's `pid_alive` re-read only as a secondary corroborating
check if review wants defence in depth.

> Caveat for tests: `fs2`/`flock` can return spurious `EWOULDBLOCK` under heavy
> parallel test load (known repo gotcha). The worker's probe must treat a single
> `EWOULDBLOCK` as "wrapper alive" (fail-safe toward *not* reaping), which is the
> correct bias anyway, so this caveat is benign for production; tests that assert
> the *reap* path must drive liveness to genuinely-free, not rely on a single
> probe.

## Design

- **Grace window:** `MVM_HOST_AGENT_ORPHAN_GRACE` (seconds), default `30`.
  Env-overridable so integration tests can set `1` and run fast. Bounds the
  worst-case leak window for a single tree to grace + one probe interval.
- **Probe interval:** fixed small constant (e.g. `500ms`), or derive as
  `min(1s, grace/4)`. The worker only probes while orphaned.
- **Where:** worker-mode path only (`run_worker_once`, reached when
  `is_worker_mode()` is true). Spawn a background watcher (a `tokio::task` on the
  worker runtime, or a dedicated thread mirroring `parent_death`'s style) that:
  1. waits until `getppid() == 1` (cheap poll, or reuse a parent-death edge),
  2. then enters the grace loop: probe wrapper liveness every interval; reset an
     `orphaned_since` instant whenever liveness is present; if
     `now - orphaned_since >= grace` with liveness continuously absent, call the
     same `_exit`-style reap `parent_death` uses.
- **Wrapper side:** acquire and hold the `daemon.lock` `flock` for the wrapper's
  lifetime (supervisor-mode path only). One small addition near where it writes
  `daemon.pid`.
- **Reuse:** `mvm_core::config::host_agent_dir`; the existing `pid_alive()`;
  `parent_death`'s orphan/exit primitives where they generalise (consider
  factoring a shared `orphan_exit()` / `is_orphaned()` out of `parent_death` so
  both call sites share one definition rather than duplicating).

## Testability — make the decision pure

Factor the grace decision into a pure function so it is unit-testable without
forking or timers:

```rust
/// Given whether a live wrapper is currently observed, the instant the worker
/// was first seen orphaned-without-a-wrapper, the current instant, and the grace
/// window, decide whether to reap.
fn should_reap(wrapper_alive: bool, orphaned_since: Option<Instant>, now: Instant, grace: Duration) -> bool
```

`wrapper_alive` resets `orphaned_since` to `None`; absence starts/continues it;
`should_reap` is `orphaned_since.is_some_and(|t| now - t >= grace)`.

## File structure

| File | Responsibility |
|------|----------------|
| `crates/mvm-hostd/src/parent_death.rs` *(modify)* | factor out shared `is_orphaned()` / `orphan_exit()` for reuse (optional but preferred). |
| `crates/mvm-hostd/src/host_agent_liveness.rs` *(create)* | wrapper-lock acquire helper; worker-side liveness probe; pure `should_reap`; the grace-loop watcher entrypoint. Small single-purpose fns. |
| `crates/mvm-hostd/src/lib.rs` *(modify)* | `pub mod host_agent_liveness;` |
| `crates/mvm-hostd/src/bin/mvm-host-agent.rs` *(modify)* | supervisor mode: acquire `daemon.lock`. worker mode: spawn the grace-loop watcher. Replace the "intentionally NOT armed" comment with a pointer to the new mechanism. |
| `crates/mvm-core/src/config.rs` *(modify, if needed)* | `host_agent_lock(tenant)` path helper alongside the pid helpers. |
| `crates/mvm-hostd/tests/host_agent_restart.rs` *(modify)* | new tests (below), driven with a short `MVM_HOST_AGENT_ORPHAN_GRACE`. |

## Tasks

- [ ] (optional) Factor `is_orphaned()` + `orphan_exit()` out of `parent_death` into a shared spot both modules use.
- [ ] Add `config::host_agent_lock(tenant)` (or reuse `host_agent_dir` join inline via a helper).
- [ ] Wrapper holds `LOCK_EX` on `daemon.lock` for its lifetime (supervisor-mode startup).
- [ ] `host_agent_liveness` module: `wrapper_alive()` probe (`LOCK_EX|LOCK_NB` then release), pure `should_reap`, and the grace-loop watcher.
- [ ] Worker spawns the watcher in `run_worker_once`; on decision, reap via `_exit`.
- [ ] Update the host-agent `main` comment + the `parent_death` module doc to describe the host-agent mechanism (it is no longer "reaper-only").
- [ ] Tests (below) green; full workspace gates green.
- [ ] Update `project_hostd_helper_parent_death_watchdog` memory + this note's status once landed.

## Test plan

- **Unit:** `should_reap` truth table — wrapper-alive never reaps; absence under
  grace doesn't reap; absence at/over grace reaps; a liveness blip resets the
  clock.
- **Integration — reaps on total death:** start the fixture with
  `MVM_HOST_AGENT_ORPHAN_GRACE=1`; kill the wrapper **and** do not restart;
  assert the worker pid is gone within ~grace + slack (poll `kill(pid,0)`).
- **Integration — survives a restart inside grace:** the existing
  `wrapper_restart_restores_journaled_registration_and_chain` must still pass
  with a short grace — kill wrapper, restart via `ensure_host_agent_daemon`
  inside the window, assert the worker still serves *and* is still alive after
  grace elapses (no false reap).
- **No regression:** `worker_restart_*` and `daemon_crash_mid_flight_*` stay
  green.

## Success criteria

1. A host-agent worker whose whole tree died self-reaps within
   `grace + one probe interval` — no dependence on the 30-minute age reaper.
2. A worker survives any wrapper restart that completes within the grace window
   (no behavioural regression to the restart contract).
3. `signer-helper` children follow the worker down (their #1174 watchdog fires
   when the worker exits), so the whole host-agent tree unwinds.
4. `just reap-helpers` remains as the long-tail backstop for anything that
   predates this change or escapes it.

## Out of scope

- The leaf-bin watchdog (#1174) — unchanged.
- A general supervisor/worker liveness framework — this is host-agent-specific;
  do not generalise speculatively (YAGNI).
- Linux vs macOS divergence — `flock` + `getppid` + `kill(pid,0)` are uniform
  across both, so this needs no per-OS path (unlike #1174's prctl/kqueue split).
