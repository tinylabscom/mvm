# mvm-host-agent daemon — idle-registration self-termination — Design + Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reap the resident `mvm-host-agent` daemon (and its worker + signer-helper) automatically once it has no work, so abandoned daemons stop accumulating — without losing the warm-daemon benefit during active use.

**Depends on:** the parent-death watchdog + reaper (PR #1174, merged). This is the host-agent-specific complement #1174 deferred. Must land after #1174.

**Standing project rules that bind this work:** all `~/.mvm` / `~/.cache/mvm` paths go through `mvm_core::config`; reuse before reimplementing; many small testable functions + builder pattern; no `#[allow(clippy::too_many_arguments)]`; no spec/PR/plan/ADR citations in code comments; no `Co-Authored-By: Claude` trailer; `cargo fmt --all`; `cargo nextest run --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo test --workspace --doc` green before "done".

---

## Why the obvious approach (a worker parent-death watchdog) is wrong

The first design for this follow-up keyed a watchdog on *wrapper liveness*. It
does not work, because of how the daemon is spawned. `ensure_host_agent_daemon`
(`crates/mvm-backend/src/host_agent_spawn.rs`) launches the supervisor via
`spawn_detached_with_config`, which calls **`setsid()` in `pre_exec`**
(`crates/mvm-backend/src/broker_services_spawn.rs:314`). The supervisor is a
**detached, resident daemon** — `ppid == 1` by design, deliberately outliving
`mvmctl up` so it stays warm.

So the dominant leak — a CLI/test process killed abnormally (the `amfid`
codesign SIGKILL, a panic) before its teardown runs — plays out as:

1. the detached daemon's parent dies, but the daemon **keeps running** (it is
   resident; orphaning does not kill it);
2. nothing reaps it, because the thing that would (the CLI/test, via the pid
   file) is gone;
3. its worker and signer-helper stay up under it.

A `getppid`/lock-liveness watchdog cannot help here: the daemon is *supposed* to
be parentless, and it is alive, so any liveness signal keyed on it reads
"healthy." The leak is not "the worker outlived its supervisor" — it is "the
supervisor outlived everything it was doing." The unit to reap is the **daemon
itself, when it has no registrations.**

## Design — idle-registration self-termination

The daemon already tracks live registrations: `HostAgentDaemon::registration_count()`
(`crates/mvm-hostd/src/broker/daemon.rs:240`, returns `self.vms.len()`), updated
on every `RegisterVm`/`DeregisterVm` and persisted to `registrations.json`. Use
it:

- The **worker** (`run_worker_once` → `HostAgentDaemon::run_shared`, which holds
  the live count behind `Arc<Mutex<HostAgentDaemon>>`) runs an **idle watcher**:
  when `registration_count()` has been `0` continuously for the idle timeout, it
  terminates the process with a distinct **idle-shutdown exit code**.
- The **wrapper** (`supervise_worker`) already loops restarting the worker. On a
  worker exit carrying the idle-shutdown code it must **not restart** — reap the
  worker group, remove the pid file, and return `Ok(())` so the whole daemon
  tree exits. (The signer-helper, a child of the worker, then exits via its #1174
  parent-death watchdog.)

During active development the daemon stays warm exactly as today: any registered
VM keeps `registration_count() >= 1`, so the idle clock never starts.

### Idle timeout

- Env `MVM_HOST_AGENT_IDLE_TIMEOUT` (whole seconds). **Unset ⇒ default 300s**
  (5 min warm window). **`0` ⇒ disabled** (never idle-exit — the escape hatch
  for users who want a permanently warm daemon). Positive ⇒ that many seconds.
- Parse into a pure helper `parse_idle_timeout(raw: Option<&str>) -> Option<Duration>`
  returning `None` for disabled, `Some(d)` otherwise — unit-testable without env.

### Idle decision (pure)

```rust
/// True iff idle-exit is enabled, no registrations are live, and the
/// registration count has been zero at least `timeout`.
fn should_idle_exit(count: usize, zero_since: Option<Instant>, now: Instant, timeout: Option<Duration>) -> bool
```

`count > 0` clears `zero_since`; `count == 0` starts it (only if `None`, so the
clock measures *continuous* idleness, not the latest tick); `should_idle_exit`
is `timeout.is_some_and(|t| count == 0 && zero_since.is_some_and(|z| now.duration_since(z) >= t))`.

### Exit-code contract

A single shared constant — `pub const IDLE_SHUTDOWN_EXIT_CODE: i32 = 42;` — in
the new module, referenced by **both** the worker (exits with it) and the
wrapper (recognizes it via `ExitStatus::code() == Some(IDLE_SHUTDOWN_EXIT_CODE)`).
No magic-number duplication.

### Wiring the worker exit

`run_shared` is an infinite `accept()` loop with no shutdown hook. The idle
watcher is a sibling `tokio::task` spawned in `run_worker_once` sharing the
`Arc<Mutex<HostAgentDaemon>>`; on the idle decision it calls
`std::process::exit(IDLE_SHUTDOWN_EXIT_CODE)`. Abrupt exit is safe here *by
definition* — idle means zero registrations and nothing in flight. (An
implementer who prefers a graceful unbind may instead thread a shutdown signal
into `run_shared` via `tokio::select!` and return a sentinel `main` maps to the
exit code; either is acceptable as long as the wrapper-side contract holds.)

## Testability

Pure, no forks/timers needed for the core:
- `parse_idle_timeout`: `None`→Some(300s); `"0"`→None; `"5"`→Some(5s); `"abc"`→Some(300s default).
- `should_idle_exit`: disabled (timeout None) never exits; count>0 never exits; count==0 under timeout doesn't; count==0 at/over timeout exits; a registration blip resets the clock.
- A pure `is_idle_shutdown(code: Option<i32>) -> bool` for the wrapper's classification.

## File structure

| File | Responsibility |
|------|----------------|
| `crates/mvm-hostd/src/host_agent_idle.rs` *(create)* | `IDLE_SHUTDOWN_EXIT_CODE`, `parse_idle_timeout`, `idle_timeout()` (env reader), pure `should_idle_exit`, `is_idle_shutdown`, and the async `run_idle_watcher(daemon, timeout)` loop. Small single-purpose fns + unit tests. |
| `crates/mvm-hostd/src/lib.rs` *(modify)* | `pub mod host_agent_idle;` (alphabetical). |
| `crates/mvm-hostd/src/bin/mvm-host-agent.rs` *(modify)* | worker: spawn `run_idle_watcher` in `run_worker_once`. wrapper: in `supervise_worker`, on a worker exit whose code `is_idle_shutdown`, reap + remove pid file + `return Ok(())` instead of restarting. Replace the #1174 "intentionally NOT armed" comment with a pointer to this mechanism. |
| `crates/mvm-hostd/src/parent_death.rs` *(modify, doc only)* | update the parenthetical that says host-agent leaks are "the reaper's job" to note the idle-timeout. |
| `crates/mvm-hostd/tests/host_agent_restart.rs` *(modify)* | new integration test (below), short `MVM_HOST_AGENT_IDLE_TIMEOUT`. |

## Tasks

- [ ] `host_agent_idle` module: constant, `parse_idle_timeout`, `idle_timeout()`, pure `should_idle_exit` + `is_idle_shutdown`, async `run_idle_watcher` + unit tests. Register in `lib.rs`. (library-only)
- [ ] Wire worker (`run_worker_once` spawns the watcher) + wrapper (`supervise_worker` honors the exit code, no restart) + doc-comment updates.
- [ ] Integration test: idle daemon self-terminates; plus no-regression on the existing restart tests.
- [ ] Update `project_hostd_helper_parent_death_watchdog` memory + this note's status once landed.

## Test plan

- **Unit:** `parse_idle_timeout` + `should_idle_exit` + `is_idle_shutdown` truth tables (above).
- **Integration — idle daemon self-terminates:** start the fixture with
  `MVM_HOST_AGENT_IDLE_TIMEOUT=1`, `deregister` its VM (or start one that never
  registers), and assert the daemon pid (and worker) are gone within
  ~timeout + slack (poll `kill(pid, 0)`). Confirm the wrapper did **not**
  respawn the worker (the tree is gone, not bounced).
- **No regression:** `wrapper_restart_*`, `worker_restart_*`, and
  `daemon_crash_mid_flight_*` still pass — they hold a registration for their
  duration, so with the default (or unset) timeout the idle clock never starts.
  These tests run well under any sane timeout; do not set a short timeout in
  them.

## Success criteria

1. A daemon with zero registrations for the timeout self-terminates its whole
   tree (worker + signer-helper), with no dependence on the 30-minute age reaper.
2. `MVM_HOST_AGENT_IDLE_TIMEOUT=0` disables idle-exit (permanently warm).
3. A registered VM keeps the daemon warm indefinitely (no behavioural change to
   active-use warmth).
4. No regression to the host-agent restart/crash contract tests.
5. `just reap-helpers` remains the long-tail backstop for anything that escapes.

## Out of scope

- The leaf-bin parent-death watchdog (#1174) — unchanged.
- Flock/liveness-based worker reaping — rejected above (the detached daemon
  defeats it).
- A general daemon-lifecycle framework — host-agent-specific; no speculative
  generalisation (YAGNI).
- Per-OS divergence — `registration_count` + an exit code are uniform; no
  prctl/kqueue split.
