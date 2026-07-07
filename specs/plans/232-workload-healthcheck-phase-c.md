# Workload Healthcheck Phase C (probing + bounded restart) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Actively probe a persistent service's healthcheck on an interval, track a health state shown in `machine ls`/`inspect`, and restart a failed service under a bounded (backoff + max-attempts) policy.

**Architecture:** The resident per-tenant `mvm-host-agent` daemon gains a probe pass on its periodic tick: it loads each registered machine's persisted `MachineSpec.health_check`, runs the check in the guest via `send_exec_streaming`, folds the result through a pure health-state reducer, records the state through the shared readiness seam, and (on failure) restarts the whole VM by spawning `mvmctl machine restart`. Transient tasks are unaffected — their exit code is their verdict (phase A).

**Tech Stack:** Rust; `mvm-hostd` (daemon), `mvm-guest::vsock` (agent exec), `mvm` (`name_registry`, `machine::persist`), `mvm-cli` (`machine ls`/`inspect`/`restart`), `mvm-core` (`InstanceReadiness`).

**Design:** `specs/notes/2026-07-07-workload-healthcheck-phase-c-design.md`. Builds on phase A (`specs/plans/231-workload-healthcheck-lifecycle.md`).

## Global Constraints

- **No spec references in code comments** (`Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` are CI-banned via `xtask check-no-spec-refs-in-comments`). Reword to the concept.
- **No `schema_version` bump.** New serde fields are `#[serde(default = ...)]` and skip-serialize when absent.
- **Exec-form probe only** (guest is vsock-only). Use `mvm_guest::vsock::send_exec_streaming` directly — NOT `console::run` (it calls `std::process::exit` on non-zero/timeout, which would kill the loop).
- **Scope: accessible/dev-tier persistent services** (`machine run`). Sealed-prod (agent-without-exec) is out of scope.
- **Reuse the readiness seam** (`record_vm_readiness`) — do not reinvent registry writes. Map `Starting→ServicesStarting`, `Healthy→ServicesReady`, `Unhealthy→Degraded`.
- **HealthCheck fields (from phase A, `mvm_sdk::ir::HealthCheck`):** `command: Vec<String>`, `interval_secs: u32` (default 30), `timeout_secs: u32` (5), `retries: u32` (3), `start_period_secs: u32` (0). Phase C is the first consumer of the timing fields.
- **Restart bound:** exponential backoff base 1s, cap 300s; `MAX_RESTART_ATTEMPTS = 5`; reset after one full `interval` sustained Healthy.
- **Test gate:** `MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace`; `cargo test --workspace --doc`; `cargo clippy --workspace -- -D warnings`; `cargo fmt --all -- --check`; `cargo run -p xtask -- check-no-spec-refs-in-comments`. Two known pre-existing local failures unrelated to this work: `doctor::collect_security_posture_returns_a_real_tier` and `embedded_binaries::each_embedded_binary_starts_with_elf_magic`.
- **Rebase note:** this branch stacks on phase A (unmerged) off an older main; before merge, rebase onto current `origin/main` (target files confirmed intact). Build Task 0 against the current-main HVF path.

---

## File Structure

- `crates/mvm-core/src/health.rs` (new) — the pure health-state reducer + `HealthState`, backoff/attempt logic. Foundation, no deps. (Task 1, 5)
- `crates/mvm/src/vm/name_registry.rs` — lift a crate-agnostic `record_readiness(vm_name, InstanceReadiness)` here so both `mvm-cli` and `mvm-hostd` call it. (Task 2)
- `crates/mvm-hostd/src/health_probe.rs` (new) — `probe_once` (host→guest exec) + the daemon tick pass that ties reducer + probe + readiness + restart together. (Tasks 3, 4, 6, 7)
- `crates/mvm-cli/src/commands/vm/readiness.rs` — redirect `record_vm_readiness` to the lifted helper. (Task 2)
- `crates/mvm-cli/src/commands/machine/mod.rs` — `machine ls` health column + `machine inspect` health field. (Task 4)
- `crates/mvm-backend/src/hvf_backend.rs` — S0 daemon wiring if missing. (Task 0)
- `public/src/content/docs/reference/cli-commands.md` — document the probing/restart behavior. (Task 8)

---

## Task 0: De-risk — host-agent daemon runs for a healthchecked machine on HVF

**Files:**
- Investigate: `crates/mvm-backend/src/hvf_backend.rs` (`start`), `crates/mvm-backend/src/libkrun.rs:636-666` + `crates/mvm-backend/src/vz.rs:423-433` (the working `register_host_agent_services_if_admitted` call sites), `crates/mvm-backend/src/host_agent_spawn.rs`.
- Modify (only if the wiring is absent): `crates/mvm-backend/src/hvf_backend.rs`.

This is a spike whose deliverable is a proven fact + any wiring needed to make it true. No new test logic beyond the manual check unless you add wiring (then a unit test for the added call path).

- [ ] **Step 1: Determine whether HVF wires the daemon.** Read `libkrun.rs`/`vz.rs` `start()` to see how they call `register_host_agent_services_if_admitted(...)`, then check whether `hvf_backend.rs::start` makes the equivalent call. Record the finding.

- [ ] **Step 2: Prove it end-to-end on this host (macOS HVF).**

```bash
MVM_SKIP_EMBED_BINARIES=1 cargo build --bin mvmctl
./target/debug/mvmctl machine run -d --image alpine --healthcheck 'true' -- sleep 600
# find the tenant's host-agent daemon pid file + control socket:
ls "$(./target/debug/mvmctl doctor --json 2>/dev/null | true)"   # or inspect ~/.mvm / ~/.cache for host-agent daemon.pid
pgrep -fl mvm-host-agent
./target/debug/mvmctl machine stop <name>
```
Expected: a `mvm-host-agent` process is running while the machine is up, and it goes away after stop. If NO daemon appears, HVF isn't wiring it.

- [ ] **Step 3 (only if absent): wire it.** Mirror the `libkrun.rs`/`vz.rs` call — add the same `register_host_agent_services_if_admitted(&config, ...)` invocation in `hvf_backend.rs::start()` at the point the VM is confirmed booted and `config.tenant_id` is `Some`. Add a focused unit test asserting the call path is taken for an admitted config (follow the pattern of the libkrun/vz tests if present).

- [ ] **Step 4: Re-run Step 2 to confirm the daemon now runs for a healthchecked HVF machine. Commit** (code + a note in the report of the proven fact).

```bash
git add -A && git commit -m "fix(hvf): register the host-agent daemon for admitted HVF machines"   # or "chore: confirm HVF daemon wiring (no change needed)"
```

**If the daemon fundamentally cannot run on HVF (BLOCKED):** stop and escalate — the design's fallback (probe thread in the per-VM supervisor) is a materially different plan.

---

## Task 1: Pure health-state reducer

**Files:**
- Create: `crates/mvm-core/src/health.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod health;`)
- Test: inline `#[cfg(test)] mod tests` in `health.rs`

**Interfaces:**
- Produces:
  - `enum ProbeResult { Pass, Fail }`
  - `enum HealthState { Starting, Healthy, Unhealthy }`
  - `struct HealthTracker { state: HealthState, consecutive_failures: u32, started_at_unix: u64, last_healthy_at_unix: Option<u64>, restart_attempts: u32, next_restart_after_unix: Option<u64> }`
  - `struct HealthPolicy { interval_secs: u32, timeout_secs: u32, retries: u32, start_period_secs: u32, backoff_base_secs: u64, backoff_cap_secs: u64, max_restart_attempts: u32 }` with `HealthPolicy::from_ir(&mvm_sdk::ir::HealthCheck) -> HealthPolicy` — WAIT: `mvm-core` must not depend on `mvm-sdk` (mvm-sdk depends on mvm-core). So `HealthPolicy` holds the raw numbers; the *caller* (mvm-hostd) builds it from the `HealthCheck`. Do NOT reference `mvm_sdk` here.
  - `enum HealthAction { None, Restart, GiveUp }` — what the daemon should do after folding a result.
  - `fn fold(tracker: &mut HealthTracker, result: ProbeResult, policy: &HealthPolicy, now_unix: u64) -> HealthAction`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> HealthPolicy {
        HealthPolicy { interval_secs: 10, timeout_secs: 5, retries: 3, start_period_secs: 30,
                       backoff_base_secs: 1, backoff_cap_secs: 300, max_restart_attempts: 5 }
    }
    fn tracker(now: u64) -> HealthTracker {
        HealthTracker { state: HealthState::Starting, consecutive_failures: 0, started_at_unix: now,
                        last_healthy_at_unix: None, restart_attempts: 0, next_restart_after_unix: None }
    }

    #[test]
    fn failures_during_start_period_do_not_count() {
        let mut t = tracker(1000);
        // 5s in, still inside the 30s start period
        assert_eq!(fold(&mut t, ProbeResult::Fail, &policy(), 1005), HealthAction::None);
        assert_eq!(t.state, HealthState::Starting);
        assert_eq!(t.consecutive_failures, 0);
    }

    #[test]
    fn pass_becomes_healthy() {
        let mut t = tracker(1000);
        assert_eq!(fold(&mut t, ProbeResult::Pass, &policy(), 1005), HealthAction::None);
        assert_eq!(t.state, HealthState::Healthy);
        assert_eq!(t.last_healthy_at_unix, Some(1005));
    }

    #[test]
    fn retries_consecutive_failures_then_unhealthy_and_restart() {
        let mut t = tracker(1000);
        fold(&mut t, ProbeResult::Pass, &policy(), 1005); // Healthy, past this point failures count
        assert_eq!(fold(&mut t, ProbeResult::Fail, &policy(), 1040), HealthAction::None);
        assert_eq!(fold(&mut t, ProbeResult::Fail, &policy(), 1050), HealthAction::None);
        // third consecutive failure (retries=3) -> Unhealthy + Restart
        assert_eq!(fold(&mut t, ProbeResult::Fail, &policy(), 1060), HealthAction::Restart);
        assert_eq!(t.state, HealthState::Unhealthy);
        assert_eq!(t.restart_attempts, 1);
    }

    #[test]
    fn recovery_resets_failures_and_backoff() {
        let mut t = tracker(1000);
        fold(&mut t, ProbeResult::Pass, &policy(), 1005);
        fold(&mut t, ProbeResult::Fail, &policy(), 1040);
        fold(&mut t, ProbeResult::Pass, &policy(), 1050);
        assert_eq!(t.state, HealthState::Healthy);
        assert_eq!(t.consecutive_failures, 0);
    }

    #[test]
    fn gives_up_after_max_restart_attempts() {
        let mut t = tracker(1000);
        t.state = HealthState::Unhealthy;
        t.restart_attempts = 5; // == max
        assert_eq!(fold(&mut t, ProbeResult::Fail, &policy(), 2000), HealthAction::GiveUp);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-core --lib health::`
Expected: FAIL — module/types not defined.

- [ ] **Step 3: Implement `health.rs`**

```rust
//! Host-observed liveness state for a persistent service: fold periodic probe
//! results into a health state and decide whether to restart. Pure logic — the
//! daemon supplies probe results, the clock, and the policy; this module owns no
//! I/O so it is exhaustively unit-testable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthAction {
    None,
    Restart,
    GiveUp,
}

#[derive(Debug, Clone)]
pub struct HealthPolicy {
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub retries: u32,
    pub start_period_secs: u32,
    pub backoff_base_secs: u64,
    pub backoff_cap_secs: u64,
    pub max_restart_attempts: u32,
}

#[derive(Debug, Clone)]
pub struct HealthTracker {
    pub state: HealthState,
    pub consecutive_failures: u32,
    pub started_at_unix: u64,
    pub last_healthy_at_unix: Option<u64>,
    pub restart_attempts: u32,
    pub next_restart_after_unix: Option<u64>,
}

impl HealthTracker {
    pub fn new(started_at_unix: u64) -> Self {
        Self {
            state: HealthState::Starting,
            consecutive_failures: 0,
            started_at_unix,
            last_healthy_at_unix: None,
            restart_attempts: 0,
            next_restart_after_unix: None,
        }
    }
}

/// Fold one probe result into the tracker and return what the daemon should do.
pub fn fold(
    tracker: &mut HealthTracker,
    result: ProbeResult,
    policy: &HealthPolicy,
    now_unix: u64,
) -> HealthAction {
    let in_start_period =
        now_unix < tracker.started_at_unix + u64::from(policy.start_period_secs);

    match result {
        ProbeResult::Pass => {
            tracker.state = HealthState::Healthy;
            tracker.consecutive_failures = 0;
            tracker.last_healthy_at_unix = Some(now_unix);
            // A sustained-healthy period resets the restart budget.
            tracker.restart_attempts = 0;
            tracker.next_restart_after_unix = None;
            HealthAction::None
        }
        ProbeResult::Fail => {
            if in_start_period {
                // Grace: failures during startup do not count and do not flip state.
                return HealthAction::None;
            }
            tracker.consecutive_failures = tracker.consecutive_failures.saturating_add(1);
            if tracker.consecutive_failures < policy.retries.max(1) {
                return HealthAction::None;
            }
            tracker.state = HealthState::Unhealthy;
            if tracker.restart_attempts >= policy.max_restart_attempts {
                return HealthAction::GiveUp;
            }
            tracker.restart_attempts = tracker.restart_attempts.saturating_add(1);
            let backoff = backoff_secs(tracker.restart_attempts, policy);
            tracker.next_restart_after_unix = Some(now_unix + backoff);
            tracker.consecutive_failures = 0;
            HealthAction::Restart
        }
    }
}

/// Exponential backoff for the Nth restart attempt (1-based), capped.
pub fn backoff_secs(attempt: u32, policy: &HealthPolicy) -> u64 {
    let shift = attempt.saturating_sub(1).min(32);
    policy
        .backoff_base_secs
        .saturating_mul(1u64 << shift)
        .min(policy.backoff_cap_secs)
}
```

Add `pub mod health;` to `crates/mvm-core/src/lib.rs` (alphabetical with the other `pub mod`s).

- [ ] **Step 4: Run to verify pass**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-core --lib health::`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/health.rs crates/mvm-core/src/lib.rs
git commit -m "feat(core): pure health-state reducer for service liveness"
```

---

## Task 2: Lift the readiness recorder so the daemon can write it

**Files:**
- Modify: `crates/mvm/src/vm/name_registry.rs` (add `pub fn record_readiness`)
- Modify: `crates/mvm-cli/src/commands/vm/readiness.rs` (delegate to it)
- Test: `name_registry.rs` tests module

**Interfaces:**
- Produces: `mvm::vm::name_registry::record_readiness(vm_name: &str, readiness: mvm_core::domain::instance::InstanceReadiness)` — best-effort: load registry, `set_readiness`, save; warn-and-return on error, never panics/gates.

- [ ] **Step 1: Write the failing test** (in `name_registry.rs` tests)

```rust
#[test]
fn record_readiness_updates_existing_entry() {
    let _g = crate::vm::name_registry::test_lock(); // reuse the module's existing test isolation if present; else set MVM_DATA_DIR to a tempdir
    // register a machine, then record readiness, then reload and assert
    // (follow the existing register/load test pattern in this module)
    let name = "hc-test";
    // ... register `name` via the module's existing helper ...
    record_readiness(name, mvm_core::domain::instance::InstanceReadiness::ServicesReady);
    let reg = VmNameRegistry::load(&registry_path()).unwrap();
    assert!(matches!(
        reg.entry(name).and_then(|e| e.readiness.clone()),
        Some(mvm_core::domain::instance::InstanceReadiness::ServicesReady)
    ));
}
```
Match the module's existing registration/test-isolation helpers (search the tests module for how other tests create + load a registry). Use those, not invented helpers.

- [ ] **Step 2: Run to verify failure** — `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm --lib record_readiness` → FAIL (fn missing).

- [ ] **Step 3: Implement** — move the body of `mvm-cli`'s `record_vm_readiness` here (it already uses `mvm::vm::name_registry` internals), as a free fn:

```rust
/// Best-effort host-observed readiness update: load the registry, set the
/// machine's readiness + change timestamp, save. Never gates control flow — a
/// failure is logged and swallowed. Shared by the CLI lifecycle recorders and
/// the health-probe daemon.
pub fn record_readiness(
    vm_name: &str,
    readiness: mvm_core::domain::instance::InstanceReadiness,
) {
    let path = registry_path();
    let mut reg = match VmNameRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(err = %e, vm = vm_name, "readiness update: load registry failed");
            return;
        }
    };
    let now = mvm_core::time::utc_now();
    match reg.set_readiness(vm_name, readiness, &now) {
        Ok(true) => {
            if let Err(e) = reg.save(&path) {
                tracing::warn!(err = %e, vm = vm_name, "readiness update: save failed");
            }
        }
        Ok(false) => tracing::debug!(vm = vm_name, "readiness update: no entry; skipping"),
        Err(e) => tracing::warn!(err = %e, vm = vm_name, "readiness update failed"),
    }
}
```
Then rewrite `mvm-cli`'s `record_vm_readiness` to a one-liner: `mvm::vm::name_registry::record_readiness(vm_name, readiness)`. (Confirm `entry(name)` accessor exists; if not, assert via a `load`+lookup the module already supports.)

- [ ] **Step 4: Run to verify pass** — both the new test and the existing `up.rs`/`down.rs` readiness behavior still compile/pass. `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm --lib record_readiness && MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm-cli`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm/src/vm/name_registry.rs crates/mvm-cli/src/commands/vm/readiness.rs
git commit -m "refactor(registry): lift record_readiness into mvm so mvm-hostd can call it"
```

---

## Task 3: `probe_once` — run the check in the guest

**Files:**
- Create: `crates/mvm-hostd/src/health_probe.rs`
- Modify: `crates/mvm-hostd/src/lib.rs` (`pub mod health_probe;`)
- Test: inline tests (mock the exec via a small seam)

**Interfaces:**
- Consumes: `mvm_core::health::ProbeResult`, `mvm_sdk::ir::HealthCheck`.
- Produces: `fn probe_once(vm_name: &str, hc: &mvm_sdk::ir::HealthCheck) -> mvm_core::health::ProbeResult` — connects to the guest agent, runs `hc.command` as a shell string, returns `Pass` on exit 0, `Fail` on non-zero / timeout / transport error. Factor the exec behind a trait so tests don't need a live VM: `trait GuestExec { fn exec(&self, vm_name: &str, cmd: &str, timeout_secs: u64) -> ExecOutcome; } enum ExecOutcome { Exited(i32), TimedOut, Unreachable }`, with a real impl using `mvm::vsock_transport::for_vm` + `mvm_guest::vsock::send_exec_streaming`, and `probe_with<E: GuestExec>(exec, vm_name, hc) -> ProbeResult` as the testable core.

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::health::ProbeResult;
    struct Fake(ExecOutcome);
    impl GuestExec for Fake {
        fn exec(&self, _: &str, _: &str, _: u64) -> ExecOutcome { self.0.clone() }
    }
    fn hc() -> mvm_sdk::ir::HealthCheck {
        mvm_sdk::ir::HealthCheck { command: vec!["/bin/sh".into(),"-lc".into(),"true".into()],
            interval_secs:30, timeout_secs:5, retries:3, start_period_secs:0 }
    }
    #[test] fn exit_zero_is_pass() {
        assert_eq!(probe_with(&Fake(ExecOutcome::Exited(0)), "vm", &hc()), ProbeResult::Pass);
    }
    #[test] fn nonzero_timeout_unreachable_are_fail() {
        assert_eq!(probe_with(&Fake(ExecOutcome::Exited(1)), "vm", &hc()), ProbeResult::Fail);
        assert_eq!(probe_with(&Fake(ExecOutcome::TimedOut), "vm", &hc()), ProbeResult::Fail);
        assert_eq!(probe_with(&Fake(ExecOutcome::Unreachable), "vm", &hc()), ProbeResult::Fail);
    }
}
```

- [ ] **Step 2: Run → FAIL.** `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-hostd --lib health_probe::`

- [ ] **Step 3: Implement.** The command string handed to the agent is `hc.command` joined for the agent's `Exec` (the agent runs a shell command string). The real `GuestExec` impl:
  - `let transport = mvm::vsock_transport::for_vm(vm_name)?;`
  - `let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;`
  - `let terminal = mvm_guest::vsock::send_exec_streaming(&mut stream, &joined_cmd, None, Some(hc.timeout_secs.into()), |_ev| {})?;`
  - map `ExecEvent::Exit{code}` → `Exited(code)`, `ExecEvent::TimedOut` → `TimedOut`, any `Err`/other → `Unreachable`.
  `probe_with` maps `Exited(0)` → `Pass`, everything else → `Fail`. `joined_cmd`: the phase-A stored command is already `["/bin/sh","-lc","<cmd>"]`; the agent's `Exec` takes one command string, so join with spaces OR (cleaner) pass `hc.command.get(2)` when the shape is the known 3-vec — match phase A's `target_command`/`quote_argv_for_exec` convention in `mvm-cli/src/exec.rs` for consistency (reuse that quoting helper if it's reachable; else replicate its shape).

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat(hostd): probe_once runs a healthcheck in the guest via agent exec"`

---

## Task 4: `machine ls` / `inspect` health rendering

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (the `ls` table builder near line 1645 `STATUS`/`AGE` columns; the `inspect` renderer)
- Test: the mod's tests (render a registration with each readiness → expected cell)

**Interfaces:**
- Consumes: `VmRegistration.readiness` (`mvm::vm::name_registry`), `mvm_core::domain::instance::InstanceReadiness`.
- Produces: a `health_cell(readiness: Option<&InstanceReadiness>) -> &'static str` helper (`ServicesReady→"healthy"`, `Degraded→"unhealthy"`, `ServicesStarting→"starting"`, `None`/other→"-"), and a HEALTH column in `ls` + a `health:` line in `inspect`.

- [ ] **Step 1: Failing test**

```rust
#[test]
fn health_cell_maps_readiness() {
    use mvm_core::domain::instance::InstanceReadiness::*;
    assert_eq!(health_cell(Some(&ServicesReady)), "healthy");
    assert_eq!(health_cell(Some(&Degraded { unhealthy: vec![] })), "unhealthy");
    assert_eq!(health_cell(Some(&ServicesStarting { pending: vec![] })), "starting");
    assert_eq!(health_cell(None), "-");
}
```
(Match the actual `Degraded`/`ServicesStarting` field shapes in `instance.rs` — adjust the constructor args to compile.)

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** `health_cell` + thread the reg's `readiness` into the `ls` row struct (add a `health` field beside `status`/`age`, header `"HEALTH"`) and an `inspect` line. Read `readiness` from the machine's `VmRegistration` when building each row.

- [ ] **Step 4: Run → PASS** + `MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm-cli`.

- [ ] **Step 5: Commit** — `git commit -m "feat(cli): show health in machine ls/inspect"`

---

## Task 5: Daemon probe pass on the tick

**Files:**
- Modify: `crates/mvm-hostd/src/health_probe.rs` (add the pass), and the daemon tick that calls it (locate: `crates/mvm-hostd/src/host_agent_idle.rs` `run_idle_watcher`, or the tick in `crates/mvm-hostd/src/bin/mvm-host-agent.rs` / `broker/daemon.rs`).
- Test: `health_probe.rs` tests (drive the pass with a fake registration set + fake exec + fake clock).

**Interfaces:**
- Consumes: Task 1 `fold`/`HealthTracker`/`HealthPolicy`, Task 2 `record_readiness`, Task 3 `probe_with`, `mvm::machine::persist::load_machine_spec`.
- Produces: `struct HealthProber { trackers: HashMap<String, HealthTracker> }` + `fn tick(&mut self, live_vm_ids: &[String], now_unix: u64, exec: &dyn GuestExec)` that, per live vm: `load_machine_spec(vm)`; if `spec.health_check` is `None`, skip + drop any tracker; else build `HealthPolicy` from the `HealthCheck` + the plan's backoff constants; if the machine is due for a probe (first tick, or `now >= last_probe + interval`), `probe_with(exec, vm, hc)`, `fold(...)`, `record_readiness(vm, map_state(tracker.state))`, and stash the resulting `HealthAction` for Task 6. Restart execution is Task 6 — here the pass returns the actions.
- `fn map_state(HealthState) -> InstanceReadiness` (Starting→ServicesStarting{pending:vec![]}, Healthy→ServicesReady, Unhealthy→Degraded{unhealthy:vec![]}).

- [ ] **Step 1: Failing test** — a `tick` over one vm whose (fake-loaded) spec has a healthcheck, with a fake exec returning Fail×retries, asserts the tracker goes Unhealthy and the returned actions include `Restart` for that vm; a vm with no healthcheck is skipped (no readiness write). Inject `load_machine_spec` behind a small fn pointer / trait so the test doesn't hit disk, OR write specs to a tempdir `MVM_DATA_DIR` and use the real loader. Prefer the tempdir approach if simpler.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement `HealthProber::tick`** as above; then call it from the daemon's periodic tick, passing the live registration ids (`daemon.registration_count`/the vm_id map — reuse the same source `run_idle_watcher` reads) and `mvm_core::time` now. Gate the whole pass behind the daemon already running (no new process). Keep per-probe work bounded (each `probe_with` already bounds via `timeout_secs`).

- [ ] **Step 4: Run → PASS** + `cargo build -p mvm-hostd`.

- [ ] **Step 5: Commit** — `git commit -m "feat(hostd): probe healthchecked machines on the daemon tick"`

---

## Task 6: Bounded restart execution

**Files:**
- Modify: `crates/mvm-hostd/src/health_probe.rs` (act on `HealthAction`)
- Test: `health_probe.rs` tests (fake restarter records calls; assert backoff gating + give-up)

**Interfaces:**
- Consumes: Task 1 `HealthAction`/`HealthTracker.next_restart_after_unix`.
- Produces: `trait Restarter { fn restart(&self, vm_name: &str); }` with a real impl spawning `Command::new(current_exe or "mvmctl").args(["machine","restart",vm_name]).spawn()` (fire-and-forget; log on spawn error). The tick, on `HealthAction::Restart`, restarts only when `now_unix >= tracker.next_restart_after_unix`; on `GiveUp`, logs once and leaves the machine `Unhealthy` (no spawn).

- [ ] **Step 1: Failing test** — with a fake `Restarter`, drive retries→Restart and assert `restart("vm")` is called once the backoff time is reached but NOT before `next_restart_after_unix`; drive to `max_restart_attempts` and assert `GiveUp` yields no further restart calls.

- [ ] **Step 2: Run → FAIL.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat(hostd): bounded restart (backoff + max-attempts) on unhealthy"`

---

## Task 7: Restart-on-exit for declared services + audit

**Files:**
- Modify: `crates/mvm-hostd/src/health_probe.rs`

**Interfaces:**
- Consumes: the live-vm-id set already passed to `tick`. A healthchecked machine whose registration was present last tick but is now gone (and was not stopped via `machine stop` — detectable by the absence of a `Stopping`/deliberate marker) is treated as a crash-exit → same restart path (respecting backoff/cap).

- [ ] **Step 1: Failing test** — a tracker for a healthchecked vm that disappears from `live_vm_ids` between ticks yields a `Restart` action (bounded), and a machine that was deliberately stopped does NOT (the `stop` path already records `Stopping` readiness — treat that as intentional). Assert the audit event is emitted (via a fake sink).

- [ ] **Step 2–4: red → implement → green.** Emit a health-transition + restart event to the machine's audit chain (reuse the existing audit-emit surface the daemon already uses; if none is reachable, log structured events and note it for the reviewer).

- [ ] **Step 5: Commit** — `git commit -m "feat(hostd): restart declared services on crash-exit; audit health transitions"`

---

## Task 8: Docs + full gate

- [ ] **Step 1: Docs.** In `public/src/content/docs/reference/cli-commands.md`, extend the `machine run --healthcheck` section: the check is now probed every `--health-interval` (after `--health-start-period`); `machine ls`/`inspect` show `starting`/`healthy`/`unhealthy`; an unhealthy service (or a crashed one) is restarted with exponential backoff up to a cap, then left `unhealthy`; requires the host-agent daemon (default-on; disabled by `MVM_HOST_AGENT_DAEMON=0`, in which case health shows `unknown`).

- [ ] **Step 2: Full gate.**
```bash
cargo fmt --all -- --check
MVM_SKIP_EMBED_BINARIES=1 cargo clippy --workspace -- -D warnings
MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace --no-fail-fast
MVM_SKIP_EMBED_BINARIES=1 cargo test --workspace --doc
cargo run -p xtask -- check-no-spec-refs-in-comments
cargo run -p xtask -- check-stubs
```
Only the two known pre-existing failures are acceptable; anything else is BLOCKED.

- [ ] **Step 3: Manual E2E (macOS HVF).**
```bash
MVM_SKIP_EMBED_BINARIES=1 cargo build --bin mvmctl
# healthy service:
./target/debug/mvmctl machine run -d --image alpine --healthcheck 'true' --health-interval 5 -- sleep 600
sleep 12; ./target/debug/mvmctl machine ls            # HEALTH=healthy
# wedged service (check always fails, process alive):
./target/debug/mvmctl machine run -d --image alpine --healthcheck 'false' --health-interval 5 --health-retries 2 -- sleep 600
sleep 25; ./target/debug/mvmctl machine ls            # unhealthy → restart(s) observed, then bounded
./target/debug/mvmctl machine stop <names>
```

- [ ] **Step 4: Commit** — `git commit -m "docs: document machine run healthcheck probing + restart (phase C)"`

---

## Self-Review

**Spec coverage:** driver on the daemon tick (Task 5) + HVF de-risk (Task 0); probe via agent exec (Task 3); state machine (Task 1); readiness persistence via the reused seam (Task 2) + `machine ls`/`inspect` display (Task 4); bounded restart backoff/cap (Task 6); restart-on-exit + audit (Task 7); scope/degradation/docs (Task 8). Every design section maps to a task. ✓

**Placeholder scan:** the pure reducer (Task 1) and `probe_with`/tests are complete code. Integration tasks (0, 5, 6, 7) name exact reuse targets (`register_host_agent_services_if_admitted`, `run_idle_watcher`, `load_machine_spec`, `send_exec_streaming`, `record_readiness`, `machine restart`) and inject fakes for tests; where a daemon-internal seam must be located, the step says "locate X and reuse it," never "implement error handling." No `TODO`/`TBD`.

**Type consistency:** `ProbeResult`/`HealthState`/`HealthAction`/`HealthPolicy`/`HealthTracker`/`fold` (Task 1) are used verbatim in Tasks 5/6; `record_readiness` (Task 2) is called in Task 5; `GuestExec`/`ExecOutcome`/`probe_with` (Task 3) are consumed in Task 5; `map_state`/`health_cell` map the same `InstanceReadiness` variants across Tasks 4/5. `mvm-core` must not reference `mvm-sdk` (Task 1 holds raw numbers; the caller builds `HealthPolicy`). ✓

**Known risk:** Task 0 (HVF daemon wiring) can turn up a BLOCKED — the design's fallback (probe thread in the per-VM supervisor) is a different plan; escalate rather than force it.
