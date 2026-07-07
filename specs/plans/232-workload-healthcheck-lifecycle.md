# Workload Healthcheck Lifecycle (Phase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--healthcheck` flag to `machine run` that promotes a run to the persistent, managed lifecycle (presence = "this is a long-running service"), recording the check for later probing without executing it.

**Architecture:** A new `HealthCheck` IR type on `App`; the flag flips the existing `persistent()` predicate; a healthchecked run without `-d` boots/registers through the persistent path but streams in the foreground. Exit code still terminates a run (phase A is signal-only). Extends ADR-091's unified `machine run` lifecycle.

**Tech Stack:** Rust, clap (CLI), serde (IR), the existing `mvm-sdk::ir` + `mvm-cli` machine-run dispatch.

**Design:** `specs/notes/2026-07-07-workload-healthcheck-lifecycle-design.md`.

## Global Constraints

- **No spec references in code comments.** `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` are CI-banned in code/comments (`xtask check-no-spec-refs-in-comments`). Reword to the concept. (Docs/specs may reference them.)
- **No schema-version bump.** Nothing is in prod; new IR fields are `#[serde(default = ...)]`, do not bump `schema_version`.
- **Regenerate SDK stubs after any workload-IR change.** `App` derives `JsonSchema`, so adding a field (Task 1) changes the emitted schema. Run `cargo run -p xtask -- gen-stubs` and commit the regenerated `schema/workload-ir-v0.json`, `sdks/python/mvm/_ir/workload.py`, `sdks/typescript/src/ir/workload.ts`; the CI `check-stubs` job fails on drift. New `HealthCheck` must derive `JsonSchema` (compile-required once `App` references it).
- **Exec-form check only.** The guest is vsock-only; the healthcheck command is an exec argv the agent runs (no HTTP/TCP probe kinds).
- **Phase A reads only `.is_some()`.** Timing fields (`interval/timeout/retries/start_period`) are stored, never acted on in this plan.
- **Test gate:** `cargo nextest run --workspace` (process-parallel; the named gate), `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`. Prefer `just` recipes. On this macOS host, `MVM_SKIP_EMBED_BINARIES=1` skips the host-vm cross-compile for non-boot tests.
- **HealthCheck defaults:** `interval_secs=30`, `timeout_secs=5`, `retries=3`, `start_period_secs=0`.
- **Persistence predicate today:** `persistent() = detach || up_json || ttl.is_some()` (`--name` is identity-only). The healthcheck term is added to this OR.

---

## File Structure

- `crates/mvm-sdk/src/ir/workload.rs` — add `HealthCheck` struct + `App.health_check: Option<HealthCheck>`. (Task 1)
- `crates/mvm-cli/src/commands/machine/mod.rs` — `MachineRunArgs` flags, `persistent()`, `resolve_mode`/foreground decision, `into_run_args`. (Tasks 2, 3, 5)
- `crates/mvm-cli/src/exec.rs` — `ExecRequest.healthcheck` carriage + the flag→`HealthCheck` mapping helper. (Task 4)
- `crates/mvm/src/machine/persist.rs` — record `health_check` on the persistent `MachineSpec`. (Task 6)
- `crates/mvm-cli/tests/cli.rs` — CLI parse coverage. (Task 2)

---

## Task 1: `HealthCheck` IR type + `App.health_check`

**Files:**
- Modify: `crates/mvm-sdk/src/ir/workload.rs` (add struct near `Concurrency`; add field to `App`)
- Test: same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `mvm_sdk::ir::HealthCheck { command: Vec<String>, interval_secs: u32, timeout_secs: u32, retries: u32, start_period_secs: u32 }`; `App.health_check: Option<HealthCheck>`.

- [ ] **Step 1: Write the failing test** (add to the `tests` module in `workload.rs`)

```rust
#[test]
fn health_check_serde_roundtrip_and_defaults() {
    // Only `command` is required on the wire; timing fields default.
    let json = r#"{"command":["/bin/sh","-lc","curl -fsS localhost/health"]}"#;
    let hc: HealthCheck = serde_json::from_str(json).unwrap();
    assert_eq!(hc.command, vec!["/bin/sh", "-lc", "curl -fsS localhost/health"]);
    assert_eq!(hc.interval_secs, 30);
    assert_eq!(hc.timeout_secs, 5);
    assert_eq!(hc.retries, 3);
    assert_eq!(hc.start_period_secs, 0);

    let back = serde_json::to_string(&hc).unwrap();
    assert_eq!(hc, serde_json::from_str::<HealthCheck>(&back).unwrap());
}

#[test]
fn app_health_check_defaults_absent() {
    // An App with no healthcheck deserializes to None and skip-serializes.
    let app: App = serde_json::from_str(MINIMAL_APP_JSON).unwrap();
    assert!(app.health_check.is_none());
}
```

If `MINIMAL_APP_JSON` does not already exist in the test module, reuse the smallest existing `App` fixture in the file instead (search the module for an `App`-deserializing test and copy its JSON literal).

- [ ] **Step 2: Run test to verify it fails**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-sdk --lib health_check`
Expected: FAIL — `cannot find type HealthCheck` / `no field health_check`.

- [ ] **Step 3: Add the struct** (place next to `Concurrency`/`WarmProcessConfig` in `workload.rs`)

```rust
/// A liveness declaration for a long-running workload. Its presence promotes a
/// run to the persistent lifecycle (the run is a service, not a task). The
/// command is exec'd in the guest via the agent; exit 0 means healthy — exec
/// form because the guest is vsock-only. The timing fields are recorded for the
/// active-probing follow-up and are not consulted while a workload only uses the
/// presence signal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub command: Vec<String>,
    #[serde(default = "default_health_interval_secs")]
    pub interval_secs: u32,
    #[serde(default = "default_health_timeout_secs")]
    pub timeout_secs: u32,
    #[serde(default = "default_health_retries")]
    pub retries: u32,
    #[serde(default = "default_health_start_period_secs")]
    pub start_period_secs: u32,
}

fn default_health_interval_secs() -> u32 {
    30
}
fn default_health_timeout_secs() -> u32 {
    5
}
fn default_health_retries() -> u32 {
    3
}
fn default_health_start_period_secs() -> u32 {
    0
}
```

- [ ] **Step 4: Add the field to `App`** (in the `pub struct App { ... }` definition, after `hooks`/`files` or alongside the other optional fields)

```rust
    /// Liveness declaration. `Some` marks the workload a long-running service
    /// (drives the persistent lifecycle); `None` is a task that tears down on
    /// entrypoint exit. Skip-serialized when absent so existing fixtures stay
    /// byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
```

If `App` is constructed by struct literal anywhere without `..Default::default()`, add `health_check: None` at those sites (compile errors will list them; search `App {`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-sdk --lib health_check && MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-sdk --lib app_health_check`
Expected: PASS.

- [ ] **Step 6: Verify no build breakage from the new field**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm-sdk`
Expected: builds clean (fix any `App {` literals flagged missing `health_check`).

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-sdk/src/ir/workload.rs
git commit -m "feat(ir): add HealthCheck type + App.health_check field"
```

---

## Task 2: `--healthcheck` CLI flags on `MachineRunArgs`

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (`MachineRunArgs` struct)
- Test: `crates/mvm-cli/tests/cli.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `MachineRunArgs.healthcheck: Option<String>`, `.health_interval: u32`, `.health_timeout: u32`, `.health_retries: u32`, `.health_start_period: u32` (the last four with clap defaults 30/5/3/0).

- [ ] **Step 1: Write the failing test** (add to `crates/mvm-cli/tests/cli.rs`)

```rust
#[test]
fn machine_run_parses_healthcheck_flags() {
    use clap::Parser;
    let cli = mvm_cli::Cli::try_parse_from([
        "mvmctl", "machine", "run", "--image", "nginx",
        "--healthcheck", "curl -fsS localhost/health",
        "--health-interval", "10", "--health-retries", "5",
        "--", "nginx", "-g", "daemon off;",
    ])
    .expect("healthcheck flags parse");
    let run = extract_machine_run_args(&cli); // helper below
    assert_eq!(run.healthcheck.as_deref(), Some("curl -fsS localhost/health"));
    assert_eq!(run.health_interval, 10);
    assert_eq!(run.health_timeout, 5);   // default
    assert_eq!(run.health_retries, 5);
    assert_eq!(run.health_start_period, 0); // default
}
```

Match the existing `tests/cli.rs` idiom for reaching a subcommand's parsed args — search the file for another `machine run` parse test and copy how it destructures `Cli` → the run args (the `extract_machine_run_args` helper stands in for whatever pattern is already used; do not invent a new one).

- [ ] **Step 2: Run test to verify it fails**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --test cli machine_run_parses_healthcheck`
Expected: FAIL — unknown argument `--healthcheck` / no field `healthcheck`.

- [ ] **Step 3: Add the fields** (in `pub struct MachineRunArgs`, near the other lifecycle flags like `detach`/`ttl`)

```rust
    /// Declare this workload a long-running service: the shell command is
    /// exec'd in the guest as its liveness check (exit 0 = healthy). Its
    /// presence promotes the run to the persistent lifecycle — it will not tear
    /// down on a backstop; it runs until `stop`. A run whose entrypoint exits
    /// still tears down on that exit code.
    #[arg(long, value_name = "CMD")]
    pub healthcheck: Option<String>,

    /// Seconds between checks. Recorded now; enforced when active probing lands.
    #[arg(long = "health-interval", default_value_t = 30)]
    pub health_interval: u32,

    /// Per-check timeout in seconds. Recorded now; enforced later.
    #[arg(long = "health-timeout", default_value_t = 5)]
    pub health_timeout: u32,

    /// Consecutive failures before unhealthy. Recorded now; enforced later.
    #[arg(long = "health-retries", default_value_t = 3)]
    pub health_retries: u32,

    /// Grace period after start before checks count. Recorded now; enforced later.
    #[arg(long = "health-start-period", default_value_t = 0)]
    pub health_start_period: u32,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --test cli machine_run_parses_healthcheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs crates/mvm-cli/tests/cli.rs
git commit -m "feat(cli): add --healthcheck and tuning flags to machine run"
```

---

## Task 3: Healthcheck flips `persistent()`; foreground decision

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (`persistent()`, plus a new `attach_foreground()` predicate)
- Test: the `#[cfg(test)] mod tests` in `machine/mod.rs` (or `commands/tests.rs` where the existing mode tests live — follow the existing `machine_run_flake_resolves_to_persistent_lifecycle` test's location)

**Interfaces:**
- Consumes: `MachineRunArgs` fields from Task 2.
- Produces: `persistent()` returns true when `healthcheck.is_some()`; `attach_foreground(&self) -> bool` returns true for a persistent run that should stream in the foreground (persistent, not interactive, not `--detach`, not `--up-json`).

- [ ] **Step 1: Write the failing tests** (co-locate with the existing mode tests)

```rust
#[test]
fn healthcheck_makes_run_persistent() {
    let mut args = minimal_machine_run_args(); // reuse existing test constructor
    assert!(!args.persistent());
    args.healthcheck = Some("true".into());
    assert!(args.persistent(), "a healthcheck promotes the run to persistent");
}

#[test]
fn name_alone_stays_transient() {
    let mut args = minimal_machine_run_args();
    args.name = Some("web".into());
    assert!(!args.persistent(), "--name is identity only, not persistence");
}

#[test]
fn healthcheck_without_detach_attaches_foreground() {
    let mut args = minimal_machine_run_args();
    args.healthcheck = Some("true".into());
    assert!(args.attach_foreground(), "healthcheck, no -d => foreground");
    args.detach = true;
    assert!(!args.attach_foreground(), "-d => detached, not foreground");
}
```

Find the existing constructor the mode tests use (search for the setup in `machine_run_flake_resolves_to_persistent_lifecycle`); `minimal_machine_run_args()` stands in for it. Do not invent a new fixture if one exists.

- [ ] **Step 2: Run tests to verify they fail**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib healthcheck_makes_run_persistent attach_foreground name_alone_stays`
Expected: FAIL — `attach_foreground` not found; `persistent()` false with healthcheck.

- [ ] **Step 3: Extend `persistent()` and add `attach_foreground()`**

```rust
    /// `-d`/`--detach`, `--up-json`, `--ttl`, or a declared `--healthcheck`
    /// makes the machine survive the command. `--tty`/`--name` are deliberately
    /// not consulted — persistence, interactivity, and identity are independent
    /// axes.
    fn persistent(&self) -> bool {
        self.detach || self.up_json || self.ttl.is_some() || self.healthcheck.is_some()
    }

    /// A persistent run that streams in the foreground instead of detaching:
    /// a declared service (`--healthcheck`) launched without `-d`/`--up-json`
    /// and without an interactive PTY. It boots/registers through the persistent
    /// path but attaches to the guest console until `stop`/Ctrl-C.
    fn attach_foreground(&self) -> bool {
        self.persistent() && !self.detach && !self.up_json && !self.interactive()
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib healthcheck_makes_run_persistent attach_foreground name_alone_stays`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(cli): healthcheck flips persistent(); add foreground-attach predicate"
```

---

## Task 4: Map the flags to `HealthCheck`; carry on `ExecRequest`

**Files:**
- Modify: `crates/mvm-cli/src/exec.rs` (`ExecRequest` struct; add a `healthcheck: Option<mvm_sdk::ir::HealthCheck>` field and a mapping helper)
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (`into_run_args`/`into_exec_args` populate it)
- Test: `crates/mvm-cli/src/exec.rs` tests module

**Interfaces:**
- Consumes: `MachineRunArgs` fields (Task 2), `HealthCheck` (Task 1).
- Produces: `fn build_healthcheck(cmd: Option<&str>, interval: u32, timeout: u32, retries: u32, start_period: u32) -> Option<mvm_sdk::ir::HealthCheck>`; `ExecRequest.healthcheck`.

- [ ] **Step 1: Write the failing test** (in `exec.rs` tests)

```rust
#[test]
fn build_healthcheck_wraps_shell_command() {
    let hc = build_healthcheck(Some("curl -fsS localhost/health"), 10, 5, 3, 0)
        .expect("Some when a command is given");
    assert_eq!(hc.command, vec!["/bin/sh", "-lc", "curl -fsS localhost/health"]);
    assert_eq!(hc.interval_secs, 10);
    assert_eq!(build_healthcheck(None, 30, 5, 3, 0), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib build_healthcheck`
Expected: FAIL — `build_healthcheck` not found.

- [ ] **Step 3: Add the helper + `ExecRequest` field**

```rust
/// Build the IR healthcheck from the CLI flags. A shell command string becomes
/// an exec argv the guest agent runs (`/bin/sh -lc <cmd>`). `None` command ⇒ no
/// healthcheck (a plain task).
pub fn build_healthcheck(
    cmd: Option<&str>,
    interval_secs: u32,
    timeout_secs: u32,
    retries: u32,
    start_period_secs: u32,
) -> Option<mvm_sdk::ir::HealthCheck> {
    let cmd = cmd?;
    Some(mvm_sdk::ir::HealthCheck {
        command: vec!["/bin/sh".into(), "-lc".into(), cmd.to_string()],
        interval_secs,
        timeout_secs,
        retries,
        start_period_secs,
    })
}
```

Add to `pub struct ExecRequest`:

```rust
    /// Recorded liveness declaration (phase A: presence only). Persisted with a
    /// persistent machine so it survives + is inspectable; not yet probed.
    pub healthcheck: Option<mvm_sdk::ir::HealthCheck>,
```

Populate it at the `into_run_args`/`into_exec_args` site(s) in `machine/mod.rs` and any `ExecRequest { ... }` literal (compile errors will list them):

```rust
    healthcheck: crate::exec::build_healthcheck(
        self.healthcheck.as_deref(),
        self.health_interval,
        self.health_timeout,
        self.health_retries,
        self.health_start_period,
    ),
```

- [ ] **Step 4: Run test + build to verify**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib build_healthcheck && MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm-cli`
Expected: PASS + clean build (add `healthcheck: None` to any other `ExecRequest {` literals flagged).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/exec.rs crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(cli): map healthcheck flags to IR HealthCheck on ExecRequest"
```

---

## Task 5: Foreground-persistent dispatch

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (`run_dispatch` / `run_persistent`)
- Test: unit test for the routing predicate; manual/integration for the boot.

**Interfaces:**
- Consumes: `attach_foreground()` (Task 3), the existing `run_persistent` boot + name-registry write, and the existing foreground console/log-follow helper used by `machine run -it`/`console` (search `run_pty_command_for_exit` / console attach / `logs` follow in `commands/vm/console.rs` and reuse; do NOT write a new relay).

- [ ] **Step 1: Write the failing routing test**

```rust
#[test]
fn healthcheck_run_routes_persistent_foreground() {
    let mut args = minimal_machine_run_args();
    args.image = Some("nginx".into());
    args.argv = vec!["nginx".into(), "-g".into(), "daemon off;".into()];
    args.healthcheck = Some("true".into());
    // resolve_mode returns the persistent lifecycle for a non-interactive
    // healthchecked run; attach_foreground() is what the dispatch consults to
    // stream instead of detaching.
    assert_eq!(args.resolve_mode().unwrap(), MachineRunMode::Persistent);
    assert!(args.attach_foreground());
}
```

- [ ] **Step 2: Run test to verify it fails or is red**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib healthcheck_run_routes_persistent_foreground`
Expected: FAIL if `resolve_mode` rejects a non-`-d` persistent run (it currently requires an image for fresh boot — ensure `--image` is set as above). If it already passes for the predicate half, proceed to wire the dispatch (Step 3).

- [ ] **Step 3: Wire the persistent dispatch to attach in the foreground**

In `run_dispatch`'s `MachineRunMode::Persistent` arm (or inside `run_persistent`), after the machine is booted and registered, branch on `args.attach_foreground()`:

```rust
    // A declared service without -d streams in the foreground: reuse the same
    // console/log follow the interactive and `console` paths use, then leave the
    // machine registered on detach so `machine stop <name>` still works.
    if args.attach_foreground() {
        return attach_foreground_to_running_machine(&resolved_name); // reuse existing follow helper
    }
```

`attach_foreground_to_running_machine` is the existing follow/attach entrypoint — locate it (`commands/vm/console.rs` console attach, or the `logs --follow` path) and call it; do not implement a new relay. If the only existing foreground attach is the PTY console, gate on non-interactive and follow `console.log` instead (the write-only capture the backend already produces).

- [ ] **Step 4: Run the routing test**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm-cli --lib healthcheck_run_routes_persistent_foreground`
Expected: PASS.

- [ ] **Step 5: Manual end-to-end verification** (macOS HVF host)

```bash
MVM_SKIP_EMBED_BINARIES=1 cargo build --bin mvmctl
# a run-to-completion task with no healthcheck tears down:
./target/debug/mvmctl machine run --image alpine -- true; ./target/debug/mvmctl machine ls   # not listed
# a healthchecked service registers + survives:
./target/debug/mvmctl machine run --image alpine --healthcheck 'true' -- sleep 600 &
sleep 8; ./target/debug/mvmctl machine ls   # listed (persistent)
./target/debug/mvmctl machine stop <name>
```
Expected: the task VM is gone after exit; the healthchecked VM is listed until `stop`.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(cli): healthchecked run boots persistent + streams foreground"
```

---

## Task 6: Record the healthcheck on the persistent machine

**Files:**
- Modify: `crates/mvm/src/machine/persist.rs` (`MachineSpec` gains `health_check: Option<mvm_sdk::ir::HealthCheck>`)
- Modify: the persistent boot path that writes the `MachineSpec` (search `MachineSpec {` construction in the persistent run path)
- Test: `machine/persist.rs` serde roundtrip

**Interfaces:**
- Consumes: `HealthCheck` (Task 1), `ExecRequest.healthcheck` (Task 4).
- Produces: a persisted, inspectable healthcheck on the registered machine.

- [ ] **Step 1: Write the failing test** (in `machine/persist.rs` tests)

```rust
#[test]
fn machine_spec_roundtrips_health_check() {
    let mut spec = minimal_machine_spec(); // reuse existing test constructor
    spec.health_check = Some(mvm_sdk::ir::HealthCheck {
        command: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
        interval_secs: 30, timeout_secs: 5, retries: 3, start_period_secs: 0,
    });
    let json = serde_json::to_string(&spec).unwrap();
    assert_eq!(spec, serde_json::from_str::<MachineSpec>(&json).unwrap());
    // Absent healthcheck skip-serializes (old spec files stay readable).
    let bare = minimal_machine_spec();
    assert!(!serde_json::to_string(&bare).unwrap().contains("health_check"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm --lib machine_spec_roundtrips_health_check`
Expected: FAIL — no field `health_check` on `MachineSpec`.

- [ ] **Step 3: Add the field + populate it at the write site**

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<mvm_sdk::ir::HealthCheck>,
```

At the persistent-path `MachineSpec { ... }` construction, set `health_check: req.healthcheck.clone()` (thread the `ExecRequest.healthcheck` through to the spec write). Add `health_check: None` to any other `MachineSpec {` literals the compiler flags.

- [ ] **Step 4: Run test + build**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo test -p mvm --lib machine_spec_roundtrips_health_check && MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm/src/machine/persist.rs
git commit -m "feat(machine): persist health_check on the managed MachineSpec"
```

---

## Task 7: Full gate + docs

**Files:**
- Modify: `public/src/content/docs/reference/cli-commands.md` (document `--healthcheck` + tuning flags, phase-A semantics)

- [ ] **Step 1: Document the flag** — add a `--healthcheck` entry to the `machine run` reference: presence promotes to the persistent lifecycle; foreground unless `-d`; exit code still terminates a task; tuning flags recorded but not yet enforced.

- [ ] **Step 2: Run the full workspace gate**

Run:
```bash
cargo fmt --all -- --check
MVM_SKIP_EMBED_BINARIES=1 cargo clippy --workspace -- -D warnings
MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace
MVM_SKIP_EMBED_BINARIES=1 cargo test --workspace --doc
```
Expected: all green. (Two known pre-existing local failures unrelated to this work: `doctor::collect_security_posture_returns_a_real_tier` — env-specific `tier: Unknown`; and `embedded_binaries::each_embedded_binary_starts_with_elf_magic` — an artifact of `MVM_SKIP_EMBED_BINARIES=1`.)

- [ ] **Step 3: Run the spec-ref-in-comments and stub-drift gates**

Run:
```bash
cargo run -p xtask -- check-no-spec-refs-in-comments
cargo run -p xtask -- check-stubs
```
Expected: both clean. (Task 1 already regenerated the stubs via `gen-stubs`; this re-verifies no drift remains.)

- [ ] **Step 4: Commit**

```bash
git add public/src/content/docs/reference/cli-commands.md
git commit -m "docs: document machine run --healthcheck (phase A)"
```

---

## Self-Review

**Spec coverage:**
- `HealthCheck` IR type + rich fields → Task 1. ✓
- CLI `--healthcheck` + tuning flags → Task 2. ✓
- `persistent = … | --healthcheck`; `--name` identity-only → Task 3. ✓
- Foreground-by-default, `-d` detaches (the one new behavior) → Tasks 3 (predicate) + 5 (dispatch). ✓
- Exit code always wins (phase A) → no teardown-on-exit change made; transient path untouched; verified in Task 5 Step 5. ✓
- Flag→IR mapping (exec form) → Task 4. ✓
- Recorded but not executed (durable on the persistent machine) → Task 6. ✓
- Testing (serde/defaults, predicate truth table, CLI parse, spec roundtrip, lifecycle) → Tasks 1–6 + 7 gate. ✓
- Deferred phase C (probe/restart) → explicitly out of every task. ✓

**Placeholder scan:** `minimal_machine_run_args`/`minimal_machine_spec`/`extract_machine_run_args`/`attach_foreground_to_running_machine` are named stand-ins for existing constructors/helpers — each step says to locate and reuse the real one rather than invent it, because the exact names are codebase-local. No `TODO`/`TBD`; every code step shows code.

**Type consistency:** `HealthCheck` fields (`command`, `interval_secs`, `timeout_secs`, `retries`, `start_period_secs`) are identical across Tasks 1/4/6; `attach_foreground()`/`persistent()` names match between Tasks 3 and 5; `ExecRequest.healthcheck` (Task 4) is the source threaded into `MachineSpec.health_check` (Task 6).
