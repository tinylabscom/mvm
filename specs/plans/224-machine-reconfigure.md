# machine reconfigure (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `machine reconfigure <name>` CLI verb that patches a
narrow set of a persistent machine's config fields and relaunches it,
plus the matching `MvmClient` facade operation (trait + DTO +
`GatewayBackend` remote impl; `LocalBackend`/`MockBackend` stubs).

**Architecture:** The CLI verb loads the on-disk `MachineSpec`
(`~/.mvm/machines/<name>/machine.json`), applies a patch (only the
flags the user passed override; everything else is inherited),
overwrites the spec, and — if the machine is running — stops and
restarts it so a fresh signed `ExecutionPlan` reflects the change. It
**reuses** the existing recreate engine (`machine_config_diff`,
`machine_is_running`, `stop_running_machine`, `overwrite_machine_spec`,
`start_machine`). The facade gains a `reconfigure_machine` op; only the
remote `GatewayBackend` implements it meaningfully in Phase 1.

**Tech Stack:** Rust, Clap (derive), serde/serde_json, async_trait,
reqwest (gateway), tokio (tests), tempfile (tests).

## Global Constraints

- Gates (all must pass): `cargo fmt --all -- --check`;
  `cargo clippy --workspace -- -D warnings`;
  `cargo nextest run --workspace`; `cargo test --workspace --doc`.
- `#[allow(clippy::too_many_arguments)]` is banned — use a params struct.
- All `~/.mvm` paths go through `mvm-core::config` helpers; never inline
  `$HOME`.
- No `schema_version` bump. `MachineSpec` gains no new persisted field in
  this plan; any future serde field lands `#[serde(default)]`.
- Reuse existing helpers — do not reimplement diff/stop/start/persist.
- Facade DTOs are fail-closed: `#[serde(deny_unknown_fields)]`.
- **Work in the worktree** at
  `/Users/auser/work/tinylabs/mvmco/mvm/.claude/worktrees/machine-reconfigure/`.
  Absolute paths that omit `.claude/worktrees/machine-reconfigure/` hit
  the main checkout — always edit under the worktree path.
- Facade scope is the common four (`net`, `allow_host`, `cpus`,
  `memory_mib`); `mem_initial` is CLI-only.

---

## File Structure

- `crates/mvm-cli/src/commands/machine/mod.rs` (modify) — new
  `MachineReconfigureArgs`, `ReconfigurePatch`, `patch_from_args`,
  `apply_patch`, `run_reconfigure`; new `MachineAction::Reconfigure`
  variant; exhaustive-match arms; unit tests in the file's test module.
- `crates/mvm-cli/tests/cli.rs` (modify) — arg-parse / help coverage.
- `crates/mvm-client/src/dto.rs` (modify) — `ReconfigureRequest` + tests.
- `crates/mvm-client/src/client.rs` (modify) — trait method.
- `crates/mvm-client/src/gateway.rs` (modify) — remote impl + body + test.
- `crates/mvm-client/src/mock.rs` (modify) — canned impl + test.
- `crates/mvm-client-local/src/lib.rs` (modify) — unsupported impl + test.
- `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md` (modify) — status rollup.

---

## Task 1: Facade DTO `ReconfigureRequest`

**Files:**
- Modify: `crates/mvm-client/src/dto.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `pub struct ReconfigureRequest { net: Option<bool>,
  allow_host: Option<Vec<String>>, cpus: Option<u32>,
  memory_mib: Option<u32> }` — all-optional patch DTO, fail-closed.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/mvm-client/src/dto.rs`:

```rust
#[test]
fn reconfigure_request_serde_round_trips() {
    let req = ReconfigureRequest {
        net: Some(true),
        allow_host: Some(vec!["api.stripe.com:443".into()]),
        cpus: Some(4),
        memory_mib: Some(1024),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: ReconfigureRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn reconfigure_request_all_none_is_valid_noop() {
    let req: ReconfigureRequest =
        serde_json::from_str("{}").expect("all fields optional");
    assert_eq!(req, ReconfigureRequest::default());
}

#[test]
fn reconfigure_request_rejects_unknown_field_fail_closed() {
    let err = serde_json::from_str::<ReconfigureRequest>(r#"{"rogue":true}"#);
    assert!(err.is_err(), "unknown field must be rejected");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p mvm-client dto::tests::reconfigure -- --nocapture`
Expected: FAIL — `cannot find type ReconfigureRequest`.

- [ ] **Step 3: Add the DTO**

In `crates/mvm-client/src/dto.rs`, after the `ExecResult` struct:

```rust
/// A patch over a machine's reconfigurable fields — intent only. Every
/// field is optional: `None` means "leave unchanged" (patch semantics).
/// `mem_initial` is intentionally absent — it stays a CLI-only field
/// (the facade doesn't model it at launch either).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconfigureRequest {
    pub net: Option<bool>,
    pub allow_host: Option<Vec<String>>,
    pub cpus: Option<u32>,
    pub memory_mib: Option<u32>,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p mvm-client dto::tests::reconfigure`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-client/src/dto.rs
git commit -m "feat(mvm-client): add ReconfigureRequest patch DTO"
```

---

## Task 2: Facade trait method + all impls

Adding a trait method breaks every `impl MvmClient` until each is
filled, so this task lands the trait method and all four impls together
(gateway real; local unsupported; mock canned).

**Files:**
- Modify: `crates/mvm-client/src/client.rs`
- Modify: `crates/mvm-client/src/gateway.rs`
- Modify: `crates/mvm-client/src/mock.rs`
- Modify: `crates/mvm-client-local/src/lib.rs`

**Interfaces:**
- Consumes: `ReconfigureRequest` (Task 1), `MachineId`, `MachineState`.
- Produces: `MvmClient::reconfigure_machine(&self, id: &MachineId,
  cfg: ReconfigureRequest) -> Result<MachineState>`.

- [ ] **Step 1: Write the failing gateway test**

In `crates/mvm-client/src/gateway.rs` `tests` module (mirror the
existing `endpoint(...)` test that builds a backend against an https
base):

```rust
#[test]
fn reconfigure_targets_the_reconfigure_endpoint() {
    let be = GatewayBackend::new(GatewayConfig {
        base_url: "https://fleet.example.com".into(),
        token: "t".into(),
    })
    .unwrap();
    let url = be.endpoint("/api/v1/sandboxes/abc/reconfigure").unwrap();
    assert_eq!(
        url.as_str(),
        "https://fleet.example.com/api/v1/sandboxes/abc/reconfigure"
    );
}

#[test]
fn reconfigure_body_serializes_only_set_fields() {
    let body = ReconfigureBody {
        net: Some(true),
        allow_host: None,
        cpus: Some(2),
        memory_mib: None,
    };
    let json = serde_json::to_string(&body).unwrap();
    assert_eq!(json, r#"{"net":true,"cpus":2}"#);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-client gateway::tests::reconfigure`
Expected: FAIL — `ReconfigureBody` / method not found.

- [ ] **Step 3: Add the trait method**

In `crates/mvm-client/src/client.rs`, add to `trait MvmClient` (and the
`ReconfigureRequest` import):

```rust
    /// Patch a machine's config and relaunch it. Patch semantics: only
    /// the `Some` fields of `cfg` change; the rest are inherited.
    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        cfg: ReconfigureRequest,
    ) -> Result<MachineState>;
```

Update the import line to:

```rust
use crate::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, ReconfigureRequest,
};
```

- [ ] **Step 4: Implement `GatewayBackend::reconfigure_machine`**

In `crates/mvm-client/src/gateway.rs`, add the outbound body struct near
`CreateSandboxBody`:

```rust
/// Body for `POST /api/v1/sandboxes/{id}/reconfigure`. Patch semantics:
/// only set fields are serialized (the gateway leaves the rest unchanged).
#[derive(serde::Serialize)]
struct ReconfigureBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    net: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_host: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_mib: Option<u32>,
}
```

Add the method inside `impl MvmClient for GatewayBackend` (import
`ReconfigureRequest` in the `use crate::dto::{...}` line):

```rust
    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        cfg: ReconfigureRequest,
    ) -> Result<MachineState> {
        let url = self.endpoint(&format!("/api/v1/sandboxes/{}/reconfigure", id.0))?;
        let body = ReconfigureBody {
            net: cfg.net,
            allow_host: cfg.allow_host,
            cpus: cfg.cpus,
            memory_mib: cfg.memory_mib,
        };
        let resp = self
            .authed(self.http.post(url))
            .json(&body)
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("reconfigure request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), &id.0) {
            return Err(e);
        }
        let env: SandboxEnvelope = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("parsing reconfigure response: {e}"),
        })?;
        Ok(env.data.into())
    }
```

- [ ] **Step 5: Implement `LocalBackend::reconfigure_machine` (unsupported)**

In `crates/mvm-client-local/src/lib.rs`, add inside `impl MvmClient for
LocalBackend` (import `ReconfigureRequest` in the `use mvm_client::dto`
line):

```rust
    async fn reconfigure_machine(
        &self,
        _id: &MachineId,
        _cfg: mvm_client::dto::ReconfigureRequest,
    ) -> Result<MachineState> {
        // The in-process local backend has no persistent-machine layer to
        // patch (its run_machine is a transient image-boot). Reconfigure is
        // the CLI verb's or the gateway backend's job until Phase 2 lifts the
        // persistent-machine engine into a shared crate.
        Err(MvmError::Backend {
            reason: "reconfigure is not supported on the in-process local backend \
                     (no persistent-machine layer); use `mvmctl machine reconfigure` \
                     or the gateway backend"
                .into(),
        })
    }
```

- [ ] **Step 6: Implement `MockBackend::reconfigure_machine`**

In `crates/mvm-client/src/mock.rs`, add inside `impl MvmClient for
MockBackend` (import `ReconfigureRequest`):

```rust
    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        _cfg: ReconfigureRequest,
    ) -> Result<MachineState> {
        let all = self.machines.lock().unwrap();
        all.iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })
    }
```

Add a mock test:

```rust
    #[tokio::test]
    async fn reconfigure_known_returns_state_unknown_is_not_found() {
        let mock = MockBackend::default();
        let started = mock
            .run_machine(MachineSpec {
                name: "web".into(), image: "i".into(),
                cpus: 1, memory_mib: 64, env: vec![],
            })
            .await
            .unwrap();
        let out = mock
            .reconfigure_machine(&started.id, ReconfigureRequest { cpus: Some(2), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(out.name, "web");
        assert!(
            mock.reconfigure_machine(&MachineId("nope".into()), ReconfigureRequest::default())
                .await
                .is_err()
        );
    }
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p mvm-client && cargo test -p mvm-client-local`
Expected: PASS (gateway + mock reconfigure tests green; local compiles).

- [ ] **Step 8: Commit**

```bash
git add crates/mvm-client/src/client.rs crates/mvm-client/src/gateway.rs \
        crates/mvm-client/src/mock.rs crates/mvm-client-local/src/lib.rs
git commit -m "feat(mvm-client): reconfigure_machine on the facade (gateway real; local unsupported)"
```

---

## Task 3: CLI surface — args, enum variant, dispatch (stub handler)

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs`
- Test: `crates/mvm-cli/tests/cli.rs`

**Interfaces:**
- Produces: `MachineAction::Reconfigure(MachineReconfigureArgs)` and a
  `fn run_reconfigure(args: MachineReconfigureArgs) -> Result<()>` (stub
  in this task; body in Task 5).

- [ ] **Step 1: Write the failing CLI parse test**

In `crates/mvm-cli/tests/cli.rs`:

```rust
#[test]
fn machine_reconfigure_help_lists_patch_flags() {
    let mut cmd = assert_cmd::Command::cargo_bin("mvmctl").unwrap();
    let out = cmd.args(["machine", "reconfigure", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for flag in ["--net", "--no-net", "--allow-host", "--cpus", "--memory", "--mem-initial"] {
        assert!(text.contains(flag), "help missing {flag}");
    }
}
```

(Match the crate's existing CLI-test harness — reuse the same helper the
neighboring `machine` tests in `cli.rs` use if it differs from
`assert_cmd`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-cli --test cli machine_reconfigure_help`
Expected: FAIL — unrecognized subcommand `reconfigure`.

- [ ] **Step 3: Add the args struct**

In `crates/mvm-cli/src/commands/machine/mod.rs`, near the other machine
arg structs:

```rust
/// Patch a persistent machine's config and relaunch it. Only the flags
/// passed change; every other field is inherited (patch semantics).
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineReconfigureArgs {
    /// Persistent machine name to reconfigure.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Enable dev-tier outbound networking (broad egress + DNS).
    #[arg(long, conflicts_with = "no_net")]
    pub net: bool,
    /// Disable outbound networking (deny-all).
    #[arg(long = "no-net", conflicts_with = "net")]
    pub no_net: bool,
    /// Replace the egress allowlist with these hosts: `HOST[:PORT]`
    /// (repeatable). Omit to inherit the current allowlist.
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Clear the egress allowlist (remove all entries).
    #[arg(long = "clear-allow-host", conflicts_with = "allow_host")]
    pub clear_allow_host: bool,
    /// New vCPU count.
    #[arg(long)]
    pub cpus: Option<u32>,
    /// New memory (human-readable: 512M, 1G, ...).
    #[arg(long)]
    pub memory: Option<String>,
    /// New initial host memory commitment (human-readable).
    #[arg(long = "mem-initial")]
    pub mem_initial: Option<String>,
    /// Workload VMM backend for the relaunch (defaults to the host's best).
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
}
```

- [ ] **Step 4: Add the enum variant + exhaustive-match arms + stub handler**

Add the variant to `enum MachineAction`, declared immediately after
`Stop`. Clap breaks `display_order` ties by declaration order, so
reusing `display_order = 5` places it right after `Stop` in `--help`
without renumbering any other variant:

```rust
    /// Patch a persistent machine's config and relaunch it
    #[command(display_order = 5)]
    Reconfigure(MachineReconfigureArgs),
```

Add `MachineAction::Reconfigure(_)` to the `"machine"` arm list in
`verb_name` (the `Run(_) | ... => "machine"` match). Add an arm to the
audit action-name match (the `=> "run" / "start" / "stop"` match near the
bottom of the file): `MachineAction::Reconfigure(_) => "reconfigure",`.
The compiler will flag any other exhaustive `match` on `MachineAction`;
add a `Reconfigure` arm to each.

Add the dispatch arm in `fn run(...)`:

```rust
        MachineAction::Reconfigure(args) => run_reconfigure(args),
```

Add the stub handler (real body in Task 5):

```rust
fn run_reconfigure(_args: MachineReconfigureArgs) -> Result<()> {
    bail!("machine reconfigure: not yet implemented")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mvm-cli --test cli machine_reconfigure_help`
Expected: PASS. Also `cargo build -p mvm-cli` compiles.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs crates/mvm-cli/tests/cli.rs
git commit -m "feat(machine): machine reconfigure CLI surface (stub handler)"
```

---

## Task 4: Patch logic — `ReconfigurePatch`, `patch_from_args`, `apply_patch`

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `MachineReconfigureArgs` (Task 3), `MachineSpec`,
  `validate_machine_memory` (`mod.rs:1231`).
- Produces: `struct ReconfigurePatch`,
  `fn patch_from_args(&MachineReconfigureArgs) -> Result<ReconfigurePatch>`,
  `fn apply_patch(MachineSpec, &ReconfigurePatch) -> MachineSpec`.

- [ ] **Step 1: Write the failing unit tests**

In the machine module's test module:

```rust
fn spec_fixture() -> MachineSpec {
    MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".into(),
        image: Some("img:1".into()),
        manifest: None,
        resolved_digest: None,
        net: false,
        allow_host: vec![],
        cpus: 2,
        memory: "512M".into(),
        mem_initial: None,
        profile: "standard".into(),
        volumes: vec!["/data:/data:ro".into()],
        init: vec![],
        ssh_agent: false,
        agent_verb: vec![],
        created_at: None,
        last_started_at: None,
    }
}

fn args_fixture(name: &str) -> MachineReconfigureArgs {
    MachineReconfigureArgs {
        name: name.into(), net: false, no_net: false,
        allow_host: vec![], clear_allow_host: false,
        cpus: None, memory: None, mem_initial: None, hypervisor: None,
    }
}

#[test]
fn apply_patch_overrides_only_set_fields_and_preserves_rest() {
    let mut args = args_fixture("web");
    args.cpus = Some(8);
    let patch = patch_from_args(&args).unwrap();
    let out = apply_patch(spec_fixture(), &patch);
    assert_eq!(out.cpus, 8);
    // Everything else preserved.
    assert_eq!(out.memory, "512M");
    assert_eq!(out.volumes, vec!["/data:/data:ro".to_string()]);
    assert!(!out.net);
}

#[test]
fn apply_patch_no_flags_is_noop() {
    let patch = patch_from_args(&args_fixture("web")).unwrap();
    assert_eq!(apply_patch(spec_fixture(), &patch), spec_fixture());
}

#[test]
fn patch_net_is_tri_state() {
    let mut on = args_fixture("web"); on.net = true;
    assert_eq!(patch_from_args(&on).unwrap().net, Some(true));
    let mut off = args_fixture("web"); off.no_net = true;
    assert_eq!(patch_from_args(&off).unwrap().net, Some(false));
    assert_eq!(patch_from_args(&args_fixture("web")).unwrap().net, None);
}

#[test]
fn patch_allow_host_replace_and_clear() {
    let mut replace = args_fixture("web");
    replace.allow_host = vec!["a:443".into()];
    let out = apply_patch(spec_fixture(), &patch_from_args(&replace).unwrap());
    assert_eq!(out.allow_host, vec!["a:443".to_string()]);

    let base = MachineSpec { allow_host: vec!["old:443".into()], ..spec_fixture() };
    let mut clear = args_fixture("web"); clear.clear_allow_host = true;
    let out = apply_patch(base, &patch_from_args(&clear).unwrap());
    assert!(out.allow_host.is_empty());
}

#[test]
fn patch_rejects_invalid_memory() {
    let mut args = args_fixture("web");
    args.memory = Some("notasize".into());
    assert!(patch_from_args(&args).is_err());
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p mvm-cli machine::tests -- apply_patch patch_`
Expected: FAIL — `ReconfigurePatch` / `patch_from_args` / `apply_patch`
not found.

- [ ] **Step 3: Implement the patch types**

In `crates/mvm-cli/src/commands/machine/mod.rs`:

```rust
/// A resolved patch over the reconfigurable `MachineSpec` fields. `None`
/// means "leave unchanged".
struct ReconfigurePatch {
    net: Option<bool>,
    allow_host: Option<Vec<String>>,
    cpus: Option<u32>,
    memory: Option<String>,
    mem_initial: Option<String>,
}

/// Resolve CLI flags into a patch, validating memory eagerly so a bad
/// size fails before we overwrite anything or bounce the VM.
fn patch_from_args(args: &MachineReconfigureArgs) -> Result<ReconfigurePatch> {
    let net = if args.net {
        Some(true)
    } else if args.no_net {
        Some(false)
    } else {
        None
    };
    let allow_host = if args.clear_allow_host {
        Some(Vec::new())
    } else if !args.allow_host.is_empty() {
        Some(args.allow_host.clone())
    } else {
        None
    };
    // Validate memory (and mem_initial) against the same parser the run
    // path uses; store the human string, not the parsed MiB.
    if let Some(mem) = args.memory.as_deref() {
        validate_machine_memory(mem, args.mem_initial.as_deref())?;
    }
    Ok(ReconfigurePatch {
        net,
        allow_host,
        cpus: args.cpus,
        memory: args.memory.clone(),
        mem_initial: args.mem_initial.clone(),
    })
}

/// Apply the patch: each `Some` overrides the corresponding field; the
/// rest of `spec` is inherited unchanged.
fn apply_patch(mut spec: MachineSpec, patch: &ReconfigurePatch) -> MachineSpec {
    if let Some(v) = patch.net {
        spec.net = v;
    }
    if let Some(v) = &patch.allow_host {
        spec.allow_host = v.clone();
    }
    if let Some(v) = patch.cpus {
        spec.cpus = v;
    }
    if let Some(v) = &patch.memory {
        spec.memory = v.clone();
    }
    if let Some(v) = &patch.mem_initial {
        spec.mem_initial = Some(v.clone());
    }
    spec
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p mvm-cli machine::tests -- apply_patch patch_`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(machine): reconfigure patch resolution + apply"
```

---

## Task 5: `run_reconfigure` handler

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs`
- Test: same file

**Interfaces:**
- Consumes: `patch_from_args`, `apply_patch` (Task 4),
  `load_machine_spec`, `machine_config_diff`, `overwrite_machine_spec`,
  `machine_is_running`, `stop_running_machine`, `start_machine`,
  `MachineStartArgs`.

- [ ] **Step 1: Write the failing test (unknown machine errors)**

```rust
#[test]
fn reconfigure_unknown_machine_errors_clearly() {
    let data = tempfile::tempdir().unwrap();
    // SAFETY: single-threaded test.
    unsafe { std::env::set_var("MVM_DATA_DIR", data.path()); }
    let mut args = args_fixture("does-not-exist");
    args.cpus = Some(4);
    let err = run_reconfigure(args).unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-cli machine::tests::reconfigure_unknown_machine`
Expected: FAIL — stub `bail!("not yet implemented")` message mismatch.

- [ ] **Step 3: Implement `run_reconfigure`**

Replace the Task-3 stub:

```rust
/// `machine reconfigure <name>`: patch the persisted spec and relaunch.
/// Patch semantics (only passed flags change), errors if the machine
/// doesn't exist, and — when running — stops + restarts so a fresh
/// signed ExecutionPlan reflects the change. When stopped, it persists
/// only; the change applies on the next `machine start`.
fn run_reconfigure(args: MachineReconfigureArgs) -> Result<()> {
    let existing = load_machine_spec(&args.name)?;
    let patch = patch_from_args(&args)?;
    let desired = apply_patch(existing.clone(), &patch);

    let changed = machine_config_diff(&existing, &desired);
    if changed.is_empty() {
        println!("machine {:?}: no changes", args.name);
        return Ok(());
    }

    let was_running = machine_is_running(&args.name);
    overwrite_machine_spec(&desired)?;

    if was_running {
        eprintln!(
            "reconfiguring {:?} ({changed}): stopping the old instance and restarting",
            args.name
        );
        stop_running_machine(&args.name);
        start_machine(MachineStartArgs {
            name: args.name.clone(),
            receipt: None,
            json: false,
            dry_run: false,
            quiet: false,
            hypervisor: args.hypervisor.clone(),
            no_supervisor: false,
            kernel_pin: None,
            has_ad_hoc_argv: false,
        })?;
    } else {
        println!(
            "machine {:?} reconfigured ({changed}); change applies on next `machine start`",
            args.name
        );
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p mvm-cli machine::tests::reconfigure_unknown_machine`
Expected: PASS.

- [ ] **Step 5: Full gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo nextest run --workspace`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(machine): implement machine reconfigure handler"
```

---

## Task 6: Docs, coordination note, status rollup

**Files:**
- Modify: `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`
- Modify: `public/src/content/docs/reference/cli-commands.md` (if it
  enumerates `machine` verbs — add `reconfigure`)

- [ ] **Step 1: mvmd coordination note**

Append a short note to the design doc's "Repo boundary" area (or a new
`specs/notes/2026-07-05-machine-reconfigure-mvmd-endpoint.md`) recording
the client-side contract mvmd must implement:
`POST /api/v1/sandboxes/{id}/reconfigure`, JSON body =
`{ net?, allow_host?, cpus?, memory_mib? }` (only set fields present),
response = the single-item sandbox envelope (`{ data: {...} }`).

- [ ] **Step 2: CLI reference docs**

If `public/src/content/docs/reference/cli-commands.md` lists `machine`
subcommands, add a `machine reconfigure <name> [flags]` entry with the
five patch flags and the auto-restart-when-running behavior.

- [ ] **Step 3: Status rollup**

Tick Plan 224 (Phase 1) in `specs/REFACTOR-STATUS.md` and bump its
"Last updated" date; add/adjust the `specs/SPRINT.md` entry to reflect
Phase 1 complete and Phase 2 (Plan 225) pending.

- [ ] **Step 4: Final gate + commit**

```bash
cargo fmt --all -- --check && cargo test --workspace --doc
git add specs/ public/
git commit -m "docs(machine): reconfigure CLI reference + mvmd endpoint note + status rollup"
```

---

## Self-Review notes

- **Spec coverage:** CLI verb (Tasks 3–5); patch semantics (Task 4);
  auto-restart-when-running + persist-only-when-stopped (Task 5);
  facade trait + DTO + gateway + local-unsupported + mock (Tasks 1–2);
  `mem_initial` CLI-only / facade common-four (Tasks 1, 3–4); mvmd
  boundary note (Task 6). Phase 2 (engine lift + real local impl) is
  Plan 225, out of scope here.
- **Type consistency:** `ReconfigureRequest` fields (Task 1) match the
  `ReconfigureBody` mapping (Task 2) and the `ReconfigurePatch`
  resolution (Task 4). `MachineStartArgs` field set matches the
  worktree definition used by `run_persistent`.
- **No placeholders:** every code step shows complete code; the one
  environment-specific step (`cli.rs` harness) says to mirror the
  existing neighboring machine tests.
