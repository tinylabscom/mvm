# SDK ↔ facade machine-client convergence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the two machine-driving clients — the SDK's subprocess `machine.rs` and the `mvm-client` facade — onto one `MvmClient` trait, so there is a single machine-driving contract and (eventually) a single admitted-boot path.

**Architecture:** Per [ADR-105](../adrs/105-sdk-facade-machine-client-convergence.md). `mvm-client` with `default-features = false` is cycle-safe (no `mvm-*` deps), so `mvm-sdk` depends on it for the trait + DTOs and provides a **subprocess** `impl MvmClient` (keeps shelling `mvmctl machine`, behind the trait) — avoiding the `mvm-sdk → mvm-backend → mvm-build → mvm-sdk` cycle. The CLI uses `LocalBackend`, studio uses `GatewayBackend`. The SDK's `Workload` IR lowers to the facade's operational `MachineSpec`. When the admitted-boot seam lands, both `run` paths route through one admission fn.

**Tech Stack:** Rust (workspace, edition 2024 idioms in tree), `async-trait`, `tokio` (subprocess + async trait), `serde`/`serde_json` (parse `mvmctl machine … --json`), `mvm-client` (trait + DTOs).

## Global Constraints

- **Toolchain:** use `~/.cargo/bin/cargo` (rustup), never Homebrew's.
- **Gates before any task is "done":** `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`. All four.
- **No dependency cycle.** `mvm-sdk` depends on `mvm-client` only with `default-features = false`. It must never pull the `local` feature (that reintroduces `mvm-backend` → the cycle). A guard test / `cargo tree` check should assert `mvm-sdk`'s `mvm-client` edge carries neither `local` nor `mvm-backend`.
- **One admission path.** No task adds a machine-boot path that skips signed-plan admission (claim 8). `run` stays an honest error until P4 wires the shared admitted-boot fn.
- **No `#[allow(clippy::too_many_arguments)]`; no spec refs in `.rs` comments; no Claude co-author trailer; terse WHY-comments; paths via `mvm-core::config`.** (Standard repo constraints.)
- **Reuse-first.** The point of this plan is to *remove* a duplicated driver — do not add a third. The SDK's existing authoring builders stay; only the lifecycle-driving surface converges.

---

## Slice roadmap

Detailed tasks below cover **P1** only. Each later slice gets its own section appended when scheduled.

| Slice | Deliverable | Status |
|---|---|---|
| **P0** | **Extract `LocalBackend` into `mvm-client-local`** so `mvm-client`'s manifest carries no `mvm-*` dep — the manifest-level cycle otherwise blocks P1 (see ADR-105 §"The unlock"). | **DONE** |
| **P1** | `mvm-sdk` depends on `mvm-client`; `SubprocessBackend` (`impl MvmClient`) for `list`/`stop`/`logs` shelling `mvmctl machine`; `cargo tree` cycle-guard test | **DONE** |
| P2 | `Workload`/`App` → `MachineSpec` lowering; the SDK run builder produces a `MachineSpec` | next |
| P3 | Migrate SDK live/invoke call sites to `MvmClient`; retire the duplicated lifecycle surface in `machine.rs` | later |
| P4 | When the admitted-boot seam lands (issue #1388 / Plan 214), route `LocalBackend::run` **and** the SDK subprocess `run` through the one admitted-boot library fn | later, dependency-gated |

> **P0/P1 landed** (impl PR alongside this doc): `mvm-client-local` extracted; `mvm-client` manifest is `mvm-*`-free; `SubprocessBackend` does stop/logs and parses `machine ls --json` for list (status reported `Stopped` — that CLI output carries no live state; noted below); `run` refuses pending the admitted-boot seam; cycle-guard green. The detailed task steps below are the record of how P1 was built.

---

## P1 — subprocess `MvmClient` in the SDK

### Task 1: Depend on the cycle-safe facade surface

**Files:**
- Modify: `crates/mvm-sdk/Cargo.toml`
- Modify: root `Cargo.toml` if `mvm-client` needs a `default-features = false` workspace-dep spelling.

**Interfaces:**
- Produces: `mvm-sdk` can name `mvm_client::{MvmClient, dto::*, MvmError}`.

- [ ] **Step 1: Add the dependency**

In `crates/mvm-sdk/Cargo.toml`, add:

```toml
mvm-client = { workspace = true, default-features = false }
```

(`async-trait`, `serde_json`, and `tokio` with `process` + `rt` are also required if not already present — add them.)

- [ ] **Step 2: Verify no cycle / no runtime pulled**

Run: `~/.cargo/bin/cargo tree -p mvm-sdk -e no-dev -i mvm-backend`
Expected: **error or empty** — `mvm-backend` must NOT appear in `mvm-sdk`'s tree. If it does, a feature leaked; fix before continuing.

- [ ] **Step 3: Build**

Run: `~/.cargo/bin/cargo build -p mvm-sdk`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-sdk/Cargo.toml Cargo.toml Cargo.lock
git commit -m "feat(sdk): depend on the mvm-client trait surface (cycle-safe, default features)"
```

### Task 2: A cycle guard test

**Files:**
- Create: `crates/mvm-sdk/tests/no_backend_dep.rs`

**Interfaces:**
- Produces: a test that fails if `mvm-sdk` ever links `mvm-backend` (the cycle sentinel).

- [ ] **Step 1: Write the failing test**

Create `crates/mvm-sdk/tests/no_backend_dep.rs`:

```rust
//! The SDK must reach machine lifecycle through the mvm-client trait's
//! subprocess impl, never by linking the runtime backend — that would form a
//! dependency cycle (sdk -> client(local) -> backend -> build -> sdk).

#[test]
fn sdk_does_not_link_mvm_backend() {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["tree", "-p", "mvm-sdk", "-e", "no-dev", "--prefix", "none"])
        .output()
        .expect("cargo tree runs");
    let tree = String::from_utf8_lossy(&out.stdout);
    assert!(
        !tree.lines().any(|l| l.trim_start().starts_with("mvm-backend ")),
        "mvm-sdk must not link mvm-backend (dependency cycle):\n{tree}"
    );
}
```

- [ ] **Step 2: Run to verify it passes now (guard, not red-first)**

Run: `~/.cargo/bin/cargo test -p mvm-sdk --test no_backend_dep`
Expected: PASS. (This is a regression sentinel; it should already hold after Task 1.)

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-sdk/tests/no_backend_dep.rs
git commit -m "test(sdk): guard against linking mvm-backend (cycle sentinel)"
```

### Task 3: The subprocess `MvmClient` impl — `stop` and `logs` first

**Files:**
- Create: `crates/mvm-sdk/src/facade.rs` (a new module; keeps the change off the existing `machine.rs` until P3)
- Modify: `crates/mvm-sdk/src/lib.rs` (add `pub mod facade;`)

**Interfaces:**
- Consumes: `mvm_client::{MvmClient, MvmError, dto::{MachineId, MachineState, MachineFilter, MachineSpec, LogOpts}}`; the existing `mvmctl` binary resolution (`MVM_CLI_BIN_ENV`, mirror `machine.rs::MachineClient::from_env`).
- Produces: `pub struct SubprocessBackend { cli_bin: PathBuf }` implementing `MvmClient`. `stop_machine` / `machine_logs` shell `mvmctl machine stop <id>` / `mvmctl machine logs <id>`; `list_machines` is Task 4; `run_machine` returns the honest "admitted-boot seam pending" error (P4).

- [ ] **Step 1: Write the failing test**

The commands shell a real `mvmctl`, so unit-test the pure parts: binary resolution and error mapping. Append to `facade.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_nonzero_exit_to_backend_error() {
        // A non-zero `mvmctl` exit becomes MvmError::Backend carrying stderr.
        let e = exit_to_error(2, "boom");
        assert!(matches!(e, mvm_client::MvmError::Backend { .. }));
    }

    #[tokio::test]
    async fn run_refuses_pending_admitted_boot() {
        let be = SubprocessBackend::new("mvmctl");
        let spec = mvm_client::dto::MachineSpec {
            name: "w".into(), image: "i".into(), cpus: 1, memory_mib: 64, env: vec![],
        };
        assert!(matches!(
            be.run_machine(spec).await,
            Err(mvm_client::MvmError::Backend { .. })
        ));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `~/.cargo/bin/cargo test -p mvm-sdk facade::`
Expected: FAIL — `SubprocessBackend` / `exit_to_error` not defined.

- [ ] **Step 3: Write the impl**

Prepend to `facade.rs`:

```rust
//! A subprocess-backed `MvmClient`: the SDK drives machine lifecycle through the
//! `mvmctl machine` CLI, behind the shared facade trait. The process boundary is
//! deliberate — linking the in-process backend here would form a dependency
//! cycle. `run` waits on the admitted-boot library seam so it never boots a
//! workload that skipped signed-plan admission.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use mvm_client::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState};
use mvm_client::{MvmClient, MvmError, Result};

pub struct SubprocessBackend {
    cli_bin: PathBuf,
}

impl SubprocessBackend {
    pub fn new(cli_bin: impl Into<PathBuf>) -> Self {
        Self { cli_bin: cli_bin.into() }
    }

    /// Resolve `mvmctl` from `MVM_CLI_BIN` (mirror `machine.rs::from_env`).
    pub fn from_env() -> Self {
        let bin = std::env::var("MVM_CLI_BIN").unwrap_or_else(|_| "mvmctl".into());
        Self::new(bin)
    }

    fn bin(&self) -> &Path {
        &self.cli_bin
    }
}

fn exit_to_error(code: i32, stderr: &str) -> MvmError {
    MvmError::Backend {
        reason: format!("`mvmctl machine` exited {code}: {}", stderr.trim()),
    }
}

#[async_trait]
impl MvmClient for SubprocessBackend {
    async fn list_machines(&self, _filter: MachineFilter) -> Result<Vec<MachineState>> {
        // Task 4.
        Err(MvmError::Backend { reason: "list not yet wired".into() })
    }

    async fn run_machine(&self, _spec: MachineSpec) -> Result<MachineState> {
        Err(MvmError::Backend {
            reason: "local run requires the admitted-boot library seam (signed-plan admission)".into(),
        })
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        let out = tokio::process::Command::new(self.bin())
            .args(["machine", "stop", &id.0])
            .output()
            .await
            .map_err(|e| MvmError::Backend { reason: format!("spawn mvmctl: {e}") })?;
        if out.status.success() {
            Ok(())
        } else {
            Err(exit_to_error(
                out.status.code().unwrap_or(-1),
                &String::from_utf8_lossy(&out.stderr),
            ))
        }
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let mut args = vec!["machine".to_string(), "logs".to_string(), id.0.clone()];
        if let Some(n) = opts.tail_lines {
            args.push("--lines".into());
            args.push(n.to_string());
        }
        let out = tokio::process::Command::new(self.bin())
            .args(&args)
            .output()
            .await
            .map_err(|e| MvmError::Backend { reason: format!("spawn mvmctl: {e}") })?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(exit_to_error(
                out.status.code().unwrap_or(-1),
                &String::from_utf8_lossy(&out.stderr),
            ))
        }
    }
}
```

Add `pub mod facade;` to `crates/mvm-sdk/src/lib.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `~/.cargo/bin/cargo test -p mvm-sdk facade::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-sdk/src/facade.rs crates/mvm-sdk/src/lib.rs
git commit -m "feat(sdk): subprocess MvmClient impl (stop/logs); run deferred to admitted-boot seam"
```

### Task 4: `list_machines` over `mvmctl machine ls --json`

**Files:**
- Modify: `crates/mvm-sdk/src/facade.rs`

**Interfaces:**
- Consumes: the `mvmctl machine ls --json` output contract. **Confirm the exact field names first** (`~/.cargo/bin/cargo run -- machine ls --json` on a host with a machine, or read `crates/mvm-cli/src/commands/machine/mod.rs::list_machines`). The mapping target is `MachineState { id, name, status }`.
- Produces: `list_machines` returning the parsed, filtered machines.

- [ ] **Step 1: Write the failing test (pure parse + map)**

Extract the parse into a pure fn so it tests without a subprocess. Append to `facade.rs` tests:

```rust
#[test]
fn parses_machine_ls_json_into_states() {
    // Shape mirrors `mvmctl machine ls --json` — CONFIRM the real field names
    // against the CLI before finalizing this fixture.
    let json = br#"[{"name":"web","status":"running"}]"#;
    let states = parse_machine_list(json).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].name, "web");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `~/.cargo/bin/cargo test -p mvm-sdk facade::parses_machine_ls_json`
Expected: FAIL — `parse_machine_list` not defined.

- [ ] **Step 3: Write the parse + wire `list_machines`**

Add a private `parse_machine_list(bytes: &[u8]) -> Result<Vec<MachineState>>` that deserializes the CLI's `machine ls --json` items into `MachineState` (mirror the CLI's persisted-spec fields — id/name/status — using a tolerant inbound struct, mapping the CLI status string via the same rules as `GatewayBackend`'s `map_status` if applicable; unknown → `Failed`). Then `list_machines` shells `mvmctl machine ls --json`, calls `parse_machine_list`, and applies `filter.matches`.

> Note: the CLI's `machine ls` lists **persisted** machines (including stopped), which is richer than `LocalBackend::list` (running VMs via `AnyBackend::list`). Record this semantic difference; do not silently assume they match. Whether to converge the two list semantics is a P3 question.

- [ ] **Step 4: Run to verify it passes**

Run: `~/.cargo/bin/cargo test -p mvm-sdk facade::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-sdk/src/facade.rs
git commit -m "feat(sdk): subprocess MvmClient list_machines over `machine ls --json`"
```

## P1 self-review

- **Cycle safety:** Task 1 uses `default-features = false`; Task 2 is a sentinel test. Constraint honored.
- **One admission path:** `run_machine` is an honest error in every impl; no task adds an admission-skipping boot. Constraint honored.
- **Reuse-first:** the new `facade.rs` is additive; `machine.rs`'s duplicated lifecycle surface is retired in P3, not forked further.
- **Placeholder scan:** `list_machines` is stubbed in Task 3 and completed in Task 4 (explicit), not left as a silent TODO. The `machine ls --json` field names are flagged for confirmation rather than guessed.
- **Type consistency:** `SubprocessBackend`, `exit_to_error`, `parse_machine_list`, and the `MvmClient` methods use the same `mvm_client::dto` types across tasks.

## Notes for P2+

P2 defines `Workload`/`App` → `MachineSpec` lowering (the run builder in `machine.rs` currently carries image/command; map those + resources → `MachineSpec`). P3 migrates SDK live/invoke to the trait and deletes the duplicated lifecycle methods on `machine.rs`. P4 is dependency-gated on the admitted-boot seam (issue #1388) and wires the single admission path for both `run` sites.
