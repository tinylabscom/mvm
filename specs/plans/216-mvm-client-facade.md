# `mvm-client` local/remote facade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce an `mvm-client` crate whose `MvmClient` trait fronts local microVM operations (in-process `mvmctl`) and, later, a remote `mvmd` fleet (REST) — so `mvmctl` and `mvm-studio` drive local *or* fleet through one interface.

**Architecture:** Per `specs/notes/mvm-client-facade-design.md` and [ADR-104](../adrs/104-cloud-control-plane-trust-boundary.md). One async `MvmClient` trait, two implementations — `LocalBackend` (in-process mvmctl libraries) and `GatewayBackend` (reqwest → mvmd-gateway; loopback sidecar or remote fleet). The whole facade lives in the **mvm** repo: a REST client is defined by the wire protocol, not a Rust dependency, so `GatewayBackend` speaks HTTP without importing any mvmd crate, preserving `mvm ← mvmd`. The client holds **zero enforcement authority** (ADR-104 dumb-courier principle); it presents credentials and ships intent. This plan's detailed tasks build **S0 only** — the crate, the trait, the typed DTO contract, and a `MockBackend` — additive and unit-tested, with no backend wiring.

**Tech Stack:** Rust (workspace, edition 2024 idioms already in tree), `async-trait`, `serde` (+ `serde_json` for tests), `thiserror`, `tokio` (dev-only for S0 tests). `reqwest`/TLS arrive with `GatewayBackend` in a later slice, not here.

## Global Constraints

- **Toolchain:** use `~/.cargo/bin/cargo` (rustup), never Homebrew's `cargo`/`rustc`.
- **Gates before any task is "done":** `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`. All four must pass.
- **`mvm-core` stays runtime-free** — the `check-core-runtime-free` gate asserts `cargo tree -p mvm-core -e no-dev` carries no `tokio`. `mvm-client` is a **new crate, not `mvm-core`**; its async/`tokio` deps must never leak into `mvm-core`. Reused DTO structs that live in `mvm-core` must stay serde-only.
- **No `#[allow(clippy::too_many_arguments)]`** in hand-written code — use a params struct + builder instead.
- **No spec references in code comments** — no `ADR-…`, `Plan …`, `#NN`, `WN.X`, `Sprint …` tokens in `.rs` comments (the `check-no-spec-refs-in-comments` gate fails on them). `claim-10`/`claim 10` style tokens are allowed. Keep the *reasoning*, drop the citation.
- **No Claude co-author trailer** in any commit message; attribute to the user.
- **Comment style:** terse, WHY-not-WHAT, expert-human voice. No decorative bold, no hedging.
- **Paths via `mvm-core::config`** helpers — never inline `$HOME/.mvm`.
- **DTOs fail closed:** every wire type carries `#[serde(deny_unknown_fields)]` — the same untrusted-input discipline as the host↔guest types, because these DTOs will be deserialized by `mvmd-gateway` from the network (ADR-104).
- **Intent-shaped DTOs:** the wire contract carries *what to do*, never local host artifacts (signing keys, host paths). Key-domain separation is a constraint on the types, not only a runtime check.
- **S0 is purely additive** — it creates a new `crates/mvm-client/` crate and touches no existing file except the workspace `Cargo.toml` member list. No `mvmctl`/backend behavior changes until S1+.

---

## Slice roadmap

This file's detailed tasks implement **S0 only** — the additive crate + trait + DTO contract + mock. Each later slice gets its own plan section appended here as it is scheduled, so each slice stays a self-contained, reviewable, working deliverable.

| Slice | Deliverable | Status |
|---|---|---|
| **S0** | `crates/mvm-client/`: `MvmClient` trait + typed `dto` module + `MockBackend`; additive, unit-tested | **this plan** |
| S1 | `LocalBackend` — implement the trait over in-process machine lifecycle. Built **on the Plan 214 `mvm::machine` library**, not a forked boot path. **S1a** (list/stop/logs against stable `AnyBackend` seams; `run` returns an honest "pending" error) is executable once the machine spec/types are public; **S1b** wires `run` through `MachineBuilder`→launch after `feat/plan-214-machine-run` lands. See the S1 section below. | scoped; gated on Plan 214 machine lib |
| S2 | `mvmctl` consumes `mvm-client::LocalBackend` for its local `machine` verbs (behaviour-preserving); `mvm-studio` can link the same crate | later |
| S3 | `GatewayBackend` — `reqwest` → `mvmd-gateway` over the shared DTO contract, no mvmd imports. **Gated on ADR-104 Accepted + Plan 57 CT-1 (cross-tenant isolation) green** | later |
| S4 | `--remote <url>` CLI flag + backend selection + fail-closed client rules (TLS-or-refuse, mTLS-preferred, keychain/env token, endpoint-bound, version-skew hard-fail) | later |
| S5 | `mvmd-gateway` adopts the shared `dto` types (replacing `Result<Value>`); retire/thin the `mvmd-client` crate (cross-repo) | later |

---

## S0 — the crate, the trait, the DTO contract

### Task 1: Crate scaffold

**Files:**
- Create: `crates/mvm-client/Cargo.toml`
- Create: `crates/mvm-client/src/lib.rs`
- Modify: `Cargo.toml` (workspace `members` list — add `"crates/mvm-client"`)

**Interfaces:**
- Produces: a compiling `mvm_client` library crate with modules `error`, `dto`, `client`, `mock` (declared, filled by later tasks).

- [ ] **Step 1: Add the crate to the workspace members**

In the root `Cargo.toml`, add `"crates/mvm-client",` to the `members = [ ... ]` array (alphabetical-ish, next to the other `crates/mvm-*` entries).

- [ ] **Step 2: Write `crates/mvm-client/Cargo.toml`**

```toml
[package]
name = "mvm-client"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
async-trait.workspace = true
serde = { workspace = true, features = ["derive"] }
thiserror = "1"

[dev-dependencies]
serde_json = { workspace = true }
tokio = { workspace = true, features = ["macros", "rt"] }
```

Note: `async-trait`, `serde`, `serde_json`, and `tokio` are already workspace dependencies; `thiserror` is a **direct** version dep in this repo (`mvm-core` uses `thiserror = "1"`), not a workspace dep — hence the literal version here.

- [ ] **Step 3: Write `crates/mvm-client/src/lib.rs`**

```rust
//! The `MvmClient` facade: one trait fronting local microVM operations
//! (in-process) and a remote `mvmd` fleet (REST), so a caller drives either
//! target through the same calls. The remote implementation is a courier with
//! no enforcement authority — every security decision is made by the authority
//! that owns the path (the local host, or mvmd), never by this client.

pub mod client;
pub mod dto;
pub mod error;
pub mod mock;

// Crate-root re-exports are added by the tasks that define each item
// (`error` in Task 2, `client` in Task 4) so the crate builds at every step.
```

- [ ] **Step 4: Stub the modules so it compiles**

Create empty-but-valid files (filled by later tasks):
`crates/mvm-client/src/error.rs`, `dto.rs`, `client.rs`, `mock.rs`, each containing only a module doc line:

```rust
//! Placeholder — filled by the next task.
```

- [ ] **Step 5: Verify it builds**

Run: `~/.cargo/bin/cargo build -p mvm-client`
Expected: compiles clean (four empty modules, no re-exports yet).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/mvm-client/
git commit -m "feat(client): scaffold mvm-client crate"
```

### Task 2: Error type

**Files:**
- Modify: `crates/mvm-client/src/error.rs`

**Interfaces:**
- Produces: `pub enum MvmError` (`#[derive(Debug, thiserror::Error)]`) with variants `NotFound { id: String }`, `InvalidSpec { reason: String }`, `Backend { reason: String }`, `Unauthorized { reason: String }`; `pub type Result<T> = std::result::Result<T, MvmError>`.

- [ ] **Step 1: Write the failing test**

Append to `crates/mvm-client/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_displays_the_id() {
        let e = MvmError::NotFound { id: "m1".into() };
        assert_eq!(e.to_string(), "machine not found: m1");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo test -p mvm-client error:: -- --nocapture`
Expected: FAIL — `MvmError` not defined.

- [ ] **Step 3: Write the type**

Prepend to `crates/mvm-client/src/error.rs`:

```rust
//! The facade's error type. Deliberately transport-agnostic: a `LocalBackend`
//! and a `GatewayBackend` surface the same variants so callers branch on the
//! failure, not on which backend produced it.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MvmError>;

#[derive(Debug, Error)]
pub enum MvmError {
    #[error("machine not found: {id}")]
    NotFound { id: String },
    #[error("invalid machine spec: {reason}")]
    InvalidSpec { reason: String },
    #[error("backend error: {reason}")]
    Backend { reason: String },
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.cargo/bin/cargo test -p mvm-client error::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-client/src/error.rs
git commit -m "feat(client): MvmError transport-agnostic error type"
```

### Task 3: The DTO contract

**Files:**
- Modify: `crates/mvm-client/src/dto.rs`

**Interfaces:**
- Produces:
  - `MachineId(pub String)` — `#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]`.
  - `MachineStatus` enum: `Starting | Running | Stopped | Failed` — serde `rename_all = "snake_case"`.
  - `MachineSpec { name: String, image: String, cpus: u32, memory_mib: u32, env: Vec<(String, String)> }` — intent only.
  - `MachineState { id: MachineId, name: String, status: MachineStatus }`.
  - `MachineFilter { name: Option<String>, status: Option<MachineStatus> }` with `MachineFilter::all()`.
  - `LogOpts { follow: bool, tail_lines: Option<u32> }` with `Default`.
  - Every struct/enum is `#[serde(deny_unknown_fields)]` where it has fields.

- [ ] **Step 1: Write the failing tests**

Append to `crates/mvm-client/src/dto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_spec_serde_round_trips() {
        let spec = MachineSpec {
            name: "web".into(),
            image: "docker.io/lib/nginx:1".into(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("PORT".into(), "8080".into())],
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MachineSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn unknown_field_is_rejected_fail_closed() {
        // A gateway deserializes these from the network; unexpected fields must
        // fail closed, not be silently ignored.
        let err = serde_json::from_str::<MachineSpec>(
            r#"{"name":"w","image":"i","cpus":1,"memory_mib":64,"env":[],"rogue":true}"#,
        );
        assert!(err.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn machine_status_wire_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&MachineStatus::Running).unwrap(),
            "\"running\""
        );
    }

    #[test]
    fn filter_all_matches_nothing_set() {
        let f = MachineFilter::all();
        assert!(f.name.is_none() && f.status.is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test -p mvm-client dto::`
Expected: FAIL — types not defined.

- [ ] **Step 3: Write the DTOs**

Prepend to `crates/mvm-client/src/dto.rs`:

```rust
//! The wire contract. These types are the seam between a caller and any
//! backend; the same structs will be deserialized by mvmd-gateway from the
//! network, so they fail closed on unknown fields and carry intent only —
//! never local host artifacts (keys, paths).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineStatus {
    Starting,
    Running,
    Stopped,
    Failed,
}

/// What to run — intent only. No host paths, no signing material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u32,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineState {
    pub id: MachineId,
    pub name: String,
    pub status: MachineStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineFilter {
    pub name: Option<String>,
    pub status: Option<MachineStatus>,
}

impl MachineFilter {
    /// The unconstrained filter — matches every machine.
    pub fn all() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogOpts {
    pub follow: bool,
    pub tail_lines: Option<u32>,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test -p mvm-client dto::`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-client/src/dto.rs
git commit -m "feat(client): typed, fail-closed DTO contract"
```

### Task 4: The `MvmClient` trait

**Files:**
- Modify: `crates/mvm-client/src/client.rs`
- Modify: `crates/mvm-client/src/lib.rs` (add the crate-root re-exports now that the items exist)

**Interfaces:**
- Consumes: `dto::{MachineId, MachineSpec, MachineState, MachineFilter, LogOpts}`, `error::Result`.
- Produces: `#[async_trait] pub trait MvmClient: Send + Sync` with:
  - `async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>>`
  - `async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState>`
  - `async fn stop_machine(&self, id: &MachineId) -> Result<()>`
  - `async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>>`

- [ ] **Step 1: Write the failing test (object-safety + usable through a trait object)**

Append to `crates/mvm-client/src/client.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof the trait is object-safe: a `dyn MvmClient` must be
    // constructable, since callers (CLI, studio) hold one behind a box.
    #[test]
    fn trait_is_object_safe() {
        fn _accepts(_c: &dyn MvmClient) {}
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo test -p mvm-client client::`
Expected: FAIL — `MvmClient` not defined.

- [ ] **Step 3: Write the trait**

Prepend to `crates/mvm-client/src/client.rs`:

```rust
//! The facade trait. `async_trait` boxes the futures so `dyn MvmClient` stays
//! object-safe — callers hold one backend behind a trait object and never see
//! which transport is underneath.

use async_trait::async_trait;

use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState};
use crate::error::Result;

#[async_trait]
pub trait MvmClient: Send + Sync {
    /// List machines matching `filter`.
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>>;

    /// Launch a machine from `spec`; returns its initial state.
    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState>;

    /// Stop a machine by id. Idempotent: stopping a stopped machine is `Ok`.
    async fn stop_machine(&self, id: &MachineId) -> Result<()>;

    /// Fetch a machine's captured console/log bytes.
    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>>;
}
```

- [ ] **Step 4: Add the crate-root re-exports**

Append to `crates/mvm-client/src/lib.rs` (below the `pub mod` block):

```rust
pub use client::MvmClient;
pub use error::{MvmError, Result};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `~/.cargo/bin/cargo test -p mvm-client client::`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-client/src/client.rs crates/mvm-client/src/lib.rs
git commit -m "feat(client): MvmClient async facade trait"
```

### Task 5: `MockBackend` + lifecycle roundtrip

**Files:**
- Modify: `crates/mvm-client/src/mock.rs`

**Interfaces:**
- Consumes: `MvmClient`, all `dto` types, `MvmError`.
- Produces: `pub struct MockBackend` (in-memory, `Default`) implementing `MvmClient`. This is the reference consumer proving the trait is usable end-to-end and the fixture later tasks (and studio) test against.

- [ ] **Step 1: Write the failing test**

Append to `crates/mvm-client/src/mock.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::*;

    #[tokio::test]
    async fn run_then_list_then_stop_roundtrips() {
        let mock = MockBackend::default();

        let spec = MachineSpec {
            name: "web".into(),
            image: "img".into(),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
        };
        let started = mock.run_machine(spec).await.unwrap();
        assert_eq!(started.status, MachineStatus::Running);

        let listed = mock.list_machines(MachineFilter::all()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "web");

        mock.stop_machine(&started.id).await.unwrap();
        let after = mock.list_machines(MachineFilter::all()).await.unwrap();
        assert_eq!(after[0].status, MachineStatus::Stopped);
    }

    #[tokio::test]
    async fn stop_unknown_is_not_found() {
        let mock = MockBackend::default();
        let err = mock
            .stop_machine(&MachineId("nope".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, MvmError::NotFound { .. }));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test -p mvm-client mock::`
Expected: FAIL — `MockBackend` not defined.

- [ ] **Step 3: Write the mock**

Prepend to `crates/mvm-client/src/mock.rs`:

```rust
//! An in-memory `MvmClient` for tests and for callers to develop against before
//! a real backend exists. Not a production path.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::client::MvmClient;
use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus};
use crate::error::{MvmError, Result};

#[derive(Default)]
pub struct MockBackend {
    machines: Mutex<Vec<MachineState>>,
    next: Mutex<u64>,
}

#[async_trait]
impl MvmClient for MockBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let all = self.machines.lock().unwrap();
        Ok(all
            .iter()
            .filter(|m| filter.name.as_ref().is_none_or(|n| *n == m.name))
            .filter(|m| filter.status.is_none_or(|s| s == m.status))
            .cloned()
            .collect())
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        if spec.name.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "name must not be empty".into(),
            });
        }
        let mut n = self.next.lock().unwrap();
        *n += 1;
        let state = MachineState {
            id: MachineId(format!("m{n}")),
            name: spec.name,
            status: MachineStatus::Running,
        };
        self.machines.lock().unwrap().push(state.clone());
        Ok(state)
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        let mut all = self.machines.lock().unwrap();
        let m = all
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })?;
        m.status = MachineStatus::Stopped;
        Ok(())
    }

    async fn machine_logs(&self, id: &MachineId, _opts: LogOpts) -> Result<Vec<u8>> {
        let all = self.machines.lock().unwrap();
        if all.iter().any(|m| m.id == *id) {
            Ok(Vec::new())
        } else {
            Err(MvmError::NotFound { id: id.0.clone() })
        }
    }
}
```

If `is_none_or` is not yet stable on the pinned toolchain, replace with `map_or(true, ...)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test -p mvm-client mock::`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full crate + workspace gates**

Run:
```bash
~/.cargo/bin/cargo test -p mvm-client
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo clippy -p mvm-client --all-targets -- -D warnings
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-client/src/mock.rs
git commit -m "feat(client): in-memory MockBackend + lifecycle roundtrip"
```

---

## S0 self-review

- **Spec coverage (design note + ADR-104):** the trait, the typed intent-shaped DTO contract, and fail-closed `deny_unknown_fields` are all present; the dumb-courier/zero-authority property is structural (the trait carries no enforcement, backends land later). `LocalBackend`/`GatewayBackend`, `--remote`, and TLS/mTLS are explicitly **out of S0** (roadmap S1/S3/S4) — not gaps.
- **Runtime-free-core:** every S0 dep (`async-trait`, `serde`, `thiserror`, dev-only `tokio`) lives in `mvm-client`, never `mvm-core`; no task edits `mvm-core`.
- **Type consistency:** `run_machine` returns `MachineState` in Task 4's interface, Task 5's mock, and its test — consistent. `MachineFilter::all()`, `MachineId(String)`, and `MachineStatus` snake_case wire are used identically across Tasks 3–5.
- **Placeholder scan:** module stubs in Task 1 are explicitly replaced by Tasks 2–5; no `TODO`/`TBD` remains in shipped code.

## S1 — `LocalBackend` (scope; sequenced on the Plan 214 machine library)

**Deliverable:** a `LocalBackend` implementing `MvmClient` by driving local microVM lifecycle in-process, witnessed by a `run → list → stop` roundtrip against a temp `MVM_DATA_DIR`.

### Seam analysis (what's callable on `main` today)

| Op | Seam on `main` | Stability |
|---|---|---|
| `list_machines` | machine specs under `mvm_core::config::machine_state_root()` (`<MVM_DATA_DIR>/machines/<name>/machine.json`) + `mvm_backend::AnyBackend::{status,list}` | **stable** |
| `stop_machine` | `AnyBackend::stop(&VmId(name))` | **stable** |
| `machine_logs` | `AnyBackend::logs(&VmId, lines, hypervisor)` | **stable** |
| `run_machine` (boot) | **no exported seam yet** — boot is embedded in `crates/mvm-cli/src/commands/vm/up.rs::start_persistent_oci_machine`, coupled to admission/signing | **volatile — under active construction** |

### Decision — build on the Plan 214 machine library; do NOT fork the boot path

The boot seam `run_machine` needs is exactly what **Plan 214** is landing on `main` right now: `crates/mvm/src/machine/` (`Machine` / `MachineBuilder` → `select_backend` → *translate to a launchable `VmStartConfig`*, merged in #1337 / #1339 / #1340), with `machine run` wiring in flight on `feat/plan-214-machine-run`. Forking a second boot path from `up.rs` would duplicate that work, violate reuse-first, and race an active effort (see the standing rule against reimplementing existing machinery and against working over another session's live area).

Therefore S1 **consumes** the `mvm::machine` library for `run_machine` (`MachineBuilder` from the `MachineSpec` DTO → launch), and the stable `AnyBackend` + `mvm_core::config` seams for `list`/`stop`/`logs`. `LocalBackend` lives where it can reach both — it depends on `mvm` (runtime) and `mvm-backend`; to keep the facade light for remote-only consumers, gate `LocalBackend` behind a `local` cargo feature on `mvm-client` (default on for the CLI, off for a pure-REST studio build).

### Sequencing

- **S1a (executable now, non-throwaway):** `LocalBackend` `list_machines` / `stop_machine` / `machine_logs` against the stable `AnyBackend` + machine-spec seams; `run_machine` returns `MvmError::Backend { reason: "boot seam pending machine-library launch path" }` (fail honest, never silent stub). Witness: seed a machine spec in a temp `MVM_DATA_DIR`, assert `list` maps it to `MachineState` and `stop` is dispatched.
- **S1b (after `feat/plan-214-machine-run` lands on `main`):** wire `run_machine` through `mvm::machine::MachineBuilder` → launch; complete the `run → list → stop` witness. This is the slice that removes the interim error.

Coordinate S1b timing with the Plan 214 machine-run owner so the launch entrypoint `LocalBackend` calls is a supported public seam, not a reach-in.
