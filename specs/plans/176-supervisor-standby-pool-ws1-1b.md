# Plan 176 — Supervisor Standby Pool (Plan 118 WS-1 Layer 1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline)
> or superpowers:subagent-driven-development to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.
>
> **This is Plan 118 WS-1 Layer 1b.** It is numbered 176 only because the
> `check-spec-numbers` gate requires a unique integer prefix and `118` is taken; the
> identity is "Plan 118 WS-1 1b". Parent design: `specs/plans/118-supervisor-standby-pool-and-live-bench.md`
> §"Part B". Builds directly on **1a (PR #748)**:
> `specs/notes/plan-118-ws1-layer1a-implementation-plan.md`.

**Goal:** Turn the 1a prelaunched-supervisor *primitive* into an actual warm pool —
spawn standbys, claim an idle one on launch (else cold-boot), and maintain the pool —
all behind a **backend-agnostic `VmBackend` trait seam** so Firecracker / Vz /
cloud-hypervisor implement the same methods, not one-offs.

**Architecture:** A new opt-in, fail-closed trait seam on `VmBackend`
(`supports_standby_pool` / `spawn_standby` / `claim_standby`) parallel to the existing
snapshot axis (`snapshot_capability` / `warm_start`). Backend-agnostic `Standby*` types
live in `mvm-core`. The `SupervisorStandbyPool` registry (state-dir under `~/.mvm/pool/`)
and the libkrun impl live in `mvm-backend`; libkrun's impl translates to the 1a
`SupervisorBaseConfig`/`SupervisorAttachConfig` wire types. Claim-on-launch + replenish
orchestration + CLI live in `mvm-cli`. The pool **fails open to cold boot** — it never
makes a launch fail that would otherwise succeed.

**Tech Stack:** Rust, `VmBackend` trait (`mvm-core`), the 1a libkrun prelaunch primitive
(`libkrun-sys` + `mvm-vm-host`), `mvm-hostd::framing` (sync length-prefixed JSON), `sha2`
(kernel identity), `rand` (binding nonce), Clap (CLI).

---

## Two stacked PRs

- **1b-i (core — Tasks 1–8):** trait seam + `Standby*` types + `warm_pool_size`; pool
  registry + libkrun `spawn_standby`/`claim_standby`; claim-on-launch + cold fallback +
  kernel-sha256 base-compat; `up --warm-pool-size N` + `mvmctl pool warm [N]`; default-off.
  Proves the warm-up works end-to-end (completes the 1a `#[ignore]`'d live boot).
- **1b-ii (lifecycle/ops — Tasks 9–14):** replenish-on-use; reaper TTL + `cache prune`;
  `mvmctl pool status` + `doctor` column; bench state-dir fix + cold-vs-warm delta
  (deferred baseline, then a time-boxed fresh-image baseline attempt); SPRINT.md
  multi-kernel deferred note.

Both PRs stack on `feat/plan-118-ws1-layer1b` (off the unmerged 1a branch
`feat/plan-118-ws1-layer1a`). Worktree: `../mvm-ws1b`.

## Build/test commands (repo gotchas)

- libkrun bits need the rustup toolchain prepended to PATH (Homebrew rustc shadows it →
  libkrun-sys bindgen E0514):
  ```bash
  RUSTUP="$HOME/.rustup/toolchains/$(rustup show active-toolchain | awk '{print $1}')/bin"
  PATH="$RUSTUP:$PATH" cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys
  ```
- The supervisor bin is feature-gated + not rebuilt by plain `cargo build`/`test` — build
  it explicitly when a live test needs the latest.
- Unit tests (no FFI): `cargo nextest run -p mvm-core -p mvm-backend -p mvm-cli -E 'not package(mvm-backend)'`.
  `mvm-backend` test bins codesign-SIGKILL on macOS — its *unit* tests run on Linux CI;
  locally exercise pool logic via `mvm-core`/`mvm-cli` tests + the `libkrun-live` lane.
- Gates before each commit closes a task: `cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`, `cargo test --workspace --doc`.

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `crates/mvm-core/src/protocol/vm_backend.rs` | `StandbySpec`/`StandbyHandle`/`StandbyClaim`/`StandbyState`/`StandbyError`; `VmBackend::{supports_standby_pool, spawn_standby, claim_standby}` (fail-closed defaults); `warm_pool_size: u32` on `VmStartConfig`. | Modify |
| `crates/mvm-core/src/config.rs` | `mvm_pool_dir()` + `pool_standby_dir(id)` helpers (next to `vm_state_dir`). | Modify |
| `crates/mvm-backend/src/standby_pool.rs` | `SupervisorStandbyPool` registry: record/load/list/select-idle-by-kernel/remove under `~/.mvm/pool/`. Backend-agnostic. | Create |
| `crates/mvm-backend/src/libkrun.rs` | libkrun `spawn_standby`/`claim_standby` impls + `supports_standby_pool`→true; translate to 1a `SupervisorBaseConfig`/`SupervisorAttachConfig`. | Modify |
| `crates/mvm-backend/src/lib.rs` | `pub mod standby_pool;` | Modify |
| `crates/mvm-cli/src/commands/pool.rs` | `mvmctl pool warm [N]` / `pool status`; `StandbySpec` builder (kernel sha256 + binding nonce + `host_signer_id()` + key path); claim-on-launch + replenish helpers. | Create |
| `crates/mvm-cli/src/commands/<up/run>.rs` | Wire warm-pool claim-then-replenish into the launch path; `--warm-pool-size`. | Modify |
| `crates/mvm-cli/src/commands/cache.rs` (1b-ii) | Reaper sweep of `~/.mvm/pool/` in `cache prune`. | Modify |
| `crates/mvm-cli/src/doctor.rs` (1b-ii) | Standby-pool column next to the warm-start matrix. | Modify |
| `crates/mvm-build/src/bench/…` (1b-ii) | Fix `~/.local/state` vs `~/.mvm` state-dir mismatch; cold-vs-warm delta span. | Modify |
| `specs/SPRINT.md` (1b-ii) | Deferred-follow-up note: multi-kernel pool keying. | Modify |

---

# PR 1b-i — core warm pool

## Task 1: Backend-agnostic `Standby*` types (mvm-core)

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (next to `SnapshotCapability`/`WarmStartError`, ~:460)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn standby_handle_serde_roundtrip_and_kernel_match() {
        let h = StandbyHandle {
            id: "standby-abc".into(),
            control_socket: "/p/standby-abc/control-deadbeef.sock".into(),
            pid: 4242,
            kernel_sha256: "a".repeat(64),
            binding_nonce: "deadbeef".repeat(8),
            spawned_unix_secs: 1_700_000_000,
            state: StandbyState::Idle,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: StandbyHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "standby-abc");
        assert_eq!(back.state, StandbyState::Idle);
        assert!(back.matches_kernel(&"a".repeat(64)));
        assert!(!back.matches_kernel(&"b".repeat(64)));
    }

    #[test]
    fn standby_error_is_std_error() {
        fn assert_err<E: std::error::Error>(_: &E) {}
        assert_err(&StandbyError::Unsupported { backend: "x".into() });
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core standby_`
Expected: FAIL — `StandbyHandle`/`StandbyState`/`StandbyError` not found.

- [ ] **Step 3: Add the types**

Insert after `WarmStartError` (~:478):

```rust
/// How a prelaunched standby is to be set up (Plan 118 WS-1 1b). Backend-agnostic:
/// the caller (the launch path) fills this in; the backend's `spawn_standby`
/// translates it to its own wire config (libkrun → `SupervisorBaseConfig`).
#[derive(Debug, Clone)]
pub struct StandbySpec {
    /// Stable id for this standby (also the `~/.mvm/pool/<id>/` dir name).
    pub id: String,
    /// Kernel image path the standby pre-loads.
    pub kernel_path: String,
    /// Lowercase-hex sha256 of the kernel image — the base-compat match key.
    pub kernel_sha256: String,
    /// Host-signer key path (claim 8) the standby re-verifies the attach plan against.
    pub signing_key_path: std::path::PathBuf,
    /// Expected envelope signer id (`host:{hostname}`) — the attach plan must match it.
    pub signer_id: String,
    /// Per-spawn binding nonce (hex of 32 random bytes); the attach must echo it.
    pub binding_nonce: String,
    /// Control UDS the standby binds and blocks on (0700 in a 0700 dir, nonce in path).
    pub control_socket: std::path::PathBuf,
    /// Per-VM state dir the standby writes its pid into.
    pub vm_state_dir: String,
}

/// A recorded, live standby (persisted as `~/.mvm/pool/<id>/standby.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyHandle {
    pub id: String,
    pub control_socket: std::path::PathBuf,
    pub pid: u32,
    pub kernel_sha256: String,
    pub binding_nonce: String,
    pub spawned_unix_secs: u64,
    pub state: StandbyState,
}

impl StandbyHandle {
    /// Base-compat: a launch may claim this standby only if its plan resolves to the
    /// same kernel image. v1 is default-kernel-only; multi-kernel keying is deferred
    /// (SPRINT.md). Exact sha256 match — no silent wrong-kernel boot.
    pub fn matches_kernel(&self, kernel_sha256: &str) -> bool {
        self.kernel_sha256 == kernel_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyState {
    /// Spawned, blocked on its control UDS, not yet claimed.
    Idle,
    /// An attach was sent; the standby is booting or has booted.
    Claimed,
}

/// What to attach to a claimed standby — the workload-specific half (the admitted,
/// signed plan + rootfs + audit substrate). Backend-agnostic.
#[derive(Debug, Clone)]
pub struct StandbyClaim {
    /// Workload rootfs ext4.
    pub rootfs_path: String,
    pub tenant_id: String,
    pub audit_dir: std::path::PathBuf,
    pub gateway_audit_socket: std::path::PathBuf,
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// JSON-encoded signed `ExecutionPlan` envelope (claim 8).
    pub plan_json: String,
    /// JSON-encoded `PolicyBundle`, if any.
    pub bundle_json: Option<String>,
}

/// Why a standby spawn/claim failed. Fail-closed: every variant means the caller must
/// fall back to a cold boot, never silently proceed without the workload.
#[derive(Debug, thiserror::Error)]
pub enum StandbyError {
    #[error("{backend}: standby pool is not supported by this backend")]
    Unsupported { backend: String },
    #[error("spawn standby: {0}")]
    SpawnFailed(String),
    #[error("claim standby: {0}")]
    ClaimFailed(String),
}
```

(`thiserror` is already a dep of mvm-core? confirm with `rg '^thiserror' crates/mvm-core/Cargo.toml`; if absent, add `thiserror = "1"`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-core standby_`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/protocol/vm_backend.rs
git commit -m "feat(core): backend-agnostic Standby{Spec,Handle,Claim,State,Error} for the warm-pool trait seam (Plan 118 WS-1 1b)"
```

## Task 2: `VmBackend` trait seam + `warm_pool_size` (mvm-core)

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (the `VmBackend` trait ~:681; `VmStartConfig` ~:30)
- Test: same file

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn standby_pool_defaults_are_fail_closed() {
        struct Bare;
        impl VmBackend for Bare {
            fn name(&self) -> &str { "bare" }
            fn capabilities(&self) -> VmCapabilities { VmCapabilities::default() }
            fn start_with_mode(&self, _: &VmStartConfig, _: StartMode) -> Result<VmId> { unreachable!() }
            fn stop(&self, _: &VmId) -> Result<()> { Ok(()) }
            fn status(&self, _: &VmId) -> Result<VmStatus> { unreachable!() }
            fn list(&self) -> Result<Vec<VmInfo>> { Ok(vec![]) }
        }
        let b = Bare;
        assert!(!b.supports_standby_pool());
        let spec = sample_standby_spec();
        match b.spawn_standby(&spec) {
            Err(StandbyError::Unsupported { backend }) => assert_eq!(backend, "bare"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn warm_pool_size_defaults_to_zero() {
        assert_eq!(VmStartConfig::default().warm_pool_size, 0);
    }
```

Add a `sample_standby_spec()` test helper returning a `StandbySpec` with dummy paths.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core standby_pool_defaults warm_pool_size`
Expected: FAIL — methods/field not found.

- [ ] **Step 3: Add the trait methods + the config field**

In `VmStartConfig` (before the closing `}` at ~:124):

```rust
    /// Plan 118 WS-1 1b — target warm-pool size. `0` (default) = feature off: no
    /// standbys, no idle RAM, no control UDS. A future Firecracker standby reads the
    /// same field (it's why this lives on the backend-agnostic config).
    pub warm_pool_size: u32,
```

In the `VmBackend` trait (after `warm_start`, ~:728):

```rust
    /// Does this backend support a prelaunched-supervisor standby pool (Plan 118
    /// WS-1 1b)? Opt-in, default `false` — orthogonal to `snapshot_capability`
    /// (snapshot = restore a booted VM; standby = pre-pay spawn/setup latency).
    fn supports_standby_pool(&self) -> bool { false }

    /// Spawn a prelaunched standby per `spec`, detached, blocked on its control UDS
    /// before any boot. Returns a [`StandbyHandle`] the pool records. Fail-closed:
    /// the default refuses so a backend opts in explicitly.
    fn spawn_standby(&self, _spec: &StandbySpec) -> std::result::Result<StandbyHandle, StandbyError> {
        Err(StandbyError::Unsupported { backend: self.name().to_string() })
    }

    /// Claim an idle standby: send its one-shot attach (the admitted signed plan +
    /// rootfs + audit substrate), which the supervisor re-verifies before boot.
    /// Returns the booted VM's [`VmId`]. Fail-closed default.
    fn claim_standby(
        &self,
        _handle: &StandbyHandle,
        _claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        Err(StandbyError::Unsupported { backend: self.name().to_string() })
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-core standby_pool_defaults warm_pool_size`
Expected: PASS. Then `cargo build -p mvm-core` (a new non-defaulted `VmStartConfig` field
compiles because the struct derives `Default`; any literal struct constructors in the
workspace that don't use `..Default::default()` need the field — fix those in Step 4b).

- [ ] **Step 4b: Fix any exhaustive `VmStartConfig { … }` literals**

Run: `rg -n 'VmStartConfig \{' crates --type rust` and add `warm_pool_size: 0,` (or
`..Default::default()`) to any literal that lists fields exhaustively. Re-run
`cargo build --workspace`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/protocol/vm_backend.rs
git commit -m "feat(core): VmBackend standby-pool trait seam + warm_pool_size (fail-closed, opt-in) (Plan 118 WS-1 1b)"
```

## Task 3: Pool dir config helpers (mvm-core)

**Files:**
- Modify: `crates/mvm-core/src/config.rs` (next to `vm_state_dir`, :336)
- Test: same file

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn pool_dirs_live_under_mvm_data_dir() {
        let _g = EnvGuard::set("MVM_DATA_DIR", "/tmp/mvm-test-home/.mvm");
        assert_eq!(mvm_pool_dir().unwrap(), std::path::PathBuf::from("/tmp/mvm-test-home/.mvm/pool"));
        assert_eq!(
            pool_standby_dir("standby-abc").unwrap(),
            std::path::PathBuf::from("/tmp/mvm-test-home/.mvm/pool/standby-abc")
        );
    }
```

(Use the file's existing env-guard pattern — `rg -n 'EnvGuard|fn.*env' crates/mvm-core/src/config.rs` to match it.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core pool_dirs_live`
Expected: FAIL — `mvm_pool_dir`/`pool_standby_dir` not found.

- [ ] **Step 3: Add the helpers**

After `vm_state_dir` (:336), mirroring its `mvm_data_dir_strict()` use:

```rust
/// `~/.mvm/pool/` — the supervisor standby pool root (Plan 118 WS-1 1b). Each idle
/// standby gets a `pool/<id>/` subdir holding its control UDS + `standby.json`.
pub fn mvm_pool_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(mvm_data_dir_strict()?.join("pool"))
}

/// `~/.mvm/pool/<id>/` for a single standby.
pub fn pool_standby_dir(id: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(mvm_pool_dir()?.join(id))
}
```

- [ ] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-core pool_dirs_live` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/config.rs
git commit -m "feat(core): mvm_pool_dir + pool_standby_dir helpers under ~/.mvm/pool (Plan 118 WS-1 1b)"
```

## Task 4: `SupervisorStandbyPool` registry (mvm-backend)

The backend-agnostic state-dir registry: persist/load standby handles, select an idle one
matching a kernel, remove a dead/claimed one. No libkrun specifics here.

**Files:**
- Create: `crates/mvm-backend/src/standby_pool.rs`
- Modify: `crates/mvm-backend/src/lib.rs` (`pub mod standby_pool;`)
- Test: in `standby_pool.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::vm_backend::{StandbyHandle, StandbyState};

    fn handle(id: &str, kernel: &str, state: StandbyState) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            control_socket: format!("/p/{id}/control.sock").into(),
            pid: std::process::id(), // a live pid so liveness passes
            kernel_sha256: kernel.into(),
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state,
        }
    }

    #[test]
    fn record_then_load_roundtrips_under_pool_root() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("s1", "aa", StandbyState::Idle)).unwrap();
        let loaded = pool.load("s1").unwrap();
        assert_eq!(loaded.id, "s1");
        assert_eq!(loaded.state, StandbyState::Idle);
    }

    #[test]
    fn select_idle_matches_kernel_and_skips_claimed_and_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("claimed", "aa", StandbyState::Claimed)).unwrap();
        let mut dead = handle("dead", "aa", StandbyState::Idle);
        dead.pid = 999_999; // not a live pid
        pool.record(&dead).unwrap();
        pool.record(&handle("good", "aa", StandbyState::Idle)).unwrap();
        pool.record(&handle("wrong-kernel", "bb", StandbyState::Idle)).unwrap();

        let picked = pool.select_idle_for_kernel("aa").unwrap();
        assert_eq!(picked.unwrap().id, "good");
        assert!(pool.select_idle_for_kernel("cc").unwrap().is_none());
    }

    #[test]
    fn remove_deletes_the_standby_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("s1", "aa", StandbyState::Idle)).unwrap();
        assert!(tmp.path().join("s1").exists());
        pool.remove("s1").unwrap();
        assert!(!tmp.path().join("s1").exists());
    }

    #[test]
    fn idle_count_for_kernel_counts_only_live_idle_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("a", "aa", StandbyState::Idle)).unwrap();
        pool.record(&handle("b", "aa", StandbyState::Claimed)).unwrap();
        assert_eq!(pool.idle_count_for_kernel("aa").unwrap(), 1);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-backend -E 'test(standby_pool)' 2>/dev/null || cargo test -p mvm-backend standby_pool::tests`
Expected: FAIL — `SupervisorStandbyPool` not found. (On macOS the mvm-backend *binary*
SIGKILLs under `nextest --list`; use `cargo test -p mvm-backend standby_pool::tests` here,
which runs the lib test directly.)

- [ ] **Step 3: Implement the registry**

```rust
//! Plan 118 WS-1 1b — the backend-agnostic supervisor standby pool registry.
//!
//! Records each prelaunched standby as `<pool_root>/<id>/standby.json` (the control
//! UDS lives alongside as `control-<nonce>.sock`, bound by the backend's spawn impl).
//! Selection/liveness/removal are backend-agnostic; only `spawn_standby`/`claim_standby`
//! on the `VmBackend` impl know how to actually launch. Default-off: with
//! `warm_pool_size == 0` the orchestration never constructs a pool.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::protocol::vm_backend::{StandbyHandle, StandbyState};

/// Filename of the per-standby metadata JSON inside its dir.
const HANDLE_FILE: &str = "standby.json";

/// A view over `~/.mvm/pool/` (or a test root). Cheap to construct; all state is on disk.
pub struct SupervisorStandbyPool {
    root: PathBuf,
}

impl SupervisorStandbyPool {
    /// Open the pool at the real `~/.mvm/pool/` root.
    pub fn open() -> Result<Self> {
        Ok(Self::at(mvm_core::config::mvm_pool_dir()?))
    }

    /// Open at an explicit root (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Persist (or update) a standby's handle under `<root>/<id>/standby.json`,
    /// creating the dir `0700`.
    pub fn record(&self, h: &StandbyHandle) -> Result<()> {
        let dir = self.root.join(&h.id);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        set_mode_0700(&dir)?;
        let json = serde_json::to_vec_pretty(h)?;
        std::fs::write(dir.join(HANDLE_FILE), json)
            .with_context(|| format!("write {} handle", h.id))?;
        Ok(())
    }

    /// Load one standby's handle by id.
    pub fn load(&self, id: &str) -> Result<StandbyHandle> {
        let path = self.root.join(id).join(HANDLE_FILE);
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// All recorded handles (ignoring unreadable/garbage dirs — they get reaped in 1b-ii).
    pub fn list(&self) -> Result<Vec<StandbyHandle>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).context("read pool root"),
        };
        for entry in rd.flatten() {
            if let Ok(h) = self.load(&entry.file_name().to_string_lossy()) {
                out.push(h);
            }
        }
        Ok(out)
    }

    /// Pick a live, idle standby whose kernel matches — the claim candidate. `None`
    /// means "no compatible warm standby; cold-boot." Skips claimed and dead entries.
    pub fn select_idle_for_kernel(&self, kernel_sha256: &str) -> Result<Option<StandbyHandle>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|h| h.state == StandbyState::Idle && h.matches_kernel(kernel_sha256) && pid_alive(h.pid)))
    }

    /// Count of live idle standbys for a kernel — drives replenish-to-target (1b-ii).
    pub fn idle_count_for_kernel(&self, kernel_sha256: &str) -> Result<usize> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|h| h.state == StandbyState::Idle && h.matches_kernel(kernel_sha256) && pid_alive(h.pid))
            .count())
    }

    /// Mark a standby `Claimed` (persisted) — so a concurrent launch won't double-claim.
    pub fn mark_claimed(&self, id: &str) -> Result<()> {
        let mut h = self.load(id)?;
        h.state = StandbyState::Claimed;
        self.record(&h)
    }

    /// Remove a standby's dir (after claim/boot, or when reaping a dead one).
    pub fn remove(&self, id: &str) -> Result<()> {
        let dir = self.root.join(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove {}", dir.display())),
        }
    }
}

/// `kill(pid, 0)` liveness — 0 ⇒ the process exists (W1.2 reaper precedent).
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn set_mode_0700(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))
}
```

Add `pub mod standby_pool;` to `crates/mvm-backend/src/lib.rs`. (`libc` is already a
mvm-backend dep — confirm via `rg '^libc' crates/mvm-backend/Cargo.toml`.)

- [ ] **Step 4: Run to verify it passes** — `cargo test -p mvm-backend standby_pool::tests` → PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/standby_pool.rs crates/mvm-backend/src/lib.rs
git commit -m "feat(backend): SupervisorStandbyPool registry — record/select-idle-by-kernel/remove under ~/.mvm/pool (Plan 118 WS-1 1b)"
```

## Task 5: libkrun `spawn_standby` / `claim_standby` (mvm-backend)

Translate the backend-agnostic `Standby*` types to the 1a libkrun wire types and drive the
prelaunch primitive: `spawn_standby` spawns `mvm-libkrun-supervisor` with a
`{"prelaunch_base": …}` stdin envelope detached; `claim_standby` frames a
`SupervisorAttachConfig` to the control UDS.

**Files:**
- Modify: `crates/mvm-backend/src/libkrun.rs`
- Test: same file (pure translation unit tests; live boot is Task 8)

- [ ] **Step 1: Write the failing tests** (pure translators — no spawn/boot)

```rust
    #[test]
    fn standby_spec_translates_to_prelaunch_base_envelope() {
        let spec = sample_standby_spec(); // kernel/key/nonce/control paths
        let base = super::standby_base_config(&spec).expect("base");
        assert!(base.krun.rootfs_path.is_none(), "a standby carries no workload rootfs");
        assert_eq!(base.binding_nonce, spec.binding_nonce);
        assert_eq!(base.signer_id, spec.signer_id);
        assert_eq!(base.control_socket_path, spec.control_socket);
        // The bin dispatches on the `prelaunch_base` wrapper key.
        let env = serde_json::json!({ "prelaunch_base": base });
        assert!(env.get("prelaunch_base").is_some());
    }

    #[test]
    fn standby_claim_translates_to_attach_config_echoing_nonce() {
        let attach = super::standby_attach_config(&sample_standby_claim(), "ab".repeat(32));
        assert_eq!(attach.binding_nonce, "ab".repeat(32));
        assert_eq!(attach.rootfs_path, "/vol/rootfs.ext4");
        assert_eq!(attach.tenant_id, "tenant-a");
        assert_eq!(attach.plan, serde_json::json!({"signed": "envelope"}));
    }
```

(`sample_standby_spec`/`sample_standby_claim` test helpers in this module; the claim's
`plan_json` is `r#"{"signed":"envelope"}"#`.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-backend libkrun::tests::standby` → FAIL (functions not found).

- [ ] **Step 3: Implement the translators + trait impls**

Add free functions (pure, unit-testable) + wire the trait methods. In `libkrun.rs`:

```rust
use libkrun_sys::{
    BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig,
};
use mvm_core::protocol::vm_backend::{StandbyClaim, StandbyError, StandbyHandle, StandbySpec, StandbyState};

/// Build the 1a `SupervisorBaseConfig` (workload-independent) from a backend-agnostic
/// `StandbySpec`. `rootfs_path` stays `None` — the workload rootfs arrives at claim.
fn standby_base_config(spec: &StandbySpec) -> Result<SupervisorBaseConfig, StandbyError> {
    // Kernel-only KrunContext: vsock wiring incl. the workload-exit + agent ports the
    // bridge path expects. Reuse the same KrunContext the cold libkrun start() builds,
    // minus the rootfs. (Factor the shared KrunContext assembly so this and start()
    // don't drift — see `krun_context_for_kernel` below.)
    let mut krun = krun_context_for_kernel(&spec.id, &spec.kernel_path, &spec.vm_state_dir)
        .map_err(|e| StandbyError::SpawnFailed(format!("build KrunContext: {e}")))?;
    krun.rootfs_path = None;
    Ok(SupervisorBaseConfig {
        krun,
        vm_state_dir: spec.vm_state_dir.clone(),
        pid_file_name: None,
        signing_key_path: spec.signing_key_path.clone(),
        signer_id: spec.signer_id.clone(),
        binding_nonce: spec.binding_nonce.clone(),
        control_socket_path: spec.control_socket.clone(),
        bridge_restart_policy: BridgeRestartPolicy::HardFail,
    })
}

/// Build the 1a `SupervisorAttachConfig` from a `StandbyClaim`, echoing the standby's
/// binding nonce. `plan_json`/`bundle_json` are decoded to `serde_json::Value` carriers
/// (the same shape `SupervisorConfig.plan` uses).
fn standby_attach_config(claim: &StandbyClaim, binding_nonce: String) -> Result<SupervisorAttachConfig, StandbyError> {
    let plan: serde_json::Value = serde_json::from_str(&claim.plan_json)
        .map_err(|e| StandbyError::ClaimFailed(format!("decode plan_json: {e}")))?;
    let bundle = match &claim.bundle_json {
        Some(b) => Some(serde_json::from_str(b).map_err(|e| StandbyError::ClaimFailed(format!("decode bundle_json: {e}")))?),
        None => None,
    };
    Ok(SupervisorAttachConfig {
        binding_nonce,
        rootfs_path: claim.rootfs_path.clone(),
        tenant_id: claim.tenant_id.clone(),
        audit_dir: claim.audit_dir.clone(),
        gateway_audit_socket: claim.gateway_audit_socket.clone(),
        gateway_events_socket: claim.gateway_events_socket.clone(),
        plan,
        bundle,
    })
}
```

> **Note (`krun_context_for_kernel`):** factor the existing rootfs+kernel KrunContext
> assembly inside libkrun `start()` into a `fn krun_context_for_kernel(name, kernel,
> state_dir) -> Result<KrunContext>` that sets vsock ports/console/networking the same way
> `start()` does, and have both `start()` and `standby_base_config` call it (DRY — reuse,
> don't fork). Grep the current `start()` for where it builds `KrunContext::new(...)` and
> lift the shared part.

Then the trait impls on the libkrun backend struct:

```rust
fn supports_standby_pool(&self) -> bool { true }

fn spawn_standby(&self, spec: &StandbySpec) -> std::result::Result<StandbyHandle, StandbyError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let base = standby_base_config(spec)?;
    // Control UDS dir 0700 (the bin re-binds the socket itself; pre-create the dir).
    if let Some(parent) = spec.control_socket.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StandbyError::SpawnFailed(e.to_string()))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let envelope = serde_json::to_vec(&serde_json::json!({ "prelaunch_base": base }))
        .map_err(|e| StandbyError::SpawnFailed(e.to_string()))?;

    let bin = resolve_supervisor_path().map_err(|e| StandbyError::SpawnFailed(e.to_string()))?;
    let mut child = std::process::Command::new(bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| StandbyError::SpawnFailed(format!("spawn supervisor: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| StandbyError::SpawnFailed("no stdin".into()))?
        .write_all(&envelope)
        .map_err(|e| StandbyError::SpawnFailed(format!("write base config: {e}")))?;
    // Detached: do not wait. The bin blocks on the control UDS until claimed.
    let pid = child.id();
    Ok(StandbyHandle {
        id: spec.id.clone(),
        control_socket: spec.control_socket.clone(),
        pid,
        kernel_sha256: spec.kernel_sha256.clone(),
        binding_nonce: spec.binding_nonce.clone(),
        spawned_unix_secs: now_unix_secs(),
        state: StandbyState::Idle,
    })
}

fn claim_standby(&self, handle: &StandbyHandle, claim: &StandbyClaim) -> std::result::Result<VmId, StandbyError> {
    let attach = standby_attach_config(claim, handle.binding_nonce.clone())?;
    let mut stream = std::os::unix::net::UnixStream::connect(&handle.control_socket)
        .map_err(|e| StandbyError::ClaimFailed(format!("connect control UDS: {e}")))?;
    mvm_hostd::framing::write_json_frame_sync(&mut stream, &attach)
        .map_err(|e| StandbyError::ClaimFailed(format!("send attach: {e}")))?;
    // The supervisor re-verifies (1a) then start_enters; it writes its pid into the
    // state dir. The VmId is the standby's name (the state-dir key), matching the cold
    // path's VmId convention.
    Ok(VmId::from(handle.id.clone()))
}
```

Add small helpers `now_unix_secs()` (`std::time::SystemTime` since `UNIX_EPOCH`) if not
present. `VmId::from` — confirm the constructor (`rg 'impl.*VmId' crates/mvm-core`); use
the existing one.

- [ ] **Step 4: Run to verify it passes** — `cargo test -p mvm-backend libkrun::tests::standby` → PASS. Then build the bin so a later live test uses the latest:
  `PATH="$RUSTUP:$PATH" cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/libkrun.rs
git commit -m "feat(backend): libkrun spawn_standby/claim_standby — drive the 1a prelaunch primitive behind the trait (Plan 118 WS-1 1b)"
```

## Task 6: Standby-spec builder + claim helper (mvm-cli)

The launch-path glue that owns `host_signer_id()` + the key path + kernel sha256 + the
binding nonce, and turns "I want to launch this workload" into either a claim or a cold boot.

**Files:**
- Create: `crates/mvm-cli/src/commands/pool.rs`
- Modify: `crates/mvm-cli/src/commands/mod.rs` (`pub mod pool;`)
- Test: in `pool.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_sha256_hex_is_64_chars_of_known_content() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"hello-kernel").unwrap();
        let hex = kernel_sha256_hex(&kp).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // sha256("hello-kernel") is stable.
        assert_eq!(hex, sha256_hex_of(b"hello-kernel"));
    }

    #[test]
    fn fresh_binding_nonce_is_64_hex_chars_and_varies() {
        let a = fresh_binding_nonce();
        let b = fresh_binding_nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn standby_spec_for_uses_pool_dir_and_nonce_in_socket_path() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"k").unwrap();
        let spec = build_standby_spec(tmp.path(), &kp, "host:test", &tmp.path().join("key")).unwrap();
        assert!(spec.control_socket.to_string_lossy().contains(&spec.binding_nonce));
        assert!(spec.control_socket.starts_with(tmp.path()));
        assert_eq!(spec.kernel_sha256.len(), 64);
    }
}
```

Provide a `sha256_hex_of(&[u8]) -> String` test helper (or compute inline).

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli pool::tests` → FAIL.

- [ ] **Step 3: Implement the builder helpers**

```rust
//! Plan 118 WS-1 1b — warm-pool launch glue + the `mvmctl pool` command.
//!
//! Owns the bits that must live above the backend: the kernel-identity hash (base-compat
//! key), the per-spawn binding nonce, and the host signer identity/key path that the
//! standby re-verifies the attach plan against (claim 8). Builds a backend-agnostic
//! `StandbySpec` and drives the `SupervisorStandbyPool` + `VmBackend` trait methods.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::protocol::vm_backend::StandbySpec;
use sha2::{Digest, Sha256};

use super::vm::host_signer::host_signer_id;

/// Lowercase-hex sha256 of a kernel image — the base-compat match key.
pub fn kernel_sha256_hex(kernel: &Path) -> Result<String> {
    let bytes = std::fs::read(kernel).with_context(|| format!("read kernel {}", kernel.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex_lower(&digest))
}

/// 32 random bytes as lowercase hex — the per-spawn binding nonce.
pub fn fresh_binding_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex_lower(&buf)
}

/// Build a `StandbySpec` for a standby that pre-loads `kernel`. The control UDS lives
/// under `pool_root/<id>/control-<nonce>.sock` (nonce in the path — defense in depth).
pub fn build_standby_spec(
    pool_root: &Path,
    kernel: &Path,
    signer_id: &str,
    signing_key_path: &Path,
) -> Result<StandbySpec> {
    let nonce = fresh_binding_nonce();
    let id = format!("standby-{}", &nonce[..16]);
    let dir = pool_root.join(&id);
    Ok(StandbySpec {
        id: id.clone(),
        kernel_path: kernel.to_string_lossy().into_owned(),
        kernel_sha256: kernel_sha256_hex(kernel)?,
        signing_key_path: signing_key_path.to_path_buf(),
        signer_id: signer_id.to_string(),
        control_socket: dir.join(format!("control-{nonce}.sock")),
        binding_nonce: nonce,
        vm_state_dir: dir.to_string_lossy().into_owned(),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

(`sha2` + `rand` are workspace deps — confirm in `crates/mvm-cli/Cargo.toml`; add if
missing. `host_signer_id` import path: confirm with `rg 'pub fn host_signer_id' crates/mvm-cli`.)

- [ ] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-cli pool::tests` → PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/pool.rs crates/mvm-cli/src/commands/mod.rs
git commit -m "feat(cli): warm-pool StandbySpec builder — kernel sha256 + binding nonce + signer identity (Plan 118 WS-1 1b)"
```

## Task 7: Claim-on-launch + `--warm-pool-size` + `pool warm` (mvm-cli)

> **RE-SCOPED DURING EXECUTION (2026-06-09).** `up.rs` turned out to have **five**
> `backend.start` sites across direct-boot / re-exec / wait paths — wiring auto-claim into
> that admission-heavy code is delicate and deserves isolated review, and both the
> `mvmctl pool` command and the `up` auto-claim need the same default-kernel + hypervisor
> resolution. So Task 7 was split:
> - **Landed in 1b-i:** the orchestration *helpers* — `claim_or_cold` (fail-open to cold)
>   + `warm_to_target` + the `StandbySpec` builder — unit-tested against a stub backend
>   (`crates/mvm-cli/src/commands/pool.rs`, `#[allow(dead_code)]` until wired).
> - **Moved to 1b-ii:** the `mvmctl pool warm [N]` / `pool status` **command**, the
>   `--warm-pool-size` flag on `up`, and the **claim-on-launch + replenish wiring** into
>   the `up`/`run` path (the fragile part, with the shared kernel/hypervisor resolution).
>
> The remainder of this task as originally written is the 1b-ii work.

Wire it into the launch path: on `up`/`run`, if `warm_pool_size > 0` and a compatible idle
standby exists, claim it; else cold-boot. After a successful launch, warm the pool toward
target (the explicit-fill half of UX option A). Add `mvmctl pool warm [N]`.

**Files:**
- Modify: `crates/mvm-cli/src/commands/pool.rs` (claim/replenish orchestration + the `pool` subcommand)
- Modify: the launch command (`rg -n 'fn .*up|warm_pool_size|backend.start' crates/mvm-cli/src/commands/` to find the `up`/`run` path) + the Clap arg struct for `--warm-pool-size`
- Test: `pool.rs` (claim-vs-cold decision is unit-testable with a mock backend) + `crates/mvm-cli/tests/cli.rs` (flag parsing)

- [ ] **Step 1: Write the failing tests**

In `pool.rs` (decision logic against a stub backend that records calls):

```rust
    #[test]
    fn claim_or_cold_claims_when_idle_standby_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = mvm_backend::standby_pool::SupervisorStandbyPool::at(tmp.path());
        pool.record(&idle_handle("s1", "aa")).unwrap();
        let backend = RecordingBackend::new("aa"); // claim_standby returns VmId("s1")
        let decision = claim_or_cold(&pool, &backend, "aa", &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::Claimed(VmId::from("s1")));
        assert!(backend.claimed());           // claim_standby called
        assert!(!pool.load("s1").is_ok());     // claimed standby dir removed after boot
    }

    #[test]
    fn claim_or_cold_falls_back_to_cold_when_no_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = mvm_backend::standby_pool::SupervisorStandbyPool::at(tmp.path());
        let backend = RecordingBackend::new("aa");
        let decision = claim_or_cold(&pool, &backend, "aa", &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(!backend.claimed());
    }

    #[test]
    fn claim_or_cold_falls_back_to_cold_when_claim_errors() {
        // A standby whose claim fails (e.g. it died / refused the attach) must NOT fail
        // the launch — fall open to cold boot.
        let tmp = tempfile::tempdir().unwrap();
        let pool = mvm_backend::standby_pool::SupervisorStandbyPool::at(tmp.path());
        pool.record(&idle_handle("s1", "aa")).unwrap();
        let backend = RecordingBackend::failing("aa");
        let decision = claim_or_cold(&pool, &backend, "aa", &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(!pool.load("s1").is_ok(), "a failed standby is removed, not left idle");
    }
```

In `crates/mvm-cli/tests/cli.rs`:

```rust
    #[test]
    fn up_accepts_warm_pool_size_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--warm-pool-size", "2"]).unwrap();
        // assert the parsed value threads to the command's warm_pool_size (match the
        // existing up-args assertion style in this file).
    }

    #[test]
    fn pool_warm_parses_optional_count() {
        assert!(Cli::try_parse_from(["mvmctl", "pool", "warm"]).is_ok());
        assert!(Cli::try_parse_from(["mvmctl", "pool", "warm", "3"]).is_ok());
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli claim_or_cold up_accepts_warm_pool pool_warm_parses` → FAIL.

- [ ] **Step 3: Implement the decision + replenish + the command**

```rust
/// Outcome of the warm-pool claim attempt on a launch.
#[derive(Debug, PartialEq, Eq)]
pub enum LaunchDecision {
    /// A standby was claimed and is booting under this VmId.
    Claimed(mvm_core::protocol::vm_backend::VmId),
    /// No compatible warm standby (or the claim failed) — caller must cold-boot.
    ColdBoot,
}

/// Try to claim an idle standby for `kernel_sha256`; fail open to cold boot. On a
/// claim error the standby is removed (it's spent/broken), never left idle.
pub fn claim_or_cold(
    pool: &mvm_backend::standby_pool::SupervisorStandbyPool,
    backend: &dyn mvm_core::protocol::vm_backend::VmBackend,
    kernel_sha256: &str,
    claim: &mvm_core::protocol::vm_backend::StandbyClaim,
) -> anyhow::Result<LaunchDecision> {
    if !backend.supports_standby_pool() {
        return Ok(LaunchDecision::ColdBoot);
    }
    let Some(handle) = pool.select_idle_for_kernel(kernel_sha256)? else {
        return Ok(LaunchDecision::ColdBoot);
    };
    // Reserve it so a concurrent launch won't double-claim.
    pool.mark_claimed(&handle.id)?;
    match backend.claim_standby(&handle, claim) {
        Ok(vm_id) => {
            // The standby has become the VM; drop its pool entry (the control UDS is
            // consumed one-shot).
            let _ = pool.remove(&handle.id);
            Ok(LaunchDecision::Claimed(vm_id))
        }
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "standby claim failed; cold-booting");
            let _ = pool.remove(&handle.id); // spent/broken — never leave it idle
            Ok(LaunchDecision::ColdBoot)
        }
    }
}

/// Warm the pool toward `target` idle standbys for `kernel`. Best-effort: spawn failures
/// are logged, not fatal (warm pool is an optimization). Returns how many were spawned.
pub fn warm_to_target(
    pool: &mvm_backend::standby_pool::SupervisorStandbyPool,
    backend: &dyn mvm_core::protocol::vm_backend::VmBackend,
    kernel: &std::path::Path,
    signer_id: &str,
    signing_key_path: &std::path::Path,
    target: u32,
) -> anyhow::Result<u32> {
    if target == 0 || !backend.supports_standby_pool() {
        return Ok(0);
    }
    let kernel_sha = kernel_sha256_hex(kernel)?;
    let have = pool.idle_count_for_kernel(&kernel_sha)? as u32;
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    std::fs::create_dir_all(&pool_root)?;
    let mut spawned = 0;
    for _ in have..target {
        let spec = build_standby_spec(&pool_root, kernel, signer_id, signing_key_path)?;
        match backend.spawn_standby(&spec) {
            Ok(handle) => { pool.record(&handle)?; spawned += 1; }
            Err(e) => tracing::warn!(error = %e, "spawn standby failed; pool stays under target"),
        }
    }
    Ok(spawned)
}
```

Then: (a) add `warm_pool_size: u32` (Clap `#[arg(long, default_value_t = 0)]`) to the
`up`/`run` arg struct, thread it into `VmStartConfig.warm_pool_size`; (b) in the launch
path, before the cold `backend.start(&cfg)`, call `claim_or_cold(...)` and use the claimed
`VmId` when `Claimed`, else `start`; **after** a successful launch call
`warm_to_target(..., cfg.warm_pool_size)`; (c) add a `Pool { Warm { count: Option<u32> },
Status }` subcommand whose `Warm` calls `warm_to_target` (default count = a small constant,
e.g. 1, when omitted — document it).

- [ ] **Step 4: Run to verify it passes** — the unit + CLI tests above → PASS; `cargo build -p mvm-cli`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/pool.rs crates/mvm-cli/src/commands/  # + the up/run + cli arg files touched
git commit -m "feat(cli): claim-on-launch + cold fallback + replenish + --warm-pool-size/pool warm (Plan 118 WS-1 1b)"
```

## Task 8: `libkrun-live` end-to-end (completes the 1a `#[ignore]`)

Spawn a real standby, claim it with a freshly-signed admitted plan, assert the guest boots
and the agent answers — the happy path 1a left `#[ignore]`'d, now driven through the pool.

**Files:**
- Create: `crates/mvm-backend/tests/standby_pool_live.rs` (gated `#![cfg(feature = "libkrun-live")]`)
- Modify: `crates/mvm-backend/Cargo.toml` (`libkrun-live` feature + dev-deps if needed)

- [ ] **Step 1: Write the test** (model the boot/agent-ping on the 1a `prelaunch_live.rs`
  refusal test + `examples/agent_ping`; grep `rg -l 'agent_ping|libkrun-live|ensure_default_microvm_image' crates examples`):

  - Build a `StandbySpec` with the default microvm kernel (`ensure_default_microvm_image()`
    path) + the agent port in vsock wiring; `spawn_standby`.
  - Sign an admitted plan with the on-disk host key (`host_signer::load_or_init_at` +
    `mvm_core::plan::sign_plan`), build a `StandbyClaim` (real rootfs + plan_json),
    `claim_standby`.
  - Assert the agent answers `vsock::ping` (Pong) within a timeout.
  - Negative: a wrong-nonce attach (claim built against a *different* standby's nonce) is
    refused and no boot occurs (reuses 1a's exit-6 behavior surfaced as a claim error).

- [ ] **Step 2: Run on the dev host**

```bash
MVM_CACHE_DIR=$(mktemp -d) MVM_DATA_DIR=$(mktemp -d) PATH="$RUSTUP:$PATH" \
  cargo test -p mvm-backend --features libkrun-live --test standby_pool_live -- --nocapture
```
Expected: claim boots + agent reachable; wrong-nonce refused. If the dev host can't boot
the default image (stale-image / Vz-default issues per the memory notes), mark the happy
path `#[ignore]` with a pointer and rely on Tasks 1–7 unit coverage + the 1a refusal
integration — **do not delete it**.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-backend/tests/standby_pool_live.rs crates/mvm-backend/Cargo.toml
git commit -m "test(backend): libkrun-live standby spawn->claim->boot + wrong-nonce refusal (Plan 118 WS-1 1b)"
```

### 1b-i finalization

- [ ] Gates: `cargo fmt --all -- --check`; `cargo clippy --workspace -- -D warnings`;
  `cargo nextest run --workspace -E 'not package(mvm-backend)'`; `cargo test -p mvm-backend
  standby_pool::tests libkrun::tests::standby`; `cargo test --workspace --doc`; build the
  feature-gated bin.
- [ ] Push `feat/plan-118-ws1-layer1b`; open the **1b-i PR** with base
  `feat/plan-118-ws1-layer1a` (stacked). No `Co-Authored-By: Claude` trailer.

---

# PR 1b-ii — lifecycle / ops

> Continue on the same branch after 1b-i merges (or restack onto 1a if 1a merged first).

## Task 9: Reaper TTL + `cache prune` integration

**Files:**
- Modify: `crates/mvm-backend/src/standby_pool.rs` (a `reap_stale(ttl)` method)
- Modify: `crates/mvm-cli/src/commands/cache.rs` (sweep `~/.mvm/pool/` in `prune`)
- Test: `standby_pool.rs` + `cache.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn reap_removes_dead_and_expired_keeps_live_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        // live + recent → kept
        pool.record(&handle("keep", "aa", StandbyState::Idle)).unwrap();
        // dead pid → reaped regardless of age
        let mut dead = handle("dead", "aa", StandbyState::Idle); dead.pid = 999_999;
        pool.record(&dead).unwrap();
        // live but expired (spawned long ago) → reaped
        let mut old = handle("old", "aa", StandbyState::Idle); old.spawned_unix_secs = 1;
        pool.record(&old).unwrap();

        let reaped = pool.reap_stale(std::time::Duration::from_secs(3600), now_unix_secs()).unwrap();
        assert!(reaped.contains(&"dead".to_string()));
        assert!(reaped.contains(&"old".to_string()));
        assert!(pool.load("keep").is_ok());
        // reaping a dead standby also kills its pid if alive (no-op for already-dead).
    }
```

- [ ] **Step 2: Run → FAIL** (`reap_stale` not found).

- [ ] **Step 3: Implement `reap_stale`** — walk `list()`; for each handle, reap when
  `!pid_alive(pid)` OR `now - spawned_unix_secs > ttl`; on reap, best-effort
  `libc::kill(pid, SIGTERM)` if alive, then `remove(id)`; return the reaped ids. Then in
  `cache prune` (extend the existing `--reap-orphans` sweep — `rg -n 'reap_orphans' crates/mvm-cli/src/commands/cache.rs`), call
  `SupervisorStandbyPool::open()?.reap_stale(POOL_TTL, now)` and report counts. Pick
  `POOL_TTL` (e.g. 30 min) as a named const with a comment.

- [ ] **Step 4: Run → PASS.** **Step 5: Commit** `feat(backend): standby reaper TTL + cache-prune sweep of ~/.mvm/pool (Plan 118 WS-1 1b)`.

## Task 10: `mvmctl pool status` + `doctor` standby-pool column

**Files:**
- Modify: `crates/mvm-cli/src/commands/pool.rs` (`Status` arm: list standbys, idle/claimed counts, `--json`)
- Modify: `crates/mvm-cli/src/doctor.rs` (a `standby pool` line: backend supports? + live idle count)
- Test: `pool.rs` + `doctor.rs` (mirror `warm_start_substrate_*` doctor tests at :2734)

- [ ] **Step 1–4:** TDD a `pool status` renderer over `SupervisorStandbyPool::list()`
  (text + `--json`, matching the repo's shared `--json` pattern) and a doctor row that
  reports `supports_standby_pool()` + `idle_count_for_kernel(default)`; assert the line
  format like the existing warm-start matrix test. **Step 5: Commit**
  `feat(cli): mvmctl pool status + doctor standby-pool column (Plan 118 WS-1 1b)`.

## Task 11: Bench — fix the state-dir mismatch

The `bench microvm-launch` probe polls the pid at `~/.local/state/mvm/...` while the
supervisor writes `~/.mvm/...` — so the `start_to_pid_ms` span never resolves on the dev
host.

**Files:**
- Modify: the bench probe (`rg -n 'local/state|start_to_pid|LibkrunProbe|pid' crates/mvm-build/src crates/mvm-cli/src -g '*bench*'`)
- Test: the probe's path-resolution unit test

- [ ] **Step 1:** Write a unit test asserting the probe resolves the pid path through
  `mvm_core::config::vm_state_dir(name)` (i.e. under `MVM_DATA_DIR`/`~/.mvm`), not
  `~/.local/state`. **Step 2:** Run → FAIL. **Step 3:** Replace the hardcoded
  `~/.local/state/...` join with `mvm_core::config::vm_state_dir(name).join("libkrun.pid")`
  (reuse the helper — never build the path inline). **Step 4:** Run → PASS. **Step 5:**
  Commit `fix(bench): resolve microvm-launch pid via mvm-core config (~/.mvm), not ~/.local/state (Plan 118 WS-1 1b)`.

## Task 12: Bench — cold-vs-warm delta span

**Files:**
- Modify: the bench probe (add a warm path that pre-warms a standby then claims, measuring `start_to_pid_ms` for both)
- Test: `libkrun-live`-gated assertion that warm `start_to_pid_ms < cold`

- [ ] **Step 1–4:** Extend the probe to optionally run a warm variant (`warm_to_target(…,1)`
  then claim) and emit both spans into the existing `BootTimingReport`/host-span JSON; a
  `libkrun-live` test asserts the warm `start_to_pid_ms` span is finite and strictly less
  than cold (the spawn/codesign/dylib collapse). Keep the **committed regression baseline
  JSON deferred** (it rides PR-10a's deferral — note it in the PR). **Step 5:** Commit
  `feat(bench): cold-vs-warm start_to_pid delta in microvm-launch (Plan 118 WS-1 1b)`.

## Task 13: Replenish-on-use already in Task 7 — verify + document

Replenish (`warm_to_target` after launch) landed in 1b-i Task 7. In 1b-ii, add an
integration assertion that a claim followed by replenish restores the idle count to target,
and document the no-daemon model in the PR + plan 118 §"Replenish-on-use".

- [ ] **Step 1–4:** `libkrun-live` (or a mock-backend unit) test: target=1, spawn 1, claim
  it, run replenish, assert `idle_count_for_kernel == 1` again. **Step 5:** Commit
  `test(cli): replenish-on-use restores pool to target after a claim (Plan 118 WS-1 1b)`.

## Task 14: Docs + deferred-follow-up notes + fresh-image baseline attempt

**Files:**
- Modify: `specs/SPRINT.md` (multi-kernel deferred note), `specs/plans/118-...md` (tick PR-10b boxes), `specs/REFACTOR-STATUS.md`, `specs/notes/plan-118-ws1-layer1a-prelaunched-supervisor-design.md` (1b status)

- [ ] **Step 1:** In `specs/SPRINT.md`, under the most relevant in-flight sprint, add a
  `### deferred follow-ups` entry:
  > - [ ] **Multi-kernel standby pool keying (Plan 118 WS-1 1b → later).** v1 is
  >   default-kernel-only (`StandbyHandle::matches_kernel` exact sha256; non-default plans
  >   cold-boot). Generalize the pool to hold standbys keyed by kernel identity with
  >   per-kernel targets + eviction once a second kernel is common.
- [ ] **Step 2:** Tick the PR-10b boxes in `specs/plans/118-...md` that 1b lands; update
  `specs/REFACTOR-STATUS.md` Plan 159 WS-1 line to "1b landed"; bump "Last updated".
- [ ] **Step 3 (time-boxed stretch — UX option B):** Attempt a fresh `default-microvm`
  image build on this Vz Mac (`mvmctl` build path) to unblock the committed bench baseline;
  if it boots cleanly, run `bench microvm-launch` cold+warm and commit the baseline JSON. If
  it hits the known stale-image / Vz dev-VM-boot issues within the time box, leave the
  baseline deferred (Task 12) and note the blocker in the PR. **Do not let this block the PR.**
- [ ] **Step 4: Commit** `docs(plan-118): record WS-1 1b standby pool; defer multi-kernel keying`.

### 1b-ii finalization

- [ ] All gates green; push; open the **1b-ii PR** stacked on 1b-i (or on 1a if 1b-i merged).

---

## Self-Review

**Spec coverage** (against the approved design): trait seam ✓ (T2), `Standby*` types ✓
(T1), pool dir helpers ✓ (T3), registry select/record/remove ✓ (T4), libkrun
spawn/claim behind the trait ✓ (T5), kernel-sha256 base-compat ✓ (T1 `matches_kernel` +
T4 select + T6 hash), `warm_pool_size`/`--warm-pool-size`/`pool warm` ✓ (T2/T7),
claim-on-launch + cold fallback ✓ (T7), replenish-on-use ✓ (T7/T13), default-off ✓
(T2 default 0 + T7 `target==0` guard), live boot ✓ (T8), reaper + cache prune ✓ (T9),
`pool status` + doctor ✓ (T10), bench state-dir fix ✓ (T11) + cold-vs-warm delta ✓
(T12) + deferred baseline / fresh-image attempt ✓ (T12/T14), multi-kernel deferred note ✓
(T14), fail-open-to-cold everywhere ✓ (T7 claim error → ColdBoot). No gaps.

**Type consistency:** `StandbySpec{id,kernel_path,kernel_sha256,signing_key_path,signer_id,binding_nonce,control_socket,vm_state_dir}`,
`StandbyHandle{id,control_socket,pid,kernel_sha256,binding_nonce,spawned_unix_secs,state}`,
`StandbyClaim{rootfs_path,tenant_id,audit_dir,gateway_audit_socket,gateway_events_socket,plan_json,bundle_json}`,
`StandbyState{Idle,Claimed}`, `StandbyError{Unsupported,SpawnFailed,ClaimFailed}` — used
consistently T1→T8. `supports_standby_pool`/`spawn_standby`/`claim_standby` signatures match
across T2 (trait), T5 (libkrun impl), T7 (caller). `SupervisorStandbyPool` methods
(`at`/`open`/`record`/`load`/`list`/`select_idle_for_kernel`/`idle_count_for_kernel`/`mark_claimed`/`remove`/`reap_stale`)
consistent T4/T7/T9. `LaunchDecision{Claimed(VmId),ColdBoot}` T7.

**Placeholders:** none — every code step shows real signatures/bodies; the few "grep to
find the exact call site" notes are lift-existing-code instructions (DRY reuse), not
invent-it-later gaps, and each names the rg query + what to change.

## Out of scope / deferred

- **Multi-kernel pool keying** → SPRINT.md deferred follow-up (Task 14).
- **Firecracker / Vz / cloud-hypervisor standby impls** → they implement the same three
  trait methods later; the seam + registry + orchestration are backend-agnostic here.
- **Committed bench regression baseline JSON** → rides PR-10a's deferral unless Task 14's
  fresh-image attempt succeeds.
- **mvmd/fleet wiring** → out of repo; the libkrun pool's v1 beneficiary is local `mvmctl up`.
