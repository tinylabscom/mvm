# Sprint 19 — Observability & Security Hygiene

**Goal:** Expose the metrics infrastructure already built into the codebase via a `mvmctl metrics` command, eliminate shell-injection-prone `xxd` shell-outs in crypto code with pure-Rust hex encoding, and add a lightweight state migration framework so persisted state files can evolve safely.

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.5.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 700                      |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| MSRV             | 1.85                     |
| Binary           | `mvmctl`                 |

## Completed Sprints

- [01-foundation.md](sprints/01-foundation.md)
- [02-production-readiness.md](sprints/02-production-readiness.md)
- [03-real-world-validation.md](sprints/03-real-world-validation.md)
- Sprint 4: Security Baseline 90%
- Sprint 5: Final Security Hardening
- [06-minimum-runtime.md](sprints/06-minimum-runtime.md)
- [07-role-profiles.md](sprints/07-role-profiles.md)
- [08-integration-lifecycle.md](sprints/08-integration-lifecycle.md)
- [09-openclaw-support.md](sprints/09-openclaw-support.md)
- [10-coordinator.md](sprints/10-coordinator.md)
- Sprint 11: Dev Environment
- [12-install-release-security.md](sprints/12-install-release-security.md)
- [13-boot-time-optimization.md](sprints/13-boot-time-optimization.md)
- [14-guest-library-and-examples.md](sprints/14-guest-library-and-examples.md)
- [15-real-world-apps.md](sprints/15-real-world-apps.md)
- [16-production-hardening.md](sprints/16-production-hardening.md)
- [17-resource-safety-release.md](sprints/17-resource-safety-release.md)
- [18-developer-experience.md](sprints/18-developer-experience.md)

---

## Rationale

**Why these three themes?**

1. **Metrics export**: `mvm-core` already has a `Metrics` struct with atomic counters and a `prometheus_exposition()` method, but nothing surfaces these values to the operator. A `mvmctl metrics` command costs ~100 lines and immediately makes the runtime observable without any new dependencies. The `MetricsSnapshot` can also be emitted as JSON for scripted consumers.

2. **Native hex encoding**: `keystore.rs` and `encryption.rs` shell out to `xxd` to convert between hex strings and raw bytes. This is the only remaining shell-injection-adjacent pattern in security-sensitive code (the key material passes through `format!()` into a shell string). Replacing the hex encode/decode with the `hex` crate (already used elsewhere in the repo) eliminates the risk entirely with zero runtime cost.

3. **State migration framework**: `schema_version` fields sit in `MvmState`, `TemplateSpec`, and `AgentState` with no migration logic. The next time any persisted struct gains or renames a field, existing installs will silently drop data or fail deserialization. A migration runner that applies versioned migration functions at load time is a 150-line investment that prevents future silent breakage.

---

## Phase 1: `mvmctl metrics` Command **Status: COMPLETE**

The `mvm_core::observability::metrics::Metrics` struct (global singleton) exposes `prometheus_exposition()` and `snapshot()` today. Nothing surfaces these to the CLI.

### 1.1 New `metrics` subcommand

- [x] Add `Commands::Metrics { json: bool }` to the `Commands` enum in `commands.rs`
- [x] `cmd_metrics(json)`:
  - JSON mode: serialize `global().snapshot()` (which is already `Serialize`) and print
  - Text mode: print `global().prometheus_exposition()` directly (already formatted)
- [x] Dispatch arm in `run()`

### 1.2 Tests

- [x] Integration test: `mvmctl metrics --help` shows Prometheus/--json in `tests/cli.rs`
- [x] Integration test: `mvmctl metrics` outputs valid Prometheus text with `mvm_requests_total`
- [x] Integration test: `mvmctl metrics --json` outputs valid JSON with expected fields
- [x] Unit tests: snapshot serialization, prometheus exposition metric names

---

## Phase 2: Shell Injection Guards in Crypto Code **Status: COMPLETE**

After reading the code: `hex_decode` validation was already in place in `keystore.rs`, and `hex_encode` in `encryption.rs` produces only `[0-9a-f]` so the hex key itself is safe. The actual shell-injection surface was **`tenant_id`** and **mapper `name`** being interpolated into shell commands without validation.

### 2.1 `keystore.rs` — `validate_shell_id` guard

- [x] Added `pub fn validate_shell_id(s: &str) -> Result<()>` — accepts only `[A-Za-z0-9_-]`, rejects empty and any shell metacharacter
- [x] Called at the top of `FileKeyProvider::get_data_key()` before `tenant_id` is embedded in the shell path command
- [x] 6 unit tests: valid IDs, empty, semicolon, spaces, dot, slash/path-traversal

### 2.2 `encryption.rs` — guards on `path` and `name`

- [x] `create_encrypted_volume`: `ensure!(!path.is_empty())`
- [x] `open_encrypted_volume`: `ensure!(!path.is_empty())` + `validate_shell_id(name)` on the mapper name
- [x] 3 unit tests: empty path rejected in both functions, bad mapper name rejected
- [x] `hex_encode` roundtrip test: verify all 256 byte values encode to valid hex-only output

---

## Phase 3: State Migration Framework **Status: COMPLETE**

### 3.1 `mvm-core/src/migration.rs`

- [x] `pub type MigrateFn = fn(serde_json::Value) -> Result<serde_json::Value>`
- [x] `pub fn migrate(value, from, to, migrations)` — iterate `from..to`, apply each fn
- [x] Returns `Ok(value)` unchanged when `from == to`
- [x] Returns `Err` when `from > to` (downgrade not supported)
- [x] Returns `Err` when migrations list is shorter than needed
- [x] `pub fn schema_version_of(value)` — reads `schema_version` field, defaults to 0
- [x] 9 unit tests covering all branches + `RunInfo` unversioned roundtrip

### 3.2 Wired into `RunInfo` load

In `crates/mvm-runtime/src/vm/microvm.rs`:

- [x] `RUN_INFO_SCHEMA_VERSION = 1` constant
- [x] `RUN_INFO_MIGRATIONS: &[MigrateFn] = &[]` — empty for now, framework is live
- [x] `read_vm_run_info_from()` deserializes to `Value`, calls `migrate()`, then to `RunInfo`
- [x] `read_run_info()` same pattern — migration errors logged as warnings, returns `None`

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```
