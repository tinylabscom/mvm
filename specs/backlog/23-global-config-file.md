# Sprint 23 — Global Config File

**Goal:** Replace scattered hardcoded defaults with a persistent operator config at `~/.mvm/config.toml`. CLI flags override config values; `mvmctl config show` and `mvmctl config set` provide read/write access.

**Branch:** `feat/sprint-23`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 757                      |
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
- [19-observability-security.md](sprints/19-observability-security.md)
- [20-production-hardening-validation.md](sprints/20-production-hardening-validation.md)
- [21-binary-signing-attestation.md](sprints/21-binary-signing-attestation.md)
- [22-observability-deep-dive.md](sprints/22-observability-deep-dive.md)

---

## Rationale

Several flags repeat the same defaults on every invocation (`--lima-cpus 8`, `--lima-mem 16`, `--cpus`, `--memory`). Users who customise these must type them every time. A single config file lets operators set-and-forget their environment preferences while preserving full CLI override capability.

The config also provides a natural home for future settings (`metrics_port`, `log_format`, `hypervisor`), avoiding further flag sprawl. `mvmd` uses a separate config; `MvmConfig` is `mvmctl`-specific and lives in `mvm-core` so any future shared tooling can also load it.

---

## Phase 1: `MvmConfig` struct and load/save in `mvm-core` **Status: COMPLETE**

### 1.1 Define `MvmConfig`

- [x] Create `crates/mvm-core/src/user_config.rs` (separate from existing `config.rs` which holds runtime constants):
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct MvmConfig {
      pub lima_cpus: u32,          // default: 8
      pub lima_mem_gib: u32,       // default: 16
      pub default_cpus: u32,       // default: 2  (for mvmctl run)
      pub default_memory_mib: u32, // default: 512
      pub log_format: Option<String>,  // default: None (human)
      pub metrics_port: Option<u16>,   // default: None (disabled)
  }
  ```
- [x] `impl Default for MvmConfig` with values matching existing CLI `default_value` annotations
- [x] Expose from `mvm_core` root: `pub mod user_config;`
- [x] 2 unit tests: `MvmConfig::default()` has expected values; TOML roundtrip preserves all fields

### 1.2 `load()` and `save()`

- [x] `pub fn load(override_dir: Option<&Path>) -> MvmConfig` — reads `~/.mvm/config.toml`; creates with defaults if absent; warns on parse error and returns defaults
- [x] `pub fn save(cfg: &MvmConfig, override_dir: Option<&Path>) -> Result<()>` — writes `~/.mvm/config.toml`, creates `~/.mvm/` dir if needed
- [x] Both functions accept an optional override dir (`Option<&Path>`) for testability — production code passes `None` to use `~/.mvm/`
- [x] 2 unit tests: `load()` from empty temp dir returns defaults and creates the file; `save()` + `load()` roundtrip

### 1.3 `set_key` helper

- [x] `pub fn set_key(cfg: &mut MvmConfig, key: &str, value: &str) -> Result<()>`
- [x] Matches known field names; parses value to correct type; returns `Err` with message listing valid keys for unknown keys
- [x] 3 unit tests: known key updates; unknown key error; invalid value (non-numeric for u32) error

---

## Phase 2: Wire config into CLI defaults **Status: COMPLETE**

### 2.1 Load config at dispatch time

- [x] In `run()` in `commands.rs`, call `mvm_core::user_config::load(None)` once before dispatch
- [x] Use config values as fallback when CLI flags are absent:
  - `--lima-cpus` / `--lima-mem`: if the flag matches its Clap default exactly, substitute from config
  - `--cpus` / `--memory` in `RunParams`: if `None`, substitute `cfg.default_cpus` / `cfg.default_memory_mib`

### 2.2 `mvmctl config show`

- [x] Add `Commands::Config { action: ConfigAction }` with `ConfigAction::Show`
- [x] `cmd_config_show()` — loads config, prints as TOML to stdout
- [x] 1 unit test: `config show` output contains `lima_cpus`

### 2.3 `mvmctl config set <key> <value>`

- [x] Add `ConfigAction::Set { key: String, value: String }`
- [x] `cmd_config_set(key, value)` — loads, calls `set_key`, saves, prints `"Set <key> = <value>"`
- [x] 2 unit tests: `set lima_cpus 4` persists; unknown key exits non-zero with helpful error

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 24: Man Pages & Shell Completions

**Goal:** Make `mvmctl` feel like a first-class Unix citizen.

- [ ] Add `clap_mangen` to `mvm-cli/Cargo.toml`
- [ ] Add `xtask` crate (or build.rs) that generates `man/mvmctl.1` and one page per subcommand
- [ ] Add `mvmctl completions <shell>` subcommand (bash, zsh, fish) via `clap_complete`
- [ ] Ship man pages and completions in the release tarball
- [ ] Update install script to copy man pages to `/usr/local/share/man/man1/`
- [ ] CI check: man page generation does not fail on clean build

### Sprint 25: E2E Test Framework & `mvmctl uninstall`

**Goal:** Catch regressions before they reach users.

- [ ] Create `tests/e2e/` directory with a test harness that:
  - Spawns a `mvmctl` subprocess for each test case
  - Captures stdout/stderr, checks exit codes
  - Runs against the actual binary (not library functions)
- [ ] Implement `mvmctl uninstall` — removes Lima VM, Firecracker binary, `/var/lib/mvm/` (with `--all` flag for aggressive cleanup)
- [ ] E2E tests for: `bootstrap --help`, `status` on clean system, `cleanup-orphans` on empty dir
- [ ] Add `e2e` CI job that runs after `build-linux` in `ci.yml`

### Sprint 26: Audit Logging

**Goal:** Provide an immutable audit trail for security-sensitive operations.

- [ ] Define `AuditEvent` struct in `mvm-core/src/audit.rs` (already partially exists — extend it)
- [ ] Emit audit events for: `vm_start`, `vm_stop`, `key_lookup`, `volume_create`, `volume_open`, `update_install`
- [ ] Append-only audit log at `/var/log/mvm/audit.jsonl` (rotate at 10 MiB)
- [ ] Add `mvmctl audit tail` — stream recent audit events
- [ ] 4 unit tests: event serialization, append-only write, rotation trigger, `audit tail` output format
