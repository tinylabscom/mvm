# Sprint 31 — VM Resource Defaults from Config

**Goal:** Honour `default_cpus` and `default_memory_mib` from `~/.mvm/config.toml`
when `--cpus` / `--memory` are not passed to `mvmctl run`.

**Branch:** `feat/sprint-31`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 840+                     |
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
- [23-global-config-file.md](sprints/23-global-config-file.md)
- [24-man-pages.md](sprints/24-man-pages.md)
- [25-e2e-uninstall.md](sprints/25-e2e-uninstall.md)
- [26-audit-logging.md](sprints/26-audit-logging.md)
- [27-config-validation.md](sprints/27-config-validation.md)
- [28-config-hot-reload.md](sprints/28-config-hot-reload.md)
- [29-shell-completions.md](sprints/29-shell-completions.md)
- [30-config-edit.md](sprints/30-config-edit.md)

---

## Rationale

`MvmConfig` has `default_cpus` (default: 2) and `default_memory_mib` (default: 512)
but `cmd_run` ignores them — it uses the Clap defaults directly.  This means
`mvmctl config set default_cpus 4` has no effect on `mvmctl run`.  Closing this gap
makes the config file the single source of truth for per-user defaults.

Priority: CLI flag > config file value > Clap argument default.

---

## Phase 1: Wire config defaults into `cmd_run` **Status: COMPLETE**

### 1.1 Apply defaults in the `Commands::Run` dispatch block

In the `Commands::Run { cpus, memory, .. }` match arm (around line 820 of
`commands.rs`), before constructing `RunParams`, resolve the effective values:

```rust
// CLI flag takes precedence; fall back to config defaults.
let effective_cpus = cpus.or(Some(cfg.default_cpus));
let effective_memory_mib = memory_mb.or(Some(cfg.default_memory_mib));
```

Pass `effective_cpus` and `effective_memory_mib` to `RunParams`.

### 1.2 No changes to `RunParams` or `cmd_run` internals

`RunParams.cpus` is already `Option<u32>` and `RunParams.memory` is `Option<u32>`.
`cmd_run` already uses these; if `Some`, they override the Lima defaults. So
providing `Some(cfg.default_cpus)` when the user omits `--cpus` is sufficient.

---

## Phase 2: Tests **Status: COMPLETE**

### 2.1 Unit tests in `commands.rs` `#[cfg(test)]`

- [x] `test_run_uses_config_default_cpus` — `cpus: None` + `cfg.default_cpus = 4` → `Some(4)`
- [x] `test_run_cli_flag_overrides_config_cpus` — `cpus: Some(8)` wins over `cfg.default_cpus = 4`
- [x] `test_run_uses_config_default_memory` — same pattern for memory
- [x] `test_run_cli_flag_overrides_config_memory` — CLI flag wins over config default

### 2.2 Integration tests in `tests/cli.rs`

- [x] `test_run_help_shows_flags` — already passing (regression guard)

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 32: `mvmctl vm list` — tabular VM roster

**Goal:** `mvmctl vm list` prints a table of all running and stopped microVMs with
their name, status, CPU count, memory, and uptime.

- [ ] Add `VmCmd::List` subcommand
- [ ] Collect VM state from Lima + local state dir
- [ ] Format as a padded ASCII table (no external dep — use `format!` with padding)
- [ ] `--json` flag for machine-readable output
- [ ] Tests: list exits 0 on clean system; `--json` stdout is valid JSON
