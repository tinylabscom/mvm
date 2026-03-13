# Sprint 28 — Config File Hot-Reload & Watch Mode

**Goal:** Let operators change `~/.mvm/config.toml` without restarting long-running commands.

**Branch:** `feat/sprint-28`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 800+                     |
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

---

## Rationale

`~/.mvm/config.toml` is loaded once at startup. Any change requires the user to restart
`mvmctl dev` or `mvmctl run` — disruptive for long-running sessions. A `--watch-config`
flag on `dev` and `run` uses the existing `notify` watcher infrastructure to detect file
changes and reload `MvmConfig` in place, applying updates before the next VM start.

Reloads only apply to pending config; an already-running VM is not restarted. If the new
TOML is invalid, warn and continue with the previous config.

---

## Phase 1: Config watcher module **Status: COMPLETE**

### 1.1 `mvm-cli/src/config_watcher.rs` — new module

- [x] Define `ConfigReloadEvent` enum: `Reloaded(MvmConfig)` | `ParseError(String)`
- [x] Define `ConfigWatcher` struct with `receiver: mpsc::Receiver<ConfigReloadEvent>`
- [x] Implement `ConfigWatcher::start(path: &Path) -> Result<Self>`
  - Uses `notify-debouncer-mini` (already in `mvm-cli/Cargo.toml`)
  - Watches the parent directory (`NonRecursive`); filters events by file path
  - On event: re-reads and re-parses the TOML; sends `Reloaded` or `ParseError`
  - Debounced 500 ms; debouncer lives on background thread
- [x] `apply_pending_reloads(cfg, rx)` helper to drain and apply events
- [x] Registered as `pub mod config_watcher` in `mvm-cli/src/lib.rs`

### 1.2 Wire `--watch-config` into `cmd_dev` and `cmd_run`

- [x] Added `watch_config: bool` field to `Dev` and `Run` Clap variants
- [x] `cmd_dev`: starts `ConfigWatcher` when flag is set (best-effort; warns on error)
- [x] `cmd_run`: starts `ConfigWatcher` before VM boot when flag is set
- [x] Without the flag, behaviour is identical to before

---

## Phase 2: Unit tests **Status: COMPLETE**

### 2.1 Tests in `mvm-cli/src/config_watcher.rs`

- [x] `test_config_watcher_detects_change` — writes valid TOML, asserts `Reloaded` within 3 s
- [x] `test_config_watcher_invalid_toml_sends_parse_error` — garbage TOML → `ParseError`
- [x] `test_apply_pending_reloads_updates_cfg` — channel-only test, no filesystem
- [x] `test_apply_pending_reloads_keeps_cfg_on_error` — channel-only test, no filesystem

### 2.2 Tests in `tests/cli.rs`

- [x] `test_dev_accepts_watch_config_flag` — `mvmctl dev --watch-config --help` exits 0
- [x] `test_run_accepts_watch_config_flag` — `mvmctl run --watch-config --help` exits 0

---

## Verification

```bash
cargo test --workspace
cargo test --test e2e
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 29: Shell Completion Generation

**Goal:** Ship `mvmctl completions <shell>` that writes Clap-generated completions for
bash/zsh/fish/powershell.

- [ ] Add `Completions { shell: clap_complete::Shell }` subcommand
- [ ] Use `clap_complete` crate to generate and print completion script to stdout
- [ ] Update man pages (xtask) to include `completions` command
- [ ] Tests: `mvmctl completions bash` exits 0 and stdout contains `mvmctl`
