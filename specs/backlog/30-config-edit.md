# Sprint 30 — `mvmctl config` Subcommand

**Goal:** Give operators a first-class CLI surface for reading and editing
`~/.mvm/config.toml` without opening the file in a text editor.

**Branch:** `feat/sprint-30`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 830+                     |
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

---

## Rationale

`~/.mvm/config.toml` is currently opaque to users who do not know its path.
The existing `mvmctl config set KEY VALUE` command (Sprint 23) lets users write
individual keys but there is no way to see the current effective values or open
the whole file for editing.  Two sub-commands close this gap:

- `mvmctl config show` — pretty-prints the current config as TOML to stdout.
- `mvmctl config edit` — opens the config file in `$EDITOR` (fallback: `nano`).

Both commands already have a placeholder for the `Config` variant; they just
need the `show` and `edit` actions wired in.

---

## Phase 1: Implement `show` and `edit` actions **Status: COMPLETE**

### 1.1 `ConfigAction::Edit` added to enum

- [x] `Edit` variant added to `ConfigAction` in `commands.rs`
- [x] Match arm `ConfigAction::Edit => cmd_config_edit()` added

### 1.2 `cmd_config_show` (pre-existing)

- [x] Loads `MvmConfig` and prints as TOML via `toml::to_string_pretty`

### 1.3 `cmd_config_edit` (new)

- [x] Ensures `~/.mvm/config.toml` exists (calls `load(None)` which creates it)
- [x] Launches `$EDITOR` (fallback: `nano`) with the config path as argument
- [x] Returns `Err` if the editor exits non-zero

---

## Phase 2: Tests **Status: COMPLETE**

### 2.1 Tests in `tests/cli.rs`

- [x] `test_config_show_exits_ok` — exits 0, stdout contains `lima_cpus`
- [x] `test_config_edit_with_true_editor` — `EDITOR=true` exits 0
- [x] `test_config_show_help` — exits 0
- [x] `test_config_edit_help` — exits 0

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

### Sprint 31: VM Resource Limits

**Goal:** Honour `default_cpus` and `default_memory_mib` from `~/.mvm/config.toml`
when `--cpus` / `--memory` are not passed to `mvmctl run`.

- [ ] Read defaults from `MvmConfig` in `cmd_run`
- [ ] `--cpus` / `--memory` CLI flags take precedence over config defaults
- [ ] Tests: run with no flags uses config value; run with explicit flag overrides it
