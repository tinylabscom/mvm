# Sprint 29 — Shell Completion Generation

**Goal:** Ship `mvmctl completions <shell>` that writes Clap-generated completions for
bash, zsh, fish, and PowerShell to stdout so users can install them with a single
redirect.

**Branch:** `feat/sprint-29`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 820+                     |
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

---

## Rationale

Users currently have to tab-complete `mvmctl` commands manually or remember them from
`--help`.  `clap_complete` can generate native shell completions from the existing Clap
definition with minimal code.  A `completions` subcommand is the standard pattern
(used by `rustup`, `gh`, `kubectl`, etc.) and plays well with package managers and
dotfile setups.

---

## Phase 1: Add `completions` subcommand **Status: COMPLETE**

### 1.1 `clap_complete` in workspace

- [x] `clap_complete = "4"` in `[workspace.dependencies]`
- [x] `clap_complete.workspace = true` in `mvm-cli/Cargo.toml`

### 1.2 `Completions` command (already implemented in a prior sprint)

- [x] `Completions { shell: clap_complete::Shell }` variant in `Commands`
- [x] `Commands::Completions { shell }` arm calls `cmd_completions(shell)`
- [x] `fn cmd_completions` calls `clap_complete::generate(...)` and returns `Ok(())`

---

## Phase 2: Tests **Status: COMPLETE**

### 2.1 Tests in `tests/cli.rs`

- [x] `test_completions_bash_exits_ok` — exits 0 and stdout contains `mvmctl`
- [x] `test_completions_zsh_exits_ok` — same for zsh
- [x] `test_completions_fish_exits_ok` — same for fish
- [x] `test_completions_no_shell_shows_error` — exits 2 (missing required arg)
- [x] `test_top_level_help_lists_completions` — `--help` mentions `completions`

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

### Sprint 30: `mvmctl config` REPL / interactive editor

**Goal:** `mvmctl config edit` opens `~/.mvm/config.toml` in `$EDITOR`; `mvmctl config
show` pretty-prints the current effective config (merged CLI overrides + file defaults).

- [ ] `Config { action: ConfigCmd }` subcommand with `Show` and `Edit` variants
- [ ] `mvmctl config show` prints the merged config as TOML to stdout
- [ ] `mvmctl config edit` opens `$EDITOR` (or `nano` fallback) on the config file
- [ ] Tests: show exits 0, edit with `EDITOR=true` exits 0
