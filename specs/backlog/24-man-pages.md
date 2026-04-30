# Sprint 24 — Man Pages & Shell Completions

**Goal:** Make `mvmctl` feel like a first-class Unix citizen by shipping man pages (via `clap_mangen`) generated at release time. Shell completions (`mvmctl completions <shell>`) already exist; this sprint adds man page generation and delivery.

**Branch:** `feat/sprint-24`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 760+                     |
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

---

## Rationale

`mvmctl` is now a full-featured CLI tool. Users expect `man mvmctl` to work. Man pages
are also required for distribution via package managers (Homebrew, apt). The `clap_mangen`
crate generates groff-format man pages directly from Clap command metadata, so there is
no manual authoring required.

Shell completions are already delivered via `mvmctl completions <shell>` and `mvmctl shell-init`.
This sprint adds the final missing piece: man page generation and distribution.

---

## Phase 1: `xtask` crate with man page generation **Status: COMPLETE**

### 1.1 Add `xtask` to the workspace

- [x] Create `xtask/` directory with `xtask/Cargo.toml`
- [x] Add `"xtask"` to `[workspace].members` in root `Cargo.toml`
- [x] Add `clap_mangen = "0.2"` to `[workspace.dependencies]`
- [x] Add `[alias] xtask = "run --package xtask --"` to `.cargo/config.toml`

### 1.2 Implement `xtask gen-man`

- [x] `xtask/src/main.rs`: parses `cargo xtask gen-man [--output-dir DIR]`
- [x] Generates `mvmctl.1` plus `mvmctl-<sub>.1` for each top-level subcommand
- [x] 2 unit tests: `gen_man_creates_main_page`, `gen_man_creates_subcommand_pages`

### 1.3 Share `Cli` definition for xtask

- [x] Expose `pub fn cli_command() -> clap::Command` in `mvm-cli/src/commands.rs`
- [x] xtask depends on `mvm-cli` workspace dep and calls `mvm_cli::commands::cli_command()`

### 1.4 Add `man/` directory skeleton and `.gitignore` entry

- [x] Add `man/.gitkeep` so the directory exists in the repo
- [x] Add `man/*.1` to `.gitignore`

---

## Phase 2: Release integration **Status: COMPLETE**

### 2.1 Generate man pages in release CI

- [x] Add `cargo xtask gen-man --output-dir man/` step in `.github/workflows/release.yml`
- [x] Include `man/` directory in the release tarball alongside the binary

### 2.2 Update install script

- [x] `install.sh` installs man pages to `${MAN_DIR:-/usr/local/share/man/man1}/` when present in archive
- [x] Uses `sudo` when needed; runs `mandb` to update man index if available

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
cargo xtask gen-man
man man/mvmctl.1  # should display the man page
```

---

## Future Sprints (Planned, Not Yet Implemented)

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
