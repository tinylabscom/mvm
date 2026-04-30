# Sprint 25 — E2E Test Framework & `mvmctl uninstall`

**Goal:** Catch regressions before they reach users with a real subprocess-based E2E test harness, and give users a clean uninstall path.

**Branch:** `feat/sprint-25`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
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
- [24-man-pages.md](sprints/24-man-pages.md)

---

## Rationale

`mvmctl` has 760+ unit/integration tests but no test suite that runs the actual binary
end-to-end. Regressions in argument parsing, exit codes, or output format slip through.
A subprocess-based harness using `assert_cmd` (already in workspace deps) fills this gap
with no new dependencies.

`mvmctl uninstall` is the natural counterpart to `mvmctl bootstrap`. Users want a clean
way to remove everything: Lima VM, Firecracker binary, `/var/lib/mvm/` state, and
optionally `~/.mvm/` config. Today they must do this manually.

---

## Phase 1: `mvmctl uninstall` command **Status: COMPLETE**

### 1.1 Add `Uninstall` variant to `Commands` enum

- [x] `Commands::Uninstall` with flags:
  - `--yes` / `-y` — skip confirmation
  - `--all` — also remove `~/.mvm/` (config, keys) and `/usr/local/bin/mvmctl`
  - `--dry-run` — print what would be removed without doing it

### 1.2 Implement `cmd_uninstall`

- [x] Stop any running microVMs first (best-effort, log-and-continue on error)
- [x] Destroy Lima VM if it exists (`lima::destroy()`)
- [x] Remove `/var/lib/mvm/` state directory (with `sudo` if needed)
- [x] With `--all`: remove `~/.mvm/` config dir and `/usr/local/bin/mvmctl` binary
- [x] `--dry-run` prints each action without executing it
- [x] Confirmation prompt unless `--yes` (lists what will be removed)

### 1.3 Tests

- [x] `test_uninstall_help` — flags present in help output
- [x] `test_uninstall_listed_in_help` — top-level help includes "uninstall"
- [x] `test_uninstall_dry_run_no_side_effects` — `--dry-run --yes` exits 0, prints plan

---

## Phase 2: E2E test harness **Status: COMPLETE**

### 2.1 Create `tests/e2e/` directory

- [x] `tests/e2e/harness.rs` — shared helpers: `mvmctl()` → `Command`, `assert_parse_ok()`
- [x] `tests/e2e/mod.rs` — declare submodules

### 2.2 E2E test cases

- [x] `tests/e2e/help.rs` — `bootstrap --help`, `status --help`, `cleanup-orphans --help`
- [x] `tests/e2e/status.rs` — `status` on clean system: exits 0 or 1, no panic, meaningful output
- [x] `tests/e2e/cleanup_orphans.rs` — `cleanup-orphans --dry-run` on empty dir: exits 0
- [x] `tests/e2e/uninstall.rs` — `uninstall --dry-run --yes` exits 0, output contains expected paths

### 2.3 Wire into test binary

- [x] Add `tests/e2e.rs` as the integration test entry point that includes `mod e2e`

---

## Phase 3: CI integration **Status: COMPLETE**

### 3.1 Add `e2e` job to `.github/workflows/ci.yml`

- [x] Runs after `build-linux` job (depends on it)
- [x] Uses `ubuntu-latest`
- [x] Step: `cargo test --test e2e`

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

### Sprint 26: Audit Logging

**Goal:** Provide an immutable audit trail for security-sensitive operations.

- [ ] Define `AuditEvent` struct in `mvm-core/src/audit.rs` (already partially exists — extend it)
- [ ] Emit audit events for: `vm_start`, `vm_stop`, `key_lookup`, `volume_create`, `volume_open`, `update_install`
- [ ] Append-only audit log at `/var/log/mvm/audit.jsonl` (rotate at 10 MiB)
- [ ] Add `mvmctl audit tail` — stream recent audit events
- [ ] 4 unit tests: event serialization, append-only write, rotation trigger, `audit tail` output format
