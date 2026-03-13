# Sprint 32 — `mvmctl vm list` Subcommand

**Goal:** Add `mvmctl vm list` as an ergonomic alias for the existing
`mvmctl vm status` (no-name form) so users have a discoverable command
that matches the conventional `<tool> <noun> list` pattern.

**Branch:** `feat/sprint-32`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 855+                     |
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
- [31-vm-resource-defaults.md](sprints/31-vm-resource-defaults.md)

---

## Rationale

`mvmctl vm status` (with no name) already prints a tabular roster of all
running microVMs.  Adding `mvmctl vm list` as a distinct subcommand that
delegates to the same implementation gives users the expected `list` verb
without duplicating any logic.

---

## Phase 1: Add `VmCmd::List` **Status: COMPLETE**

- [x] Add `List { json: bool }` variant to `VmCmd` enum
- [x] Add match arm `VmCmd::List { json } => cmd_vm_status_all(json)` in `cmd_vm`
- [x] Help text: "List all running microVMs (alias for 'vm status')"

---

## Phase 2: Tests **Status: COMPLETE**

### 2.1 Tests in `tests/cli.rs`

- [x] `test_vm_list_help_exits_ok` — `mvmctl vm list --help` exits 0
- [x] `test_vm_list_exits_ok_on_clean_system` — exits 0 on a system with no Lima VM
- [x] `test_vm_list_json_exits_ok` — `mvmctl vm list --json` exits 0 and stdout
  is valid JSON (`[]` when no VMs are running)
- [x] `test_vm_help_lists_list_subcommand` — `mvmctl vm --help` contains `list`

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 33: `mvmctl run --detach` — background VM launch

**Goal:** `mvmctl run --detach` starts the VM in the background and immediately
returns, printing the VM name to stdout.  Without `--detach`, the current
blocking behaviour is preserved.

- [ ] Add `detach: bool` flag to `Run`
- [ ] When set, fork a background process (or use `std::process::Command::spawn`)
  and return immediately after logging the VM name
- [ ] Tests: `--detach --help` exits 0; with detach the command exits before
  the VM is fully booted
