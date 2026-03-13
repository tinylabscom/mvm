# Sprint 35 — `mvmctl run --watch`

**Goal:** Add `--watch` to `mvmctl run --flake <path>` so the VM is
automatically rebuilt and rebooted whenever a `.nix` or `flake.lock` file
changes — the full edit→rebuild→reboot loop in a single command.

**Branch:** `feat/sprint-35`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 873+                     |
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
- [32-vm-list.md](sprints/32-vm-list.md)
- [33-template-init-preset.md](sprints/33-template-init-preset.md)
- [34-flake-check.md](sprints/34-flake-check.md)

---

## Rationale

The inner dev loop for microVM development is:
1. Edit `flake.nix`
2. `mvmctl build --flake .` — rebuilds the image
3. `mvmctl stop my-vm && mvmctl run --flake . --name my-vm` — reboots

`mvmctl run --flake . --watch` collapses all three steps: it starts the VM,
watches the flake directory, and on any `.nix` / `flake.lock` change it stops
the running VM, rebuilds, and starts a fresh one.  Ctrl-C exits cleanly.

---

## Phase 1: Add `--watch` to `Commands::Run` **Status: COMPLETE**

- [x] Add `watch: bool` flag to `Commands::Run`
- [x] Pass `watch` through `RunParams`
- [x] In `cmd_run`, after the VM starts, if `watch` is set:
  - Guard: `--watch` requires a local `--flake`; if absent or remote, print
    warning and return without entering the loop
  - Enter loop: `wait_for_changes` → stop VM → rebuild → start VM → repeat

---

## Phase 2: Tests **Status: COMPLETE**

- [x] `test_run_watch_flag_accepted_in_help` — help text contains `watch`
- [x] `test_run_watch_requires_flake` — `--watch` without `--flake` exits 0
  (the guard degrades gracefully, same as `build --watch` with remote flake)

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```
