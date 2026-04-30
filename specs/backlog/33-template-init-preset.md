# Sprint 33 — `mvmctl template init --preset`

**Goal:** Add a `--preset` flag to `mvmctl template init` so users can start
from a meaningful scaffold instead of a blank/minimal template.  Four presets
are supported: `minimal` (default), `http`, `postgres`, and `worker`.

**Branch:** `feat/sprint-33`

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
- [32-vm-list.md](sprints/32-vm-list.md)

---

## Rationale

`mvmctl template init` currently writes one minimal `flake.nix` that shows a
Python HTTP server.  New users need to edit the whole file to get started with
a real workload.  Adding named presets lets users pick a starting point that
already has the right packages, services, and health checks wired up.

---

## Phase 1: Scaffold Preset Files **Status: COMPLETE**

- [x] Update `crates/mvm-cli/resources/template_scaffold/flake.nix` → truly
  minimal preset (packages only, no services, comments guide the user)
- [x] Add `crates/mvm-cli/resources/template_scaffold/flake-http.nix` — Python
  HTTP server with curl health check
- [x] Add `crates/mvm-cli/resources/template_scaffold/flake-postgres.nix` —
  PostgreSQL service with `pg_isready` health check
- [x] Add `crates/mvm-cli/resources/template_scaffold/flake-worker.nix` —
  long-running background worker with no ports

---

## Phase 2: CLI & Logic **Status: COMPLETE**

- [x] Add `--preset <minimal|http|postgres|worker>` arg to `TemplateCmd::Init`
  (default: `minimal`)
- [x] Update `template_cmd::init` signature to accept `preset: &str`
- [x] Update `scaffold_template_files` to select flake content by preset;
  return `Err` for unknown preset name
- [x] Pass `preset` through in `cmd_template` dispatch

---

## Phase 3: Tests **Status: COMPLETE**

- [x] `test_template_init_help_shows_preset_flag`
- [x] `test_template_init_preset_minimal_exits_ok`
- [x] `test_template_init_preset_http_exits_ok`
- [x] `test_template_init_preset_unknown_shows_error`

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 34: `mvmctl flake check` — validate a flake before building

### Sprint 35: `mvmctl run --watch` — edit→rebuild→reboot loop
