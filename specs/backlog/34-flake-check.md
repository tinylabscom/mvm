# Sprint 34 — `mvmctl flake check`

**Goal:** Add `mvmctl flake check [--flake <path>]` to validate a Nix flake
before committing to a full `nix build`, giving users fast feedback on syntax
and evaluation errors.

**Branch:** `feat/sprint-34`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 870+                     |
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

---

## Rationale

`nix build` on an invalid flake can take 30+ seconds before failing.
`mvmctl flake check` runs `nix flake check` inside the Lima VM (where Nix
lives) and streams its output immediately, giving fast syntax/evaluation
feedback without kicking off the full build pipeline.

---

## Phase 1: Add `Commands::Flake` **Status: COMPLETE**

- [x] Add `Commands::Flake { action: FlakeCmd }` top-level subcommand
- [x] Add `enum FlakeCmd { Check { flake: Option<String>, json: bool } }`
- [x] Add `cmd_flake_check(flake: Option<&str>, json: bool) -> Result<()>`
  - Defaults flake path to `"."` when not given
  - Resolves to absolute path via `resolve_flake_ref`
  - Runs `nix flake check <path>` inside Lima via visible shell exec
  - On success prints `Flake is valid.` (or `{"valid":true}` in JSON mode)
  - On failure prints error output (or `{"valid":false,"error":"..."}`)
- [x] `cmd_flake` dispatch function

---

## Phase 2: Tests **Status: COMPLETE**

- [x] `test_flake_check_help_exits_ok` — `mvmctl flake check --help` exits 0
- [x] `test_flake_top_level_help_lists_check` — `mvmctl flake --help` mentions `check`
- [x] `test_flake_help_lists_in_top_level` — `mvmctl --help` mentions `flake`

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 35: `mvmctl run --watch` — edit→rebuild→reboot loop
