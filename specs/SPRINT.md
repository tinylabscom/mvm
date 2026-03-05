# mvm — Maintenance Mode

Active development has moved to [mvmd](https://github.com/auser/mvmd) (fleet orchestrator).

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

## Current Status (v0.3.6)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 630                      |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| Examples         | hello, openclaw, paperclip |
| Boot time        | < 10s (< 200ms from snapshot) |
| Binary           | `mvmctl`                 |

## Deferred Backlog

These items may be addressed as needed, driven by mvmd requirements:

- **Config-driven multi-variant builds**: `template.toml` support for building multiple
  variants (gateway, worker) in one command with per-variant resource defaults.

- **mvm-profiles.toml redesign**: Map profiles to flake package attributes instead of
  NixOS module paths. Update Rust parser in mvm-build accordingly.

- **Upstream mvm-core changes**: `UpdateStrategy` types, `DesiredPool.registry_artifact`,
  and `registry_download_revision()` extraction are complete (Phases 71-72a). Further
  fields may be added as needed by mvmd Sprint 13.

## Maintenance Policy

Bug fixes and mvm-core type changes (for mvmd compatibility) will continue to be
committed here. New feature development happens in mvmd.
