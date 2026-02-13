# mvm Sprint 12: Install & Release Reliability

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [SPRINT-6-minimum-runtime.md](sprints/SPRINT-6-minimum-runtime.md) (complete)
- [SPRINT-7-role-profiles.md](sprints/SPRINT-7-role-profiles.md) (complete)
- [SPRINT-8-integration-lifecycle.md](sprints/SPRINT-8-integration-lifecycle.md) (complete)
- [SPRINT-9-openclaw-support.md](sprints/SPRINT-9-openclaw-support.md) (complete)
- [SPRINT-10-coordinator.md](sprints/SPRINT-10-coordinator.md) (complete)
- [SPRINT-11-dev-environment.md](sprints/SPRINT-11-dev-environment.md) (complete)

---

## Motivation

We hardened dev workflows in Sprint 11 but saw recurring friction around sync/bootstrap and release packaging (crates.io, GH Actions). Sprint 12 focuses on making installation, syncing, and publishing reliable on both macOS (Lima) and native Linux, with better diagnostics and documented escape hatches.

## Baseline

| Metric            | Value           |
| ----------------- | --------------- |
| Workspace crates  | 7 + root facade |
| Lib tests         | 366             |
| Integration tests | 10              |
| Total tests       | 376             |
| Clippy warnings   | 0               |
| Tag               | v0.2.0          |

---

## Phase 1: Sync/Bootstrap Hardening
**Status: IN PROGRESS**

- [ ] Detect Lima presence/absence more robustly; avoid `limactl` calls inside guest
- [ ] Make rustup/cargo pathing resilient (no `.cargo/env` required); add self-check
- [x] Add `mvm sync doctor` that reports deps (rustup, cargo, nix, firecracker, limactl)
- [ ] Add regression tests for sync on macOS host + Lima guest + native Linux

## Phase 2: Release + Publish Reliability
**Status: PENDING**

- [ ] Dry-run and live crates.io publish via GH Actions (publish-crates workflow) with docs
- [ ] Version bump tool/guard: refuse publish if workspace versions not updated/tagged
- [ ] Release artifacts: checksums + optional SBOM + signature (gitsign or cosign)
- [ ] Add a `mvm release --dry-run` command that exercises the GH workflow locally

## Phase 3: Installer/Setup UX
**Status: PENDING**

- [ ] Make `mvm setup`/`bootstrap` idempotent with clear re-run messaging
- [ ] Preflight check for KVM, virtualization, network bridges; actionable guidance
- [ ] Improve error surfaces (hint to use `--force`, show missing tool and install cmd)
- [ ] Update docs/QUICKSTART with known-good host matrix and fallback paths

## Phase 4: Observability & Logs
**Status: PENDING**

- [ ] Structured logs for sync/build (timestamps, phases) with `--json` flag
- [ ] Capture and surface builder VM logs when nix build fails
- [ ] Add `mvm doctor` summary (reuses sync doctor) to show overall health

## Phase 5: QA & Documentation
**Status: PENDING**

- [ ] CLI help/examples refreshed for new flags (force, builder resources, doctor)
- [ ] Update sprint README/CHANGELOG section for release notes
- [ ] Add one end-to-end test covering: sync → build --flake → run --config

---

## Non-goals (this sprint)

- Multi-node deployment or cloud installers
- UI/dashboard work
- New feature areas outside install/release reliability

## Success criteria

- `cargo run -- sync` succeeds on macOS host + Lima guest and native Linux without manual fixes
- publish-crates GH workflow completes a dry-run and one live publish for the tagged version
- Documentation reflects install/release workflow and troubleshooting
