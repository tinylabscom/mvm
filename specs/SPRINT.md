# Sprint 37 — Image Insights, DX Polish & Guest-Lib Expansion

**Goal:** Instrument the build pipeline with artifact size tracking, enrich
`template info` with revision/snapshot data, expand error hints, and add
`mkPythonService` / `mkStaticSite` to guest-lib.

**Branch:** `feat/sprint-37`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 858+                     |
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
- [35-run-watch.md](sprints/35-run-watch.md)
- [36-fast-boot-minimal-images.md](sprints/36-fast-boot-minimal-images.md)

---

## Rationale

Sprint 36 delivered fast boot via pre-compiled exports, dev-dep pruning, and
`mkNodeService`, but left three items incomplete: rootfs size measurement,
post-pruning server verification, and health-check log suppression testing.
These naturally feed into Sprint 37's first theme — instrumenting the build
pipeline with artifact size tracking.

After `template build`, the user sees "Template 'foo' built successfully
(revision: abc123)" but has no idea whether the rootfs is 50 MB or 500 MB.
The snapshot code already measures sizes via `stat -c%s` — this pattern just
needs extending to build artifacts.

On the DX side, `template info` shows only the TemplateSpec. It doesn't surface
artifact sizes, revision details, or snapshot status — all data that lives in
`revision.json` but is invisible. The error hint system covers ~8 patterns but
misses common failures.

For guest-lib, `mkNodeService` established a clean `{ package, service,
healthCheck }` pattern. Extending to Python and static sites is straightforward
and high-value.

---

## Phase 1: Sprint 36 Carryovers — Size Measurement & Verification

### 1a. `ArtifactSizes` struct in mvm-core

- [x] `ArtifactSizes` struct with `vmlinux_bytes`, `rootfs_bytes`, `initrd_bytes`, `nix_closure_bytes`
- [x] `format_bytes()` utility with unit tests (0, KiB, MiB, GiB boundaries)
- [x] `sizes: Option<ArtifactSizes>` added to `ArtifactPaths` (backward compat via `#[serde(default)]`)
- [x] Serde roundtrip tests for `ArtifactSizes`

### 1b. Size capture in dev_build

- [x] `measure_artifact_sizes()` function using `stat -c%s`
- [x] `artifact_sizes` field added to `DevBuildResult`
- [x] Sizes measured on both fresh-build and cache-hit paths
- [x] Tests for size measurement

### 1c. Store sizes in TemplateRevision

- [x] `template_build()` populates `artifact_sizes` from `DevBuildResult`
- [x] Build success message includes human-readable sizes (rootfs + kernel)

### 1d. Health check grace period test

- [x] Unit tests for `build_integration_reports()` grace period logic
- [x] Tests cover: `Starting` during grace, `Error` after grace, no integrations case

### Verification

```bash
cargo test --workspace              # 858+ tests pass
cargo clippy --workspace -- -D warnings  # zero warnings
```

---

## Phase 2: Enhanced `template info` and Artifact Reporting

- [x] `template_load_current_revision()` in lifecycle.rs
- [x] `template info` shows revision hash, built_at, artifact sizes, snapshot status
- [x] `template info --json` includes full revision data via `InfoOut` struct

---

## Phase 3: DX — Error Hints & Scaffold Expansion

### 3a. New error hint patterns

- [x] Stale flake.lock (`does not provide attribute` / `flake has no`)
- [x] Disk full (`No space left on device` / `ENOSPC`)
- [x] Timeout/connection errors (`timed out` / `connection refused`)
- [x] FOD hash mismatch (`hash mismatch` + `got:`)
- [x] Template not found → suggest `mvmctl template list`

### 3b. Python scaffold preset

- [x] `flake-python.nix` scaffold template
- [x] `flake_content_for_preset("python")` wired up
- [x] Preset help text updated
- [x] CLI test for python preset

### 3c. Doctor: Nix store size warning

- [x] `nix_store_size_check()` warns if store > 20 GiB
- [x] Suggests `nix-collect-garbage -d`

---

## Phase 4: Guest-Lib — `mkPythonService` and `mkStaticSite`

- [x] `mkPythonService` in `nix/guest-lib/flake.nix`
- [x] `mkStaticSite` in `nix/guest-lib/flake.nix`
- [x] Service builder contract documented in flake.nix comments
- [x] `hello-python` example (flake.nix + app/main.py)

---

## Key Files Changed

| File | Changes |
|------|---------|
| `crates/mvm-core/src/pool.rs` | `ArtifactSizes` struct, `format_bytes()` |
| `crates/mvm-core/src/template.rs` | Test fix for new `sizes` field |
| `crates/mvm-build/src/dev_build.rs` | Size capture, `DevBuildResult.artifact_sizes` |
| `crates/mvm-build/src/orchestrator.rs` | `sizes: None` compat |
| `crates/mvm-build/tests/pipeline.rs` | `sizes: None` compat |
| `crates/mvm-runtime/src/vm/template/lifecycle.rs` | Store sizes, `template_load_current_revision()` |
| `crates/mvm-cli/src/template_cmd.rs` | Enrich `info()`, python preset |
| `crates/mvm-cli/src/commands.rs` | 5 new `with_hints()` patterns |
| `crates/mvm-cli/src/doctor.rs` | Nix store size check |
| `crates/mvm-cli/resources/template_scaffold/flake-python.nix` | New scaffold |
| `crates/mvm-guest/src/bin/mvm-guest-agent.rs` | Grace period unit tests |
| `nix/guest-lib/flake.nix` | `mkPythonService`, `mkStaticSite`, docs |
| `nix/examples/hello-python/` | New example |
| `tests/cli.rs` | Python preset test |
