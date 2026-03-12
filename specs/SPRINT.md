# Sprint 17 — Resource Safety & Release v0.5.0

**Goal:** Add RAII cleanup for VM resources to prevent leaks, specify MSRV, and cut a v0.5.0 release packaging all hardening work from Sprint 16.

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.5.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 679                      |
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

---

## Phase 1: Drop Impls for VM Resources **Status: COMPLETE**

### 1.1 Audit resource ownership

- [x] Full audit of all OS resource handles across workspace (Firecracker PIDs, TAP interfaces, vsock sockets, temp dirs, cgroups, socat children, file locks)
- [x] Mapped each resource to existing cleanup function
- [x] Identified medium-risk targets: Firecracker process (dev+flake), TAP interfaces

### 1.2 Firecracker process guard

- [x] `FirecrackerGuard` struct in `microvm.rs`: wraps VM directory path, kills FC process on drop via PID file
- [x] `defuse()` method prevents cleanup after successful launch (ownership transfers to `stop_vm()`)
- [x] Handles both `fc.pid` (multi-VM) and `.fc-pid` (legacy) PID file locations
- [x] Wired into `run_from_build()`, `restore_from_template_snapshot()`, and legacy `start()`
- [x] 3 tests: defuse prevents cleanup, drop runs cleanup with correct script, tolerates cleanup failure

### 1.3 TAP interface guard

- [x] `TapGuard` struct in `microvm.rs`: wraps `VmSlot`, calls `network::tap_destroy()` on drop
- [x] `defuse()` method prevents cleanup after successful launch
- [x] Wired into `run_from_build()` and `restore_from_template_snapshot()`
- [x] 2 tests: defuse prevents cleanup, drop runs cleanup with TAP destroy command

### 1.4 Shell mock fix for `run_visible`

- [x] Added `shell_mock::intercept()` to `LimaEnv::run_visible()` and `NativeEnv::run_visible()` — previously mock was not checked for visible shell commands, making Drop impls untestable

### 1.5 Build temp directory cleanup (deferred)

- Build temp dirs are created inside bash scripts (`mktemp -d`) with inline cleanup
- Already low-risk: scripts use `set -e` and cleanup runs at script end
- `tempfile::TempDir` not applicable (dirs created in Lima VM, not host)

---

## Phase 2: MSRV Specification **Status: COMPLETE**

- [x] Add `rust-version = "1.85"` to workspace `Cargo.toml`
- [x] Add `rust-version.workspace = true` to root package
- [x] Verified via `cargo check --workspace` (Edition 2024 requires 1.85+)

---

## Phase 3: Release v0.5.0 **Status: COMPLETE**

### 3.1 Version bump

- [x] Update version in all workspace `Cargo.toml` files (root + 6 crates via `workspace.package`)
- [x] Update `Cargo.lock`

### 3.2 Changelog

- [x] Updated CHANGELOG.md with v0.5.0 section
- [x] Highlighted Sprint 16 hardening: error handling, test coverage, observability, state safety, security defaults
- [x] Highlighted Sprint 17: resource safety, MSRV

### 3.3 Release prep

- [x] `cargo test --workspace` — 679 tests pass
- [x] `cargo clippy --workspace -- -D warnings` — zero warnings
- [ ] Tag `v0.5.0`
- [ ] Archive Sprint 17 to `specs/sprints/17-resource-safety-release.md`

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```
