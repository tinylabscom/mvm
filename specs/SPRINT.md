# Sprint 40 — Apple Container Dev Environment

**Goal:** Make `mvmctl dev` work with Apple Containers on macOS 26+ where
`/dev/kvm` is not available. Lima becomes an optional fallback via `--lima`.
This is a dev DX improvement only — production (Firecracker + KVM on Linux)
is unaffected.

**Branch:** `main`

**Plan:** [specs/plans/23-apple-container-dev.md](plans/23-apple-container-dev.md)

## Current Status (v0.9.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 970                      |
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
- [37-image-insights-dx-guest-lib.md](sprints/37-image-insights-dx-guest-lib.md)
- [38-multi-backend-abstraction.md](sprints/38-multi-backend-abstraction.md)
- [39-developer-experience-dx.md](sprints/39-developer-experience-dx.md)

---

## Rationale

On macOS 26+ Apple Silicon, `mvmctl dev` still requires Lima — a 2-5 second
boot overhead plus 500MB+ download on first run. Apple's Virtualization.framework
provides sub-second VM startup with native vsock support. Our `mvm-apple-container`
crate already boots VMs with `VZLinuxBootLoader` using our custom kernel and init
(NOT vminitd), so the guest agent and PTY console work identically to Firecracker.

This sprint makes Apple Container the default dev backend on macOS 26+, with
Lima as an explicit `--lima` fallback.

**Production is unaffected**: All Apple Container code is `#[cfg(target_os = "macos")]`
and doesn't compile on Linux. Production always uses Firecracker + KVM.

---

## Phase 1: Platform Routing

### 1a. Update `needs_lima()` for macOS 26+ ✓

- [x] `crates/mvm-core/src/platform.rs` — `Platform::MacOS => !self.has_apple_containers()`
- [x] `bootstrap.rs:is_lima_required()` — now skips Lima on macOS 26+
- [x] `linux_env.rs:create_linux_env()` — routes to `AppleContainerEnv`
- [x] Test updated: `needs_lima()` conditional on Apple Container availability

### 1b. Route dev commands ✓

- [x] `cmd_dev(DevCmd::Up)` — `cmd_dev_apple_container()`: boot dev VM, wait for agent, open PTY console
- [x] `cmd_dev(DevCmd::Down)` — `cmd_dev_apple_container_down()`: stop dev VM
- [x] `cmd_dev(DevCmd::Shell)` — `console_interactive("mvm-dev")` when dev VM running
- [x] `cmd_dev(DevCmd::Status)` — `cmd_dev_apple_container_status()`: show backend, VM status, kernel version
- [x] Removed "Falling back to Lima" message
- [x] `ensure_dev_image()` — checks cache, builds from Nix flake if missing

---

## Phase 2: Dev Image ✓

### 2a. Nix flake for dev rootfs ✓

- [x] Created `nix/dev-image/flake.nix` using `mkGuest` from guest-lib
- [x] Packages: bash, coreutils, gcc, gnumake, nix, git, curl, wget, iproute2, openssh, nano, e2fsprogs, squashfsTools, strace, procps, htop
- [x] ext4 rootfs + kernel in single `#default` output
- [x] Same kernel as production images (shared Firecracker kernel)

### 2b. Dev image caching ✓

- [x] Cache at `~/.cache/mvm/dev/vmlinux` and `~/.cache/mvm/dev/rootfs.ext4`
- [x] `ensure_dev_image()` checks cache, builds via `nix build` if missing
- [x] Requires host Nix — clear error message with install link if missing
- [x] `find_dev_image_flake()` locates flake in source tree or falls back to guest-lib

### 2c. Shared directory support ✓

- [x] Added `VZSharedDirectory` + `VZVirtioFileSystemDeviceConfiguration` to `macos.rs:start_vm()`
- [x] Host home directory shared as virtiofs tag "home" (read-write)
- [x] Guest init mounts `virtiofs home /host` (silent no-op on Firecracker/Lima)
- [x] Added objc2-virtualization features: VZDirectorySharingDeviceConfiguration, VZSharedDirectory, etc.
- [x] Lima unaffected — uses its own 9p/sshfs sharing

---

## Phase 3: AppleContainerEnv ✓

- [x] `AppleContainerEnv` struct in `crates/mvm-runtime/src/linux_env.rs`
- [x] Implements `LinuxEnv` trait via vsock `GuestRequest::Exec`
- [x] `run()`, `run_visible()`, `run_stdout()`, `run_capture()` — all routed through vsock
- [x] `exec_via_vsock()` — connects to guest agent, sends Exec request, returns `Output`
- [x] `create_linux_env()` factory prefers Apple Container → Lima → Native
- [x] `shell::run_in_vm()` automatically routes through Apple Container

---

## Phase 4: Build Pipeline Without Lima ✓

- [x] `RuntimeBuildEnv` uses `shell::run_in_vm()` which routes through `create_linux_env()`
- [x] `create_linux_env()` now prefers `AppleContainerEnv` on macOS 26+
- [x] Nix builds automatically execute inside Apple Container dev VM
- [x] `run_setup_steps()` skips Lima VM creation when `is_lima_required()` returns false

---

## Phase 5: Tests & Docs ✓

- [x] `AppleContainerEnv` construction test
- [x] CLI tests: `dev up --lima`, `dev down`, `dev shell`, `dev status`
- [x] `is_apple_container_dev_running()` smoke test
- [x] Platform test: `needs_lima()` conditional on Apple Container availability
- [x] E2E test updated: `dev status` accepts Apple Container output
- [x] `CLAUDE.md` updated with Apple Container dev mode description
- [x] CLI reference updated: `dev` command notes Apple Container on macOS 26+
- [x] Development guide already documents dev workflow commands

---

## Key Files

| File | Changes |
|------|---------|
| `crates/mvm-core/src/platform.rs` | `needs_lima()` conditional on `has_apple_containers()` |
| `crates/mvm-cli/src/commands.rs` | Dev command routing for Apple Container |
| `crates/mvm-runtime/src/linux_env.rs` | New `AppleContainerEnv` struct |
| `crates/mvm-apple-container/src/macos.rs` | Shared directory support |
| `crates/mvm-runtime/src/build_env.rs` | Build env selection |
| `nix/dev-image/flake.nix` | New: dev environment rootfs flake |

---

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
# On macOS 26+ Apple Silicon:
mvmctl dev                    # Boots Apple Container, not Lima
mvmctl dev shell              # PTY console into dev VM
mvmctl dev status             # Apple Container dev VM status
mvmctl dev down               # Stops Apple Container dev VM
mvmctl dev --lima             # Falls back to Lima explicitly
mvmctl build --flake .        # Nix build without Lima
```
