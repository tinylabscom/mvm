# Sprint 38 — Multi-Backend VM Abstraction

**Goal:** Unify the VM backend interface and add Apple Container support for
sub-second dev startup on macOS 26+, while keeping Firecracker as the
production backend on Linux.

**Branch:** `feat/multi-backend`

**Plan:** [specs/plans/20-multi-backend-abstraction.md](plans/20-multi-backend-abstraction.md)

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 866+                     |
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

---

## Rationale

mvm currently requires Lima + Firecracker (KVM) for all VM operations on macOS.
This adds startup latency (2-5s for Lima boot) and complexity. Apple's new
Containerization framework (macOS 26+) provides lightweight VMs with sub-second
startup and native vsock support — architecturally identical to Firecracker
microVMs but without needing KVM.

The `VmBackend` trait already exists but the interface is leaky: callers must use
backend-specific `start_firecracker()` / `start_microvm_nix()` methods. Adding
new backends (Apple Container, Docker) requires a unified `VmStartConfig` first.

This sprint delivers:
1. **Phase 0**: Unified backend interface (`VmStartConfig`, `GuestChannel`, `VmNetworkInfo`)
2. **Phase 1**: Apple Container backend via `swift-bridge` Rust↔Swift FFI
3. **Phase 2**: Guest agent integration, dev mode awareness, template tiering

Docker backend for Windows dev is deferred to a follow-up sprint.

---

## Phase 0: Unify Backend Interface

### 0a. `VmStartConfig` in mvm-core ✓

- [x] `VmStartConfig` struct (name, rootfs_path, kernel_path, cpus, memory, ports, volumes, config/secret files)
- [x] `VmPortMapping`, `VmVolume`, `VmFile` types with serde + tests
- [x] Replace `VmBackend::type Config` with `VmStartConfig`
- [x] `FirecrackerConfig::from_start_config()` and `MicrovmNixConfig::from_start_config()`
- [x] Unified `AnyBackend::start(&VmStartConfig)` — all 4 CLI call sites migrated
- [x] `start_firecracker()` retained only for snapshot restore path
- [x] `VmStartParams` struct in commands.rs (avoids clippy::too_many_arguments)

### 0b. `GuestChannelInfo` enum ✓

- [x] `GuestChannelInfo` enum (`Vsock { cid, port }`, `UnixSocket { path }`) in mvm-core
- [x] `guest_channel_info()` default method on `VmBackend` trait
- [x] Serde roundtrip tests for both variants

### 0c. `VmNetworkInfo` ✓

- [x] `VmNetworkInfo` struct (guest_ip, gateway_ip, subnet_cidr)
- [x] `network_info()` default method on `VmBackend` trait
- [x] Serde roundtrip test

### 0d. `TemplateKind` ✓

- [x] `TemplateKind::Image` and `TemplateKind::Snapshot(SnapshotInfo)` enum
- [x] `PartialEq + Eq` on `SnapshotInfo` for equality checks
- [x] Serde roundtrip tests for both variants

### Verification ✓

```bash
cargo test --workspace   # 866 tests, 0 failures
cargo clippy --workspace -- -D warnings  # 0 warnings
# All existing tests pass, backend.start(&config) works for both backends
```

---

## Phase 1: Apple Container Backend

### 1a. `mvm-apple-container` crate

- [ ] Swift package importing Containerization framework
- [ ] `swift-bridge` build integration
- [ ] FFI: `is_available()`, `create_container()`, `start_container()`, `stop_container()`, `exec_shell()`
- [ ] `#[cfg(target_os = "macos")]` conditional compilation
- [ ] Boot test: validate Nix ext4 rootfs in Apple Container via `cctl`

### 1b. `AppleContainerBackend`

- [ ] Implements `VmBackend` with capabilities (vsock=true, snapshots=false)
- [ ] Direct ext4 mount via `VZDiskImageStorageDeviceAttachment`
- [ ] `guest_channel()` → vsock to guest agent
- [ ] `network_info()` → vmnet subnet

### 1c. Wire into CLI

- [ ] `AppleContainer` variant in `AnyBackend`
- [ ] `--hypervisor apple-container` flag
- [ ] Platform detection: `has_apple_containers()` in `platform.rs`
- [ ] Auto-select on macOS 26+

---

## Phase 2: Guest Agent + Dev Mode + Templates

### 2a. Guest agent on Apple Container

- [ ] vminitd gRPC client (`vminitd_client.rs`)
- [ ] Launch mvm guest agent via `createProcess` gRPC
- [ ] Health checks over vsock

### 2b. Backend-aware dev mode

- [ ] `mvmctl dev` → Apple Container shell on macOS 26+
- [ ] `mvmctl dev --lima` → Lima fallback
- [ ] `exec_shell()` via vminitd gRPC

### 2c. Networking

- [ ] Port forwarding via `VmNetworkInfo` (not hardcoded IPs)
- [ ] vmnet subnet handling for Apple Container

### 2d. Template tiering

- [ ] `TemplateKind::Image` for Apple Container (no snapshot)
- [ ] `TemplateKind::Snapshot` for Firecracker (unchanged)
- [ ] `template run` handles both kinds

### Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
mvmctl run --hypervisor apple-container --flake . --profile minimal
mvmctl dev                 # auto-selects Apple Container on macOS 26+
mvmctl dev --lima           # explicit Lima fallback
mvmctl template build base  # image-only template on Apple Container
mvmctl run --hypervisor firecracker  # unchanged
```

---

## Key Files

| File | Changes |
|------|---------|
| `crates/mvm-core/src/vm_backend.rs` | `VmStartConfig`, `GuestChannel`, `VmNetworkInfo`, trait refactor |
| `crates/mvm-core/src/template.rs` | `TemplateKind` enum |
| `crates/mvm-core/src/platform.rs` | `has_apple_containers()` |
| `crates/mvm-apple-container/` | New crate: Swift wrapper + swift-bridge |
| `crates/mvm-runtime/src/vm/backend.rs` | `AppleContainer` variant, unified `start()` |
| `crates/mvm-runtime/src/vm/apple_container.rs` | `AppleContainerBackend` impl |
| `crates/mvm-runtime/src/vm/vminitd_client.rs` | gRPC client for vminitd |
| `crates/mvm-runtime/src/vm/network.rs` | Parameterize subnet |
| `crates/mvm-cli/src/commands.rs` | Unified start, `--hypervisor`, dev mode |
| `crates/mvm-cli/src/doctor.rs` | Apple Container availability check |
| `crates/mvm-guest/src/vsock.rs` | `GuestChannel` trait impl |
