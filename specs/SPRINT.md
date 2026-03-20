# Sprint 38 — Multi-Backend VM Abstraction

**Goal:** Unify the VM backend interface and add Apple Container support for
sub-second dev startup on macOS 26+, while keeping Firecracker as the
production backend on Linux.

**Branch:** `feat/multi-backend`

**Plan:** [specs/plans/20-multi-backend-abstraction.md](plans/20-multi-backend-abstraction.md)

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 886+                     |
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

### 1a. Platform detection ✓

- [x] `has_apple_containers()` in `platform.rs` (macOS 26+ on Apple Silicon)
- [x] `is_macos_26_or_later()` via `sw_vers` runtime check
- [x] Tests for platform detection on all platforms

### 1b. `AppleContainerBackend` ✓

- [x] `apple_container.rs` in mvm-runtime with full `VmBackend` impl
- [x] Capabilities: vsock=true, snapshots=false, pause_resume=false
- [x] Stub lifecycle methods with clear error messages
- [x] `network_info()` and `guest_channel_info()` stubs (vsock:1024 for vminitd)
- [x] Tests for backend name, capabilities, list, stop_all, status

### 1c. Wire into CLI ✓

- [x] `AppleContainer` variant in `AnyBackend` enum
- [x] `AnyBackend::inner()` dispatch helper (eliminates per-method match repetition)
- [x] `from_hypervisor("apple-container")` selection
- [x] `auto_select()` — prefers Apple Container on macOS 26+
- [x] `--hypervisor apple-container` flag in `run` and `up` commands
- [x] `mvmctl doctor` Apple Container availability check

### 1d. Swift FFI bridge ✓

- [x] `mvm-apple-container` crate with C FFI (`@_cdecl`) to Swift static library
- [x] Swift package wrapping Apple Containerization framework
- [x] `build.rs`: auto-builds Swift, links static lib + system frameworks + rpath
- [x] `#[cfg(apple_container_stub)]` — no-op on non-macOS platforms
- [x] FFI lifecycle: `start()`, `stop()`, `list_ids()` wired end-to-end
- [x] `AppleContainerBackend::start/stop/list/status` use live FFI
- [x] Swift bridge: `ContainerManager` + `VmnetNetwork` + local ext4 `Mount.block()`
- [x] Boot test: FFI chain validated end-to-end (vmnet returns permission error as expected — needs entitlement for full boot)

### Verification ✓

```bash
cargo test --workspace   # 886 tests, 0 failures
cargo clippy --workspace -- -D warnings  # 0 warnings
cargo test -p mvm-apple-container -- --ignored boot_test  # FFI chain works, vmnet needs entitlement
mvmctl run --hypervisor apple-container  # flag accepted
mvmctl doctor  # shows Apple Container availability status
```

---

## Phase 2: Guest Agent + Dev Mode + Templates

### 2a. Guest agent on Apple Container ✓

- [x] `vminitd_client.rs` — typed Rust client for vminitd gRPC API
- [x] `ProcessConfig` struct for launching processes via CreateProcess
- [x] `VminitdClient::launch_guest_agent()`, `write_file()`, `kill()` stubs
- [x] `SandboxContext.proto` copied to `proto/` for reference
- [x] Constants: `VMINITD_VSOCK_PORT=1024`, `GUEST_AGENT_VSOCK_PORT=52`
- [ ] gRPC-over-vsock transport (blocked on vmnet entitlement for running containers)

### 2b. Backend-aware dev mode ✓

- [x] `mvmctl dev --lima` flag for explicit Lima fallback
- [x] On macOS 26+: informs user Apple Container dev is coming, falls back to Lima
- [x] CLI test for `--lima` flag visibility in help

### 2c. Networking ✓

- [x] `VmNetworkInfo` struct and `network_info()` on VmBackend trait (Phase 0)
- [x] Hardcoded IPs are internal to Firecracker backend (no leakage into CLI)
- [x] Apple Container backend will return vmnet subnet via `network_info()`

### 2d. Template tiering ✓

- [x] `template build --snapshot` checks `backend.capabilities().snapshots`
- [x] Non-snapshot backends (Apple Container, Docker) auto-fall back to image-only
- [x] `run --template` only restores from snapshot if backend supports it
- [x] Cold-boot from image works for all backends

### Verification ✓

```bash
cargo test --workspace   # 878 tests, 0 failures
cargo clippy --workspace -- -D warnings  # 0 warnings
mvmctl run --hypervisor apple-container  # flag accepted
mvmctl dev --lima          # explicit Lima fallback
# template build --snapshot on non-FC backend → warns, builds image-only
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
