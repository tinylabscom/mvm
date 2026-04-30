# mvm Sprint 14: Guest Library, Template Snapshots & OpenClaw Fixes

Previous sprints:
- Sprints 1-12: complete (see `specs/sprints/`)
- [13-boot-time-optimization.md](13-boot-time-optimization.md) (complete)

---

## Motivation

Sprint 13 achieved sub-10s boot times for Firecracker microVMs. Sprint 14 focused on
making the Nix guest image build process modular and reusable, adding template snapshots
for instant VM startup, and stabilizing the OpenClaw integration for production use.

## Baseline

| Metric           | Value                  |
| ---------------- | ---------------------- |
| Workspace crates | 6 + root facade        |
| Total tests      | 557                    |
| Clippy warnings  | 0                      |
| Boot time        | < 10s (post Sprint 13) |

---

## Phase 1: Nix Guest Library Restructure

**Status: COMPLETE**

Extracted a reusable `mkGuest` function in `nix/guest-lib/flake.nix` that builds
minimal Firecracker rootfs images from declarative Nix configurations.

- [x] `nix/guest-lib/flake.nix` — core library defining `mkGuest` builder
- [x] `nix/guest-lib/minimal-init.nix` — PID 1 init script generator (service loops, health checks, user management)
- [x] `nix/guest-lib/firecracker-kernel-pkg.nix` — custom kernel build
- [x] `nix/guest-lib/guest-agent-pkg.nix` — guest agent binary packaging
- [x] `rootfsType` parameter: "ext4" (default) or "squashfs" (compressed RO images)
- [x] Examples unified under `nix/examples/` using `mvm.url = "path:../guest-lib"`

## Phase 2: Template Snapshot-on-Build

**Status: COMPLETE**

Added `mvmctl template build --snapshot` to create Firecracker snapshots at build time
for instant VM restore (~200ms startup).

- [x] `template_build_with_snapshot()` in `crates/mvm-runtime/src/vm/template/lifecycle.rs`
- [x] Boot temporary VM from built artifacts
- [x] `wait_for_healthy()` — vsock ping to guest agent
- [x] `wait_for_integrations_healthy()` — per-service health checks
- [x] Snapshot creation (vCPU pause + full snapshot via Firecracker API)
- [x] `vmstate.bin` + `mem.bin` stored in template revision directory
- [x] Per-instance symlinks + flock serialization for concurrent startup
- [x] `mvmctl template edit` command for modifying template config
- [x] Human-readable memory sizes (512M, 4G, 1024K)
- [x] 15-minute health check timeout for nested virtualization

## Phase 3: OpenClaw Stabilization

**Status: COMPLETE**

Fixed multiple issues preventing OpenClaw gateway from running reliably in Firecracker:

- [x] **esbuild single-file bundle**: ESM format (`--format=esm`), `.mjs` extension, `--loader:.node=empty` for native modules. Reduced rootfs from ~1.8GB to ~50-100MB.
- [x] **Gateway double-start bug fix**: Entry point wrapper suppresses `process.exit(1)` from concurrent `startGatewayServer()` conflict
- [x] **Loopback proxy for device pairing**: TCP proxy `0.0.0.0:3000 → 127.0.0.1:3001` makes all connections appear local (auto-approved)
- [x] **Config fallback**: `OPENCLAW_CONFIG_PATH` environment variable support
- [x] **WhatsApp channel**: `"enabled": true` required in channel config

## Phase 4: Binary Rename & Release Infrastructure

**Status: COMPLETE**

- [x] Binary renamed from `mvm` to `mvmctl` (crates.io publishing)
- [x] Lima VM name stays `mvm` internally
- [x] `install.sh` updated for GitHub releases
- [x] git-cliff configuration for automated CHANGELOG generation
- [x] Release workflow with changelog automation
- [x] Lima installation updated to use GitHub releases (not Homebrew)
- [x] Cross-compilation fixes for aarch64

---

## Summary

| Metric           | Before | After |
| ---------------- | ------ | ----- |
| Workspace crates | 6      | 6     |
| Total tests      | 557    | 576   |
| Clippy warnings  | 0      | 0     |
| Version          | 0.3.2  | 0.3.5 |
| OpenClaw rootfs  | ~1.8GB | ~100MB |
| VM cold start    | ~5-10s | ~200ms (from snapshot) |
