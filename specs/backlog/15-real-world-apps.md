# mvm Sprint 15: Real-World Applications & Developer Experience

Previous sprints:
- Sprints 1-13: complete (see `specs/sprints/`)
- [14-guest-library-and-examples.md](14-guest-library-and-examples.md) (complete)

---

## Motivation

Sprint 14 delivered a modular Nix guest library (mkGuest), template snapshots, and
stabilized OpenClaw. Sprint 15 proved the platform by adding a second real-world
application (Paperclip — AI agent platform with PostgreSQL), improving the developer
experience with environment injection, port forwarding, fleet config, and consolidating
the CLI commands.

## Baseline

| Metric           | Value             |
| ---------------- | ----------------- |
| Workspace crates | 6 + root facade   |
| Total tests      | 576               |
| Clippy warnings  | 0                 |
| Version          | 0.3.5             |
| Examples         | hello, openclaw   |

---

## Phase 1: Paperclip Example Application

**Status: COMPLETE**

Added a complete AI agent orchestration platform (Paperclip) as a microVM example:

- [x] `nix/examples/paperclip/flake.nix` — three-phase Nix build:
  1. FOD: deterministic `npm install` with workspace→npm compatibility patching
  2. Patching: autoPatchelf for embedded native binaries
  3. Compilation: TypeScript + Vite build
- [x] PostgreSQL service running in-VM (starts before Paperclip)
- [x] Config injection via `/mnt/config/paperclip.json`
- [x] Health checks: port 3100 (hex 0x0C1C) via `/proc/net/tcp` polling
- [x] `nix/examples/paperclip/start.sh` — quick-start script with auto-build and port forwarding
- [x] Environment variable configuration with sensible defaults

## Phase 2: Environment Variable Injection & Port Forwarding

**Status: COMPLETE**

- [x] `--env KEY=VALUE` flag on `mvmctl run` — injects environment variables into guest
- [x] Environment variables written to `mvm-env.env` on config drive
- [x] `minimal-init.nix` sources `mvm-env.env` at service startup
- [x] Post-restore re-source for snapshot-restored VMs
- [x] `--port HOST:GUEST` flag for port forwarding specification
- [x] `--forward` flag for automatic port forwarding after boot
- [x] `mvmctl forward NAME --port HOST:GUEST` standalone command

## Phase 3: CLI Consolidation

**Status: COMPLETE**

- [x] Renamed `upgrade` command to `update` (clearer semantics)
- [x] Removed legacy `Start` command — `Run` is the sole VM launcher
- [x] Added `alias = "start"` on `Run` for backward compatibility
- [x] Simplified microVM DNS to use 8.8.8.8 instead of gateway IP
- [x] Updated doctor messaging and bootstrap jq installation

## Phase 4: Documentation Site & Fleet Config

**Status: COMPLETE**

- [x] Astro-based documentation site deployed at gomicrovm.com
- [x] CNAME configuration for GitHub Pages
- [x] Config/secrets guide updated with volume syntax and env vars
- [x] Template guide updated with snapshot workflow
- [x] README refresh with updated feature list

---

## Summary

| Metric           | Before   | After   |
| ---------------- | -------- | ------- |
| Workspace crates | 6        | 6       |
| Total tests      | 576      | 611     |
| Clippy warnings  | 0        | 0       |
| Version          | 0.3.5    | 0.3.6   |
| Examples         | 2        | 3 (+ paperclip) |
| CLI commands     | 20       | 19 (consolidated) |
| Docs site        | none     | gomicrovm.com |
