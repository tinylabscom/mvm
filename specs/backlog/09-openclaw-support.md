# mvm Sprint 9: OpenClaw Support — Template + Wake API + Deploy Config

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [SPRINT-6-minimum-runtime.md](sprints/SPRINT-6-minimum-runtime.md) (complete)
- [SPRINT-7-role-profiles.md](sprints/SPRINT-7-role-profiles.md) (complete)
- [SPRINT-8-integration-lifecycle.md](sprints/SPRINT-8-integration-lifecycle.md) (complete)

Sprint 9 adds template-based deployments and a standalone deploy command. OpenClaw
is the first template — a personal AI assistant gateway (Telegram/Discord -> Claude
AI -> local CLI tools) that runs as per-user worker VMs with sleep/wake on demand.

OpenClaw is NOT a built-in role. It's a template that creates standard gateway +
worker pools pointing at an external flake (`github:openclaw/nix-openclaw`) which
provides its own `mvm-profiles.toml` and NixOS modules. This approach supports any
Nix-built image/set of images that execute within a microVM.

Full spec: [specs/plans/11-openclaw-support.md](plans/11-openclaw-support.md)

---

## Phase 1: OpenClaw Template
**Status: COMPLETE**

Template for `mvm new openclaw <name>` that creates a gateway + worker deployment
using standard roles, pointing at the external OpenClaw flake.

- [x] `src/templates.rs` — openclaw template: gateway (1024 MiB) + workers (2048 MiB, `Role::Worker`)
- [x] `src/templates.rs` — `default_flake = "github:openclaw/nix-openclaw"` (external, not built-in)

## Phase 2: Vsock Wake Protocol
**Status: COMPLETE**

Guest-to-host communication so gateway VMs can tell the host agent to wake sleeping worker VMs.

- [x] `src/worker/vsock.rs` — `HostBoundRequest` enum: `WakeInstance`, `QueryInstanceStatus`
- [x] `src/worker/vsock.rs` — `HostBoundResponse` enum: `WakeResult`, `InstanceStatus`, `Error`
- [x] `src/worker/vsock.rs` — `read_frame()` / `write_frame()` helpers for generic length-prefixed JSON
- [x] `src/worker/vsock.rs` — `HOST_BOUND_PORT = 53` constant
- [x] Tests: request/response serde roundtrip, port constant (3 new tests)

## Phase 3: Config File + Deploy Command
**Status: COMPLETE**

Config file for `mvm new --config` and standalone `mvm deploy manifest.toml`.

- [x] `src/templates.rs` — `DeployConfig`, `SecretRef`, `OverrideConfig`, `PoolOverride` types
- [x] `src/templates.rs` — `DeploymentManifest`, `ManifestTenant`, `ManifestPool` types
- [x] `src/main.rs` — `--config <path>` flag on `Commands::New`
- [x] `src/main.rs` — `Commands::Deploy { manifest, watch, interval }` command
- [x] `src/main.rs` — `cmd_new()` applies config overrides (flake, vcpus, mem, instances)
- [x] `src/main.rs` — `cmd_deploy()` creates tenant/pools from manifest, supports `--watch`
- [x] Tests: deploy config parse, minimal config, manifest parse, manifest defaults (4 new tests)

## Phase 4: Documentation
**Status: COMPLETE**

- [x] `docs/cli.md` — added `mvm new --config`, `mvm deploy`, `mvm connect` sections
- [x] `specs/SPRINT.md` — Sprint 9 current

---

## Summary

| Metric | Value |
|--------|-------|
| Lib tests | 315 (+19) |
| Integration tests | 10 |
| Total tests | 325 |
| Clippy warnings | 0 |
| New files | `specs/sprints/SPRINT-8-integration-lifecycle.md` |

## Files Created/Modified

| File | Changes |
|------|---------|
| `specs/plans/11-openclaw-support.md` | **NEW** — full OpenClaw support spec |
| `src/main.rs` | `--config`, `Deploy` command, `cmd_deploy()` |
| `src/templates.rs` | OpenClaw template + DeployConfig + DeploymentManifest types |
| `src/worker/vsock.rs` | HostBoundRequest/Response + frame helpers |
| `docs/cli.md` | `mvm deploy` and `--config` docs |
