# mvm Sprint 12: Install & Release Reliability + Securing OpenClaw

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

Additionally, the vsock protocol between host and guest has no authentication, no command validation, no threat detection, and no health monitoring. OpenClaw agents run inside Firecracker microVMs as adversarial-by-default workloads — they will drift, forget rules, and silently fail. The security phases close the gaps identified in the [OpenClaw security research](research/openclaw-security.md) and implement the [securing plan](plans/14-securing-openclaw.md). All security improvements are native Rust — SafeClaw and the OpenClaw Field Manual are reference material only.

## Baseline

| Metric            | Value           |
| ----------------- | --------------- |
| Workspace crates  | 5 + root facade |
| Lib tests         | 366             |
| Integration tests | 10              |
| Total tests       | 376             |
| Clippy warnings   | 0               |
| Tag               | v0.3.0          |

---

## Phase 1: Sync/Bootstrap Hardening
**Status: COMPLETE**

- [x] Detect Lima presence/absence more robustly; avoid `limactl` calls inside guest
- [x] Make rustup/cargo pathing resilient (no `.cargo/env` required); add self-check
- [x] Add `mvm sync doctor` that reports deps (rustup, cargo, nix, firecracker, limactl)
- [ ] Add regression tests for sync on macOS host + Lima guest + native Linux

## Phase 2: Release + Publish Reliability
**Status: COMPLETE**

- [x] Dry-run and live crates.io publish via GH Actions (publish-crates workflow) — removed stale mvm-agent/mvm-coordinator from pipeline
- [x] Version bump tool/guard: `deploy-guard.sh` verifies workspace version, git tag, no hardcoded versions, inter-crate dep consistency, clippy
- [x] Release artifacts: SHA256 checksums generated per-platform and combined into `checksums-sha256.txt`; installer verifies checksums
- [x] Add a `mvm release --dry-run` command that exercises publish checks locally (also `--guard-only` for fast pre-publish verification)
- [x] Removed mvm-agent and mvm-coordinator crates (belong in mvmd repo, not dev CLI)
- [x] Fixed `mvm-install.sh` to match release archive format (tar.gz + target triples)

## Phase 2b: Global Templates (shared images, tenant-scoped pools)
**Status: COMPLETE**

- [x] Add `template` CLI group (create/list/info/delete/build) and global cache under `/var/lib/mvm/templates/<template>/`
- [x] Add `TemplateSpec`/`TemplateRevision` types and path helpers in `mvm-core`
- [x] Make `pool create` require `--template`; `pool build` reuses template artifacts (template `current` copied into pool). `--force` on pool rebuilds template first.
- [x] Config-driven template builds (`mvm template build --config template.toml`) to emit multiple role variants
- [x] Template build cache key on flake.lock/profile/role; `template_build()` now computes actual `nix hash path flake.lock` instead of using revision hash. Pool build links artifacts via cache key match, no per-tenant rebuild.
- [x] Doc polish — template CLI reference added to `docs/user-guide.md` (scaffold, create, build, config-driven variants, registry push/pull/verify, pool integration)
- ~~Migration helper~~ deferred (no existing pools to migrate)

## Phase 2c: Vsock CLI & Guest Agent
**Status: COMPLETE**

- [x] Add `mvm vm ping <name>` and `mvm vm status <name> [--json]` CLI commands
- [x] Enable vsock device (`PUT /vsock`) in dev-mode Firecracker configuration
- [x] Add VSOCK column to `mvm status` multi-VM table
- [x] Lima delegation for vsock commands (macOS → Lima VM re-invocation)
- [x] Fix vsock socket permissions after VM start (`chmod 0666`)
- [x] Create `mvm-guest-agent` binary with real system monitoring (load sampling, idle/busy detection)
- [x] Guest agent handles: Ping, WorkerStatus, SleepPrep (sync + drop caches), Wake
- [x] Guest agent accepts config file (`/etc/mvm/agent.json`) and CLI flags (`--port`, `--busy-threshold`, `--sample-interval`)
- [x] Shared NixOS module (`nix/modules/guest-agent.nix`) and package (`nix/modules/guest-agent-pkg.nix`)
- [x] OpenClaw flake imports guest agent module; agent starts automatically on boot
- [x] Template scaffold emits guest agent module files on `mvm template create`
- [x] CLI integration tests for `mvm vm` subcommands (help, parsing, graceful errors)
- [x] Add `rust-overlay` to Nix flakes for Rust 1.85+ (edition 2024 support)
- [x] Rebuild images with guest agent and validate `mvm vm ping` end-to-end

## Phase 3: Installer/Setup UX
**Status: COMPLETE**

- [x] Make `mvm setup`/`bootstrap` idempotent with clear re-run messaging and `--force` flag
- [x] Preflight check for KVM, virtualization, disk space, Lima status; actionable guidance via expanded `mvm doctor`
- [x] Improve error surfaces (`with_hints` wrapper for common failures: missing tools, KVM, permissions, Nix)
- [x] `mvm doctor --json` for machine-readable diagnostics
- [x] Create `docs/quickstart.md` with known-good host matrix, install steps, and troubleshooting

## Phase 4: Observability & Logs
**Status: COMPLETE**

- [x] Structured logs for sync/build (timestamps, phases) with `--json` flag
- [x] Capture and surface builder VM logs when nix build fails
- [x] Add `mvm doctor` summary (reuses sync doctor) to show overall health (done in Phase 3)

## Phase 5: QA & Documentation
**Status: COMPLETE**

- [x] CLI help/examples refreshed for new flags (force, builder resources, doctor, --json)
- [x] Update CHANGELOG section for v0.3.2 release notes
- [x] Add end-to-end integration test covering: sync → build --flake → run flag chain parsing

---

## Phase 6: Authenticated Vsock Protocol
**Status: PENDING**

**Goal:** Ed25519-signed vsock frames with per-session keys provisioned via the secrets drive.

- [ ] Add `SecurityPolicy`, `AuthenticatedFrame`, `SessionHello`/`SessionHelloAck`, `AccessPolicy`, `RateLimitPolicy` types in new `mvm-core/src/security.rs`
- [ ] Add `pub mod security` to `mvm-core/src/lib.rs`
- [ ] Implement authenticated frame wrappers (`write_authenticated_frame`, `read_authenticated_frame`) in `mvm-guest/src/vsock.rs`
- [ ] Add `ed25519-dalek` dependency to `mvm-guest/Cargo.toml`
- [ ] Add session key generation to `mvm-runtime/src/security/signing.rs`
- [ ] Implement challenge-response handshake (`SessionHello` → `SessionHelloAck`) after existing `CONNECT/OK`
- [ ] Key provisioning: host writes per-session keypair to secrets drive (`/mnt/secrets/vsock/`) before VM boot
- [ ] Version negotiation: fall back to unauthenticated mode if guest responds `version: 1`
- [ ] Default `require_auth: false`, opt-in via `--require-vsock-auth`
- [ ] Tests: frame signing roundtrip, serde roundtrip, challenge-response handshake (mock UnixStream), tampered frame rejection, replay detection via sequence numbers

## Phase 7: Command Gating
**Status: PENDING**

**Goal:** Host-side blocklist for vsock commands. Matching commands are blocked or held for approval.

- [ ] Add `GateDecision`, `ApprovalVerdict`, `BlocklistEntry` types to `mvm-core/src/security.rs`
- [ ] Create `mvm-runtime/src/security/command_gate.rs` — Aho-Corasick literal matching + glob wildcards
- [ ] Gate logic: non-match → allow, Block → reject, RequireApproval → hold (dev mode: auto-approve with warning)
- [ ] Log every gate decision to audit trail
- [ ] Harden builder agent (`mvm-guest/src/bin/mvm-builder-agent.rs`): validate `flake_ref` against allow-list, validate `attr` starts with `packages.`, reject when `access.build == false`
- [ ] Export `command_gate` from `mvm-runtime/src/security/mod.rs`
- [ ] Tests: blocklist matching, gate decision logic, builder flake_ref validation, blocked command returns error via vsock

## Phase 8: Threat Classification + Audit Extension
**Status: PENDING**

**Goal:** Classify every vsock message against 10 threat categories using idiomatic Rust (not a wall of regex). Extend audit trail.

- [ ] Add `ThreatCategory` (10 variants), `ThreatFinding`, `Severity` types to `mvm-core/src/security.rs`
- [ ] Create `mvm-runtime/src/security/threat_classifier.rs` with three-tier detection:
  - [ ] Tier 1: Aho-Corasick multi-pattern matching (~200 literals, single O(n) scan) — credential prefixes, destructive commands, exfil domains, privilege escalation, system paths, Firecracker-specific
  - [ ] Tier 2: Typed Rust pattern matching (str methods + match arms) — path analysis, command structure, credential format, network patterns, permission parsing, Nix-specific
  - [ ] Tier 3: Regex only for complex patterns (~20-30 via `RegexSet`) — AWS key format, JWT tokens, base64 payloads, obfuscation, shell injection
- [ ] MicroVM-specific patterns: Firecracker escape, Nix sandbox breakout, cgroup escape, seccomp bypass, vsock abuse
- [ ] Add `aho-corasick` dependency to `mvm-runtime/Cargo.toml`
- [ ] Extend `AuditEntry` in `mvm-core/src/audit.rs`: add `threats`, `gate_decision`, `frame_sequence` fields (`#[serde(default)]`)
- [ ] Add `AuditAction` variants: `VsockSessionStarted`, `VsockSessionEnded`, `VsockFrameReceived`, `CommandBlocked`, `CommandApproved`, `CommandDenied`, `ThreatDetected`, `RateLimitExceeded`, `SessionRecycled`
- [ ] Wire classifier into audit event emission in `mvm-runtime/src/security/audit.rs`
- [ ] Tests: per-category classification, benign message produces no findings, `AuditEntry` backward compat, performance (<10ms for 1000 frames)

## Phase 9: Health Monitoring + Session Lifecycle + Rate Limiting
**Status: PENDING**

**Goal:** Host-side vsock health checks with kill/restart. VM session recycling. Frame rate limiting.

- [ ] Create `mvm-runtime/src/security/health_monitor.rs` — periodic vsock Ping, consecutive failure tracking, kill + restart after N failures, audit logging
- [ ] Create `mvm-runtime/src/security/session_manager.rs` — per-VM session state (started_at, tasks_completed, frames_sent/received), recycle on `max_lifetime_secs` or `max_tasks`, graceful drain via SleepPrep
- [ ] Create `mvm-runtime/src/security/rate_limiter.rs` — sliding window token bucket, configurable frames_per_second/frames_per_minute, exceeded frames dropped + audit event
- [ ] Add session + rate limit config types to `mvm-core/src/security.rs`
- [ ] Export new modules from `mvm-runtime/src/security/mod.rs`
- [ ] Tests: rate limiter allows/blocks correctly, session expiry triggers recycle, 3 consecutive ping failures triggers kill

## Phase 10: Security Posture Scoring + Immutable Config
**Status: PENDING**

**Goal:** Multi-layer health scoring for VM security config. Config drive integrity verification. CLI surface.

- [ ] Create `mvm-runtime/src/security/posture.rs` — 12 security layers (JailerIsolation, CgroupLimits, SeccompFilter, NetworkIsolation, VsockAuth, EncryptionAtRest, EncryptionInTransit, AuditLogging, SecretManagement, ConfigImmutability, GuestHardening, SupplyChainIntegrity)
- [ ] Implement `PostureCheck { name, score, status, detail }` and overall score calculation
- [ ] Config drive integrity: SHA-256 hash at boot, periodic re-check for tampering
- [ ] `SecurityPolicy` lives on config drive (read-only post-boot)
- [ ] Add `mvm security status` CLI command (or `mvm doctor --security`)
- [ ] Add posture types to `mvm-core/src/security.rs`
- [ ] Tests: posture check scoring, overall calculation, config hash computation

---

## Non-goals (this sprint)

- Multi-node deployment or cloud installers
- UI/dashboard work
- SafeClaw integration (reference material only)
- mvmd-specific security (coordinator approval flow, fleet-wide session management) — follow-up after mvm-side work lands
- Hardware attestation (TPM2/SEV-SNP/TDX)

## Success criteria

- `cargo run -- sync` succeeds on macOS host + Lima guest and native Linux without manual fixes
- publish-crates GH workflow completes a dry-run and one live publish for the tagged version
- Vsock protocol supports authenticated frames with Ed25519 signatures
- Command gate blocks known-dangerous patterns, auto-approves in dev mode
- Threat classifier detects credential leaks, destructive commands, Firecracker escape attempts
- Health monitor detects and kills unresponsive VMs
- `mvm security status` outputs a posture score for a running VM
- All existing tests pass, zero clippy warnings
- New test count: 376 + ~40-60 security tests
- Documentation reflects install/release workflow and troubleshooting

## Verification

After each phase:
1. `cargo build` — no compile errors
2. `cargo clippy -- -D warnings` — zero warnings
3. `cargo test` — all existing + new tests pass
