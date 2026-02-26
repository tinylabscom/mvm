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
- [ ] Add regression tests for sync on macOS host + Lima guest + native Linux (deferred — requires CI matrix)

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
**Status: COMPLETE**

**Goal:** Ed25519-signed vsock frames with per-session keys provisioned via the secrets drive.

- [x] Add `SecurityPolicy`, `AuthenticatedFrame`, `SessionHello`/`SessionHelloAck`, `AccessPolicy`, `RateLimitPolicy`, `SessionPolicy` types in new `mvm-core/src/security.rs`
- [x] Add `pub mod security` to `mvm-core/src/lib.rs`
- [x] Implement authenticated frame wrappers (`write_authenticated_frame`, `read_authenticated_frame`) in `mvm-guest/src/vsock.rs`
- [x] Add `ed25519-dalek`, `rand`, `chrono` dependencies to `mvm-guest/Cargo.toml`; add `ed25519-dalek`, `rand`, `base64` to `mvm-runtime/Cargo.toml`
- [x] Add session key generation (`generate_session_keypair`, `provision_session_keys`, `load_session_key`, `load_verifying_key`) to `mvm-runtime/src/security/signing.rs`
- [x] Implement challenge-response handshake (`handshake_as_host`, `handshake_as_guest`) after existing `CONNECT/OK`
- [x] Key provisioning: `provision_session_keys()` writes per-session keypair to secrets drive (`/mnt/secrets/vsock/`) before VM boot
- [x] Version negotiation: protocol version constants (`PROTOCOL_VERSION_AUTHENTICATED = 2`, `PROTOCOL_VERSION_LEGACY = 1`), `read_authenticated_frame` rejects mismatched versions
- [x] Default `require_auth: false` in `SecurityPolicy`, all `AccessPolicy` toggles default true, `RateLimitPolicy` defaults 100 fps / 3000 fpm
- [x] Enabled `pub mod security` in `mvm-runtime/src/lib.rs` (was dead code; trimmed to compilable modules: audit, cgroups, jailer, metadata, seccomp, signing)
- [x] Fixed `generate_keypair()` to use `rand::rngs::OsRng` (was referencing unavailable `aes_gcm::aead::OsRng`)
- [x] Tests (24 new): 8 mvm-core serde/defaults, 10 mvm-guest auth frame roundtrip + tampered rejection + wrong key + replay detection + session mismatch + handshake roundtrip + full exchange, 6 mvm-runtime session key provisioning + loading + error cases

## Phase 7: Command Gating
**Status: COMPLETE**

**Goal:** Host-side blocklist for vsock commands. Matching commands are blocked or held for approval.

- [x] Add `GateDecision`, `ApprovalVerdict`, `BlocklistEntry`, `BlocklistAction`, `BlocklistSeverity` types to `mvm-core/src/security.rs`
- [x] Add `blocklist: Vec<BlocklistEntry>` field to `SecurityPolicy` (`#[serde(default)]` for backward compat)
- [x] Create `mvm-runtime/src/security/command_gate.rs` — `CommandGate` struct with Aho-Corasick literal matching + glob wildcards
- [x] Gate logic: non-match → allow, Block → reject, RequireApproval → hold; `evaluate_dev_mode()` auto-approves with warning
- [x] Default blocklist: 13 entries covering destructive commands, privilege escalation, sensitive file access, VM escape vectors
- [x] Harden builder agent (`mvm-guest/src/bin/mvm-builder-agent.rs`): `validate_flake_ref()` rejects shell metacharacters + path traversal, `validate_build_attr()` requires `packages.` prefix, `load_security_policy()` checks `access.build == false`
- [x] Export `command_gate` from `mvm-runtime/src/security/mod.rs`; add `aho-corasick` workspace dependency
- [x] Tests (29 new): 7 mvm-core gate type serde/defaults, 14 mvm-runtime command gate (glob matching, literal block/approval/log, precedence, dev mode, default blocklist), 8 mvm-guest builder validation (flake_ref safety, attr validation, policy loading)

## Phase 8: Threat Classification + Audit Extension
**Status: COMPLETE**

**Goal:** Classify every vsock message against 10 threat categories using idiomatic Rust (not a wall of regex). Extend audit trail.

- [x] Add `ThreatCategory` (10 variants: SecretExposure, DataExfiltration, Injection, Destructive, PrivilegeEscalation, SupplyChain, SensitiveFileAccess, SystemModification, NetworkAbuse, ToolPoisoning), `Severity` (5 levels with Ord), `ThreatFinding` struct to `mvm-core/src/security.rs`
- [x] Create `mvm-runtime/src/security/threat_classifier.rs` — `ThreatClassifier` struct with three-tier detection:
  - [x] Tier 1: Aho-Corasick multi-pattern matching (70+ literals, single O(n) scan) — credential prefixes (AKIA, ghp_, sk_live_, xoxb-, etc.), destructive commands (rm -rf /, mkfs, dd, DROP TABLE, fork bomb), exfil domains (pastebin, ngrok, transfer.sh, webhook.site), privilege escalation (sudo, nsenter, unshare, capsh), sensitive files (.ssh/id_rsa, .aws/credentials, .kube/config), VM escape (/dev/kvm, release_agent, sysrq-trigger), injection (eval, exec, subprocess), system modification (iptables, sysctl, remount rw)
  - [x] Tier 2: Typed Rust pattern matching (str methods + match arms) — sensitive path analysis (/etc/passwd, /etc/shadow, /proc/self, /sys/fs/cgroup), command structure (12 dangerous binaries with sudo/path stripping), pipe-to-curl/wget exfil, reverse shell via /dev/tcp, PEM private key format, credential assignment, suspicious protocols (gopher://, dict://), setuid/setgid chmod detection (octal mode parsing), Nix patterns (--no-sandbox, --impure, nix-shell --run, remote builders)
  - [x] Tier 3: RegexSet (20 patterns) — AWS access key format, JWT tokens, hex-encoded secrets, base64 decode execution, shell command substitution ($(), backtick), IP:port connections, crontab modification, hex escape obfuscation, Python/Perl reverse shells, env exfiltration, DNS exfiltration, LD_PRELOAD injection, MMDS metadata access, /proc and /sys writes, setcap escalation, unusual port fetches
- [x] MicroVM-specific patterns: /dev/kvm access, cgroup release_agent, cgroupfs mount, sysrq-trigger, prctl(PR_SET_NO_NEW_PRIVS), MMDS 169.254.169.254, Nix sandbox bypass
- [x] Add `regex = "1"` workspace dependency; add `regex.workspace = true` to `mvm-runtime/Cargo.toml`
- [x] Extend `AuditEntry` in `mvm-core/src/audit.rs`: add `threats: Vec<ThreatFinding>`, `gate_decision: Option<GateDecision>`, `frame_sequence: Option<u64>` fields (all `#[serde(default)]` for backward compat)
- [x] Add 9 `AuditAction` variants: `VsockSessionStarted`, `VsockSessionEnded`, `VsockFrameReceived`, `CommandBlocked`, `CommandApproved`, `CommandDenied`, `ThreatDetected`, `RateLimitExceeded`, `SessionRecycled`
- [x] Export `threat_classifier` from `mvm-runtime/src/security/mod.rs`
- [x] Tests (63 new across 3 crates): 4 mvm-core threat type serde/ordering, 4 mvm-core audit backward compat + security fields, 55 mvm-runtime threat classifier (3 benign, 19 literal/Tier 1, 14 structural/Tier 2, 11 regex/Tier 3, 1 multi-category, 3 edge cases + throughput), updated all AuditEntry test constructions

## Phase 9: Rate Limiting (mvm) + Health/Session Deferred to mvmd
**Status: COMPLETE**

**Goal:** Sliding-window rate limiter for vsock frames. Health monitoring and session lifecycle deferred to mvmd (fleet daemon behavior, not dev-tool scope).

- [x] Create `mvm-runtime/src/security/rate_limiter.rs` — `RateLimiter` struct with sliding-window token bucket (1-second and 1-minute windows), `check_and_record()` / `check_and_record_at()` API, `RateLimitResult` enum (Allowed/ExceededPerSecond/ExceededPerMinute), allowed/rejected counters, `reset()`, `is_unlimited()`
- [x] Uses `RateLimitPolicy` from `mvm-core/src/security.rs` (already exists: `frames_per_second`, `frames_per_minute`, defaults 100/3000)
- [x] Export `rate_limiter` from `mvm-runtime/src/security/mod.rs`
- [x] Tests (11 new): within-limits allowed, per-second exceeded, per-minute exceeded, window expiry allows after cooldown, minute window expiry, unlimited mode, per-second checked before per-minute, reset clears state, fps/fpm counters with window rollover, default policy, sustained rate within limit
- **Deferred to mvmd:** `health_monitor.rs` (periodic vsock Ping, kill/restart) and `session_manager.rs` (session lifecycle, auto-recycle) — these are fleet daemon behaviors that require a long-running async runtime watching many VMs. See mvmd specs for implementation plan.

## Phase 10: Security Posture Scoring + Crate Extraction + VmBackend Trait
**Status: COMPLETE**

**Goal:** Multi-layer posture scoring, extract pure-logic security modules into standalone crate, add backend-agnostic VM trait.

### 10a: Extract `mvm-security` Crate
- [x] Create `crates/mvm-security/` with `command_gate`, `threat_classifier`, `rate_limiter` (moved from `mvm-runtime/src/security/`)
- [x] Re-export from `mvm-runtime::security` for backward compatibility (`pub use mvm_security::*`)
- [x] Add `mvm-security` to root facade (`mvm::security`)
- [x] Update `.github/workflows/publish-crates.yml` publish order (core → guest → security → build → runtime → cli)
- [x] Remove `aho-corasick` and `regex` direct deps from mvm-runtime (now transitive via mvm-security)

### 10b: `VmBackend` Trait
- [x] Create `mvm-core/src/vm_backend.rs` — `VmBackend` trait with associated `Config` type, `VmId`, `VmStatus`, `VmCapabilities`, `VmInfo` types
- [x] Create `mvm-runtime/src/vm/backend.rs` — `FirecrackerBackend` implementing `VmBackend`, delegating to existing `microvm::*` and `firecracker::*` functions
- [x] Tests (8 new): 6 mvm-core serde roundtrips + Display + defaults, 2 mvm-runtime backend name + capabilities

### 10c: Security Posture Scoring
- [x] Add `SecurityLayer` enum (12 variants), `PostureCheck`, `PostureReport` types to `mvm-core/src/security.rs`
- [x] Create `mvm-security/src/posture.rs` — `SecurityPosture` struct with `evaluate(checks, timestamp) -> PostureReport`, `uncovered_layers()`, `failed_checks()`, `passed_checks()`, `summary()` utilities
- [x] Re-export `posture` from `mvm-runtime::security`
- [x] Tests (17 new): 4 mvm-core posture type serde (layer count, layer roundtrip, check roundtrip, report roundtrip), 13 mvm-security posture evaluation (all-pass, mixed, all-fail, empty, uncovered layers, failed/passed filters, summary output, timestamp preservation, single check, layer tag coverage, all-covered)

### 10d: CLI — `mvm security status`
- [x] Add `SecurityCmd` subcommand enum with `Status { json: bool }` variant
- [x] Create `mvm-cli/src/security_cmd.rs` — probes 6 security layers (JailerIsolation, SeccompFilter, NetworkIsolation, AuditLogging, VsockAuth, GuestHardening), graceful degradation when Lima not running, text + JSON output
- [x] Add `mvm-security.workspace = true` to mvm-cli dependencies
- [x] Tests (8 new): 2 Clap parsing (subcommand + --json flag), 6 security_cmd unit tests (check construction, no-vm fallback, JSON output, dev default, layer tag + name coverage)

### 10e: Bootstrap Security Hardening
- [x] Update `firecracker::install()` to also install jailer binary from release tarball (same archive already downloaded)
- [x] Update `jailer::JAILER_PATH` to `/usr/local/bin/jailer` to match install location
- [x] Add Step 5 (security baseline) to `run_setup_steps()`: deploys seccomp strict profile, creates audit log directory, reports jailer status
- [x] `setup_security_baseline()` is idempotent — each sub-step checks before acting

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
- Health monitor and session lifecycle deferred to mvmd (see Phase 9)
- `mvm security status` outputs a posture score for the current environment
- All existing tests pass, zero clippy warnings
- New test count: 376 + ~100 security tests (~475 total)
- Documentation reflects install/release workflow and troubleshooting

## Verification

After each phase:
1. `cargo build` — no compile errors
2. `cargo clippy -- -D warnings` — zero warnings
3. `cargo test` — all existing + new tests pass
