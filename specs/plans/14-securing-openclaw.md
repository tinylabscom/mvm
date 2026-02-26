# Securing OpenClaw in mvm

## Context

OpenClaw runs AI agents inside Firecracker microVMs managed by mvm. The current vsock protocol between host and guest has no authentication, no command validation, no threat detection, and no health monitoring. Research from the OpenClaw Field Manual and SafeClaw's open-source security dashboard identified 10 security patterns to close these gaps.

SafeClaw and the Field Manual are **reference material only** — no integration with SafeClaw. All security improvements are native Rust, implemented in mvm's existing crate structure.

**Scope:** All 5 phases. Type and protocol changes in mvm (mvm-core, mvm-guest). Runtime security modules in mvm-runtime (reusable by mvmd as a dependency). mvmd-specific integration (QUIC approval flow, fleet-wide session management) is a follow-up after the mvm-side work lands.

**Research:** See [specs/research/openclaw-security.md](../research/openclaw-security.md) for the full analysis of the OpenClaw Field Manual, SafeClaw codebase, and current mvm security gaps.

---

## Existing Infrastructure to Reuse

| What | Where | Used In |
|------|-------|---------|
| Ed25519 signing/verification | `crates/mvm-runtime/src/security/signing.rs` | Phase 1 (vsock auth) |
| `SignedPayload` type | `crates/mvm-core/src/signing.rs` | Phase 1 (frame envelope) |
| Audit log (append-only JSON, rotation) | `crates/mvm-runtime/src/security/audit.rs` | Phase 3 (extend) |
| `AuditAction` + `AuditEntry` types | `crates/mvm-core/src/audit.rs` | Phase 3 (add variants) |
| Secrets drive (ro, noexec) | `nix/openclaw/guests/baseline.nix` | Phase 1 (session keys) |
| Config drive (ro) | `nix/openclaw/guests/baseline.nix` | Phase 5 (immutable policy) |
| Jailer, cgroups, seccomp | `crates/mvm-runtime/src/security/` | Phase 5 (posture checks) |
| Vsock protocol (`read_frame`/`write_frame`) | `crates/mvm-guest/src/vsock.rs` | Phase 1 (wrap with auth) |

---

## Phase 1: Authenticated Vsock Protocol (Foundation)

**Goal:** Ed25519-signed vsock frames with per-session keys provisioned via the secrets drive.

**New types in `mvm-core/src/security.rs`:**
- `AuthenticatedFrame` — versioned envelope: `{ version, session_id, sequence, timestamp, signed: SignedPayload }`
- `SessionHello` / `SessionHelloAck` — challenge-response handshake
- `SecurityPolicy` — per-VM security config (require_auth, access policy, blocklist, rate limits, session limits)
- `AccessPolicy` — toggles for filesystem, network, build, host_communication
- `RateLimitPolicy` — frames_per_second, frames_per_minute

**Wire format:** After existing `CONNECT/OK` handshake, add `SessionHello`->`SessionHelloAck` exchange. Then all frames become `[4-byte BE length][AuthenticatedFrame JSON]` where `signed.payload` is the original `GuestRequest`/`GuestResponse` JSON.

**Key provisioning:** Host writes per-session Ed25519 keypair to secrets drive before VM boot:
- `/mnt/secrets/vsock/session_key.pem` (guest signing key)
- `/mnt/secrets/vsock/host_pubkey.pem` (host public key for verification)

**Backward compatibility:** Version negotiation in the first frame. If guest responds `version: 1`, fall back to unauthenticated mode + log warning. Default `require_auth: false` initially, opt-in via `--require-vsock-auth`.

**Files:**
- NEW: `crates/mvm-core/src/security.rs`
- MODIFY: `crates/mvm-core/src/lib.rs` (add `pub mod security`)
- MODIFY: `crates/mvm-guest/src/vsock.rs` (authenticated wrappers)
- MODIFY: `crates/mvm-guest/Cargo.toml` (add `ed25519-dalek`)
- MODIFY: `crates/mvm-runtime/src/security/signing.rs` (session key generation)

**Tests:** Frame signing roundtrip, serde roundtrip, challenge-response handshake via mock UnixStream, tampered frame rejection, replay detection via sequence numbers.

---

## Phase 2: Command Gating (Exec Approval)

**Goal:** Host-side blocklist for vsock commands. Commands matching restricted patterns are held for approval or auto-denied.

**New types in `mvm-core/src/security.rs`:**
- `GateDecision` — Allow / Blocked { pattern, reason } / RequiresApproval { reason }
- `ApprovalVerdict` — Approved / Denied { reason } / Timeout
- `BlocklistEntry` — pattern (literal or glob), category, severity, action (Block/RequireApproval/Log)

**New module `mvm-runtime/src/security/command_gate.rs`:**
- Receives vsock frames, extracts command text
- Matches against blocklist using Aho-Corasick (literals) + glob matching (wildcards like `rm -rf *`)
- Non-match: allow. Match with Block action: reject immediately. Match with RequireApproval: hold up to 10 min
- Dev mode (mvm): auto-approve with warning. Fleet mode (mvmd): coordinator provides verdict via QUIC
- Every decision logged to audit trail

**Builder agent hardening (`mvm-guest/src/bin/mvm-builder-agent.rs`):**
- Validate `flake_ref` against allowed list from config drive
- Validate `attr` against allow-pattern (e.g., must start with `packages.`)
- Reject when `access.build == false`

**Files:**
- NEW: `crates/mvm-runtime/src/security/command_gate.rs`
- MODIFY: `crates/mvm-runtime/src/security/mod.rs`
- MODIFY: `crates/mvm-core/src/security.rs` (gate types)
- MODIFY: `crates/mvm-guest/src/bin/mvm-builder-agent.rs` (validation)

**Tests:** Blocklist matching, gate decision logic, builder flake_ref validation, blocked command returns error via vsock.

---

## Phase 3: Threat Classification + Audit Extension

**Goal:** Classify every vsock message against 10 threat categories. Extend audit trail with threat metadata. Use idiomatic Rust instead of a wall of regex.

**New types in `mvm-core/src/security.rs`:**
- `ThreatCategory` enum — SecretExposure, DataExfiltration, Injection, Destructive, PrivilegeEscalation, SupplyChain, SensitiveFileAccess, SystemModification, NetworkAbuse, ToolPoisoning
- `ThreatFinding` — category, pattern_id, severity, matched_text, context
- `Severity` enum — Critical, High, Medium, Low, Info

**New module `mvm-runtime/src/security/threat_classifier.rs`:**

Three-tier detection approach (minimize regex, maximize performance):

**Tier 1: Aho-Corasick multi-pattern matching** (`aho-corasick` crate)
- Single-pass scan for all literal keyword/prefix patterns
- Credential prefixes: `AKIA`, `ghp_`, `gho_`, `glpat-`, `sk_live_`, `sk_test_`, `SG.`, `xoxb-`, `xoxp-`
- Destructive commands: `rm -rf /`, `mkfs`, `dd if=/dev/zero`, `DROP TABLE`, `TRUNCATE`
- Exfiltration domains: `pastebin.com`, `transfer.sh`, `ngrok.io`, `webhook.site`
- Privilege escalation: `sudo`, `nsenter`, `unshare`, `chroot`
- System paths: `/etc/passwd`, `/etc/shadow`, `.ssh/id_rsa`, `.aws/credentials`
- Firecracker-specific: `/dev/kvm`, `release_agent`, `cgroupfs`
- ~200 literals, single Aho-Corasick automaton, O(n) scan

**Tier 2: Typed Rust pattern matching** (no regex, just `str` methods + match arms)
- Path analysis: `starts_with("/etc/")`, `starts_with("/usr/bin/")`, `contains(".ssh/")`
- Command structure: split on whitespace, match first token against known-dangerous binaries
- Credential format: `starts_with("-----BEGIN")` + `contains("PRIVATE KEY")`
- Network patterns: `contains("://")` + parse scheme for suspicious protocols
- Permission patterns: numeric mode parsing for setuid detection (`chmod 4xxx`)
- Nix-specific: validate flake ref format, detect `--impure`, `--no-sandbox`

**Tier 3: Regex only for genuinely complex patterns** (~20-30 regexes via `regex::RegexSet`)
- AWS access key format: `AKIA[0-9A-Z]{16}`
- JWT tokens: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Base64 payloads: detect `atob()`, `Buffer.from(*, 'base64')`
- Obfuscation: `String.fromCharCode`, hex escape sequences
- Shell injection: `$()`, backtick substitution in arguments

**MicroVM-specific patterns (not in SafeClaw):**
- Firecracker escape: `/dev/kvm` access, jailer breakout (`nsenter`, `unshare -m`)
- Nix sandbox breakout: `nix-shell --run`, `--no-sandbox`, unrestricted builders
- Cgroup escape: `release_agent` writes, `cgroupfs` mount attempts
- Seccomp bypass: `prctl(PR_SET_NO_NEW_PRIVS)`, `ptrace` attachment
- Vsock abuse: port scanning, excessive connection attempts

**Design:**
```rust
pub struct ThreatClassifier {
    aho: AhoCorasick,                    // Tier 1: literal patterns
    aho_map: Vec<(ThreatCategory, Severity, &'static str)>,  // pattern_id for each match
    regexes: RegexSet,                   // Tier 3: complex patterns
    regex_map: Vec<(ThreatCategory, Severity, &'static str)>,
}

impl ThreatClassifier {
    pub fn new() -> Self { /* compile once */ }
    pub fn classify(&self, text: &str) -> Vec<ThreatFinding> {
        let mut findings = Vec::new();
        self.classify_literals(text, &mut findings);   // Tier 1
        self.classify_structural(text, &mut findings);  // Tier 2
        self.classify_regex(text, &mut findings);       // Tier 3
        findings
    }
}
```

**Extend `mvm-core/src/audit.rs`:**
- Add `threats: Vec<ThreatFinding>`, `gate_decision: Option<GateDecision>`, `frame_sequence: Option<u64>` to `AuditEntry` (with `#[serde(default)]` for backward compat)
- Add `AuditAction` variants: `VsockSessionStarted`, `VsockSessionEnded`, `VsockFrameReceived`, `CommandBlocked`, `CommandApproved`, `CommandDenied`, `ThreatDetected`, `RateLimitExceeded`, `SessionRecycled`

**Files:**
- NEW: `crates/mvm-runtime/src/security/threat_classifier.rs`
- MODIFY: `crates/mvm-runtime/Cargo.toml` (add `aho-corasick`)
- MODIFY: `crates/mvm-core/src/security.rs` (threat types)
- MODIFY: `crates/mvm-core/src/audit.rs` (extend AuditEntry + new actions)
- MODIFY: `crates/mvm-runtime/src/security/audit.rs` (emit extended events)

**Tests:** Known-bad pattern classification per category, benign message produces no findings, AuditEntry backward compat, performance benchmark (<10ms for 1000 frames — Aho-Corasick is O(n)).

---

## Phase 4: Health Monitoring + Session Lifecycle + Rate Limiting

**Goal:** Host-side periodic vsock Ping with kill/restart on timeout. VM session recycling. Frame rate limiting.

**New modules in `mvm-runtime/src/security/`:**

`health_monitor.rs`:
- Periodic Ping via vsock, configurable interval
- Consecutive failure tracking per-instance
- Kill + restart after N consecutive failures
- Audit logging of health events

`session_manager.rs`:
- Track per-VM session state (started_at, tasks_completed, frames_sent/received)
- Recycle when `max_lifetime_secs` or `max_tasks` exceeded
- Graceful drain (SleepPrep) then restart from clean image

`rate_limiter.rs`:
- Sliding window token bucket per-instance
- Configurable frames_per_second and frames_per_minute
- Exceeded frames are dropped + audit event (soft defense, no VM kill)

**Files:**
- NEW: `crates/mvm-runtime/src/security/health_monitor.rs`
- NEW: `crates/mvm-runtime/src/security/session_manager.rs`
- NEW: `crates/mvm-runtime/src/security/rate_limiter.rs`
- MODIFY: `crates/mvm-runtime/src/security/mod.rs`
- MODIFY: `crates/mvm-core/src/security.rs` (session + rate limit types)

**Tests:** Rate limiter allows/blocks correctly, session expiry triggers recycle, 3 consecutive ping failures triggers kill.

---

## Phase 5: Security Posture Scoring + Immutable Config

**Goal:** Multi-layer health scoring for VM security configuration. Config drive integrity verification.

**New module `mvm-runtime/src/security/posture.rs`:**
- 12 security layers: JailerIsolation, CgroupLimits, SeccompFilter, NetworkIsolation, VsockAuth, EncryptionAtRest, EncryptionInTransit, AuditLogging, SecretManagement, ConfigImmutability, GuestHardening, SupplyChainIntegrity
- Each layer has multiple checks -> `PostureCheck { name, score, status, detail }`
- Overall score = `passed_checks / total_checks * 100`

**Config drive integrity:**
- Compute SHA-256 hash of config drive at boot
- Periodic re-check that hash hasn't changed (tampering detection)
- `SecurityPolicy` lives on config drive, making it immutable post-boot

**CLI integration:** `mvm security status` or extend `mvm doctor --security`

**Files:**
- NEW: `crates/mvm-runtime/src/security/posture.rs`
- MODIFY: `crates/mvm-cli/src/commands.rs` (security status command)
- MODIFY: `crates/mvm-core/src/security.rs` (posture types)

**Tests:** Posture check scoring, overall calculation, config hash computation.

---

## Sprint Mapping

| Sprint | Phase | Key Deliverable |
|--------|-------|-----------------|
| S1 | Phase 1 | Authenticated vsock protocol + key provisioning |
| S2 | Phase 2 | Command gating + builder agent hardening |
| S3 | Phase 3 | Threat classification (250+ patterns) + extended audit trail |
| S4 | Phase 4 | Health monitor + session lifecycle + rate limiting |
| S5 | Phase 5 | Security posture scoring + config immutability + CLI |

Phases 1-3 are the critical path. Phases 4-5 can be parallelized.

## Migration Path

1. Phase 1 ships with `require_auth: false` default — existing guest images work unchanged
2. Opt-in via `--require-vsock-auth` flag on `mvm start`/`mvm run`
3. Version negotiation in handshake ensures mixed-version environments degrade gracefully
4. Once new guest images are deployed, flip default to `require_auth: true`

## Verification

After each phase:
1. `cargo build` — no compile errors
2. `cargo clippy -- -D warnings` — zero warnings
3. `cargo test` — all existing + new tests pass
4. Phase 1: mock vsock test with authenticated frame exchange
5. Phase 2: blocked command returns error, allowed command passes
6. Phase 3: known-bad payload produces correct ThreatFindings
7. Phase 5: `mvm security status` outputs posture report

## mvmd Impact

All work happens in the mvm repo first. mvmd consumes mvm-core and mvm-guest as dependencies, so type and protocol changes propagate automatically. The runtime security modules (threat classifier, rate limiter, posture checks) live in mvm-runtime and can be consumed by mvmd-runtime as a crate dependency — no code duplication.

mvmd-specific follow-up work (separate from this plan):
- Phase 2: coordinator provides approve/deny verdicts via QUIC
- Phase 4: health monitor + session manager run as tokio background tasks across the fleet
