# Research: Safely Providing OpenClaw in mvm

## Context

The goal is to understand how to securely provide OpenClaw — the AI agent framework — within mvm's Firecracker microVM environment. This document synthesizes findings from three research sources to identify security patterns, gaps, and a path forward.

**Status**: Research phase. Waiting for a third resource from the user before finalizing an implementation plan.

---

## Source 1: The OpenClaw Field Manual (PDF, 90 pages)

The Field Manual is the community guide (v1.0, Feb 2026) for running OpenClaw — a Node.js AI agent platform that uses Claude API, with a gateway process, MCP servers, channels (WhatsApp, Discord, Google), cron jobs, heartbeats, and a memory system.

### Security-Relevant Patterns Extracted

**1. Deny-by-default execution policy** (AGENTS.md `execPolicy`)
- Whitelist of allowed commands, everything else blocked
- Pattern: `{ "allow": ["git *", "npm test"], "deny": ["rm -rf *", "sudo *"], "requireApproval": ["npm publish", "git push"] }`
- Three tiers: allow silently, deny silently, require human approval

**2. Autonomous execution tiers** (escalation ladder)
- Tier 1: Interactive — human approves every action
- Tier 2: Delegated — pre-approved action set, human escalation for unknowns
- Tier 3: Fully autonomous — all pre-approved, error-triggered escalation only
- Recommendation: start Tier 1, promote to Tier 2 after trust established

**3. Agent drift prevention**
- Hard reset every 50 tasks (kill session, start fresh)
- Session state checkpointing before reset
- SOUL.md as immutable behavioral anchor (re-read on every boot)

**4. Network hardening**
- Gateway binds to loopback only (127.0.0.1), never 0.0.0.0
- Token auth required for all API access
- Tailscale for remote access (never expose gateway publicly)
- UFW deny all inbound except Tailscale

**5. File permission lockdown**
- `chmod 444` for SOUL.md, AGENTS.md (immutable behavioral rules)
- `chmod 644` for USER.md, TOOLS.md (read by agent, edited by human)
- `chmod 600` for .env (secrets)
- `chmod 700` for memory/ directory

**6. Watchdog / health monitoring**
- Systemd timer checks gateway health every 5 minutes
- Auto-restart on failure (RestartSec=10, Restart=always)
- Health endpoint: `curl http://127.0.0.1:19847/health`

**7. Systemd service hardening**
- `NoNewPrivileges=true`
- `ProtectHome=read-only`
- `ReadWritePaths` limited to workspace only
- Separate error log file

**8. Memory system security**
- Two-layer: ephemeral daily logs + durable MEMORY.md
- memoryFlush extracts before compaction (prevents knowledge loss)
- Error logging protocol with structured format
- Memory search uses embeddings (requires API key)

**9. 8 Silent Failures** (things that break without alerting)
1. WhatsApp reconnect loops
2. Cron delivery failures (missing deliverTo)
3. Heartbeat token accumulation
4. Memory search 401s (missing embedding API key)
5. Agent drift (personality shift over long sessions)
6. Exec registry loss (after compaction, agent forgets what's allowed)
7. Ghost .tmp files blocking gateway
8. Queue blocking (long task blocks all other messages)

### Key Takeaway for mvm
The Field Manual treats the agent as **adversarial-by-default** — it will drift, forget rules, accumulate costs, and silently fail. Every safety mechanism is designed around the assumption that the agent cannot be trusted to self-regulate over time. This philosophy maps directly to how we should treat guest workloads in Firecracker microVMs.

---

## Source 2: SafeClaw (github.com/DinoMorphica/safeclaw)

SafeClaw is an open-source TypeScript security dashboard (MIT license) that sits between an AI agent and the host OS. It intercepts, monitors, and controls what the agent can do.

### Architecture

```
User prompt → OpenClaw Agent → SafeClaw → OS / Network / MCP
                                   │
                         Dashboard (localhost:54335)
                                   │
                         SQLite (~/.safeclaw/safeclaw.db)
```

**Two ingestion paths:**
1. **WebSocket client** → OpenClaw gateway (port 18789) — real-time events via Ed25519-authenticated binary protocol
2. **SessionWatcher** → JSONL session files on disk — file-based activity monitoring

### 5 Independent Security Subsystems

**1. Threat Analysis Engine (passive, informational)**
- 10 TC-* categories, 200+ regex patterns, 17 credential-type secret scanner
- Categories: TC-SEC (secrets), TC-EXF (exfiltration), TC-INJ (prompt injection), TC-DES (destructive ops), TC-ESC (privilege escalation), TC-SUP (supply chain), TC-SFA (sensitive file access), TC-SYS (system modification), TC-NET (network), TC-MCP (tool poisoning)
- Severity levels: NONE, LOW, MEDIUM, HIGH, CRITICAL
- OWASP LLM Top 10 references on every finding
- Does NOT block — purely informational for dashboard display

**2. Exec Approval System (active enforcement)**
- Blocklist model: restricted patterns → commands matching are held for approval
- Gateway sends `exec.approval.requested` event
- Non-matching commands: auto-approved immediately
- Matching commands: queued as pending, 10-minute timeout, then auto-deny
- User decisions: Allow Once, Allow Always (removes pattern), Deny

**3. Access Control Toggles (tool group blocks)**
- 4 toggle dimensions: filesystem, system_commands, network, mcp_servers
- Mutates OpenClaw's `tools.deny` config and plugin enable/disable

**4. Skill Scanner (static pre-execution)**
- 15 SK-* categories for analyzing markdown skill definitions before use
- Detects: hidden content, prompt injection, shell exec, data exfil, embedded secrets, memory/config poisoning, supply chain, encoded payloads, image exfil, system prompt extraction, argument injection, cross-tool chaining, excessive permissions, suspicious structure

**5. Security Posture (cross-layer health score)**
- 12 security layers, 40+ checks
- Layers: sandbox, filesystem, network, egress-proxy, exec, mcp, gateway, secrets, supply-chain, input-output, monitoring, human-in-loop
- Score: `passed_checks / total_checks * 100`

### Gateway Protocol (OpenClawClient)
- WebSocket to `ws://127.0.0.1:{port}` (default 18789)
- **Ed25519 device authentication**: reads keypair from `~/.openclaw/identity/device.json`, signs challenge payload, gateway verifies
- Connect handshake: `connect.challenge` → client signs → `connect` request → `hello-ok`
- Event streams: `agent` (tool calls), `chat` (messages), `lifecycle` (session start/end), `exec.approval.requested`, `tick` (keepalive)
- Reconnect: exponential backoff (2s base, 1.5x, max 30s, 20 attempts)

### Key Takeaway for mvm
SafeClaw provides a concrete, working implementation of the "external observer" pattern with 5 security subsystems. The most directly applicable patterns for mvm are:
- **Threat classification on vsock traffic** — adapt the 10 TC-* categories to classify guest agent commands
- **Exec approval flow** — blocklist + human-in-the-loop approval maps to host-side vsock command gating
- **Security posture scoring** — multi-layer health check model applies to VM security configuration
- **Ed25519 gateway auth** — mvm already has Ed25519 signing infrastructure, same pattern for vsock auth

---

## Source 3: Current mvm OpenClaw Implementation (Codebase Exploration)

### What Exists Today

**Guest agent system** (mvm-guest crate):
- Vsock protocol on port 52 (guest control): GuestRequest/GuestResponse
- Port 53 (host-bound): HostBoundRequest/Response
- Port 21470 (builder agent): accepts `nix build` commands
- 4-byte BE length prefix + JSON, 256 KiB max frame, 10s timeout

**Nix guest images** (nix/openclaw/):
- `flake.nix` builds tenant-gateway and tenant-worker NixOS images
- `guests/baseline.nix` — hardened guest OS: no SSH, no sudo, serial console only
- Drive mounts: config (ro), secrets (ro, noexec), data (rw, noexec)
- nftables firewall: deny lateral movement, IP/MAC binding

**Host-side security** (mvm-runtime/src/security/):
- Jailer: chroot + uid/gid isolation per VM
- Cgroups v2: CPU/memory/IO limits
- Seccomp: syscall filtering
- Encryption: LUKS for drives, AES-GCM for snapshots, Ed25519 signing
- mTLS cert generation
- Audit logging

### Critical Security Gaps

| Gap | Risk | Field Manual Analog |
|-----|------|-------------------|
| **No auth on vsock protocol** | Any process in guest can send control commands | Token auth on gateway API |
| **No TLS on vsock** | Traffic visible to anyone who can attach to vsock | Loopback + token pattern |
| **Builder agent accepts arbitrary nix build** | Code execution without approval | Deny-by-default exec policy |
| **No rate limiting on guest agent** | DoS from guest side | Heartbeat interval controls |
| **No request signing** | Cannot verify request origin | Ed25519 signing exists but unused on vsock |
| **No health monitoring of guest** | Silent failures go undetected | Watchdog timer pattern |
| **No drift detection** | Long-running agents may behave unexpectedly | Hard reset every N tasks |
| **No exec policy enforcement** | Guest can run anything the agent allows | AGENTS.md execPolicy |

---

## Synthesis: Security Patterns That Apply to mvm

### Pattern 1: Authenticated Vsock Protocol
- **From**: Field Manual's token auth + mvm's existing Ed25519 signing
- **Apply**: Add HMAC or Ed25519 signature to every vsock frame. Host generates a per-session secret at VM boot, passes it via the secrets drive (already mounted ro, noexec). Guest agent must sign every request.

### Pattern 2: Command Allow-listing (Exec Policy)
- **From**: Field Manual's deny-by-default execPolicy
- **Apply**: Builder agent should have a fixed whitelist of allowed Nix operations. The host-side vsock handler should validate and reject unrecognized commands before they reach the guest.

### Pattern 3: External Health Monitoring (SafeClaw Pattern)
- **From**: SafeClaw's external observer + Field Manual's watchdog timer
- **Apply**: Host-side periodic health checks via vsock Ping. If guest doesn't respond within timeout, host can kill/restart the VM. This is already partially implemented (Ping exists in the protocol) but needs enforcement.

### Pattern 4: Session Lifecycle Management
- **From**: Field Manual's hard reset every 50 tasks + drift prevention
- **Apply**: VMs should have configurable max-lifetime / max-task-count. After threshold, host tears down and recreates the VM from clean image. Firecracker's fast boot (~125ms) makes this practical.

### Pattern 5: Rate Limiting & Frame Budgets
- **From**: Field Manual's token cost controls + heartbeat frequency limits
- **Apply**: Host-side vsock handler should enforce per-second frame rate and per-minute request budget. Prevents guest from flooding the host.

### Pattern 6: Audit Trail
- **From**: Field Manual's error-log.md + structured logging
- **Apply**: Every vsock message should be logged with timestamp, direction, request type. mvm already has audit.rs — extend it to cover vsock traffic.

### Pattern 7: Immutable Configuration
- **From**: Field Manual's chmod 444 for SOUL.md/AGENTS.md
- **Apply**: Guest config drive is already mounted read-only. Ensure the agent's behavioral rules, allowed commands, and security policy are on the config drive (not data drive) so the guest cannot modify them.

---

## Open Questions (Awaiting Third Resource)

1. **What monitoring capabilities does SafeClaw actually provide?** The public info is thin. The third resource may fill this gap.
2. **Should mvm embed a SafeClaw-compatible monitoring protocol?** If SafeClaw has an API/webhook format, mvm could emit compatible events.
3. **What scope of changes does the user want?** This research identifies 8 gaps and 7 patterns. Are we implementing all of them, or starting with a focused subset?
4. **Does the user want changes in mvm (the dev tool) or mvmd (the fleet orchestrator)?** Most of these security patterns matter more in multi-tenant fleet mode. For dev mode (single VM, local), the threat model is different.

---

## Recommended Next Steps

1. **Wait for third resource** — may provide SafeClaw technical details or additional security patterns
2. **Scope the work** — after all resources reviewed, identify which gaps to address first
3. **Prioritize by threat model**:
   - For dev mode (mvm): builder agent auth + health monitoring are highest priority
   - For fleet mode (mvmd): all 7 patterns apply, vsock auth is critical
4. **Design implementation spec** — once scope is agreed, create a sprint plan

---

*Research complete for sources 1 and 2. Awaiting third resource.*
