# Agent Sandbox Patterns — Research & Implementation Plan

**Date:** 2026-03-23
**Source:** Competitive research across 8 Rust crates in the AI agent sandboxing space

## Context

Surveyed 8 crates (ai-jail, mino, agentkernel, arcbox-vm, wasm-sandbox, sandbox-runtime,
sandbox-rs, agent-sandbox) to identify patterns for hardening mvm as an AI agent execution
platform. Four patterns selected for adoption.

---

## Crate Landscape

| Crate | Isolation | Key Pattern | Lines |
|-------|-----------|-------------|-------|
| **arcbox-vm** | Firecracker microVM | Three-tier isolation, Docker API compat, sub-50ms snapshot restore | 4.2k |
| **agentkernel** | OCI container | MITM proxy secret injection ("Gondolin"), LLM cost tracking, HTTP API | 44k |
| **mino** | Podman container | Temp cloud creds, iptables egress filtering, lockfile-keyed caching | 15k |
| **ai-jail** | Process (bwrap/seatbelt) | Seccomp + Landlock + dotfile layering, lockdown mode | 6k |
| **sandbox-runtime** | Process (bwrap/seatbelt) | Domain allowlist proxy (HTTP + SOCKS5), Anthropic-derived | 3.6k |
| **sandbox-rs** | Process (namespaces) | 6-tier cumulative seccomp hierarchy, `seccompiler` crate | 5.3k |
| **agent-sandbox** | WASM | FS snapshot/diff, SSRF prevention, 80+ emulated CLI tools | 970 |
| **wasm-sandbox** | WASM | Capability-based security, Wasmtime/Wasmer abstraction | 11.8k |

mvm's differentiator: **hardware-isolated full Linux** (KVM boundary) with **Nix-based reproducible builds**.

---

## Pattern 1: Domain-Based Network Allowlists

**Priority: 1 (highest)**
**Effort: Medium (~300-500 lines)**
**No guest changes needed**

### Design

iptables rules on the Lima VM's FORWARD chain constrain microVM egress by resolved domain:port.

**Implementation** (mino's approach):
1. After TAP creation in `network.rs`, apply `iptables -P FORWARD DROP` for microVM traffic
2. Allow ESTABLISHED/RELATED and DNS (udp/tcp 53)
3. For each allowed `host:port`, resolve and `iptables -A FORWARD -d <ip> -p tcp --dport <port> -j ACCEPT`
4. Built-in presets:
   - `dev`: github.com:443, api.github.com:443, registry.npmjs.org:443, crates.io:443, static.crates.io:443, index.crates.io:443, pypi.org:443, files.pythonhosted.org:443, api.anthropic.com:443, api.openai.com:443
   - `registries`: npm, crates.io, pypi only
   - `none`: no outbound (FORWARD DROP, no exceptions beyond DNS)
   - `unrestricted`: no filtering (current default, backward compat)

### Files

- `mvm-core/src/network_policy.rs` (new) — `NetworkPolicy` enum, `HostPort`, presets
- `mvm-runtime/src/vm/network.rs` — `apply_network_policy(slot, policy)` after TAP creation
- `mvm-cli/src/commands.rs` — `--network-allow`, `--network-preset` flags
- `mvm-core/src/template.rs` — `network_policy` field

### Config

```bash
mvmctl run --flake . --network-preset dev
mvmctl run --flake . --network-allow github.com:443,api.openai.com:443
mvmctl template create base --network-preset dev
```

---

## Pattern 2: Tiered Seccomp Profiles

**Priority: 2**
**Effort: Medium (~400-600 lines)**
**Completes mvm-security defense-in-depth story**

### Design

5 cumulative tiers (adapted from sandbox-rs), using `seccompiler` crate (from Firecracker project):

| Tier | Name | ~Syscalls | Use Case |
|------|------|-----------|----------|
| 1 | Essential | 40 | Process bootstrap only |
| 2 | Minimal | 110 | + signals, pipes, timers, process control |
| 3 | Standard | 140 | + file ops (default for most workloads) |
| 4 | Network | 160 | + sockets (needed for networked agents) |
| 5 | Unrestricted | all | Dev/debug, no restrictions |

Named bundles combine seccomp + resource limits:
- **Strict**: Minimal seccomp, 128MB mem, 50% CPU
- **Moderate**: Standard seccomp, 512MB mem, 75% CPU
- **Permissive**: Unrestricted seccomp, 2GB mem, 90% CPU

### Application paths

1. **Guest-side** (v1): Ship BPF filter in config drive, guest init loads via `prctl(PR_SET_SECCOMP)`
2. **Jailer mode** (future): Firecracker's jailer applies filter to VMM process

### Files

- `mvm-security/src/seccomp.rs` (new) — tier definitions, BPF compilation
- `mvm-security/Cargo.toml` — add `seccompiler` dependency
- `mvm-security/src/lib.rs` — re-export
- `mvm-cli/src/commands.rs` — `--seccomp-profile` flag

---

## Pattern 3: Filesystem Diff Tracking

**Priority: 3**
**Effort: Low-Medium (~200-400 lines)**
**Builds on existing squashfs/overlay infrastructure**

### Design

Use read-only rootfs + overlay (already supported by mkGuest `readOnlyRoot = true`).
All agent writes go to overlay. After VM stop, inspect the overlay for changes.

**Two collection methods:**
1. **Guest-side** (preferred): `fs-diff` vsock command in guest agent walks overlay, returns JSON
2. **Post-mortem**: Mount overlay image in Lima after VM shutdown, walk it

### Output format

```json
[
  {"path": "/app/output.txt", "kind": "created", "size": 1234},
  {"path": "/etc/hosts", "kind": "modified", "size": 89},
  {"path": "/tmp/scratch", "kind": "deleted", "size": 0}
]
```

### Files

- `mvm-runtime/src/vm/fs_diff.rs` (new) — overlay inspection, diff manifest
- `mvm-guest/src/vsock.rs` — `fs-diff` command handler
- `mvm-cli/src/commands.rs` — `mvmctl diff <instance>` subcommand

---

## Pattern 4: Network-Layer Secret Injection

**Priority: 4 (highest long-term value, highest effort)**
**Effort: High (~800-1200 lines)**
**Recommend as dedicated sprint**

### Design

MITM HTTPS proxy (agentkernel's "Gondolin" pattern) running inside Lima VM:

1. Proxy generates a CA, injects CA PEM into guest trust store at boot
2. Guest sets `HTTP_PROXY`/`HTTPS_PROXY` env vars pointing to proxy
3. On HTTPS CONNECT: proxy generates per-host TLS cert → MITM bridge
4. Injects secret headers (e.g., `Authorization: Bearer <key>`) only for bound domains
5. Non-bound hosts get plain TCP passthrough (no MITM overhead)
6. Guest env vars set to `mvm-proxy-managed` so agent tools pass existence checks
7. Audit log for every proxied request

### Secret binding syntax

```toml
[secrets]
OPENAI_API_KEY = { host = "api.openai.com" }
ANTHROPIC_API_KEY = { host = "api.anthropic.com", header = "x-api-key" }
GITHUB_TOKEN = { host = "api.github.com", value = "ghp_..." }
```

### Dependencies

- `hyper` (HTTP server/client)
- `tokio-rustls` (async TLS)
- `rcgen` (dynamic cert generation)
- `rustls` (TLS implementation)

### Files

- `mvm-runtime/src/vm/secret_proxy.rs` (new) — proxy implementation
- `mvm-core/src/secret_binding.rs` (new) — binding types, config parsing
- `mvm-runtime/src/vm/microvm.rs` — proxy lifecycle (start before VM, stop after)
- `mvm-core/src/template.rs` — secret bindings in template config

---

## Implementation Order

| Phase | Pattern | Sprint |
|-------|---------|--------|
| 1 | Domain network allowlists | Sprint 39 |
| 2 | Tiered seccomp profiles | Sprint 39 |
| 3 | Filesystem diff tracking | Sprint 40 |
| 4 | Network secret injection | Sprint 40 or 41 |

Patterns 1-2 can be done in one sprint. Patterns 3-4 are independent and can be parallelized or sequenced.

## Verification

For each pattern:
- `cargo test --workspace` — all tests pass
- `cargo clippy --workspace -- -D warnings` — zero warnings
- Integration test: boot a microVM with the feature enabled, verify behavior
