---
title: "ADR-003: local Model Context Protocol server (`mvmctl mcp`)"
status: Proposed
date: 2026-04-30
related: ADR-002 (microVM security posture); plan 32 (MCP + LLM-agent adoption); plan 33 (hosted MCP transport — mvmd cross-repo)
---

## Status

Proposed. Implementation tracked in `specs/plans/32-mcp-agent-adoption.md`
Proposal A. Composes with ADR-002 — does not introduce new attacker
surfaces, only a new dispatch path on top of the existing
`mvmctl exec` machinery.

## Context

LLM clients (Claude Code, opencode, Codex, etc.) speak Model Context
Protocol over stdio. Each client expects a server that announces
itself via `initialize`, lists its tools via `tools/list`, and
dispatches via `tools/call`. Today, mvmctl is invokable only via
shell; an LLM driving it has to spawn a subprocess per call, parse
free-form output, and lose the protocol's structured affordances
(content blocks, error semantics, capability negotiation).

`mvmctl mcp` adds the MCP transport. It exposes mvm's microVM
template registry as a single parameterized `run` tool — borrowing
nix-sandbox-mcp's design insight that one tool with an `env`
parameter keeps the LLM context-window cost flat (~420 tokens)
regardless of how many envs the user has built. nix-sandbox-mcp's
own roadmap explicitly lists "microvm.nix backend" as future work
because microVMs are "the right choice for running untrusted code
from the internet"; mvm already has that backend. The combination
— mvm's isolation strength with nix-sandbox-mcp's tool-design
ergonomics — is the point.

## Threat model (additive over ADR-002)

The MCP server is a host-local stdio process spawned by the user's
LLM client. There is **no new attacker** beyond ADR-002:

1. The transport is `stdin`/`stdout` of the same user's shell
   environment. No network listener.
2. The `env` parameter is allowlisted against the existing
   `mvmctl template list`. An unknown name returns a structured
   MCP error listing valid envs; no shell interpolation, no
   arbitrary path access.
3. The `code` parameter is passed as a single argv element (via
   `bash -c <quoted>`) to the guest interpreter inside the
   already-isolated microVM. The microVM is the security boundary;
   `code` cannot escape.
4. The dispatch chain goes through `crate::exec::run_captured` →
   guest agent's `Exec` over vsock. ADR-002 §W4.3's
   `prod-agent-no-exec` CI gate ensures production guest agents
   are built without `dev-shell`, so the `Exec` handler is
   physically absent from the binary; production workloads return
   "exec not available" gracefully. **No new feature gate is
   needed at the CLI level** — the existing chain is the gate.

Surfaces specific to this ADR:

| Surface | Today | Hardened |
|---|---|---|
| MCP transport | stdio only | Stdio only; hosted HTTP/SSE deferred to mvmd per plan 33 |
| `tools/call run` env validation | n/a | Allowlist match against `template_list()`; structured error on miss |
| `tools/call run` code injection | n/a | `bash -c` argv (single quoted) — no shell expansion possible |
| Output capture | n/a | stdout/stderr capped at 64 KiB each; truncation reported via `[truncated, N more bytes]` marker |
| Concurrency | n/a | `MVM_MCP_MAX_INFLIGHT` (default 4); over-cap returns structured error |
| Memory ceiling | n/a | `MVM_MCP_MEM_CEILING_MIB` (default 4096); env's template `mem_mib` is checked against it |
| Per-call timeout | n/a | `[1, 600]` seconds; out-of-range values clamp (do not error) |
| Audit logging | n/a | Every call lands in `~/.local/state/mvm/log/audit.jsonl` via `LocalAuditKind::McpToolsCallRun{,Error}` |
| stdout discipline | n/a | All `tracing` output goes to stderr — stdout is reserved for JSON-RPC frames |

## Decisions

1. **Single parameterized tool.** One `run` tool, parameters
   `{env, code, session?, timeout_secs?}`. Adding new envs (templates)
   doesn't add tools. Token budget ≤ 500 verified by unit test.

2. **No new external dependencies.** Hand-roll the JSON-RPC 2.0
   frames in `mvm-mcp` (~200 LoC) instead of adopting `rmcp`. Every
   workspace dep needs to clear ADR-002's supply-chain bar
   (`cargo-deny`, `cargo-audit`); a hand-rolled protocol is cheaper
   to audit than a third-party impl.

3. **Two feature flags, day one.** `mvm-mcp/protocol-only` (no I/O,
   wire types only) and `mvm-mcp/stdio` (default, adds the JSON-RPC
   loop). Plan 33's mvmd hosted variant consumes `protocol-only`;
   shipping the split day one means no coordinated bump later.

4. **No CLI-level feature gate.** `mvmctl mcp` is always present in
   CLI builds. The dispatch path requires a dev-feature guest agent
   (per ADR-002 §W4.3), so the CI gate that already enforces
   `do_exec` symbol absence in production agents transitively covers
   this surface. Adding a separate CLI gate would duplicate the
   existing one and complicate consumer flows.

5. **Hosted transport is mvmd's, not mvm's.** Plan 33 documents the
   cross-repo handoff. mvm owns the protocol; mvmd owns
   tenant-aware HTTP/SSE transport, auth, rate limits.

6. **Session semantics deferred to A.2.** The `session` parameter
   exists in the v1 schema but is ignored — clients can adopt the
   field ahead of the server. The implementation (snapshot-resumed
   warm VMs) is in plan 32 / Proposal A.2.

## Consequences

### Positive

- LLM clients drive mvmctl directly via MCP. The user's
  context-window cost stays flat at ~420 tokens regardless of how
  many envs they've built.
- The `env` parameter doubles as a discovery surface — `mvmctl
  template list` is the registry.
- mvmd (plan 33) inherits the wire schema unchanged. Same protocol
  code path on the LLM client side.

### Negative / accepted costs

- One new workspace crate (`mvm-mcp`) to maintain. Mitigated by
  keeping it tiny: protocol types + stdio loop, no business logic.
- The `run` tool's lack of structured stdin (only `code` as a
  string) means clients have to pre-render scripts into a single
  string. nix-sandbox-mcp has the same shape; we'll match it.

### Explicit non-goals

- **HTTP/SSE transport.** Out of scope for this ADR; lives in
  mvmd per plan 33.
- **Per-tenant authentication.** mvm is single-host; mvmd handles
  tenant auth.
- **Streaming responses.** v1 returns one `tools/call` response per
  request, not a stream. nix-sandbox-mcp does the same. If the LLM
  ecosystem moves to require streaming we revisit.
- **Wire compatibility with non-mvm MCP servers' run tools** beyond
  the parameter-name overlap (`env`, `code`, `session`). Different
  semantics per server are unavoidable; we don't promise a strict
  superset.

## Reversal cost

If the MCP server proves a poor fit:

- Drop the `mvmctl mcp` subcommand, keep `mvm-mcp` as a library —
  mvmd may still want `protocol-only`.
- If even the protocol crate is unwanted, deprecate it; downstream
  removal is one minor version bump per plan 33.
- The `ExecDispatcher` is a thin wrapper over `crate::exec::run_captured`;
  removing it doesn't touch `mvmctl exec` semantics.

The audit kind additions (`LocalAuditKind::McpToolsCallRun{,Error}`)
are append-only — removing them would be a serde-breaking change to
existing audit logs. Keep them even if the MCP server is dropped.

## References

- Plan 32: `specs/plans/32-mcp-agent-adoption.md`
- Plan 33: `specs/plans/33-hosted-mcp-transport.md`
- Related ADRs: ADR-002 (microVM security posture)
- Upstream design: [SecBear/nix-sandbox-mcp](https://github.com/SecBear/nix-sandbox-mcp) — single-tool design pattern
- MCP protocol spec: <https://modelcontextprotocol.io/>
