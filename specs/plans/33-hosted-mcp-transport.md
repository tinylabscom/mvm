---
title: "Plan 33 — Hosted MCP transport (mvmd cross-repo)"
status: Proposed (cross-repo handoff to mvmd)
date: 2026-04-30
related: ADR-002 (microVM security posture); plan 25 (microVM hardening); plan 32 (MCP + LLM-agent adoption); ADR-003 (local MCP — Proposal A)
owner: mvmd team
---

## Status

Proposed. **Implementation lives in the
[mvmd](https://github.com/auser/mvmd) repository, not this one.** This
document is mvm's permanent record of the boundary so the protocol
crate stays a single source of truth.

## Context

Plan 32 / Proposal A (ADR-003) adds `mvmctl mcp --stdio`: a local-only
MCP server that exposes one parameterized `run` tool, dispatching into
transient microVMs on the developer's machine. That's the right shape
for a single user driving a single host.

Multi-tenant operation — a fleet of microVMs exposed over HTTP/SSE to
remote LLM clients, with auth, tenant isolation, and pool routing — is
mvmd's domain. mvmd already owns tenants, pools, instances, agents, and
the coordinator API; a hosted MCP transport is one more surface on top
of that orchestration layer.

This plan locks in the boundary so neither repo accidentally drifts:

- **mvm** owns the MCP *protocol* — wire types, tool schemas, JSON-RPC
  framing, the single-tool design philosophy.
- **mvmd** owns the *transport* — HTTP/SSE, auth, tenant routing,
  per-tenant rate limits, observability.

## Decision

Split the local MCP work in mvm into two artifacts:

1. **`mvm-mcp` crate (this repo)** — a library with two feature flags:
   - `protocol-only` (default-off): exports protocol types
     (`JsonRpcRequest`, `ToolSchema`, `RunParams`, `RunResult`) and
     a transport-agnostic `Dispatcher` trait. No I/O.
   - `stdio` (default-on for `mvmctl`): adds the stdio loop that
     `mvmctl mcp --stdio` invokes.

2. **mvmd's `mvmd-mcp` crate (mvmd repo)** — depends on `mvm-mcp` with
   `protocol-only`. Implements:
   - HTTP/SSE transport (Axum or similar; matches mvmd's existing HTTP
     surface).
   - Auth: API tokens scoped per tenant; reuses mvmd's signing key
     infrastructure.
   - `run` tool whose `env` parameter is mvmd-shaped:
     `tenant/pool/template@revision`. Resolves to a microVM in mvmd's
     instance pool.
   - Per-tenant rate limits and quota tracking via mvmd's existing
     metering.

## Threat model (additive over ADR-002)

mvmd's hosted transport adds two adversaries beyond ADR-002:

1. **A remote LLM client.** Untrusted by default. Authenticated via
   tenant-scoped API tokens. Cannot escape its tenant's pool. The
   `run` tool's `env` parameter is validated against the tenant's
   allowed templates; an attacker forging a different tenant's
   template name returns 403.

2. **A compromised tenant.** A tenant whose API token is leaked must
   not be able to read another tenant's data, exhaust shared
   resources, or pivot to mvmd's coordinator. Per-tenant pools (mvmd
   already isolates these) plus per-tenant rate limits are the
   defenses.

Out of scope (named explicitly):

- Cross-tenant code execution. mvmd doesn't multiplex tenants onto a
  single microVM.
- BYO-cloud / customer-VPC hosting. Future work for mvmd.

## Wire compatibility

The `run` tool's schema is owned by `mvm-mcp`. mvmd's hosted variant
extends only the `env` parameter's *value space* (it accepts
`tenant/pool/template@revision` strings); the schema itself is
unchanged. This guarantees a Claude Code client that talks to local
`mvmctl mcp` can talk to a hosted mvmd MCP endpoint with the same
protocol code path — only the env strings differ.

## Cross-repo workflow

- mvm bumps `mvm-mcp` versions and publishes Cargo metadata.
- mvmd pins to a specific `mvm-mcp` version and integrates new tool
  fields via the `protocol-only` feature.
- Breaking changes to the wire format require coordinated releases:
  mvm publishes first (with the new field optional), mvmd consumes
  next.

## Tracking

- Issue in mvmd: "Hosted MCP transport over the coordinator API"
  (referencing this plan and ADR-003).
- mvm-side checkpoint: `mvm-mcp` crate ships with the `protocol-only`
  feature flag and a public `Dispatcher` trait from day one of plan
  32 / Proposal A v1. Without that, mvmd cannot consume the crate
  cleanly later.

## Verification (mvm side only)

- `cargo build -p mvm-mcp --no-default-features --features protocol-only`
  succeeds and produces no I/O symbols (`std::io::stdin`, etc).
  Asserted via `nm` symbol grep in CI.
- `cargo test -p mvm-mcp --no-default-features --features protocol-only`
  green.
- Public API exports stable: enforced via `cargo-semver-checks` in CI.

mvmd-side verification lives in mvmd's repo.

## Reversal cost

If mvmd later decides hosted MCP isn't a fit, the `protocol-only`
feature in mvm is harmless — it's a thin set of types. Removing it
costs one minor version bump.
