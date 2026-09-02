# ADR-002: Local Model Context Protocol server (`mvmctl ops mcp stdio`)

## Status

Withdrawn (2026-07-31); superseded by ADR-048 (2026-08-19). The server, its `mcp` Cargo feature, the
`mvmctl ops mcp stdio` verb, the stdio roundtrip smoke script, and the
`mcp-server-smoke` CI lane were all deleted. It was a surface nobody
drove: it shipped behind an opt-in feature composed only into `user`,
had no consumer, and duplicated authority that the CLI's JSON output
and the SDKs already expose. The record below is kept for the numbering
and for the reasoning. ADR-048 revisits the surface only as a capability-derived
adapter over `MvmClient`; this record does not describe the replacement.

## Context

LLM clients speak Model Context Protocol over stdio: a server announces
itself via `initialize`, lists tools via `tools/list`, and dispatches via
`tools/call`. mvmctl is otherwise invoked as a shell command; an LLM
driving it that way has to spawn a subprocess per call, parse free-form
text output, and lose MCP's structured affordances (content blocks, error
semantics, capability negotiation).

`mvm-mcp` adds the MCP transport. It exposes mvm's environments as a
single parameterized `run` tool so the LLM's context-window cost stays
flat regardless of how many environments exist, rather than growing with
one tool definition per environment.

The transport is a host-local stdio process spawned by the user's LLM
client. There is no new attacker beyond the microVM security posture
(ADR-001): the `code` a caller submits reaches the guest as a single argv
element inside an already-isolated microVM, and the microVM — not the MCP
layer — is the security boundary.

## Decision

**`mvmctl ops mcp stdio` speaks MCP over stdin/stdout only.** No network
listener, no HTTP/SSE transport in this repo. A hosted transport, if ever
built, is fleet-orchestration's concern (tenant auth, rate limits); this
repo owns the protocol only.

**One tool, `run`, not one tool per environment.** Parameters: `{env,
code, session?, close?, timeout_secs?}`. `env` names a built-in preset
(`shell`, `bash`, `python`, `node`) or an absolute path to a project
manifest whose slot has already been built via `mvmctl build`. An unknown
`env` returns a structured MCP error listing the valid built-ins and the
caller's currently-built slots — no shell interpolation, no arbitrary path
access. `session` and `close` are reserved fields for a future
session-pinned warm VM; v1 accepts and ignores them so a client can adopt
the field shape ahead of the server implementing it.

**`code` reaches the guest as a single argv element**, dispatched through
the existing exec path to the guest agent's `Exec` handler over vsock. A
production guest agent is built without the `dev-shell` feature, so `Exec`
is physically absent from that binary (ADR-001 claim 4); a production
workload refuses code execution rather than running it. `mvmctl ops mcp
stdio` needs no separate feature gate at the CLI level — the existing
chain is the gate.

**No third-party MCP protocol dependency.** The JSON-RPC 2.0 framing is
hand-rolled in `mvm-mcp`: every workspace dependency has to clear the
supply-chain bar (`cargo-deny`, `cargo-audit`), and a protocol surface
this small is cheaper to audit in-house than to bring in and vet a
third-party implementation.

**The wire-schema crate and the stdio loop are separable.** `mvm-mcp`
keeps the tool/wire types (schema, no I/O) apart from the JSON-RPC stdio
loop, so a future hosted transport can reuse the wire types without
inheriting this repo's process model.

**Every call is bounded and audited.** stdout/stderr are captured with a
fixed per-stream cap and an explicit truncation marker past that cap;
concurrent in-flight calls and each environment's declared memory
footprint are checked against configurable ceilings (`MVM_MCP_MAX_INFLIGHT`,
default 4; `MVM_MCP_MEM_CEILING_MIB`, default 4096), returning a
structured "retry" or "exceeds ceiling" error rather than admitting the
call; a per-call timeout clamps to a fixed range instead of erroring on an
out-of-range value. Every call is written to the local audit log.
`tracing` output goes to stderr exclusively — stdout is reserved for
JSON-RPC frames.

**Session bookkeeping is a pure map; VM materialization is a separate,
not-yet-built concern.** A session tracks idle/max-lifetime expiry and
closes through a pluggable `Reaper` (kill the VM, audit-log the close).
Actually booting a long-lived VM that persists across `tools/call`
invocations and reusing it from session state is not implemented yet —
the wire schema already carries the `session`/`close` fields so that can
land without a wire break.

## Consequences

**Positive.** LLM clients drive mvmctl directly via MCP instead of
shelling out and parsing text output. The `env` parameter doubles as a
discovery surface. A future hosted transport inherits the same wire
schema unchanged.

**Negative.** One more workspace crate to maintain, kept deliberately
small (wire types + a stdio loop, no business logic). The `run` tool
takes only a flat `code` string, not structured stdin, so a caller has to
pre-render a script into one string.

**Non-goals.** No HTTP/SSE transport in this repo. No per-tenant
authentication — mvm is single-host. No streaming `tools/call` responses.
No wire-compatibility promise with other MCP servers' `run` tools beyond
parameter-name overlap (`env`, `code`, `session`).
