# ADR-048 — MvmClient-backed local MCP server

Backing: shipped-source
Validation: `cargo test -p mvm-mcp`

**Status:** Accepted
**Date:** 2026-08-19
**Supersedes:** ADR-002

## Context

ADR-002's first MCP server was withdrawn because it duplicated lifecycle and
session authority, exposed a bespoke `run` environment abstraction, and had no
named consumer. The later `MvmClient` facade now provides the missing single
surface: local, remote, and test backends already express machine intent through
one object-safe trait. Issue #2647 asks for MCP to be revived only if it adapts
that facade rather than becoming another control plane.

The current [MCP protocol](https://modelcontextprotocol.io/specification/2026-07-28)
is the 2026-07-28 stateless model. Requests carry
their protocol version and client capabilities in `_meta`, `server/discover`
is mandatory, and stdio messages are newline-delimited JSON-RPC. Older clients
still in use perform the `initialize` handshake, at 2025-11-25 or 2025-06-18.

## Decision

`mvm-mcp` is a small, hand-written JSON-RPC adapter over `Arc<dyn MvmClient>`.
It contains no backend selection, admission, lifecycle, session, credential,
or audit policy. Every machine tool translates strict JSON arguments into an
existing facade DTO and invokes exactly one facade operation.

The catalog is derived from `BackendCapabilityReport.operations`. Those
operation capabilities are a serialized deny-all-by-default field, distinct
from hypervisor capabilities because two transports can expose different
methods against the same VMM. Local, gateway, and mock clients attach the
methods they actually implement. An operation that is not reported is not
advertised or callable. In particular, local and gateway clients do not
advertise `exec` while their facade implementations return unsupported.

The process transport is only `mvmctl ops mcp stdio`. There is no listener,
HTTP transport, authentication subsystem, or orchestration service. The server
implements current `server/discover`, `tools/list`, and `tools/call`, plus the
legacy initialize response. That response echoes a requested 2025-11-25 or
2025-06-18 and answers any other requested version with 2025-11-25, as the MCP
lifecycle prescribes, rather than refusing it; the server keeps no session, and
every response it emits is valid under each of those versions. A request in a
handshake session may carry `_meta` without a protocol version, such as a
progress token, and that metadata is ignored. Current requests are independently validated; no
authority or capability state is inherited from a prior request.

Frames are bounded before allocation, output is bounded before emission,
unknown fields fail closed, tool-originated failures use `isError`, and
protocol/tool-lookup failures use JSON-RPC errors. stdout is protocol-only.

`scripts/test-mcp-roundtrip.sh` is the named consumer. It drives discovery,
catalog listing, and the read-only backend-capability tool without booting a
VM. Protocol and dispatch coverage lives in ordinary workspace tests against
`MockBackend`; there is no dedicated CI lane to become an unowned second gate.

## Consequences

Agents and humans can use one long-lived structured process while local CLI,
SDK, gateway, and MCP calls retain the same authority boundary. Adding a facade
method does not silently add a tool: the client must report the operation and
the adapter must define and test its strict mapping. MCP version changes remain
an audited in-house maintenance responsibility, but add no third-party protocol
dependency to the supply chain.
