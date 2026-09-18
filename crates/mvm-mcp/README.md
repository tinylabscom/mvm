# mvm-mcp

`mvm-mcp` is a bounded, stdio-only Model Context Protocol adapter over
`MvmClient`. It lets an MCP client discover and invoke machine operations
without creating a second lifecycle, admission, or authorization
implementation.

## Who uses it

`mvm-cli` embeds the server in the user-facing MCP command. The only product
dependency below it is `mvm-client`, so local, remote, and mock behavior stays
consistent with other automation clients.

## How it works

`McpServer` reads one JSON-RPC message at a time from buffered stdin, validates
the protocol envelope and method, converts parameters into typed client DTOs,
and invokes the selected `MvmClient`. It serializes the bounded result to
stdout. Discovery metadata is generated from the client's capability report,
so unsupported operations are not advertised as available.

`ServerLimits` caps incoming frames, outgoing payloads, and related resource
use. Protocol errors, invalid parameters and unsupported capabilities are
mapped to JSON-RPC errors with fixed messages. A failed client operation is
reported with its typed code, its retryable flag, and the backend's own error
message, capped at 512 characters: that message is the backend's to choose, so
what it names (a machine id, a path) reaches the caller. The adapter opens no
network listener; any remote traffic belongs to the selected client backend.

Tool failures and capability-discovery failures carry a stable `code` and a
`retryable` flag, so a caller can branch without parsing message text. The
other protocol errors (`-32700`, `-32600`, `-32601`, `-32602`, including an
unknown tool) carry only the JSON-RPC code and message. A failed tool call is
a tool result with `isError: true` and the pair in `_meta`: the `MvmError` variant's own code
(`NOT_FOUND`, `INVALID_SPEC`, `BACKEND_ERROR`, `UNAUTHORIZED`, `CONFLICT`,
`REJECTED`, or `UNAVAILABLE`, the only retryable one), `INVALID_INPUT` for bad
arguments, `OUTPUT_TOO_LARGE` when a result exceeds the output limit, and
`INTERNAL` when the server cannot serialize a result. A failed capability
discovery has no tool result to attach it to, so `tools/list` and `tools/call`
return a JSON-RPC `-32603` error with the same pair in its `data` field and a
fixed message that leaves out the backend's error text.

## Owned surface

The crate owns:

- MCP initialization and protocol-version negotiation;
- tool discovery and JSON schemas;
- JSON-RPC framing, dispatch, and error mapping;
- conversion between MCP values and `mvm-client` DTOs;
- response truncation and other server limits.

It does not own machine state, artifact verification, admission, credentials,
or authorization. Those remain in `mvm-client` and its backend.

## Developing

Run `cargo test -p mvm-mcp`. Add tests for valid dispatch, unknown methods,
invalid/oversized frames, unavailable capabilities, output limits, and redacted
errors whenever the protocol surface changes.

The advertised tool surface is pinned in `tests/fixtures/tool-contract.json`:
each tool's name, description, input schema, and gating client operation.
Changing any of them fails `tool_surface_matches_the_pinned_contract`. An agent
reads that surface as its contract, so review the change as one, then re-bless
with `MVM_UPDATE_MCP_TOOL_CONTRACT=1 cargo test -p mvm-mcp --test protocol
tool_surface_matches_the_pinned_contract` and commit the fixture diff.
