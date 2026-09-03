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
use. Protocol errors, invalid parameters, unsupported capabilities, and client
failures are mapped to stable JSON-RPC errors without exposing secrets or
internal debug data. The adapter opens no network listener; any remote traffic
belongs to the selected client backend.

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
