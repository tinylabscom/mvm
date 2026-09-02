# mvm-client

`mvm-client` is the stable machine-control facade for Rust consumers. One
surface covers local in-process machines, remote fleet gateways, deterministic
mocks, workload output streams, volumes, secrets, readiness, and audit records.

## Who uses it

`mvm-cli` uses the facade for command implementation and `mvm-mcp` translates
MCP requests into the same operations. External Rust automation can depend on
this crate instead of the full `mvmctl` facade. `mvm-conformance` tests the
contract. The trait and common DTOs are defined in feature-gated `mvm-core` so
`mvm-sdk` can share them without creating a dependency cycle.

## How it works

`MvmClient` defines backend-neutral operations and capability discovery.
`connect` parses a target and selects an implementation:

- `LocalBackend` invokes the local build, runtime, host daemon, and filesystem
  layers in-process.
- `GatewayBackend`, enabled by `remote`, carries the same DTOs over the remote
  gateway transport.
- `MockBackend` records deterministic requests for tests and embedders.

Before an operation, callers can inspect `ClientOperationCapabilities` instead
of discovering unsupported behavior after mutation. Launch helpers normalize
requests and bind grants, registration, and readiness records. Stream helpers
read captured workload output; the optional tracing bridge republishes it into
a consumer's tracing subscriber.

## Main modules

| Module | Responsibility |
|---|---|
| `connect` | Target parsing and backend selection |
| `local` | In-process local implementation |
| `launch` / `boot` | Request validation and machine startup |
| `inventory` / `registration` | Machine discovery and durable identity |
| `stream` | Captured output access |
| `volume` | Volume lifecycle, leases, and snapshots |
| `secret` | Secret-reference inputs and audit records |
| `audit` / `grants` / `readiness` | Evidence and lifecycle state |

## Features

The default feature set is local-only. `remote` enables the gateway backend,
`tracing-bridge` enables stream-to-tracing adaptation, and `test-support`
exposes runtime fixtures.

## Developing

Run `cargo test -p mvm-client`. New operations need local, remote DTO, mock,
capability-discovery, and unsupported-operation coverage. Secret-related errors
and debug output must never contain resolved secret material.
