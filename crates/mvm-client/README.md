# mvm-client

`mvm-client` is the stable machine-control facade for Rust consumers. One
surface covers local in-process machines, remote fleet gateways, deterministic
mocks, workload output streams, volumes, secrets, readiness, and audit records.

## Who uses it

`mvm-cli` uses the facade for commands and its private MCP adapter.
External Rust automation can depend on
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

Local machine list and inspect return a backend error if the name registry cannot
be read or parsed, rather than silently omitting stopped entries or metadata.
A missing registry remains a valid empty initial registry. Bulk-stop target
discovery stays best-effort and excludes registry-only entries.

`checkpoint::Checkpoints::remove` owns host-local checkpoint removal for the CLI
and host library. It refuses incomplete/unreadable metadata, session pins,
dependent checkpoints, and failed guard reads. An absent checkpoint directory is
already removed. Removal also refuses any visible checkpoint directory lacking
metadata: it cannot establish that the directory is not a dependent. Read-only
listing still ignores incomplete directories and staging. These preflight checks
do not serialize concurrent pin, lineage,
or path changes with deletion; they do not grant guest, MCP, or remote authority.

## Main modules

| Module | Responsibility |
|---|---|
| `connect` | Target parsing and backend selection |
| `local` | In-process local implementation |
| `launch` / `boot` | Request validation and machine startup |
| `inventory` / `registration` | Machine discovery and durable identity |
| `checkpoint` | Host-local catalog access and guarded checkpoint removal |
| `stream` | Captured output access |
| `volume` | Volume lifecycle, leases, and snapshots |
| `secret` | Secret-reference inputs and audit records |
| `bundle` | Sealing built artifacts into a signed `.mvmpkg`, under the host key or a caller's |
| `builder_bundle` | Building a flake in a builder VM and sealing the result into a `.mvmpkg` |
| `audit` / `grants` / `readiness` | Evidence and lifecycle state |

## Features

The default feature set is local-only. `remote` enables the gateway backend,
`tracing-bridge` enables stream-to-tracing adaptation, and `test-support`
exposes runtime fixtures.

## Developing

Run `cargo test -p mvm-client`. New operations need local, remote DTO, mock,
capability-discovery, and unsupported-operation coverage. Secret-related errors
and debug output must never contain resolved secret material.
