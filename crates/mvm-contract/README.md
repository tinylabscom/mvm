# mvm-contract

`mvm-contract` is the portable contract layer shared by mvm components and
fleet orchestrators. It defines the data that crosses process, host/guest, and
storage boundaries without depending on a hypervisor or orchestration runtime.
The default build is `no_std` plus `alloc`.

## What it provides

- The canonical workload IR and its validation and canonicalization rules.
- Versioned host/guest wire messages, lifecycle messages, and service calls.
- Execution plans, capability grants, network policy, and admission records.
- OCI references, digests, platform selection, and manifest DTOs.
- Audit-chain, assurance-session, and storage-volume contract types.
- Generated builders for multi-field protocol values.

These serialized types are public protocols. Inbound structures use strict
deserialization where compatibility permits, and hashes are computed from
canonical representations so different components agree on identity.

## Who uses it

Most product crates consume this crate directly: `mvm-agentd`, `mvm-core`,
`mvm-net`, `mvm-vmm`, `mvm-backends`, `mvm-runtime`, `mvm-build`, `mvm-fs`,
`mvm-sdk`, `mvm-capture`, `mvm-client`, `mvm-cli`, and `mvm-hostd`. External
fleet software can depend on the same contracts without pulling in the local
runtime.

## How it works

The default `protocol` feature exposes the workload, plan, policy, grant,
assurance, OCI, and wire modules. Values are validated at construction or
deserialization and are then passed between higher layers as typed data rather
than loose JSON maps. Optional features add progressively less-portable
surfaces:

| Feature | Adds |
|---|---|
| `protocol` (default) | `no_std` protocol, IR, policy, and identity types |
| `schema` | JSON Schema derivation and the schema emitter binary; requires `std` |
| `volume` | Async-neutral volume backend contracts |
| `local` | Tokio-based local directory volume implementation |

The crate intentionally contains no VM booting, host filesystem discovery,
network setup, or CLI behavior. Those belong to crates that interpret these
contracts.

## Main modules

| Module | Responsibility |
|---|---|
| `ir` | Workload definition, normalization, validation, and hashing |
| `plan` | Admitted execution plans and verb/service bindings |
| `policy` / `grants` | Requested policy and enforceable capability ceilings |
| `protocol` | Host/guest request, response, and session envelopes |
| `assurance` | Admission-bound AI assurance sessions and outcomes |
| `oci` | Registry reference, digest, platform, and manifest contracts |
| `volume` | Storage backend traits and volume DTOs |
| `wire` | Framing and shared wire-level helpers |

## Developing

Run the focused suite with `cargo test -p mvm-contract`. Validate the portable
surface with the repository's wasm/no-std checks, and regenerate schemas after
changing a schema-bearing type. Protocol changes should include serialization
round trips plus malformed, unknown-field, and version-mismatch tests.
