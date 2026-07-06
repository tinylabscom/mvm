# `machine reconfigure` — mvmd gateway endpoint contract

**Date:** 2026-07-05
**Phase:** 1 (remote path only; `LocalBackend` unsupported until Plan 225)

## What the client sends

`GatewayBackend::reconfigure_machine` issues:

```
POST /api/v1/sandboxes/{id}/reconfigure
Authorization: Bearer <token>
Content-Type: application/json

{
  "net": true,                     // optional — set only if user passed --net / --no-net
  "allow_host": ["api.stripe.com:443"],  // optional — set only if user passed --allow-host
  "cpus": 2,                       // optional — set only if user passed --cpus
  "memory_mib": 1024               // optional — set only if user passed --memory
}
```

Only the fields the caller explicitly set are present in the body — per-field
`#[serde(skip_serializing_if = "Option::is_none")]` on `ReconfigureRequest` in
`crates/mvm-client/src/dto.rs`. An empty body `{}` is valid (a no-op patch).

`mem_initial` is a CLI-only field and is **not** in the facade DTO; the server
need not handle it.

## What the server returns

The same single-item sandbox envelope that `run_machine` / `stop_machine` return:

```json
{ "data": { <SandboxDto fields> } }
```

`SandboxDto` is the existing `{ sandbox_id, name, status, ... }` shape.
The client maps this through `parse_response::<SandboxDto>` and wraps it in
`MachineState` exactly as the other mutation verbs do.

## Behavior contract (for server implementers)

- Apply only the fields present in the body; absent fields leave the sandbox
  config unchanged (patch semantics, mirroring the CLI verb).
- If the sandbox is running, the server should stop it, apply the new config,
  and start it again — same "auto stop + start" behavior as the CLI.
- If the sandbox is stopped, persist the change so it takes effect on the next
  start.
- Return the updated sandbox state after the operation.

## Phasing note

The client-side `GatewayBackend` method is shipped in Plan 224 Phase 1
(branch `worktree-machine-reconfigure`). `LocalBackend` returns a clear
`MvmError::Backend` unsupported error in Phase 1; the real local
implementation is Plan 225 (Phase 2 — lift the persistent-machine engine to
a shared crate and wire `LocalBackend`).
