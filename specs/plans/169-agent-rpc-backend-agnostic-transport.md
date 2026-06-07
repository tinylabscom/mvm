# Plan 169 — Backend-agnostic agent-RPC transport (`fs`/`proc`/`exec`/`cp`/`diff`)

## Status: IN PROGRESS (2026-06-07). `fs` + `cp` migrated + box-verified on QEMU; `proc`/`exec`/`diff` remaining. Surfaced by Plan 166 Phase 2 box verification.

> **Cross-backend, not QEMU-specific.** The QEMU workload runtime (Plan 166
> Phase 2, PR #671/#675) is the trigger, but the gap is in the shared
> host↔guest agent-RPC layer and equally affects **libkrun**. This is its
> own plan precisely because it changes a shared API used by every backend
> (and consumed by mvmd), so it wants a focused review separate from Plan 166.

## Problem

The agent-RPC CLI verbs resolve the guest vsock socket the **Firecracker**
way — `<instance_dir>/runtime/v.sock` — instead of through the
backend-aware `mvm::vsock_transport::for_vm(name)`. So they fail against a
QEMU (or libkrun) workload, whose agent is reached over a per-port UNIX
socket at `mvm_core::config::vm_vsock_port_socket(name, port)` (for QEMU,
the `__qemu-vsock-bridge` binds it; for libkrun, the supervisor does).

Observed on the box (Plan 166 Phase 2): `mvmctl fs ls <qemu-vm> /` →
`Vsock socket not found at /root/microvm/vms/<name>/runtime/v.sock`.

`mvmctl wait` and `mvmctl boot-report` already work against QEMU because
they take the right path: `for_vm(name)?.connect(GUEST_AGENT_PORT)` + the
stream-based framing primitives. The fix is to make the rest do the same.

## Root cause

`crates/mvm-guest/src/vsock.rs` exposes ~8 **dir-based** wrappers that each
call `connect(instance_dir)` → `connect_to(vsock_uds_path(instance_dir))` →
`<instance_dir>/runtime/v.sock`:

- `send_fs_request(instance_dir, req) -> FsResult`
- `send_proc_request(instance_dir, req) -> ProcResult`
- `send_proc_wait(instance_dir, pid_token, …, on_event)` (streaming)
- `send_run_entrypoint(instance_dir, …)` (streaming; `exec`/`invoke`)
- `query_worker_status` / `query_integration_status` / `query_probe_status` /
  `query_fs_diff(instance_dir)`

The **framing primitives are already stream-based and `pub`**:
`connect_to` / `connect_to_port`, `write_frame` / `read_frame`,
`send_request`, `require_capabilities`. There are also `*_at(uds_path)`
variants for some queries — a precedent for explicit-path entry points.

CLI callers: `commands/vm/{fs,proc,exec,cp,diff}.rs` (+ `invoke.rs`).
`fs.rs` (7) / `proc.rs` (6) / `cp.rs` (4) call the dir-based wrappers;
`fs::instance_dir_for` → `microvm::resolve_running_vm_dir` is the FC-only
resolver feeding them.

## Approach

Mirror what `wait` does: obtain a connected stream from
`vsock_transport::for_vm(name)` (which already probes apple-container →
libkrun-socket → firecracker, and the libkrun-socket probe matches the QEMU
bridge socket), then drive the stream-based primitives.

- [x] **`mvm-guest::vsock`**: `send_fs_request_on(stream, req)` added; dir-based
  `send_fs_request` delegates to it (FC/mock/mvmd dir callers unchanged).
  (`send_proc_request_on` / `send_proc_wait_on` / `send_run_entrypoint_on`
  still to add for the proc/exec slice.)
- [x] **`mvmctl fs`**: `fs_request(name, req)` helper routes through
  `for_vm(name)?.connect(GUEST_AGENT_PORT)?` + `send_fs_request_on`, keeping
  the mock fast path ahead of the probe. All 7 verbs migrated; the dead
  `instance_dir_for`/`microvm` import dropped.
- [x] **`mvmctl cp`**: routed through `fs::fs_request`.
- [ ] **`mvmctl proc`**: add `send_proc_request_on` / `send_proc_wait_on`;
  route `proc.rs` (its own `instance_dir_for`) through `for_vm`.
- [ ] **`mvmctl exec` / `invoke`**: route `send_run_entrypoint` through
  `for_vm` (confirm exec's current mechanism first).
- [ ] **`mvmctl diff`**: route `query_fs_diff` through `for_vm` (or its
  `_at` variant fed by the resolved socket path).
- [ ] Keep the mock-VM fast path (`MockBackend::vm_dir/.../runtime/v.sock`)
  working — `for_vm` doesn't know mock; either add a mock probe to `for_vm`
  or keep the mock check ahead of the `for_vm` call in each command.

## Verification

- [ ] Unit: `for_vm` selects the libkrun/QEMU socket for a marker-resolved
  VM; the `*_on` framing round-trips against a mock stream.
- [ ] Box (x86_64): `mvmctl up --hypervisor qemu` then `fs ls` / `fs read` /
  `proc list` / `cp` succeed against the live QEMU workload (agent over the
  `__qemu-vsock-bridge`).
- [ ] Regression: the same verbs still work against Firecracker + mock
  (`--hypervisor mock`) + the mvmd dir-based callers compile unchanged.
- [ ] `cargo nextest` + clippy + nightly fmt + `check-spec-numbers`.

## Non-goals

- New agent RPCs or wire-format changes — pure transport-resolution.
- Changing the mvmd-side dir-based callers (they keep the dir API).
- The mvmd `--prod` Tier-2/3 admission gate (tracked in Plan 166 / mvmd).
