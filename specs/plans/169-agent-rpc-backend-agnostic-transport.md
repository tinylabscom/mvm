# Plan 169 — Backend-agnostic agent-RPC transport (`fs`/`proc`/`exec`/`cp`/`diff`)

## Status: DONE (2026-06-07). All verbs (`fs`/`proc`/`exec`/`cp`/`diff`) migrated to the backend-aware transport + box-verified on QEMU. `fs`+`cp` landed in PR #681; `proc`/`exec`/`diff` in this slice. Surfaced by Plan 166 Phase 2 box verification.

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
  Proc/diff slice: `send_proc_request_on` / `send_proc_wait_on` /
  `query_fs_diff_on` added the same way (dir-based `send_proc_request` /
  `send_proc_wait` / `query_fs_diff` / `query_fs_diff_at` delegate). No
  `send_run_entrypoint_on` was needed — `send_run_entrypoint` is already
  stream-based. `query_fs_diff_on` adds the plan 74 W1 hello prelude
  (`require_capabilities(FilesystemRpc)`) the old dir-based diff helpers
  skipped — a hard-cutover agent (ADR-053) rejected the un-helloed `FsDiff`,
  so `mvmctl diff` was latently broken on **every** backend, not just QEMU.
- [x] **`mvmctl fs`**: `fs_request(name, req)` helper routes through
  `for_vm(name)?.connect(GUEST_AGENT_PORT)?` + `send_fs_request_on`, keeping
  the mock fast path ahead of the probe. All 7 verbs migrated; the dead
  `instance_dir_for`/`microvm` import dropped.
- [x] **`mvmctl cp`**: routed through `fs::fs_request`.
- [x] **`mvmctl proc`**: added `send_proc_request_on` / `send_proc_wait_on`;
  `proc.rs` now has `proc_request` / `proc_wait` helpers (mock fast path →
  `for_vm`), dropping its own `instance_dir_for` + the `microvm` import.
- [x] **`mvmctl exec` / `invoke`**: already backend-agnostic — `invoke.rs`'s
  `dispatch_inner` drives `for_vm(...).connect()` + the stream-based
  `send_run_entrypoint`. Confirmed it predates this plan; no change needed.
  (`mvmctl exec`/`run` is the transient-VM runner and never speaks agent RPC.)
- [x] **`mvmctl diff`**: `diff.rs` now has an `fs_diff` helper routing through
  `for_vm` + `query_fs_diff_on` (mock fast path ahead of the probe).
- [x] Keep the mock-VM fast path (`MockBackend::vm_dir/.../runtime/v.sock`)
  working — kept the mock check ahead of the `for_vm` call in `proc_request` /
  `proc_wait` / `fs_diff`, mirroring `fs::fs_request`. Added an `FsDiff` arm
  to the mock guest agent so `mvmctl diff --hypervisor mock` succeeds.

## Verification

- [x] Unit: the `*_on` framing round-trips against a mock stream —
  `send_proc_request_on` / `send_proc_wait_on` / `query_fs_diff_on` tests in
  `mvm-backend::mock_guest_agent` drive a CONNECT-handshaked stream (the shape
  `for_vm(...).connect(...)` yields). The dir-based wrappers (which delegate to
  the `*_on` entry points) keep their existing round-trip tests.
- [x] Box (x86_64): `mvmctl up --flake … --hypervisor qemu` booted
  `mushy-house`; `mvmctl diff` and `mvmctl fs ls` returned real results
  (full round-trips over the QEMU `vsock-5252.sock` bridge), and
  `mvmctl proc ls/start/wait` reached the agent and returned a typed
  `UnsupportedInProduction` (this e2e flake's agent is built without
  `dev-shell`, so proc handlers are compiled out — orthogonal to transport).
  The FC-style `…/runtime/v.sock` path is **absent** for the QEMU VM, so the
  pre-migration resolver would have failed with "Vsock socket not found"; only
  `vsock_transport::for_vm` finds the live `vsock-5252.sock`. This is the
  end-to-end proof the transport migration works.
- [x] Regression: the same verbs still work against Firecracker + mock
  (`--hypervisor mock`); the mvmd dir-based callers (`send_proc_request`,
  `query_fs_diff`) compile unchanged — they now delegate to the `*_on` forms.
- [x] `cargo nextest` (proc/diff slice) + clippy `-D warnings` + nightly fmt +
  `check-spec-numbers`.

## Non-goals

- New agent RPCs or wire-format changes — pure transport-resolution.
- Changing the mvmd-side dir-based callers (they keep the dir API).
- The mvmd `--prod` Tier-2/3 admission gate (tracked in Plan 166 / mvmd).
