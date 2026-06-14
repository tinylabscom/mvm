# Plan 197 Phase 2a — macOS egress substitution: implementation blueprint

**Date:** 2026-06-13
**Status:** design accepted; implementing in 2 commits
**Scope:** wire the egress-substitution **vsock channel** (explicit `HTTP_PROXY`)
onto libkrun + vz. The transparent :80/:443 terminator is Phase 2b (rvproxy).

## Key decision — port 5253 direction

`SUBSTITUTION_PORT` (5253) is **host-listens / guest-connects** (the guest dials
`connect_host_vsock(5253)`), the same direction as `WORKLOAD_EXIT_PORT` (5251) —
**not** `GUEST_AGENT_PORT` (5252, guest-listens). The host substitution endpoint
process binds the per-VM UDS; the guest's AF_VSOCK connect is routed to it.

- **libkrun:** register 5253 via `.add_host_listen_port(5253)` in
  `krun_context_base` (unconditional — fail-closed: nothing binds the UDS when
  the plan has no secrets, so a stray dial gets ECONNREFUSED). The **endpoint
  process** binds `vm_vsock_port_socket(name, 5253)`; libkrun proxies guest
  connects to it. No supervisor change. (Verify `configure()` does NOT pre-unlink
  `listen=false` sockets — it must not clobber the endpoint's bind.)
- **vz:** the existing `start_vsock_proxy` is the wrong direction
  (host-connects-to-guest). Add a new `host_listen_ports: Vec<u32>` to
  `mvm_build::vz::VsockConfig` (`#[serde(default)]`) and a
  `start_host_listen_proxy` in `vz_objc.rs` that installs a
  `VZVirtioSocketListener` on 5253 and splices each guest connection to
  `vm_vz_vsock_port_socket(name, 5253)` (the endpoint's UDS). Must run before
  `start()`. `shutdown()` must NOT unlink that UDS (the endpoint owns it).

## Shared

- `substitution_spawn::spawn_substitution_endpoint` currently hardcodes
  `transport: vsock{5253}`. Add a `transport: EndpointTransport` param and
  serialize it. FC passes `Vsock{5253}` (no behavior change); macOS passes
  `Uds{ path: <per-VM 5253 socket> }`; `terminator_listen: None` on macOS.
- Un-Linux-gate `decode_plan_secrets` into a shared
  `decode_plan_secrets_from_state(state_dir)` (used by libkrun + vz; FC keeps
  its path or shares it).
- Each macOS backend spawns the endpoint after the supervisor PID file appears,
  before returning `Ok(VmId)`, gated on the plan carrying secrets; an
  `EndpointGuard` reaps on early return; `stop()` reaps (mirrors FC `stop_vm`).

## Build sequence

**Commit 1 (libkrun half — CI-verifiable):** `substitution_spawn` transport
param + update FC/QEMU callers (no behavior change); shared
`decode_plan_secrets_from_state`; `add_host_listen_port(5253)` in
`krun_context_base`; libkrun `start`/`stop` spawn+reap+guard; unit tests
(no-secrets no-op; spawn writes `kind:"uds"` config with a stub endpoint bin).

**Commit 2 (vz half + cleanup — needs live boot):** `VsockConfig.host_listen_ports`;
`vz_objc.rs` `start_host_listen_proxy` + `run_host_listen_port_proxy`; vz
`start`/`stop` spawn+reap; remove QEMU's dead substitution call; vz serde test;
**live vz boot** — a `SecretRef` workload on `--hypervisor vz` with explicit
`HTTP_PROXY` sees only the placeholder, host endpoint injects the real credential.

**Commit-2 cleanup (reuse-first):** collapse FC's Linux-gated
`microvm.rs::decode_plan_secrets` into `egress_shared::decode_plan_secrets_from_state`
(repoint FC's two callsites, delete the dup). It edits Linux-only code, so verify
with a Linux-target `cargo clippy --target` cross-check, not just the macOS build.

## Risks (from the spike + architect review)

- libkrun: endpoint (not supervisor) binds `vsock-5253.sock`; supervisor must not
  pre-unlink it. Fail-closed when no secrets.
- vz: the `VZVirtioSocketListener` must be installed before boot; `shutdown` must
  not unlink the endpoint-owned UDS; spawn-timing must put the listener up before
  the guest can dial.
- Commit 2's vz proxy + live boot is the high-risk part — validate on the macOS-26
  Vz box, isolated env.
