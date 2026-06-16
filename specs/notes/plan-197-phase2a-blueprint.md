# Plan 197 Phase 2a — macOS egress substitution: implementation blueprint

**Date:** 2026-06-13
**Status:** ✅ COMPLETE on vz — control plane + DATA PLANE proven live on macOS-26 (2026-06-15).
**Scope:** wire the egress-substitution **vsock channel** (explicit `HTTP_PROXY`)
onto libkrun + vz. The transparent :80/:443 terminator is Phase 2b (rvproxy).

## Live data-plane proof (vz, macOS-26 Apple Silicon, 2026-06-15)

Both 2a commits merged via #909 (the pre-start `plan.json` persist on the `up`
AND `invoke`/`session` paths — the gate that made the endpoint actually spawn).
Data plane validated end-to-end on a clean origin/main worktree.

**Driver (sidesteps the pre-existing 5252 early-boot reset race):** don't lean on
`up` to fire the entrypoint. Boot detached, settle the agent, then dispatch:

```
mvmctl up --flake <compiled-out> --name N --hypervisor vz -d
mvmctl vm wait N --for all          # agent settles past the early-boot reset window
mvmctl invoke N --attach            # RunEntrypoint into the running VM
```

`invoke --attach` reads the boot-minted `substitution-env.json` and injects
`HTTP_PROXY=http://127.0.0.1:18080` + the placeholder vars — so the sealed-prod
function runs with live substitution and **no `vm proc` exec** (claims 4/15 intact).
No `--from-workload-ir` is needed in attach mode (placeholders already minted at `up`).

**Evidence:** endpoint pid alive, `vsock/vsock-5253.sock` bound, supervisor
`host_listen_ports:[5253]`, `substitution-env.json = [["API_KEY","mvm-secret-…"]]`
(real key absent from guest env). httpbin.org/get reflected the **real** Bearer
credential (it reached the destination) while the guest held only the placeholder
(claim 13); `example.com` (not in `allowed_hosts`) was refused with
`HTTP 502: substitution refused: destination example.com is not in the secret's
allowed_hosts` (claim 12).

**Repeated-dial risk (the unproven crux) — DISPROVEN.** A single call issues 3
sequential dials; ran `invoke --attach` twice ⇒ 6 guest→host dials on the 5253
`VZVirtioSocketListener`, endpoint + supervisor alive throughout. The one-shot
`if let Some(rx.recv())` is ONLY on the exit port 5251 (`run_exit_listener`); the
5253 host-listen proxy is `while let Some(conn)=rx.recv()`
(`run_host_listen_port_proxy`) with a re-arming `VsockListenerDelegate::should_accept`
(`tx.set(Some(tx))`), and the endpoint UDS `serve` is `loop { accept }`. Every hop
loops — no supervisor bug, no code change required (pure verification).

Remaining 2a cleanup (non-blocking): remove QEMU's dead substitution call and
collapse FC's Linux-gated `decode_plan_secrets` into
`egress_shared::decode_plan_secrets_from_state` (verify with a Linux-target
cross-check). Phase 2b = rvproxy transparent terminator.

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
