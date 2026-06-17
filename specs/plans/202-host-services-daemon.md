# Plan 202 — Host services daemon (per-tenant, not per-VM spawn)

- Status: **In progress**
- ADR: [ADR-084](../adrs/084-host-services-daemon-not-per-vm-spawn.md)
- Revises: the E5.3b-2 per-VM spawn stack (`mvm_backend::broker_services_spawn`) landed under [Plan 125](125-cli-sdk-dx-surface.md) E5.3b
- Consumer: mvmd Plan 52 (host services) adopts the daemon per tenant

## Goal

Replace per-VM `mvm-broker` + `mvm-audit-signer` forks with **one host-agent daemon + a supervised signer helper, per tenant** — the user runs one daemon, its many microVMs are *registrations* not processes, and the helper is an invisible privilege-separated child. Host-process count drops from `O(VMs)` to `O(active tenants)`; `host.audit.v1` becomes available on a normal admitted `up`, decoupled from `MVM_GATEWAY_BRIDGE`. `mvm` (one tenant) is the single-tenant degenerate case of `mvmd` (one such unit per tenant). The guest-facing wire (`ServiceCall` on `BROKER_PORT`) does not change.

## Invariants to hold throughout

- The moat survives: the host-agent daemon (keyless, does broker dispatch + parses untrusted guest input) and the signer helper (holds all signing keys) stay in separate address spaces.
- `vm_id` and `correlation_id` are server-derived, never guest-supplied.
- The control plane (Register/Deregister) is host-only (mode 0700) and host-signed — never guest-reachable.
- Claim 12 (binding-gated dispatch), claim 13 (no raw secret over the channel), the 20/s rate limit, and the 4 KiB cap are preserved, keyed by `vm_id`.
- No guest-facing protocol, port, or frame change — the SDK veneer and the in-guest `audit-probe` are untouched.
- **Tenant boundary by replication:** one (host-agent + helper) per tenant; each helper holds only *that tenant's* keys; the VM/jailer is the primary boundary and `mvmd` is the cross-tenant arbiter (ADR-084 §Tenant boundaries). Per-tenant keys are required, not optional.

## Phase 0 — ADR + plan

- [x] ADR-084 written (per-tenant daemon model, supersedes the in-process/per-VM split).
- [x] Plan 202 written (this doc).
- [ ] ADR-084 reviewed + accepted.

## Phase 1 — host-agent daemon (broker dispatch) + control plane

The host-agent daemon does broker dispatch and stays **keyless**; the signer it talks to is still the per-VM signer for now and becomes the supervised helper in Phase 2.

- [x] **1a — control protocol.** `mvm_hostd::broker::control`: `RegisterVm { vm_id, tenant_id, broker_listen_socket, workload_chain_path, audit_signer_uds_path, services_bindings }` / `DeregisterVm { vm_id }` under a `ControlRequest` enum, plus `SignedControl` (Ed25519 over JCS canonical bytes by the host signer key — the same discipline as the audit chain). 8 tests: serde roundtrip, `deny_unknown_fields`, sign→verify, tampered-request / tampered-sig / wrong-key / malformed-encoding / short-sig rejection. Types + sign/verify only; the daemon that binds the control UDS (mode 0700) and acts on these is 1b.
- [x] **1b — daemon skeleton.** `mvm_hostd::broker::daemon::HostAgentDaemon`: resident per-tenant, holds a `vm_id → VmHandle{socket, serve_task}` map; `apply(RegisterVm)` validates tenant + `vm_id` (path-safe guard), builds a per-VM `Registry` (its own `host.audit.v1` handler → that VM's audit-signer, so rate-bucket + chain are per-VM), binds the VM's `BROKER_PORT` socket, and `tokio::spawn`s `serve_on_listener`; `apply(DeregisterVm)` drops the `VmHandle` (RAII: abort task + unlink socket). `run(control_socket)` binds the per-tenant control UDS (mode 0700, host-only), reads host-signed `SignedControl` frames, verifies, applies, replies `ControlResponse`. New `mvm-host-agent` bin (reads `HostAgentConfig` on stdin, loads the host pubkey, runs the daemon) — the existing per-VM `mvm-broker` bin is left intact until Phase 6. Existing `ServiceCall` dispatch + claim-12 gate reused unchanged.
- [x] **1c — `ensure_daemon` + `register_vm`.** New `mvm_backend` seam replacing `spawn_broker` in the start path: lazily start the per-tenant host-agent daemon (idempotent; pid/lock under the run dir so concurrent `up`s converge on one) and send `RegisterVm`. `stop()` sends `DeregisterVm` (no daemon teardown — it stays warm). Landed behind `MVM_HOST_AGENT_DAEMON=1` (default flips in Phase 3 after the live re-verify).
  - [x] **1c-prep** — control protocol moved to `mvm-core` so the backend (which can't depend on `mvm-hostd`) shares the types.
  - [x] **1c-wire-a (seam)** — `mvm_backend::host_agent_spawn`: `ensure_host_agent_daemon` (flock-idempotent spawn of `mvm-host-agent` per tenant → control socket; reuses `resolve_subprocess_bin`/`spawn_detached_with_config`/`wait_for_uds`), `register_vm`/`deregister_vm` (sign with the host key via `mvm-core`'s `SignedControl::sign_with_key_bytes`, sync framed control client, surface `ControlResponse::Err`). `host_agent_dir`/`host_agent_control_socket` path helpers added to `mvm-core::config`. Additive — **not yet wired into `start()`/`stop()`**. 4 tests (sign+send accepts Ok, Err surfaced, sign_with_key_bytes).
  - [x] **1c-wire-b** — `start()`/`stop()` (libkrun + vz) branch onto the seam behind `MVM_HOST_AGENT_DAEMON=1` (default stays the proven per-VM fork). `register_host_agent_services_if_admitted` (spawn per-VM audit-signer + `ensure_host_agent_daemon` + `register_vm`, writes a `host-agent.tenant` ref) + a unified `ServicesGuard` (Fork/Agent/None) defused on success; `stop()` calls `reap_host_agent_services_from_state` (reads the ref → deregister + reap audit-signer) alongside the fork reap — each a no-op for the other path, so `stop()` needs no flag. 5 seam tests. The real-`mvm-host-agent`-bin live round-trip is the Phase 3 re-verify (when the default flips).
- [x] **1d — identity is server-derived.** Each VM's socket has its own serve task + `Registry`, and `vm_id` is threaded from registration into dispatch — the guest frame carries none. Test `registered_vm_dispatches_through_its_own_registry_with_server_correlation` proves a guest-picked `correlation_id` is replaced by a server `brk-*` id; the per-VM-socket structure means a guest can only reach its own VM's bindings.

**Verify:** `cargo test -p mvm-hostd -p mvm-backend`; unit test for register→bind→dispatch→deregister→unbind; concurrent-`up` converges-on-one-daemon test.

## Phase 2 — signer helper (the one key-holding address space)

The signer becomes a **supervised helper** of the host-agent daemon, holding **all** of the tenant's signing keys, so the host agent is keyless including admission.

- [ ] **2a — helper + per-VM heads.** The signer helper is resident per tenant (a child the host agent supervises), holding the tenant's key(s), with a `vm_id → in-memory chain head` map; `RegisterVm` opens/owns that VM's `<tenant>.<vm>.workload.jsonl`, `DeregisterVm` flushes + closes it. Single-writer per file preserved by one owning process.
- [ ] **2b — host-agent→helper forwarding tagged by server `vm_id`.** The host agent forwards each accepted audit entry with the server-derived `vm_id`; the helper routes to the right head and stamps `category: workload_audit`. Cross-VM forgery test (guest A cannot land in B's chain).
- [ ] **2c — admission signing moves to the helper.** Plan admission (`host_signer`) signs via the helper too, so the keyless-host-agent invariant covers admission as well as audit — one helper holds every key. Existing claim-8 admission tests stay green through the indirection.
- [ ] **2d — restart rebuilds heads.** On helper restart, rebuild each head from the persisted secondary head + re-bind from the live registration set; chain stays append-only (no fork). Kill-and-restart test asserts the chain still `verify_workload_chain`s clean across the restart.

**Verify:** `verify_workload_chain` clean before and after a signer restart; per-VM chains isolated; `cargo test -p mvm-hostd`.

## Phase 3 — decouple availability from the egress bridge

- [x] **3a — daemon is the default.** `host_agent_daemon_enabled()` inverted: **default on**, `MVM_HOST_AGENT_DAEMON=0` is the opt-out escape hatch back to the per-VM fork during the soak. An admitted `up` already threads `tenant_id` unconditionally (the broker-spawn decoupling), so a plain `up` registers with the daemon and `host.audit.v1` is reachable **without `MVM_GATEWAY_BRIDGE`** — that flag now gates *only* the egress bridge / L4 policy. Catalog services still require an explicit `services` binding (dispatch-gated).
- [ ] **3b — cost is `O(active tenants)`, not zero-per-workload.** Per ADR-084 `host.audit.v1` is implicitly available to *every* admitted workload, so the daemon runs whenever a tenant has an admitted workload — but it is **per-tenant and warm**, so the host-services process cost is `O(active tenants)`, not `O(VMs)`. (The per-VM audit-signer is still forked until Phase 2.) "Zero cost when unused" holds at the install level — no admitted workloads ⇒ no daemon.
- [x] **3c — `mvmctl doctor`** reports the per-tenant daemon state (running / warm / absent) so the move from per-VM is observable. The `host-agent daemon` platform check enumerates `<MVM_DATA_DIR>/host-agent/<tenant>/`, reports warm daemons by live `daemon.pid` + `control.sock`, flags stale pid/socket artifacts, and stays informational so first-run machines are not blocked.

**Verify:** a plain `mvmctl up --tenant local` (no `MVM_GATEWAY_BRIDGE`) makes `host.audit.v1` reachable — **PROVEN live on libkrun 2026-06-16**: the daemon spawned per-tenant (control socket mode 0700), bound the VM's `BROKER_PORT` socket on register, the in-guest probe's 22 emits verified clean via `verify_workload_chain`, and teardown deregistered while the daemon stayed warm. The `MVM_HOST_AGENT_DAEMON=1` boot proved the path; the default-on boot is the same code with the env-default flipped. The `doctor` line is covered by `host_agent_daemon_summary_reports_absent_warm_and_stale`; vz live-verify remains.

## Phase 4 — supervision + crash semantics

- [ ] **4a — registration journal.** Persist the live registration set so a restarted daemon re-binds sockets + reopens heads for still-running VMs.
- [ ] **4b — supervised restart.** `mvm` restarts a crashed local daemon; document the blast-radius trade. Crash-mid-flight test: a kill during dispatch loses at most the in-flight call, never corrupts a chain.

**Verify:** kill-and-restart leaves every running VM's `host.audit.v1` working and chains clean.

## Phase 5 — mvmd adoption + tenant boundaries (cross-repo)

mvmd replicates the local unit — **one (host-agent + helper) per active tenant** — and is the cross-tenant arbiter. It does not reimplement the daemon.

- [ ] **5a — coordinator replicates per tenant.** mvmd starts/supervises one (host-agent + helper) per active tenant at host init (not per VM), registering VMs as it launches them under the right tenant. Tracked in mvmd Plan 52; this repo exposes the daemon + control protocol as the shared surface.
- [ ] **5b — per-tenant keys.** Each tenant's helper holds only that tenant's signing key(s); mvmd mints/scopes them. A cross-tenant sign/forge attempt is refused (test).
- [ ] **5c — boundary tests.** A VM of tenant A cannot reach tenant B's host agent or write tenant B's chain (the VM's socket is bound only by A's daemon); tenant-scoped authz on cross-VM requests is mvmd's (ADR-084 §Tenant boundaries).
- [ ] **5d — density check.** Confirm `O(active tenants)` process count under a fleet-shaped load (many VMs, few tenants).

## Phase 6 — closeout

- [ ] Remove `broker_services_spawn::spawn_broker_services_if_admitted` (per-VM fork) and its call sites once the daemon path is the default on libkrun + vz.
- [ ] Update ADR-059 status to note its process model is superseded by ADR-084.
- [ ] `specs/REFACTOR-STATUS.md` + this plan ticked; CLAUDE.md "process moat" description updated (per-tenant daemon, not per-VM subprocess).

## Success criteria

- `host.audit.v1` works on a plain admitted `mvmctl up` (libkrun + vz) with no `MVM_GATEWAY_BRIDGE`.
- One host-agent daemon + one signer helper **per tenant**, warm across VM churn; a user's many VMs add zero processes; a no-services plan starts neither.
- Live round-trip + `verify_workload_chain` green, including across a daemon restart.
- Claim 12/13, rate limit, cap, and server-derived identity all preserved (existing tests stay green; cross-VM/cross-tenant forgery tests added).
- mvmd replicates the unit per tenant with per-tenant keys; cross-tenant reach/forge refused (ADR-084 §Tenant boundaries).

## Deferred / follow-ups

- [ ] Per-tenant **secrets dispatcher** (`host.secrets.v1`, ADR-059) folded into the same register/deregister model (it is the next catalog service after audit/time/cost).
- [ ] Whether the broker control socket should carry a nonce/replay guard beyond host-signing (host-only access makes it low-risk, but worth a look when secrets ride the same plane).
