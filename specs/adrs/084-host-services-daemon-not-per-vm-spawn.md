# ADR-084: Host services as a per-tenant daemon, not per-VM spawn

- Status: Proposed
- Date: 2026-06-16
- Owner: MVM Project
- Related: ADR-059 (host services broker over vsock — this revises its process model), ADR-049 (TLS substitution mechanism), ADR-002 (microVM security posture — claims 12/13), ADR-041 (signed audited execution plans — claim 8), mvmd Plan 52 (host-services consumer, open)
- Sequenced by: [Plan 202 — Host services daemon](../plans/202-host-services-daemon.md)

## Context

ADR-059 specified the host-services broker as an **in-process** listener inside the per-VM supervisor, with `host.secrets.v1` split into a dedicated subprocess. The implementation that actually shipped (the E5.3b-2 spawn stack) diverged: both the broker **and** the audit-signer became **per-VM detached subprocesses**, forked from `mvmctl up` via `mvm_backend::broker_services_spawn::spawn_broker_services_if_admitted` — one `mvm-broker` and one `mvm-audit-signer` `setsid` child per admitted VM, each binding a UDS, readiness-polled, then reaped on stop.

That model has two problems we hit grounding the first live in-guest `host.audit.v1` round-trip:

1. **It is fork-per-request at the wrong granularity.** `N` VMs cost `2N` host processes plus a fork/exec/bind/poll cycle on *every* boot. mvm tolerates that for one dev VM; `mvmd`, whose entire point is density (dozens–hundreds of microVMs per host), cannot. This is the CGI-fork antipattern where a resident daemon belongs.

2. **Availability got coupled to egress.** The broker only spawns when `up` threads `tenant_id` into the launch, and `up` only does that under `MVM_GATEWAY_BRIDGE=1` (`should_thread_signed_plan`). So on a normal admitted `mvmctl up`, `host.audit.v1` is silently absent — a workload's `emit` fails with a transport error for a reason that has nothing to do with audit. The gating signal is the egress bridge, which is the wrong axis entirely.

The moat that the two-process split exists to provide is real and must survive: the broker parses **untrusted guest frames** (the fuzzed surface, claim 5) and must never share an address space with the **host signing key** (claim 13 — no raw secret crosses the broker channel). But that is an *address-space* boundary between *two roles*; it does not require a process *per VM*. Two processes total satisfy it.

`mvmd` is the production consumer of this surface (its host-services work is open), and we want the same capability locally in `mvm`. Whatever process model we pick is the one `mvmd` inherits at fleet scale — so the decision has to be made for density now, not retrofitted later.

## Decision

Host services run as **two long-lived daemons, scoped per tenant**, that VMs **register with** at boot and **deregister from** at teardown. There is no per-VM fork.

- **`mvm-broker` daemon (per tenant)** — guest-facing dispatch. Holds no keys. Owns a control socket; binds each registered VM's `BROKER_PORT` socket dynamically and demultiplexes accepted connections to a `vm_id` by *which socket accepted them*. Enforces the admitted plan's `services` bindings (claim 12) and the per-workload rate limit, both keyed by `vm_id`.
- **`mvm-audit-signer` daemon (per tenant)** — holds the tenant signing key and is the single writer to every per-VM workload chain (`<tenant>.<vm>.workload.jsonl`), one in-memory chain head per `vm_id`. The broker forwards each accepted entry tagged with a **server-derived** `vm_id` (never guest-supplied) for the signer to route and stamp `category: workload_audit`.

Per tenant, that is **two** processes regardless of VM count. Per host it is `O(active tenants)`, never `O(VMs)`.

VM lifecycle becomes registration:

- **start** → `ensure_daemons(tenant)` (lazy, idempotent; warm after the first VM) → `Register { vm_id, broker_listen_socket, services_bindings, workload_chain_path }`. The supervisor splices the guest's `connect_host_vsock(BROKER_PORT)` to `broker_listen_socket` exactly as today — the backend-specific path is unchanged.
- **stop** → `Deregister { vm_id }` → the broker unbinds and drops that VM's socket; the signer flushes and closes that VM's chain head.

Registration is driven by the **admitted plan**, not by `MVM_GATEWAY_BRIDGE`. A plan that binds no host services registers nothing and spawns nothing — same zero-process outcome as today, but for the right reason. `host.audit.v1` is implicitly available to any admitted workload (emitting to your own chain is a low-risk, broadly useful capability); the catalog services (`time`, `cost`, secrets, future addons) require an explicit `ExecutionPlan.services` binding and are dispatch-gated on it.

### Scope: per tenant

The broker holds no secrets, so a single host-wide broker handling every tenant would be functionally sufficient. We reject it for **defense in depth**: a parsing bug in a daemon that eats untrusted guest input must not be a cross-tenant confidentiality boundary, and the audit-signer holds a tenant-scoped signing key that must not be reachable from another tenant's traffic. One daemon pair per tenant makes the process boundary the tenant boundary. For local `mvm` that is one tenant (`local`) and therefore one pair; for `mvmd` it is one pair per *active* tenant on the host — bounded by tenancy, not by fan-out.

## Architecture

### Identity is server-derived

`vm_id` for every dispatched call and every signed entry comes from the socket that accepted the connection, established at `Register` time — never from a field in the guest frame. This is the same discipline the broker already applies to `correlation_id` (the supervisor reassigns a server-authoritative id at ingress). A compromised guest therefore cannot address another VM's bindings or write another VM's chain, even within one shared broker process.

### Registration control plane

The daemons listen on a per-tenant control socket under the run dir (e.g. `<run>/broker-control-<tenant>.sock`, mode 0700, host-owned). `Register`/`Deregister` are signed by the host (the same host identity that signs plans), so a guest — which has no access to the control socket — cannot register or unbind sockets. The wire `ServiceCall`/`ServiceResponse` shape on `BROKER_PORT` is unchanged from ADR-059; only the *owner* of the per-VM socket moves from a per-VM fork to the resident daemon.

### Crash and restart

A resident per-tenant daemon has a larger blast radius than a per-VM child: its crash drops host services for every VM of that tenant. Mitigations:

- The daemon is **supervised** — by `mvm` locally and by `mvmd`'s host agent in the fleet — and restarted.
- Chain integrity survives restart: each per-VM head already persists out of band (the secondary head file), so the signer rebuilds heads from disk + the live registration set rather than forking the chain. A restart re-binds sockets for the still-registered VMs from the journal.
- This is the ordinary resident-daemon bargain (nix-daemon, containerd) and is the correct trade for `O(tenants)` instead of `O(VMs)` processes.

### Why not fold the broker into the supervisor

Considered: drop the broker process entirely, handle `BROKER_PORT` inline in the per-VM supervisor (which already parses guest vsock I/O), keep only the shared signer. Rejected: the supervisor is the VMM — already the largest, most-exposed TCB — and widening it with host-service dispatch is the wrong direction. Dispatch stays in a separate, keyless, *shared* daemon.

## Security model

The claim-12 (binding-gated dispatch) and claim-13 (no raw secret over the broker channel) properties are **preserved unchanged** — this ADR moves *where the two roles live*, not *what they may do*:

- Two address spaces still separate the untrusted-input parser (broker, keyless) from the key holder (signer). `2` per tenant instead of `2N`.
- `vm_id` and `correlation_id` remain server-authoritative — a guest cannot forge cross-VM identity, and the per-tenant process boundary blocks cross-tenant reach.
- The rate limit and the 4 KiB record cap stay host-side, now keyed by `vm_id` in the daemon's per-VM state.
- The signing key path stays pinned under the host key dir (the claim-8 trust boundary); the daemon model does not relax it.

### Surfaces that do not expand

The guest-facing wire (`ServiceCall` over `AuthenticatedFrame` on `BROKER_PORT`) is byte-identical to ADR-059. The new surface is the **host-side control socket** (Register/Deregister), reachable only by the host (mode 0700, host-signed messages), never by a guest. No new guest-reachable verb, port, or frame type.

## Alternatives considered

- **Per-VM subprocess (status quo).** Correct moat, wrong granularity: `2N` processes + per-boot spawn latency. Fails mvmd density. This ADR replaces it.
- **In-process broker in the supervisor (original ADR-059).** Avoids a separate broker process but puts guest-service dispatch in the VMM's address space and is still per-VM. Rejected for TCB and granularity reasons.
- **Single host-wide broker for all tenants.** Fewest processes, but a parsing bug becomes a cross-tenant boundary and one signer would hold every tenant's key. Rejected for tenant isolation; per-tenant is the chosen middle.
- **Lazy spawn on first guest dial.** Defers the cost but reintroduces per-VM processes and adds first-call latency inside the request path. The register-at-boot daemon gets the same "only when needed" property without per-VM processes.

## Consequences

### Positive

- Host-process count drops from `O(VMs)` to `O(active tenants)`; per-VM boot no longer pays a fork/exec/bind/poll cycle.
- `host.audit.v1` becomes available on a normal admitted `up`, decoupled from the egress bridge.
- One daemon + protocol is shared by `mvm` (local) and `mvmd` (fleet) — local is a single-tenant slice of production, not a different code path.
- The moat and all claim-12/13 properties are preserved.

### Negative

- Larger crash blast radius per tenant (mitigated by supervision + persisted heads + a registration journal).
- A registration control plane is new surface to implement, supervise, and reason about (host-only, host-signed).
- Revises a process model that just shipped; the per-VM spawn stack must be migrated, not extended.

## Migration

Phased in [Plan 202](../plans/202-host-services-daemon.md). The wire protocol on `BROKER_PORT` does not change, so guests, the SDK veneer, and the in-guest probe are untouched. The change is host-side: `spawn_broker_services_if_admitted` (fork) becomes `ensure_daemons` + `register_vm`, the daemons gain a control plane, and `mvmd`'s host agent adopts the same daemon per tenant.

## Out of scope

- The guest-facing wire format, the service catalog, and the capability-gating rules — all unchanged from ADR-059.
- Cross-VM / cross-tenant data delegation, which remains mvmd's tenant-scoped-authz responsibility (ADR-059 §Cross-VM delegation).
- The egress gateway bridge and its L4 policy enforcement — a separate axis that this ADR deliberately stops conflating with host-service availability.
