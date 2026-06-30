# ADR-101 — In-house VMM: one unified vsock egress gateway (claims 10/12/13 in one endpoint)

**Status:** Accepted (2026-06-30)
**Relates to:** [ADR-100](100-vsock-sole-guest-world-channel.md) (vsock is the sole
guest↔world channel — this ADR is the concrete in-house realization of its "single
host gateway"), [ADR-049](049-vsock-substitution-service.md) (vsock substitution),
[ADR-059](059-host-services-broker.md) (claims 12/13), [ADR-082](082-rust-native-egress-gateway.md)
(the gateway seam), [ADR-083](083-workload-backend-type-bar.md) (`WorkloadBackend`),
[ADR-002](002-microvm-security-posture.md) (claim 10), [Plan 214](../plans/214-clean-replacement-architecture.md).

## Context

ADR-100 made it a backend-wide invariant that a workload guest's only channel off
the guest is vsock, and that all egress flows through "a single host gateway that
enforces the signed `ExecutionPlan`'s network policy ... fed by the substitution
service." That ADR fixed the *principle*. It did not pin down how the in-house VMM
(HVF/KVM — `crates/mvm-backend/src/{vmm,hvf,kvm}`) realizes it concretely, and the
in-house path arrived at that principle from two directions that had not yet been
joined:

- **Raw-TCP egress (claim 10).** `vmm/egress_proxy.rs` (`EgressProxy`) treats the
  first frame on a `EGRESS_PORT` (5253) stream as a connect target `"ip:port"`,
  decides it against the claim-10 `EgressGate` (default-deny), then proxies raw
  bytes. This is the path the in-house VMM's claim-10 milestone proved (the
  `kvm-backend-egress` / `hvf-backend-egress` examples drive it directly).
- **Substitution (claims 12/13).** The guest's *only* egress client —
  `mvm-guest`'s forward-proxy (`forward_proxy.rs` → `substitution_client.rs`) —
  dials `EGRESS_PORT` and speaks the **WireRequest** protocol (4-byte BE length +
  JSON; `mvm_core::substitution_wire`). The host terminates TLS and injects the
  bound credential. The endpoint (`mvm-substitution-endpoint`) enforces the
  per-secret binding (claim 12) and never lets a raw secret cross (claim 13).

These two collide on one port. `EgressProxy` reads the WireRequest's length prefix
as a malformed `"ip:port"` and resets the stream — which is exactly why
secret-bearing (and in fact *all* forward-proxy) egress does not work on the
in-house VMM today. A guest contract for the resolution is already written
(`crates/mvm-guest/src/vsock.rs` `EGRESS_PORT`): 5253 is "the single host-mediated
egress chokepoint ... the host's per-VM gateway makes the claim-10 allow/deny
decision and proxies the flow, and for a bound-secret destination performs the
claims-12/13 credential substitution — **a behavior of this one gateway, not a
separate channel**." This ADR makes the host side match that contract.

The trigger is Plan 214: HVF must carry secret-bearing workloads (claims 12/13) to
retire Vz. Vz carries them over `EgressSubstitutionTransport::VsockUdsChannel` (the
supervisor splices a guest 5253 dial to the per-VM endpoint UDS). HVF must reach
the same capability without regressing the claim-10 it already has.

## Decision

**On the in-house VMM, `EGRESS_PORT` (5253) carries exactly one protocol — the
WireRequest substitution protocol — through one host gateway (the per-VM
`SubstitutionBridge`) that pipelines two enforcement stages on every request:
claim-10 at the bridge (the existing egress gate) and claims 12/13 at the per-VM
`mvm-substitution-endpoint`.**

1. **One protocol per route, chosen at configuration time — never by peeking the
   wire.** For a secret-bearing workload (a substitution endpoint is configured)
   5253 routes to the `SubstitutionBridge` and speaks WireRequest only — what the
   guest's sole egress client sends and what Vz terminates, so the guest image stays
   backend-agnostic. For a workload with no endpoint, 5253 keeps the legacy raw-
   `"ip:port"` `EgressProxy` route. The device picks the route from VM configuration
   (is an endpoint wired?), not from inspecting guest bytes — so there is no
   protocol-confusion surface between the two. The bridge does parse the first frame
   of its own protocol, but only to make the claim-10 decision; it never has to
   guess *which* protocol a stream is.

2. **A per-VM `SubstitutionBridge` in `vmm/` is the host gateway.** It bridges each
   guest→host 5253 vsock stream to the per-VM endpoint's Unix socket, keyed by the
   guest `src_port`, reusing the `EndpointTransport::Uds { path }` channel the
   libkrun/vz backends already use (so the endpoint binary is unchanged). It is
   **frame-aware for exactly one decision**: it buffers the first WireRequest frame,
   extracts the destination host:port from its `url`, and makes the claim-10
   allow/deny call (below) *before* opening the endpoint — then becomes a plain byte
   relay for the rest of the connection.

3. **Enforcement is a two-stage pipeline on the one stream** — both stages run for
   every request, so there is no protocol-confusion surface and no place to smuggle
   traffic past a gate:
   - **Claim 10 — at the bridge.** The bridge decides the destination against the
     *same* `EgressGate` the device's raw-egress path uses (`vmm/egress_gate.rs`,
     default-deny, DNS-pin host resolution). An unadmitted destination is refused
     *before the endpoint is contacted* — check-then-relay, never relay-then-check
     (which would leak bytes past the gate). This keeps claim-10 where the in-house
     VMM already enforces it (the egress gate) and keeps the secrets moat focused on
     secrets. **Why not in the endpoint:** folding the network policy into the
     shared `mvm-substitution-endpoint` would change the moat that *every* backend
     (Firecracker/libkrun/vz) spawns and force-touch all four spawn call sites for a
     gate the in-house VMM already owns. Enforcing at the bridge is HVF-local — zero
     shared-code change — and reuses the existing gate.
   - **Claims 12/13 — at the endpoint** (unchanged). Once admitted, the stream is
     relayed to the per-VM `mvm-substitution-endpoint`, which binding-checks the
     secret (claim 12 — unbound → `WireResponse::Refused`, no upstream) and never
     lets a raw secret cross (claim 13 — the guest holds only `mvm-secret-<hex>`).

4. **Lifecycle.** The endpoint is spawned/reaped through the existing shared moat
   (`substitution_spawn::{spawn_substitution_endpoint, reap_substitution_endpoint}`,
   `EndpointTransport::Uds`), called from `HvfBackend::{start,stop}` exactly as
   `VzBackend` calls it — unchanged: spawned when the admitted plan carries secret
   bindings, reaped before the not-running check on stop. The decrypted-secret
   process never outlives a failed launch (`EndpointGuard`) or the guest. The bridge
   is wired (endpoint socket + claim-10 gate) only when that endpoint exists; a
   secret-free workload keeps the legacy raw-egress path. Note this means a
   *no-secret but allow-listed* workload still egresses over the legacy path, not
   the WireRequest gateway — the same scope Vz has today; widening the bridge to all
   egress is a later step, not required to carry secret-bearing workloads.

5. **`HvfBackend` declares `EgressSubstitutionTransport::VsockUdsChannel`** and
   `backend.rs::as_workload_backend` returns `Some` for `Hvf` — but only **after**
   the path above is built and adversarially verified live (claims 12/13 + the
   protocol-confusion failure modes). Declaring the transport or flipping the gate
   on an unverified path would be a false security claim.

## Why option (b), not (a) multiplex or (c) two ports

- **(a) Multiplex 5253 by peeking the first frame** (raw `"ip:port"` vs. a JSON
  length prefix) puts a heuristic at the security boundary. The two protocols feed
  *different enforcers* (raw-TCP → claim-10 only; WireRequest → claim-12/13), so a
  guest that steers a stream to the weaker enforcer for a given destination is a
  bypass primitive. A byte-shape guess is precisely the confusion surface to avoid.
- **(c) Put substitution on a second vsock port**, leaving `EgressProxy` on 5253,
  contradicts ADR-100's single-chokepoint invariant and the already-written guest
  contract, and forks egress policy across two enforcers (the claim-10 gate would
  not see substitution traffic, and vice-versa) — the same split-brain risk as (a),
  just statically partitioned.
- **(b) One protocol, one gateway, a two-stage pipeline** is the chosen option: a
  secret-bearing stream is WireRequest only, through one host gateway that runs
  claim-10 (bridge) then claims 12/13 (endpoint) in sequence — no shape-guess, no
  split-by-protocol. It matches Vz (`VsockUdsChannel`) and the guest contract, so
  the guest image and the `WorkloadBackend` seam need no per-backend special-casing.
  Claim-10 lives at the **bridge** rather than inside the endpoint deliberately:
  folding the network policy into the shared `mvm-substitution-endpoint` would
  change the secrets moat that Firecracker/libkrun/vz all spawn and force-touch
  every spawn call site, to enforce a decision the in-house VMM's egress gate
  already makes. Bridge-side claim-10 is HVF-local (zero shared-code change) and a
  true pipeline (both stages run on every request), so it is not the split-brain of
  (a)/(c) — there is exactly one route a secret-bearing stream can take, and it
  passes both gates.

## Consequences

- The in-house VMM gains secret-bearing workload support and HVF can retire Vz
  (Plan 214) once verified.
- `EgressProxy` (`vmm/egress_proxy.rs`) stays the route for a no-endpoint workload;
  for a secret-bearing one, 5253 routes to the bridge instead. The `EgressGate`
  (`vmm/egress_gate.rs`) is shared by both routes — the device hands a clone to the
  bridge so claim-10 is one rule set whichever route a stream takes.
- The shared `mvm-substitution-endpoint` and its spawn path are **unchanged** by
  this ADR (no `network_policy` field, no touched call sites) — claim-10 is added
  at the HVF bridge, not the moat. The endpoint remains spawned only for a
  secret-bearing plan.
- Non-HTTP raw-TCP egress is **out of scope**: the WireRequest gateway is HTTP(S)
  absolute-form only, matching Vz's capability. The in-house VMM never carried a
  guest raw-TCP egress client, so nothing regresses. If a future workload needs
  raw-TCP egress it is a separate ADR (a CONNECT-style verb within the same
  endpoint, still one enforcer).

## Out of scope (same threat model, deferred)

- Productionizing the per-VM **agent** socket off the `MVM_HVF_AGENT_SOCKET` env
  hook onto a supervisor-config per-VM path (Plan 214 follow-up; orthogonal to
  egress enforcement, tracked alongside the gate flip).
- Auto-selecting HVF on macOS 26+ and deleting the Vz backend (Plan 214 endgame).
