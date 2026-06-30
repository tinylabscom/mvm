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
WireRequest substitution protocol — and exactly one enforcer: the per-VM
`mvm-substitution-endpoint`, which decides claims 10, 12, and 13 for every request.**

1. **One protocol on the wire.** 5253 speaks WireRequest only. This is what the
   guest's sole egress client already sends and what Vz already terminates, so the
   guest image stays backend-agnostic. The raw-`"ip:port"` `EgressProxy` protocol
   is spoken by no guest; it is **retired from the workload egress path** (the
   examples that drove it directly are reframed as device/relay tests, not a guest
   transport). There is no first-frame peek and therefore no protocol-confusion
   surface.

2. **A dumb host relay.** A per-VM `SubstitutionBridge` in `vmm/` bridges each
   guest→host 5253 vsock stream to the per-VM endpoint's Unix socket, mirroring
   `AgentBridge`/`EgressProxy` (transport-agnostic, keyed by the guest `src_port`,
   speaks raw bytes). It parses nothing and enforces nothing — it moves bytes
   between the device and the endpoint UDS. This reuses the
   `EndpointTransport::Uds { path }` channel the libkrun/vz backends already use,
   so the endpoint binary is unchanged on its listener side.

3. **All enforcement folds into the one endpoint** (option *b*, not multiplexing):
   - **Claim 13** — raw secret never crosses; the guest holds only `mvm-secret-<hex>`
     placeholders (unchanged endpoint behavior).
   - **Claim 12** — per-secret destination binding; an unbound destination →
     `WireResponse::Refused`, no upstream connection (unchanged).
   - **Claim 10** — the signed plan's network policy is added to `EndpointConfig`;
     the endpoint refuses any destination the policy does not admit (default-deny)
     **before** binding/forwarding. This is the new enforcement this ADR mandates,
     and it is *essential, not deferrable*: routing WireRequests to an endpoint
     that did not gate the destination would let a placeholder-free request reach
     any host — a claim-10 regression. One process now owns the whole egress
     decision.

4. **Lifecycle.** The endpoint is spawned/reaped through the existing shared moat
   (`substitution_spawn::{spawn_substitution_endpoint, reap_substitution_endpoint}`,
   `EndpointTransport::Uds`), called from `HvfBackend::{start,stop}` exactly as
   `VzBackend` calls it. It is spawned whenever the admitted plan permits egress
   (secret bindings present, or a network policy that admits any host). A pure
   default-deny / no-egress workload spawns no endpoint; the bridge's connect to
   the absent UDS then fails closed (no egress), which is the correct default-deny
   outcome. The decrypted-secret process never outlives a failed launch
   (`EndpointGuard`) or the guest (reap-before-not-running, as on Vz).

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
- **(b) One protocol, one enforcer** is the only option with no shape-guess and no
  split enforcement: every byte of guest egress is a WireRequest, decided in one
  process that holds claim-10, claim-12, and claim-13 together. It also matches Vz
  (`VsockUdsChannel`) and the guest contract verbatim, so the guest image and the
  `WorkloadBackend` seam need no per-backend special-casing.

## Consequences

- The in-house VMM gains secret-bearing workload support and HVF can retire Vz
  (Plan 214) once verified.
- `EgressProxy`'s raw-`"ip:port"` role on the workload path is superseded. Its core
  (`vmm/egress_proxy.rs`) and the `EgressGate` (`vmm/egress_gate.rs`) are not
  deleted in this step — claim-10 policy construction is reused by the endpoint —
  but the device no longer routes 5253 OP_RW to it for a workload guest.
- The endpoint subprocess is now an egress dependency for *any* admitted egress,
  not only secret-bearing egress. The fail-closed-on-absent-UDS property keeps a
  spawn failure safe.
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
