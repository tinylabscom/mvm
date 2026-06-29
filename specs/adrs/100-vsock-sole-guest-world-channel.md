# ADR-100 — vsock is the sole guest↔world channel (no guest NIC; egress via a host vsock gateway)

**Status:** Accepted (2026-06-29)
**Relates to:** [ADR-002](002-microvm-security-posture.md) (claim 10 — default-deny
egress), [ADR-049](049-vsock-substitution-service.md) (vsock substitution),
[ADR-059](059-host-services-broker.md) (host-services broker over vsock),
[ADR-082](082-rust-native-egress-gateway.md) (in-house egress gateway),
[ADR-083](083-workload-backend-type-bar.md) (`WorkloadBackend`),
[ADR-099](099-multi-backend-hypervisor-abstraction.md) (the backend seam),
[Plan 214](../plans/214-clean-replacement-architecture.md).

## Context

A guest can reach the host/outside world over two planes:

- **Control plane** — host↔guest agent traffic (console, exec, file ops, secrets,
  the host-services broker, time/cost). This is **already vsock-only on every
  backend** (`mvm-guest`'s vsock protocol); there is no SSH, serial, or other
  control side-channel in any rootfs.
- **Data plane** — the guest workload's *network* egress (it calling an API, a
  registry, etc.). This is **not** uniform today: Firecracker gives the guest a
  virtio-net NIC with host nftables default-deny; libkrun/vz give a virtio-net
  NIC through the gvproxy/passt **gateway-bridge** with a `PlanFlowPolicy`. Each
  is host-enforced (claim 10 holds), but each is a *different* mechanism, and each
  puts a NIC + IP stack inside the guest.

An in-house vsock-mediated egress path already exists (the substitution service —
ADR-049 — and the `WorkloadBackend` seam, ADR-083), but it is parity-gated, not
the universal default.

The Plan 214 brief is explicit: **no guest NIC by default; host/vsock-mediated
networking with endpoint allowlisting.** This ADR makes that a hard, backend-wide
invariant rather than a per-backend choice.

## Decision

**A workload guest's only channel off the guest is vsock to the host.** There is
no guest NIC. Everything bound for the outside world flows:

```
guest app → vsock → host gateway (policy chokepoint, claim-10 default-deny) → outside
```

Precisely, for every workload backend — **HVF, Firecracker, libkrun, vz** (and any
future backend, e.g. KVM/WHP):

1. **No virtio-net device** is attached to a workload guest. No tap, no
   passt/gvproxy bridge, no in-guest IP stack on the workload path.
2. **All egress is vsock-mediated** through a single host gateway that enforces
   the signed `ExecutionPlan`'s network policy (default-deny; ADR-002 claim 10),
   the same code on every backend (the gateway is the seam from ADR-082/083, fed
   by the substitution service from ADR-049).
3. **All host services** (secrets, broker, console, exec, file ops) remain over
   vsock (already true; ADR-059).

The guest therefore has exactly one device class for talking to anything: vsock.

## Why (not just preference)

- **One enforcement seam.** Claim 10 is enforced in *one* host gateway, identical
  across backends — instead of auditing three mechanisms (FC nftables, the
  libkrun/vz gateway-bridge, …). A vsock stream cannot bypass it: there is no
  other route out of the guest.
- **Smaller guest attack surface.** No virtio-net driver, no in-guest IP stack,
  no NIC to escape from or to misconfigure into an open route.
- **Backend-agnostic.** vsock exists on every VMM we support, so the egress model
  no longer depends on each VMM's netdev. A new backend gets egress + policy "for
  free" by speaking the gateway's vsock protocol — nothing per-VMM to re-audit.
- **Composes with the rest of Plan 214.** The control plane is already vsock-only;
  this makes the data plane match, so the whole guest↔world surface is one
  transport with one policy.

## Cost / consequences

- The host gateway is an **L4/L7 proxy** (the in-house gateway, ADR-082; fed by
  the substitution service, ADR-049), not transparent IP routing. Every protocol
  flows through it; protocols it doesn't model don't get out (which is the point —
  fail-closed — but it must cover what workloads need: TCP connect, DNS, TLS
  passthrough).
- **Migration, not a flag flip.** Firecracker, libkrun, and vz currently attach a
  virtio-net NIC; converging them means routing their egress through the vsock
  gateway and **retiring the virtio-net paths** (nftables install, gateway-bridge,
  passt/gvproxy spawn). Staged, like the Vz sunset.
- Workloads that assume a real NIC (raw sockets, inbound listeners, non-TCP
  protocols) are not supported on the workload path by design; inbound is a host
  port-forward terminated at the gateway, not a guest-side listener on a NIC.

## Scope

- **Workload guests: in scope, mandatory.** Every backend that carries an
  untrusted workload (`AnyBackend::as_workload_backend == Some`).
- **The builder VM is a separate, explicitly-tracked case.** It is a dev/test
  substrate (Tier 2, outside the numbered claims — ADR-002 §tier matrix) that
  fetches nixpkgs; during the transition it may retain a host gateway NIC. Moving
  the builder onto the same vsock gateway is desirable but tracked independently
  of the workload invariant so it never blocks it.
- The **QEMU** backend is dev/test only (Tier 2, claim-10 not wired — ADR-002);
  it is held to the invariant on the workload path for uniformity, but its
  non-enforcement is already documented and it is never `auto_select`ed.

## Implementation / migration plan

1. **HVF implements it natively (reference).** HVF has no NIC today, so it is the
   clean slate: its egress is vsock-only from the first line — guest → vsock →
   host gateway with claim-10 default-deny. This becomes the model the others
   converge to (and is HVF's "workload parity" networking step).
2. **Converge Firecracker / libkrun / vz** onto the same host vsock gateway; then
   delete their virtio-net attach paths.
3. **CI guard.** A lint/test asserts no workload guest config attaches a
   virtio-net device (no `add_net` / tap / passt / gvproxy on the workload path),
   so a regression that re-adds a guest NIC fails closed — the machine-checked
   form of this invariant.

## Alternatives considered

- **Keep per-backend NICs with host-enforced default-deny (today's posture).**
  Rejected as the *end state*: claim 10 holds, but it is three mechanisms to
  audit and keeps an IP stack in every guest. Acceptable only as the transition
  state while backends converge.
- **A guest NIC routed to a host gateway (no in-guest policy, but a real NIC).**
  Still a NIC + IP stack in the guest and still per-VMM netdev wiring; gives up
  the single-seam and surface-reduction wins. Rejected.
