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

## The end state: one vsock egress gateway, no network layer

There is **no guest NIC and no host network-gateway layer at all**. A workload
guest has no `eth0` and no IP stack beyond loopback (used only by the in-guest
egress shim). Every outbound flow is the guest opening a **vsock** stream to a
single host-side **egress gateway**, which is the sole chokepoint and does *both*
jobs:

- **Claim 10** — the allow/deny decision (`EgressGate` over `CanonicalEgress`).
- **Claims 12/13** — for a bound-secret destination, the credential substitution
  (the placeholder→real-credential rewrite) the terminator does today.

This deletes the entire userspace network plane — **passt, gvproxy, the in-house
rvproxy, and the nft/redirect terminator all go away**. They exist only to gateway
a guest NIC's IP traffic; with no NIC there is nothing for them to do. "vsock ports"
(`5251` exit, `5252` agent, `5253` substitution, a new egress port) are just how the
single vsock transport multiplexes services — they are not network ports and not a
NIC.

**Protocol scope.** The gateway proxies **TCP**, and DNS is resolved host-side via
the pin registry. UDP/QUIC (HTTP/3), ICMP, and raw sockets are *not* carried by a
TCP-only gateway; if they come into scope they get an explicit datagram-over-vsock
path in the gateway — never a NIC. For headless TCP/HTTP(S) workloads this is the
full surface.

## Implementation / migration plan

1. **HVF implements it natively (reference).** HVF has no NIC, so it is the clean
   slate: guest → vsock → host gateway with claim-10 default-deny, live-proven.
2. **Converge Firecracker / libkrun / vz** onto the *same* single vsock gateway:
   move claim-10 egress **and** claims-12/13 substitution onto the vsock egress
   path, then delete the NIC attach **and** the whole gateway layer (passt /
   gvproxy / rvproxy / terminator) for workload VMs. The builder VM (not a
   workload) is out of scope and keeps its NIC.
3. **CI guard.** A lint/test asserts no workload guest config attaches a virtio-net
   device or a userspace gateway (no `add_net` / tap / passt / gvproxy / rvproxy on
   the workload path), so a regression that re-adds the network plane fails closed.

## Status (HVF reference, live-proven on Apple silicon)

Step 1 is realized on HVF:

- ✅ No guest NIC; the guest's only off-guest channels are vsock (control, the
  transient workload-exit signal, and egress).
- ✅ Egress **deny by default** — a NIC-less guest's connect request over vsock is
  refused unless policy admits it (`vmm::egress_gate` reuses the claim-10
  `CanonicalEgress`).
- ✅ Egress **allow + TCP proxy** when admitted — the host opens the socket and
  proxies bytes; an echo round-trips guest → vsock → host TCP → guest.
- ✅ The gate is built from the **admitted plan's `NetworkPolicy`**, with the
  supervisor **resolving host-allowlist DNS pins** at startup; fails closed.
- ✅ **Async bidirectional streaming** — replies / server-push reach a guest
  blocked in `recv` (WFI), not just inline request/response. The run loop takes a
  `should_stop` predicate so a forced exit (`Canceled`) polls host-side I/O before
  ending; the HVF watchdog doubles as a ~5 ms heartbeat that `force_exit`s the
  vCPU to break WFI, so `drain_egress` runs and the vsock rx IRQ wakes the guest.
  (Root cause: `hv_vcpu_run` sleeps on WFI, so the loop otherwise never returns to
  drain the socket — confirmed by tracing.)
- ✅ **CI guard** (`xtask check-vsock-only-egress`) keeps the vmm/HVF path NIC-free.

Step 1 (HVF reference) is complete, and the shared host-side pieces for Step 2 are
built + unit-tested: the transport-agnostic `EgressProxy` core, the in-guest
SOCKS→vsock client (`mvm-egress-client`), and the async host egress server
(`mvm_vm_host::egress_server`, reusing `EgressGate`). Step 2 — converge
Firecracker/libkrun/vz onto the single vsock gateway (egress **+** substitution),
delete the NIC + gateway layer, widen the CI guard — remains; it changes the
claims-12/13 implementation (substitution moves onto the vsock path), so it is a
security-touching, per-backend change. See
`specs/notes/2026-06-29-adr100-step2.3-libkrun-cutover-plan.md`.

## Alternatives considered

- **Keep per-backend NICs with host-enforced default-deny (today's posture).**
  Rejected as the *end state*: claim 10 holds, but it is three mechanisms to
  audit and keeps an IP stack in every guest. Acceptable only as the transition
  state while backends converge.
- **A guest NIC routed to a host gateway (no in-guest policy, but a real NIC).**
  Still a NIC + IP stack in the guest and still per-VMM netdev wiring; gives up
  the single-seam and surface-reduction wins. Rejected.
- **Keep the userspace network gateway (passt / gvproxy / rvproxy) and enforce on
  it.** This is today's transition posture and what claims 10/12/13 are built on
  for the NIC backends. Rejected as the end state: it keeps an IP stack in every
  guest and a userspace network plane (three proxies + an nft/redirect terminator)
  to audit, when vsock already gives one host↔guest channel. The gateway exists
  only to service a guest NIC; removing the NIC removes the reason for it. Its one
  real capability beyond a TCP vsock gateway is arbitrary-IP/UDP — addressed by a
  datagram-over-vsock path if needed, not by retaining the network plane.
