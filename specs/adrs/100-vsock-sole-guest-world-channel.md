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

There is **no guest NIC and no host network-gateway layer at all** — no `eth0`, no
bridged/external interface, no userspace network gateway (passt/gvproxy/rvproxy).
Every outbound flow is the guest opening a **vsock** stream to a single host-side
**egress gateway**, which is the sole chokepoint and does *both* jobs:

- **Claim 10** — the allow/deny decision (`EgressGate` over `CanonicalEgress`).
- **Claims 12/13** — for a bound-secret destination, the credential substitution
  (the placeholder→real-credential rewrite) the terminator does today.

This deletes the entire userspace network plane — **passt, gvproxy, the in-house
rvproxy, and the nft/redirect terminator all go away**. They exist only to gateway
a guest NIC's IP traffic; with no NIC there is nothing for them to do.

**One egress port, not two — substitution is a behavior.** Credential substitution
is not a separate channel or port; it is what the egress gateway *does* when a
flow's target is a bound-secret host. So there is a single **egress-gateway port**
(`EGRESS_PORT` — the number `SUBSTITUTION_PORT` already used, since the substitution
channel was always host-mediated egress), alongside `5251` workload-exit and `5252`
agent control. Each microVM has its **own** vsock transport (its own device + host
endpoint + per-VM gateway/policy); these port numbers are a fixed, well-known
*service map* reused per VM — a constant like a registered TCP port, not a secret and
not per-VM-unique. Isolation is in the per-VM transport + per-VM policy, never in the
port number. Concurrent egress streams from one guest share the one egress port,
distinguished by the guest's source port.

**Protocol scope.** The gateway proxies **TCP**, and DNS is resolved host-side via
the pin registry. UDP/QUIC (HTTP/3), ICMP, and raw sockets are *not* carried by a
TCP-only gateway; if they come into scope they get an explicit datagram-over-vsock
path in the gateway — never a NIC. For headless TCP/HTTP(S) workloads this is the
full surface.

## Two planes over vsock: control + transparent data

A workload guest's vsock carries two distinct things, both already per-VM and
policy-gated:

**Control plane (commands).** Multiplexed by well-known vsock port:
- `5252` **guest agent** — host→guest `GuestRequest` control: `ProtocolHello`
  (capability negotiation), `Ping`, `WorkerStatus`, `SleepPrep`/`Wake` (warm-pool
  lifecycle), `PrimedStatus` (warm-snapshot barrier), `CheckpointIntegrations`,
  `ProbeStatus`, `Exec` (dev-only), + the agent RPC family.
- `5300` **broker** — workload→host `ServiceCall`, binding-gated + audited (claims
  12/13): `host.secrets.v1` (destination/time-bound creds — no raw secret crosses),
  `host.audit.v1`, `host.time.v1`, `host.cost.v1`.
- `5251` workload-exit, `5253` egress gateway, `10000+` port-forward, `20000+`
  console, `5301` ssh-agent (dev).
New control surface = a new `host.<svc>.v1` broker method or a new `GuestRequest`;
both ride the existing gated/audited paths.

**Data plane (egress) — vsock is the *only* primitive (hard invariant).** This is
the security design, not merely minimalism: a workload guest has **no NIC, no IP
routing, no userspace network gateway (no gvproxy/passt/rvproxy), no TUN, no
netfilter.** Its sole means of reaching anything off-guest is an `AF_VSOCK` stream to
the host egress gateway. There is no network in the guest to attack, misconfigure, or
escape onto; a direct `connect(realIP)` has nowhere to route, so egress is *only*
possible by asking the host. The reach the guest has is exactly what the host's
policy grants — enforced by **absence of any other path**, not by a firewall the
guest could fight.

How a workload's traffic gets onto vsock without an in-guest IP stack:

- **Runtime/SDK-native (the production path).** The mvm runtime serves the workload's
  egress through the in-guest `mvm-egress-client` (loopback SOCKS5 → vsock) and sets
  `ALL_PROXY=socks5h://127.0.0.1:<port>`. Standard HTTP clients (curl, requests,
  fetch, Go `net/http` — all honor proxy env) thus reach the network transparently
  with **only loopback present** — no NIC, no route, no netfilter, no IP stack beyond
  `lo`. The mvm SDK wires this automatically, so SDK workloads are transparent. With
  `socks5h`, the client sends the **hostname**, not a resolved IP — so DNS happens
  *host-side* (see below); the guest never resolves and never needs a resolver.
- **AF_VSOCK-native (the purest variant).** A workload (or the runtime) speaks the
  vsock egress protocol directly — zero IP stack at all, not even loopback. Used where
  the runtime fully owns the socket layer.

The **host side is unchanged in shape**: the egress gateway takes `(target,
byte-stream)` → claim-10 decide → proxy. HTTPS is forwarded TCP bytes (no
termination); TLS-terminating credential substitution is the separate claims-12/13
behavior, only for bound-secret hosts.

**DNS = host-side resolution over vsock (no guest resolver).** Because the client
uses `socks5h`, the guest sends `"hostname:port"` over vsock and the **host** gateway
resolves the name — checking it against the claim-10 host-allowlist / DNS pin registry
*before* connecting, and connecting to the pinned IP. This is "DNS-over-vsock" in the
literal sense: the name travels the vsock and the trusted host does the lookup +
policy check. No `mvm-addon-dns`, no in-guest UDP/53. (Policies are naturally
host-based — "allow `api.stripe.com:443`" — so host-side name resolution *is* the
enforcement point.)

**Explicitly out of scope (deliberate trade):**
- *Full transparency for arbitrary raw `AF_INET` binaries.* A static binary that
  ignores proxy env and calls `connect(realIP)` directly cannot be intercepted
  without an in-guest IP stack (TUN/netfilter) — which this design **rejects** (it
  would re-introduce "a network in the guest"). Such workloads must use the
  SDK/runtime egress. We accept a strictly smaller, unbypassable guest over
  capturing raw IP egress.
- *UDP/QUIC (HTTP/3), ICMP, raw sockets.* Not carried by a TCP vsock gateway; they'd
  need a datagram-over-vsock channel, never a NIC.

The `spikes/transparent-egress/` (netfilter REDIRECT) and the TUN+`smoltcp` sketch
are **illustrative of full transparency only — not the production direction**: both
require an in-guest IP stack, which the hard invariant above forbids.

## Security model + mvmd integration

**The host egress gateway is the trust boundary. Everything in the guest is
untrusted.** The guest can express *intent* ("connect me to `host:port`, here are
the bytes"); it cannot *act*. The host makes the real connection, on the guest's
behalf, only if the admitted policy permits it. Concretely:

- **Guest-side code is untrusted plumbing.** `mvm-egress-client`, `ALL_PROXY`, and
  the (rejected-for-production) TUN/netfilter spikes are conveniences for getting a
  workload's bytes onto vsock. None of them enforces anything — a fully compromised
  guest (root) can tamper with all of it. Security does **not** depend on them.
- **The boundary is the host gateway**, outside the guest's control: it makes the
  claim-10 decision, resolves names against the pin registry, opens the socket, and
  for bound-secret destinations performs the claims-12/13 substitution (the guest
  never receives raw secrets). A compromised guest still reaches only what policy
  admits, because it has no other path out and the host is the one dialing.
- **Confined transport.** vsock is host↔guest point-to-point (guest can only address
  CID 2); no NIC means no L2/L3, no lateral movement to other VMs, no raw-packet
  exfil. The attack surface collapses to "the messages the guest sends the gateway",
  which are parsed by a fuzzed parser (claim 5) and policy-checked.

**mvmd (the orchestration layer) owns policy; the per-VM host gateway enforces it.**
This is the control-plane / data-plane split:

- **mvmd = control plane.** It owns tenants/pools and authors each workload's
  `NetworkPolicy` (the claim-10 allow-list of `host:port` it may reach, the
  bound-secret → destination bindings), signs it into the `ExecutionPlan`, and
  schedules the microVM.
- **host gateway = data-plane enforcement.** Per VM, it builds its `EgressGate` from
  the admitted plan's `NetworkPolicy`, then decides every vsock egress request
  (default-deny), resolves names host-side against the pins, and emits chain-signed
  audit entries. The same plan drives substitution.

So the fleet decides *what each microVM is permitted to reach*; the per-VM gateway
enforces it on every request, with no egress path the guest can take around it. This
is capability-based egress at fleet scale, and it is exactly the property mvmd needs
to safely run untrusted multi-tenant workloads.

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
4. **Guest egress shim = `mvm-egress-client` (loopback SOCKS5 → vsock), the runtime
   sets `ALL_PROXY`.** No in-guest IP stack beyond `lo`; no TUN, no netfilter. The
   `spikes/transparent-egress/` REDIRECT prototype and the TUN+`smoltcp` sketch are
   **illustrative of full transparency only and are not productionized** — they need
   an in-guest IP stack, which the hard invariant forbids.
5. **DNS-over-vsock = host-side name resolution in the gateway.** Extend `EgressGate`
   to accept a `"hostname:port"` target (sent by the `socks5h` client), resolve it
   against the claim-10 host-allowlist / DNS pin registry, and connect the pinned IP.
   No guest resolver, no UDP/53.

## Status

Both **in-house VMM** paths now prove vsock-only egress live, reusing one
`EgressProxy` + run loop + heartbeat:

- **HVF / macOS / Apple silicon** — the reference (details below).
- **KVM / x86_64 / Linux** — `KvmVm::boot_with_egress` puts the same `VirtioVsock` +
  `EgressProxy` on a virtio-mmio window (no guest NIC). Live on real `/dev/kvm`: a
  NIC-less guest (kernel built with `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` +
  `VIRTIO_VSOCKETS` `=y`) opened a vsock stream → host admitted it (claim-10,
  `egress_allowed`) → opened the real TCP connection → the echo round-tripped back
  (`reply n=4 data=ping`). KVM specifics vs HVF: the SIGUSR1 heartbeat breaks the
  in-kernel HLT, and the device IRQ is **pulsed** (x86 IOAPIC edge delivery) so async
  replies reach an idle guest. The third-party VMMs (libkrun/vz/Firecracker) are the
  remaining convergence (Step 2 below); the in-house path is the destination runtime.

### HVF reference (Apple silicon)

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
- **In-guest TUN + userspace netstack (`smoltcp`), or netfilter REDIRECT, for full
  transparency.** Both work (the REDIRECT variant is live-proven in
  `spikes/transparent-egress/`) and capture *any* raw `connect()`. **Rejected for
  production**: both require an in-guest IP stack (TUN/netfilter/routing) — i.e. "a
  network in the guest" — which is exactly the surface this ADR removes. They stay as
  illustrative spikes. (smoltcp's license is fine — `0BSD`, the most permissive there
  is, already on `deny.toml`'s allow-list — so the rejection is about guest surface,
  not licensing.)
- **`LD_PRELOAD` / syscall-shim `connect()` interception.** Rejected: covers only
  dynamically-linked libc callers (static/Go/non-libc bypass it) and isn't a
  boundary anyway.
- **Proxy-env / SDK-native (`ALL_PROXY` → `mvm-egress-client` → vsock) — CHOSEN.**
  This is the production path: loopback-only (no NIC/route/netfilter/IP-stack), the
  runtime sets `ALL_PROXY`, and `socks5h` pushes DNS to the host. The accepted cost
  is that a raw-`AF_INET` binary ignoring proxy env has no egress (no route) and must
  use the SDK/runtime — a deliberate trade for an unbypassable, network-free guest.
