# ADR-003: Egress — one host-mediated chokepoint per guest, default-deny

## Status

Accepted

Owns the workload egress data path, including connect completion, DNS
and the single flow-aware vsock path (folded in 2026-11-27,
[#4839](https://github.com/tinylabscom/mvm/issues/4839)). The claims this path
enforces (10 and 13) and their witnesses stay in ADR-001; the secret
substitution mechanism stays in ADR-023.

## Context

A workload guest is untrusted: code running inside it may try to exfiltrate
data or reach hosts the operator never authorized. The hypervisor boundary is
the only place enforcement can hold, because the guest's own network stack —
where it has one — is inside the thing being defended against.

Historically, workload backends attached different network hardware to a
guest, and an opt-in raw-packet mode later gave the guest a TUN and an IP
stack. Two production paths meant two policy implementations, and claim 10's
"one decision point" was true of only one of them. Both are retired.

Separately, some workloads need to reach destinations that require a real
credential — an API key, a registry token — without that credential ever
existing in guest memory. The credential has to be substituted by something
the guest doesn't control, on a per-destination basis, without breaking
end-to-end TLS for every other destination the guest talks to.

## Decision

**There is exactly one external networking path for an untrusted
workload.**

```text
guest loopback adapter
  -> FlowMux session on GuestService::NetworkFlow (vsock port 5253)
  -> one per-VM mvm-network-endpoint
  -> EgressGate: policy, DNS, substitution, rate and audit
  -> host-originated TCP/UDP socket or host-owned ingress listener
```

The guest has no NIC on any workload backend. Default-deny admission is
enforced before launch, and the host endpoint spawner
(`RealNetworkEndpointSpawner`) is the sole raw egress path, so Firecracker,
HVF and libkrun share one host seam and cannot fall back to a routable guest
NIC or a userspace L3 tunnel. `Off` is the absence of a network grant and of
`NetworkFlow`, not a second mode; there is no transport selector.

**The endpoint is flow-aware at L4, with L7 only where the plan asks.** TCP
and UDP payloads whose signed plan requests no transformation are relayed as
opaque bytes; the host does not parse them or claim to have inspected them.
TLS termination, substitution and route rules run only for a destination the
plan binds a secret or an intercepting route to. A plan that requires a
transformation on a flow shape the endpoint cannot enforce is refused rather
than downgraded. Universal host TLS termination is rejected: pinning, mutual
TLS, QUIC and ECH defeat it, it makes enforcement depend on decrypting
everything, and it would turn a per-destination endpoint compromise into a
universal one. Arbitrary guest-originated TLS and host-side credential
replacement are therefore mutually exclusive, and the plan says which a flow
gets.

**Secret-bound destinations never put the real credential in the guest.**
The guest sends a request carrying an opaque placeholder in place of a
credential. The per-VM endpoint checks the request's destination against the
plan's secret bindings and substitutes the real credential only on the
outbound leg, after that check passes. For `https` destinations that need
substitution, TLS is terminated at the host only for those specific bound
hosts: each VM gets a freshly minted, self-signed CA whose `nameConstraints`
are exactly that plan's bound hosts. The guest receives that CA's certificate
and nothing else — no private key, and no long-lived root shared across VMs,
because there is none. A flow to a host outside the plan's bound hosts is
relayed opaquely; the endpoint never decrypts it. The certificate constraint
is defense in depth: the real boundary is the host-side allow-list check the
endpoint runs before every substitution, which holds whatever the guest's TLS
library validates.

**Internal addresses are refused by the gate, not by the allow-list alone.**
One classifier (`mvm_contract::policy::restricted_address`) decides which
destinations are internal, for every connect, datagram, DNS answer and
forward-leg dial. Cloud metadata endpoints (`169.254.169.254`,
`169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`), loopback, the
unspecified block, link-local and carrier-grade NAT are refused under every
policy. RFC1918, IPv6 unique-local, multicast and reserved addresses are
refused by default and re-admitted only by a grant that names the address — a
literal IP, a CIDR inside the private range, or an allow-listed host that
resolved to it at admission. An open policy, or a `0.0.0.0/0` rule, names
none of them. An IPv6 address carrying an IPv4 one (mapped, compatible, NAT64,
6to4, Teredo) is judged by the IPv4 address it reaches. Each refusal is
recorded with its class (`cloud_metadata`, `private_range`, …), not a generic
denial.

**A host is resolved once.** The gate resolves a destination — against the
admission pins, or live under an open policy — and every connection to it is
made to exactly those addresses: FlowMux dials the verdict's addresses, and
the substitution path's forward leg resolves through the gate's recorded
answer rather than the system resolver. A name cannot answer the decision
with one address and the connection with another.

**An admitted connect completes or fails fast.** The guest adapter reports
success to its client only after the host's connect returns; a failed
admitted connect is a `502 Bad Gateway` or SOCKS `REP_GENERAL_FAILURE`, never
a tunnel that silently delivers nothing. The host tries every admitted
address for a name, first success wins, each bounded by a per-address
budget (`flowmux::tcp_relay::connect_first_admitted`), so an unreachable AAAA
pin does not stall a dual-stack connect.

**DNS is part of the same seam, not beside it.** The guest egress client
serves a DNS stub on `127.0.0.1:53` and forwards queries over the same
FlowMux session; there is no guest resolver of its own and no plain
forwarding resolver. The host resolves a name only if the workload's signed
`NetworkPolicy` admits it, answers `REFUSED` otherwise with no upstream
lookup, filters answers through the same internal-address classifier, and
records refusals (`dns.refused`) in the audit chain. The codec is
`hickory-proto` limited to question records and A/AAAA answers with a bounded
message size, fuzzed by `fuzz_dns_codec`; the query rate is bounded per workload. One policy drives the name gate and the connect gate.

**Endpoint routes are decided by the gate, where the request is read.** A
plan's network policy can carry routes: a destination, rules over HTTP method
and path glob, and an outcome of allow, deny or ask
(`mvm_contract::policy::routes`). `EgressGate::decide_route` decides a request
against them on every flow the endpoint reads — typed flows and terminated
ones — and each decision is recorded with the route and rule. A route never
causes interception by itself: a destination no secret is bound to is
terminated for its rules only when the route grants it (`intercept`), the
per-VM certificate is minted over those hosts too, and an opaque flow to a
destination whose rules cannot be enforced is refused.

**An `ask` is held and answered in the endpoint, never in the guest.** The
same endpoint that read the request holds the flow and puts the question —
route, rule, destination, method, path — to an approval broker on a socket in
the VM's socket directory, bound by the `mvmctl` that launched the run
(`mvm_hostd::supervisor::endpoint::runtime_approval`). A secret binding marked
`approve = ask` raises the same question before its placeholder is
substituted. The broker only answers; the endpoint records each request in
the contract's `ApprovalLedger`, enforces the timeout, the per-VM prompt rate
and the session-grant lifetime, and chain-signs `approval.requested`,
`approval.granted`, `approval.denied` and `approval.timed_out`. Every failure —
no broker, an unreachable socket, a malformed or late answer — is a denial,
so the decision point stays single and fails closed. The endpoint's
confinement grants the broker's socket by its directory, the VM's own socket
directory, because the broker binds after the endpoint has confined itself.

**Per-VM network provisioning goes through one trait.** Each backend's
provider brings a VM up against an admitted network spec and reports the
same vsock-only capability shape; a caller never branches on which backend it
is talking to. QEMU remains a non-production development substrate outside
the workload claim boundary.

**What is unsupported, by design.** Raw sockets, arbitrary IP protocols and
in-guest resolvers have no route; a program that ignores the loopback
adapters (HTTP proxy, SOCKS5h, SOCKS5 UDP, the DNS stub, the mediated
`mvm-ping`, typed SDK connectors) fails closed. A stale declaration asking
for the retired raw IP stack (`raw_ip_stack`) is refused with a migration
error. No compatibility concession may weaken `PR_SET_DUMPABLE`, ptrace
isolation, capability bounding, seccomp, verified boot, the read-only rootfs
or secret handling.

## Alternatives rejected

- **An L3 TUN-over-vsock mode and its userspace (smoltcp) socket datapath.**
  Shipped, then deleted: a second production path with its own policy code
  and audit shape. If a packet path is ever reconsidered, the reasons the TUN
  was chosen still hold: a virtio-net NIC deletes "the host originates every
  flow"; packets on the control RPC tie backpressure to control liveness; an
  L2 TAP needs ARP, DHCP and broadcast policing; slirp-style gateways are a
  second policy engine outside the signed plan.
- **Transparent connect interception through ptrace or seccomp
  user-notification.** It needs weaker process isolation, or reading workload
  memory, to serve programs that bypass the adapters.
- **A raw-packet path kept for dev/test.** A second network stack with a
  different label; hermetic protocol doubles are allowed instead.
- **A privileged macOS network helper** (utun, PF anchors). Nothing needs
  ICMP or raw IP, and a root process widens a helper bug to root on the host.
  mvm adds no root-capable component.
- **A plain forwarding resolver.** DNS would bypass the connect allow-list.

## Consequences

Removing the guest NIC and the L3 stack closes the guest-side network-device
attack class for every production workload backend. One runner seam means
default-deny, DNS and secret substitution are enforced in one place, instead
of being re-derived once per VMM's network stack. Workloads that need an
in-guest IP stack, ICMP beyond `mvm-ping`, or opaque TLS with substitution
have no supported path; that is a deliberate ceiling.

The name-constrained per-VM CA bounds the blast radius of a leaked CA key
to exactly the hosts that plan was allowed to reach, and to that one VM:
nothing signs across VMs. A client that did not enforce `nameConstraints`
would get no benefit from the constraint itself, but the endpoint's
allow-list check still holds regardless of what the guest's TLS library
validates.
