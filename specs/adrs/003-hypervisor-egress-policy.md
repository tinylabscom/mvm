# ADR-003: Egress — one host-mediated chokepoint per guest, default-deny

## Status

Accepted

## Context

A workload guest is untrusted: code running inside it may try to exfiltrate
data or reach hosts the operator never authorized. The hypervisor boundary is
the only place enforcement can hold, because the guest's own network stack —
where it has one — is inside the thing being defended against.

Workload backends attach fundamentally different network hardware to a
guest. Some backends can omit a network device entirely, closing off an
entire class of guest-side attack surface: no kernel netdev driver, no
in-guest IP stack to misconfigure or escape through. Others still expose a
virtio-net NIC to the guest. A single egress story has to hold across both
shapes without turning into one enforcement mechanism per VMM to audit.

Separately, some workloads need to reach destinations that require a real
credential — an API key, a registry token — without that credential ever
existing in guest memory. The credential has to be substituted by something
the guest doesn't control, on a per-destination basis, without breaking
end-to-end TLS for every other destination the guest talks to.

## Decision

**HVF and libkrun workload guests attach no virtio-net device.** Their only
channel to the host, and through it to anything outside the guest, is
`AF_VSOCK`. There is no guest kernel IP stack, no tap device, and no
userspace network gateway process to compromise or misconfigure on these
backends.

**Firecracker attaches a TAP NIC behind a host-side nftables default-deny
chain.** When a run also configures the vsock network tunnel described
below, the TAP's own policy is pinned to deny-all so the tunnel is the sole
enforced and audited egress path — a guest that brought the NIC up itself
could otherwise reach an allow-listed host directly, bypassing the tunnel's
audit and substitution logic. A Firecracker run with no tunnel configured
keeps its egress on the TAP-plus-nftables path directly. QEMU also attaches
a NIC, as a Linux dev/test substrate; it is never auto-selected and carries
no default-deny enforcement, consistent with its status outside the
security-claim boundary.

**The network tunnel is one implementation shared by every backend.** The
guest hands the host raw IPv4 packets over a dedicated `AF_VSOCK` port using
a backend-agnostic framing. Before any packet can leave the host, a decision
gate checks its destination against the admitted network policy, projected
through a DNS-pin registry established at admission time — there is no
guest-side DNS resolution to trust. An unparseable packet, an unpinned
destination host, or a destination with no IP pin all resolve to drop
(claim 10). Admitted packets are handed to an in-process, userspace
`smoltcp` TCP/IP stack that terminates each guest flow and splices it to an
ordinary host socket, or to an unprivileged ping socket for ICMP echo — no
root, no host kernel TUN or NAT device, and one codebase shared by every
backend instead of one per VMM.

**Secret-bound destinations never put the real credential in the guest.**
The guest sends a request carrying an opaque placeholder in place of a
credential. A per-VM host-side substitution endpoint checks the request's
destination against the plan's secret bindings and substitutes the real
credential only on the outbound leg, after that check passes. For `https`
destinations that need substitution, TLS is terminated at the host only for
those specific bound hosts: each VM gets a freshly minted intermediate CA,
chained to a long-lived host CA, whose `nameConstraints` are exactly that
plan's bound hosts. The guest trusts only this per-VM intermediate — never
the host CA, never any private key. SNI outside the plan's bound hosts is
spliced through untouched; the terminator never decrypts it, so end-to-end
TLS holds for everything the guest wasn't explicitly asking to have
substituted. Not every TLS client enforces `nameConstraints`; the
certificate constraint is defense in depth, and the real boundary is the
host-side allow-list check the substitution endpoint runs before every
substitution.

**Per-VM network provisioning goes through one trait.** Each backend's
provider brings a VM's network up and down against an admitted network
spec and reports the policy it enforces; a caller never branches on which
backend it's talking to. Firecracker's TAP/bridge provider enforces its own
nftables rules directly; the vsock-tunnel path enforces through the shared
decision gate above. The same trait is implemented outside single-host mvm
for fleet-mesh networking, so the provisioning seam is not
workload-backend-specific.

## Consequences

Removing the network device on HVF and libkrun closes an entire class of
guest-side attack surface for those backends: no kernel netdev to drive, no
ARP/DHCP/routing table to attack, and no way for a compromised guest to
reach anything the host didn't explicitly proxy for it. Firecracker keeping
its TAP means it carries two things that have to stay consistent whenever a
tunnel is configured — the deny-all TAP policy and the tunnel's own admitted
policy — rather than one.

One shared `smoltcp` forwarder and one shared decision gate means a fix or
an audit finding in the packet path applies to every backend at once,
instead of being re-derived once per VMM's own network stack. The cost is
that every workload backend now depends on this forwarder's correctness for
its egress story; a bug in the shared gate is a bug on every backend
simultaneously, not isolated to one.

The name-constrained per-VM CA bounds the blast radius of a leaked
intermediate key to exactly the hosts that plan was allowed to reach, at the
cost of one more certificate in the chain for every bound-host TLS
handshake. Clients that don't enforce `nameConstraints` get no benefit from
the constraint itself, but the substitution endpoint's allow-list check
still holds regardless of what the guest's TLS library validates.
