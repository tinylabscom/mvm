# ADR-003: Egress — one host-mediated chokepoint per guest, default-deny

## Status

Accepted

## Context

A workload guest is untrusted: code running inside it may try to exfiltrate
data or reach hosts the operator never authorized. The hypervisor boundary is
the only place enforcement can hold, because the guest's own network stack —
where it has one — is inside the thing being defended against.

Historically, workload backends attached different network hardware to a
guest. That split is retired: workload execution now uses one runner seam with
no NIC surface, and the host endpoint spawner is the sole raw egress path.

Separately, some workloads need to reach destinations that require a real
credential — an API key, a registry token — without that credential ever
existing in guest memory. The credential has to be substituted by something
the guest doesn't control, on a per-destination basis, without breaking
end-to-end TLS for every other destination the guest talks to.

## Decision

**Every workload backend uses the uniform vsock runner.** Its guest has no
workload NIC surface. Default-deny admission is enforced before launch; an
admitted raw host/port flow crosses vsock to the host's
`RealNetworkEndpointSpawner`, while secret-bearing flows use the broker and the
supervisor's live L4 gate. Firecracker, HVF, and libkrun therefore share the
same host seam and cannot silently fall back to a routable guest NIC or a
userspace L3 tunnel.

**Secret-bound destinations never put the real credential in the guest.**
The guest sends a request carrying an opaque placeholder in place of a
credential. A per-VM host-side substitution endpoint checks the request's
destination against the plan's secret bindings and substitutes the real
credential only on the outbound leg, after that check passes. For `https`
destinations that need substitution, TLS is terminated at the host only for
those specific bound hosts: each VM gets a freshly minted, self-signed CA
whose `nameConstraints` are exactly that plan's bound hosts. The guest
receives that CA's certificate and nothing else — no private key, and no
long-lived root shared across VMs, because there is none. A flow to a host
outside the plan's bound hosts is relayed opaquely; the endpoint never
decrypts it, so end-to-end TLS holds for everything the guest wasn't
explicitly asking to have substituted. The certificate constraint is defense
in depth: OpenSSL- and rustls-backed clients enforce it from a self-signed
anchor, but the real boundary is the host-side allow-list check the
substitution endpoint runs before every substitution, which holds whatever
the guest's TLS library validates.

**Per-VM network provisioning goes through one trait.** Each backend's
provider brings a VM up against an admitted network spec and reports the
same vsock-only capability shape; a caller never branches on which backend it
is talking to. QEMU remains a non-production development substrate outside
the workload claim boundary.

## Consequences

Removing the workload NIC surface and the dead L3 stack closes the guest-side
network-device attack class for every production workload backend. One runner
seam means default-deny and secret substitution are enforced in one place,
instead of being re-derived once per VMM's network stack.

The name-constrained per-VM CA bounds the blast radius of a leaked CA key
to exactly the hosts that plan was allowed to reach, and to that one VM:
nothing signs across VMs. A client that did not enforce `nameConstraints`
would get no benefit from the constraint itself, but the substitution
endpoint's allow-list check still holds regardless of what the guest's TLS
library validates.
